#!/usr/bin/env python3
"""
config_checks.py — the code and its configuration must agree, both ways.

Two failure modes, both of which have happened in this repository:

  * the code reads a key the config does not define — `z['key_fpr']` raised
    KeyError the moment `./build_iso.py templates` reached the component
    generator, before a single template was built;
  * the config defines a key the code never reads — a documented knob that
    silently does nothing, which is worse than an error because it looks
    configured.

Both are decidable statically. This is that check.

    ./tests/config_checks.py
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAILED: list[str] = []
PASSED: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASSED if ok else FAILED).append(name if ok else f"{name}\n          {detail}")


def _lit(node):
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError):
        pass
    if isinstance(node, ast.Dict):
        return {_lit(k): _lit(v) for k, v in zip(node.keys, node.values)}
    if isinstance(node, (ast.List, ast.Tuple)):
        return [_lit(e) for e in node.elts]
    return "<computed>"


def default_config(script: str) -> dict:
    tree = ast.parse((ROOT / script).read_text())
    for node in tree.body:
        target = (getattr(node.target, "id", "") if isinstance(node, ast.AnnAssign)
                  else next((getattr(t, "id", "") for t in node.targets), "")
                  if isinstance(node, ast.Assign) else "")
        if target == "DEFAULT_CONFIG":
            return _lit(node.value)
    raise AssertionError(f"DEFAULT_CONFIG not found in {script}")


# The roots through which config is reached in each script, and the sub-dict
# each names. golden_image.py aliases them heavily (o, r, q, w, b = ...), so the
# aliases are resolved by name rather than by dataflow.
ALIASES = {
    "golden_image.py": {
        "w": "wazuh", "z": "zeek", "k": "kali", "d": "dns", "b": "backup",
        "res": "resources", "cc": "credentials",
    },
    "build_iso.py": {
        "k": "kali", "z": "zeek", "w": "wazuh", "inst": "install",
    },
}


def reads(script: str) -> set[str]:
    """Config keys the source actually subscripts."""
    src = (ROOT / script).read_text()
    found: set[str] = set()
    # self.c["a"]["b"] / x.c["a"]["b"] / cfg["a"]
    for m in re.finditer(r"(?:self\.c|x\.c|cfg|self\.c)\[[\"'](\w+)[\"']\]"
                         r"(?:\[[\"'](\w+)[\"']\])?", src):
        found.add(m.group(1) if not m.group(2) else f"{m.group(1)}.{m.group(2)}")
    # .get("a") on the same roots
    for m in re.finditer(r"(?:self\.c|x\.c|cfg)\.get\(\s*[\"'](\w+)[\"']", src):
        found.add(m.group(1))
    # the local aliases, e.g. w["port_events"] where w = cfg["wazuh"]
    for alias, section in ALIASES.get(script, {}).items():
        for m in re.finditer(rf"\b{alias}\[[\"'](\w+)[\"']\]", src):
            found.add(f"{section}.{m.group(1)}")
        for m in re.finditer(rf"\b{alias}\.get\(\s*[\"'](\w+)[\"']", src):
            found.add(f"{section}.{m.group(1)}")
    return found


def flat(d: dict, prefix: str = "") -> set[str]:
    out = set()
    for k, v in d.items():
        out.add(prefix + k)
        if isinstance(v, dict):
            out |= flat(v, prefix + k + ".")
    return out


# Keys read through an indirection this static pass cannot follow, or held for
# an operator to set. Each needs a reason, not just an entry.
EXPECTED_UNREAD = {
    "golden_image.py": {
        "credentials.fixed.dashboard", "credentials.fixed.api",
        "credentials.fixed.authd", "credentials.fixed.backup",  # read via f[...]
        "tpl.sys", "tpl.proxy", "tpl.ids", "tpl.kali", "tpl.personal",
        "tpl.wazuh",                                            # read via self.t
        "qube.proxy", "qube.ids", "qube.dpi", "qube.firewall", "qube.net",
        "qube.usb", "qube.whonix", "qube.wazuh", "qube.kali_clear",
        "qube.kali_tor", "qube.dvm_offline",                    # read via self.q
        "prebuilt_templates.kali", "prebuilt_templates.personal",
        "prebuilt_templates.ids", "prebuilt_templates.proxy",   # read via pre[key]
        "wazuh.central_address",                                # central mode only
        # read as w.get(key) with key from a loop over (tool, key) pairs
        "wazuh.certs_tool_sha256", "wazuh.passwords_tool_sha256",
    },
    "build_iso.py": {
        "kali.keyring_url",              # read as k["keyring_url"] in fetch_kali_key
    },
}


def main() -> int:
    for script in ("golden_image.py", "build_iso.py"):
        cfg = flat(default_config(script))
        used = reads(script)
        sections = {k for k in cfg if "." not in k and
                    isinstance(default_config(script).get(k), dict)}

        unknown = {k for k in used if k not in cfg and k.split(".")[0] in
                   {s for s in cfg if "." not in s}}
        check(f"{script}: every config key the code reads exists", not unknown,
              "reads keys that are not in DEFAULT_CONFIG: "
              + ", ".join(sorted(unknown)))

        unread = {k for k in cfg
                  if k not in used
                  and k not in sections
                  and k not in EXPECTED_UNREAD.get(script, set())
                  and not any(u.startswith(k + ".") for u in used)}
        check(f"{script}: every config key the code defines is read", not unread,
              "defined but never read — a setting that silently does nothing: "
              + ", ".join(sorted(unread)))

    for f in FAILED:
        print(f"  FAIL  {f}")
    total = len(PASSED) + len(FAILED)
    print(f"\n  {len(PASSED)}/{total} configuration checks pass")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
