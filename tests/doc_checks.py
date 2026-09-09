#!/usr/bin/env python3
"""
doc_checks.py — the documentation must not drift away from the code.

Every claim in this repository's documentation that can be checked mechanically
is checked here: file paths, command lines, configuration keys, version stamps
and the supply-chain fingerprints. docs/VERIFICATION.md says the "verified"
stamp is load-bearing; this is what keeps it honest.

    ./tests/doc_checks.py
"""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = sorted(ROOT.glob("*.md")) + sorted((ROOT / "docs").glob("*.md"))
# The design specification is HTML, which is exactly why it drifted: it was the
# one document nothing checked. Its prose is scanned the same way as the .md
# files, with tags stripped.
HTML_DOCS = sorted((ROOT / "docs").glob("*.html"))

FAILED: list[str] = []
PASSED: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASSED if ok else FAILED).append(name if ok else f"{name}\n          {detail}")


def positional_choices(script: str) -> set[str]:
    """The subcommands a script accepts, read from its POSITIONAL argument.

    A regex for the first `choices=[...]` in the file matched whichever option
    happened to be declared first — so adding `--case-mode` with choices turned
    every word in the docs into a candidate subcommand. Ask the AST which
    add_argument call is the positional one.
    """
    tree = ast.parse((ROOT / script).read_text())
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and getattr(node.func, "attr", "") == "add_argument"):
            continue
        if not node.args:
            continue
        first = node.args[0]
        if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
            continue
        if first.value.startswith("-"):
            continue                      # an option, not the subcommand
        for kw in node.keywords:
            if kw.arg == "choices":
                try:
                    return {str(v) for v in ast.literal_eval(kw.value)}
                except (ValueError, SyntaxError):
                    return set()
    return set()


def _lit(node):
    """literal_eval, but tolerant of the odd computed default (Path.home()/...)."""
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
    """Read DEFAULT_CONFIG out of a script without importing it."""
    tree = ast.parse((ROOT / script).read_text())
    for node in tree.body:
        target = None
        if isinstance(node, ast.AnnAssign):
            target = getattr(node.target, "id", "")
        elif isinstance(node, ast.Assign):
            target = next((getattr(t, "id", "") for t in node.targets), "")
        if target == "DEFAULT_CONFIG":
            return _lit(node.value)
    raise AssertionError(f"DEFAULT_CONFIG not found in {script}")


def flat_keys(d: dict, prefix: str = "") -> set[str]:
    out = set()
    for k, v in d.items():
        out.add(prefix + k)
        if isinstance(v, dict):
            out |= flat_keys(v, prefix + k + ".")
    return out


def cli_options(script: str) -> set[str]:
    src = (ROOT / script).read_text()
    return set(re.findall(r'add_argument\(\s*"(--[a-z0-9-]+)"', src)) | \
           set(re.findall(r'"([a-z-]+)"', re.search(r'choices=\[([^\]]*)\]', src).group(1))
               if re.search(r'choices=\[([^\]]*)\]', src) else set())


# ---------------------------------------------------------------------------
def check_paths() -> None:
    """Every repo-relative path a doc points at must exist."""
    pat = re.compile(r"(?:\]\(|`)((?:docs/|tests/|\./)?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*"
                     r"\.(?:md|py|html|json|txt|yml|yaml|sh))(?:\)|`)")
    for doc in DOCS:
        for m in pat.finditer(doc.read_text()):
            rel = m.group(1).lstrip("./")
            if rel.startswith(("http", "/")) or "*" in rel:
                continue
            # Only paths that claim to be in THIS repository. The docs also cite
            # files in upstream repositories (qubes-core-admin, Zeek, Wazuh) by
            # path, and those are references, not promises.
            top = rel.split("/")[0]
            if "/" in rel and not (ROOT / top).exists():
                continue
            # Files the docs describe as build *outputs*, not repo content.
            if rel in {"iso-build.json", "golden-image.json", "credentials.json",
                       "BUILD-RECORD.txt", "CREDENTIALS-README.txt",
                       "unit-signing-key.asc", "builder.yml", "investigator.ks",
                       "suricata.yaml", "node.cfg", "squid.conf", "ossec.conf",
                       "authd.pass", "kali.list", "wazuh.list", "comps-dom0.xml",
                       "qubes-kickstart.cfg", "archive-keyring.gpg",
                       "kali-archive-keyring.gpg", "wazuh.gpg", "security_zeek.gpg",
                       "ca-certificates.crt", "golden-image.conf", "wazuh.repo",
                       "dependencies-debian.txt", "supply-chain.lock.json",
                       "FINGERPRINT.txt", "verify-iso.sh", "wazuh-config.yml",
                       "wazuh-certs-tool.sh", "wazuh-passwords-tool.sh",
                       "golden-weekly-backup.sh", "Release.key", "GPG-KEY-WAZUH",
                       "config.yml", "node.cfg", "client.keys", "Packages",
                       "golden-image.json", "investigator.ks", "admin.py",
                       "qvm-firewall.rst", "functions.sh"}:
                continue
            # A bare name in docs/GUIDE.md means docs/GUIDE.md's own directory.
            exists = (ROOT / rel).exists() or (doc.parent / rel).exists()
            check(f"{doc.name}: path `{rel}` exists", exists,
                  f"referenced in {doc.name}, missing from the repository")


def _command_lines(text: str) -> list[str]:
    """Command lines a reader would actually type: fenced code blocks, plus
    inline code spans whose whole content is a command."""
    out = []
    for block in re.findall(r"```[a-z]*\n(.*?)```", text, re.S):
        for line in block.splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                out.append(line)
    for span in re.findall(r"`([^`\n]+)`", text):
        span = span.strip()
        if re.match(r"^(sudo )?(\./)?(golden_image\.py|build_iso\.py|golden-image-provision)\b", span):
            out.append(span)
    return out


def check_cli() -> None:
    """Every command line shown in a doc must use flags and actions that exist."""
    surfaces = {
        "golden_image.py": ("golden_image.py", "golden-image-provision"),
        "build_iso.py": ("build_iso.py",),
    }
    for script, names in surfaces.items():
        src = (ROOT / script).read_text()
        opts = set(re.findall(r'add_argument\(\s*"(--[a-z0-9-]+)"', src))
        # Flags that consume the next token. Without this, `--get tier` reads
        # 'tier' as a subcommand.
        valued = {m.group(1) for m in
                  re.finditer(r'add_argument\(\s*"(--[a-z0-9-]+)"((?:[^()]|\([^()]*\))*?)\)',
                              src, re.S)
                  if 'action="store_true"' not in m.group(2)}
        actions = positional_choices(script)
        for doc in DOCS:
            for line in _command_lines(doc.read_text()):
                toks = line.split()
                idx = next((i for i, t in enumerate(toks)
                            if t.lstrip("./") in names or t in names), None)
                if idx is None:
                    continue
                skip = False
                for tok in toks[idx + 1:]:
                    if skip:
                        skip = False
                        continue
                    if tok.startswith("--"):
                        flag = tok.split("=")[0]
                        check(f"{doc.name}: `{flag}` is a real flag of {script}",
                              flag in opts,
                              f"{script} accepts: {' '.join(sorted(opts))}")
                        skip = "=" not in tok and flag in valued
                    elif re.fullmatch(r"[a-z][a-z-]*", tok) and actions:
                        check(f"{doc.name}: `{tok}` is a real action of {script}",
                              tok in actions,
                              f"{script} accepts: {' '.join(sorted(actions))}")
                    else:
                        break


def check_config_keys() -> None:
    """A dotted name in the docs whose root is a real config section must
    resolve. Restricting it to known roots keeps `self.creds` and `build.log`
    out of it while still catching `wazuh.pin_agent` written as
    `WAZUH_PIN_AGENT`."""
    gi = flat_keys(default_config("golden_image.py"))
    bi = flat_keys(default_config("build_iso.py"))
    known = gi | bi
    roots = {k for k in known if "." not in k}
    for doc in DOCS:
        for m in re.finditer(r"`([a-z_]+(?:\.[a-z_]+)+)`", doc.read_text()):
            key = m.group(1)
            if key.split(".")[0] not in roots:
                continue
            # `credentials.json` is a filename, not credentials.<key>.
            if key.rsplit(".", 1)[-1] in {
                    "json", "py", "md", "sh", "log", "asc", "gpg", "html", "txt",
                    "conf", "yml", "yaml", "xml", "pem", "ks", "list", "rules",
                    "service", "timer", "mount", "desktop", "cfg", "pass"}:
                continue
            check(f"{doc.name}: config key `{key}` exists",
                  key in known, "not a key in either DEFAULT_CONFIG")


def html_text(path: Path) -> str:
    t = re.sub(r"<(script|style)\b.*?</\1>", " ", path.read_text(), flags=re.S | re.I)
    t = re.sub(r"<[^>]+>", " ", t)
    return (t.replace("&lt;", "<").replace("&gt;", ">")
             .replace("&amp;", "&").replace("&nbsp;", " "))


def check_html_docs() -> None:
    """The design spec publishes version stamps, verification dates and test
    results. Nothing checked it, so it kept publishing the previous release's."""
    gi = default_config("golden_image.py")
    ver, wz = gi["image_version"], gi["wazuh"]
    for doc in HTML_DOCS:
        t = html_text(doc)
        stamps = set(re.findall(r"Build specification · v(\d+\.\d+)", t))
        check(f"{doc.name}: version stamp matches image_version",
              stamps == {ver} if stamps else True,
              f"stamped {', '.join(sorted(stamps))}, image_version is {ver}")
        check(f"{doc.name}: no stale product name",
              "QubesOS-Cybercrime-Investigator" not in t)
        check(f"{doc.name}: does not present custom-prerouting as a live chain",
              not re.search(r"nft [^\n]*custom-prerouting", t))
        # As a config line, not in prose explaining why it was wrong.
        check(f"{doc.name}: the backup profile key is the one qvm-backup accepts",
              not re.search(r"passphrase_file\s*:", t),
              "qubes-core-admin accepts passphrase_text or passphrase_vm only")
        check(f"{doc.name}: pins the same Kali key as the code",
              gi["kali"]["key_fpr"] in t.replace(" ", "") or
              gi["kali"]["key_fpr"] in t)
        check(f"{doc.name}: names the pinned Wazuh version",
              wz["version"] in t)
        check(f"{doc.name}: does not quote a superseded Zeek package",
              "zeek-8.0" not in t,
              "zeek-8.0 is frozen upstream at 8.0.1-0; the LTS line is zeek-lts")


def check_versions() -> None:
    gi = default_config("golden_image.py")
    ver = gi["image_version"]
    changelog = (ROOT / "CHANGELOG.md").read_text()
    latest = re.search(r"^## (\S+)", changelog, re.M)
    check("CHANGELOG's newest entry matches image_version",
          latest is not None and latest.group(1) == ver,
          f"image_version={ver}, CHANGELOG top entry={latest.group(1) if latest else 'none'}")

    readme = (ROOT / "README.md").read_text()
    for doc, name in ((readme, "README.md"),):
        m = re.findall(r"v(\d+\.\d+)", doc)
        for found in set(m):
            check(f"{name}: version v{found} matches image_version",
                  found == ver, f"image_version is {ver}")

    rev = (ROOT / "docs" / "VERIFICATION.md").read_text()
    rows = re.findall(r"^\|\s*(\d{4}-\d{2}-\d{2})\s*\|\s*([\d.]+)\s*\|", rev, re.M)
    # Older rows are history and stay as they were written. The newest one is
    # the "verified" stamp docs/GUIDE.md calls load-bearing, so that one has to
    # describe the version in the code.
    check("VERIFICATION.md has a revision log", bool(rows))
    if rows:
        date, v = max(rows)
        check(f"VERIFICATION.md's newest revision row ({date}) names the current "
              f"image version", v == ver, f"row says {v}, image_version is {ver}")


def check_product_name() -> None:
    """One product name. A second one in the docs sends people looking for a
    file that the build never produces."""
    iso = default_config("build_iso.py")["iso_name"]
    for doc in DOCS:
        text = doc.read_text()
        stray = set(re.findall(r"\b(QubesOS-Cybercrime-Investigator[\w.-]*)", text))
        check(f"{doc.name}: no stale product name",
              not stray, f"found {', '.join(sorted(stray))}; the ISO is {iso}")
    for src in ("golden_image.py", "build_iso.py"):
        text = (ROOT / src).read_text()
        stray = set(re.findall(r"\b(QubesOS-Cybercrime-Investigator[\w.-]*)", text))
        check(f"{src}: no stale product name", not stray, ", ".join(sorted(stray)))


def check_supply_chain() -> None:
    """The fingerprints in the docs and in both scripts must agree."""
    gi = default_config("golden_image.py")
    bi = default_config("build_iso.py")
    check("both scripts pin the same Kali signing key",
          gi["kali"]["key_fpr"] == bi["kali"]["key_fpr"],
          f"{gi['kali']['key_fpr']} vs {bi['kali']['key_fpr']}")
    check("both scripts pin the same legacy Kali key",
          gi["kali"]["key_fpr_legacy"] == bi["kali"]["key_fpr_legacy"])
    ver = (ROOT / "docs" / "VERIFICATION.md").read_text()
    for fpr in (gi["kali"]["key_fpr"], gi["kali"]["key_fpr_legacy"]):
        check(f"VERIFICATION.md records the pinned key {fpr[:8]}...", fpr in ver,
              "the code pins a key the verification record does not mention")
    check("VERIFICATION.md records the pinned Wazuh version",
          gi["wazuh"]["version"] in ver, gi["wazuh"]["version"])
    check("both scripts use the same Zeek repository line",
          gi["zeek"]["repo_line"] == bi["zeek"]["repo_line"])
    check("both scripts install the same Zeek package",
          gi["zeek"]["package"] == bi["zeek"]["package"])

    lock = ROOT / "supply-chain.lock.json"
    if lock.exists():
        L = json.loads(lock.read_text())
        check("supply-chain.lock.json agrees with the Kali key in the code",
              L.get("kali", {}).get("key_fpr") == gi["kali"]["key_fpr"],
              "run ./build_iso.py check-upstream --update")


def check_docs_do_not_contradict() -> None:
    """REVIEW.md resolved defects that VERIFICATION.md must not still list as
    open questions -- two documents in one repo disagreeing is worse than
    either being silent."""
    ver = (ROOT / "docs" / "VERIFICATION.md").read_text()
    # Naming the chain to explain that it does not exist is fine; presenting it
    # as an open action item for somebody to go and verify is not.
    open_items = [line for line in ver.splitlines()
                  if line.lstrip().startswith("- [ ]")
                  and "custom-prerouting" in line]
    check("VERIFICATION.md does not still list custom-prerouting as a chain to check",
          not open_items,
          "docs/REVIEW.md defect 1 established that this chain does not exist: "
          + "; ".join(open_items))
    for src in ("golden_image.py", "build_iso.py"):
        body = (ROOT / src).read_text()
        check(f"{src} issues no nft command against custom-prerouting",
              re.search(r"nft [^\n]*custom-prerouting", body) is None,
              "the chain does not exist in Qubes")


def check_stdlib_claim() -> None:
    """A script the docs call "standard library only" must actually be one.

    README.md and docs/DESIGN.html said BOTH scripts were standard-library
    Python with no `pip install`, giving dom0's lack of a network as the
    reason. That reason only ever applied to golden_image.py: build_iso.py
    imports PyYAML to edit builder.yml, and pykickstart to check the generated
    kickstart. The claim is now scoped to the script it is true of, and this
    keeps it that way.
    """
    # Modules that ship with this interpreter, plus the repository's own.
    local = {p.stem for p in ROOT.glob("*.py")} | {"tests"}

    def third_party(script: str) -> set[str]:
        found = set()
        for node in ast.walk(ast.parse((ROOT / script).read_text())):
            if isinstance(node, ast.Import):
                found |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.add(node.module.split(".")[0])
        return {m for m in found
                if m not in sys.stdlib_module_names and m not in local}

    gi = third_party("golden_image.py")
    check("golden_image.py really is standard-library only", not gi,
          "the docs say it is, and dom0 has no network to install from: "
          + ", ".join(sorted(gi)))

    # build_iso.py runs on a networked build host, so a third-party import is
    # allowed — but each one has to be accounted for, because setup-host must
    # install it and the docs must not claim it does not exist.
    known = {"yaml"}
    bi = third_party("build_iso.py")
    check("build_iso.py imports no unaccounted third-party module",
          bi <= known,
          "new third-party imports: " + ", ".join(sorted(bi - known))
          + " — setup-host has to install them and README.md/DESIGN.html "
            "describe what they are")

    for doc, text in [(d.name, d.read_text()) for d in DOCS] + \
                     [(h.name, html_text(h)) for h in HTML_DOCS]:
        flat = " ".join(text.split())
        for claim in ("Both are standard-library", "Both are standard library",
                      "Two Python 3 scripts, standard library only"):
            check(f"{doc}: does not claim both scripts are standard-library only",
                  claim not in flat,
                  "build_iso.py imports " + ", ".join(sorted(known))
                  + "; scope the claim to golden_image.py")


def check_no_secrets() -> None:
    """Nothing that looks like key material may be committed."""
    bad = []
    for p in ROOT.rglob("*"):
        if not p.is_file() or ".git/" in str(p):
            continue
        try:
            t = p.read_text(errors="ignore")
        except OSError:
            continue
        for pat in ("PGP PRIVATE KEY BLOCK", "RSA PRIVATE KEY",
                    "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY"):
            if re.search(r"-----BEGIN [^\n]*" + pat + r"-----", t) and \
                    re.search(r"-----END [^\n]*" + pat + r"-----", t):
                bad.append(f"{p.relative_to(ROOT)}: {pat}")
    check("no private key material is committed", not bad, "; ".join(bad))
    check(".gitignore exists", (ROOT / ".gitignore").exists(),
          "README.md tells the reader it keeps credentials out of git")
    if (ROOT / ".gitignore").exists():
        gi = (ROOT / ".gitignore").read_text()
        for pat in ("credentials.json", "golden-image.json", "iso-build.json"):
            check(f".gitignore excludes {pat}", pat in gi)


def main() -> int:
    check_paths()
    check_html_docs()
    check_cli()
    check_config_keys()
    check_versions()
    check_product_name()
    check_supply_chain()
    check_docs_do_not_contradict()
    check_stdlib_claim()
    check_no_secrets()

    for f in FAILED:
        print(f"  FAIL  {f}")
    total = len(PASSED) + len(FAILED)
    print(f"\n  {len(PASSED)}/{total} documentation checks pass")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
