#!/usr/bin/env python3
"""
qubes_stub.py — one binary standing in for every dom0 command.

The harness puts tests/stubs/ on PATH; every name in there is a symlink to this
file. Nothing is executed for real: the stub keeps a small world model in JSON,
answers predicates from it, records every invocation, and captures the content
of every file the provisioner writes into a qube.

That is enough to run golden_image.py end to end off a Qubes machine and then
assert on what it *generated*, which is where the interesting bugs live.

Environment
    FAKE_DOM0_STATE    JSON world model (read/write)
    FAKE_DOM0_ACTIONS  newline-delimited JSON log of every invocation
    FAKE_DOM0_CAPTURE  directory tree receiving files written into qubes
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path

STATE = Path(os.environ["FAKE_DOM0_STATE"])
ACTIONS = Path(os.environ["FAKE_DOM0_ACTIONS"])
CAPTURE = Path(os.environ["FAKE_DOM0_CAPTURE"])


def load() -> dict:
    return json.loads(STATE.read_text())


def save(w: dict) -> None:
    STATE.write_text(json.dumps(w, indent=2, sort_keys=True) + "\n")


def record(kind: str, **kw) -> None:
    with ACTIONS.open("a") as fh:
        fh.write(json.dumps({"kind": kind, **kw}) + "\n")


def vm(w: dict, name: str) -> dict:
    return w["vms"].setdefault(name, {"prefs": {}, "running": False, "class": "AppVM"})


# --------------------------------------------------------------------------
#  predicate answers for in-qube shell snippets
# --------------------------------------------------------------------------
def answer(w: dict, name: str, script: str) -> int:
    """Exit code the fake qube returns for a shell snippet."""
    for rule in w.get("qtest", []):
        if rule.get("vm") not in (None, name):
            continue
        if rule["match"] in script:
            return int(rule.get("rc", 0))
    return int(w.get("default_qtest_rc", 0))


def capture_write(name: str, path: str, data: str, mode: str) -> None:
    dest = CAPTURE / name / path.lstrip("/")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(data)
    meta = CAPTURE / name / (path.lstrip("/") + ".mode")
    meta.parent.mkdir(parents=True, exist_ok=True)
    meta.write_text(mode + "\n")
    record("qwrite", vm=name, path=path, mode=mode, bytes=len(data))


CAT_RE = re.compile(r"cat > (?P<p>'[^']*'|\"[^\"]*\"|\S+)")
CHMOD_RE = re.compile(r"chmod (?P<m>[0-7]{3,4})")


def cmd_qvm_run(w: dict, argv: list[str]) -> int:
    pass_io = "--pass-io" in argv
    rest = [a for a in argv if not a.startswith("-")]
    # after stripping flags: [vm, command]; -u root consumes 'root' as well
    if "-u" in argv:
        i = argv.index("-u")
        user = argv[i + 1]
        rest = [a for a in rest if a != user] or rest
    if len(rest) < 2:
        return 0
    name, inner = rest[0], rest[-1]

    if pass_io:
        data = sys.stdin.read()
        m = CAT_RE.search(inner)
        if m:
            path = m.group("p").strip("'\"")
            mode = (CHMOD_RE.search(inner) or [None, "0644"])[1] if CHMOD_RE.search(inner) else "0644"
            capture_write(name, path, data, mode)
            return 0
        record("qvm-run-passio", vm=name, cmd=inner, stdin_bytes=len(data))
        return 0

    script = inner
    if script.startswith("bash -c "):
        try:
            script = shlex.split(script)[2]
        except (ValueError, IndexError):
            script = script[len("bash -c "):]
    record("qrun", vm=name, script=script)
    return answer(w, name, script)


def main() -> int:
    prog = Path(sys.argv[0]).name
    argv = sys.argv[1:]
    w = load()
    record("exec", prog=prog, argv=argv)

    if prog == "qvm-check":
        args = [a for a in argv if not a.startswith("-")]
        if not args:
            return 1
        name = args[0]
        if name not in w["vms"]:
            return 1
        if "--running" in argv:
            return 0 if w["vms"][name].get("running") else 1
        return 0

    if prog == "qvm-create":
        name = [a for a in argv if not a.startswith("-")][-1]
        cls = argv[argv.index("--class") + 1] if "--class" in argv else "AppVM"
        tpl = argv[argv.index("--template") + 1] if "--template" in argv else ""
        lbl = argv[argv.index("--label") + 1] if "--label" in argv else ""
        v = vm(w, name)
        v.update({"class": cls, "prefs": {"template": tpl, "label": lbl, "netvm": ""}})
        save(w)
        return 0

    if prog == "qvm-clone":
        args = [a for a in argv if not a.startswith("-")]
        cls = argv[argv.index("--class") + 1] if "--class" in argv else None
        if cls:
            args = [a for a in args if a != cls]
        src, dst = args[0], args[1]
        if src not in w["vms"]:
            return 1
        v = vm(w, dst)
        v.update(json.loads(json.dumps(w["vms"][src])))
        if cls:
            v["class"] = cls
        v["running"] = False
        save(w)
        return 0

    if prog == "qvm-prefs":
        args = [a for a in argv if not a.startswith("-")]
        if not args:
            return 1
        name = args[0]
        if name not in w["vms"]:
            sys.stderr.write(f"no such domain: {name}\n")
            return 1
        if len(args) == 1:
            for k, val in sorted(w["vms"][name]["prefs"].items()):
                print(f"{k}  -  {val}")
            return 0
        if len(args) == 2:
            print(w["vms"][name]["prefs"].get(args[1], ""))
            return 0
        w["vms"][name]["prefs"][args[1]] = args[2]
        save(w)
        return 0

    if prog == "qvm-ls":
        fields = []
        if "--fields" in argv:
            fields = argv[argv.index("--fields") + 1].split(",")
        if "--raw-list" in argv:
            for n in sorted(w["vms"]):
                print(n)
            return 0
        for n in sorted(w["vms"]):
            p = w["vms"][n]["prefs"]
            row = []
            for f in fields or ["NAME"]:
                row.append({"NAME": n, "NETVM": p.get("netvm", ""),
                            "IP": p.get("ip", "")}.get(f.upper(), ""))
            print("|".join(row))
        return 0

    if prog == "qvm-start":
        args = [a for a in argv if not a.startswith("-")]
        if args and args[0] in w["vms"]:
            w["vms"][args[0]]["running"] = True
            save(w)
            return 0
        return 1

    if prog == "qvm-shutdown":
        args = [a for a in argv if not a.startswith("-")]
        for a in args:
            if a in w["vms"]:
                w["vms"][a]["running"] = False
        save(w)
        return 0

    if prog == "qvm-run":
        return cmd_qvm_run(w, argv)

    if prog == "qvm-volume":
        return 0

    if prog == "qvm-features":
        return 0

    if prog == "qvm-firewall":
        if "--help" in argv:
            print("usage: qvm-firewall [-h] VMNAME {add,del,list,policy}")
            return 0
        args = [a for a in argv if not a.startswith("-")]
        if len(args) >= 2 and args[1] == "list":
            name = args[0]
            print("NO   ACTION  ...")
            for i, r in enumerate(w["vms"].get(name, {}).get("fw", [])):
                print(f"{i}    {r}")
            return 0
        if len(args) >= 2 and args[1] == "add":
            w["vms"].setdefault(args[0], vm(w, args[0])).setdefault("fw", []).append(" ".join(args[2:]))
            save(w)
            return 0
        if len(args) >= 2 and args[1] == "del":
            fw = w["vms"].get(args[0], {}).get("fw", [])
            if fw:
                fw.pop(0)
            save(w)
            return 0
        return 0

    if prog == "qvm-backup":
        return 0

    if prog == "systemctl":
        units = w.setdefault("units", {})
        if argv and argv[0] == "is-enabled":
            return 0 if units.get(argv[-1], {}).get("enabled") else 1
        if argv and argv[0] == "is-active":
            return 0 if units.get(argv[-1], {}).get("active") else 1
        if argv and argv[0] == "enable":
            units[argv[-1]] = {"enabled": True, "active": "--now" in argv}
            save(w)
            return 0
        return 0

    if prog in ("qubes-vm-update", "qubesctl", "logger", "shred"):
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
