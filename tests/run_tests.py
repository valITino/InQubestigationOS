#!/usr/bin/env python3
"""
run_tests.py — the fake-dom0 harness.

Runs golden_image.py end to end against stub qvm-* binaries and a synthetic
dom0 root, then asserts on what it generated. No Qubes machine required, so CI
can catch a regression in the firewall or the SIEM before it reaches a laptop.

    ./tests/run_tests.py              # everything
    ./tests/run_tests.py --keep       # keep the work tree for inspection

Exit code is non-zero if any stage fails.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"

STUB_NAMES = [
    "qvm-check", "qvm-create", "qvm-clone", "qvm-prefs", "qvm-ls", "qvm-run",
    "qvm-start", "qvm-shutdown", "qvm-volume", "qvm-features", "qvm-firewall",
    "qvm-backup", "systemctl", "qubes-vm-update", "qubesctl", "logger",
]

# A stock Qubes 4.3 install, before provisioning.
BASE_VMS = [
    "dom0", "sys-net", "sys-firewall", "sys-usb", "personal", "work", "vault",
    "untrusted", "default-dvm",
    "debian-13-xfce", "fedora-43-xfce",
    "whonix-gateway-18", "whonix-workstation-18", "sys-whonix", "anon-whonix",
]

RESULTS: list[tuple[str, bool, str]] = []


def stage(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    print(f"  {mark}  {name}" + (f"  -- {detail}" if detail and not ok else ""))


def build_world(path: Path) -> None:
    vms = {}
    for n in BASE_VMS:
        vms[n] = {"prefs": {"netvm": "sys-firewall" if n in
                            ("personal", "work", "untrusted", "default-dvm") else "",
                            "label": "gray"},
                  "running": False, "class": "TemplateVM" if "-1" in n else "AppVM"}
    vms["sys-net"]["prefs"]["netvm"] = ""
    vms["sys-firewall"]["prefs"]["netvm"] = "sys-net"
    vms["sys-whonix"]["prefs"]["netvm"] = "sys-firewall"
    vms["vault"]["prefs"]["netvm"] = ""
    world = {
        "vms": vms,
        "units": {},
        "default_qtest_rc": 0,
        # Predicates the provisioner asks the qubes about. Everything not listed
        # answers success, which models a healthy machine; the entries below
        # model the parts that must answer "no" on a fresh install.
        "qtest": [
            {"match": "test -d /var/ossec", "rc": 1},
            {"match": "dpkg -s wazuh-manager", "rc": 1},
            {"match": "test -x /opt/wazuh-certs-tool.sh", "rc": 1},
            {"match": "test -x /opt/wazuh-passwords-tool.sh", "rc": 1},
        ],
    }
    path.write_text(json.dumps(world, indent=2) + "\n")


def make_env(work: Path) -> dict:
    stubs = work / "stubs"
    stubs.mkdir(parents=True, exist_ok=True)
    for n in STUB_NAMES:
        dst = stubs / n
        if not dst.exists():
            shutil.copy2(TESTS / "qubes_stub.py", dst)
            dst.chmod(0o755)

    dom0 = work / "dom0root"
    (dom0 / "etc").mkdir(parents=True, exist_ok=True)
    (dom0 / "etc" / "qubes-release").write_text("Qubes release 4.3.1 (R4.3)\n")
    (dom0 / "var" / "lib" / "qubes").mkdir(parents=True, exist_ok=True)
    (dom0 / "root").mkdir(parents=True, exist_ok=True)

    env = dict(os.environ)
    env["PATH"] = f"{stubs}:{env['PATH']}"
    env["FAKE_DOM0_STATE"] = str(work / "world.json")
    env["FAKE_DOM0_ACTIONS"] = str(work / "actions.jsonl")
    env["FAKE_DOM0_CAPTURE"] = str(work / "capture")
    env["GOLDEN_IMAGE_DOM0_ROOT"] = str(dom0)
    env["HOME"] = str(work / "home")
    (work / "home").mkdir(parents=True, exist_ok=True)
    (work / "capture").mkdir(parents=True, exist_ok=True)
    (work / "actions.jsonl").touch()
    return env


def run(script: Path, args: list[str], env: dict, cwd: Path) -> subprocess.CompletedProcess:
    # golden_image.py refuses a synthetic dom0 root unless the caller says so
    # explicitly — the variable alone must never be enough, because it would
    # satisfy the "am I in dom0?" guard while qvm-* still reached a real machine.
    if script.name == "golden_image.py":
        args = [*args, "--test-root"]
    return subprocess.run([sys.executable, str(script), *args], env=env, cwd=cwd,
                          capture_output=True, text=True, timeout=900)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="keep the work tree")
    a = ap.parse_args()

    work = Path(tempfile.mkdtemp(prefix="golden-harness-"))
    print(f"\nfake-dom0 harness   work tree: {work}\n")

    # golden_image.py writes its config beside itself, so run from a copy.
    sandbox = work / "repo"
    sandbox.mkdir()
    for f in ("golden_image.py", "build_iso.py"):
        shutil.copy2(ROOT / f, sandbox / f)
    gi = sandbox / "golden_image.py"
    bi = sandbox / "build_iso.py"

    print("compile")
    for f in (ROOT / "golden_image.py", ROOT / "build_iso.py"):
        p = subprocess.run([sys.executable, "-m", "py_compile", str(f)],
                           capture_output=True, text=True)
        stage(f"{f.name} compiles", p.returncode == 0, p.stderr.strip())

    print("\ndry run")
    build_world(work / "world.json")
    env = make_env(work)
    p = run(gi, ["--dry-run"], env, sandbox)
    stage("dry run exits 0", p.returncode == 0, p.stderr.strip()[-400:])
    stage("dry run reaches phase 12", "Phase 12" in p.stdout, "phase 12 not reached")
    planned = p.stdout.count("[dry-run]")
    stage("dry run plans actions", planned > 100, f"only {planned} actions planned")
    print(f"        {planned} actions planned")
    stage("dry run changed nothing",
          not (work / "capture").exists() or not any((work / "capture").iterdir()),
          "files were written during a dry run")

    print("\nreal run against the harness")
    shutil.rmtree(work / "capture", ignore_errors=True)
    (work / "capture").mkdir()
    (work / "actions.jsonl").write_text("")
    build_world(work / "world.json")
    (sandbox / "golden-image.json").unlink(missing_ok=True)
    p = run(gi, [], env, sandbox)
    # 0 = everything passed. 2 = the run completed and the acceptance tests
    # reported failures, which is the honest answer against stub qubes that
    # cannot actually run Suricata. Anything else is a crash.
    stage("real run completes without crashing", p.returncode in (0, 2),
          f"rc={p.returncode} " + p.stderr.strip()[-600:])
    (work / "run.log").write_text(p.stdout + "\n----- stderr -----\n" + p.stderr)

    state = (Path(env["HOME"]) / "golden-image" / ".build-state")
    done = state.read_text().split() if state.exists() else []
    stage("phases recorded as complete", len(done) >= 11,
          f"only {len(done)} phases marked: {' '.join(done)}")

    creds = Path(env["HOME"]) / "golden-image" / "credentials.json"
    stage("credentials file created", creds.exists())
    if creds.exists():
        stage("credentials file is mode 600",
              oct(creds.stat().st_mode)[-3:] == "600", oct(creds.stat().st_mode)[-3:])
        c = json.loads(creds.read_text())
        secrets = {c.get(k) for k in ("dashboard", "api", "authd", "backup")}
        stage("four distinct secrets generated", len(secrets) == 4, str(len(secrets)))
        stage("secrets are long enough",
              all(len(c.get(k, "")) >= 24 for k in ("dashboard", "api", "authd", "backup")))
        stage("no secret leaked into the build log",
              not any(s and s in (work / "run.log").read_text() for s in secrets),
              "a generated secret appears in the run log")

    log = Path(env["HOME"]) / "golden-image" / "build.log"
    if log.exists() and creds.exists():
        c = json.loads(creds.read_text())
        leaked = [k for k in ("dashboard", "api", "authd", "backup")
                  if c.get(k) and c[k] in log.read_text()]
        stage("no secret written into build.log", not leaked, f"leaked: {', '.join(leaked)}")

    print("\nresume")
    p2 = run(gi, [], env, sandbox)
    stage("re-run is idempotent", p2.returncode in (0, 2),
          f"rc={p2.returncode} " + p2.stderr.strip()[-400:])
    stage("completed phases are skipped on re-run", "skipping" in p2.stdout)

    print("\ncredential lifecycle")
    # The handover used to be a checklist whose last step — destroying the dom0
    # copy — was the one that got skipped. These are the commands that replaced
    # it, and the refusal is the part that matters.
    p_no = run(gi, ["--shred-credentials"], env, sandbox)
    stage("--shred-credentials refuses without an escrow record",
          p_no.returncode != 0 and creds.exists(),
          "it destroyed the only copy of the machine's secrets")
    p_es = run(gi, ["--escrow-credentials", "vault"], env, sandbox)
    stage("--escrow-credentials copies into the offline qube",
          p_es.returncode == 0, p_es.stderr.strip()[-400:])
    escrowed = work / "capture" / "vault"
    stage("the escrowed copy exists in the target qube",
          escrowed.is_dir() and any(escrowed.rglob("golden-image-credentials-*.json")))
    rec = Path(env["HOME"]) / "golden-image" / "escrow.json"
    stage("an escrow record was written", rec.exists())
    p_sh = run(gi, ["--shred-credentials"], env, sandbox)
    stage("--shred-credentials proceeds once the copy is verified",
          p_sh.returncode == 0, p_sh.stderr.strip()[-400:])
    stage("the dom0 copy is gone", not creds.exists())
    log_after = Path(env["HOME"]) / "golden-image" / "build.log"
    stage("the build log is destroyed with it", not log_after.exists(),
          "it records every command run against every qube")

    print("\nacceptance tests")
    p3 = run(gi, ["--verify"], env, sandbox)
    stage("--verify runs", p3.returncode in (0, 2), f"rc={p3.returncode} "
          + p3.stderr.strip()[-400:])
    stage("--verify reports results", "passed" in p3.stdout)
    # The point of the exit code: a machine that failed its tests must not look
    # like a machine that passed them.
    stage("--verify exits non-zero when tests fail",
          (p3.returncode == 0) == ("0 failed" in p3.stdout.replace("\x1b[31m", "")
                                   .replace("\x1b[0m", "")),
          f"rc={p3.returncode} but the summary says otherwise")

    print("\ngenerated configuration")
    p4 = subprocess.run([sys.executable, str(TESTS / "static_checks.py"),
                         str(work / "capture")], capture_output=True, text=True)
    print(p4.stdout.rstrip())
    stage("static configuration checks", p4.returncode == 0, "see output above")

    print("\nbuild_iso.py")
    ienv = dict(env)
    p5 = run(bi, ["--write-config"], ienv, sandbox)
    stage("build_iso --write-config exits 0", p5.returncode == 0, p5.stderr.strip()[-300:])
    stage("iso-build.json written", (sandbox / "iso-build.json").exists())
    # docs/GUIDE.md's first build command is `./build_iso.py --dry-run all` on a
    # host where nothing has been fetched yet. It has to reach the end.
    p6 = run(bi, ["--dry-run", "--yes", "all"], ienv, sandbox)
    stage("build_iso --dry-run all completes on a bare host", p6.returncode == 0,
          p6.stdout.strip()[-500:] + p6.stderr.strip()[-300:])
    stage("the dry run reaches the final phase", "4 —" in p6.stdout,
          "it stopped before naming and signing the image")
    stage("the dry run wrote nothing",
          not (Path(ienv["HOME"]) / "investigator-iso").exists(),
          "a work tree was created by a run that says it changes nothing")

    print("\nconfiguration")
    pc = subprocess.run([sys.executable, str(TESTS / "config_checks.py")],
                        capture_output=True, text=True, cwd=ROOT)
    print(pc.stdout.rstrip())
    stage("the code and its configuration agree", pc.returncode == 0,
          "see output above")

    print("\ndocumentation")
    p7 = subprocess.run([sys.executable, str(TESTS / "doc_checks.py")],
                        capture_output=True, text=True, cwd=ROOT)
    print(p7.stdout.rstrip())
    stage("documentation matches the code", p7.returncode == 0, "see output above")

    ok = sum(1 for _, o, _ in RESULTS if o)
    bad = [n for n, o, _ in RESULTS if not o]
    print(f"\n  {ok}/{len(RESULTS)} harness stages pass")
    if bad:
        print("  failing stages:")
        for n in bad:
            print(f"    - {n}")

    if a.keep:
        print(f"\n  work tree kept at {work}")
    else:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
