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
import re
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
    "qubes-prefs", "qvm-template", "qvm-service", "rpm",
]

# A stock Qubes 4.3 install, before provisioning.
BASE_VMS = [
    "dom0", "sys-net", "sys-firewall", "sys-usb", "personal", "work", "vault",
    "untrusted", "default-dvm",
    "debian-13-xfce", "fedora-43-xfce",
    "whonix-gateway-18", "whonix-workstation-18", "sys-whonix", "anon-whonix",
]

RESULTS: list[tuple[str, bool, str]] = []

# How many acceptance checks --verify must actually execute. Not a target to
# tune: it exists so that DELETING acceptance groups fails the suite. Raise it
# when groups are added; never lower it to make a run pass.
ACCEPTANCE_FLOOR = 75


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
            # A stock install carries none of the payloads: the tier-1 install
            # path (phase 4) has to run, or the Kali recipe, the Zeek key fetch
            # and the office payload are never exercised at all.
            {"match": "command -v maltego", "rc": 1},
            {"match": "command -v libreoffice", "rc": 1},
            {"match": "command -v suricata", "rc": 1},
            {"match": "command -v squid", "rc": 1},
            # The Tier 2 template bakes the vendor tools in; the SIEM packages
            # are modelled as absent so the Tier 1 install path is exercised,
            # and the stub records the install so the re-check afterwards passes.
            {"match": "test -x /opt/wazuh-certs-tool.sh", "rc": 0},
            {"match": "test -x /opt/wazuh-passwords-tool.sh", "rc": 0},
            {"match": "test -f /opt/wazuh-certificates/root-ca.pem", "rc": 0},
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
    env["PYTHONPYCACHEPREFIX"] = str(work / "pycache")
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
    for f in ("golden_image.py", "build_iso.py", "bootstrap_workflow.py"):
        shutil.copy2(ROOT / f, sandbox / f)
    gi = sandbox / "golden_image.py"
    bi = sandbox / "build_iso.py"

    print("compile")
    # Bytecode goes to the work tree, not into the repository: a test run must
    # not need write access to the checkout, and CI checkouts are not ours to
    # litter.
    cenv = dict(os.environ, PYTHONPYCACHEPREFIX=str(work / "pycache"))
    for f in (ROOT / "golden_image.py", ROOT / "build_iso.py"):
        p = subprocess.run([sys.executable, "-m", "py_compile", str(f)],
                           capture_output=True, text=True, env=cenv)
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

    # ------------------------------------------------------------------
    # The inspected chain, read back off the world the run actually built.
    #
    # Everything above this asserts that the provisioner RAN. None of it
    # asserted WHAT IT BUILT, and the stub answers every in-qube command 0,
    # so rewiring sys-proxy straight to sys-firewall — removing the Suricata
    # IPS and the Zeek DPI recorder from the path entirely, which is the
    # design's central claim — left the whole suite green.
    world = json.loads((work / "world.json").read_text())
    prefs = {name: vm.get("prefs", {}) for name, vm in world.get("vms", {}).items()}

    def netvm_of(name: str) -> str:
        return prefs.get(name, {}).get("netvm", "")

    # qube -> sys-proxy -> sys-ids -> sys-dpi -> sys-firewall -> sys-net
    CHAIN = [("sys-proxy", "sys-ids"), ("sys-ids", "sys-dpi"),
             ("sys-dpi", "sys-firewall")]
    for downstream, upstream in CHAIN:
        stage(f"{downstream} routes through {upstream}",
              netvm_of(downstream) == upstream,
              f"{downstream} netvm is {netvm_of(downstream)!r}, not {upstream!r}"
              " — traffic would skip an inspection hop")

    # No clearnet qube may attach above sys-proxy. This is the property the
    # whole topology exists to enforce, so it is asserted over every qube
    # rather than over a list that could quietly stop including one.
    chain_members = {"sys-proxy", "sys-ids", "sys-dpi", "sys-firewall",
                     "sys-net", "sys-usb", "sys-whonix"}
    bypassing = sorted(
        name for name, p in prefs.items()
        if name not in chain_members
        and p.get("netvm") in ("sys-firewall", "sys-net"))
    stage("no clearnet qube bypasses the inspected chain", not bypassing,
          f"attached above sys-proxy: {', '.join(bypassing)}")

    # The Tor branch joins at the firewall and is deliberately uninspected.
    stage("sys-whonix joins at the firewall",
          netvm_of("sys-whonix") in ("sys-firewall", ""),
          f"sys-whonix netvm is {netvm_of('sys-whonix')!r}")

    # Offline qubes must have no netvm at all. An offline qube reports 'none',
    # not an empty string, so both spellings are accepted deliberately.
    for offline in ("vault", "dvm-offline"):
        if offline in prefs:
            stage(f"{offline} has no netvm",
                  netvm_of(offline) in ("", "none", "None"),
                  f"{offline} netvm is {netvm_of(offline)!r}")

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

    # ------------------------------------------------------------------
    # What the provisioner did INSIDE the qubes, read back off the recorded
    # actions. The stub answers every in-qube command 0, so nothing above can
    # tell a keyring fetched through the update proxy from one that fails with
    # "could not resolve host" on a real template, or a template committed
    # before its qubes were created from one still running with the packages
    # only in its live root.
    actions = [json.loads(line) for line in
               (work / "actions.jsonl").read_text().splitlines() if line.strip()]
    templates = {"debian-13-xfce", "fedora-43-xfce"} | {
        n for n in world["vms"] if n.startswith("tpl-")}
    # An invocation (`curl -…`), not the package name in an apt-get line.
    tpl_curl = [a for a in actions if a["kind"] == "qrun" and a["vm"] in templates
                and re.search(r"(?<![\w-])curl\s+-", a["script"])]
    bare = [a["vm"] + ": " + a["script"][:50] for a in tpl_curl
            if "--proxy http://127.0.0.1:8082" not in a["script"]]
    stage("templates fetch repository keys through the Qubes update proxy",
          bool(tpl_curl) and not bare,
          "templates have no netvm, so a bare curl fails there: " + "; ".join(bare))

    def first(pred):
        return next((i for i, a in enumerate(actions) if pred(a)), None)

    def last(pred):
        hits = [i for i, a in enumerate(actions) if pred(a)]
        return hits[-1] if hits else None

    def shutdown_of(vm):
        return lambda a: a["kind"] == "exec" and a["prog"] == "qvm-shutdown" and vm in a["argv"]

    def qrun_in(vm, needle):
        return lambda a: a["kind"] == "qrun" and a["vm"] == vm and needle in a["script"]

    last_install = last(qrun_in("tpl-proxy", "apt-get install"))
    first_chain = first(qrun_in("sys-proxy", ""))
    committed = next((i for i, a in enumerate(actions) if shutdown_of("tpl-proxy")(a)
                      and last_install is not None and i > last_install), None)
    stage("templates are shut down after their packages are installed and before "
          "the chain qubes are configured",
          None not in (last_install, first_chain, committed) and committed < first_chain,
          f"install@{last_install} shutdown@{committed} sys-proxy@{first_chain} — a qube "
          "created from a running template boots the template's OLD root")

    kali = [a["script"] for a in actions if a["kind"] == "qrun" and a["vm"] == "tpl-kali"]
    up = next((i for i, s in enumerate(kali) if "dist-upgrade" in s), None)
    ins = next((i for i, s in enumerate(kali) if "--allow-downgrades" in s
                and "kali-menu" in s and "kali-linux-default" in s), None)
    stage("the Kali template is dist-upgraded to Kali before the toolset is "
          "installed, as upstream's template does",
          up is not None and ins is not None and up < ins, f"upgrade@{up} install@{ins}")
    stage("no apt call asks for -t kali-rolling against a Debian-preferring pin",
          not any("-t kali-rolling" in s for s in kali))
    pin = work / "capture" / "tpl-kali" / "etc/apt/preferences.d/allow-downgrade"
    stage("Kali is pinned at 1001 for the install, as upstream's template does",
          pin.is_file() and "Pin-Priority: 1001" in pin.read_text()
          and "o=Kali" in pin.read_text(), "no allow-downgrade pin captured")
    stage("the old Debian-over-Kali pin is not written",
          not (work / "capture" / "tpl-kali" / "etc/apt/preferences.d/99-kali-pin").exists())

    pers = [a["script"] for a in actions if a["kind"] == "qrun" and a["vm"] == "personal"]
    mnt = next((i for i, s in enumerate(pers) if "mount --bind" in s
                and "/rw/bind-dirs/var/ossec" in s), None)
    conf = next((i for i, s in enumerate(pers) if "ossec.conf" in s), None)
    stage("the agent's /var/ossec is bind-mounted from /rw before it is enrolled",
          mnt is not None and conf is not None and mnt < conf,
          f"mount@{mnt} configure@{conf} — written into the volatile root, the "
          "enrollment is gone at the next boot")
    hook = work / "capture" / "personal" / "rw/config/golden-image-agent.sh"
    stage("the agent boot hook honours the case-mode marker",
          hook.is_file() and "golden-agent-masked" in hook.read_text()
          and "exit" not in hook.read_text(),
          "the hook is sourced by rc.local: no exit, and the marker must be checked")

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

    # A floor on how much --verify actually checks. Without one, deleting whole
    # acceptance groups from golden_image.py — chain order, clearnet bypass,
    # offline netvm — left the suite completely green: every remaining stage
    # only asked whether the command ran and whether its exit code agreed with
    # its own summary, both of which stay true as the suite shrinks.
    plain = re.sub(r"\x1b\[[0-9;]*m", "", p3.stdout)
    counts = {word: int(n) for n, word in
              re.findall(r"(\d+)\s+(passed|warnings|failed)", plain)}
    executed = sum(counts.get(k, 0) for k in ("passed", "warnings", "failed"))
    stage("--verify reports a countable result", bool(counts), plain[-300:])
    stage(f"--verify runs at least {ACCEPTANCE_FLOOR} checks",
          executed >= ACCEPTANCE_FLOOR,
          f"only {executed} acceptance checks executed "
          f"({counts}) — groups have been removed or are silently skipping")

    # The count alone is too blunt: deleting one group costs only the handful
    # of checks it contributed and stays above any floor loose enough not to be
    # brittle. So the groups that carry the design's security claims are named.
    # Deleting one has to fail, not merely lower a number.
    REQUIRED_GROUPS = [
        "every qube and template this design requires exists",
        "chain order",
        "no clearnet qube bypasses the inspection stack",
        "offline qubes have no netvm",
        "Wazuh agent present in every template",
        "supply chain integrity",
        "DNS enforcement",
        "inspection services",
        "proxy logs the originating qube",
        "Tor branch",
        "backup",
        "credentials",
    ]
    absent = [g for g in REQUIRED_GROUPS if g not in plain]
    stage("every acceptance group is still present", not absent,
          f"--verify no longer runs: {'; '.join(absent)}")
    # personal and work carry `accept specialtarget=dns` + drop, enforced in
    # their netvm, so a probe from them never reaches the intercept and fails
    # a working chain. The probe has to come from a qube without those rules.
    stage("DNS interception is probed from a qube without the per-qube DNS rule",
          re.search(r"every port-53 query from (kali-clear|untrusted) is captured",
                    plain) is not None,
          "group 7 does not probe from kali-clear or untrusted")

    print("\ncase mode")
    (work / "actions.jsonl").write_text("")
    pa = run(gi, ["--case-mode", "anonymous", "--case", "T-1"], env, sandbox)
    pn = run(gi, ["--case-mode", "normal", "--case", "T-1"], env, sandbox)
    case_acts = [json.loads(line) for line in
                 (work / "actions.jsonl").read_text().splitlines() if line.strip()]
    tor = [a["script"] for a in case_acts if a["kind"] == "qrun" and a["vm"] == "kali-tor"]
    on = next((i for i, s in enumerate(tor) if s.strip() == "touch /rw/config/golden-agent-masked"), None)
    off = next((i for i, s in enumerate(tor) if s.strip() == "rm -f /rw/config/golden-agent-masked"), None)
    stage("--case-mode anonymous/normal both run", pa.returncode == 0 and pn.returncode == 0,
          pa.stderr[-300:] + pn.stderr[-300:])
    stage("anonymous leaves a marker in /rw that survives a reboot, normal removes it",
          on is not None and off is not None and on < off,
          "systemctl mask alone lives in the volatile root and the boot hook "
          "would have restarted the agent mid-case")

    print("\ninitial setup (unattended first boot, before any wizard)")
    build_world(work / "world.json")
    fresh = json.loads((work / "world.json").read_text())
    for tpl in ("debian-13-xfce", "fedora-43-xfce"):
        fresh["vms"].pop(tpl, None)
    (work / "world.json").write_text(json.dumps(fresh, indent=2) + "\n")
    dom0 = Path(env["GOLDEN_IMAGE_DOM0_ROOT"])
    pkgs = dom0 / "var/lib/qubes/template-packages"
    pkgs.mkdir(parents=True, exist_ok=True)
    shipped = ("qubes-template-debian-13-xfce-4.3.0-202609010000.noarch.rpm",
               "qubes-template-fedora-43-xfce-4.3.0-202609010000.noarch.rpm")
    for rpm in shipped:
        (pkgs / rpm).write_bytes(b"rpm")
    kernels = dom0 / "var/lib/qubes/vm-kernels"
    for k in ("6.6.9-1.qubes.fc41.x86_64", "6.12.31-1.qubes.fc41.x86_64", "misc-1.0"):
        (kernels / k).mkdir(parents=True, exist_ok=True)
    (work / "actions.jsonl").write_text("")
    pi = run(gi, ["--initial-setup"], env, sandbox)
    stage("--initial-setup exits 0 on a fresh install with no templates yet",
          pi.returncode == 0, pi.stderr[-400:] + pi.stdout[-400:])
    setup_acts = [json.loads(line) for line in
                  (work / "actions.jsonl").read_text().splitlines() if line.strip()]
    execs = [(i, a["prog"], a["argv"]) for i, a in enumerate(setup_acts) if a["kind"] == "exec"]

    def at(prog, *needles):
        return next((i for i, p_, av in execs
                     if p_ == prog and all(nd in av for nd in needles)), None)

    i_tpl = at("qvm-template", "install", "--nogpgcheck")
    i_kernel = at("qubes-prefs", "default-kernel", "6.12.31-1.qubes.fc41.x86_64")
    i_deftpl = at("qubes-prefs", "default-template", "debian-13-xfce")
    i_enable = at("qubesctl", "top.enable", "qvm.sys-net")
    i_high = at("qubesctl", "--all", "state.highstate")
    i_disable = at("qubesctl", "top.disable", "qvm.sys-net")
    i_netvm = at("qubes-prefs", "default-netvm", "sys-firewall")
    after = json.loads((work / "world.json").read_text())["vms"]
    stage("the shipped template RPMs are installed with qvm-template --nogpgcheck",
          i_tpl is not None and all(after.get(t, {}).get("class") == "TemplateVM"
                                    for t in ("debian-13-xfce", "fedora-43-xfce")),
          "without them qvm.sys-net has nothing to base sys-net on")
    stage("the newest VM kernel becomes default-kernel (compared as a version, "
          "so 6.12 beats 6.6)", i_kernel is not None)
    stage("default-template is the Debian base", i_deftpl is not None)
    stage("initial setup runs the wizard's sequence in the wizard's order",
          None not in (i_tpl, i_deftpl, i_enable, i_high, i_disable, i_netvm)
          and i_tpl < i_deftpl < i_enable < i_high < i_disable < i_netvm,
          f"template@{i_tpl} default-template@{i_deftpl} enable@{i_enable} "
          f"highstate@{i_high} disable@{i_disable} default-netvm@{i_netvm}")
    stage("updatevm and clockvm are set like the wizard sets them",
          at("qubes-prefs", "updatevm", "sys-firewall") is not None
          and at("qubes-prefs", "clockvm", "sys-net") is not None)
    stage("the template RPMs are removed once installed, as the wizard removes them",
          not pkgs.exists())
    (work / "actions.jsonl").write_text("")
    pi2 = run(gi, ["--initial-setup"], env, sandbox)
    again = [json.loads(line) for line in
             (work / "actions.jsonl").read_text().splitlines() if line.strip()]
    stage("--initial-setup is idempotent: a retry installs nothing twice",
          pi2.returncode == 0 and not any(a["kind"] == "exec" and a["prog"] == "qvm-template"
                                          for a in again),
          pi2.stderr[-300:])

    # ------------------------------------------------------------------
    # The unwired edition: the same templates and payloads, and nothing
    # wired. Run in its own world so nothing above can satisfy it.
    print("\nunwired edition")
    uwork = work / "unwired"
    usand = uwork / "repo"
    usand.mkdir(parents=True)
    shutil.copy2(ROOT / "golden_image.py", usand / "golden_image.py")
    (usand / "golden-image.json").write_text(json.dumps({"edition": "unwired"}))
    ugi = usand / "golden_image.py"
    build_world(uwork / "world.json")
    uenv = make_env(uwork)
    pu = run(ugi, [], uenv, usand)
    stage("unwired: the run exits 0", pu.returncode == 0,
          f"rc={pu.returncode} " + pu.stderr[-400:] + pu.stdout[-400:])
    ustate = Path(uenv["HOME"]) / "golden-image" / ".build-state"
    umarks = sorted(ustate.read_text().split()) if ustate.exists() else []
    stage("unwired: exactly phases 1, 3, 4 and 5 ran",
          umarks == ["phase:1", "phase:3", "phase:4", "phase:5"], " ".join(umarks))
    stage("unwired: no credentials are generated",
          not (Path(uenv["HOME"]) / "golden-image" / "credentials.json").exists())
    uacts = [json.loads(line) for line in
             (uwork / "actions.jsonl").read_text().splitlines() if line.strip()]
    wiring = [" ".join([a["prog"], *a["argv"]]) for a in uacts
              if a["kind"] == "exec" and (
                  a["prog"] in ("qvm-create", "qvm-firewall")
                  or (a["prog"] == "qvm-prefs" and "netvm" in a["argv"]))]
    stage("unwired: no qube is created and no netvm or firewall is touched",
          not wiring, "; ".join(wiring[:5]))
    uworld = json.loads((uwork / "world.json").read_text())["vms"]
    utpls = ("tpl-sys", "tpl-proxy", "tpl-ids", "tpl-kali", "tpl-personal", "tpl-wazuh")
    stage("unwired: every template is built", all(t in uworld for t in utpls),
          f"missing: {[t for t in utpls if t not in uworld]}")
    stock = {"debian-13-xfce", "fedora-43-xfce", "whonix-gateway-18",
             "whonix-workstation-18"}
    touched = sorted({v for a in uacts if a["kind"] == "exec" and a["prog"] == "qvm-run"
                      for v in a["argv"] if v in stock})
    stage("unwired: nothing runs inside the stock templates", not touched,
          f"qvm-run into {', '.join(touched)}")
    journal = [" ".join(a["argv"]) for a in uacts
               if a["kind"] == "exec" and a["prog"] == "logger"]
    stage("unwired: every phase reports its progress to the journal",
          any("phase 1 (1/4, 0% done)" in j for j in journal)
          and any("phase 5 (4/4, 75% done)" in j for j in journal)
          and any("provisioning run finished" in j for j in journal),
          "; ".join(journal[:6]))
    stage("unwired: the handover points at the workstation guide",
          "WORKSTATION-GUIDE.md" in pu.stdout, pu.stdout[-400:])
    pv = run(ugi, ["--verify"], uenv, usand)
    # The stub reports /var/ossec absent in every template (see build_world),
    # so this asserts the unwired checks RUN — phase completion and every
    # template's presence — not that stub qubes carry real payloads.
    pvt = re.sub(r"\x1b\[[0-9;]*m", "", pv.stdout)
    stage("unwired: --verify checks the templates, not the wired estate",
          pv.returncode in (0, 2) and "not complete" not in pvt
          and all(f"template {t} exists" in pvt for t in utpls)
          and "sys-proxy" not in pvt,
          f"rc={pv.returncode} " + pvt[-400:])
    pp = run(ugi, ["--phase", "6"], uenv, usand)
    stage("unwired: a wiring phase is refused, not run",
          pp.returncode == 1 and "not part of the unwired edition" in pp.stderr,
          f"rc={pp.returncode} " + pp.stderr[-300:])
    ph = run(ugi, ["--handover"], uenv, usand)
    stage("unwired: credential commands say there are none",
          ph.returncode == 1 and "generates no credentials" in ph.stderr,
          f"rc={ph.returncode} " + ph.stderr[-300:])
    pw = run(ugi, ["--edition", "wired"], uenv, usand)
    uworld = json.loads((uwork / "world.json").read_text())["vms"]
    stage("unwired: --edition wired completes the topology later",
          pw.returncode in (0, 2) and "sys-proxy" in uworld,
          f"rc={pw.returncode} " + pw.stderr[-400:])
    stage("unwired: --edition wired is recorded for every later command",
          json.loads((usand / "golden-image.json").read_text()).get("edition") == "wired"
          and "edition: wired" in run(ugi, ["--status"], uenv, usand).stdout)

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

    print("\nbuild host")
    # -B: these run from inside the checkout, and a __pycache__ left behind
    # shows up as untracked files in the tree the harness is testing.
    ph = subprocess.run([sys.executable, "-B", str(TESTS / "host_checks.py")],
                        capture_output=True, text=True, cwd=ROOT)
    print(ph.stdout.rstrip())
    # A traceback goes to stderr. Swallowing it turned a crashed check script
    # into a bare "see output above" with no output above.
    if ph.stderr.strip():
        print(ph.stderr.rstrip())
    stage("build_iso.py supports the hosts it claims to", ph.returncode == 0,
          "see output above")

    print("\nconfiguration")
    # -B: these run from inside the checkout, and a __pycache__ left behind
    # shows up as untracked files in the tree the harness is testing.
    pc = subprocess.run([sys.executable, "-B", str(TESTS / "config_checks.py")],
                        capture_output=True, text=True, cwd=ROOT)
    print(pc.stdout.rstrip())
    # A traceback goes to stderr. Swallowing it turned a crashed check script
    # into a bare "see output above" with no output above.
    if pc.stderr.strip():
        print(pc.stderr.rstrip())
    stage("the code and its configuration agree", pc.returncode == 0,
          "see output above")

    print("\ndocumentation")
    # -B: these run from inside the checkout, and a __pycache__ left behind
    # shows up as untracked files in the tree the harness is testing.
    p7 = subprocess.run([sys.executable, "-B", str(TESTS / "doc_checks.py")],
                        capture_output=True, text=True, cwd=ROOT)
    print(p7.stdout.rstrip())
    # A traceback goes to stderr. Swallowing it turned a crashed check script
    # into a bare "see output above" with no output above.
    if p7.stderr.strip():
        print(p7.stderr.rstrip())
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
