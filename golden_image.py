#!/usr/bin/env python3
"""
golden_image.py — InQubestigationOS provisioner

Runs in DOM0 on each investigator workstation. Builds the inspection chain,
templates, SIEM, segmentation and backups described in the design document.

Self-contained: stdlib only, no pip installs (dom0 has no network by design).
Configuration is embedded and written to golden-image.json on first run; your
edits are never overwritten.

    sudo ./golden_image.py --write-config     # emit the config, review, edit
    sudo ./golden_image.py --dry-run          # print every action, change nothing
    sudo ./golden_image.py                    # build (resumable)
    sudo ./golden_image.py --from-phase 7     # resume after a failure
    sudo ./golden_image.py --verify           # acceptance tests only

NOT TESTED against a live Qubes 4.3.1 system. Run --dry-run, read it, then
run for real on a throwaway install before this touches an issued laptop.
Items printed as [VERIFY] are upstream details to confirm.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shlex
import string
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

# ===========================================================================
#  Embedded default configuration
# ===========================================================================
DEFAULT_CONFIG: dict = {
    "image_name": "InQubestigationOS",
    "image_version": "2.2",
    "expect_qubes_release": "4.3",

    # Base templates. Verified against qubes-release release4.3 comps-dom0.xml,
    # which pins @debian to debian-13-xfce and @fedora to fedora-43-xfce.
    #
    # Qubes 4.3 shipped with Fedora 42; fedora-43 was added 2026-02 and
    # fedora-44 2026-07, so 42/43/44 ALL exist for 4.3 — choose deliberately
    # rather than assuming "latest". debian-13-xfce is the default Debian
    # template (bare debian-13 is the GNOME build). dom0 itself is Fedora 41.
    "base_debian": "debian-13-xfce",
    "base_fedora": "fedora-43-xfce",
    "base_whonix_gw": "whonix-gateway-18",
    "base_whonix_ws": "whonix-workstation-18",

    # Debian everywhere it is possible.
    #
    # dom0 is Fedora and CANNOT be changed — Qubes builds dom0 on Fedora and
    # there is no Debian dom0. That is architecture, not a setting. Everything
    # ELSE in this image is Debian:
    #   * tpl-sys (sys-net, sys-firewall, sys-usb) cloned from Debian, not
    #     Fedora. Verified supported: the Qubes Debian template installs
    #     qubes-vm-recommended, which depends on qubes-core-agent-networking,
    #     qubes-core-agent-network-manager and qubes-usb-proxy, and its package
    #     list carries firmware-linux, network-manager and nftables.
    #   * Whonix is already Debian (Whonix 18 is built on Debian trixie).
    #   * Every custom template derives from debian-13-xfce.
    # Result: one distribution, one package manager, one update cadence, one
    # Wazuh repository type across the whole estate.
    "prefer_debian": True,

    # Whether the stock Fedora template is part of this estate at all.
    #   false (default): it is left alone — no agent, not covered by the
    #          acceptance tests, and nothing is based on it. One distribution.
    #   true:  it is treated as a template in service — it receives a Wazuh
    #          agent and phase 12 asserts on it, so "an agent in every
    #          template" stays true of the set you actually run.
    "use_fedora_template": False,

    "tpl": {
        "sys": "tpl-sys",
        "proxy": "tpl-proxy",
        "ids": "tpl-ids",
        "kali": "tpl-kali",
        "personal": "tpl-personal",
        "wazuh": "tpl-wazuh",
    },
    "qube": {
        "proxy": "sys-proxy",
        "ids": "sys-ids",
        "dpi": "sys-dpi",
        "firewall": "sys-firewall",
        "net": "sys-net",
        "usb": "sys-usb",
        "whonix": "sys-whonix",
        "wazuh": "wazuh-srv",
        "kali_clear": "kali-clear",
        "kali_tor": "kali-tor",
        "dvm_offline": "dvm-offline",
    },

    # If these template names already exist (baked in by a Tier 2 ISO), the
    # matching build phase is skipped instead of rebuilding from network.
    "prebuilt_templates": {
        "kali": "investigator-kali",
        "personal": "investigator-office",
        "ids": "investigator-ids",
        "proxy": "investigator-proxy",
    },

    # --- supply chain, verified 2026-09-01 against vendor primary sources ---
    "kali": {
        "repo_line": "deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] https://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware",
        "keyring_url": "https://archive.kali.org/archive-keyring.gpg",
        "keyring_path": "/usr/share/keyrings/kali-archive-keyring.gpg",
        # 827C...E4C5 IS the CURRENT 2025 key (rsa4096, 2025-04-17, expires
        # 2028-04-17), short id ED65462EC8D5E4C5. The retired key is
        # 44C6513A...0BF6 (short ED444FF07D8D0BF6, expires 2027-02-04), still
        # shipped in the keyring so older releases still verify.
        "key_fpr": "827C8569F2518CC677FECA1AED65462EC8D5E4C5",
        "key_fpr_legacy": "44C6513A8E4FB3D30875F758ED444FF07D8D0BF6",
        "keyring_sha1": "603374c107a90a69d983dbcb4d31e0d6eedfc325",
        "keyserver_url": "https://keyserver.ubuntu.com/pks/lookup?search=827C8569F2518CC677FECA1AED65462EC8D5E4C5&fingerprint=on&op=index",
        "metapackage": "kali-linux-default",
    },
    "zeek": {
        "repo_line": "deb [signed-by=/usr/share/keyrings/security_zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/Debian_13/ /",
        "key_url": "https://download.opensuse.org/repositories/security:zeek/Debian_13/Release.key",
        # The openSUSE Build Service is outside the Zeek project's control, so
        # this key deserves the same gate as the Kali and Wazuh ones rather than
        # "whatever came back over TLS". Confirmed 2026-09-08; expires
        # 2026-12-02, which golden-key-expiry.timer and check-upstream both
        # watch. Blank disables the check and says so.
        "key_fpr": "F9FA0223B56B116C363737EF5DA57BDD6DD785CA",
        # NOT /etc/apt/trusted.gpg.d: a key there is a global trust anchor and
        # apt accepts ANY repository signed by it. The openSUSE Build Service is
        # outside the Zeek project's control, so its key is scoped to the Zeek
        # repository alone via signed-by= on the line below.
        "keyring_path": "/usr/share/keyrings/security_zeek.gpg",
        # NOT "zeek-8.0": that OBS package is frozen at 8.0.1-0. The 8.0 LTS
        # line is published as "zeek-lts" and is currently 8.0.10-0, i.e. nine
        # point releases of fixes the DPI recorder would otherwise never see.
        # ("zeek" itself tracks the feature line, 8.2.2-0 today — not what you
        # want when predictable log formats matter more than new features.)
        "package": "zeek-lts",
        "prefix": "/opt/zeek",
    },
    "wazuh": {
        "version": "4.14.7",
        "key_url": "https://packages.wazuh.com/key/GPG-KEY-WAZUH",
        # Verified the same way as the Kali key: whatever comes back from the
        # network is checked against this fingerprint before it is trusted to
        # sign packages for a police workstation. Blank disables the check and
        # says so loudly. Confirm against the Wazuh installation guide before
        # changing it; ./build_iso.py check-upstream reports drift.
        "key_fpr": "0DCFCA5547B19D2A6099506096B3EE5F29111145",
        "keyring_path": "/usr/share/keyrings/wazuh.gpg",
        "apt_repo_line": "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main",
        "yum_baseurl": "https://packages.wazuh.com/4.x/yum/",
        # Wazuh guarantee compatibility only when manager >= agent. These
        # templates update weekly, so an unpinned agent WILL overtake the
        # manager and every agent stops reporting. Do not disable casually.
        "pin_agent": True,
        # "local"   — a wazuh-srv qube on this machine.
        # "central"  — agents report to central_address instead.
        # "auto"     — local if the machine has the RAM for it (phase 1 already
        #              measures that), central otherwise, and it says which it
        #              chose. A 16 GB laptop running a local indexer is a laptop
        #              that swaps during casework.
        "mode": "local",            # "local" | "central" | "auto"
        "central_address": "",
        "ip": "10.137.0.50",
        "port_events": 1514,
        "port_enroll": 1515,
        # The two vendor scripts phase 8 runs as root inside wazuh-srv. Pinned
        # by checksum, confirmed 2026-09-08 for the 4.14 series; blank disables
        # the check and says so. check-upstream reports drift.
        "certs_tool_sha256": "8c93ed36d7b956a6e97a906aed6b6bc636d7cb55a15a41fd6e9c2aa825164216",
        "passwords_tool_sha256": "29ce567ce1bcb4629a34f3ccfcaec7463a5418bcdd0ee96db5e25dbc0340f8eb",
        "mem": 4096, "maxmem": 8192, "vcpus": 2, "root_gb": 60,
    },

    "dns": {
        "mode": "dot",              # "dot" (unbound DoT->Quad9) | "plain"
        "primary": "9.9.9.9",
        "secondary": "149.112.112.112",
        "tls_name": "dns.quad9.net",
    },
    # "closed": Suricata down => chain stops. Nothing passes uninspected.
    # "open":   nft bypass; traffic flows if Suricata dies.
    "ips_failure_mode": "closed",

    "resources": {
        "ids_mem": 1024, "ids_maxmem": 3072, "ids_vcpus": 2,
        "proxy_mem": 512, "proxy_maxmem": 2048,
    },

    "credentials": {
        # false (recommended): unique random secrets per build.
        # true: fixed shared strings. Isolated lab only.
        "use_fixed_defaults": False,
        "fixed": {
            "dashboard": "ChangeMe-Dashboard-01",
            "api": "ChangeMe-Api-01",
            "authd": "ChangeMe-Enroll-01",
            "backup": "ChangeMe-Backup-01",
        },
    },
    "backup": {
        "dest_qube": "sys-usb",
        "dest_dir": "/mnt/backup",
        "schedule": "Sun 03:00",
        # Sets older than this are pruned by the weekly wrapper. 0 disables
        # pruning; the destination then fills up on its own schedule.
        "keep_sets": 4,
        # The backup disk is identified by filesystem LABEL, never by device
        # node, and mounts itself when it appears. Label it once:
        #     sudo mkfs.ext4 -L GOLDEN-BACKUP /dev/sdX1
        "media_label": "GOLDEN-BACKUP",
    },
    # Days after provisioning at which the login banner starts saying this image
    # is stale. An ISO freezes dom0, Xen and the kernel at build time.
    "staleness_warn_days": 120,
    "timeouts": {"short": 300, "long": 5400},
}

BUILD_DIR = Path.home() / "golden-image"
CONF_PATH = Path(__file__).resolve().parent / "golden-image.json"

# Every dom0 path this script reads or writes goes through dom0(). In normal
# operation the prefix is "/" and dom0("/etc/qubes") is /etc/qubes. The test
# harness points GOLDEN_IMAGE_DOM0_ROOT at a synthetic tree so the twelve
# phases can be exercised end to end on a machine that is not Qubes — which is
# what makes the acceptance claims in docs/REVIEW.md reproducible in CI.
DOM0_ROOT = Path(os.environ.get("GOLDEN_IMAGE_DOM0_ROOT", "/"))
TEST_ROOT = DOM0_ROOT != Path("/")


def dom0(path: str) -> Path:
    return DOM0_ROOT / path.lstrip("/")


def assert_test_root_is_deliberate(args) -> None:
    """A synthetic dom0 root satisfies the 'am I in dom0?' guard, while the
    qvm-* calls still go to the real machine. That combination must never
    happen by accident, so it needs an explicit flag as well as the variable,
    and it announces itself in red."""
    if not TEST_ROOT:
        return
    if not getattr(args, "test_root", False):
        print(f"{Out.R}GOLDEN_IMAGE_DOM0_ROOT is set to {DOM0_ROOT}.{Out.RST}\n"
              "This redirects every dom0 file read and write into a synthetic tree\n"
              "while qvm-* commands still reach the real machine. It exists for the\n"
              "test harness only. Pass --test-root if that is genuinely what you want.",
              file=sys.stderr)
        sys.exit(2)
    print(f"{Out.R}{Out.B}"
          f"══ TEST ROOT: dom0 files go to {DOM0_ROOT}, qvm-* commands do not ══"
          f"{Out.RST}")


# ===========================================================================
#  Output
# ===========================================================================
class Out:
    RST, B, R, G, Y, C, D = (
        "\033[0m", "\033[1m", "\033[31m", "\033[32m",
        "\033[33m", "\033[36m", "\033[2m",
    )

    def __init__(self, log_path: Path, enabled: bool = True):
        self.log_path = log_path
        self.enabled = enabled
        self.verify_notes: list[str] = []
        # Values that must never reach the log. Commands are logged verbatim
        # for auditability, and several of them legitimately carry a generated
        # secret on the command line, so the redaction happens at the writer.
        self._secrets: set[str] = set()
        if not enabled:
            return
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            # The log records every command run against every qube. It is not
            # world-readable, and it is listed beside credentials.json in the
            # shred instructions.
            fd = os.open(log_path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
            os.close(fd)
            os.chmod(log_path, 0o600)
        except OSError:
            pass

    def guard(self, *values: str) -> None:
        """Register values that must be redacted out of every log line."""
        for v in values:
            if v and len(v) >= 8:
                self._secrets.add(v)

    def _redact(self, line: str) -> str:
        for v in self._secrets:
            line = line.replace(v, "«redacted»")
        return line

    def _log(self, line: str) -> None:
        if not self.enabled:
            return
        try:
            with self.log_path.open("a") as fh:
                fh.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {self._redact(line)}\n")
        except OSError:
            pass

    def say(self, m=""):   print(m);                                  self._log(m)
    def info(self, m):     print(f"  {self.D}{m}{self.RST}");         self._log(f"INFO  {m}")
    def ok(self, m):       print(f"  {self.G}\u2713{self.RST} {m}");  self._log(f"OK    {m}")
    def skip(self, m):
        print(f"  {self.D}\u00b7{self.RST} {m} {self.D}(already present){self.RST}")
        self._log(f"SKIP  {m}")
    def warn(self, m):     print(f"  {self.Y}!{self.RST} {m}");       self._log(f"WARN  {m}")

    def verify(self, m):
        print(f"  {self.Y}?{self.RST} {self.Y}[VERIFY] {m}{self.RST}")
        self._log(f"VERIFY {m}")
        self.verify_notes.append(m)

    def phase(self, n, name):
        print(f"\n{self.B}{self.C}\u2550\u2550 Phase {n} \u2014 {name}{self.RST}")
        self._log(f"PHASE {n} {name}")

    def phase_skipped(self, n, name):
        print(f"\n{self.D}\u2550\u2550 Phase {n} \u2014 {name} (done, skipping "
              f"\u2014 --from-phase {n} to redo){self.RST}")
        self._log(f"PHASE {n} {name} SKIPPED (already marked complete)")


class Fatal(Exception):
    pass


# ===========================================================================
#  Runner — every state-changing action goes through here
# ===========================================================================
class Runner:
    def __init__(self, out: Out, dry_run: bool, timeout_long: int,
                 timeout_short: int = 300):
        self.out = out
        self.dry_run = dry_run
        # timeouts.long covers the in-qube installs that genuinely take an hour.
        # Everything else — a qvm-prefs, a file write, a predicate — gets the
        # short timeout, so a hung dom0 call fails in minutes rather than in an
        # hour and a half.
        self.timeout_long = timeout_long
        self.timeout_short = timeout_short
        # In a dry run nothing is actually created, so later phases would
        # wrongly conclude their inputs are missing and abort. Track what the
        # run *would* have created so the operator sees the whole plan.
        self.simulated: set[str] = set()

    def run(self, *argv: str, check: bool = True, capture: bool = False,
            timeout: int | None = None) -> str:
        cmd = list(argv)
        if self.dry_run:
            print(f"  {Out.D}[dry-run]{Out.RST} {' '.join(shlex.quote(a) for a in cmd)}")
            return ""
        self.out._log("EXEC  " + " ".join(cmd))
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               stdin=subprocess.DEVNULL,
                               timeout=timeout or self.timeout_short)
        except subprocess.TimeoutExpired:
            raise Fatal(f"timed out after "
                        f"{timeout or self.timeout_short}s: {' '.join(cmd)}")
        self.out._log(f"      rc={p.returncode} {p.stdout[-2000:]}{p.stderr[-2000:]}")
        if check and p.returncode != 0:
            raise Fatal(f"command failed: {' '.join(cmd)}\n     see {self.out.log_path}")
        return p.stdout if capture else ""

    def quiet(self, *argv: str) -> bool:
        """Run, return success. Never raises. Not gated by dry-run (read-only)."""
        try:
            p = subprocess.run(list(argv), capture_output=True, text=True,
                               stdin=subprocess.DEVNULL, timeout=self.timeout_short)
            return p.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    # --- qube helpers ------------------------------------------------------
    def qrun(self, vm: str, script: str, check: bool = True) -> None:
        """Run a shell snippet as root inside a qube."""
        if self.dry_run:
            print(f"  {Out.D}[dry-run]{Out.RST} {vm}: {script[:110]}")
            return
        self.out._log(f"QRUN  {vm} :: {script}")
        cmd = ["qvm-run", "--no-gui", "-u", "root", vm, f"bash -c {shlex.quote(script)}"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               stdin=subprocess.DEVNULL, timeout=self.timeout_long)
        except subprocess.TimeoutExpired:
            raise Fatal(f"in-qube command timed out in {vm}")
        self.out._log(f"      rc={p.returncode} {p.stdout[-2000:]}{p.stderr[-2000:]}")
        if check and p.returncode != 0:
            raise Fatal(f"in-qube command failed in '{vm}': {script[:160]}\n"
                        f"     see {self.out.log_path}")

    def qtest(self, vm: str, script: str, dry_default: bool = True) -> bool:
        """A predicate evaluated inside a qube.

        In a dry run nothing exists to ask, so the answer is a caller-supplied
        assumption. Callers whose guard reads "if NOT present, do the work"
        must pass dry_default=False, or the dry run silently plans nothing.
        """
        if self.dry_run:
            return dry_default
        cmd = ["qvm-run", "--no-gui", "-u", "root", vm, f"bash -c {shlex.quote(script)}"]
        try:
            return subprocess.run(cmd, capture_output=True,
                                  stdin=subprocess.DEVNULL,
                                  timeout=self.timeout_short).returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def qwrite(self, vm: str, path: str, content: str, mode: str = "0644") -> None:
        """Write a file into a qube from stdin."""
        if self.dry_run:
            print(f"  {Out.D}[dry-run]{Out.RST} write {vm}:{path} ({mode}, {len(content)} bytes)")
            return
        self.out._log(f"QWRITE {vm} :: {path}")
        inner = (f"mkdir -p {shlex.quote(str(Path(path).parent))} && "
                 f"cat > {shlex.quote(path)} && chmod {mode} {shlex.quote(path)}")
        cmd = ["qvm-run", "--no-gui", "--pass-io", "-u", "root", vm, inner]
        try:
            # Only add the trailing newline the file is missing. Appending one
            # unconditionally meant qwrite silently modified every file it
            # wrote, so a copy could never be byte-identical to its original.
            payload = content if content.endswith("\n") else content + "\n"
            p = subprocess.run(cmd, input=payload, capture_output=True,
                               text=True, timeout=self.timeout_short)
        except subprocess.TimeoutExpired:
            raise Fatal(f"writing {path} into {vm} timed out")
        if p.returncode != 0:
            raise Fatal(f"failed writing {path} into {vm}: {p.stderr[:300]}")

    # --- predicates --------------------------------------------------------
    def vm_exists(self, vm: str) -> bool:
        if self.dry_run and vm in self.simulated:
            return True
        return self.quiet("qvm-check", "--quiet", vm)

    def will_create(self, vm: str) -> None:
        """Record a qube this run creates, so dry-run planning stays coherent."""
        if self.dry_run:
            self.simulated.add(vm)

    def vm_running(self, vm: str) -> bool:
        return self.quiet("qvm-check", "--quiet", "--running", vm)

    def ensure_running(self, vm: str) -> None:
        """Start a qube and wait until qrexec actually answers.

        A fixed sleep was both too long on a fast machine and too short on a
        slow one. Poll for the condition that matters — that the qube will
        accept a command — and give up after the short timeout.
        """
        if self.dry_run:
            print(f"  {Out.D}[dry-run]{Out.RST} start {vm}")
            return
        if self.vm_running(vm):
            return
        self.run("qvm-start", "--skip-if-running", vm, timeout=self.timeout_long)
        deadline = time.monotonic() + self.timeout_short
        while time.monotonic() < deadline:
            if self.quiet("qvm-run", "--no-gui", "-u", "root", vm, "true"):
                return
            time.sleep(2)
        self.out.warn(f"{vm} started but has not answered qrexec within "
                      f"{self.timeout_short}s — continuing, expect failures")

    def shutdown(self, vm: str) -> bool:
        """Shut a qube down. Returns False if it is still running afterwards —
        re-templating a running qube is refused, so the caller must know."""
        if self.dry_run or not self.vm_exists(vm):
            return True
        self.quiet("qvm-shutdown", "--wait", "--timeout", "60", vm)
        return not self.vm_running(vm)

    def prefs(self, vm: str, **kv) -> None:
        for k, v in kv.items():
            self.run("qvm-prefs", vm, k, str(v))


# ===========================================================================
#  Provisioner
# ===========================================================================
class Provisioner:
    PHASES = [
        "preflight checks",
        "credentials",
        "clone templates",
        "install template payloads",
        "wazuh agent in every template",
        "build inspection chain qubes",
        "configure inspection chain",
        "wazuh manager",
        "app qubes and netvm assignment",
        "dom0 policy, segmentation, backup",
        "agent enrollment",
        "acceptance tests",
    ]

    def __init__(self, cfg: dict, args):
        self.c = cfg
        self.args = args
        self.build_dir = BUILD_DIR
        if not args.dry_run:
            self.build_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.build_dir / ".build-state"
        self.cred_file = self.build_dir / "credentials.json"
        # "--dry-run: print every action, change nothing" includes the log.
        self.out = Out(self.build_dir / "build.log", enabled=not args.dry_run)
        self.r = Runner(self.out, args.dry_run, cfg["timeouts"]["long"],
                        cfg["timeouts"]["short"])
        self.creds: dict = {}
        self._load_creds()
        self.t = cfg["tpl"]
        self.q = cfg["qube"]
        self.tests = {"pass": 0, "fail": 0, "warn": 0}

    def _load_creds(self) -> None:
        """Read credentials.json if it exists.

        Phase 2 writes it, but a resumed run (--from-phase, --phase 8, or a
        second invocation after phase 2 was marked done) never calls p02, and
        every later phase that needs a secret would otherwise silently use "".
        That produced an empty dashboard admin password while printing success.
        """
        if not self.cred_file.exists():
            return
        try:
            self.creds = json.loads(self.cred_file.read_text())
        except (OSError, json.JSONDecodeError) as e:
            raise Fatal(f"{self.cred_file} exists but cannot be read: {e}\n"
                        "     Delete it to generate new secrets, or restore it "
                        "from your escrow.")
        self.out.guard(*(v for k, v in self.creds.items()
                         if isinstance(v, str) and not k.startswith("_")))

    def _need_secret(self, key: str, phase: int) -> str:
        """A secret this phase cannot proceed without."""
        val = self.creds.get(key, "")
        if not val:
            raise Fatal(
                f"phase {phase} needs the '{key}' secret but "
                f"{self.cred_file} has no usable value.\n"
                "     Run phase 2 first:  sudo ./golden_image.py --phase 2")
        return val

    # --- state -------------------------------------------------------------
    def _done(self, n: int) -> bool:
        if not self.state_file.exists():
            return False
        return f"phase:{n}" in self.state_file.read_text().split()

    def _mark(self, n: int) -> None:
        if not self.args.dry_run:
            with self.state_file.open("a") as fh:
                fh.write(f"phase:{n}\n")

    def _clear_marks_from(self, n: int) -> None:
        """--from-phase N means 'redo from N'. Leaving the completion marks in
        place made it a no-op: every phase from N on was skipped as done."""
        if self.args.dry_run or not self.state_file.exists():
            return
        keep = [t for t in self.state_file.read_text().split()
                if not (t.startswith("phase:") and t[6:].isdigit()
                        and int(t[6:]) >= n)]
        self.state_file.write_text("".join(f"{t}\n" for t in keep))

    def _should_run(self, n: int) -> bool:
        if self.args.verify:
            return n == 12
        if self.args.phase is not None:
            return n == self.args.phase
        if n < self.args.from_phase:
            return False
        if self._done(n) and not self.args.dry_run:
            self.out.phase_skipped(n, self.PHASES[n - 1])
            return False
        return True

    # =======================================================================
    #  1 — preflight
    # =======================================================================
    def p01(self):
        o, r = self.out, self.r
        # qvm-* works as an unprivileged user in dom0, so a run without sudo
        # re-templates the service qubes and rewires every netvm quite happily,
        # and only falls over later when it tries to write /root/.backup-pass.
        if os.geteuid() != 0 and not self.args.dry_run:
            raise Fatal("this must run as root — it writes dom0 policy, systemd "
                        "units and /root/.backup-pass.\n"
                        f"     sudo {Path(sys.argv[0]).name} "
                        f"{' '.join(sys.argv[1:])}")
        if not dom0("/etc/qubes-release").exists():
            raise Fatal("not running in dom0 — this script must run in dom0.")
        rel = dom0("/etc/qubes-release").read_text().strip()
        o.info(f"dom0 reports: {rel}")
        if self.c["expect_qubes_release"] not in rel and not self.args.force:
            raise Fatal(f"expected Qubes {self.c['expect_qubes_release']}, found: {rel}. "
                        "Use --force to override.")

        deb = self.c["base_debian"]
        if not r.vm_exists(deb):
            raise Fatal(f"required base template missing: {deb}\n"
                        "     Adjust 'base_debian' in golden-image.json. Note that "
                        "Qubes 4.3 ships xfce-flavoured templates.")
        o.ok(f"base template present: {deb}")

        fed = self.c["base_fedora"]
        if r.vm_exists(fed):
            if self.c["use_fedora_template"]:
                o.ok(f"Fedora template present and in use: {fed} — it will receive "
                     f"an agent and is covered by the acceptance tests")
            else:
                o.info(f"Fedora template present but not part of this estate: {fed}")
                o.info("  set use_fedora_template=true if you base qubes on it, so "
                       "it gets an agent and is tested")
        else:
            o.info(f"Fedora template {fed} not installed — fine, nothing needs it")

        o.info("dom0 is Fedora and cannot be changed — that is Qubes architecture.")
        o.info("Everything else in this image is Debian: service qubes, all custom")
        o.info("templates, and Whonix (which is built on Debian trixie).")
        for tpl_key in ("base_whonix_gw", "base_whonix_ws"):
            name = self.c[tpl_key]
            if r.vm_exists(name):
                o.ok(f"base template present: {name}")
            else:
                o.warn(f"Whonix template missing: {name} — the Tor branch will be skipped")

        for svc in (self.q["net"], self.q["firewall"]):
            if not r.vm_exists(svc):
                raise Fatal(f"{svc} missing — this is not a stock Qubes install")

        # Disk / RAM
        try:
            st = os.statvfs(dom0("/var/lib/qubes"))
            free_gb = st.f_bavail * st.f_frsize // (1024 ** 3)
            o.info(f"free space in /var/lib/qubes: {free_gb}G")
            if free_gb < 250:
                o.warn("under 250G free — the full image will be tight")
        except OSError:
            pass
        try:
            kb = int(next(l for l in Path("/proc/meminfo").read_text().splitlines()
                          if l.startswith("MemTotal")).split()[1])
            gb = kb // 1024 // 1024
            o.info(f"system RAM: {gb}G")
            if self.c["wazuh"]["mode"] == "auto":
                if gb >= 16:
                    self.c["wazuh"]["mode"] = "local"
                    o.ok(f"wazuh.mode=auto resolved to 'local' ({gb}G RAM)")
                elif self.c["wazuh"]["central_address"]:
                    self.c["wazuh"]["mode"] = "central"
                    o.ok(f"wazuh.mode=auto resolved to 'central' ({gb}G RAM) — "
                         f"agents will report to "
                         f"{self.c['wazuh']['central_address']}")
                else:
                    raise Fatal(
                        f"wazuh.mode is 'auto' and this machine has {gb}G RAM, "
                        f"which is too little for a local indexer.\n"
                        "     Set wazuh.central_address to a central manager, or "
                        "force wazuh.mode='local'\n     and accept that the SIEM "
                        "will compete with casework for memory.")
            elif gb < 16 and self.c["wazuh"]["mode"] == "local":
                o.warn("under 16G RAM with a local SIEM qube — consider "
                       "wazuh.mode='central', or 'auto' to decide per machine")
        except (OSError, StopIteration, ValueError):
            pass

        # Pinned SIEM address collision
        wip = self.c["wazuh"]["ip"]
        if not self.args.dry_run:
            # check=True: an empty result from a failed qvm-ls used to be
            # indistinguishable from "nothing uses this address", and the code
            # then printed 'free' either way.
            data = r.run("qvm-ls", "--raw-data", "--fields", "NAME,IP",
                         check=True, capture=True)
            if not data.strip():
                raise Fatal("qvm-ls returned nothing — cannot tell whether "
                            f"{wip} is free. Refusing to pin the SIEM address on "
                            "a guess.")
            for line in data.splitlines():
                parts = [f.strip() for f in line.split("|")]
                if len(parts) >= 2 and parts[1] == wip and parts[0] != self.q["wazuh"]:
                    raise Fatal(f"{wip} is already used by '{parts[0]}'. "
                                "Pick another wazuh.ip in golden-image.json.")
            o.ok(f"{wip} is free for {self.q['wazuh']}")

        # Tier 2 detection
        pre = self.c["prebuilt_templates"]
        found = [v for v in pre.values() if r.vm_exists(v)]
        if found:
            o.ok(f"Tier 2 templates already present: {', '.join(found)}")
            o.info("their build phases will be skipped; the chain is still wired here")

        o.info("firewall chains used: custom-forward and custom-input (both documented"
               " user hooks), plus a created custom-dnat-squid chain, plus a wholesale"
               " replacement of dnat-dns via /rw/config/qubes-firewall.d/")
        o.info("rules are asserted live in acceptance-test group 13 — "
               "no manual nft inspection needed")
        self._mark(1)

    # =======================================================================
    #  2 — credentials
    # =======================================================================
    @staticmethod
    def _secret(n: int = 24) -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(n))

    def p02(self):
        o = self.out
        if self.cred_file.exists() and not self.args.dry_run:
            o.skip("credentials.json exists — delete it to force new secrets")
            self._load_creds()
            self._mark(2)
            return

        cc = self.c["credentials"]
        if cc["use_fixed_defaults"]:
            o.warn("use_fixed_defaults is true — every laptop built from this config "
                   "shares the same secrets.")
            o.warn("Acceptable only for an isolated lab. Do not ship to issued hardware.")
            f = cc["fixed"]
            self.creds = {"dashboard": f["dashboard"], "api": f["api"],
                          "authd": f["authd"], "backup": f["backup"],
                          "_stamp": "FIXED DEFAULTS — SHARED ACROSS BUILDS — ROTATE NOW"}
        else:
            self.creds = {"dashboard": self._secret(), "api": self._secret(),
                          "authd": self._secret(), "backup": self._secret(48),
                          "_stamp": "generated uniquely for this machine at build time"}
            o.ok("generated four unique secrets for this build")

        o.guard(*(v for k, v in self.creds.items()
                  if isinstance(v, str) and not k.startswith("_")))
        if self.args.dry_run:
            o.info(f"[dry-run] would write {self.cred_file} (mode 600)")
            self._mark(2)
            return

        self.creds.update({
            "dashboard_user": "admin",
            "api_user": "wazuh-wui",
            "_host": os.uname().nodename,
            "_built": f"{datetime.now():%Y-%m-%d %H:%M:%S}",
        })
        old = os.umask(0o077)
        try:
            self.cred_file.write_text(json.dumps(self.creds, indent=2) + "\n")
            self.cred_file.chmod(0o600)
            (self.build_dir / "CREDENTIALS-README.txt").write_text(self._cred_readme())
        finally:
            os.umask(old)
        o.ok(f"wrote {self.cred_file} (mode 600)")

        try:
            dom0("/root/.backup-pass").parent.mkdir(parents=True, exist_ok=True)
            old_umask = os.umask(0o077)
            try:
                dom0("/root/.backup-pass").write_text(self.creds["backup"] + "\n")
            finally:
                os.umask(old_umask)
            dom0("/root/.backup-pass").chmod(0o600)
        except OSError as e:
            # Without this file the weekly backup cannot run unattended, and a
            # warning here used to let the build finish and the laptop ship with
            # a backup timer that fails every Sunday in silence.
            raise Fatal(f"could not write /root/.backup-pass ({e}).\n"
                        "     The weekly backup needs it. Are you running as root?")
        self._mark(2)

    def _cred_readme(self) -> str:
        me = Path(sys.argv[0]).name
        w, q = self.c["wazuh"], self.q
        return f"""\
credentials.json — {self.c['image_name']} v{self.c['image_version']}
Host: {os.uname().nodename}   Built: {datetime.now():%Y-%m-%d %H:%M:%S}
{self.creds.get('_stamp','')}

THIS IS THE ONLY COPY until you escrow it. Mode 600, dom0 only.
Never commit it to the provisioning repository.

HANDOVER — three commands, in this order
----------------------------------------
    sudo {me} --rotate-credentials
        Generates four new secrets and applies every one of them: the manager's
        enrollment password and each enrolled qube's copy, the dashboard admin
        password and the wazuh-wui API password through the Wazuh passwords
        tool, and the backup passphrase. If it cannot set the dashboard
        password it stops before writing anything, so the old values stay
        valid rather than this file and the machine disagreeing.

        The PREVIOUS backup passphrase is kept in this file afterwards, under
        _previous_backup_passphrase: existing backup sets still need it, for
        {self.c['backup']['keep_sets']} weeks.

    sudo {me} --escrow-credentials
        Copies this file into 'vault' — verifying the copy by SHA-256, and
        refusing outright if the target qube has a netvm — and records where
        it went. Copy the values into your unit's password process too: a
        vault qube is offline, but it is on the same disk as everything else.

    sudo {me} --shred-credentials
        Destroys the dom0 copy. It refuses without an escrow record, and
        re-verifies the escrowed copy before it touches anything. It shreds
        the build log as well, because that log records every command run
        against every qube.

Or all three at once, with one confirmation:  sudo {me} --handover

WHAT EACH SECRET IS
-------------------
dashboard   admin login for the Wazuh dashboard and indexer.
api         the wazuh-wui API user the dashboard authenticates with.
authd       agent enrollment password. Rotating it does not disturb agents
            that are already enrolled; it gates NEW registrations. Rotate
            whenever somebody leaves the team.
backup      passphrase for the weekly encrypted backup. NO PASSPHRASE, NO
            RESTORE — escrow it before anything else.

IF YOU HAVE TO DO IT BY HAND
----------------------------
You should not need to; --rotate-credentials exists so that the procedure is
the same on every machine. If you are recovering a machine where it failed:

  Dashboard / API   in {q['wazuh']}:
                        /opt/wazuh-passwords-tool.sh -u admin     -p 'NEW'
                        /opt/wazuh-passwords-tool.sh -u wazuh-wui -p 'NEW'
                    [VERIFY] the tool path for Wazuh {w['version']}.
  Enrollment        in {q['wazuh']}: write NEW to /var/ossec/etc/authd.pass,
                    mode 640, owner root:wazuh, then restart wazuh-manager.
                    Write the same value to every enrolled qube's copy.
  Backup            write NEW to dom0:/root/.backup-pass (mode 600). The
                    weekly wrapper reads it into the profile at run time.

Afterwards, put the new values in this file so the machine and the record
agree, and escrow it again — --shred-credentials refuses to proceed against
an escrow record that no longer matches.
"""

    # =======================================================================
    #  3 — clone templates
    # =======================================================================
    def _clone(self, src: str, dst: str, label: str) -> bool:
        o, r = self.out, self.r
        if r.vm_exists(dst):
            o.skip(dst)
            return True
        if not r.vm_exists(src):
            o.warn(f"source template {src} missing — skipping {dst}")
            return False
        o.info(f"cloning {src} -> {dst} (several minutes)")
        r.run("qvm-clone", src, dst, timeout=self.r.timeout_long)
        r.run("qvm-prefs", dst, "label", label)
        r.will_create(dst)
        o.ok(dst)
        return True

    def p03(self):
        pre, r, o = self.c["prebuilt_templates"], self.r, self.out
        deb, fed = self.c["base_debian"], self.c["base_fedora"]
        sys_src = deb if self.c["prefer_debian"] else fed
        if self.c["prefer_debian"]:
            o.info(f"{self.t['sys']} from Debian — service qubes stay on the same "
                   "distribution as everything else")
        made = [self._clone(sys_src, self.t["sys"], "orange")]
        for key, label in (("proxy", "orange"), ("ids", "orange"),
                           ("kali", "yellow"), ("personal", "green"),
                           ("wazuh", "blue")):
            src = deb
            if key in pre and r.vm_exists(pre[key]):
                src = pre[key]
                o.info(f"using Tier 2 template {src} as the source for {self.t[key]}")
            made.append(self._clone(src, self.t[key], label))
        # A template that could not be cloned means later phases have nothing to
        # install into. Marking the phase done anyway froze that state: the
        # resume path skipped it forever and the machine stayed half-built.
        if not all(made):
            raise Fatal("one or more templates could not be created (see the "
                        "warnings above). Phase 3 is NOT marked complete; fix the "
                        "missing base template and re-run.")
        self._mark(3)

    # =======================================================================
    #  4 — template payloads
    # =======================================================================
    #  What "already baked in" means, per template: a probe for something only
    #  that payload provides. Asking "does investigator-kali exist?" was not the
    #  same question — phase 3's clone short-circuits on the DESTINATION, so
    #  tpl-kali could be a plain Debian clone from an earlier run while the
    #  prebuilt template sat beside it untouched, and phase 4 would then skip
    #  the payload install and leave a Kali qube with no Kali in it.
    PAYLOAD_PROBE = {
        "kali": "test -f /etc/apt/sources.list.d/kali.list && command -v maltego",
        "personal": "command -v libreoffice",
        "ids": "command -v suricata",
        "proxy": "command -v squid",
    }

    def _tier2_ready(self, key: str) -> bool:
        tpl = self.t.get(key)
        probe = self.PAYLOAD_PROBE.get(key)
        if not tpl or not probe or not self.r.vm_exists(tpl):
            return False
        return self.r.qtest(tpl, probe, dry_default=False)

    def p04(self):
        o, r = self.out, self.r
        o.warn("templates reach the network through the Qubes update proxy (qrexec), "
               "not a netvm.")
        o.info("if apt fails with a proxy/CONNECT error on an HTTPS repo, "
               "temporarily assign the template a netvm, install, then clear it "
               "— a workaround, not something to verify")

        # --- office ---
        if self._tier2_ready("personal"):
            o.skip(f"{self.t['personal']} payload (baked in by the Tier 2 ISO)")
        else:
            o.info(f"{self.t['personal']}: LibreOffice suite and desktop tooling")
            r.qrun(self.t["personal"],
                   "export DEBIAN_FRONTEND=noninteractive; apt-get update && "
                   "apt-get install -y --no-install-recommends "
                   "libreoffice libreoffice-l10n-de libreoffice-help-de "
                   "hunspell-de-ch hyphen-de thunderbird keepassxc gimp vlc "
                   "pdfarranger p7zip-full unzip curl ca-certificates gnupg")
            o.ok(f"{self.t['personal']} payload installed")

        # --- sys template: service-qube packages ---
        # sys-net / sys-firewall / sys-usb need these. The full debian-13-xfce
        # template already pulls them via qubes-vm-recommended; a *minimal*
        # template does not. Installing explicitly makes either base work and
        # is a no-op when they are present.
        if r.vm_exists(self.t["sys"]) and self.c["prefer_debian"]:
            o.info(f"{self.t['sys']}: service-qube packages (networking, USB, firmware)")
            # Not check=False with an unconditional 'ok' afterwards: these are
            # the packages sys-net, sys-firewall and sys-usb need to function at
            # all, and the update-proxy CONNECT failure warned about above is
            # exactly the case that used to be swallowed and reported as done.
            r.qrun(self.t["sys"],
                   "export DEBIAN_FRONTEND=noninteractive; apt-get update && "
                   "apt-get install -y qubes-core-agent-networking "
                   "qubes-core-agent-network-manager qubes-usb-proxy "
                   "qubes-input-proxy-sender libpam-systemd unbound ca-certificates")
            # Firmware blobs are read from the TEMPLATE even though the kernel
            # comes from dom0. Without these, Wi-Fi in a Debian sys-net fails.
            r.qrun(self.t["sys"],
                   "export DEBIAN_FRONTEND=noninteractive; "
                   "apt-get install -y firmware-linux firmware-iwlwifi || "
                   "apt-get install -y firmware-linux-free || true", check=False)
            o.ok(f"{self.t['sys']} service-qube packages installed")
            o.info("group 13 checks for a wireless interface and for firmware load "
                   "failures in sys-net")

        # --- proxy ---
        if self._tier2_ready("proxy"):
            o.skip(f"{self.t['proxy']} payload (baked in)")
        else:
            o.info(f"{self.t['proxy']}: Squid + unbound")
            r.qrun(self.t["proxy"],
                   "export DEBIAN_FRONTEND=noninteractive; apt-get update && "
                   "(apt-get install -y squid-openssl ca-certificates openssl || "
                   " apt-get install -y squid ca-certificates openssl)")
            o.info("group 13 runs 'squid -k parse' against the peek/splice config")
            o.ok(f"{self.t['proxy']} payload installed")

        # --- ids ---
        if self._tier2_ready("ids"):
            o.skip(f"{self.t['ids']} payload (baked in)")
        else:
            z = self.c["zeek"]
            o.info(f"{self.t['ids']}: Suricata (Debian main)")
            r.qrun(self.t["ids"],
                   "export DEBIAN_FRONTEND=noninteractive; apt-get update && "
                   "apt-get install -y suricata suricata-update jq curl gnupg ca-certificates")
            o.info(f"{self.t['ids']}: {z['package']} from the Zeek project's OBS repository")
            o.warn("Zeek packages are signed by the openSUSE Build Service, outside the "
                   "Zeek project's control.")
            o.warn("When that key expires you must re-add it manually — monthly checklist.")
            r.qwrite(self.t["ids"], "/etc/apt/sources.list.d/security:zeek.list",
                     z["repo_line"])
            r.qrun(self.t["ids"],
                   f"curl -fsSL {shlex.quote(z['key_url'])} | gpg --dearmor "
                   f"> {shlex.quote(z['keyring_path'])} && chmod 644 {shlex.quote(z['keyring_path'])}")
            self._verify_keyring(self.t["ids"], z["keyring_path"],
                                 z.get("key_fpr", ""), "Zeek OBS")
            r.qrun(self.t["ids"],
                   f"export DEBIAN_FRONTEND=noninteractive; apt-get update && "
                   f"apt-get install -y {shlex.quote(z['package'])}")
            o.ok(f"{z['package']} installed (prefix {z['prefix']})")

        # --- kali ---
        if self._tier2_ready("kali"):
            o.skip(f"{self.t['kali']} payload (baked in)")
        else:
            self._install_kali()
        self._mark(4)

    def _install_kali(self):
        o, r, k = self.out, self.r, self.c["kali"]
        tpl = self.t["kali"]
        o.info(f"{tpl}: Kali archive keyring")
        r.qrun(tpl, "export DEBIAN_FRONTEND=noninteractive; apt-get update && "
                    "apt-get install -y curl ca-certificates gnupg")
        r.qrun(tpl, f"curl -fsSL {shlex.quote(k['keyring_url'])} -o "
                    f"{shlex.quote(k['keyring_path'])} && chmod 644 {shlex.quote(k['keyring_path'])}")

        if not self.args.dry_run:
            # --with-colons is the machine-readable form: one record per line,
            # 'fpr' records carry the fingerprint in field 10 and nothing else.
            # The previous check stripped ALL whitespace from the human-readable
            # output and looked for the fingerprint as a substring, so a key's
            # own attacker-controlled UID text could satisfy it.
            fpr_check = (
                f"gpg --no-default-keyring --keyring {shlex.quote(k['keyring_path'])} "
                f"--with-colons --fingerprint 2>/dev/null "
                f"| awk -F: '$1==\"fpr\"{{print toupper($10)}}' "
                f"| grep -qxF {shlex.quote(k['key_fpr'].upper())}")
            if not r.qtest(tpl, fpr_check, dry_default=False):
                r.qrun(tpl, f"gpg --no-default-keyring --keyring "
                            f"{shlex.quote(k['keyring_path'])} --fingerprint", check=False)
                raise Fatal(
                    f"Kali keyring does NOT contain the expected fingerprint {k['key_fpr']}.\n"
                    "     Do not proceed. Either Kali rolled the key again (check\n"
                    "     kali.org/blog and update kali.key_fpr) or the download was\n"
                    f"     tampered with. Cross-check at:\n     {k['keyserver_url']}\n"
                    f"     Fingerprints actually found are in {self.out.log_path}")
            o.ok(f"key fingerprint verified: {k['key_fpr']}")
            legacy_check = (
                f"gpg --no-default-keyring --keyring {shlex.quote(k['keyring_path'])} "
                f"--with-colons --fingerprint 2>/dev/null "
                f"| awk -F: '$1==\"fpr\"{{print toupper($10)}}' "
                f"| grep -qxF {shlex.quote(k['key_fpr_legacy'].upper())}")
            if r.qtest(tpl, legacy_check, dry_default=False):
                o.ok("legacy Kali key also present")
            else:
                o.warn(f"legacy key {k['key_fpr_legacy']} absent — expected if it aged out")

            if k.get("keyring_sha1"):
                if r.qtest(tpl, f"sha1sum {shlex.quote(k['keyring_path'])} | "
                                f"grep -qF {shlex.quote(k['keyring_sha1'])}",
                           dry_default=False):
                    o.ok("Kali keyring checksum matches the published value")
                else:
                    o.warn("Kali keyring SHA1 differs from the published value. The "
                           "fingerprint check PASSED, so the key itself is right.")
                    o.warn("This normally means the keyring file was regenerated "
                           "upstream. Re-verify and update kali.keyring_sha1.")

        o.info(f"{tpl}: kali-rolling repository, pinned below Debian")
        r.qwrite(tpl, "/etc/apt/sources.list.d/kali.list", k["repo_line"])
        r.qwrite(tpl, "/etc/apt/preferences.d/99-kali-pin",
                 "Package: *\nPin: release o=Debian\nPin-Priority: 900\n\n"
                 "Package: *\nPin: release o=Kali\nPin-Priority: 100\n")
        r.qrun(tpl, f"export DEBIAN_FRONTEND=noninteractive; apt-get update && "
                    f"apt-get install -y -t kali-rolling "
                    f"{shlex.quote(k['metapackage'])} maltego")
        o.ok(f"{tpl}: {k['metapackage']} and Maltego installed")
        o.info("Maltego licence activation is per-qube (lives in /home), not in the template")

    # =======================================================================
    #  5 — wazuh agent in every template
    # =======================================================================
    def _wazuh_repo_apt(self, tpl: str):
        w = self.c["wazuh"]
        self.r.qrun(tpl, "export DEBIAN_FRONTEND=noninteractive; "
                         "apt-get install -y gnupg apt-transport-https curl ca-certificates")
        # curl -f: an HTTP error page must abort, not get piped into gpg as if
        # it were a key. curl -s alone exits 0 on a 404.
        self.r.qrun(tpl, f"curl -fsSL {shlex.quote(w['key_url'])} | gpg --no-default-keyring "
                         f"--keyring gnupg-ring:{shlex.quote(w['keyring_path'])} --import && "
                         f"chmod 644 {shlex.quote(w['keyring_path'])}")
        self._verify_wazuh_key(tpl, w["keyring_path"])
        self.r.qwrite(tpl, "/etc/apt/sources.list.d/wazuh.list", w["apt_repo_line"])
        self.r.qrun(tpl, "apt-get update")

    def _verify_keyring(self, tpl: str, keyring: str, fpr: str, label: str) -> None:
        """A key fetched over the network signs packages for a police
        workstation. Every one of them is compared against a pinned
        fingerprint, exactly as the Kali key is."""
        o, r = self.out, self.r
        fpr = (fpr or "").strip().upper()
        if not fpr:
            o.warn(f"no pinned fingerprint for the {label} key — it is imported "
                   f"UNVERIFIED. Anything that can answer for that host can sign "
                   f"packages this image trusts.")
            return
        if self.args.dry_run:
            o.info(f"[dry-run] verify {label} key {fpr} in {tpl}")
            return
        check = (f"gpg --no-default-keyring --keyring {shlex.quote(keyring)} "
                 f"--with-colons --fingerprint 2>/dev/null "
                 f"| awk -F: '$1==\"fpr\"{{print toupper($10)}}' "
                 f"| grep -qxF {shlex.quote(fpr)}")
        if not r.qtest(tpl, check, dry_default=False):
            r.qrun(tpl, f"gpg --no-default-keyring --keyring {shlex.quote(keyring)} "
                        f"--fingerprint", check=False)
            raise Fatal(
                f"the {label} signing key in {tpl} is not {fpr}.\n"
                "     Either upstream rolled the key — confirm the new fingerprint\n"
                "     at the vendor's own site and update the config — or the\n"
                f"     download was tampered with. What was found is in\n"
                f"     {self.out.log_path}")
        o.ok(f"{tpl}: {label} signing key verified ({fpr[-8:]})")

    def _verify_wazuh_key(self, tpl: str, keyring: str) -> None:
        self._verify_keyring(tpl, keyring, self.c["wazuh"].get("key_fpr", ""),
                             "Wazuh")

    def _wazuh_repo_dnf(self, tpl: str):
        w = self.c["wazuh"]
        self.r.qwrite(tpl, "/etc/yum.repos.d/wazuh.repo",
                      "[wazuh]\ngpgcheck=1\n"
                      f"gpgkey={w['key_url']}\nenabled=1\n"
                      "name=Wazuh repository\n"
                      f"baseurl={w['yum_baseurl']}\npriority=1\n")
        self.r.qrun(tpl, f"rpm --import {shlex.quote(w['key_url'])}")
        fpr = (w.get("key_fpr") or "").strip().upper()
        if fpr and not self.args.dry_run:
            # rpm stores imported keys as gpg-pubkey-<short id>-<release>.
            short = fpr[-8:].lower()
            if not self.r.qtest(tpl, f"rpm -q gpg-pubkey | grep -qi {shlex.quote(short)}",
                                dry_default=False):
                raise Fatal(f"the Wazuh signing key {fpr} is not in {tpl}'s rpm "
                            f"keyring after import.")
            self.out.ok(f"{tpl}: Wazuh signing key verified ({fpr[-8:]})")

    def p05(self):
        o, r, w = self.out, self.r, self.c["wazuh"]
        o.info("Agent in EVERY template, installed DISABLED. Why disabled: a template")
        o.info("is a shared filesystem. An enabled agent would beacon during template")
        o.info("updates, and every qube cloned from it would inherit the SAME agent")
        o.info("identity, so they would collide in the manager instead of appearing")
        o.info("as separate hosts. Phase 11 enables it per qube automatically — there")
        o.info("is no manual step, only a correct ordering.")

        deb_tpls = [self.t["proxy"], self.t["ids"], self.t["kali"],
                    self.t["personal"], self.t["wazuh"], self.c["base_debian"]]
        if self.c["prefer_debian"]:
            deb_tpls.insert(0, self.t["sys"])
        else:
            # tpl-sys is a Fedora clone in this configuration, so it needs the
            # rpm path. Without this it got no agent at all while phase 12 still
            # asserted one — that configuration could never pass its own tests.
            if r.vm_exists(self.t["sys"]) and not r.qtest(
                    self.t["sys"], "test -d /var/ossec", dry_default=False):
                o.info(f"{self.t['sys']}: wazuh-agent {w['version']} (dnf — "
                       f"prefer_debian is false, so this template is Fedora)")
                self._wazuh_repo_dnf(self.t["sys"])
                r.qrun(self.t["sys"], f"dnf install -y "
                                      f"wazuh-agent-{shlex.quote(w['version'])} "
                                      f"|| dnf install -y wazuh-agent", check=False)
                r.qrun(self.t["sys"], "systemctl disable --now wazuh-agent",
                       check=False)
                if w["pin_agent"]:
                    r.qrun(self.t["sys"],
                           "sed -i 's|^enabled=1|enabled=0|' "
                           "/etc/yum.repos.d/wazuh.repo", check=False)
                o.ok(self.t["sys"])
        for k in ("base_whonix_gw", "base_whonix_ws"):
            if r.vm_exists(self.c[k]):
                deb_tpls.append(self.c[k])

        for tpl in deb_tpls:
            if not r.vm_exists(tpl):
                continue
            if r.qtest(tpl, "test -d /var/ossec", dry_default=False):
                o.skip(f"{tpl} — agent already present (Tier 2)")
                continue
            o.info(f"{tpl}: wazuh-agent {w['version']}")
            self._wazuh_repo_apt(tpl)
            # Pin at install time. The version was printed as though it were
            # being installed, but apt was given a bare package name and took
            # whatever the repository offered; the dpkg hold below then froze
            # that unknown version instead of the configured one.
            if not r.qtest(tpl, "export DEBIAN_FRONTEND=noninteractive; "
                                f"apt-get install -y "
                                f"wazuh-agent={shlex.quote(w['version'])}-1",
                           dry_default=True):
                # Wazuh has shipped -2 revisions, and the repository moves on.
                # Falling back is reasonable; doing it silently is not — the
                # hold below would then freeze an unknown version and phase 12
                # only checks that a hold exists, not what it holds.
                o.warn(f"{tpl}: wazuh-agent {w['version']}-1 is not available; "
                       f"installing whatever the repository offers")
                r.qrun(tpl, "export DEBIAN_FRONTEND=noninteractive; "
                            "apt-get install -y wazuh-agent")
                got = r.run("qvm-run", "--no-gui", "--pass-io", "-u", "root", tpl,
                            "dpkg-query -W -f='${Version}' wazuh-agent",
                            check=False, capture=True).strip()
                o.warn(f"{tpl}: pinned at {got or 'unknown'}, not "
                       f"{w['version']} — update wazuh.version to match the "
                       f"manager, or this agent may overtake it")
            # Not '|| true': p05's own preamble explains that an enabled agent
            # in a shared template gives every qube cloned from it the SAME
            # identity, so they collide in the manager instead of appearing as
            # separate hosts. Forcing this to succeed hid exactly that.
            r.qrun(tpl, "systemctl disable --now wazuh-agent")
            if w["pin_agent"]:
                r.qrun(tpl, "echo 'wazuh-agent hold' | dpkg --set-selections && "
                            "sed -i 's|^deb |#deb |' /etc/apt/sources.list.d/wazuh.list && "
                            "apt-get update")
                o.ok(f"{tpl} — installed, disabled, version-held, repo disabled")
            else:
                o.warn(f"{tpl} — agent NOT pinned. Weekly updates can push it past the "
                       "manager version and every agent stops reporting.")
                o.ok(tpl)

        # The Fedora template is the only thing left needing dnf. If prefer_debian
        # is set, tpl-sys is Debian and was handled in the apt loop above.
        fed = self.c["base_fedora"]
        if not self.c["use_fedora_template"]:
            o.info(f"{fed} is not part of this estate (use_fedora_template=false) "
                   f"— left untouched")
        elif r.vm_exists(fed) and not r.qtest(fed, "test -d /var/ossec",
                                              dry_default=False):
            o.info(f"{fed}: wazuh-agent {w['version']} (dnf — the only rpm path left)")
            self._wazuh_repo_dnf(fed)
            r.qrun(fed, f"dnf install -y wazuh-agent-{shlex.quote(w['version'])} "
                        f"|| dnf install -y wazuh-agent", check=False)
            r.qrun(fed, "systemctl disable wazuh-agent 2>/dev/null || true", check=False)
            if w["pin_agent"]:
                r.qrun(fed, "sed -i 's|^enabled=1|enabled=0|' /etc/yum.repos.d/wazuh.repo",
                       check=False)
            o.ok(fed)
        elif r.vm_exists(fed):
            o.skip(f"{fed} — agent already present")

        o.say("")
        o.info("agent coverage complete across all templates — verified in phase 12")
        if w["pin_agent"]:
            o.info(f"agents pinned at {w['version']}. Upgrade order when the time comes:")
            o.info("  wazuh-srv FIRST, then release the holds and upgrade agents.")
            o.info("  An agent newer than the manager is unsupported and stops reporting.")
        self._mark(5)

    # =======================================================================
    #  6 — chain qubes
    # =======================================================================
    def _mk_netqube(self, name, tpl, netvm, label, mem, maxmem, vcpus) -> bool:
        o, r = self.out, self.r
        if r.vm_exists(name):
            o.skip(name)
        else:
            if not r.vm_exists(tpl):
                o.warn(f"template {tpl} missing — cannot create {name}")
                return False
            r.run("qvm-create", "--class", "AppVM", "--template", tpl,
                  "--label", label, name)
            r.will_create(name)
            o.ok(f"created {name}")
        r.prefs(name, provides_network="True", netvm=netvm, memory=mem,
                maxmem=maxmem, vcpus=vcpus, autostart="True")
        o.info(f"{name} -> netvm {netvm}")
        return True

    def p06(self):
        o, r, res, q = self.out, self.r, self.c["resources"], self.q
        o.info("building the chain top-down so each upstream exists first")
        r.run("qvm-prefs", q["firewall"], "netvm", q["net"])

        built = [
            self._mk_netqube(q["dpi"], self.t["ids"], q["firewall"], "orange",
                             res["ids_mem"], res["ids_maxmem"], res["ids_vcpus"]),
            self._mk_netqube(q["ids"], self.t["ids"], q["dpi"], "orange",
                             res["ids_mem"], res["ids_maxmem"], res["ids_vcpus"]),
            self._mk_netqube(q["proxy"], self.t["proxy"], q["ids"], "orange",
                             res["proxy_mem"], res["proxy_maxmem"], 2),
        ]
        if not all(built):
            raise Fatal("the inspection chain is incomplete — a chain qube could "
                        "not be created. Phase 6 is NOT marked complete. Fix the "
                        "missing template and re-run; issuing a laptop whose chain "
                        "has a hole is exactly what this design exists to prevent.")

        # Downstream first. sys-firewall and sys-usb are clients of sys-net, so
        # stopping sys-net first is the case most likely to be refused or to
        # hang — and a refused shutdown makes the qvm-prefs below fail.
        for svc in (q["usb"], q["firewall"], q["net"]):
            if r.vm_exists(svc) and r.vm_exists(self.t["sys"]):
                if svc == q["usb"]:
                    o.warn(f"{svc} is about to shut down. If your keyboard or mouse "
                           f"is attached through it, expect input to drop briefly.")
                if not r.shutdown(svc):
                    raise Fatal(f"{svc} is still running after a 60 s shutdown — "
                                f"cannot re-template it. Shut it down by hand "
                                f"(qvm-shutdown --wait {svc}) and re-run "
                                f"--from-phase 6.")
                r.run("qvm-prefs", svc, "template", self.t["sys"])
                o.ok(f"{svc} re-templated onto {self.t['sys']}")

        if r.vm_exists(q["whonix"]):
            r.run("qvm-prefs", q["whonix"], "netvm", q["firewall"])
            o.ok(f"{q['whonix']} -> {q['firewall']} (bypasses proxy/IPS/DPI by design)")

        o.say("")
        o.info(f"chain: <app qubes> -> {q['proxy']} -> {q['ids']} -> {q['dpi']} "
               f"-> {q['firewall']} -> {q['net']} -> internet")
        o.info(f"tor:   <tor qubes> -> {q['whonix']} -> {q['firewall']} "
               f"-> {q['net']} -> internet")
        self._mark(6)

    # =======================================================================
    #  7 — chain configuration
    # =======================================================================
    def _install_timer(self, tpl: str, name: str, description: str,
                       script_path: str, oncalendar: str, body: str,
                       condition: str = "") -> None:
        """Install a recurring job into a TEMPLATE so it survives reboots.

        Everything docs/GUIDE.md listed under "ongoing maintenance" was a line
        in a table addressed to a human. A template-resident timer is the same
        instruction addressed to systemd, which does not go on holiday.

        Enabling it in the template plants the wants-symlink in the read-only
        root, so every qube cloned from it inherits the timer. `condition`
        keeps it dormant in the qubes it does not apply to.
        """
        o, r = self.out, self.r
        if not r.vm_exists(tpl):
            o.warn(f"{tpl} missing — cannot install the {name} timer")
            return
        r.ensure_running(tpl)
        r.qwrite(tpl, script_path, body, mode="0755")
        cond = f"ConditionPathExists={condition}\n" if condition else ""
        r.qwrite(tpl, f"/etc/systemd/system/{name}.service",
                 f"[Unit]\nDescription={description}\n{cond}"
                 f"\n[Service]\nType=oneshot\nExecStart={script_path}\n")
        r.qwrite(tpl, f"/etc/systemd/system/{name}.timer",
                 f"[Unit]\nDescription=Schedule: {description}\n{cond}"
                 f"\n[Timer]\nOnCalendar={oncalendar}\nPersistent=true\n"
                 f"RandomizedDelaySec=900\n"
                 f"\n[Install]\nWantedBy=timers.target\n")
        r.qrun(tpl, f"systemctl enable {shlex.quote(name)}.timer", check=False)
        o.ok(f"{tpl}: {name}.timer installed ({oncalendar})")

    def _rc_hook(self, vm: str, name: str, body: str) -> None:
        """Install boot-time logic without destroying the operator's rc.local.

        /rw/config/rc.local is the documented place for local customisation and
        this provisioner runs on qubes it did not create — sys-firewall and the
        Whonix gateway routinely carry VPN or NetworkManager tweaks there.
        Overwriting it wholesale silently deleted them. The golden-image logic
        lives in its own file; rc.local only gains one sourcing line, once.
        """
        r = self.r
        path = f"/rw/config/{name}"
        r.qwrite(vm, path, body, mode="0755")
        marker = f". {path}"
        r.qrun(vm, f"""
set -e
RC=/rw/config/rc.local
if [ ! -e "$RC" ]; then
    printf '#!/bin/sh\n' > "$RC"
elif ! grep -qF {shlex.quote(marker)} "$RC"; then
    [ -e "$RC.pre-golden-image" ] || cp -a "$RC" "$RC.pre-golden-image"
fi
grep -qF {shlex.quote(marker)} "$RC" || printf '%s\n' {shlex.quote(marker)} >> "$RC"
chmod 0755 "$RC"
""", check=False)

    def p07(self):
        o, r, q, w = self.out, self.r, self.q, self.c["wazuh"]

        # ---------------- sys-proxy ----------------
        o.info(f"{q['proxy']}: Squid intercept + attribution logging")
        r.ensure_running(q["proxy"])
        r.qwrite(q["proxy"], "/rw/config/squid-golden.conf", """\
# Golden image Squid — transparent intercept, TLS peeked not decrypted.
http_port  3128 intercept
https_port 3129 intercept ssl-bump generate-host-certificates=off \\
           tls-cert=/etc/squid/placeholder.pem

acl step1 at_step SslBump1
ssl_bump peek step1
ssl_bump splice all

acl localqubes src 10.137.0.0/16 10.138.0.0/16
http_access allow localqubes
http_access deny all

cache deny all

logformat attrib %ts.%03tu %>a %Ss/%03>Hs %rm %ru %ssl::>sni
access_log daemon:/var/log/squid/access.log attrib
""")
        r.qwrite(q["proxy"], "/rw/config/qubes-bind-dirs.d/50_golden_proxy.conf",
                 "binds+=( '/etc/squid' )\nbinds+=( '/var/log/squid' )\n")
        r.qwrite(q["proxy"], "/rw/config/qubes-firewall-user-script", f"""\
#!/bin/sh
# Golden image — {q['proxy']}
#
# There is NO 'custom-prerouting' chain in Qubes. The documented pattern is to
# create your own nat chain (Qubes firewall docs, port-forwarding section):
#     nft add chain qubes custom-dnat-NAME
#         '{{ type nat hook prerouting priority filter +1 ; policy accept; }}'
# and then add a matching accept in a filter chain.
#
# Redirected traffic terminates LOCALLY on this qube, so the accept belongs in
# custom-input, not custom-forward. Without it Squid never receives anything.
#
# IDEMPOTENCE. qubes-firewall runs this script on every firewall reload, not
# once per boot, and 'nft add rule' appends unconditionally — so without the
# flushes below the rule set grew a duplicate copy every time a downstream
# qube's firewall changed. custom-input and custom-forward are user hooks that
# Qubes itself leaves empty, and in this image nothing else writes to them, so
# flushing them is safe. If you add your own rules to this qube, add them to
# THIS file, below, rather than out of band.

nft flush chain ip qubes custom-input 2>/dev/null
nft flush chain ip qubes custom-forward 2>/dev/null
nft delete chain ip qubes custom-dnat-squid 2>/dev/null
nft add chain ip qubes custom-dnat-squid \
    '{{ type nat hook prerouting priority filter + 1 ; policy accept; }}'

# Redirect downstream web traffic into Squid. Non-web ports are untouched and
# continue up the chain, still inspected by Suricata and Zeek.
nft add rule ip qubes custom-dnat-squid iifname "vif*" tcp dport 80  redirect to :3128
nft add rule ip qubes custom-dnat-squid iifname "vif*" tcp dport 443 redirect to :3129

# Let the redirected packets reach the local Squid sockets.
nft add rule ip qubes custom-input iifname "vif*" tcp dport {{ 3128, 3129 }} counter accept

# Sibling qubes meet here first: permit agent traffic to the SIEM, nothing else.
# Both ports: 1514 carries events, 1515 carries enrollment. Without 1515 an
# agent can never register in the first place.
nft add rule ip qubes custom-forward ip daddr {w['ip']} tcp dport {{ {w['port_events']}, {w['port_enroll']} }} counter accept
""", mode="0755")
        self._rc_hook(q["proxy"], "golden-image-proxy.sh", """\
#!/bin/sh
# Golden image — Squid intercept
cp -f /rw/config/squid-golden.conf /etc/squid/squid.conf 2>/dev/null
[ -f /etc/squid/placeholder.pem ] || \\
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \\
    -subj "/CN=golden-image-proxy" \\
    -keyout /etc/squid/placeholder.pem -out /etc/squid/placeholder.pem 2>/dev/null
chmod 0600 /etc/squid/placeholder.pem 2>/dev/null
systemctl restart squid
""")
        o.ok(f"{q['proxy']} configured")
        o.info("uses a created custom-dnat-squid chain + custom-input accept, per the")
        o.info("  documented Qubes port-forwarding pattern — there is no custom-prerouting")
        o.info("group 13 reads the custom-dnat-squid counters back and fails if "
               "nothing was redirected")

        # ---------------- sys-ids ----------------
        mode = self.c["ips_failure_mode"]
        o.info(f"{q['ids']}: Suricata inline IPS (failure mode: {mode})")
        r.ensure_running(q["ids"])
        bypass = " bypass" if mode == "open" else ""
        # "closed" promises that nothing passes uninspected. That promise only
        # holds while the queue rule exists — previously a failure to install it
        # was logged and swallowed, and the qube then forwarded EVERYTHING with
        # no inspection at all, which is the opposite of the configured mode.
        fallback = (
            'nft add rule ip qubes custom-forward counter drop \\\n'
            '        || logger -t golden-image "fallback drop also failed — this '
            'qube is forwarding UNINSPECTED traffic"'
            if mode == "closed" else
            'logger -t golden-image "ips_failure_mode=open: traffic continues '
            'uninspected by design"')
        r.qwrite(q["ids"], "/rw/config/qubes-firewall-user-script", f"""\
#!/bin/sh
# Golden image — {q['ids']}
# Every forwarded packet is queued to Suricata for an accept/drop verdict.
# ips_failure_mode = {mode}
#   closed : no bypass — Suricata down means the chain stops. Nothing passes
#            uninspected. This is the casework default.
#   open   : bypass — traffic keeps flowing if Suricata is not listening.
#
# Flushed first: qubes-firewall re-runs this on every reload and 'insert rule'
# appends a fresh copy each time, so the queue rule accumulated duplicates.
nft flush chain ip qubes custom-forward 2>/dev/null
if ! nft insert rule ip qubes custom-forward counter queue num 0{bypass}; then
    logger -t golden-image "NFQUEUE hook FAILED in {q['ids']}"
    {fallback}
fi
""", mode="0755")
        r.qwrite(q["ids"], "/rw/config/qubes-bind-dirs.d/50_golden_ids.conf",
                 "binds+=( '/etc/suricata' )\nbinds+=( '/var/lib/suricata' )\n"
                 "binds+=( '/var/log/suricata' )\n")

        # The unit goes into the TEMPLATE, not the qube. sys-ids is an AppVM:
        # anything written under /etc that is not bind-mounted is discarded at
        # shutdown, so a unit written into the qube vanished on the first
        # reboot and the fail-closed queue rule then had no listener — which in
        # a fail-closed chain means no traffic at all, on a machine that had
        # passed its acceptance tests the day before.
        if r.vm_exists(self.t["ids"]):
            r.ensure_running(self.t["ids"])
            r.qwrite(self.t["ids"], "/etc/systemd/system/suricata-nfqueue.service",
                     """\
[Unit]
Description=Suricata inline IPS (NFQUEUE) - golden image
After=network.target

[Service]
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -q 0
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
""")
            o.ok(f"suricata-nfqueue.service installed into {self.t['ids']} "
                 f"(persists across reboots)")
        else:
            o.warn(f"{self.t['ids']} missing — the IPS unit has nowhere persistent "
                   f"to live")

        self._rc_hook(q["ids"], "golden-image-ids.sh", """\
#!/bin/sh
# Golden image — start the inline IPS. The unit lives in the template.
systemctl daemon-reload
if [ ! -f /etc/systemd/system/suricata-nfqueue.service ]; then
    logger -t golden-image "suricata-nfqueue.service missing — the fail-closed \
queue rule has no listener and this qube will pass no traffic"
fi
systemctl start suricata-nfqueue.service
""")
        r.qwrite(q["ids"], "/var/lib/suricata/rules/golden-image-test.rules",
                 'alert http any any -> any any (msg:"GOLDEN-IMAGE-TEST canary"; '
                 'content:"golden-image-canary"; http_uri; sid:9000001; rev:1;)\n')

        # Rules go stale; GUIDE section 12 used to ask somebody to remember this
        # every week. A timer does not forget.
        self._install_timer(
            self.t["ids"], "golden-suricata-update",
            "Refresh Suricata rules and reload them in place",
            "/usr/local/sbin/golden-suricata-update", "Mon 04:00",
            condition="/rw/config/golden-image-ids.sh",
            body="""#!/bin/sh
# Golden image — weekly rule refresh. Reload is in-place: no restart, so the
# fail-closed chain never drops out from under live traffic.
set -e
suricata-update
suricatasc -c reload-rules || systemctl reload suricata-nfqueue || true
logger -t golden-image "suricata rules updated"
""")
        o.ok(f"{q['ids']} configured")

        # ---------------- sys-dpi ----------------
        z = self.c["zeek"]
        o.info(f"{q['dpi']}: Zeek deep packet inspection")
        r.ensure_running(q["dpi"])
        r.qwrite(q["dpi"], "/rw/config/zeek-node.cfg",
                 "[zeek]\ntype=standalone\nhost=localhost\ninterface=eth0\n")
        r.qwrite(q["dpi"], "/rw/config/qubes-bind-dirs.d/50_golden_dpi.conf",
                 f"binds+=( '{z['prefix']}/etc' )\nbinds+=( '{z['prefix']}/logs' )\n")
        self._rc_hook(q["dpi"], "golden-image-dpi.sh", f"""\
#!/bin/sh
# Golden image — deep packet inspection.
# The prefix is discovered rather than assumed: the OBS packages have moved it
# between releases, and a wrong guess used to leave the DPI recorder silently
# not running.
PREFIX={z['prefix']}
if [ ! -x "$PREFIX/bin/zeekctl" ]; then
  for cand in /opt/zeek /usr/local/zeek /usr; do
    [ -x "$cand/bin/zeekctl" ] && PREFIX="$cand" && break
  done
fi
if [ -x "$PREFIX/bin/zeekctl" ]; then
  [ "$PREFIX" = {z['prefix']} ] || \\
    logger -t golden-image "zeek found at $PREFIX, not {z['prefix']} — update zeek.prefix"
  mkdir -p "$PREFIX/etc"
  cp -f /rw/config/zeek-node.cfg "$PREFIX/etc/node.cfg" 2>/dev/null
  "$PREFIX/bin/zeekctl" deploy
else
  logger -t golden-image "zeekctl not found — Zeek not installed in this template"
fi
""")
        o.ok(f"{q['dpi']} configured")

        # The openSUSE Build Service key that signs Zeek expires, and Zeek's own
        # documentation says you must re-add it by hand when it does. An expired
        # key stops DPI updates silently. GUIDE section 12 asked a human to check
        # this monthly.
        self._install_timer(
            self.t["ids"], "golden-key-expiry",
            "Warn before a third-party signing key expires",
            "/usr/local/sbin/golden-key-expiry", "Mon 05:00",
            condition="/rw/config/golden-image-dpi.sh",
            body=f"""#!/bin/sh
# Golden image — third-party signing key expiry watch.
set -u
now=$(date +%s)
for kr in {shlex.quote(self.c['zeek']['keyring_path'])} \\
          {shlex.quote(self.c['kali']['keyring_path'])} \\
          {shlex.quote(self.c['wazuh']['keyring_path'])}; do
    [ -f "$kr" ] || continue
    gpg --no-default-keyring --keyring "$kr" --with-colons --list-keys 2>/dev/null \\
    | awk -F: -v now="$now" -v kr="$kr" '
        $1=="pub" && $7!="" {{
            days = int(($7 - now) / 86400)
            if (days < 60)
                printf "golden-image: %s key %s expires in %d days\\n", kr, $5, days
        }}' | while read -r line; do
        logger -t golden-image "$line"
        echo "$line" >> /var/log/golden-image-key-expiry.log
    done
done
""")

        # ---------------- sys-firewall ----------------
        # DNS enforcement, and the ordering that decides whether it works.
        #
        # dnat-dns is Qubes-managed. qubes-setup-dnat-to-ns rewrites it from
        # /usr/lib/qubes/init/network-proxy-setup.sh, which runs as part of
        # qubes-network.service — and qubes-network.service starts AFTER
        # qubes-firewall.service (qubes-issues #9056 says this explicitly).
        #
        # So anything applied from /rw/config/qubes-firewall.d/ runs first and
        # is then overwritten. That directory is still where the rule set lives,
        # because it is the documented place for it and it covers a firewall
        # reload — but it cannot be the only place it is applied. A oneshot unit
        # ordered After=qubes-network.service re-applies it once the network is
        # up, which is the point at which the Qubes-generated chain has already
        # been written and can be replaced for good.
        d = self.c["dns"]
        o.info(f"{q['firewall']}: DNS enforcement ({d['mode']}) + segmentation")
        r.ensure_running(q["firewall"])

        if d["mode"] == "dot":
            # unbound listens on the qube's interfaces; downstream port 53 is
            # redirected to it locally. 'redirect' avoids needing
            # route_localnet, which a 'dnat to 127.0.0.1' would require.
            dns_rule = ('iifname "vif*" meta l4proto { tcp, udp } th dport 53 '
                        'redirect to :53')
            r.qwrite(q["firewall"], "/rw/config/unbound-quad9.conf", f"""\
server:
    interface: 0.0.0.0
    access-control: 127.0.0.0/8 allow
    access-control: 10.137.0.0/16 allow
    access-control: 10.138.0.0/16 allow
    access-control: 0.0.0.0/0 refuse
    do-not-query-localhost: no
    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt
forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-first: no
    forward-addr: {d['primary']}@853#{d['tls_name']}
    forward-addr: {d['secondary']}@853#{d['tls_name']}
""")
            self._rc_hook(q["firewall"], "golden-image-dns.sh", """\
#!/bin/sh
# Golden image — enforced DNS.
# unbound ships its drop-in dir at /etc/unbound/unbound.conf.d on Debian.
if command -v unbound >/dev/null 2>&1; then
  mkdir -p /etc/unbound/unbound.conf.d
  install -m 644 /rw/config/unbound-quad9.conf \
      /etc/unbound/unbound.conf.d/golden-image.conf
  systemctl restart unbound
else
  logger -t golden-image "unbound missing — install it or set dns.mode=plain"
fi
""")
            if self.c["prefer_debian"]:
                r.qrun(q["firewall"], "export DEBIAN_FRONTEND=noninteractive; "
                                      "apt-get update && apt-get install -y unbound "
                                      "ca-certificates", check=False)
            else:
                r.qrun(q["firewall"], "dnf install -y unbound ca-certificates",
                       check=False)
        else:
            dns_rule = (f'iifname "vif*" meta l4proto {{ tcp, udp }} th dport 53 '
                        f'dnat to {d["primary"]}')

        # Replace dnat-dns wholesale. Runs at qubes-firewall start, before the
        # network is up, so it wins over the regenerated default.
        r.qwrite(q["firewall"], "/rw/config/qubes-firewall.d/10-golden-dns", f"""\
#!/usr/sbin/nft -f
# Golden image — DNS enforcement in {q['firewall']}
# Replaces the Qubes-generated dnat-dns chain. Applied twice: here at
# qubes-firewall start, and again by golden-dns.service once
# qubes-network.service has run qubes-setup-dnat-to-ns and overwritten it.
#
# mode: {d['mode']}
#   dot   — redirect downstream DNS to the local unbound, which forwards over
#           TLS to {d['primary']}. Query contents never cross the wire in clear.
#   plain — DNAT downstream DNS straight to {d['primary']}.
#
# The Tor branch is exempt structurally: {q['whonix']} resolves inside Tor and
# never emits port 53 toward this qube. DO NOT add DNS rules for it. Ever.
add chain ip qubes dnat-dns
delete chain ip qubes dnat-dns
table ip qubes {{
    chain dnat-dns {{
        type nat hook prerouting priority dstnat; policy accept;
        {dns_rule}
    }}
}}
""", mode="0755")

        # In 'plain' mode dnat-dns rewrites the destination to the configured
        # resolver and the packet then goes through the forward path — so a
        # blanket port-53 drop there would kill the very queries the DNAT just
        # redirected. Exempt the DNAT target. In 'dot' mode nothing on port 53
        # ever reaches forward (the redirect delivers locally), so the drop is
        # defence in depth: it carries a counter, and a non-zero counter means
        # the redirect is not doing its job.
        dns_drop = ('meta l4proto { tcp, udp } th dport 53 counter drop'
                    if d["mode"] == "dot" else
                    f'meta l4proto {{ tcp, udp }} th dport 53 '
                    f'ip daddr != {d["primary"]} counter drop')
        r.qwrite(q["firewall"], "/rw/config/qubes-firewall-user-script", f"""\
#!/bin/sh
# Golden image — {q['firewall']}
#
# Flushed first: qubes-firewall re-runs this on every reload and 'nft add rule'
# appends, so without this the same rules stacked up indefinitely.
nft flush chain ip qubes custom-input 2>/dev/null
nft flush chain ip qubes custom-forward 2>/dev/null

# Let downstream DNS reach the local resolver after the redirect above.
nft add rule ip qubes custom-input iifname "vif*" meta l4proto {{ tcp, udp }} th dport 53 counter accept

# Nothing raw on port 53 leaves upstream: kills clients with hardcoded
# resolvers. dns.mode = {d['mode']}
nft add rule ip qubes custom-forward {dns_drop}

# Segmentation: qube-to-qube stays denied except the SIEM flows permitted at
# {q['proxy']}.
nft add rule ip qubes custom-forward ip saddr 10.137.0.0/16 ip daddr 10.137.0.0/16 counter drop
nft add rule ip qubes custom-forward ip saddr 10.138.0.0/16 ip daddr 10.137.0.0/16 counter drop
""", mode="0755")

        # The unit goes in the template: sys-firewall is an AppVM, so a unit
        # written into /etc/systemd/system of the qube would not survive a
        # reboot — and this is precisely the rule that has to survive one.
        if r.vm_exists(self.t["sys"]):
            r.ensure_running(self.t["sys"])
            r.qwrite(self.t["sys"], "/etc/systemd/system/golden-dns.service", """\
[Unit]
Description=Golden image - reapply enforced DNS after Qubes rewrites dnat-dns
# qubes-setup-dnat-to-ns runs from qubes-network.service, which starts AFTER
# qubes-firewall.service. Anything applied at firewall time loses to it.
After=qubes-network.service qubes-firewall.service
Wants=qubes-network.service
ConditionPathExists=/rw/config/qubes-firewall.d/10-golden-dns

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /rw/config/qubes-firewall.d/10-golden-dns
ExecStartPost=/bin/sh -c 'nft list chain ip qubes dnat-dns | grep -q "dport 53" \\
    || logger -t golden-image "dnat-dns does NOT carry the golden rule"'

[Install]
WantedBy=multi-user.target
""")
            r.qrun(self.t["sys"], "systemctl enable golden-dns.service", check=False)
            o.ok(f"{self.t['sys']}: golden-dns.service installed and enabled")
        else:
            o.warn(f"{self.t['sys']} missing — DNS enforcement will be overwritten "
                   f"by qubes-setup-dnat-to-ns on every network start")

        o.ok(f"{q['firewall']} configured")
        o.info("dnat-dns is replaced from /rw/config/qubes-firewall.d/10-golden-dns")
        o.info("  and re-applied by golden-dns.service after qubes-network.service,")
        o.info("  which is the thing that overwrites it. Acceptance-test group 13")
        o.info("  reads the chain back to prove it stuck.")

        # Everything above is staged, not applied: rc.local, the firewall user
        # script, the nft drop-in and the bind-dirs entries are all read at qube
        # BOOT. ensure_running() uses --skip-if-running, so a chain qube that
        # was already up never re-read any of it — and phase 12 then tested an
        # unconfigured system and passed it. Cycle the chain here so what the
        # acceptance tests measure is what will actually be running.
        self._restart_chain()
        self._mark(7)

    def _restart_chain(self) -> None:
        """Cycle the inspection chain so staged boot-time config takes effect."""
        o, r, q = self.out, self.r, self.q
        if self.args.dry_run:
            o.info("[dry-run] restart the inspection chain so the staged config "
                   "is actually applied")
            return
        o.say("")
        o.info("applying: restarting the chain so the staged configuration loads")
        o.warn("network drops for a moment — every qube reaches the internet "
               "through these")
        # Downstream first on the way down, upstream first on the way up.
        down = [q["proxy"], q["ids"], q["dpi"], q["firewall"]]
        for vm in down:
            if r.vm_exists(vm) and not r.shutdown(vm):
                o.warn(f"{vm} would not shut down — its configuration is staged "
                       f"but not live. Reboot the machine before running the "
                       f"acceptance tests.")
        for vm in reversed(down):
            if not r.vm_exists(vm):
                continue
            if r.quiet("qvm-start", "--skip-if-running", vm):
                time.sleep(3)
                o.ok(f"{vm} restarted with the golden-image configuration")
            else:
                o.warn(f"{vm} did not start — check 'qvm-start {vm}' by hand")

    # =======================================================================
    #  8 — wazuh manager
    # =======================================================================
    def p08(self):
        o, r, w, q = self.out, self.r, self.c["wazuh"], self.q
        if w["mode"] == "central":
            if not w["central_address"]:
                raise Fatal("wazuh.mode is 'central' but wazuh.central_address is empty")
            o.info(f"central mode — agents will target {w['central_address']}")
            self._mark(8)
            return

        if r.vm_exists(q["wazuh"]):
            o.skip(q["wazuh"])
        else:
            if not r.vm_exists(self.t["wazuh"]) and not self.args.dry_run:
                raise Fatal(f"{self.t['wazuh']} missing — run phase 3 first")
            o.info(f"creating {q['wazuh']} as a StandaloneVM (the manager needs a "
                   "persistent root)")
            r.run("qvm-clone", "--class", "StandaloneVM", self.t["wazuh"], q["wazuh"],
                  timeout=r.timeout_long)
            r.run("qvm-prefs", q["wazuh"], "label", "blue")
            r.will_create(q["wazuh"])
            o.ok(f"created {q['wazuh']}")

        r.prefs(q["wazuh"], netvm=q["proxy"], memory=w["mem"], maxmem=w["maxmem"],
                vcpus=w["vcpus"], autostart="True", ip=w["ip"])
        r.run("qvm-volume", "resize", f"{q['wazuh']}:root", f"{w['root_gb']}G",
              timeout=r.timeout_long)
        o.info(f"{q['wazuh']} pinned to {w['ip']}, root grown to {w['root_gb']}G")

        if not self.args.dry_run:
            authd = self._need_secret("authd", 8)
            r.ensure_running(q["wazuh"])
            r.qwrite(q["wazuh"], "/rw/golden-authd.pass", authd, mode="0600")
            r.qwrite(q["wazuh"], "/rw/config/qubes-bind-dirs.d/50_golden_wazuh.conf",
                     "binds+=( '/var/ossec' )\n")
            o.info(f"enrollment password staged at {q['wazuh']}:/rw/golden-authd.pass")

        if r.vm_exists(q["wazuh"]):
            r.ensure_running(q["wazuh"])
            self._wazuh_repo_apt(q["wazuh"])
            o.ok(f"Wazuh repository configured in {q['wazuh']}")

        # ---- automated single-node configuration --------------------------
        # If the Tier 2 template baked the stack in, everything below is local
        # and needs no network. Certificates and passwords are per machine and
        # are generated HERE, never in a shared template.
        baked = r.qtest(q["wazuh"], "dpkg -s wazuh-manager >/dev/null 2>&1")
        if not baked:
            o.warn("the Wazuh stack is not present in this qube.")
            o.warn("  Tier 2 bakes it into the investigator-wazuh template. On a Tier 1")
            o.warn("  build, install indexer + server + dashboard from the configured")
            o.warn("  repository, then re-run:  sudo ./golden_image.py --phase 8")
            self._mark(8)
            return

        o.ok("Wazuh packages present (baked in by the Tier 2 template)")
        o.info("generating per-machine certificates and starting the stack")

        # Baked into the template by the ISO build, then run as root against the
        # SIEM. Checksum them before that happens.
        for tool, key in (("wazuh-certs-tool.sh", "certs_tool_sha256"),
                          ("wazuh-passwords-tool.sh", "passwords_tool_sha256")):
            want = (w.get(key) or "").strip()
            if not want:
                o.warn(f"no pinned checksum for {tool} — it runs as root in "
                       f"{q['wazuh']} unverified")
                continue
            if not r.qtest(q["wazuh"], f"test -f /opt/{tool}", dry_default=False):
                continue
            if not r.qtest(q["wazuh"],
                           f"sha256sum /opt/{tool} | grep -qF {shlex.quote(want)}",
                           dry_default=False):
                raise Fatal(
                    f"/opt/{tool} in {q['wazuh']} does not match the pinned "
                    f"checksum\n     {want}\n"
                    "     It is about to run as root against the SIEM. Confirm the\n"
                    "     current file at packages.wazuh.com and update "
                    f"wazuh.{key},\n     or rebuild the template.")
            o.ok(f"{tool} matches its pinned checksum")

        certs_ok = r.qtest(q["wazuh"], "test -x /opt/wazuh-certs-tool.sh")
        if certs_ok:
            # The file MUST be called config.yml and MUST sit beside the script:
            # wazuh-certs-tool.sh hardcodes `config_file="${base_path}/config.yml"`
            # and has no -c/--config-file flag at all. The old invocation passed
            # -c /opt/wazuh-config.yml, which the tool ignored — it then found no
            # config, generated nothing, and the `|| true` hid the failure until
            # the indexer refused to start with no certificates.
            r.qwrite(q["wazuh"], "/opt/config.yml", f"""\
nodes:
  indexer:
    - name: node-1
      ip: {w['ip']}
  server:
    - name: wazuh-1
      ip: {w['ip']}
  dashboard:
    - name: dashboard
      ip: {w['ip']}
""")
            # -A generates everything; the tool refuses if the output directory
            # already exists, which used to break every resumed run.
            r.qrun(q["wazuh"], "rm -rf /opt/wazuh-certificates "
                               "/opt/wazuh-certificates.tar", check=False)
            r.qrun(q["wazuh"], "cd /opt && ./wazuh-certs-tool.sh -A")
            if not r.qtest(q["wazuh"], "test -f /opt/wazuh-certificates/root-ca.pem"):
                raise Fatal(
                    "wazuh-certs-tool.sh produced no certificates.\n"
                    "     The indexer cannot start without them. Check "
                    f"{q['wazuh']}:/opt/config.yml and re-run "
                    "'sudo ./golden_image.py --phase 8'.")
            r.qrun(q["wazuh"], """
set -e
install -d -m 500 /etc/wazuh-indexer/certs
install -m 400 /opt/wazuh-certificates/node-1.pem      /etc/wazuh-indexer/certs/indexer.pem
install -m 400 /opt/wazuh-certificates/node-1-key.pem  /etc/wazuh-indexer/certs/indexer-key.pem
install -m 400 /opt/wazuh-certificates/admin.pem       /etc/wazuh-indexer/certs/admin.pem
install -m 400 /opt/wazuh-certificates/admin-key.pem   /etc/wazuh-indexer/certs/admin-key.pem
install -m 400 /opt/wazuh-certificates/root-ca.pem     /etc/wazuh-indexer/certs/root-ca.pem
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

install -d -m 500 /etc/filebeat/certs
install -m 400 /opt/wazuh-certificates/wazuh-1.pem     /etc/filebeat/certs/wazuh-1.pem 2>/dev/null || true
install -m 400 /opt/wazuh-certificates/wazuh-1-key.pem /etc/filebeat/certs/wazuh-1-key.pem 2>/dev/null || true
install -m 400 /opt/wazuh-certificates/root-ca.pem     /etc/filebeat/certs/root-ca.pem 2>/dev/null || true

install -d -m 500 /etc/wazuh-dashboard/certs
install -m 400 /opt/wazuh-certificates/dashboard.pem     /etc/wazuh-dashboard/certs/dashboard.pem
install -m 400 /opt/wazuh-certificates/dashboard-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
install -m 400 /opt/wazuh-certificates/root-ca.pem       /etc/wazuh-dashboard/certs/root-ca.pem
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
""", check=False)
            o.ok("per-machine certificates generated and installed")
        else:
            o.warn("wazuh-certs-tool.sh not baked in — certificates must be generated")
            o.warn("  manually before the indexer will start.")

        # Enrollment password from credentials.json, per the documented flow.
        r.qrun(q["wazuh"],
               "if ! grep -q '<use_password>' /var/ossec/etc/ossec.conf; then "
               "  sed -i 's|<auth>|<auth>\\n      <use_password>yes</use_password>|' "
               "    /var/ossec/etc/ossec.conf; fi", check=False)
        r.qrun(q["wazuh"],
               "install -m 640 -o root -g wazuh /rw/golden-authd.pass "
               "/var/ossec/etc/authd.pass", check=False)

        o.info("starting indexer, manager and dashboard")
        for svc in ("wazuh-indexer", "wazuh-manager", "wazuh-dashboard"):
            r.qrun(q["wazuh"], f"systemctl daemon-reload && "
                               f"systemctl enable --now {svc}", check=False)

        # Apply the admin password we generated, so credentials.json is the
        # single source of truth rather than a vendor-random value nobody has.
        if r.qtest(q["wazuh"], "test -x /opt/wazuh-passwords-tool.sh"):
            # An empty -p used to set the indexer admin password to the empty
            # string and still print success, on any run where phase 2 had not
            # executed (a resume, or --phase 8).
            dash = self._need_secret("dashboard", 8)
            if not r.quiet("qvm-run", "--no-gui", "-u", "root", q["wazuh"],
                           "bash -c " + shlex.quote(
                               f"/opt/wazuh-passwords-tool.sh -u admin "
                               f"-p {shlex.quote(dash)}")):
                raise Fatal(
                    "setting the dashboard admin password failed. The indexer is "
                    "running with whatever password it generated, which nobody "
                    "has.\n     Fix it inside "
                    f"{q['wazuh']} and re-run:  sudo ./golden_image.py --phase 8")
            o.ok("dashboard admin password set from credentials.json")
            # The 'api' secret was generated, written into credentials.json,
            # documented in CREDENTIALS-README.txt and rotated — and applied to
            # nothing. Either it is a credential or it is not.
            api = self._need_secret("api", 8)
            if r.quiet("qvm-run", "--no-gui", "-u", "root", q["wazuh"],
                       "bash -c " + shlex.quote(
                           f"/opt/wazuh-passwords-tool.sh -u wazuh-wui "
                           f"-p {shlex.quote(api)}")):
                o.ok("API password set from credentials.json")
            else:
                o.warn("could not set the wazuh-wui API password — the dashboard "
                       "keeps whatever the installer generated. Reset it before "
                       "issuing the laptop.")
        else:
            o.warn("wazuh-passwords-tool.sh not available — the admin password is")
            o.warn("  whatever the indexer generated. Retrieve it from")
            o.warn("  /etc/wazuh-indexer/ or reset it before issuing the laptop.")

        o.info("group 13 asserts wazuh-manager, -indexer and -dashboard are active")
        o.verify(f"certificate paths against the Wazuh {w['version']} single-node "
                 f"guide — the layout changes between series, and this is the one "
                 f"thing group 13 cannot tell apart from a working install")
        o.info("agents self-enroll on first start (phase 11) — no manual key exchange")

        self._mark(8)

    # =======================================================================
    #  9 — app qubes
    # =======================================================================
    def _firewall_clear(self, vm: str) -> None:
        """Clear a qube's firewall rules.

        'reset' IS a documented subcommand on 4.3 — it is in the synopsis of
        qvm-firewall.rst in qubes-core-admin-client and registered in
        qubesadmin/tools/qvm_firewall.py. An earlier version of this file
        claimed otherwise and carried a rule-by-rule fallback for it. The
        capability check is kept because it costs one call and covers an older
        client, but the fallback is no longer the expected path.
        """
        o, r = self.out, self.r
        helptext = r.run("qvm-firewall", "--help", check=False, capture=True)
        if "reset" in helptext:
            r.quiet("qvm-firewall", vm, "reset")
            o.info(f"{vm}: rules cleared with 'reset'")
            return
        o.warn(f"this qvm-firewall has no 'reset' subcommand — falling back to "
               f"deleting rules one at a time")
        for _ in range(64):
            listing = r.run("qvm-firewall", vm, "list", check=False, capture=True)
            rows = [l for l in listing.splitlines()[1:] if l.strip()]
            if not rows:
                break
            if not r.quiet("qvm-firewall", vm, "del", "--rule-no", "0"):
                break
        o.info(f"{vm}: rules cleared with 'del --rule-no'")

    def p09(self):
        o, r, q = self.out, self.r, self.q
        for name in ("personal", "work", "vault"):
            if r.vm_exists(name) and r.vm_exists(self.t["personal"]):
                r.shutdown(name)
                r.run("qvm-prefs", name, "template", self.t["personal"])
                o.ok(f"{name} -> {self.t['personal']}")

        for name in ("personal", "work", "untrusted", "default-dvm"):
            if r.vm_exists(name):
                r.run("qvm-prefs", name, "netvm", q["proxy"])
                o.info(f"{name} -> netvm {q['proxy']}")

        if r.vm_exists("vault"):
            r.run("qvm-prefs", "vault", "netvm", "none")
            r.run("qvm-prefs", "vault", "label", "black")
            o.ok("vault is offline (netvm none)")

        if r.vm_exists(self.t["kali"]):
            if not r.vm_exists(q["kali_clear"]):
                r.run("qvm-create", "--class", "AppVM", "--template", self.t["kali"],
                      "--label", "yellow", q["kali_clear"])
                r.will_create(q["kali_clear"])
                o.ok(f"created {q['kali_clear']}")
            else:
                o.skip(q["kali_clear"])
            r.run("qvm-prefs", q["kali_clear"], "netvm", q["proxy"])

            if r.vm_exists(q["whonix"]):
                if not r.vm_exists(q["kali_tor"]):
                    r.run("qvm-create", "--class", "AppVM", "--template", self.t["kali"],
                          "--label", "purple", q["kali_tor"])
                    r.will_create(q["kali_tor"])
                    o.ok(f"created {q['kali_tor']}")
                else:
                    o.skip(q["kali_tor"])
                r.run("qvm-prefs", q["kali_tor"], "netvm", q["whonix"])
                o.info(f"{q['kali_tor']} -> {q['whonix']} (TCP only over Tor: no SYN "
                       "scans, no UDP, no ICMP)")

        if r.vm_exists(self.t["personal"]):
            if not r.vm_exists(q["dvm_offline"]):
                r.run("qvm-create", "--class", "AppVM", "--template", self.t["personal"],
                      "--label", "red", q["dvm_offline"])
                r.will_create(q["dvm_offline"])
                o.ok(f"created {q['dvm_offline']}")
            else:
                o.skip(q["dvm_offline"])
            r.run("qvm-prefs", q["dvm_offline"], "netvm", "none")
            r.run("qvm-prefs", q["dvm_offline"], "template_for_dispvms", "True")
            r.run("qvm-features", q["dvm_offline"], "appmenus-dispvm", "1")
            o.info(f"{q['dvm_offline']}: evidence opens here — no network, destroyed on close")

        for name in ("personal", "work"):
            if not r.vm_exists(name):
                continue
            if self.args.dry_run:
                o.info(f"[dry-run] qvm-firewall {name}: web + dns only")
                continue
            self._firewall_clear(name)
            # The SIEM first: phase 11 enrols these qubes over the network to
            # wazuh.ip on 1514/1515. Qubes enforces per-VM rules in their own
            # chain, so the accept added to sys-proxy's custom-forward does not
            # help here — without these two lines the trailing drop silently
            # stopped every agent from reporting.
            w = self.c["wazuh"]
            if w["mode"] != "central":
                for port in (w["port_events"], w["port_enroll"]):
                    r.run("qvm-firewall", name, "add", "accept", "proto=tcp",
                          f"dsthost={w['ip']}", f"dstports={port}")
            r.run("qvm-firewall", name, "add", "accept", "proto=tcp", "dstports=80")
            r.run("qvm-firewall", name, "add", "accept", "proto=tcp", "dstports=443")
            r.run("qvm-firewall", name, "add", "accept", "specialtarget=dns")
            r.run("qvm-firewall", name, "add", "drop")
            o.ok(f"{name} egress restricted to web + dns (plus the SIEM)")
        self._mark(9)

    # =======================================================================
    #  10 — policy, segmentation, backup
    # =======================================================================
    def _qrexec_telemetry_qubes(self) -> list[str]:
        """Qubes whose agent traffic must travel over qrexec rather than the
        network: the Tor branch (which must never beacon clearnet) and
        everything upstream of sys-proxy (which has no route down to the SIEM
        — the SIEM hangs off sys-proxy, so only its downstream can reach it)."""
        q = self.q
        return [q["whonix"], q["kali_tor"], "anon-whonix",
                q["ids"], q["dpi"], q["firewall"], q["net"], q["usb"]]

    def p10(self):
        o, r, q, w, b = self.out, self.r, self.q, self.c["wazuh"], self.c["backup"]
        pol = dom0("/etc/qubes/policy.d/30-golden-image.policy")
        # The third column is the DESTINATION of the request.
        # `qvm-connect-tcp <local>:<vm>:<port>` names <vm> as the destination, so
        # a rule whose destination is @default does not match it — @default only
        # matches the form with an empty middle field. Every caller in this image
        # names the qube explicitly, so the rules do too; the @default form is
        # kept alongside for anyone who types the short version by hand.
        lines = [f"# {self.c['image_name']} v{self.c['image_version']}",
                 "# Dashboard reachable only from 'work', over qrexec — no open "
                 "HTTPS port.",
                 f"qubes.ConnectTCP +443  work  {q['wazuh']}  allow",
                 f"qubes.ConnectTCP +443  work  @default  allow target={q['wazuh']}",
                 "",
                 "# Telemetry for qubes with no network route to the SIEM: the Tor",
                 "# branch (nothing beacons clearnet from an anonymous context) and",
                 f"# everything upstream of {q['proxy']}, which cannot route down to it.",
                 "# Both ports: an agent registers on "
                 f"{w['port_enroll']} before it can send an event on {w['port_events']}."]
        for vm in self._qrexec_telemetry_qubes():
            for port in (w["port_events"], w["port_enroll"]):
                lines.append(f"qubes.ConnectTCP +{port}  {vm}  {q['wazuh']}  allow")
                lines.append(f"qubes.ConnectTCP +{port}  {vm}  @default  "
                             f"allow target={q['wazuh']}")
        policy = "\n".join(lines) + "\n"
        if self.args.dry_run:
            o.info(f"[dry-run] write {pol}")
        else:
            pol.parent.mkdir(parents=True, exist_ok=True)
            pol.write_text(policy)
            o.ok(f"wrote {pol}")
        o.info("group 13 opens the dashboard from 'work' over qrexec, which is the "
               "policy grammar and the argument order both, tested end to end")

        for name in self._qrexec_telemetry_qubes():
            if not r.vm_exists(name):
                continue
            r.ensure_running(name)
            self._rc_hook(name, "golden-image-telemetry.sh",
                          "#!/bin/sh\n"
                          "# Golden image — Tor-branch telemetry over qrexec, never\n"
                          "# the network. Both ports: enrollment first, then events.\n"
                          f"qvm-connect-tcp {w['port_enroll']}:{q['wazuh']}:{w['port_enroll']} &\n"
                          f"qvm-connect-tcp {w['port_events']}:{q['wazuh']}:{w['port_events']} &\n")
            o.ok(f"{name}: qrexec telemetry pipes staged (events + enrollment)")

        # --- backup -------------------------------------------------------
        # qvm-backup has NO --yes flag. Profile mode is the documented
        # non-interactive path: the profile carries destination, passphrase and
        # include list, and --profile is mutually exclusive with everything else.
        prof_name = "golden-image"
        prof_path = dom0(f"/etc/qubes/backup/{prof_name}.conf")
        bscript = dom0("/usr/local/bin/golden-weekly-backup.sh")
        tpls = [self.t["kali"], self.t["personal"], self.t["ids"],
                self.t["proxy"], self.t["sys"], self.t["wazuh"]]
        base_include = ["dom0", "vault", "personal", "work",
                        q["kali_clear"], q["wazuh"]] + tpls

        if self.args.dry_run:
            o.info(f"[dry-run] write {prof_path}, {bscript}, timer ({b['schedule']})")
        else:
            # Case qubes come and go, so the profile is regenerated before each
            # run rather than frozen at provisioning time.
            prof_path.parent.mkdir(parents=True, exist_ok=True)
            self._write_backup_profile(prof_path, base_include)
            prof_path.chmod(0o600)
            o.ok(f"wrote {prof_path} (mode 600 — it holds the passphrase)")

            bscript.parent.mkdir(parents=True, exist_ok=True)
            bscript.write_text(f"""#!/bin/bash
# {self.c['image_name']} — weekly backup
# Regenerates the profile so current case-* qubes are included, then runs it.
# Deliberately excluded: the Tor branch (holds nothing, and backing it up would
# copy anonymous-context artifacts into attributed storage) and stock templates.
set -e
PROFILE={prof_name}
CONF=/etc/qubes/backup/$PROFILE.conf
BASE="{' '.join(base_include)}"
KEEP={b['keep_sets']}
DEST_DIR={shlex.quote(b['dest_dir'])}
DEST_VM={shlex.quote(b['dest_qube'])}
CASES=$(qvm-ls --raw-list | grep '^case-' || true)

# The passphrase comes from /root/.backup-pass (mode 600) and is written into
# the profile as passphrase_text — the only file-free key qvm-backup accepts.
# The profile is written 600 before anything is put in it.
umask 077
: > "$CONF"
{{
  echo "destination_vm: {b['dest_qube']}"
  echo "destination_path: {b['dest_dir']}"
  echo "compression: true"
  echo "passphrase_text: $(cat /root/.backup-pass)"
  echo "include:"
  for v in $BASE $CASES; do
      qvm-check --quiet "$v" 2>/dev/null && echo " - $v"
  done
}} > "$CONF"
chmod 600 "$CONF"

# --yes: it is registered on qvm-backup's top-level parser, not inside the
# mutually-exclusive "Profile setup" group, so it combines with --profile. A
# release note in this repository once claimed the flag does not exist; it does,
# and a timer that can be asked a y/N question is a timer that hangs forever.
qvm-backup --yes --profile "$PROFILE"

# Retention. backup.keep_sets used to be documented in CREDENTIALS-README.txt
# as a policy and implemented nowhere, so the destination filled up until the
# weekly backup started failing for want of space.
if [ "$KEEP" -gt 0 ]; then
    old=$(qvm-run --no-gui --pass-io -u root "$DEST_VM" \
          "ls -1t '$DEST_DIR'/qubes-backup-* 2>/dev/null | tail -n +$((KEEP + 1))" \
          || true)
    for f in $old; do
        qvm-run --no-gui -u root "$DEST_VM" "rm -f -- '$f'" && \
            logger -t golden-image "pruned old backup set $f"
    done
fi
""")
            bscript.chmod(0o755)
            dom0("/etc/systemd/system").mkdir(parents=True, exist_ok=True)
            dom0("/etc/systemd/system/golden-backup.service").write_text(
                "[Unit]\nDescription=Golden image weekly Qubes backup\n"
                "[Service]\nType=oneshot\n"
                f"ExecStart={bscript}\n")
            dom0("/etc/systemd/system/golden-backup.timer").write_text(
                "[Unit]\nDescription=Run the golden image weekly backup\n"
                f"[Timer]\nOnCalendar={b['schedule']}\nPersistent=true\n"
                "[Install]\nWantedBy=timers.target\n")
            r.quiet("systemctl", "daemon-reload")
            if r.quiet("systemctl", "enable", "--now", "golden-backup.timer"):
                o.ok(f"backup timer enabled ({b['schedule']})")
            else:
                o.warn("could not enable golden-backup.timer — enable it manually")

        o.info("the backup profile schema is validated by the acceptance tests "
               "(phase 12, group 11) — no manual qvm-backup run needed")
        o.warn("escrow the backup passphrase before shredding credentials.json — "
               "no passphrase, no restore")

        self._install_backup_media_automount()
        self._install_dom0_timers()
        self._install_dashboard_launcher()
        self._mark(10)

    # -----------------------------------------------------------------------
    #  Ongoing operation — GUIDE section 12, as timers rather than a table
    # -----------------------------------------------------------------------
    def _install_backup_media_automount(self) -> None:
        """"Attach the backup disk and mount it" becomes "plug it in"."""
        o, r, b = self.out, self.r, self.c["backup"]
        dest, path = b["dest_qube"], b["dest_dir"]
        label = b["media_label"]
        if not r.vm_exists(dest):
            o.warn(f"{dest} does not exist — cannot arm the backup automount")
            return
        r.ensure_running(dest)
        unit = path.strip("/").replace("/", "-")
        r.qwrite(dest, f"/rw/config/golden-backup-mount/{unit}.mount",
                 f"[Unit]\nDescription=Golden image backup media\n"
                 f"\n[Mount]\nWhat=/dev/disk/by-label/{label}\nWhere={path}\n"
                 f"Options=noatime\n")
        self._rc_hook(dest, "golden-image-backup-media.sh", f"""\
#!/bin/sh
# Golden image — mount the backup disk whenever it appears.
# The disk is identified by filesystem LABEL, not by device node: /dev/sdb is
# whatever was plugged in last, and a backup written to the wrong disk is worse
# than no backup.
set -e
mkdir -p {shlex.quote(path)}
install -m 644 /rw/config/golden-backup-mount/{unit}.mount \\
    /etc/systemd/system/{unit}.mount
cat > /etc/udev/rules.d/99-golden-backup.rules <<'UDEVEOF'
ACTION=="add", SUBSYSTEM=="block", ENV{{ID_FS_LABEL}}=="{label}", \\
    TAG+="systemd", ENV{{SYSTEMD_WANTS}}="{unit}.mount"
UDEVEOF
udevadm control --reload 2>/dev/null || true
systemctl daemon-reload
systemctl start {unit}.mount 2>/dev/null || true
""")
        o.ok(f"{dest}: a disk labelled {label} now mounts itself at {path}")
        o.info(f"  label the backup disk once:  mkfs.ext4 -L {label} /dev/sdX1")

    def _dom0_unit(self, name: str, description: str, oncalendar: str,
                   body: str) -> None:
        o, r = self.out, self.r
        script = dom0(f"/usr/local/sbin/{name}")
        if self.args.dry_run:
            o.info(f"[dry-run] install {name}.timer ({oncalendar})")
            return
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(body)
        script.chmod(0o755)
        dom0("/etc/systemd/system").mkdir(parents=True, exist_ok=True)
        dom0(f"/etc/systemd/system/{name}.service").write_text(
            f"[Unit]\nDescription={description}\n"
            f"\n[Service]\nType=oneshot\nExecStart={script}\n")
        dom0(f"/etc/systemd/system/{name}.timer").write_text(
            f"[Unit]\nDescription=Schedule: {description}\n"
            f"\n[Timer]\nOnCalendar={oncalendar}\nPersistent=true\n"
            f"RandomizedDelaySec=1800\n"
            f"\n[Install]\nWantedBy=timers.target\n")
        r.quiet("systemctl", "daemon-reload")
        if r.quiet("systemctl", "enable", "--now", f"{name}.timer"):
            o.ok(f"{name}.timer enabled ({oncalendar})")
        else:
            o.warn(f"could not enable {name}.timer")

    def _install_dom0_timers(self) -> None:
        """Everything GUIDE section 12 listed as a cadence for a human."""
        o = self.out
        me = Path(sys.argv[0]).resolve()

        self._dom0_unit(
            "golden-template-update",
            "Weekly template and dom0 update check",
            "Sun 02:00",
            """#!/bin/bash
# Golden image — weekly updates. Templates first; dom0 is reported, never
# applied unattended, because a dom0 update can require a reboot and an
# investigator's laptop is not the place to discover that at 02:00.
#
# Which updater exists, and which flags it takes, varies across 4.3 point
# releases — so ask, rather than assume, exactly as the firewall code asks
# about 'qvm-firewall reset'.
set -u
if command -v qubes-vm-update >/dev/null; then
    opts=""
    qubes-vm-update --help 2>&1 | grep -q -- --show-output && \
        opts="$opts --show-output"
    qubes-vm-update --all $opts 2>&1 | logger -t golden-image
elif command -v qubesctl >/dev/null; then
    qubesctl --show-output --skip-dom0 --templates state.sls update.qubes-vm \
        2>&1 | logger -t golden-image
else
    logger -t golden-image "no template updater found — update by hand"
fi
if qubes-dom0-update --check-only >/dev/null 2>&1; then
    logger -t golden-image "dom0 updates are available — apply them by hand"
    mkdir -p /etc/motd.d
    echo "  dom0 updates are available: sudo qubes-dom0-update" \
        > /etc/motd.d/golden-image-updates
else
    rm -f /etc/motd.d/golden-image-updates
fi
""")

        self._dom0_unit(
            "golden-selfcheck",
            "Weekly re-run of the acceptance tests",
            "Mon 07:00",
            f"""#!/bin/bash
# Golden image — the acceptance tests are not a one-off gate before issue.
# Chain order, netvm assignments and the SIEM can all drift afterwards; this
# notices within a week rather than at the next incident.
set -u
LOG=/var/log/golden-image-selfcheck.log
if {shlex.quote(str(me))} --verify >> "$LOG" 2>&1; then
    logger -t golden-image "weekly acceptance tests: all passed"
    rm -f /etc/motd.d/golden-image-selfcheck
else
    logger -t golden-image "weekly acceptance tests FAILED — see $LOG"
    mkdir -p /etc/motd.d
    {{
      echo
      echo "  *** GOLDEN IMAGE ACCEPTANCE TESTS FAILED ***"
      echo "      $(date '+%F %T')  —  see $LOG"
      echo "      Re-run: sudo {me.name} --verify"
      echo
    }} > /etc/motd.d/golden-image-selfcheck
fi
""")

        self._dom0_unit(
            "golden-restore-test",
            "Monthly restore verification of the newest backup set",
            "*-*-01 04:00",
            f"""#!/bin/bash
# Golden image — a backup nobody has restored is a hope, not a backup.
# GUIDE section 12 asked for this monthly, calendared, with a named owner.
# This performs it: restore the newest set into a throwaway prefix, confirm
# the qubes appear, then delete them.
set -u
PROFILE=golden-image
LOG=/var/log/golden-image-restore-test.log
exec >> "$LOG" 2>&1
echo "=== $(date '+%F %T') restore verification"

DEST_VM={shlex.quote(self.c['backup']['dest_qube'])}
DEST_DIR={shlex.quote(self.c['backup']['dest_dir'])}
SET=$(qvm-run --no-gui --pass-io -u root "$DEST_VM" \
      "ls -1t '$DEST_DIR'/qubes-backup-* 2>/dev/null | head -1")
if [ -z "$SET" ]; then
    logger -t golden-image "restore test: no backup set found on $DEST_VM"
    exit 1
fi
echo "set: $SET"

# --verify-only reads the whole archive and checks its integrity without
# creating a single qube, so this is safe to run unattended on a working
# machine. vault is small and offline: the cheapest meaningful proof that the
# passphrase, the media and the archive still work together.
#   -d names the qube holding the backup; the positional is the path within it.
if qvm-backup-restore --verify-only -d "$DEST_VM" \
       --passphrase-file /root/.backup-pass "$SET" vault; then
    logger -t golden-image "restore test PASSED for $SET"
    rm -f /etc/motd.d/golden-image-restore
else
    logger -t golden-image "restore test FAILED for $SET — see $LOG"
    mkdir -p /etc/motd.d
    echo "  *** BACKUP RESTORE VERIFICATION FAILED — see $LOG ***" \
        > /etc/motd.d/golden-image-restore
fi
""")

        self._dom0_unit(
            "golden-staleness",
            "Warn when this image is too old to install safely",
            "*-*-* 08:00",
            f"""#!/bin/bash
# Golden image — an ISO freezes dom0, Xen and the kernel at build time.
# README says a stale image is a liability; this is what says so out loud.
set -u
STAMP=/var/lib/golden-image/built
[ -e "$STAMP" ] || exit 0
age=$(( ( $(date +%s) - $(stat -c %Y "$STAMP") ) / 86400 ))
mkdir -p /etc/motd.d
if [ "$age" -gt {self.c['staleness_warn_days']} ]; then
    {{
      echo
      echo "  This image was provisioned $age days ago."
      echo "  Rebuild and re-cut the ISO if any Qubes Security Bulletin since"
      echo "  then affects dom0, Xen or the kernel:"
      echo "      ./build_iso.py check-upstream     (on the build host)"
      echo
    }} > /etc/motd.d/golden-image-staleness
else
    rm -f /etc/motd.d/golden-image-staleness
fi
""")
        if not self.args.dry_run:
            stamp = dom0("/var/lib/golden-image/built")
            stamp.parent.mkdir(parents=True, exist_ok=True)
            stamp.write_text(f"{datetime.now():%Y-%m-%d %H:%M:%S}\n")

    def _install_dashboard_launcher(self) -> None:
        """The dashboard was reached by typing a qvm-connect-tcp line from the
        guide. Ship it as something to click instead."""
        o, r, q = self.out, self.r, self.q
        if not r.vm_exists("work"):
            return
        r.ensure_running("work")
        r.qwrite("work", "/rw/config/golden-image-dashboard.sh", f"""\
#!/bin/sh
# Golden image — open the SIEM dashboard over qrexec.
# No HTTPS port is exposed anywhere; qubes.ConnectTCP carries it, and only
# from this qube, per /etc/qubes/policy.d/30-golden-image.policy in dom0.
set -e
PORT=8443
if ! ss -ltn 2>/dev/null | grep -q ":$PORT "; then
    qvm-connect-tcp "$PORT:{q['wazuh']}:443" &
    sleep 3
fi
exec xdg-open "https://localhost:$PORT"
""", mode="0755")
        r.qwrite("work", "/rw/config/golden-image-dashboard.desktop",
                 "[Desktop Entry]\nType=Application\n"
                 "Name=SIEM dashboard\n"
                 "Comment=Wazuh dashboard for this workstation, over qrexec\n"
                 "Exec=/rw/config/golden-image-dashboard.sh\n"
                 "Icon=security-high\nTerminal=false\n"
                 "Categories=System;Security;\n")
        self._rc_hook("work", "golden-image-dashboard-install.sh", """\
#!/bin/sh
mkdir -p /usr/local/share/applications
install -m 644 /rw/config/golden-image-dashboard.desktop \\
    /usr/local/share/applications/golden-image-dashboard.desktop
""")
        o.ok("work: 'SIEM dashboard' launcher installed (no qvm-connect-tcp to type)")

    def _write_backup_profile(self, path: Path, include: list[str]) -> None:
        """Write a qvm-backup profile.

        Profile mode is the only documented non-interactive path (there is no
        --yes flag). The schema is flagged [VERIFY]: confirm with one manual
        run, or generate a reference profile via --save-profile.
        """
        # qubes-core-admin's _load_backup_profile accepts exactly two ways to
        # supply the secret: passphrase_text, or passphrase_vm naming a qube
        # that answers qubes.BackupPassphrase. There is no passphrase_file key —
        # a profile carrying one is rejected with "specify passphrase_text or
        # passphrase_vm", so the weekly backup would have failed every Sunday.
        # The profile is mode 600 in dom0, the same protection /root/.backup-pass
        # had.
        lines = [f"destination_vm: {self.c['backup']['dest_qube']}",
                 f"destination_path: {self.c['backup']['dest_dir']}",
                 "compression: true",
                 f"passphrase_text: {self._need_secret('backup', 10)}",
                 "include:"]
        for vm in include:
            if vm == "dom0" or self.r.vm_exists(vm):
                lines.append(f" - {vm}")
        path.write_text("\n".join(lines) + "\n")

    # =======================================================================
    #  11 — enrollment
    # =======================================================================
    def _enroll(self, vm: str, via: str, target: str):
        o, r = self.out, self.r
        if not r.vm_exists(vm):
            return
        r.ensure_running(vm)
        r.qwrite(vm, "/rw/config/qubes-bind-dirs.d/50_golden_wazuh.conf",
                 "binds+=( '/var/ossec' )\n")
        # bind-dirs copies the template's copy into /rw/bind-dirs on first use.
        # If the path does not already exist there, that copy fails and the
        # agent silently loses its identity on every reboot. Seed it explicitly.
        r.qrun(vm, "mkdir -p /rw/bind-dirs/var && "
                   "if [ ! -d /rw/bind-dirs/var/ossec ] && [ -d /var/ossec ]; then "
                   "  cp -a /var/ossec /rw/bind-dirs/var/ossec; fi", check=False)
        if self.args.dry_run:
            o.info(f"[dry-run] enroll {vm} via {via} -> {target}")
            return
        if not r.qtest(vm, "test -d /var/ossec"):
            o.warn(f"{vm}: agent not present — enroll later")
            return
        # Over stdin, not on the command line: qvm-run puts its argument in the
        # argv of a process INSIDE the target qube, and /proc/<pid>/cmdline is
        # world-readable there. The enrollment secret would have been visible to
        # anything the investigator ran in that qube.
        pw = self._need_secret("authd", 11)
        r.qwrite(vm, "/var/ossec/etc/authd.pass", pw, mode="0640")
        r.qrun(vm, "chown root:wazuh /var/ossec/etc/authd.pass 2>/dev/null || true")
        r.qrun(vm, "sed -i -e 's|<address>MANAGER_IP</address>|"
                   f"<address>{target}</address>|' "
                   f"-e 's|<address>[0-9.]*</address>|<address>{target}</address>|' "
                   "/var/ossec/etc/ossec.conf")
        # `systemctl enable` writes a symlink under /etc/systemd/system, which
        # in an AppVM is volatile — the agent came back DISABLED at the next
        # boot, on every qube, silently. /rw/config/rc.local is the persistent
        # place, so the agent is started from there instead. (The unit itself
        # lives in the template, where it belongs.)
        self._rc_hook(vm, "golden-image-agent.sh",
                      "#!/bin/sh\n"
                      "# Golden image — start the SIEM agent.\n"
                      "# 'systemctl enable' does not survive an AppVM reboot; this does.\n"
                      "systemctl start wazuh-agent\n")
        r.qrun(vm, "systemctl start wazuh-agent", check=False)
        o.ok(f"{vm} enrolled via {via} -> {target}")

    def p11(self):
        o, q, w = self.out, self.q, self.c["wazuh"]
        mgr = w["central_address"] if w["mode"] == "central" else w["ip"]
        if not self.creds and self.cred_file.exists():
            self.creds = json.loads(self.cred_file.read_text())

        # Which transport a qube gets is decided by where it sits in the chain,
        # not by whether it is "clearnet".
        #
        # wazuh-srv hangs off sys-proxy, i.e. at the BOTTOM of the chain. Only
        # qubes downstream of sys-proxy can route to it. sys-ids, sys-dpi,
        # sys-firewall, sys-net and sys-usb are all UPSTREAM: their traffic goes
        # outward, never back down into a sibling of their own client. Enrolling
        # them at 10.137.0.50 pointed them at an address unreachable from them
        # by construction, and they would simply never have reported.
        o.info("network transport — qubes that can actually route to the SIEM")
        for vm in (q["proxy"], "personal", "work", "untrusted", q["kali_clear"]):
            self._enroll(vm, "network", mgr)

        o.info("qrexec transport — the Tor branch, and everything upstream of "
               f"{q['proxy']}")
        for vm in (q["whonix"], q["kali_tor"], "anon-whonix",
                   q["ids"], q["dpi"], q["firewall"], q["net"], q["usb"]):
            self._enroll(vm, "qrexec pipe", "127.0.0.1")

        o.say("")
        o.warn(f"{q['dvm_offline']} and vault keep the agent installed but dormant — "
               "they are offline.")
        o.warn("dom0 gets no agent: bridging dom0 to the network for telemetry would be "
               "the worst trade in the whole image.")
        o.say("")
        o.warn("RECORDED RISK — Tor-branch telemetry lands in the same index as "
               "attributed telemetry.")
        o.warn("  The qrexec transport keeps that correlation local to this laptop "
               "(nothing beacons")
        o.warn("  clearnet from an anonymous context). If a case demands zero linkage, "
               "disable the")
        o.warn(f"  agent in {q['kali_tor']} for the duration and note it in the case log.")
        self._mark(11)

    # =======================================================================
    #  12 — acceptance tests
    # =======================================================================
    def _t(self, kind: str, msg: str):
        sym = {"pass": (Out.G, "\u2713 PASS"), "fail": (Out.R, "\u2717 FAIL"),
               "warn": (Out.Y, "~ WARN")}[kind]
        print(f"  {sym[0]}{sym[1]}{Out.RST}  {msg}")
        self.out._log(f"{kind.upper()} {msg}")
        self.tests[kind] += 1

    def p12(self):
        o, r, q, w = self.out, self.r, self.q, self.c["wazuh"]
        if self.args.dry_run:
            o.info("[dry-run] acceptance tests are read-only; run them for real")
            return

        # A check that never runs cannot fail, and the gate counts failures. So
        # a half-finished build — sys-ids never created, --verify run before
        # phase 6, an aborted phase 8 — used to sail through most of these
        # groups, because every one of them starts "if not r.vm_exists(...):
        # continue". Assert the estate exists FIRST.
        o.say("")
        o.info("0. every qube and template this design requires exists")
        required = [q["proxy"], q["ids"], q["dpi"], q["firewall"], q["net"],
                    self.t["sys"], self.t["proxy"], self.t["ids"],
                    self.t["kali"], self.t["personal"]]
        if self.c["wazuh"]["mode"] != "central":
            required += [q["wazuh"], self.t["wazuh"]]
        for name in required:
            present = r.vm_exists(name)
            self._t("pass" if present else "fail",
                    f"{name} exists" if present else
                    f"{name} is MISSING — every test that would have examined it "
                    f"is silently skipped")
        for name in (q["whonix"], q["kali_tor"], q["usb"], q["dvm_offline"],
                     "personal", "work", "vault"):
            if not r.vm_exists(name):
                self._t("warn", f"{name} does not exist — its checks are skipped")

        o.say("")
        o.info("1. chain order")
        expect = [
            (q["proxy"], q["ids"]), (q["ids"], q["dpi"]), (q["dpi"], q["firewall"]),
            (q["firewall"], q["net"]), (q["kali_clear"], q["proxy"]),
            ("personal", q["proxy"]), ("work", q["proxy"]),
            (q["wazuh"], q["proxy"]), (q["whonix"], q["firewall"]),
            (q["kali_tor"], q["whonix"]),
        ]
        for vm, want in expect:
            if not r.vm_exists(vm):
                self._t("warn", f"{vm} does not exist")
                continue
            got = r.run("qvm-prefs", vm, "netvm", check=False, capture=True).strip()
            self._t("pass" if got == want else "fail",
                    f"{vm} -> {got}" + ("" if got == want else f" (expected {want})"))

        o.say("")
        o.info("2. no clearnet qube bypasses the inspection stack")
        exempt = {q["proxy"], q["ids"], q["dpi"], q["firewall"], q["net"], q["whonix"]}
        strays = 0
        data = r.run("qvm-ls", "--raw-data", "--fields", "NAME,NETVM",
                     check=False, capture=True)
        for line in data.splitlines():
            parts = line.split("|")
            if len(parts) < 2:
                continue
            name, netvm = parts[0].strip(), parts[1].strip()
            if name in exempt or not name:
                continue
            if netvm in (q["firewall"], q["net"]):
                self._t("fail", f"{name} attaches directly to {netvm} — must use {q['proxy']}")
                strays += 1
        if strays == 0:
            self._t("pass", f"every clearnet qube enters at {q['proxy']}")

        o.say("")
        o.info("3. offline qubes have no netvm")
        for vm in ("vault", q["dvm_offline"]):
            if not r.vm_exists(vm):
                continue
            nv = r.run("qvm-prefs", vm, "netvm", check=False, capture=True).strip()
            offline = nv.lower() in ("", "none")
            self._t("pass" if offline else "fail",
                    f"{vm} is offline" if offline else f"{vm} has netvm '{nv}'")

        o.say("")
        o.info("4. Wazuh agent present in every template")
        covered = [self.t["sys"], self.t["proxy"], self.t["ids"], self.t["kali"],
                   self.t["personal"], self.t["wazuh"], self.c["base_debian"],
                   self.c["base_whonix_gw"], self.c["base_whonix_ws"]]
        if self.c["use_fedora_template"]:
            covered.append(self.c["base_fedora"])
        o.info(f"   {len(covered)} templates in service")
        for tpl in covered:
            if not r.vm_exists(tpl):
                continue
            # Once, not twice: each qtest is a qvm-run round trip that starts a
            # halted template, and two independent calls could disagree.
            has_agent = r.qtest(tpl, "test -d /var/ossec")
            self._t("pass" if has_agent else "fail",
                    f"{tpl} carries the agent" if has_agent
                    else f"{tpl} has no /var/ossec")

        if self.c["prefer_debian"]:
            o.say("")
            o.info("5. Debian everywhere it is possible")
            for tpl in (self.t["sys"], self.t["proxy"], self.t["ids"],
                        self.t["kali"], self.t["personal"], self.t["wazuh"]):
                if not r.vm_exists(tpl):
                    continue
                self._t("pass" if r.qtest(tpl, "test -f /etc/debian_version") else "fail",
                        f"{tpl} is Debian-based")
            self._t("warn", "dom0 is Fedora by Qubes architecture — not changeable")

            for pkg in ("qubes-core-agent-networking", "qubes-usb-proxy"):
                if r.vm_exists(self.t["sys"]):
                    good = r.qtest(self.t["sys"], f"dpkg -s {pkg} >/dev/null 2>&1")
                    self._t("pass" if good else "fail",
                            f"{self.t['sys']} has {pkg}")

        o.say("")
        o.info("6. supply chain integrity")
        k = self.c["kali"]
        if r.vm_exists(self.t["kali"]):
            r.ensure_running(self.t["kali"])
            good = r.qtest(self.t["kali"],
                           f"gpg --no-default-keyring --keyring "
                           f"{shlex.quote(k['keyring_path'])} --with-colons "
                           f"--fingerprint 2>/dev/null "
                           f"| awk -F: '$1==\"fpr\"{{print toupper($10)}}' "
                           f"| grep -qxF {shlex.quote(k['key_fpr'].upper())}")
            self._t("pass" if good else "fail",
                    "Kali keyring carries the expected 2025 signing key" if good
                    else "Kali keyring fingerprint mismatch — investigate before shipping")
        if r.vm_exists(self.t["ids"]):
            zp = self.c["zeek"]["prefix"]
            good = r.qtest(self.t["ids"], f"test -x {zp}/bin/zeek")
            self._t("pass" if good else "fail",
                    f"Zeek present at {zp}" if good else f"Zeek binary missing at {zp}")
        if w["pin_agent"]:
            checked = held = 0
            for tpl in (self.t["proxy"], self.t["ids"], self.t["kali"], self.t["personal"]):
                if not r.vm_exists(tpl):
                    continue
                checked += 1
                if r.qtest(tpl, "dpkg --get-selections wazuh-agent | grep -q hold"):
                    held += 1
            if checked and held == checked:
                self._t("pass", f"wazuh-agent version-held in all {checked} Debian templates")
            else:
                self._t("fail", f"wazuh-agent held in only {held} of {checked} templates — "
                                "weekly updates can overtake the manager")

        o.say("")
        o.info("7. DNS enforcement")
        if r.vm_exists("personal"):
            r.ensure_running("personal")
            if not r.qtest("personal", "command -v dig >/dev/null"):
                self._t("warn", "dig is not installed in personal — install "
                                "dnsutils or this group proves nothing")
            else:
                # The old test read 'dig @8.8.8.8 exited 0' as 'the packet
                # reached Google'. It does not: a WORKING intercept answers that
                # query locally, so correct enforcement scored FAIL and a missing
                # dig scored PASS. Assert capture directly instead — 192.0.2.1 is
                # TEST-NET-1, guaranteed unrouted, so an answer from it can only
                # have come from the local redirect.
                captured = r.quiet(
                    "qvm-run", "--no-gui", "personal",
                    "timeout 8 dig +short +time=3 +tries=1 @192.0.2.1 example.com")
                self._t("pass" if captured else "fail",
                        "every port-53 query is captured, whatever resolver the "
                        "client asks for" if captured else
                        "a query to an unrouted resolver was not intercepted — "
                        "a client with a hardcoded resolver escapes the enforced path")
                answered = r.quiet(
                    "qvm-run", "--no-gui", "personal",
                    "timeout 8 dig +short +time=3 +tries=1 @8.8.8.8 example.com")
                self._t("pass" if answered else "warn",
                        "8.8.8.8 is answered by the enforced resolver, not by Google"
                        if answered else
                        "queries addressed to 8.8.8.8 get no answer at all — "
                        "check unbound in " + q["firewall"])
            # A fail, not a warn: warnings never block, and this is the only
            # end-to-end check that the enforced DNS path works at all. A
            # workstation that resolves nothing used to pass phase 12.
            resolves = r.quiet("qvm-run", "--no-gui", "personal",
                               "timeout 8 getent hosts example.com")
            self._t("pass" if resolves else "fail",
                    "name resolution works via the enforced path" if resolves
                    else f"personal cannot resolve anything — check unbound in "
                         f"{q['firewall']}")

        o.say("")
        o.info("8. inspection services")
        if r.vm_exists(q["ids"]):
            r.ensure_running(q["ids"])
            self._t("pass" if r.qtest(q["ids"], "pgrep -x suricata") else "fail",
                    f"Suricata running in {q['ids']}")
            self._t("pass" if r.qtest(q["ids"],
                    "nft list chain ip qubes custom-forward 2>/dev/null | grep -q queue")
                    else "fail", "NFQUEUE hook present")
        if r.vm_exists(q["dpi"]):
            r.ensure_running(q["dpi"])
            self._t("pass" if r.qtest(q["dpi"], "pgrep -f zeek") else "warn",
                    f"Zeek running in {q['dpi']}")
        if r.vm_exists(q["proxy"]):
            r.ensure_running(q["proxy"])
            self._t("pass" if r.qtest(q["proxy"], "pgrep -x squid") else "fail",
                    f"Squid running in {q['proxy']}")

        o.say("")
        o.info("9. proxy logs the originating qube")
        if r.vm_exists("personal") and r.vm_exists(q["proxy"]):
            r.quiet("qvm-run", "--no-gui", "personal",
                    "timeout 10 curl -s -o /dev/null http://example.com/golden-image-canary")
            time.sleep(3)
            self._t("pass" if r.qtest(q["proxy"], "grep -q 10.137 /var/log/squid/access.log")
                    else "warn", "Squid access.log carries per-qube source addresses")

        o.say("")
        o.info("10. Tor branch")
        if r.vm_exists(q["kali_tor"]):
            nv = r.run("qvm-prefs", q["kali_tor"], "netvm", check=False, capture=True).strip()
            self._t("pass" if nv == q["whonix"] else "fail",
                    f"{q['kali_tor']} routes via {q['whonix']} only" if nv == q["whonix"]
                    else f"{q['kali_tor']} routes via '{nv}' — the Tor branch is bypassed")
            # This was "manual: open Tor Browser and look". The Tor Project
            # publishes a machine-readable endpoint for exactly this question.
            r.ensure_running(q["kali_tor"])
            out = r.run("qvm-run", "--no-gui", "--pass-io", q["kali_tor"],
                        "timeout 45 curl -s https://check.torproject.org/api/ip",
                        check=False, capture=True)
            if '"IsTor":true' in out.replace(" ", ""):
                self._t("pass", "check.torproject.org confirms traffic exits over Tor")
            elif '"IsTor":false' in out.replace(" ", ""):
                self._t("fail", f"{q['kali_tor']} reaches the internet but NOT over "
                                f"Tor — an OSINT qube leaking its real address")
            else:
                self._t("warn", "could not reach check.torproject.org — no network, "
                                "or Tor is still bootstrapping")

        o.say("")
        o.info("11. backup")
        self._t("pass" if r.quiet("systemctl", "is-enabled", "golden-backup.timer")
                else "fail", "golden-backup.timer enabled")
        self._t("pass" if dom0("/root/.backup-pass").exists() else "fail",
                "backup passphrase file present"
                if dom0("/root/.backup-pass").exists() else
                "/root/.backup-pass missing — the weekly backup cannot run")

        o.say("")
        o.info("12. credentials")
        if self.cred_file.exists():
            mode = oct(self.cred_file.stat().st_mode)[-3:]
            self._t("pass" if mode == "600" else "fail", f"credentials.json mode {mode}")
            if self.c["credentials"]["use_fixed_defaults"]:
                self._t("warn", "use_fixed_defaults is on — secrets shared across builds. "
                                "Rotate now.")
        else:
            self._t("warn", "credentials.json not found")

        self._t_hardware_checks()

        o.say("")
        print(f"  {Out.G}{self.tests['pass']} passed{Out.RST}   "
              f"{Out.R}{self.tests['fail']} failed{Out.RST}   "
              f"{Out.Y}{self.tests['warn']} warnings{Out.RST}")
        if self.tests["fail"] == 0:
            self._mark(12)

    # -----------------------------------------------------------------------
    #  11 — the checks that used to be a list in the guide
    #
    #  docs/GUIDE.md section 10 ended with "then confirm by hand the four
    #  things the tests cannot check", and every o.verify() printed one more.
    #  They were all checkable; they just had not been written down as code.
    # -----------------------------------------------------------------------
    def _t_hardware_checks(self) -> None:
        o, r, q, w = self.out, self.r, self.q, self.c["wazuh"]
        o.say("")
        o.info("13. what the guide used to ask you to confirm by hand")

        # 1. DNS enforcement survived the restart. The highest-value check:
        #    this is the one that used to fail silently.
        if r.vm_exists(q["firewall"]):
            r.ensure_running(q["firewall"])
            chain = r.run("qvm-run", "--no-gui", "--pass-io", "-u", "root",
                          q["firewall"], "nft list chain ip qubes dnat-dns",
                          check=False, capture=True)
            if not chain.strip():
                self._t("fail", "dnat-dns chain is absent from sys-firewall")
            elif "redirect to :53" in chain or self.c["dns"]["primary"] in chain:
                self._t("pass", "dnat-dns carries the golden-image rule, not the "
                                "regenerated default")
            else:
                self._t("fail", "dnat-dns exists but does NOT carry the golden-image "
                                "rule — qubes-setup-dnat-to-ns overwrote it")

        # 2. The Squid intercept is actually receiving packets. Test 7 above
        #    generated traffic through it; the counters prove it arrived.
        if r.vm_exists(q["proxy"]):
            ch = r.run("qvm-run", "--no-gui", "--pass-io", "-u", "root", q["proxy"],
                       "nft list chain ip qubes custom-dnat-squid",
                       check=False, capture=True)
            nums = [int(m) for m in re.findall(r"packets (\d+)", ch)]
            if not ch.strip():
                self._t("fail", "custom-dnat-squid chain missing in sys-proxy")
            elif any(n > 0 for n in nums):
                self._t("pass", f"custom-dnat-squid counters are incrementing "
                                f"({max(nums)} packets redirected)")
            else:
                self._t("warn", "custom-dnat-squid exists but has counted nothing "
                                "yet — browse from an app qube and re-run")

        # 3. Squid's peek/splice directives are accepted by the shipped build.
        if r.vm_exists(q["proxy"]):
            ok_parse = r.qtest(q["proxy"], "squid -k parse >/dev/null 2>&1")
            self._t("pass" if ok_parse else "fail",
                    "Squid accepts the peek/splice configuration" if ok_parse
                    else "squid -k parse rejects the config — the packaged build "
                         "may lack SSL support (needs squid-openssl)")

        # 4. The SIEM is up.
        if w["mode"] != "central" and r.vm_exists(q["wazuh"]):
            r.ensure_running(q["wazuh"])
            for svc in ("wazuh-manager", "wazuh-indexer", "wazuh-dashboard"):
                up = r.qtest(q["wazuh"], f"systemctl is-active --quiet {svc}")
                self._t("pass" if up else "fail",
                        f"{svc} is running" if up else f"{svc} is NOT running")
            ip = r.run("qvm-prefs", q["wazuh"], "ip", check=False, capture=True).strip()
            self._t("pass" if ip == w["ip"] else "fail",
                    f"qvm-prefs ip accepted: {q['wazuh']} is {ip}" if ip == w["ip"]
                    else f"{q['wazuh']} has ip '{ip}', expected {w['ip']}")

        # 5. The dashboard is reachable over qrexec from 'work' — which is both
        #    the ConnectTCP policy grammar check and the argument-order check.
        if r.vm_exists("work") and r.vm_exists(q["wazuh"]):
            r.ensure_running("work")
            reachable = r.qtest("work",
                                "timeout 25 sh -c '"
                                f"qvm-connect-tcp 18443:{q['wazuh']}:443 & "
                                "sleep 6; "
                                "curl -sk --max-time 8 https://localhost:18443 >/dev/null; "
                                "rc=$?; kill %1 2>/dev/null; exit $rc'")
            self._t("pass" if reachable else "warn",
                    "qubes.ConnectTCP policy works: the dashboard answers from 'work'"
                    if reachable else
                    "could not reach the dashboard over qrexec from 'work' — check "
                    "the policy in /etc/qubes/policy.d/30-golden-image.policy")

        # 6. The backup profile schema is accepted.
        self._t_backup_profile()

        # 6b. The maintenance this laptop is supposed to do for itself. Phase 10
        #     warns when it cannot enable a timer, and a warning does not block —
        #     so a laptop could be issued with no backups, no updates and no
        #     self-checks, and pass.
        for unit in ("golden-backup.timer", "golden-template-update.timer",
                     "golden-selfcheck.timer", "golden-restore-test.timer",
                     "golden-staleness.timer"):
            on = r.quiet("systemctl", "is-enabled", unit)
            self._t("pass" if on else "fail",
                    f"{unit} is enabled" if on else
                    f"{unit} is NOT enabled — this machine will not maintain itself")

        # 7. Wi-Fi. Drivers come from the dom0 kernel but firmware comes from the
        #    Debian template, and that is the one place the Debian switch bites.
        if r.vm_exists(q["net"]):
            r.ensure_running(q["net"])
            has_wifi = r.qtest(q["net"],
                               "ls /sys/class/net/*/wireless >/dev/null 2>&1 || "
                               "nmcli -t -f TYPE device 2>/dev/null | grep -q wifi")
            if has_wifi:
                self._t("pass", "a wireless interface is present in sys-net")
                clean = r.qtest(q["net"],
                                "! dmesg 2>/dev/null | grep -qiE "
                                "'firmware.*(failed|not found|missing)'")
                self._t("pass" if clean else "fail",
                        "no firmware load failures in sys-net" if clean else
                        "sys-net reports a firmware load failure — install the "
                        "matching firmware-* package in " + self.t["sys"])
            else:
                self._t("warn", "no wireless interface in sys-net — expected on a "
                                "wired-only machine")

    def _t_backup_profile(self) -> None:
        """Confirm qvm-backup accepts our profile keys, without taking a backup.

        `--save-profile` writes a profile from known-good arguments; comparing
        its key names against ours validates the schema. docs/REVIEW.md listed
        this as something to check by hand with a real backup run.
        """
        o, r, b = self.out, self.r, self.c["backup"]
        prof = dom0("/etc/qubes/backup/golden-image.conf")
        if not prof.exists():
            self._t("fail", "backup profile /etc/qubes/backup/golden-image.conf missing")
            return
        ours = {l.split(":", 1)[0].strip() for l in prof.read_text().splitlines()
                if ":" in l and not l.startswith(" ")}
        probe = dom0("/etc/qubes/backup/golden-image-schema-probe.conf")
        made = r.quiet("qvm-backup", "--save-profile", "golden-image-schema-probe",
                       "--dest-vm", b["dest_qube"], b["dest_dir"], "dom0")
        if not made or not probe.exists():
            self._t("warn", "qvm-backup --save-profile unavailable — cannot validate "
                            "the profile schema automatically; run "
                            "'sudo qvm-backup --profile golden-image' once by hand")
            probe.unlink(missing_ok=True)
            return
        try:
            ref = {l.split(":", 1)[0].strip() for l in probe.read_text().splitlines()
                   if ":" in l and not l.startswith(" ")}
            # No exemptions. passphrase_file in particular is the key the
            # admin API is guaranteed to reject, and subtracting it here would
            # have hidden exactly the defect this test exists to catch.
            # (--save-profile emits passphrase_text, so it is in the reference.)
            unknown = ours - ref
            self._t("pass" if not unknown else "fail",
                    "qvm-backup accepts every key in the golden-image profile"
                    if not unknown else
                    f"qvm-backup does not recognise: {', '.join(sorted(unknown))} "
                    f"— it accepts {', '.join(sorted(ref))}")
        finally:
            probe.unlink(missing_ok=True)

    # =======================================================================
    #  Credential lifecycle — GUIDE section 11, as commands
    #
    #  "Read credentials.json, change all four secrets, escrow the new values,
    #  shred the file" was four manual steps performed differently on every
    #  laptop, and the shred step was the one that got skipped.
    # =======================================================================
    ESCROW_RECORD = "escrow.json"

    def rotate_credentials(self) -> int:
        o, r, q, w = self.out, self.r, self.q, self.c["wazuh"]
        if not self.creds:
            raise Fatal(f"no {self.cred_file} to rotate. Run phase 2 first.")
        print(f"\n{Out.B}{Out.C}══ Rotating credentials{Out.RST}")
        old_backup = self.creds.get("backup", "")
        new = {"dashboard": self._secret(), "api": self._secret(),
               "authd": self._secret(), "backup": self._secret(48)}
        o.guard(*new.values())
        if self.args.dry_run:
            for k in new:
                o.info(f"[dry-run] rotate {k}")
            return 0

        # 1. The SIEM manager, first: an agent password change is only useful
        #    once the manager expects the new one.
        if w["mode"] != "central" and r.vm_exists(q["wazuh"]):
            r.ensure_running(q["wazuh"])
            r.qwrite(q["wazuh"], "/rw/golden-authd.pass", new["authd"], mode="0600")
            r.qwrite(q["wazuh"], "/var/ossec/etc/authd.pass", new["authd"], mode="0640")
            r.qrun(q["wazuh"], "chown root:wazuh /var/ossec/etc/authd.pass "
                               "2>/dev/null || true", check=False)
            r.qrun(q["wazuh"], "systemctl restart wazuh-manager", check=False)
            o.ok("manager enrollment password rotated")
            if r.qtest(q["wazuh"], "test -x /opt/wazuh-passwords-tool.sh"):
                r.quiet("qvm-run", "--no-gui", "-u", "root", q["wazuh"],
                        "bash -c " + shlex.quote(
                            f"/opt/wazuh-passwords-tool.sh -u wazuh-wui "
                            f"-p {shlex.quote(new['api'])}"))
                if r.quiet("qvm-run", "--no-gui", "-u", "root", q["wazuh"],
                           "bash -c " + shlex.quote(
                               f"/opt/wazuh-passwords-tool.sh -u admin "
                               f"-p {shlex.quote(new['dashboard'])}")):
                    o.ok("dashboard and API passwords rotated")
                else:
                    raise Fatal("could not set the new dashboard password — "
                                "nothing has been written to credentials.json, so "
                                "the old values are still valid.")
            else:
                o.warn("wazuh-passwords-tool.sh not present — the dashboard "
                       "password was NOT rotated")
                new["dashboard"] = self.creds.get("dashboard", new["dashboard"])

        # 2. Every enrolled agent gets the new enrollment password.
        for vm in self._enrolled_qubes():
            if not r.vm_exists(vm):
                continue
            r.ensure_running(vm)
            r.qwrite(vm, "/var/ossec/etc/authd.pass", new["authd"], mode="0640")
            r.qrun(vm, "chown root:wazuh /var/ossec/etc/authd.pass 2>/dev/null || true",
                   check=False)
            o.ok(f"{vm}: enrollment password updated")

        # 3. The backup passphrase. The OLD one still opens existing sets, so
        #    it is kept in the record until those sets age out.
        dom0("/root/.backup-pass").write_text(new["backup"] + "\n")
        dom0("/root/.backup-pass").chmod(0o600)
        o.ok("backup passphrase rotated")

        self.creds.update(new)
        self.creds["_rotated"] = f"{datetime.now():%Y-%m-%d %H:%M:%S}"
        self.creds["_previous_backup_passphrase"] = old_backup
        self.creds["_stamp"] = ("rotated after provisioning — the previous backup "
                                f"passphrase is kept here until the existing "
                                f"{self.c['backup']['keep_sets']} sets age out")
        old_umask = os.umask(0o077)
        try:
            self.cred_file.write_text(json.dumps(self.creds, indent=2) + "\n")
        finally:
            os.umask(old_umask)
        self.cred_file.chmod(0o600)
        # An escrow record for the old values no longer describes this file.
        (self.build_dir / self.ESCROW_RECORD).unlink(missing_ok=True)
        o.ok(f"{self.cred_file} rewritten (mode 600)")
        print(f"\n  Now escrow them:  sudo {Path(sys.argv[0]).name} "
              f"--escrow-credentials\n")
        return 0

    def handover_sequence(self, target: str) -> int:
        """rotate, then escrow, then shred — with one confirmation.

        The order is the whole point: shredding before escrowing destroys the
        only copy, and escrowing before rotating escrows values that are about
        to stop being true. Each step already refuses to run out of order; this
        just removes the opportunity to get it wrong.
        """
        o = self.out
        print(f"\n{Out.B}{Out.C}══ Handover{Out.RST}")
        print(f"""
  This will, in order:
    1. generate four new secrets and apply them to the SIEM, every enrolled
       qube and the backup passphrase
    2. copy the result into '{target}' and verify it by SHA-256
    3. destroy the dom0 copy and the build log

  Step 3 is not reversible. Step 2 puts the values in an offline qube on this
  same disk — that is not off-site storage. Copy them into your unit's password
  process between steps 2 and 3 if that is your policy, by running the three
  commands separately instead.
""")
        if not self.args.dry_run and not self.args.force:
            if not sys.stdin.isatty():
                raise Fatal("--handover needs a terminal, or --force.")
            if input("  Type HANDOVER to continue: ").strip() != "HANDOVER":
                raise Fatal("aborted")
        for step in (lambda: self.rotate_credentials(),
                     lambda: self.escrow_credentials(target),
                     lambda: self.shred_credentials()):
            rc = step()
            if rc:
                raise Fatal("handover stopped — the remaining steps were not run, "
                            "and nothing has been shredded.")
        o.ok("handover complete")
        return 0

    def _enrolled_qubes(self) -> list[str]:
        q = self.q
        return ["personal", "work", q["kali_clear"], q["kali_tor"], q["whonix"],
                "anon-whonix", q["proxy"], q["ids"], q["dpi"], q["wazuh"]]

    def escrow_credentials(self, target: str) -> int:
        """Copy the credentials into the offline vault qube and record it.

        The vault has no netvm and lives on the same encrypted disk, which is
        where the guide already told the operator to put them by hand.
        """
        o, r = self.out, self.r
        if not self.cred_file.exists():
            raise Fatal(f"{self.cred_file} does not exist — nothing to escrow")
        if not r.vm_exists(target):
            raise Fatal(f"escrow target '{target}' does not exist")
        netvm = r.run("qvm-prefs", target, "netvm", check=False, capture=True).strip()
        # qvm-prefs reports an offline qube as "", "None" or "none" depending on
        # how it was set; all three mean the same thing.
        if netvm.lower() not in ("", "none"):
            raise Fatal(f"'{target}' has netvm '{netvm}'. Refusing to copy every "
                        f"secret for this machine into a qube with a network "
                        f"route. Use an offline qube.")
        import hashlib
        data = self.cred_file.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        name = f"golden-image-credentials-{os.uname().nodename}-{datetime.now():%Y%m%d}.json"
        dest = f"/home/user/{name}"
        if self.args.dry_run:
            o.info(f"[dry-run] copy {self.cred_file} to {target}:{dest}")
            return 0
        r.ensure_running(target)
        r.qwrite(target, dest, data.decode(), mode="0600")
        r.qrun(target, f"chown user:user {shlex.quote(dest)} 2>/dev/null || true",
               check=False)
        back = r.run("qvm-run", "--no-gui", "--pass-io", "-u", "root", target,
                     f"sha256sum {shlex.quote(dest)}", check=False, capture=True)
        if digest not in back:
            raise Fatal(f"the copy in {target} does not match the original. "
                        f"Nothing has been shredded; investigate before retrying.")
        (self.build_dir / self.ESCROW_RECORD).write_text(json.dumps({
            "qube": target, "path": dest, "sha256": digest,
            "at": f"{datetime.now():%Y-%m-%d %H:%M:%S}",
            "host": os.uname().nodename,
        }, indent=2) + "\n")
        o.ok(f"escrowed to {target}:{dest} (verified by sha256)")
        o.warn("that qube is offline but not off-site. Copy it into your unit's "
               "password process as well, then:")
        print(f"      sudo {Path(sys.argv[0]).name} --shred-credentials\n")
        return 0

    def shred_credentials(self) -> int:
        """Destroy the dom0 copy — but only once it exists somewhere else."""
        o, r = self.out, self.r
        rec_path = self.build_dir / self.ESCROW_RECORD
        if not rec_path.exists() and not self.args.force:
            raise Fatal(
                "no escrow record. Refusing to destroy the only copy of this "
                "machine's secrets.\n"
                f"     sudo {Path(sys.argv[0]).name} --escrow-credentials\n"
                "     ...or --force if you have escrowed them another way and are "
                "certain.")
        if rec_path.exists():
            rec = json.loads(rec_path.read_text())
            import hashlib
            digest = hashlib.sha256(self.cred_file.read_bytes()).hexdigest() \
                if self.cred_file.exists() else ""
            if digest and digest != rec["sha256"]:
                raise Fatal("credentials.json has changed since it was escrowed. "
                            "Re-run --escrow-credentials first.")
            back = r.run("qvm-run", "--no-gui", "--pass-io", "-u", "root",
                         rec["qube"], f"sha256sum {shlex.quote(rec['path'])}",
                         check=False, capture=True)
            if rec["sha256"] not in back:
                raise Fatal(f"the escrowed copy in {rec['qube']} is missing or "
                            f"changed. Nothing shredded.")
            o.ok(f"escrowed copy verified in {rec['qube']}")

        if self.args.dry_run:
            o.info(f"[dry-run] shred {self.cred_file} and {self.out.log_path}")
            return 0
        targets = [self.cred_file, self.out.log_path,
                   self.build_dir / "CREDENTIALS-README.txt"]
        # Stop logging first, or the very next o.ok() re-creates the log file
        # this command just destroyed.
        self.out.enabled = False
        for t in targets:
            if not t.exists():
                continue
            # The build log records every command run against every qube, which
            # is why it is shredded alongside the credentials rather than left
            # behind as the guide used to leave it.
            if r.quiet("shred", "-u", "-z", str(t)):
                o.ok(f"shredded {t}")
            else:
                t.unlink(missing_ok=True)
                o.warn(f"shred unavailable — {t} was unlinked, not overwritten")
        return 0

    def upgrade_wazuh(self) -> int:
        """Manager first, then the agents. Never the reverse."""
        o, r, q, w = self.out, self.r, self.q, self.c["wazuh"]
        print(f"\n{Out.B}{Out.C}══ Wazuh upgrade{Out.RST}")
        o.info("Wazuh support compatibility only while manager >= agent, so the "
               "order is not negotiable: manager, then holds released, then "
               "agents, then re-pinned.")
        if self.args.dry_run:
            o.info("[dry-run] upgrade manager, release holds, upgrade agents, re-pin")
            return 0
        if w["mode"] == "central":
            o.warn(f"central mode: upgrade {w['central_address']} yourself first. "
                   f"This will only touch the agents.")
            if not self.args.force:
                raise Fatal("re-run with --force once the central manager is "
                            "upgraded")
        elif r.vm_exists(q["wazuh"]):
            r.ensure_running(q["wazuh"])
            r.qrun(q["wazuh"], "export DEBIAN_FRONTEND=noninteractive; "
                               "sed -i 's|^#deb |deb |' "
                               "/etc/apt/sources.list.d/wazuh.list; "
                               "apt-get update && apt-get install -y "
                               "wazuh-manager wazuh-indexer wazuh-dashboard")
            ver = r.run("qvm-run", "--no-gui", "--pass-io", "-u", "root", q["wazuh"],
                        "dpkg-query -W -f='${Version}' wazuh-manager",
                        check=False, capture=True).strip().split("-")[0]
            if not ver:
                raise Fatal("could not read the manager version after upgrading. "
                            "Stopping before touching any agent.")
            o.ok(f"manager is now {ver}")
            self.c["wazuh"]["version"] = ver

        target = self.c["wazuh"]["version"]
        tpls = [self.t["sys"], self.t["proxy"], self.t["ids"], self.t["kali"],
                self.t["personal"], self.t["wazuh"], self.c["base_debian"]]
        for tpl in tpls:
            if not r.vm_exists(tpl):
                continue
            r.ensure_running(tpl)
            r.qrun(tpl, "export DEBIAN_FRONTEND=noninteractive; "
                        "echo 'wazuh-agent install' | dpkg --set-selections && "
                        "sed -i 's|^#deb |deb |' /etc/apt/sources.list.d/wazuh.list && "
                        "apt-get update && apt-get install -y "
                        f"wazuh-agent={shlex.quote(target)}-1", check=False)
            if self.c["wazuh"]["pin_agent"]:
                r.qrun(tpl, "echo 'wazuh-agent hold' | dpkg --set-selections && "
                            "sed -i 's|^deb |#deb |' "
                            "/etc/apt/sources.list.d/wazuh.list", check=False)
            o.ok(f"{tpl}: agent at {target}, re-pinned")
        # Persist it. Telling the operator to make the same edit by hand was an
        # invitation for the config and the machine to disagree, and the next
        # provisioning run would then re-pin the agents to the old version.
        if CONF_PATH.exists():
            try:
                stored = json.loads(CONF_PATH.read_text())
            except json.JSONDecodeError:
                stored = {}
        else:
            stored = {}
        stored.setdefault("wazuh", {})["version"] = target
        old_umask = os.umask(0o077)
        try:
            CONF_PATH.write_text(json.dumps(stored, indent=2) + "\n")
        finally:
            os.umask(old_umask)
        CONF_PATH.chmod(0o600)
        o.say("")
        o.ok(f"wazuh.version set to {target} in {CONF_PATH.name}")
        o.info("commit that change to the provisioning repository — the golden "
               "image is the git tag, not any one laptop")
        return 0

    def refresh_repo_keys(self) -> int:
        """Re-fetch and re-verify the third-party repository keys.

        Zeek's own documentation says that on Debian you must re-add the OBS key
        by hand when it expires, and an expired key silently stops DPI updates.
        The expiry watch tells you when; this is what it tells you to run.
        """
        o, r = self.out, self.r
        print(f"\n{Out.B}{Out.C}══ Repository signing keys{Out.RST}")
        jobs = [
            (self.t["ids"], self.c["zeek"]["key_url"],
             self.c["zeek"]["keyring_path"], self.c["zeek"].get("key_fpr", ""),
             "Zeek OBS", "dearmor"),
            (self.t["kali"], self.c["kali"]["keyring_url"],
             self.c["kali"]["keyring_path"], self.c["kali"]["key_fpr"],
             "Kali", "raw"),
        ]
        for tpl in (self.t["proxy"], self.t["ids"], self.t["kali"],
                    self.t["personal"], self.t["wazuh"]):
            jobs.append((tpl, self.c["wazuh"]["key_url"],
                         self.c["wazuh"]["keyring_path"],
                         self.c["wazuh"].get("key_fpr", ""), "Wazuh", "import"))

        failures = 0
        for tpl, url, path, fpr, label, how in jobs:
            if not r.vm_exists(tpl):
                continue
            if self.args.dry_run:
                o.info(f"[dry-run] refresh the {label} key in {tpl}")
                continue
            r.ensure_running(tpl)
            if how == "dearmor":
                cmd = (f"curl -fsSL {shlex.quote(url)} | gpg --dearmor "
                       f"> {shlex.quote(path)} && chmod 644 {shlex.quote(path)}")
            elif how == "raw":
                cmd = (f"curl -fsSL {shlex.quote(url)} -o {shlex.quote(path)} && "
                       f"chmod 644 {shlex.quote(path)}")
            else:
                cmd = (f"rm -f {shlex.quote(path)} && curl -fsSL {shlex.quote(url)} "
                       f"| gpg --no-default-keyring "
                       f"--keyring gnupg-ring:{shlex.quote(path)} --import && "
                       f"chmod 644 {shlex.quote(path)}")
            # Keep the old key until the new one has been verified: a failed
            # refresh must not leave the template unable to update at all.
            r.qrun(tpl, f"cp -a {shlex.quote(path)} {shlex.quote(path)}.prev "
                        f"2>/dev/null || true", check=False)
            try:
                r.qrun(tpl, cmd)
                self._verify_keyring(tpl, path, fpr, label)
            except Fatal as e:
                r.qrun(tpl, f"mv -f {shlex.quote(path)}.prev {shlex.quote(path)} "
                            f"2>/dev/null || true", check=False)
                o.warn(f"{tpl}: {label} refresh failed and was rolled back — {e}")
                failures += 1
                continue
            r.qrun(tpl, f"rm -f {shlex.quote(path)}.prev", check=False)
            r.qrun(tpl, "apt-get update", check=False)
        if failures:
            o.warn(f"{failures} key(s) could not be refreshed. If a fingerprint "
                   f"changed, confirm the new one at the vendor's own site and "
                   f"update the config first.")
            return 1
        o.ok("every pinned repository key re-fetched and re-verified")
        return 0

    # =======================================================================
    def handover(self):
        if self.args.dry_run:
            return
        q = self.q
        print(f"\n{Out.B}{Out.C}\u2550\u2550 Handover{Out.RST}")
        me = Path(sys.argv[0]).name
        print(f"""
  Credentials      {self.cred_file}   (mode 600, dom0 only)
  How to rotate    {self.build_dir / 'CREDENTIALS-README.txt'}
  Build log        {self.out.log_path}   (mode 600 — it logs every command)
  Resume state     {self.state_file}

  Handover, in three commands
    sudo {me} --rotate-credentials   new secrets, applied everywhere
    sudo {me} --escrow-credentials   copied into 'vault', verified by hash
    sudo {me} --shred-credentials    destroys the dom0 copy and the build log

  The dashboard is a launcher in 'work' called "SIEM dashboard" — there is no
  qvm-connect-tcp line to type any more.

  Before this laptop is issued
    sudo {me} --verify        every acceptance test must pass (non-zero exit
                              if any fail, so it can gate a script)

  Running from here on, without anyone remembering to:
    golden-template-update.timer   weekly template updates      (dom0)
    golden-selfcheck.timer         weekly acceptance tests      (dom0)
    golden-restore-test.timer      monthly restore verification (dom0)
    golden-staleness.timer         daily "is this image too old" (dom0)
    golden-suricata-update.timer   weekly IPS rules             ({self.q['ids']})
    golden-key-expiry.timer        monthly signing-key expiry   ({self.q['dpi']})
    golden-backup.timer            weekly encrypted backup      (dom0)
  Failures raise a banner on the login screen and a line in the journal.
""")
        if self.out.verify_notes:
            print(f"  {Out.Y}Items flagged [VERIFY] this run:{Out.RST}")
            for n in dict.fromkeys(self.out.verify_notes):
                print(f"    - {n}")
            print()

    def run(self) -> int:
        o = self.out
        print(f"\n{Out.B}{Out.C}{self.c['image_name']} v{self.c['image_version']}{Out.RST}")
        if self.args.dry_run:
            print(f"{Out.Y}DRY RUN — nothing will be changed{Out.RST}")
        o.say(f"log: {self.out.log_path}")

        if self.args.from_phase > 1 and self.args.phase is None and not self.args.verify:
            self._clear_marks_from(self.args.from_phase)
            o.info(f"resuming: completion marks for phases "
                   f"{self.args.from_phase}-12 cleared, they will run again")

        phases: list[Callable] = [
            self.p01, self.p02, self.p03, self.p04, self.p05, self.p06,
            self.p07, self.p08, self.p09, self.p10, self.p11, self.p12,
        ]
        for i, fn in enumerate(phases, start=1):
            if self._should_run(i):
                o.phase(i, self.PHASES[i - 1])
                fn()
        self.handover()
        o.say("")
        if self.tests["fail"]:
            o.warn(f"{self.tests['fail']} acceptance test(s) failed — this machine "
                   f"is NOT ready to issue")
        else:
            o.ok("finished")
        return self.tests["fail"]


# ===========================================================================
#  Config handling
# ===========================================================================
def deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(write_only: bool = False, dry_run: bool = False) -> dict:
    if CONF_PATH.exists():
        if write_only:
            print(f"golden-image.json already exists — not overwriting: {CONF_PATH}",
                  file=sys.stderr)
            sys.exit(1)
        try:
            user = json.loads(CONF_PATH.read_text())
        except json.JSONDecodeError as e:
            raise Fatal(f"golden-image.json is not valid JSON: {e}")
        return deep_merge(DEFAULT_CONFIG, user)

    if dry_run and not write_only:
        print(f"  {Out.Y}!{Out.RST} no golden-image.json — planning against the "
              f"embedded defaults (a dry run writes nothing)\n")
        return dict(DEFAULT_CONFIG)
    CONF_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2) + "\n")
    # 0600, not 0644: credentials.fixed in this file holds four passwords when
    # use_fixed_defaults is on, and it sits next to a credentials.json that is
    # carefully kept at 0600.
    CONF_PATH.chmod(0o600)
    if write_only:
        print(f"Wrote {CONF_PATH}")
        print("Review and edit it, then run:  sudo ./golden_image.py --dry-run")
        sys.exit(0)
    print(f"  {Out.Y}!{Out.RST} no golden-image.json found — wrote embedded defaults "
          f"to {CONF_PATH}")
    print("  Review it before a real build; it is yours to edit and will not be "
          "overwritten.\n")
    return dict(DEFAULT_CONFIG)


def main() -> int:
    p = argparse.ArgumentParser(
        description=f"{DEFAULT_CONFIG['image_name']} provisioner (dom0)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dry-run", action="store_true",
                   help="print every action, change nothing")
    sel = p.add_mutually_exclusive_group()
    sel.add_argument("--phase", type=int, metavar="N",
                     choices=range(1, len(Provisioner.PHASES) + 1),
                     help="run only phase N")
    sel.add_argument("--from-phase", type=int, default=1, metavar="N",
                     choices=range(1, len(Provisioner.PHASES) + 1),
                     help="redo everything from phase N (resume after a failure)")
    sel.add_argument("--verify", action="store_true",
                     help="run the acceptance tests only; exits non-zero if any fail")
    p.add_argument("--force", action="store_true",
                   help="skip the Qubes release check and other confirmations")
    p.add_argument("--write-config", action="store_true",
                   help="emit golden-image.json and exit")
    p.add_argument("--list-phases", action="store_true")
    p.add_argument("--test-root", action="store_true",
                   help=argparse.SUPPRESS)          # tests/run_tests.py only

    life = p.add_argument_group(
        "credential lifecycle",
        "handover, as commands rather than as a checklist in docs/GUIDE.md")
    life.add_argument("--rotate-credentials", action="store_true",
                      help="generate new secrets and apply them everywhere")
    life.add_argument("--escrow-credentials", nargs="?", const="vault",
                      metavar="QUBE",
                      help="copy credentials.json into an offline qube "
                           "(default: vault) and record that it is there")
    life.add_argument("--shred-credentials", action="store_true",
                      help="destroy the dom0 copy — refuses without an escrow record")
    life.add_argument("--handover", nargs="?", const="vault", metavar="QUBE",
                      help="rotate, escrow and shred in that order, with one "
                           "confirmation")
    life.add_argument("--upgrade-wazuh", action="store_true",
                      help="upgrade the SIEM in the supported order: manager, "
                           "then agents")
    life.add_argument("--refresh-repo-keys", action="store_true",
                      help="re-fetch and re-verify the pinned repository signing "
                           "keys (what the expiry watch tells you to run)")
    args = p.parse_args()

    if args.list_phases:
        for i, name in enumerate(Provisioner.PHASES, start=1):
            print(f"  {i:2d}  {name}")
        return 0

    assert_test_root_is_deliberate(args)

    try:
        cfg = load_config(write_only=args.write_config, dry_run=args.dry_run)
        prov = Provisioner(cfg, args)

        if args.handover:
            return prov.handover_sequence(args.handover)
        if args.refresh_repo_keys:
            return prov.refresh_repo_keys()
        if args.rotate_credentials:
            return prov.rotate_credentials()
        if args.escrow_credentials:
            return prov.escrow_credentials(args.escrow_credentials)
        if args.shred_credentials:
            return prov.shred_credentials()
        if args.upgrade_wazuh:
            return prov.upgrade_wazuh()

        # Exit non-zero when acceptance tests fail. Without this, --verify could
        # not gate anything: the first-boot runner, a CI job and a shell && all
        # read a passing exit status from a machine that failed its tests.
        if prov.run():
            return 2
    except Fatal as e:
        print(f"\n{Out.R}FATAL:{Out.RST} {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted — re-run to resume from the last completed phase",
              file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # Piping to head/less closes stdout early; exit quietly rather than
        # printing a traceback over the user's terminal.
        try:
            sys.stdout.close()
        finally:
            os._exit(0)
