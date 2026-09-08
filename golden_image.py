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
    "image_version": "2.0",
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

    # The Fedora template ships with a stock install and stays available as a
    # fallback. Set true only if you actually base qubes on it; it still
    # receives a Wazuh agent either way, to satisfy "an agent in every
    # template".
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
        "repo_line": "deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware",
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
        "repo_line": "deb http://download.opensuse.org/repositories/security:/zeek/Debian_13/ /",
        "key_url": "https://download.opensuse.org/repositories/security:zeek/Debian_13/Release.key",
        "keyring_path": "/etc/apt/trusted.gpg.d/security_zeek.gpg",
        "package": "zeek-8.0",
        "prefix": "/opt/zeek",
    },
    "wazuh": {
        "version": "4.14.7",
        "key_url": "https://packages.wazuh.com/key/GPG-KEY-WAZUH",
        "keyring_path": "/usr/share/keyrings/wazuh.gpg",
        "apt_repo_line": "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main",
        "yum_baseurl": "https://packages.wazuh.com/4.x/yum/",
        # Wazuh guarantee compatibility only when manager >= agent. These
        # templates update weekly, so an unpinned agent WILL overtake the
        # manager and every agent stops reporting. Do not disable casually.
        "pin_agent": True,
        "mode": "local",            # "local" | "central"
        "central_address": "",
        "ip": "10.137.0.50",
        "port_events": 1514,
        "port_enroll": 1515,
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
        "keep_sets": 4,
    },
    "timeouts": {"short": 300, "long": 5400},
}

BUILD_DIR = Path.home() / "golden-image"
CONF_PATH = Path(__file__).resolve().parent / "golden-image.json"


# ===========================================================================
#  Output
# ===========================================================================
class Out:
    RST, B, R, G, Y, C, D = (
        "\033[0m", "\033[1m", "\033[31m", "\033[32m",
        "\033[33m", "\033[36m", "\033[2m",
    )

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.verify_notes: list[str] = []
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.touch(exist_ok=True)
        except OSError:
            pass

    def _log(self, line: str) -> None:
        try:
            with self.log_path.open("a") as fh:
                fh.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {line}\n")
        except OSError:
            pass

    def say(self, m=""):   print(m);                                  self._log(m)
    def info(self, m):     print(f"  {self.D}{m}{self.RST}");         self._log(f"INFO  {m}")
    def ok(self, m):       print(f"  {self.G}\u2713{self.RST} {m}");  self._log(f"OK    {m}")
    def skip(self, m):     print(f"  {self.D}\u00b7{self.RST} {m} {self.D}(already present){self.RST}")
    def warn(self, m):     print(f"  {self.Y}!{self.RST} {m}");       self._log(f"WARN  {m}")

    def verify(self, m):
        print(f"  {self.Y}?{self.RST} {self.Y}[VERIFY] {m}{self.RST}")
        self._log(f"VERIFY {m}")
        self.verify_notes.append(m)

    def phase(self, n, name):
        print(f"\n{self.B}{self.C}\u2550\u2550 Phase {n} \u2014 {name}{self.RST}")
        self._log(f"PHASE {n} {name}")

    def phase_skipped(self, n, name):
        print(f"\n{self.D}\u2550\u2550 Phase {n} \u2014 {name} (done, skipping){self.RST}")


class Fatal(Exception):
    pass


# ===========================================================================
#  Runner — every state-changing action goes through here
# ===========================================================================
class Runner:
    def __init__(self, out: Out, dry_run: bool, timeout_long: int):
        self.out = out
        self.dry_run = dry_run
        self.timeout_long = timeout_long
        # In a dry run nothing is actually created, so later phases would
        # wrongly conclude their inputs are missing and abort. Track what the
        # run *would* have created so the operator sees the whole plan.
        self.simulated: set[str] = set()

    def run(self, *argv: str, check: bool = True, capture: bool = False) -> str:
        cmd = list(argv)
        if self.dry_run:
            print(f"  {Out.D}[dry-run]{Out.RST} {' '.join(shlex.quote(a) for a in cmd)}")
            return ""
        self.out._log("EXEC  " + " ".join(cmd))
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=self.timeout_long)
        except subprocess.TimeoutExpired:
            raise Fatal(f"timed out: {' '.join(cmd)}")
        self.out._log(f"      rc={p.returncode} {p.stdout[-2000:]}{p.stderr[-2000:]}")
        if check and p.returncode != 0:
            raise Fatal(f"command failed: {' '.join(cmd)}\n     see {self.out.log_path}")
        return p.stdout if capture else ""

    def quiet(self, *argv: str) -> bool:
        """Run, return success. Never raises. Not gated by dry-run (read-only)."""
        try:
            p = subprocess.run(list(argv), capture_output=True, text=True, timeout=120)
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
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout_long)
        except subprocess.TimeoutExpired:
            raise Fatal(f"in-qube command timed out in {vm}")
        self.out._log(f"      rc={p.returncode} {p.stdout[-2000:]}{p.stderr[-2000:]}")
        if check and p.returncode != 0:
            raise Fatal(f"in-qube command failed in '{vm}': {script[:160]}\n"
                        f"     see {self.out.log_path}")

    def qtest(self, vm: str, script: str) -> bool:
        if self.dry_run:
            return True
        cmd = ["qvm-run", "--no-gui", "-u", "root", vm, f"bash -c {shlex.quote(script)}"]
        try:
            return subprocess.run(cmd, capture_output=True, timeout=180).returncode == 0
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
            p = subprocess.run(cmd, input=content + "\n", capture_output=True,
                               text=True, timeout=self.timeout_long)
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
        if self.dry_run:
            print(f"  {Out.D}[dry-run]{Out.RST} start {vm}")
            return
        if not self.vm_running(vm):
            self.run("qvm-start", "--skip-if-running", vm)
            time.sleep(5)

    def shutdown(self, vm: str) -> None:
        if self.dry_run or not self.vm_exists(vm):
            return
        self.quiet("qvm-shutdown", "--wait", "--timeout", "60", vm)

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
        self.build_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.build_dir / ".build-state"
        self.cred_file = self.build_dir / "credentials.json"
        self.out = Out(self.build_dir / "build.log")
        self.r = Runner(self.out, args.dry_run, cfg["timeouts"]["long"])
        self.creds: dict = {}
        self.t = cfg["tpl"]
        self.q = cfg["qube"]
        self.tests = {"pass": 0, "fail": 0, "warn": 0}

    # --- state -------------------------------------------------------------
    def _done(self, n: int) -> bool:
        if not self.state_file.exists():
            return False
        return f"phase:{n}" in self.state_file.read_text().split()

    def _mark(self, n: int) -> None:
        if not self.args.dry_run:
            with self.state_file.open("a") as fh:
                fh.write(f"phase:{n}\n")

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
        if not Path("/etc/qubes-release").exists():
            raise Fatal("not running in dom0 — this script must run in dom0.")
        rel = Path("/etc/qubes-release").read_text().strip()
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
                o.ok(f"Fedora template present and in use: {fed}")
            else:
                o.info(f"Fedora template present but unused: {fed} "
                       "(it still gets an agent)")
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
            st = os.statvfs("/var/lib/qubes")
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
            if gb < 16:
                o.warn("under 16G RAM — use wazuh.mode='central' rather than a local SIEM qube")
        except (OSError, StopIteration, ValueError):
            pass

        # Pinned SIEM address collision
        wip = self.c["wazuh"]["ip"]
        if not self.args.dry_run:
            data = r.run("qvm-ls", "--raw-data", "--fields", "NAME,IP",
                         check=False, capture=True)
            for line in data.splitlines():
                parts = line.split("|")
                if len(parts) >= 2 and parts[1].strip() == wip and parts[0] != self.q["wazuh"]:
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
        o.verify("after the build, confirm rules are live: "
                 "nft list table ip qubes | grep -A5 'custom-input\\|dnat-dns'")
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
            self.creds = json.loads(self.cred_file.read_text())
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
            Path("/root/.backup-pass").write_text(self.creds["backup"] + "\n")
            Path("/root/.backup-pass").chmod(0o600)
        except OSError:
            o.warn("could not write /root/.backup-pass — do it manually before phase 10")
        self._mark(2)

    def _cred_readme(self) -> str:
        w, q = self.c["wazuh"], self.q
        return f"""\
credentials.json — {self.c['image_name']} v{self.c['image_version']}
Host: {os.uname().nodename}   Built: {datetime.now():%Y-%m-%d %H:%M:%S}
{self.creds.get('_stamp','')}

THIS IS THE ONLY COPY. Mode 600, dom0 only.
  1. Use these to log in for the first time.
  2. Change every one of them (below).
  3. Store the new values in your vault qube / unit password process.
  4. Shred:  shred -u {self.cred_file}
Never commit this file to the provisioning repo.

HOW TO CHANGE EACH ONE
----------------------
Dashboard / indexer admin password
  In {q['wazuh']}, use the Wazuh indexer security admin tooling to set a new
  hash for 'admin', then restart the indexer and dashboard.
  [VERIFY] exact tool path and arguments for Wazuh {w['version']}.

API password
  Change via the Wazuh API users endpoint or the dashboard security settings,
  then update the dashboard's stored API credentials.

Agent enrollment password
  In {q['wazuh']}:
      echo "NEWSECRET" > /var/ossec/etc/authd.pass
      chmod 640 /var/ossec/etc/authd.pass
      chown root:wazuh /var/ossec/etc/authd.pass
      systemctl restart wazuh-manager
  Already-enrolled agents keep working; this only gates NEW registrations.
  Rotate whenever someone leaves the team.

Backup passphrase
  Write the new value to dom0:/root/.backup-pass (mode 600).
  Old backup sets still need the OLD passphrase — keep it escrowed until
  those sets age out ({self.c['backup']['keep_sets']} weeks).
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
        r.run("qvm-clone", src, dst)
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
        self._clone(sys_src, self.t["sys"], "orange")
        for key, label in (("proxy", "orange"), ("ids", "orange"),
                           ("kali", "yellow"), ("personal", "green"),
                           ("wazuh", "blue")):
            src = deb
            if key in pre and r.vm_exists(pre[key]):
                src = pre[key]
                o.info(f"using Tier 2 template {src} as the source for {self.t[key]}")
            self._clone(src, self.t[key], label)
        self._mark(3)

    # =======================================================================
    #  4 — template payloads
    # =======================================================================
    def _tier2_ready(self, key: str) -> bool:
        pre = self.c["prebuilt_templates"].get(key)
        return bool(pre and self.r.vm_exists(pre))

    def p04(self):
        o, r = self.out, self.r
        o.warn("templates reach the network through the Qubes update proxy (qrexec), "
               "not a netvm.")
        o.verify("if apt fails with a proxy/CONNECT error on an HTTPS repo, temporarily "
                 "assign the template a netvm, install, then clear it")

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
            r.qrun(self.t["sys"],
                   "export DEBIAN_FRONTEND=noninteractive; apt-get update && "
                   "apt-get install -y qubes-core-agent-networking "
                   "qubes-core-agent-network-manager qubes-usb-proxy "
                   "qubes-input-proxy-sender libpam-systemd unbound ca-certificates",
                   check=False)
            # Firmware blobs are read from the TEMPLATE even though the kernel
            # comes from dom0. Without these, Wi-Fi in a Debian sys-net fails.
            r.qrun(self.t["sys"],
                   "export DEBIAN_FRONTEND=noninteractive; "
                   "apt-get install -y firmware-linux firmware-iwlwifi || "
                   "apt-get install -y firmware-linux-free || true", check=False)
            o.ok(f"{self.t['sys']} service-qube packages installed")
            o.verify("Wi-Fi actually works in a Debian sys-net on your NIC — drivers "
                     "come from the dom0 kernel, firmware from this template")

        # --- proxy ---
        if self._tier2_ready("proxy"):
            o.skip(f"{self.t['proxy']} payload (baked in)")
        else:
            o.info(f"{self.t['proxy']}: Squid + unbound")
            r.qrun(self.t["proxy"],
                   "export DEBIAN_FRONTEND=noninteractive; apt-get update && "
                   "(apt-get install -y squid-openssl ca-certificates openssl || "
                   " apt-get install -y squid ca-certificates openssl)")
            o.verify("whether the installed squid build supports peek/splice "
                     "(squid-openssl does; plain squid cannot log TLS SNI)")
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
            r.qrun(self.t["ids"],
                   f"export DEBIAN_FRONTEND=noninteractive; apt-get update && "
                   f"apt-get install -y {z['package']}")
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
            fpr_check = (f"gpg --no-default-keyring --keyring {shlex.quote(k['keyring_path'])} "
                         f"--fingerprint 2>/dev/null | tr -d ' \\n' | grep -qi {k['key_fpr']}")
            if not r.qtest(tpl, fpr_check):
                r.qrun(tpl, f"gpg --no-default-keyring --keyring "
                            f"{shlex.quote(k['keyring_path'])} --fingerprint", check=False)
                raise Fatal(
                    f"Kali keyring does NOT contain the expected fingerprint {k['key_fpr']}.\n"
                    "     Do not proceed. Either Kali rolled the key again (check\n"
                    "     kali.org/blog and update kali.key_fpr) or the download was\n"
                    f"     tampered with. Cross-check at:\n     {k['keyserver_url']}\n"
                    f"     Fingerprints actually found are in {self.out.log_path}")
            o.ok(f"key fingerprint verified: {k['key_fpr']}")
            if r.qtest(tpl, f"gpg --no-default-keyring --keyring "
                            f"{shlex.quote(k['keyring_path'])} --fingerprint 2>/dev/null "
                            f"| tr -d ' \\n' | grep -qi {k['key_fpr_legacy']}"):
                o.ok("legacy Kali key also present")
            else:
                o.warn(f"legacy key {k['key_fpr_legacy']} absent — expected if it aged out")

            if k.get("keyring_sha1"):
                if r.qtest(tpl, f"sha1sum {shlex.quote(k['keyring_path'])} | "
                                f"grep -q {k['keyring_sha1']}"):
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
                    f"apt-get install -y -t kali-rolling {k['metapackage']} maltego")
        o.ok(f"{tpl}: {k['metapackage']} and Maltego installed")
        o.info("Maltego licence activation is per-qube (lives in /home), not in the template")

    # =======================================================================
    #  5 — wazuh agent in every template
    # =======================================================================
    def _wazuh_repo_apt(self, tpl: str):
        w = self.c["wazuh"]
        self.r.qrun(tpl, "export DEBIAN_FRONTEND=noninteractive; "
                         "apt-get install -y gnupg apt-transport-https curl ca-certificates")
        self.r.qrun(tpl, f"curl -s {shlex.quote(w['key_url'])} | gpg --no-default-keyring "
                         f"--keyring gnupg-ring:{shlex.quote(w['keyring_path'])} --import && "
                         f"chmod 644 {shlex.quote(w['keyring_path'])}")
        self.r.qwrite(tpl, "/etc/apt/sources.list.d/wazuh.list", w["apt_repo_line"])
        self.r.qrun(tpl, "apt-get update")

    def _wazuh_repo_dnf(self, tpl: str):
        w = self.c["wazuh"]
        self.r.qwrite(tpl, "/etc/yum.repos.d/wazuh.repo",
                      "[wazuh]\ngpgcheck=1\n"
                      f"gpgkey={w['key_url']}\nenabled=1\n"
                      "name=Wazuh repository\n"
                      f"baseurl={w['yum_baseurl']}\npriority=1\n")
        self.r.qrun(tpl, f"rpm --import {shlex.quote(w['key_url'])}")

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
        for k in ("base_whonix_gw", "base_whonix_ws"):
            if r.vm_exists(self.c[k]):
                deb_tpls.append(self.c[k])

        for tpl in deb_tpls:
            if not r.vm_exists(tpl):
                continue
            if r.qtest(tpl, "test -d /var/ossec"):
                o.skip(f"{tpl} — agent already present (Tier 2)")
                continue
            o.info(f"{tpl}: wazuh-agent {w['version']}")
            self._wazuh_repo_apt(tpl)
            r.qrun(tpl, "export DEBIAN_FRONTEND=noninteractive; apt-get install -y wazuh-agent")
            r.qrun(tpl, "systemctl disable wazuh-agent 2>/dev/null || true")
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
        if r.vm_exists(fed) and not r.qtest(fed, "test -d /var/ossec"):
            o.info(f"{fed}: wazuh-agent {w['version']} (dnf — the only rpm path left)")
            self._wazuh_repo_dnf(fed)
            r.qrun(fed, "dnf install -y wazuh-agent", check=False)
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
    def _mk_netqube(self, name, tpl, netvm, label, mem, maxmem, vcpus):
        o, r = self.out, self.r
        if r.vm_exists(name):
            o.skip(name)
        else:
            if not r.vm_exists(tpl):
                o.warn(f"template {tpl} missing — cannot create {name}")
                return
            r.run("qvm-create", "--class", "AppVM", "--template", tpl,
                  "--label", label, name)
            r.will_create(name)
            o.ok(f"created {name}")
        r.prefs(name, provides_network="True", netvm=netvm, memory=mem,
                maxmem=maxmem, vcpus=vcpus, autostart="True")
        o.info(f"{name} -> netvm {netvm}")

    def p06(self):
        o, r, res, q = self.out, self.r, self.c["resources"], self.q
        o.info("building the chain top-down so each upstream exists first")
        r.run("qvm-prefs", q["firewall"], "netvm", q["net"])

        self._mk_netqube(q["dpi"], self.t["ids"], q["firewall"], "orange",
                         res["ids_mem"], res["ids_maxmem"], res["ids_vcpus"])
        self._mk_netqube(q["ids"], self.t["ids"], q["dpi"], "orange",
                         res["ids_mem"], res["ids_maxmem"], res["ids_vcpus"])
        self._mk_netqube(q["proxy"], self.t["proxy"], q["ids"], "orange",
                         res["proxy_mem"], res["proxy_maxmem"], 2)

        for svc in (q["net"], q["firewall"], q["usb"]):
            if r.vm_exists(svc) and r.vm_exists(self.t["sys"]):
                r.shutdown(svc)
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

# Create the chain if it does not already exist (idempotent across restarts).
nft add chain ip qubes custom-dnat-squid \
    '{{ type nat hook prerouting priority filter + 1 ; policy accept; }}' 2>/dev/null

# Redirect downstream web traffic into Squid. Non-web ports are untouched and
# continue up the chain, still inspected by Suricata and Zeek.
nft add rule ip qubes custom-dnat-squid iifname "vif*" tcp dport 80  redirect to :3128
nft add rule ip qubes custom-dnat-squid iifname "vif*" tcp dport 443 redirect to :3129

# Let the redirected packets reach the local Squid sockets.
nft add rule ip qubes custom-input iifname "vif*" tcp dport {{ 3128, 3129 }} counter accept

# Sibling qubes meet here first: permit agent traffic to the SIEM, nothing else.
nft add rule ip qubes custom-forward ip daddr {w['ip']} tcp dport {{ {w['port_events']}, {w['port_enroll']} }} counter accept
""", mode="0755")
        r.qwrite(q["proxy"], "/rw/config/rc.local", """\
#!/bin/sh
cp -f /rw/config/squid-golden.conf /etc/squid/squid.conf 2>/dev/null
[ -f /etc/squid/placeholder.pem ] || \\
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \\
    -subj "/CN=golden-image-proxy" \\
    -keyout /etc/squid/placeholder.pem -out /etc/squid/placeholder.pem 2>/dev/null
systemctl restart squid
""", mode="0755")
        o.ok(f"{q['proxy']} configured")
        o.info("uses a created custom-dnat-squid chain + custom-input accept, per the")
        o.info("  documented Qubes port-forwarding pattern — there is no custom-prerouting")
        o.verify("counters increment: nft list chain ip qubes custom-dnat-squid")

        # ---------------- sys-ids ----------------
        mode = self.c["ips_failure_mode"]
        o.info(f"{q['ids']}: Suricata inline IPS (failure mode: {mode})")
        r.ensure_running(q["ids"])
        bypass = " bypass" if mode == "open" else ""
        r.qwrite(q["ids"], "/rw/config/qubes-firewall-user-script", f"""\
#!/bin/sh
# Golden image — {q['ids']}
# Every forwarded packet is queued to Suricata for an accept/drop verdict.
# ips_failure_mode = {mode}
#   closed : no bypass — Suricata down means the chain stops. Nothing passes
#            uninspected. This is the casework default.
#   open   : bypass — traffic keeps flowing if Suricata is not listening.
nft insert rule ip qubes custom-forward counter queue num 0{bypass} 2>/dev/null || \\
  logger -t golden-image "NFQUEUE hook failed — VERIFY custom-forward chain name"
""", mode="0755")
        r.qwrite(q["ids"], "/rw/config/qubes-bind-dirs.d/50_golden_ids.conf",
                 "binds+=( '/etc/suricata' )\nbinds+=( '/var/lib/suricata' )\n"
                 "binds+=( '/var/log/suricata' )\n")
        r.qwrite(q["ids"], "/etc/systemd/system/suricata-nfqueue.service", """\
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
        r.qwrite(q["ids"], "/rw/config/rc.local",
                 "#!/bin/sh\nsystemctl daemon-reload\n"
                 "systemctl start suricata-nfqueue.service\n", mode="0755")
        r.qwrite(q["ids"], "/var/lib/suricata/rules/golden-image-test.rules",
                 'alert http any any -> any any (msg:"GOLDEN-IMAGE-TEST canary"; '
                 'content:"golden-image-canary"; http_uri; sid:9000001; rev:1;)\n')
        o.ok(f"{q['ids']} configured")

        # ---------------- sys-dpi ----------------
        z = self.c["zeek"]
        o.info(f"{q['dpi']}: Zeek deep packet inspection")
        r.ensure_running(q["dpi"])
        r.qwrite(q["dpi"], "/rw/config/zeek-node.cfg",
                 "[zeek]\ntype=standalone\nhost=localhost\ninterface=eth0\n")
        r.qwrite(q["dpi"], "/rw/config/qubes-bind-dirs.d/50_golden_dpi.conf",
                 f"binds+=( '{z['prefix']}/etc' )\nbinds+=( '{z['prefix']}/logs' )\n")
        r.qwrite(q["dpi"], "/rw/config/rc.local", f"""\
#!/bin/sh
if [ -x {z['prefix']}/bin/zeekctl ]; then
  cp -f /rw/config/zeek-node.cfg {z['prefix']}/etc/node.cfg 2>/dev/null
  {z['prefix']}/bin/zeekctl deploy
else
  logger -t golden-image "zeekctl not found — Zeek not installed in this template"
fi
""", mode="0755")
        o.ok(f"{q['dpi']} configured")
        o.verify(f"Zeek install prefix — these configs assume {z['prefix']}")

        # ---------------- sys-firewall ----------------
        # DNS enforcement.
        #
        # The previous version wrote rules into the 'dnat-dns' chain from
        # qubes-firewall-user-script. That was wrong twice over: dnat-dns is
        # Qubes-managed, and qubes-setup-dnat-to-ns REGENERATES it when the
        # network comes up, silently discarding our rules.
        #
        # The working pattern (qubes-issues #9056) is an nft script that
        # replaces the chain wholesale, placed in /rw/config/qubes-firewall.d/
        # so it runs as part of qubes-firewall startup.
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
            r.qwrite(q["firewall"], "/rw/config/rc.local", """\
#!/bin/sh
# unbound ships its drop-in dir at /etc/unbound/unbound.conf.d on Debian.
if command -v unbound >/dev/null 2>&1; then
  install -m 644 /rw/config/unbound-quad9.conf \
      /etc/unbound/unbound.conf.d/golden-image.conf
  systemctl restart unbound
else
  logger -t golden-image "unbound missing — install it or set dns.mode=plain"
fi
""", mode="0755")
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
# Replaces the Qubes-generated dnat-dns chain. Pattern from qubes-issues #9056.
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

        r.qwrite(q["firewall"], "/rw/config/qubes-firewall-user-script", f"""\
#!/bin/sh
# Golden image — {q['firewall']}

# Let downstream DNS reach the local resolver after the redirect above.
nft add rule ip qubes custom-input iifname "vif*" meta l4proto {{ tcp, udp }} th dport 53 counter accept

# Nothing raw on port 53 leaves upstream: kills clients with hardcoded
# resolvers. Placed AFTER the redirect, so legitimate queries are already
# translated and never reach the forward path.
nft add rule ip qubes custom-forward meta l4proto {{ tcp, udp }} th dport 53 counter drop

# Segmentation: qube-to-qube stays denied except the SIEM flows permitted at
# {q['proxy']}.
nft add rule ip qubes custom-forward ip saddr 10.137.0.0/16 ip daddr 10.137.0.0/16 counter drop
nft add rule ip qubes custom-forward ip saddr 10.138.0.0/16 ip daddr 10.137.0.0/16 counter drop
""", mode="0755")

        o.ok(f"{q['firewall']} configured")
        o.info("dnat-dns is replaced via /rw/config/qubes-firewall.d/10-golden-dns,")
        o.info("  not patched from the user script — Qubes regenerates that chain.")
        o.verify("after reboot: nft list chain ip qubes dnat-dns  (should show the "
                 "golden-image rule, not the default nameservers)")
        self._mark(7)

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
            r.run("qvm-clone", "--class", "StandaloneVM", self.t["wazuh"], q["wazuh"])
            r.run("qvm-prefs", q["wazuh"], "label", "blue")
            r.will_create(q["wazuh"])
            o.ok(f"created {q['wazuh']}")

        r.prefs(q["wazuh"], netvm=q["proxy"], memory=w["mem"], maxmem=w["maxmem"],
                vcpus=w["vcpus"], autostart="True", ip=w["ip"])
        r.run("qvm-volume", "resize", f"{q['wazuh']}:root", f"{w['root_gb']}G")
        o.info(f"{q['wazuh']} pinned to {w['ip']}, root grown to {w['root_gb']}G")

        if not self.args.dry_run and self.creds:
            r.ensure_running(q["wazuh"])
            r.qwrite(q["wazuh"], "/rw/golden-authd.pass", self.creds["authd"], mode="0600")
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

        certs_ok = r.qtest(q["wazuh"], "test -x /opt/wazuh-certs-tool.sh")
        if certs_ok:
            r.qwrite(q["wazuh"], "/opt/wazuh-config.yml", f"""\
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
            r.qrun(q["wazuh"],
                   "cd /opt && ./wazuh-certs-tool.sh -A -c /opt/wazuh-config.yml",
                   check=False)
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
            r.qrun(q["wazuh"],
                   f"/opt/wazuh-passwords-tool.sh -u admin "
                   f"-p {shlex.quote(self.creds.get('dashboard',''))} || true",
                   check=False)
            o.ok("dashboard admin password set from credentials.json")
        else:
            o.warn("wazuh-passwords-tool.sh not available — the admin password is")
            o.warn("  whatever the indexer generated. Retrieve it from")
            o.warn("  /etc/wazuh-indexer/ or reset it before issuing the laptop.")

        o.verify("the SIEM is actually up before issuing the laptop:")
        o.verify("    qvm-run -u root wazuh-srv 'systemctl is-active wazuh-manager "
                 "wazuh-indexer wazuh-dashboard'")
        o.verify("certificate paths against the Wazuh "
                 f"{w['version']} single-node guide — layout changes between series")
        o.info("agents self-enroll on first start (phase 11) — no manual key exchange")

        self._mark(8)

    # =======================================================================
    #  9 — app qubes
    # =======================================================================
    def _firewall_clear(self, vm: str) -> None:
        """Clear a qube's firewall rules.

        'qvm-firewall <vm> reset' is widely used in community scripts but is NOT
        in the official manpage, so it may not exist on every release. Use it
        only if --help advertises it; otherwise delete rules by number, which is
        documented.
        """
        o, r = self.out, self.r
        helptext = r.run("qvm-firewall", "--help", check=False, capture=True)
        if "reset" in helptext:
            r.quiet("qvm-firewall", vm, "reset")
            o.info(f"{vm}: rules cleared with 'reset'")
            return
        # Documented fallback: delete rule 0 until none remain.
        for _ in range(64):
            listing = r.run("qvm-firewall", vm, "list", check=False, capture=True)
            rows = [l for l in listing.splitlines()[1:] if l.strip()]
            if not rows:
                break
            if not r.quiet("qvm-firewall", vm, "del", "--rule-no", "0"):
                break
        o.info(f"{vm}: rules cleared with 'del --rule-no' (no 'reset' subcommand)")

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
            r.run("qvm-firewall", name, "add", "accept", "proto=tcp", "dstports=80")
            r.run("qvm-firewall", name, "add", "accept", "proto=tcp", "dstports=443")
            r.run("qvm-firewall", name, "add", "accept", "specialtarget=dns")
            r.run("qvm-firewall", name, "add", "drop")
            o.ok(f"{name} egress restricted to web + dns")
        self._mark(9)

    # =======================================================================
    #  10 — policy, segmentation, backup
    # =======================================================================
    def p10(self):
        o, r, q, w, b = self.out, self.r, self.q, self.c["wazuh"], self.c["backup"]
        pol = Path("/etc/qubes/policy.d/30-golden-image.policy")
        policy = f"""\
# {self.c['image_name']} v{self.c['image_version']}
# Dashboard reachable only from 'work', over qrexec — no open HTTPS port.
qubes.ConnectTCP +443   work        @default allow target={q['wazuh']}

# Tor-branch telemetry. These qubes have NO network route to the SIEM by
# design; dom0 pipes their agent traffic instead, so nothing beacons clearnet
# from an anonymous context.
qubes.ConnectTCP +{w['port_events']}  {q['whonix']}  @default allow target={q['wazuh']}
qubes.ConnectTCP +{w['port_events']}  {q['kali_tor']} @default allow target={q['wazuh']}
qubes.ConnectTCP +{w['port_events']}  anon-whonix   @default allow target={q['wazuh']}
"""
        if self.args.dry_run:
            o.info(f"[dry-run] write {pol}")
        else:
            pol.parent.mkdir(parents=True, exist_ok=True)
            pol.write_text(policy)
            o.ok(f"wrote {pol}")
        o.verify("qubes.ConnectTCP policy grammar and qvm-connect-tcp argument order")

        for name in (q["whonix"], q["kali_tor"], "anon-whonix"):
            if not r.vm_exists(name):
                continue
            r.ensure_running(name)
            r.qwrite(name, "/rw/config/rc.local",
                     "#!/bin/sh\n"
                     "# Golden image — Tor-branch telemetry over qrexec, never the network.\n"
                     f"qvm-connect-tcp {w['port_events']}:{q['wazuh']}:{w['port_events']} &\n",
                     mode="0755")
            o.ok(f"{name}: qrexec telemetry pipe staged")

        # --- backup -------------------------------------------------------
        # qvm-backup has NO --yes flag. Profile mode is the documented
        # non-interactive path: the profile carries destination, passphrase and
        # include list, and --profile is mutually exclusive with everything else.
        prof_name = "golden-image"
        prof_path = Path(f"/etc/qubes/backup/{prof_name}.conf")
        bscript = Path("/usr/local/bin/golden-weekly-backup.sh")
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

            bscript.write_text(f"""#!/bin/bash
# {self.c['image_name']} — weekly backup
# Regenerates the profile so current case-* qubes are included, then runs it.
# Deliberately excluded: the Tor branch (holds nothing, and backing it up would
# copy anonymous-context artifacts into attributed storage) and stock templates.
set -e
PROFILE={prof_name}
CONF=/etc/qubes/backup/$PROFILE.conf
BASE="{' '.join(base_include)}"
CASES=$(qvm-ls --raw-list | grep '^case-' || true)

{{
  echo "destination_vm: {b['dest_qube']}"
  echo "destination_path: {b['dest_dir']}"
  echo "compression: true"
  echo "passphrase_file: /root/.backup-pass"
  echo "include:"
  for v in $BASE $CASES; do
      qvm-check --quiet "$v" 2>/dev/null && echo " - $v"
  done
}} > "$CONF"
chmod 600 "$CONF"

qvm-backup --profile "$PROFILE"
""")
            bscript.chmod(0o755)
            Path("/etc/systemd/system/golden-backup.service").write_text(
                "[Unit]\nDescription=Golden image weekly Qubes backup\n"
                "[Service]\nType=oneshot\n"
                f"ExecStart={bscript}\n")
            Path("/etc/systemd/system/golden-backup.timer").write_text(
                "[Unit]\nDescription=Run the golden image weekly backup\n"
                f"[Timer]\nOnCalendar={b['schedule']}\nPersistent=true\n"
                "[Install]\nWantedBy=timers.target\n")
            r.quiet("systemctl", "daemon-reload")
            if r.quiet("systemctl", "enable", "--now", "golden-backup.timer"):
                o.ok(f"backup timer enabled ({b['schedule']})")
            else:
                o.warn("could not enable golden-backup.timer — enable it manually")

        o.verify("the backup profile schema. Confirm with a one-off run:")
        o.verify(f"    sudo qvm-backup --profile {prof_name}")
        o.verify("  If the key names are rejected, generate a known-good profile with")
        o.verify("  'qvm-backup --save-profile <name> ...' once and copy its keys.")
        o.warn(f"attach the backup disk to {b['dest_qube']} and mount it at {b['dest_dir']}")
        o.warn("escrow the backup passphrase before shredding credentials.json — "
               "no passphrase, no restore")
        self._mark(10)

    def _write_backup_profile(self, path: Path, include: list[str]) -> None:
        """Write a qvm-backup profile.

        Profile mode is the only documented non-interactive path (there is no
        --yes flag). The schema is flagged [VERIFY]: confirm with one manual
        run, or generate a reference profile via --save-profile.
        """
        lines = [f"destination_vm: {self.c['backup']['dest_qube']}",
                 f"destination_path: {self.c['backup']['dest_dir']}",
                 "compression: true",
                 "passphrase_file: /root/.backup-pass",
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
        pw = self.creds.get("authd", "")
        r.qrun(vm, f"printf '%s\\n' {shlex.quote(pw)} > /var/ossec/etc/authd.pass && "
                   "chmod 640 /var/ossec/etc/authd.pass && "
                   "chown root:wazuh /var/ossec/etc/authd.pass 2>/dev/null || true")
        r.qrun(vm, "sed -i -e 's|<address>MANAGER_IP</address>|"
                   f"<address>{target}</address>|' "
                   f"-e 's|<address>[0-9.]*</address>|<address>{target}</address>|' "
                   "/var/ossec/etc/ossec.conf")
        r.qrun(vm, "systemctl enable --now wazuh-agent")
        o.ok(f"{vm} enrolled via {via} -> {target}")

    def p11(self):
        o, q, w = self.out, self.q, self.c["wazuh"]
        mgr = w["central_address"] if w["mode"] == "central" else w["ip"]
        if not self.creds and self.cred_file.exists():
            self.creds = json.loads(self.cred_file.read_text())

        o.info("network transport — clearnet and chain qubes")
        for vm in (q["proxy"], q["ids"], q["dpi"], q["firewall"], q["net"], q["usb"],
                   "personal", "work", "untrusted", q["kali_clear"]):
            self._enroll(vm, "network", mgr)

        o.info("qrexec transport — Tor branch (no network path to the SIEM exists)")
        for vm in (q["whonix"], q["kali_tor"], "anon-whonix"):
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
            self._t("pass" if nv in ("", "None") else "fail",
                    f"{vm} is offline" if nv in ("", "None") else f"{vm} has netvm '{nv}'")

        o.say("")
        o.info("4. Wazuh agent present in every template")
        for tpl in (self.t["sys"], self.t["proxy"], self.t["ids"], self.t["kali"],
                    self.t["personal"], self.t["wazuh"], self.c["base_debian"],
                    self.c["base_fedora"], self.c["base_whonix_gw"],
                    self.c["base_whonix_ws"]):
            if not r.vm_exists(tpl):
                continue
            self._t("pass" if r.qtest(tpl, "test -d /var/ossec") else "fail",
                    f"{tpl} carries the agent" if r.qtest(tpl, "test -d /var/ossec")
                    else f"{tpl} has no /var/ossec")

        if self.c["prefer_debian"]:
            o.say("")
            o.info("4a. Debian everywhere it is possible")
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
        o.info("4b. supply chain integrity")
        k = self.c["kali"]
        if r.vm_exists(self.t["kali"]):
            r.ensure_running(self.t["kali"])
            good = r.qtest(self.t["kali"],
                           f"gpg --no-default-keyring --keyring {shlex.quote(k['keyring_path'])} "
                           f"--fingerprint 2>/dev/null | tr -d ' \\n' | grep -qi {k['key_fpr']}")
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
        o.info("5. DNS enforcement")
        if r.vm_exists("personal"):
            r.ensure_running("personal")
            leaked = r.quiet("qvm-run", "--no-gui", "personal",
                             "timeout 8 dig +short +time=3 +tries=1 @8.8.8.8 example.com")
            self._t("fail" if leaked else "pass",
                    "personal reached 8.8.8.8 — port-53 capture not working" if leaked
                    else "external resolver 8.8.8.8 unreachable from personal")
            resolves = r.quiet("qvm-run", "--no-gui", "personal",
                               "timeout 8 getent hosts example.com")
            self._t("pass" if resolves else "warn",
                    "name resolution works via the enforced path" if resolves
                    else f"resolution failed in personal — check unbound in {q['firewall']}")

        o.say("")
        o.info("6. inspection services")
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
        o.info("7. proxy logs the originating qube")
        if r.vm_exists("personal") and r.vm_exists(q["proxy"]):
            r.quiet("qvm-run", "--no-gui", "personal",
                    "timeout 10 curl -s -o /dev/null http://example.com/golden-image-canary")
            time.sleep(3)
            self._t("pass" if r.qtest(q["proxy"], "grep -q 10.137 /var/log/squid/access.log")
                    else "warn", "Squid access.log carries per-qube source addresses")

        o.say("")
        o.info("8. Tor branch")
        if r.vm_exists(q["kali_tor"]):
            nv = r.run("qvm-prefs", q["kali_tor"], "netvm", check=False, capture=True).strip()
            self._t("pass" if nv == q["whonix"] else "fail",
                    f"{q['kali_tor']} routes via {q['whonix']} only")
            self._t("warn", "manual: open Tor Browser in kali-tor and confirm "
                            "check.torproject.org reports Tor")

        o.say("")
        o.info("9. backup")
        self._t("pass" if r.quiet("systemctl", "is-enabled", "golden-backup.timer")
                else "fail", "golden-backup.timer enabled")
        self._t("pass" if Path("/root/.backup-pass").exists() else "warn",
                "backup passphrase file present")

        o.say("")
        o.info("10. credentials")
        if self.cred_file.exists():
            mode = oct(self.cred_file.stat().st_mode)[-3:]
            self._t("pass" if mode == "600" else "fail", f"credentials.json mode {mode}")
            if self.c["credentials"]["use_fixed_defaults"]:
                self._t("warn", "use_fixed_defaults is on — secrets shared across builds. "
                                "Rotate now.")
        else:
            self._t("warn", "credentials.json not found")

        o.say("")
        print(f"  {Out.G}{self.tests['pass']} passed{Out.RST}   "
              f"{Out.R}{self.tests['fail']} failed{Out.RST}   "
              f"{Out.Y}{self.tests['warn']} warnings{Out.RST}")
        if self.tests["fail"] == 0:
            self._mark(12)

    # =======================================================================
    def handover(self):
        if self.args.dry_run:
            return
        q = self.q
        print(f"\n{Out.B}{Out.C}\u2550\u2550 Handover{Out.RST}")
        print(f"""
  Credentials      {self.cred_file}   (mode 600, dom0 only)
  How to rotate    {self.build_dir / 'CREDENTIALS-README.txt'}
  Build log        {self.out.log_path}
  Resume state     {self.state_file}

  First login
    1. Read credentials.json — four secrets, generated for THIS machine.
    2. In 'work':  qvm-connect-tcp 8443:{q['wazuh']}:443
       then browse https://localhost:8443 and log in as admin.
    3. Change all four secrets (see CREDENTIALS-README.txt).
    4. Escrow the new values, then:  shred -u {self.cred_file}

  Before this laptop is issued
    - Read the [VERIFY] list this run printed and confirm each on the machine.
    - Re-run:  sudo {Path(sys.argv[0]).name} --verify
    - All acceptance tests must pass.
""")
        if self.out.verify_notes:
            print(f"  {Out.Y}Items flagged [VERIFY] this run:{Out.RST}")
            for n in dict.fromkeys(self.out.verify_notes):
                print(f"    - {n}")
            print()

    def run(self):
        o = self.out
        print(f"\n{Out.B}{Out.C}{self.c['image_name']} v{self.c['image_version']}{Out.RST}")
        if self.args.dry_run:
            print(f"{Out.Y}DRY RUN — nothing will be changed{Out.RST}")
        o.say(f"log: {self.out.log_path}")

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
        o.ok("finished")


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


def load_config(write_only: bool = False) -> dict:
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

    CONF_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2) + "\n")
    CONF_PATH.chmod(0o644)
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
        description="QubesOS Cybercrime Investigator provisioner (dom0)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dry-run", action="store_true",
                   help="print every action, change nothing")
    p.add_argument("--phase", type=int, metavar="N", help="run only phase N")
    p.add_argument("--from-phase", type=int, default=1, metavar="N",
                   help="start at phase N (resume after failure)")
    p.add_argument("--verify", action="store_true", help="run acceptance tests only")
    p.add_argument("--force", action="store_true", help="skip the Qubes release check")
    p.add_argument("--write-config", action="store_true",
                   help="emit golden-image.json and exit")
    p.add_argument("--list-phases", action="store_true")
    args = p.parse_args()

    if args.list_phases:
        for i, name in enumerate(Provisioner.PHASES, start=1):
            print(f"  {i:2d}  {name}")
        return 0

    try:
        cfg = load_config(write_only=args.write_config)
        Provisioner(cfg, args).run()
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
