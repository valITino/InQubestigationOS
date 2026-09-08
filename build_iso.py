#!/usr/bin/env python3
"""
build_iso.py — InQubestigationOS.iso

Builds a custom bootable Qubes installer with qubes-builderv2, optionally with
the investigator templates baked in (Tier 2) so the target installs with no
network at all.

*** RUNS ON A BUILD HOST, NEVER IN DOM0 ***
Needs Fedora or Debian, Docker or Podman, ~100 GB free (Tier 1) or ~250 GB
(Tier 2), and several hours.

    ./build_iso.py --write-config          # emit iso-build.json, review, edit
    ./build_iso.py --dry-run               # print the plan
    ./build_iso.py templates               # Tier 2: build investigator templates
    ./build_iso.py iso                     # build the ISO
    ./build_iso.py all                     # templates (if Tier 2) then ISO

VERIFIED FACTS baked into the defaults, checked 2026-09-01 against
QubesOS/qubes-qubes-release @ release4.3 and QubesOS/qubes-builderv2:

  * The kickstart component "qubes-release" resolves to the repository
    https://github.com/QubesOS/qubes-qubes-release.git — the builder builds
    URLs as baseurl + git.prefix + component name, and the prefix is
    "QubesOS/qubes-".
  * conf/ holds: qubes-kickstart.cfg (the real base), iso-online.ks,
    iso-online-testing.ks, iso-online-testing-no-templates.ks,
    iso-unknown-key.ks, iso-unsigned.ks, iso-unsigned2.ks
  * comps/ holds: comps-dom0.xml, comps-host.xml, comps-vm.xml
  * comps-dom0.xml on release4.3 hardcodes the template groups:
        @fedora -> qubes-template-fedora-43-xfce
        @debian -> qubes-template-debian-13-xfce
        @whonix -> qubes-template-whonix-gateway-18, -workstation-18
  * comps-dom0.xml on release4.3 does NOT contain the @QUBES_TEMPLATES@
    marker, so the installer plugin's render_comps() is a no-op there.
    Custom templates therefore CANNOT be installed via a comps group on this
    branch — they must be listed explicitly in %packages. This script does
    exactly that, and verifies the assumption at build time.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ===========================================================================
DEFAULT_CONFIG: dict = {
    "iso_name": "InQubestigationOS.iso",
    "iso_flavor": "InQubestigationOS",
    "iso_version": "",
    "qubes_release": "r4.3",
    "builder_branch": "release4.3",

    # TIER 2 IS THE DEFAULT AND THE INTENDED PATH.
    #   2 = investigator templates baked into the ISO as RPMs. Installs with no
    #       network. First boot only wires the topology — minutes, not hours.
    #   1 = stock templates only; the investigator templates get built on first
    #       boot from the network. Smaller ISO, but 1-3 hours of first-boot work
    #       and a hard dependency on connectivity at install time. Fallback only.
    "tier": 2,

    "work_dir": str(Path.home() / "investigator-iso"),
    # docker, not podman: upstream states the podman executor currently cannot
    # build DEB packages, and every custom template here is Debian.
    "container_engine": "docker",
    # The Mock chroot for the build cages must match the HOST distribution of
    # the Qubes release you are building (dom0 is Fedora — that part is fixed
    # by Qubes and cannot be Debian).
    "mock_config": "fedora-41-x86_64",
    # Build host preference. qubes-builderv2 supports Fedora or Debian hosts;
    # dependencies-debian.txt is shipped and Debian 13 carries the Sequoia
    # packages the builder wants. A Debian 13 build host keeps the toolchain on
    # the same distribution as everything the image actually runs.
    "prefer_debian_build_host": True,

    # Blank = auto-detected from the fetched sources. Verified names on
    # release4.3 are listed in the module docstring.
    "base_kickstart": "",
    "comps_file": "comps/comps-dom0.xml",

    # Blank = derived from comps-dom0.xml at build time rather than guessed.
    # Hardcoding these was a real bug: release4.3 pins fedora-43-xfce while the
    # builderv2 example config builds fedora-44-xfce.
    "iso_templates": [],

    "tier2_templates": [
        "investigator-kali", "investigator-office",
        "investigator-ids", "investigator-proxy", "investigator-wazuh",
    ],
    "cache_templates": [],

    "auto_provision": True,

    # GPG fingerprint (40 hex chars) of the unit key that signs the ISO.
    # THIS IS A FINGERPRINT, NOT A KEY. The private key stays in the build
    # host's GPG keyring and must never appear in this file or in the repo.
    # The script exports the matching PUBLIC key next to the ISO so colleagues
    # can verify, and refuses to run if key material is pasted here.
    "iso_sign_key": "",

    # --- Tier 2 template build -------------------------------------------
    "dist_codename": "trixie",
    "template_root_size": "30G",
    # Top-level build timeout in seconds. The Kali template is the slow one.
    "build_timeout": 21600,
    "kali": {
        "keyring_url": "https://archive.kali.org/archive-keyring.gpg",
        # 827C...E4C5 IS the CURRENT 2025 key (expires 2028-04-17), short id
        # ED65462EC8D5E4C5. 44C6513A...0BF6 is the retired one, still shipped.
        "key_fpr": "827C8569F2518CC677FECA1AED65462EC8D5E4C5",
        "key_fpr_legacy": "44C6513A8E4FB3D30875F758ED444FF07D8D0BF6",
        "metapackage": "kali-linux-default",
    },
    "zeek": {
        "repo_line": "deb http://download.opensuse.org/repositories/security:/zeek/Debian_13/ /",
        "key_url": "https://download.opensuse.org/repositories/security:zeek/Debian_13/Release.key",
        "package": "zeek-8.0",
    },
    "wazuh": {
        "key_url": "https://packages.wazuh.com/key/GPG-KEY-WAZUH",
        "apt_repo_line": "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main",
    },
}

CONF_PATH = Path(__file__).resolve().parent / "iso-build.json"
RST, B, R, G, Y, C, D = ("\033[0m", "\033[1m", "\033[31m", "\033[32m",
                         "\033[33m", "\033[36m", "\033[2m")


class Fatal(Exception):
    pass


class Ctx:
    def __init__(self, cfg: dict, args):
        self.c = cfg
        self.args = args
        self.work = Path(cfg["work_dir"])
        self.builder = self.work / "qubes-builderv2"
        self.component = self.work / "qubes-template-investigator"
        self.out_dir = self.work / "output"
        self.log = self.work / "build.log"
        self.state = self.work / ".state"
        self.work.mkdir(parents=True, exist_ok=True)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.log.touch(exist_ok=True)
        self.verify_notes: list[str] = []

    # --- output --------------------------------------------------------
    def _log(self, s):
        with self.log.open("a") as f:
            f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {s}\n")

    def say(self, m=""):  print(m); self._log(m)
    def info(self, m):    print(f"  {D}{m}{RST}"); self._log(f"INFO  {m}")
    def ok(self, m):      print(f"  {G}\u2713{RST} {m}"); self._log(f"OK    {m}")
    def skip(self, m):    print(f"  {D}\u00b7{RST} {m} {D}(done){RST}")
    def warn(self, m):    print(f"  {Y}!{RST} {m}"); self._log(f"WARN  {m}")

    def verify(self, m):
        print(f"  {Y}?{RST} {Y}[VERIFY] {m}{RST}")
        self.verify_notes.append(m)

    def phase(self, n, name):
        print(f"\n{B}{C}\u2550\u2550 {n} \u2014 {name}{RST}")
        self._log(f"PHASE {n} {name}")

    # --- exec ----------------------------------------------------------
    def run(self, *argv, cwd=None, check=True, capture=False, live=False):
        cmd = [str(a) for a in argv]
        if self.args.dry_run:
            print(f"  {D}[dry-run]{RST} {' '.join(shlex.quote(a) for a in cmd)}")
            return ""
        self._log("EXEC  " + " ".join(cmd))
        if live:
            p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True)
            assert p.stdout
            with self.log.open("a") as lf:
                for line in p.stdout:
                    sys.stdout.write(line)
                    lf.write(line)
            p.wait()
            if check and p.returncode != 0:
                raise Fatal(f"failed: {' '.join(cmd)} — see {self.log}")
            return ""
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
        self._log(f"      rc={p.returncode}\n{p.stdout[-4000:]}{p.stderr[-4000:]}")
        if check and p.returncode != 0:
            raise Fatal(f"failed: {' '.join(cmd)} — see {self.log}")
        return p.stdout if capture else ""

    def quiet(self, *argv) -> bool:
        try:
            return subprocess.run([str(a) for a in argv], capture_output=True,
                                  timeout=180).returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    # ---- signing ------------------------------------------------------
    def check_sign_key(self) -> None:
        """Validate iso_sign_key is a fingerprint and that we can sign with it.

        A FINGERPRINT is public and safe to store. PRIVATE KEY MATERIAL must
        never appear in a config file or a repository — if someone pastes a
        key block here, refuse loudly rather than committing it to git.
        """
        fp = (self.c.get("iso_sign_key") or "").strip()
        if not fp:
            return
        if "BEGIN PGP" in fp or "PRIVATE KEY" in fp:
            raise Fatal(
                "iso_sign_key contains PGP key material.\n"
                "     Put only the 40-character FINGERPRINT here. The private key\n"
                "     belongs in the build host's GPG keyring and must never be\n"
                "     written to a config file or committed to a repository.\n"
                "     If a private key was pasted, treat it as compromised: revoke\n"
                "     it and generate a new one.")
        clean = fp.replace(" ", "").upper()
        if not re.fullmatch(r"[0-9A-F]{40}", clean):
            raise Fatal(f"iso_sign_key '{fp}' is not a 40-hex-character GPG "
                        "fingerprint. Get it with:  gpg --fingerprint <key-id>")
        self.c["iso_sign_key"] = clean
        if not self.args.dry_run:
            if not self.quiet("gpg", "--list-secret-keys", clean):
                raise Fatal(
                    f"no SECRET key for {clean} in this build host's keyring.\n"
                    "     Signing needs the private key present locally. Either\n"
                    "     import it here, or build unsigned and sign on the machine\n"
                    "     that holds the key.")
            self.ok(f"signing key present and usable: {clean}")

    def export_pubkey(self) -> None:
        """Ship the public key beside the ISO so colleagues can verify."""
        fp = self.c["iso_sign_key"]
        out = self.out_dir / "unit-signing-key.asc"
        if self.args.dry_run:
            self.info(f"[dry-run] export public key {fp} -> {out.name}")
            return
        if self.quiet("gpg", "--armor", "--output", str(out), "--export", fp):
            self.ok(f"public key exported: {out.name}")
            self.warn("Distribute this fingerprint through a channel INDEPENDENT of")
            self.warn("  the ISO — a key shipped only alongside the image it signs")
            self.warn("  proves nothing. Read it out on the phone, or publish it on")
            self.warn("  an internal page colleagues already trust.")
        else:
            self.warn("could not export the public key")

    def done(self, key) -> bool:
        return self.state.exists() and key in self.state.read_text().split()

    def mark(self, key):
        if not self.args.dry_run:
            with self.state.open("a") as f:
                f.write(key + "\n")


# ===========================================================================
#  Preflight
# ===========================================================================
def preflight(x: Ctx, tier2: bool):
    x.phase("pre", "preflight and warnings")
    if Path("/etc/qubes-release").exists() and not Path("/usr/share/qubes/marker-vm").exists():
        raise Fatal("this looks like dom0. The ISO builder must NOT run in dom0.\n"
                    "     Use a Fedora/Debian host, or a Qubes app qube with network.")
    x.ok("not running in dom0")

    # Validate configuration before anything slow or environmental. A pasted
    # private key must be caught immediately, not after a Docker check fails.
    x.check_sign_key()

    x.say("")
    print(f"{B}{Y}  Three things to understand before you ship this ISO{RST}")
    x.say("")
    x.warn("1. A SELF-BUILT ISO IS NOT SIGNED BY THE QUBES TEAM.")
    x.warn("   Colleagues cannot verify it against the Qubes release key, because it")
    x.warn("   is not a Qubes release. You become the signing authority: set")
    x.warn("   iso_sign_key and distribute that fingerprint through a channel")
    x.warn("   independent of the ISO. An unsigned image passed around on USB sticks")
    x.warn("   is exactly the supply-chain problem this design exists to prevent.")
    x.say("")
    x.info("Note: dom0 is Fedora and cannot be Debian — Qubes builds dom0 on")
    x.info("Fedora and ships no Debian dom0. Everything the image actually runs")
    x.info("(service qubes, all custom templates, Whonix) is Debian.")
    x.say("")
    x.warn("2. THIS ISO GOES STALE AND BECOMES A LIABILITY.")
    x.warn("   It freezes dom0, Xen and the kernel at build time. Security bulletins")
    x.warn("   keep coming. An image built today and installed in six months installs")
    x.warn("   six months of known-vulnerable dom0 before its first update. Rebuild on")
    x.warn("   every QSB affecting dom0 or Xen; treat a stale image as unusable.")
    x.say("")
    if tier2:
        x.warn("3. TIER 2 AGES IN TWO PLACES, NOT ONE.")
        x.warn("   Templates freeze their package versions too. Every Kali, Zeek or")
        x.warn("   Wazuh update means rebuilding templates and re-cutting the ISO.")
        x.warn("   Expect an image in the tens of GB — check your USB media and")
        x.warn("   distribution method can carry it before committing to a build.")
    else:
        x.warn("3. TIER 1 BUILDS THE INVESTIGATOR TEMPLATES ON FIRST BOOT.")
        x.warn("   The ISO carries stock templates plus the provisioning payload, so")
        x.warn("   the first boot needs network and takes 1-3 hours. Set tier=2 for a")
        x.warn("   fully offline install.")
    x.say("")

    if not x.args.force and not x.args.dry_run:
        if input("  Type UNDERSTOOD to continue: ").strip() != "UNDERSTOOD":
            raise Fatal("aborted at the warnings (use --force to skip)")

    need = 250 if tier2 else 100
    try:
        st = os.statvfs(x.work)
        free = st.f_bavail * st.f_frsize // (1024 ** 3)
        x.info(f"free space at {x.work}: {free}G")
        if free < need:
            x.warn(f"under {need}G free — this build will very likely fail")
    except OSError:
        pass

    for tool in ("git", "curl", "gpg"):
        if not shutil.which(tool):
            raise Fatal(f"{tool} not installed")

    host = "debian/ubuntu" if shutil.which("apt-get") else (
        "fedora" if shutil.which("dnf") else "unknown")
    x.info(f"build host: {host}")
    if x.c["prefer_debian_build_host"] and host == "fedora":
        x.info("a Debian 13 build host is preferred here, but Fedora works — "
               "qubes-builderv2 ships dependency lists for both")
    if x.c["container_engine"] == "podman":
        x.warn("podman selected: upstream states its executor currently cannot build")
        x.warn("  DEB packages, and every custom template in this image is Debian.")
        x.warn("  Use docker unless you have verified otherwise.")

    ce = x.c["container_engine"]
    if not shutil.which(ce):
        raise Fatal(f"{ce} is required for the builder cages")
    if not x.quiet(ce, "ps"):
        raise Fatal(f"cannot talk to {ce} without sudo.\n"
                    f"     sudo usermod -aG {ce} $USER, then log out and back in.\n"
                    "     In an app qube also add /var/lib/docker to bind-dirs.")
    x.ok(f"{ce} usable without sudo")

    payload = Path(__file__).resolve().parent / "golden_image.py"
    if not payload.is_file():
        raise Fatal(f"provisioning payload not found: {payload}\n"
                    "     golden_image.py must sit beside this script — it is what "
                    "gets embedded into the ISO.")
    x.ok(f"provisioning payload found: {payload.name}")
    return payload


# ===========================================================================
#  Builder setup
# ===========================================================================
def setup_builder(x: Ctx):
    x.phase("1", "fetch qubes-builderv2 and build the container image")
    if (x.builder / ".git").is_dir():
        x.skip("qubes-builderv2 cloned")
    else:
        x.run("git", "clone", "https://github.com/QubesOS/qubes-builderv2",
              str(x.builder), live=True)
        x.ok("cloned qubes-builderv2")
    x.run("git", "submodule", "update", "--init", cwd=x.builder)

    x.warn("VERIFY THE BUILDER ITSELF before building a police workstation with it.")
    x.warn("  Check the signature on the checked-out tag against a Qubes developer key")
    x.warn("  you obtained independently. The builder verifies what it fetches;")
    x.warn("  nothing verifies the builder for you.")
    x.verify("signature on the qubes-builderv2 checkout")

    if not x.args.dry_run:
        if shutil.which("dnf"):
            deps = (x.builder / "dependencies-fedora.txt").read_text().split()
            x.run("sudo", "dnf", "install", "-y", *deps, live=True, check=False)
        elif shutil.which("apt-get"):
            deps = (x.builder / "dependencies-debian.txt").read_text().split()
            x.run("sudo", "apt-get", "install", "-y", *deps, live=True, check=False)
        else:
            raise Fatal("no dnf or apt-get — builderv2 supports Fedora or Debian hosts")
    x.ok("builder dependencies installed")

    x.info("building the container image for the build cages (slow, one-off)")
    x.verify(f"mock_config '{x.c['mock_config']}' matches the host distribution of "
             f"{x.c['qubes_release']}")
    x.run("tools/generate-container-image.sh", x.c["container_engine"],
          x.c["mock_config"], cwd=x.builder, live=True, check=False)

    bcfg = x.builder / "builder.yml"
    if not bcfg.exists():
        example = x.builder / "example-configs" / f"qubes-os-{x.c['qubes_release']}.yml"
        if not example.exists():
            avail = sorted(p.name for p in (x.builder / "example-configs").glob("*.yml"))
            raise Fatal(f"no example config for {x.c['qubes_release']}.\n"
                        f"     available: {', '.join(avail)}\n"
                        "     Official release configs: "
                        "https://github.com/QubesOS/qubes-release-configs")
        if not x.args.dry_run:
            shutil.copy(example, bcfg)
        x.ok(f"seeded builder.yml from {example.name}")
    else:
        x.skip("builder.yml present")

    x.info("fetching qubes-release sources (kickstarts and comps live there)")
    x.run("./qb", "-c", "qubes-release", "package", "fetch",
          cwd=x.builder, live=True, check=False)
    x.mark("builder")


# ===========================================================================
#  Discover kickstarts and template names from the real sources
# ===========================================================================
def release_dir(x: Ctx) -> Path:
    return x.builder / "artifacts" / "sources" / "qubes-release"


def list_kickstarts(x: Ctx) -> list[str]:
    d = release_dir(x) / "conf"
    if not d.is_dir():
        x.warn(f"{d} not present — run the builder setup first")
        return []
    return sorted(p.name for p in d.glob("*.ks"))


def comps_template_names(x: Ctx, comps_rel: str) -> tuple[list[str], bool]:
    """Return (template names referenced by comps, has @QUBES_TEMPLATES@ marker)."""
    path = release_dir(x) / comps_rel
    if not path.is_file():
        return [], False
    text = path.read_text()
    marker = "@QUBES_TEMPLATES@" in text
    names: list[str] = []
    for gid in ("fedora", "debian", "whonix"):
        m = re.search(r"<group>\s*<id>" + re.escape(gid) + r"</id>(.*?)</group>",
                      text, re.S)
        if m:
            for pkg in re.findall(r"<packagereq[^>]*>([^<]+)</packagereq>", m.group(1)):
                if pkg.startswith("qubes-template-"):
                    names.append(pkg[len("qubes-template-"):])
    return names, marker


# ===========================================================================
#  Tier 2 — template component + build
# ===========================================================================
HOOK_HEADER = """#!/bin/bash -e
# vim: set ts=4 sw=4 sts=4 et :
#
# Generated by build_iso.py
# Hook: 04_install_qubes.sh step "post" — runs after the Qubes agent packages
# are installed in the chroot. Hook naming and helper functions were read from
# qubes-builderv2 plugins/template/scripts/functions.sh (buildStep) and match
# the upstream qubes-template-kali component.

if [ "${VERBOSE:-0}" -ge 2 ] || [ "${DEBUG:-0}" == "1" ]; then
    set -x
fi

if [ -z "${FLAVORS_DIR}" ]; then
    FLAVORS_DIR="${BUILDER_DIR}/${SRC_DIR}/template-investigator"
fi
[ -n "${SCRIPTSDIR}" ] && TEMPLATE_CONTENT_DIR="${SCRIPTSDIR}"
[ -n "${INSTALLDIR}" ] && INSTALL_DIR="${INSTALLDIR}"

source "${TEMPLATE_CONTENT_DIR}/vars.sh"
source "${TEMPLATE_CONTENT_DIR}/distribution.sh"

exitOnNoFile "${INSTALL_DIR}/${TMPDIR}/.prepared_qubes" "prepared_qubes has not completed!... Exiting"

trap cleanup ERR
trap cleanup EXIT
prepareChroot
mount --bind /dev "${INSTALL_DIR}/dev"
"""

HOOK_FOOTER = """
#### '----------------------------------------------------------------------
info ' Wazuh agent — installed, DISABLED, and version-held'
#### '----------------------------------------------------------------------
# Wazuh guarantee compatibility only when manager version >= agent version.
# These templates get weekly updates once deployed, so an unpinned agent would
# eventually overtake the manager and every agent would stop reporting.
chroot_cmd mkdir -p /usr/share/keyrings
chroot_cmd bash -c "curl -s '@WAZUH_KEY@' | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg"
echo '@WAZUH_REPO@' > "${INSTALL_DIR}/etc/apt/sources.list.d/wazuh.list"
aptUpdate
aptInstall wazuh-agent
chroot_cmd systemctl disable wazuh-agent || true
chroot_cmd bash -c "echo 'wazuh-agent hold' | dpkg --set-selections"
sed -i 's|^deb |#deb |' "${INSTALL_DIR}/etc/apt/sources.list.d/wazuh.list"

#### '----------------------------------------------------------------------
info ' Persist /var/ossec across AppVM reboots'
#### '----------------------------------------------------------------------
# AppVM /var is ephemeral. Without this the agent loses its identity on every
# reboot and re-enrolls as a new agent.
chroot_cmd mkdir -p /etc/qubes-bind-dirs.d
cat > "${INSTALL_DIR}/etc/qubes-bind-dirs.d/50-wazuh.conf" <<'BINDEOF'
binds+=( '/var/ossec' )
BINDEOF

updateLocale
UWT_DEV_PASSTHROUGH="1" DEBIAN_FRONTEND="noninteractive" DEBIAN_PRIORITY="critical" \\
    DEBCONF_NOWARNINGS="yes" chroot_cmd ${eatmydata_maybe} apt-get "${APT_GET_OPTIONS[@]}" autoremove

umount_all "${INSTALL_DIR}/" || true
trap - ERR EXIT
trap
"""


def fetch_kali_key(x: Ctx):
    x.phase("t1", "fetch and verify the Kali archive keyring")
    k = x.c["kali"]
    keydir = x.component / "keys"
    keyfile = keydir / "kali-archive-keyring.gpg"
    if x.args.dry_run:
        x.info(f"[dry-run] fetch {k['keyring_url']} and verify {k['key_fpr']}")
        return
    keydir.mkdir(parents=True, exist_ok=True)
    x.run("curl", "-fsSL", k["keyring_url"], "-o", str(keyfile))
    x.ok("fetched the Kali archive keyring")

    fprs = x.run("gpg", "--no-default-keyring", "--keyring", str(keyfile),
                 "--fingerprint", capture=True, check=False)
    flat = re.sub(r"[\s]", "", fprs).upper()
    if k["key_fpr"].upper() not in flat:
        x.say(fprs)
        raise Fatal(
            f"Kali keyring does NOT contain {k['key_fpr']}.\n"
            "     Stop. Either Kali rolled the key again (check kali.org/blog and\n"
            "     update kali.key_fpr) or this download was tampered with. This key\n"
            "     is about to be baked into an ISO you hand to colleagues — do not\n"
            "     proceed on a guess.")
    x.ok(f"verified Kali 2025 signing key {k['key_fpr']}")
    if k["key_fpr_legacy"].upper() in flat:
        x.ok("legacy Kali key also present")
    else:
        x.warn("legacy key absent — fine if it has aged out")


def gen_component(x: Ctx):
    x.phase("t2", "generate the template component")
    if x.args.dry_run:
        x.info(f"[dry-run] generate component at {x.component} with 4 flavors")
        return
    dist = x.c["dist_codename"]
    comp = x.component
    comp.mkdir(parents=True, exist_ok=True)

    (comp / "Makefile.builder").write_text(
        "ifeq (1,$(TEMPLATE_BUILDER))\n"
        "ifneq (,$(findstring investigator, $(TEMPLATE_FLAVOR)))\n"
        "APPMENUS_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))\n"
        "endif\nendif\n\n# vim: ft=make\n")
    (comp / ".qubesbuilder").write_text("")

    k, z, w = x.c["kali"], x.c["zeek"], x.c["wazuh"]
    # e.g. "4.14" from "4.14.7" — the vendor publishes tooling per series.
    wazuh_series = ".".join(x.c.get("wazuh_version", "4.14.7").split(".")[:2])
    bodies = {
        "investigator-kali": f"""
#### '----------------------------------------------------------------------
info ' Kali repository, key from the component keys/ directory'
#### '----------------------------------------------------------------------
aptInstall apt-transport-https ca-certificates curl gnupg
installQubesRepo

kali_signing_key_file="${{FLAVORS_DIR}}/keys/kali-archive-keyring.gpg"
test -f "$kali_signing_key_file" || error "Kali keyring missing from the component"
cp "$kali_signing_key_file" "${{INSTALL_DIR}}/etc/apt/trusted.gpg.d/kali-archive-keyring.gpg"
echo 'deb [signed-by=/etc/apt/trusted.gpg.d/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware' \\
    > "${{INSTALL_DIR}}/etc/apt/sources.list.d/kali.list"

# grub-pc gets confused by the loop device during the chroot build.
dev=$(df --output=source "${{INSTALL_DIR}}" | tail -n 1); dev=${{dev%p?}}
echo "grub-pc grub-pc/install_devices multiselect $dev" | chroot_cmd debconf-set-selections

aptUpdate
aptDistUpgrade

cat > "${{INSTALL_DIR}}/etc/apt/preferences.d/allow-downgrade" <<'PREFEOF'
Package: *
Pin: release o=Kali
Pin-Priority: 1001
PREFEOF

#### '----------------------------------------------------------------------
info ' Kali toolset and Maltego'
#### '----------------------------------------------------------------------
# kali-linux-default, NOT kali-linux-everything: the latter is enormous and
# would push the ISO past any sensible size.
aptInstall --allow-downgrades kali-menu {k['metapackage']} maltego

uninstallQubesRepo
""",
        "investigator-office": """
#### '----------------------------------------------------------------------
info ' LibreOffice suite and investigator desktop tooling'
#### '----------------------------------------------------------------------
installQubesRepo
aptUpdate
aptInstall libreoffice libreoffice-l10n-de libreoffice-help-de \\
           hunspell-de-ch hyphen-de \\
           thunderbird keepassxc gimp vlc pdfarranger \\
           p7zip-full unzip curl ca-certificates gnupg
uninstallQubesRepo
""",
        "investigator-ids": f"""
#### '----------------------------------------------------------------------
info ' Suricata (Debian main) and Zeek (Zeek project OBS repository)'
#### '----------------------------------------------------------------------
installQubesRepo
aptUpdate
aptInstall suricata suricata-update jq curl gnupg ca-certificates

# Zeek is not in Debian main. Upstream ships via the openSUSE Build Service,
# which signs these packages — that trust is on OBS, not on the Zeek project.
echo '{z['repo_line']}' > "${{INSTALL_DIR}}/etc/apt/sources.list.d/security:zeek.list"
chroot_cmd bash -c "curl -fsSL '{z['key_url']}' | gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg && chmod 644 /etc/apt/trusted.gpg.d/security_zeek.gpg"
aptUpdate
aptInstall {z['package']}
uninstallQubesRepo
""",
        "investigator-proxy": """
#### '----------------------------------------------------------------------
info ' Squid, plus unbound for the DNS enforcement point'
#### '----------------------------------------------------------------------
installQubesRepo
aptUpdate
# squid-openssl supports peek/splice, needed to log TLS SNI without decrypting.
aptInstall squid-openssl ca-certificates openssl unbound || \\
    aptInstall squid ca-certificates openssl unbound
uninstallQubesRepo
""",
        "investigator-wazuh": f"""
#### '----------------------------------------------------------------------
info ' Wazuh single-node stack: indexer + server + dashboard'
#### '----------------------------------------------------------------------
# Baked in so first boot has NOTHING manual left. Packages are installed here;
# certificates and passwords are generated per machine at first boot, because
# they must be unique to each laptop and must never live in a shared template.
installQubesRepo
aptUpdate
aptInstall curl gnupg apt-transport-https ca-certificates lsb-release

chroot_cmd bash -c "curl -s '{w['key_url']}' | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg"
echo '{w['apt_repo_line']}' > "${{INSTALL_DIR}}/etc/apt/sources.list.d/wazuh.list"
aptUpdate

aptInstall wazuh-indexer wazuh-manager wazuh-dashboard

# Never start anything in a template: certificates do not exist yet, and a
# template must not hold per-machine state.
chroot_cmd systemctl disable wazuh-indexer wazuh-manager wazuh-dashboard || true

# Bake the vendor tooling so first boot works with no network at all.
chroot_cmd bash -c "curl -fsSL https://packages.wazuh.com/{wazuh_series}/wazuh-certs-tool.sh -o /opt/wazuh-certs-tool.sh && chmod 755 /opt/wazuh-certs-tool.sh" || \\
    info 'wazuh-certs-tool.sh not fetched — first boot will need network for it'
chroot_cmd bash -c "curl -fsSL https://packages.wazuh.com/{wazuh_series}/wazuh-passwords-tool.sh -o /opt/wazuh-passwords-tool.sh && chmod 755 /opt/wazuh-passwords-tool.sh" || true

# Pin: weekly template updates must not move the manager out from under the
# agents, which are held at the same version.
chroot_cmd bash -c "echo 'wazuh-indexer hold'   | dpkg --set-selections"
chroot_cmd bash -c "echo 'wazuh-manager hold'   | dpkg --set-selections"
chroot_cmd bash -c "echo 'wazuh-dashboard hold' | dpkg --set-selections"
sed -i 's|^deb |#deb |' "${{INSTALL_DIR}}/etc/apt/sources.list.d/wazuh.list"

uninstallQubesRepo
""",
    }
    menus = {
        "investigator-kali": ["kali-msfconsole.desktop", "kali-wireshark.desktop",
                              "kali-zenmap.desktop", "maltego.desktop",
                              "firefox-esr.desktop"],
        "investigator-office": ["libreoffice-startcenter.desktop",
                                "libreoffice-writer.desktop", "libreoffice-calc.desktop",
                                "thunderbird.desktop", "org.keepassxc.KeePassXC.desktop"],
        "investigator-ids": ["debian-xterm.desktop"],
        "investigator-proxy": ["debian-xterm.desktop"],
        "investigator-wazuh": ["debian-xterm.desktop"],
    }

    footer = (HOOK_FOOTER.replace("@WAZUH_KEY@", w["key_url"])
                         .replace("@WAZUH_REPO@", w["apt_repo_line"]))
    for flavor, body in bodies.items():
        d = comp / flavor
        d.mkdir(exist_ok=True)
        hook = d / "04_install_qubes_post.sh"
        hook.write_text(HOOK_HEADER + body + footer)
        hook.chmod(0o755)

        m = comp / f"appmenus_{dist}_{flavor}"
        m.mkdir(exist_ok=True)
        (m / "netvm-whitelisted-appmenus.list").write_text("debian-xterm.desktop\n")
        (m / "vm-whitelisted-appmenus.list").write_text("\n".join(menus[flavor]) + "\n")
        (m / "whitelisted-appmenus.list").write_text("debian-xterm.desktop\n")

    (comp / "README.md").write_text(
        f"# qubes-template-investigator\n\nGenerated {datetime.now():%Y-%m-%d %H:%M:%S}.\n"
        "Flavors: " + ", ".join(bodies) + "\n\n"
        "Structure follows upstream qubes-template-kali: flavor directories with\n"
        "buildStep hook scripts, appmenus lists, and keys/.\n")

    x.ok(f"component generated at {comp}")
    for p in sorted(comp.rglob("*")):
        if p.is_file() and ".git" not in p.parts:
            x.say(f"    {p.relative_to(comp)}")

    if not (comp / ".git").is_dir():
        x.run("git", "init", "-q", cwd=comp)
        x.run("git", "config", "user.email", "builder@investigator.local", cwd=comp)
        x.run("git", "config", "user.name", "Investigator Image Builder", cwd=comp)
    x.run("git", "add", "-A", cwd=comp)
    x.run("git", "commit", "-q", "-m", f"investigator templates {datetime.now():%F %T}",
          cwd=comp, check=False)
    x.ok("local component repo ready")
    x.warn("This component is fetched from a local path with signature checking OFF.")
    x.warn("  Acceptable only because you generated it on your own build host. Before")
    x.warn("  production, move it to your unit's git server, sign the tags, and switch")
    x.warn("  verification-mode back on.")


def build_templates(x: Ctx):
    x.phase("t3", "wire templates into builder.yml and build")
    bcfg = x.builder / "builder.yml"
    if not bcfg.exists():
        raise Fatal("builder.yml not found — run the builder setup first")
    dist = x.c["dist_codename"]
    names = x.c["tier2_templates"]

    # template-root-size and timeout are documented as TOP-LEVEL builder.yml
    # keys. Per-template 'timeout' is not documented, so it is not emitted here.
    block = ["\n# --- investigator-templates BEGIN ---",
             f'template-root-size: "{x.c["template_root_size"]}"',
             f'timeout: {x.c["build_timeout"]}',
             "", "templates:"]
    for n in names:
        block += [f"  - {n}:", f"      dist: {dist}", f"      flavor: {n}"]
    block += ["", "components:", "  - template-investigator:",
              "      packages: False",
              f"      url: file://{x.component}",
              "      verification-mode: insecure-skip-checking",
              "# --- investigator-templates END ---", ""]

    if x.args.dry_run:
        x.info("[dry-run] append templates/components block to builder.yml")
    else:
        shutil.copy(bcfg, bcfg.with_suffix(f".yml.bak.{int(datetime.now().timestamp())}"))
        text = re.sub(r"\n# --- investigator-templates BEGIN ---.*?"
                      r"# --- investigator-templates END ---\n", "\n",
                      bcfg.read_text(), flags=re.S)
        bcfg.write_text(text + "\n".join(block))
        x.ok("builder.yml updated (backup kept)")

    x.warn("templates: and components: now appear more than once in builder.yml.")
    x.warn("  YAML keeps only the LAST occurrence of a duplicate key. If the build")
    x.warn("  reports missing components, merge these into the existing blocks by")
    x.warn("  hand — the script will not silently rewrite arbitrary YAML for you.")
    x.verify("merged templates:/components: blocks (./qb config get-var templates)")

    x.warn("the long one: four templates, each a full debootstrap. Kali dominates.")
    for n in names:
        x.say("")
        x.info(f"building template: {n}")
        x.run("./qb", "-t", n, "template", "all", cwd=x.builder, live=True)
        x.ok(f"{n} built")

    rpmdir = x.builder / "artifacts" / "templates" / "rpm"
    if not x.args.dry_run:
        missing = [n for n in names
                   if not list(rpmdir.glob(f"qubes-template-{n}-*.rpm"))]
        if missing:
            raise Fatal(f"missing template RPMs: {', '.join(missing)}\n"
                        "     Do not build an ISO from a partial set.")
        for n in names:
            rpm = next(iter(rpmdir.glob(f"qubes-template-{n}-*.rpm")))
            x.ok(f"{n:24s} {rpm.stat().st_size // (1024*1024)} MB")
    x.mark("templates")


# ===========================================================================
#  ISO
# ===========================================================================
def write_builder_iso_config(x: Ctx, base_ks: str, iso_tpls: list[str]):
    bcfg = x.builder / "builder.yml"
    ver = f'    version: "{x.c["iso_version"]}"\n' if x.c["iso_version"] else ""
    sign = f'sign-key:\n  iso: {x.c["iso_sign_key"]}\n' if x.c["iso_sign_key"] else ""
    tpl_yaml = "".join(f"      - {t}\n" for t in iso_tpls)
    cache_yaml = "".join(f"      - {t}\n" for t in x.c["cache_templates"])

    block = f"""
# --- investigator-iso BEGIN ---
# Appended by build_iso.py. Edit above this marker, not inside it.
iso:
    kickstart: ./investigator.ks
    comps: {x.c['comps_file']}
    flavor: {x.c['iso_flavor']}
{ver}    is-final: false
    use-kernel-latest: true
    templates:
{tpl_yaml}
cache:
    templates:
{cache_yaml}
{sign}# --- investigator-iso END ---
"""
    if x.args.dry_run:
        x.info("[dry-run] append iso: block to builder.yml")
        return
    text = re.sub(r"\n# --- investigator-iso BEGIN ---.*?# --- investigator-iso END ---\n",
                  "\n", bcfg.read_text(), flags=re.S)
    bcfg.write_text(text + block)
    x.ok("builder.yml iso: block written")


def write_kickstart(x: Ctx, base_ks: str, payload: Path, extra_packages: list[str]):
    x.phase("2", "generate the custom kickstart")
    ks = x.builder / "investigator.ks"
    if x.args.dry_run:
        x.info(f"[dry-run] write {ks} (%include conf/{base_ks} + %post payload)")
        return
    b64 = base64.b64encode(payload.read_bytes()).decode()
    b64 = "\n".join(b64[i:i + 76] for i in range(0, len(b64), 76))

    pkgs = ""
    if extra_packages:
        pkgs = ("\n# Custom templates. comps-dom0.xml on this branch has no\n"
                "# @QUBES_TEMPLATES@ marker, so a comps group will not pick these up —\n"
                "# they are named explicitly here. The RPMs reach the ISO via\n"
                "# iso: templates: in builder.yml.\n%packages\n"
                + "\n".join(f"qubes-template-{p}" for p in extra_packages)
                + "\n%end\n")

    autoline = ("systemctl enable golden-image-firstboot.service"
                if x.c["auto_provision"]
                else "# auto_provision disabled — operator runs it manually")

    ks.write_text(f"""\
# =============================================================================
#  investigator.ks — {x.c['iso_name']}
#  Generated by build_iso.py on {datetime.now():%Y-%m-%d %H:%M:%S}
#  Includes the stock Qubes kickstart unchanged, then plants the golden-image
#  provisioning payload into dom0.
# =============================================================================

%include conf/{base_ks}
{pkgs}
%post --log=/root/investigator-ks-post.log
set -x

# --- provisioning payload -----------------------------------------------
cat > /usr/local/sbin/golden_image.py.b64 <<'PAYLOAD_B64_EOF'
{b64}
PAYLOAD_B64_EOF
base64 -d /usr/local/sbin/golden_image.py.b64 > /usr/local/sbin/golden_image.py
rm -f /usr/local/sbin/golden_image.py.b64
chmod 755 /usr/local/sbin/golden_image.py

cat > /usr/local/sbin/golden-image-provision <<'WRAP_EOF'
#!/bin/bash
# Provision this machine into the investigator golden image.
# Safe to re-run: completed phases are skipped.
exec /usr/bin/python3 /usr/local/sbin/golden_image.py "$@"
WRAP_EOF
chmod 755 /usr/local/sbin/golden-image-provision

# --- first-boot service --------------------------------------------------
cat > /etc/systemd/system/golden-image-firstboot.service <<'SVC_EOF'
[Unit]
Description=Golden image first-boot provisioning
After=multi-user.target
ConditionPathExists=!/var/lib/golden-image/provisioned

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/golden-image-firstboot
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
SVC_EOF

cat > /usr/local/sbin/golden-image-firstboot <<'FB_EOF'
#!/bin/bash
# Guarded first-boot runner. Waits until Qubes initial setup has produced the
# default qubes, because provisioning re-templates and re-wires them.
set -u
MARKER=/var/lib/golden-image/provisioned
mkdir -p /var/lib/golden-image
[ -e "$MARKER" ] && exit 0

for i in $(seq 1 60); do
    if qvm-check --quiet sys-net 2>/dev/null && qvm-check --quiet sys-firewall 2>/dev/null; then
        break
    fi
    sleep 30
done

if ! qvm-check --quiet sys-net 2>/dev/null; then
    logger -t golden-image "initial setup incomplete after 30 min; not provisioning"
    mkdir -p /etc/motd.d
    echo "Golden image provisioning deferred. Run: sudo golden-image-provision" \\
        > /etc/motd.d/golden-image
    exit 0
fi

logger -t golden-image "starting provisioning"
/usr/local/sbin/golden-image-provision >> /var/log/golden-image-firstboot.log 2>&1
rc=$?
if [ $rc -eq 0 ]; then
    touch "$MARKER"
    logger -t golden-image "provisioning finished"
else
    logger -t golden-image "provisioning failed rc=$rc; resume: sudo golden-image-provision"
fi
exit 0
FB_EOF
chmod 755 /usr/local/sbin/golden-image-firstboot

{autoline}

mkdir -p /etc/motd.d
cat > /etc/motd.d/golden-image <<'MOTD_EOF'

  QubesOS Cybercrime Investigator image
  -------------------------------------
    sudo golden-image-provision --dry-run    # see the plan
    sudo golden-image-provision              # run or resume
    sudo golden-image-provision --verify     # acceptance tests

  Credentials are written to ~/golden-image/credentials.json (mode 600).
  Change them, escrow them, then shred that file.

MOTD_EOF

%end
""")
    ks.chmod(0o644)
    x.ok(f"wrote {ks}")
    x.info(f"%include conf/{base_ks}")
    if extra_packages:
        x.info(f"%packages adds: {', '.join('qubes-template-'+p for p in extra_packages)}")
        x.verify("pykickstart merges multiple %packages sections rather than letting "
                 "one override the other. This is standard Anaconda behaviour but was "
                 "not confirmed against a Qubes-specific source — after the build, "
                 "mount the ISO and check the templates appear in the package set, or "
                 "install once in a VM and run 'qvm-ls | grep investigator'.")
    x.info(f"auto-provision on first boot: {x.c['auto_provision']}")
    x.verify("the first-boot service fires after Qubes initial setup on your hardware "
             "(the runner polls for sys-net rather than trusting unit order)")
    x.warn("the ISO embeds the provisioning script. It contains NO secrets: credentials")
    x.warn("  are generated on the target machine, never baked into the image.")


def build_iso(x: Ctx, payload: Path):
    tier2 = int(x.c["tier"]) == 2

    x.phase("2a", "resolve kickstart and template names from the real sources")
    ks_list = list_kickstarts(x)
    if not ks_list:
        raise Fatal("no kickstarts found. Run the builder setup (it fetches "
                    "qubes-release), then retry.")
    x.info("kickstarts available in qubes-release/conf:")
    for k in ks_list:
        x.say(f"    {k}")

    base_ks = x.c["base_kickstart"]
    if not base_ks:
        pref = [k for k in ks_list if "online" in k and "testing" not in k
                and "no-templates" not in k]
        base_ks = pref[0] if pref else ks_list[0]
    if base_ks not in ks_list:
        raise Fatal(f"base_kickstart '{base_ks}' is not in qubes-release/conf.\n"
                    f"     available: {', '.join(ks_list)}")
    x.ok(f"base kickstart: {base_ks}")

    derived, marker = comps_template_names(x, x.c["comps_file"])
    if derived:
        x.ok(f"templates referenced by {x.c['comps_file']}: {', '.join(derived)}")
    else:
        x.warn(f"could not read template names from {x.c['comps_file']}")
    x.info(f"@QUBES_TEMPLATES@ marker in comps: "
           f"{'PRESENT' if marker else 'ABSENT'}")

    iso_tpls = list(x.c["iso_templates"]) or derived
    if not iso_tpls:
        raise Fatal("no ISO templates resolved. Set iso_templates in iso-build.json.")

    extra: list[str] = []
    if tier2:
        rpmdir = x.builder / "artifacts" / "templates" / "rpm"
        missing = [n for n in x.c["tier2_templates"]
                   if not list(rpmdir.glob(f"qubes-template-{n}-*.rpm"))]
        if missing and not x.args.dry_run:
            raise Fatal(f"tier=2 but these templates are not built: {', '.join(missing)}\n"
                        "     Run:  ./build_iso.py templates\n"
                        "     Baking a partial set produces an ISO that installs a "
                        "broken workstation.")
        iso_tpls = iso_tpls + list(x.c["tier2_templates"])
        if marker:
            x.ok("comps has the marker — the installer will render groups for the "
                 "custom templates")
        else:
            extra = list(x.c["tier2_templates"])
            x.warn("comps has NO @QUBES_TEMPLATES@ marker on this branch, so a comps")
            x.warn("  group cannot pull in the custom templates. They are added to")
            x.warn("  %packages in the kickstart instead. iso: templates: still gets")
            x.warn("  their RPMs into the ISO repository.")
    x.info(f"tier {x.c['tier']}; ISO installs: {', '.join(iso_tpls)}")

    x.phase("2b", "builder.yml iso: block")
    write_builder_iso_config(x, base_ks, iso_tpls)
    if not x.c["iso_sign_key"]:
        x.warn("iso_sign_key is empty — the ISO will be UNSIGNED")

    write_kickstart(x, base_ks, payload, extra)

    x.phase("3", "build the ISO")
    x.warn("expect hours, heavy disk and CPU. The builder downloads Anaconda and")
    x.warn("  Lorax packages, then creates the ISO offline inside a Mock chroot.")
    x.run("./qb", "installer", "init-cache", "all", cwd=x.builder, live=True)
    x.ok("builder finished")

    x.phase("4", "name, checksum, sign, report")
    if x.args.dry_run:
        x.info("[dry-run] locate ISO, copy, checksum, sign")
        return

    arts = x.builder / "artifacts"
    cands = sorted(arts.rglob(f"Qubes-*{x.c['iso_flavor']}*.iso")) or \
            sorted(arts.rglob("Qubes-*.iso"))
    if not cands:
        raise Fatal("no ISO found under artifacts/ — the build produced no image")
    built = cands[0]
    x.info(f"built image: {built}")

    target = x.out_dir / x.c["iso_name"]
    shutil.copy2(built, target)
    x.ok(f"-> {target}")

    import hashlib
    h = hashlib.sha256()
    with target.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    digest = h.hexdigest()
    (x.out_dir / f"{x.c['iso_name']}.sha256").write_text(f"{digest}  {x.c['iso_name']}\n")
    x.ok(f"checksum: {digest[:32]}…")

    signed = "NO — do not distribute"
    if x.c["iso_sign_key"]:
        x.export_pubkey()
        if x.quiet("gpg", "--local-user", x.c["iso_sign_key"], "--detach-sign",
                   "--armor", "--output", str(x.out_dir / f"{x.c['iso_name']}.asc"),
                   str(target)):
            x.ok(f"signed: {x.c['iso_name']}.asc")
            signed = f"yes, key {x.c['iso_sign_key']}"
        else:
            x.warn("signing failed — do not distribute an unsigned image")
    else:
        x.warn("UNSIGNED. Set iso_sign_key and re-run to sign before distributing.")

    size_gb = target.stat().st_size / (1024 ** 3)
    (x.out_dir / "BUILD-RECORD.txt").write_text(f"""\
{x.c['iso_name']}
built:            {datetime.now():%Y-%m-%d %H:%M:%S}
host:             {os.uname().nodename}
qubes release:    {x.c['qubes_release']}
base kickstart:   {base_ks}
comps:            {x.c['comps_file']}
tier:             {x.c['tier']}
templates:        {' '.join(iso_tpls)}
auto-provision:   {x.c['auto_provision']}
size:             {size_gb:.1f} GB
sha256:           {digest}
signed:           {signed}

EXPIRY: rebuild when a Qubes Security Bulletin affects dom0, Xen or the kernel.
An investigator ISO older than its dom0 patch level is not fit to install.

Verify before installing:
  sha256sum -c {x.c['iso_name']}.sha256
  gpg --verify {x.c['iso_name']}.asc {x.c['iso_name']}
""")
    x.ok("build record written")

    print(f"\n{B}{C}\u2550\u2550 Done{RST}")
    print(f"""
  ISO        {target}   ({size_gb:.1f} GB)
  Checksum   {x.c['iso_name']}.sha256
  Signature  {signed}
  Record     BUILD-RECORD.txt
  Log        {x.log}

  Write to USB:
    sudo dd if={target} of=/dev/sdX bs=4M status=progress oflag=direct

  On the target: boot, install, reboot, complete Qubes initial setup.
  Provisioning then runs automatically and can be watched with:
    journalctl -t golden-image -f

  Test the whole path on a spare machine before issuing any laptop.
""")
    if x.verify_notes:
        print(f"  {Y}Items flagged [VERIFY] this run:{RST}")
        for n in dict.fromkeys(x.verify_notes):
            print(f"    - {n}")
        print()


# ===========================================================================
def deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        out[k] = deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def load_config(write_only=False) -> dict:
    if CONF_PATH.exists():
        if write_only:
            print(f"iso-build.json already exists — not overwriting: {CONF_PATH}",
                  file=sys.stderr)
            sys.exit(1)
        return deep_merge(DEFAULT_CONFIG, json.loads(CONF_PATH.read_text()))
    CONF_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2) + "\n")
    if write_only:
        print(f"Wrote {CONF_PATH}")
        print("Review and edit it, then run:  ./build_iso.py --dry-run iso")
        sys.exit(0)
    print(f"  {Y}!{RST} no iso-build.json found — wrote embedded defaults to {CONF_PATH}\n")
    return dict(DEFAULT_CONFIG)


def main() -> int:
    p = argparse.ArgumentParser(description="InQubestigationOS — build custom templates and a bootable ISO")
    p.add_argument("action", nargs="?", default="iso",
                   choices=["iso", "templates", "all", "list-kickstarts"],
                   help="what to do (default: iso)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--force", action="store_true", help="skip the warning prompt")
    p.add_argument("--write-config", action="store_true")
    args = p.parse_args()

    try:
        cfg = load_config(write_only=args.write_config)
        x = Ctx(cfg, args)
        tier2 = int(cfg["tier"]) == 2

        print(f"\n{B}{C}{cfg['iso_name']}{RST}")
        if args.dry_run:
            print(f"{Y}DRY RUN — nothing will be changed{RST}")
        x.say(f"work dir: {x.work}")
        x.say(f"log:      {x.log}")

        if args.action == "list-kickstarts":
            for k in list_kickstarts(x):
                print(f"  {k}")
            names, marker = comps_template_names(x, cfg["comps_file"])
            print(f"\n  comps templates: {', '.join(names) or '(none found)'}")
            print(f"  @QUBES_TEMPLATES@ marker: {'PRESENT' if marker else 'ABSENT'}")
            return 0

        payload = preflight(x, tier2)
        if not x.done("builder") or args.dry_run:
            setup_builder(x)
        else:
            x.skip("builder setup")

        if args.action in ("templates", "all"):
            if not tier2:
                x.warn("tier is 1 — building templates anyway, but set tier=2 in "
                       "iso-build.json to bake them into the ISO")
            fetch_kali_key(x)
            gen_component(x)
            build_templates(x)
            if args.action == "templates":
                print(f"\n  Next: set \"tier\": 2 in {CONF_PATH}, then "
                      "./build_iso.py iso\n")
                return 0

        if args.action in ("iso", "all"):
            build_iso(x, payload)
    except Fatal as e:
        print(f"\n{R}FATAL:{RST} {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
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
