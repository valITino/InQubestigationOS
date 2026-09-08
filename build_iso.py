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
    # "auto" derives the chroot from the fetched builder's example config for
    # this Qubes release, so nobody has to keep the two in step by hand. Pin an
    # explicit "fedora-NN-x86_64" only to override that.
    "mock_config": "auto",
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
        "repo_line": "deb [signed-by=/usr/share/keyrings/security_zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/Debian_13/ /",
        "key_url": "https://download.opensuse.org/repositories/security:zeek/Debian_13/Release.key",
        # zeek-8.0 in the OBS repository is frozen at 8.0.1-0; the 8.0 LTS line
        # is published as zeek-lts (8.0.10-0 today).
        "package": "zeek-lts",
    },
    "wazuh": {
        # Kept in step with golden_image.py's wazuh.version by tests/doc_checks.py;
        # 'check-upstream' compares it against the current upstream release.
        "version": "4.14.7",
        "key_url": "https://packages.wazuh.com/key/GPG-KEY-WAZUH",
        # Wazuh.com (Wazuh Signing Key) <support@wazuh.com>, rsa4096.
        "key_fpr": "0DCFCA5547B19D2A6099506096B3EE5F29111145",
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
        # "--dry-run: nothing will be changed" has to include the work tree and
        # the log, or the very first documented invocation contradicts its own
        # banner. The same goes for the read-only actions: doctor is what a
        # reviewer runs first, and it is advertised as changing nothing.
        readonly = getattr(args, "action", "") in ("doctor", "config",
                                                   "list-kickstarts")
        self.logging = not args.dry_run and not readonly
        if self.logging:
            self.work.mkdir(parents=True, exist_ok=True)
            self.out_dir.mkdir(parents=True, exist_ok=True)
            self.log.touch(exist_ok=True)
        self.verify_notes: list[str] = []

    # --- output --------------------------------------------------------
    def _log(self, s):
        if not self.logging:
            return
        try:
            with self.log.open("a") as f:
                f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {s}\n")
        except OSError:
            pass

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
            lf = self.log.open("a") if self.logging else None
            try:
                for line in p.stdout:
                    sys.stdout.write(line)
                    if lf:
                        lf.write(line)
            finally:
                if lf:
                    lf.close()
            p.wait()
            if check and p.returncode != 0:
                raise Fatal(f"failed: {' '.join(cmd)} — see {self.log}")
            return ""
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL)
        self._log(f"      rc={p.returncode}\n{p.stdout[-4000:]}{p.stderr[-4000:]}")
        if check and p.returncode != 0:
            raise Fatal(f"failed: {' '.join(cmd)} — see {self.log}")
        return p.stdout if capture else ""

    def quiet(self, *argv) -> bool:
        try:
            return subprocess.run([str(a) for a in argv], capture_output=True,
                                  stdin=subprocess.DEVNULL,
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
        out.unlink(missing_ok=True)
        if self.quiet("gpg", "--batch", "--yes", "--armor", "--output", str(out),
                      "--export", fp):
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

    if not getattr(x.args, "assume_yes", False) and not x.args.dry_run:
        if not sys.stdin.isatty():
            raise Fatal("no terminal to acknowledge the warnings on.\n"
                        "     For an unattended build pass --yes, which records the "
                        "acknowledgement\n     in the build log instead of asking.")
        if input("  Type UNDERSTOOD to continue: ").strip() != "UNDERSTOOD":
            raise Fatal("aborted at the warnings (use --yes to skip)")
    elif not x.args.dry_run:
        x._log("ACK   warnings acknowledged non-interactively (--yes/--force)")

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
                    f"     Fix it in one step:  ./build_iso.py setup-host\n"
                    f"     (adds you to the {ce} group, enables the service, and in "
                    f"an app qube\n      persists /var/lib/docker through bind-dirs)")
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
    branch = x.c["builder_branch"]
    if (x.builder / ".git").is_dir():
        x.skip("qubes-builderv2 cloned")
        # builder_branch was a documented setting nothing ever read: the clone
        # took the default branch whatever it said, so pinning the builder to
        # the release you are building silently did nothing.
        x.run("git", "-C", str(x.builder), "fetch", "origin", branch,
              check=False, live=True)
        x.run("git", "-C", str(x.builder), "checkout", branch, check=False, live=True)
    else:
        x.run("git", "clone", "--branch", branch,
              "https://github.com/QubesOS/qubes-builderv2", str(x.builder), live=True)
        x.ok(f"cloned qubes-builderv2 @ {branch}")
    on = x.run("git", "-C", str(x.builder), "rev-parse", "--abbrev-ref", "HEAD",
               check=False, capture=True).strip()
    if on and on != branch:
        x.warn(f"qubes-builderv2 is on '{on}', not the configured '{branch}' — "
               f"the builder and the release you are building may disagree")
    else:
        x.ok(f"qubes-builderv2 on {branch}")
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
        x.info("builder dependencies installed (failures above are not fatal — the "
               "container image build below is the real test)")

    x.info("building the container image for the build cages (slow, one-off)")
    resolve_auto_values(x)
    # check=True: without the container image nothing downstream can build, and
    # marking the phase done anyway meant every later run skipped the setup and
    # failed somewhere far less obvious.
    x.run("tools/generate-container-image.sh", x.c["container_engine"],
          x.c["mock_config"], cwd=x.builder, live=True)

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
    if not x.args.dry_run:
        conf = release_dir(x) / "conf"
        if not conf.is_dir():
            raise Fatal(f"qubes-release sources are not present at {conf}.\n"
                        "     The kickstarts and comps files live there and the ISO\n"
                        "     build cannot proceed without them. Re-run; if the fetch\n"
                        f"     keeps failing, check {x.log}.")
        x.ok(f"qubes-release sources at {conf}")
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
    # SRC_DIR already resolves to this component's source directory — keys/ and
    # the flavor directories live directly under it. Appending the component
    # name again named a directory that is never created, so the Kali keyring
    # the build had just downloaded and verified could not be found.
    FLAVORS_DIR="${BUILDER_DIR}/${SRC_DIR}"
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
chroot_cmd bash -c "curl -fsSL '@WAZUH_KEY@' | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg"
# Pin it, exactly as the Kali key is pinned. This key signs every package in the
# SIEM that watches the whole workstation; importing whatever came back from the
# network and trusting it via signed-by= is not a check.
chroot_cmd bash -c "gpg --no-default-keyring --keyring /usr/share/keyrings/wazuh.gpg --with-colons --fingerprint | awk -F: '\\$1==\\"fpr\\"{print toupper(\\$10)}' | grep -qxF '@WAZUH_KEY_FPR@'" \\
    || error 'Wazuh signing key is not @WAZUH_KEY_FPR@ — refusing to bake an unverified key into the image'
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

    # Exact comparison against the machine-readable key list. The previous
    # check flattened `gpg --fingerprint`'s human-readable output — uid lines
    # and all — and looked for the fingerprint as a substring, so a key whose
    # UID simply contained those 40 characters satisfied it. The only input to
    # this check is the file that was just downloaded.
    found = _gpg_scan(keyfile.read_bytes())
    fprs = {key["fpr"].upper() for key in found}
    if not fprs:
        raise Fatal(f"gpg found no keys in {keyfile} — the download is not a "
                    "keyring. Do not proceed.")
    if k["key_fpr"].upper() not in fprs:
        for key in found:
            x.say(f"    {key['fpr']}  {key['uid']}")
        raise Fatal(
            f"Kali keyring does NOT contain {k['key_fpr']}.\n"
            "     Stop. Either Kali rolled the key again (check kali.org/blog and\n"
            "     update kali.key_fpr) or this download was tampered with. This key\n"
            "     is about to be baked into an ISO you hand to colleagues — do not\n"
            "     proceed on a guess.")
    x.ok(f"verified Kali 2025 signing key {k['key_fpr']}")
    if k["key_fpr_legacy"].upper() in fprs:
        x.ok("legacy Kali key also present")
    else:
        x.warn("legacy key absent — fine if it has aged out")
    unexpected = fprs - {k["key_fpr"].upper(), k["key_fpr_legacy"].upper()}
    if unexpected:
        x.warn(f"keyring also carries {', '.join(sorted(unexpected))} — confirm at "
               "kali.org before baking this into an image")


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
    # Derived from wazuh.version, which IS a documented config key and which
    # 'check-upstream' compares against the repository. The old code read a
    # "wazuh_version" key that appeared in no DEFAULT_CONFIG, so --write-config
    # never emitted it and the series was hard-coded in practice.
    wazuh_series = ".".join(str(x.c["wazuh"]["version"]).split(".")[:2])
    bodies = {
        "investigator-kali": f"""
#### '----------------------------------------------------------------------
info ' Kali repository, key from the component keys/ directory'
#### '----------------------------------------------------------------------
aptInstall apt-transport-https ca-certificates curl gnupg
installQubesRepo

kali_signing_key_file="${{FLAVORS_DIR}}/keys/kali-archive-keyring.gpg"
test -f "$kali_signing_key_file" || error "Kali keyring missing from the component"
# /usr/share/keyrings, NOT /etc/apt/trusted.gpg.d: a key in trusted.gpg.d is a
# GLOBAL anchor and apt will accept any repository signed by it, which defeats
# the signed-by= scoping on the very next line.
mkdir -p "${{INSTALL_DIR}}/usr/share/keyrings"
cp "$kali_signing_key_file" "${{INSTALL_DIR}}/usr/share/keyrings/kali-archive-keyring.gpg"
chmod 644 "${{INSTALL_DIR}}/usr/share/keyrings/kali-archive-keyring.gpg"
echo 'deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] https://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware' \\
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
# Scoped to the Zeek repository via signed-by= on the line above, not dropped
# into /etc/apt/trusted.gpg.d where it would vouch for every repository. The
# openSUSE Build Service is outside the Zeek project's control.
chroot_cmd mkdir -p /usr/share/keyrings
chroot_cmd bash -c "curl -fsSL '{z['key_url']}' | gpg --dearmor > /usr/share/keyrings/security_zeek.gpg && chmod 644 /usr/share/keyrings/security_zeek.gpg"
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
# Fatal, not a note: Tier 2's whole promise is that the target installs and
# provisions with no network. Without this script phase 8 cannot generate the
# per-machine certificates, the indexer never starts, and the failure surfaces
# on the investigator's laptop instead of here on the build host.
chroot_cmd bash -c "curl -fsSL https://packages.wazuh.com/{wazuh_series}/wazuh-certs-tool.sh -o /opt/wazuh-certs-tool.sh && chmod 755 /opt/wazuh-certs-tool.sh" || \\
    error 'wazuh-certs-tool.sh could not be fetched — a Tier 2 image without it needs network at first boot'
chroot_cmd bash -c "curl -fsSL https://packages.wazuh.com/{wazuh_series}/wazuh-passwords-tool.sh -o /opt/wazuh-passwords-tool.sh && chmod 755 /opt/wazuh-passwords-tool.sh" || \\
    error 'wazuh-passwords-tool.sh could not be fetched — without it the dashboard admin password cannot be set from credentials.json'

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
                         .replace("@WAZUH_KEY_FPR@", w["key_fpr"])
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



# ---------------------------------------------------------------------------
#  builder.yml — merged, not appended
#
#  The old code appended a second `templates:` / `components:` / `sign-key:`
#  mapping and then WARNED that YAML keeps only the last occurrence, telling
#  the operator to merge them by hand. That is not a warning, it is a bug with
#  a note attached: the effective component list became one entry, the rpm and
#  deb signing keys silently vanished, and the build either failed obscurely or
#  produced unsigned packages inside a signed ISO.
# ---------------------------------------------------------------------------
def _entry_key(item):
    """Name of a builder.yml list entry, whether it is a string or a mapping."""
    if isinstance(item, str):
        return item
    if isinstance(item, dict) and len(item) == 1:
        return next(iter(item))
    return None


def _merge(base, over):
    """Deep-merge `over` into `base`, replacing list entries by their name."""
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for k, v in over.items():
            out[k] = _merge(out[k], v) if k in out else v
        return out
    if isinstance(base, list) and isinstance(over, list):
        out = list(base)
        for item in over:
            name = _entry_key(item)
            for i, existing in enumerate(out):
                if name is not None and _entry_key(existing) == name:
                    out[i] = item
                    break
            else:
                out.append(item)
        return out
    return over


def merge_builder_config(x: Ctx, updates: dict, what: str) -> None:
    bcfg = x.builder / "builder.yml"
    if x.args.dry_run:
        x.info(f"[dry-run] merge {what} into builder.yml: "
               f"{', '.join(sorted(updates))}")
        return
    if not bcfg.exists():
        raise Fatal("builder.yml not found — run the builder setup first")
    try:
        import yaml
    except ImportError:
        raise Fatal(
            "python3-yaml is needed to edit builder.yml safely.\n"
            "     Appending raw text would create duplicate top-level keys, and\n"
            "     YAML keeps only the last one — that silently drops the upstream\n"
            "     component list and the rpm/deb signing keys.\n"
            "     Install it:  ./build_iso.py setup-host")

    backup = bcfg.with_name(f"builder.yml.bak.{int(datetime.now().timestamp())}")
    shutil.copy2(bcfg, backup)
    try:
        current = yaml.safe_load(bcfg.read_text()) or {}
    except yaml.YAMLError as e:
        raise Fatal(f"builder.yml is not valid YAML: {e}")
    if not isinstance(current, dict):
        raise Fatal("builder.yml does not parse as a mapping")

    merged = _merge(current, updates)
    bcfg.write_text(
        f"# Merged by build_iso.py on {datetime.now():%Y-%m-%d %H:%M:%S} ({what}).\n"
        f"# Previous contents: {backup.name}\n"
        + yaml.safe_dump(merged, sort_keys=False, default_flow_style=False))
    x.ok(f"builder.yml: {what} merged (backup {backup.name})")

    # Automates the [VERIFY] this step used to print: ask the builder what it
    # actually sees rather than asking the operator to go and check.
    seen = x.run("./qb", "config", "get-var", "templates", cwd=x.builder,
                 check=False, capture=True)
    if seen.strip():
        missing = [n for n in updates.get("templates", [])
                   if _entry_key(n) and _entry_key(n) not in seen]
        if missing:
            raise Fatal(f"builder.yml merged but 'qb config get-var templates' "
                        f"does not list {', '.join(str(m) for m in missing)}.\n"
                        f"     Restored copy: {backup}")
        x.ok("verified with 'qb config get-var templates'")
    else:
        x.warn("'qb config get-var templates' returned nothing — could not verify "
               "the merge automatically")


def missing_template_rpms(x: Ctx) -> list[str]:
    rpmdir = x.builder / "artifacts" / "templates" / "rpm"
    return [n for n in x.c["tier2_templates"]
            if not list(rpmdir.glob(f"qubes-template-{n}-*.rpm"))]


def build_templates(x: Ctx):
    x.phase("t3", "wire templates into builder.yml and build")
    bcfg = x.builder / "builder.yml"
    if not bcfg.exists():
        raise Fatal("builder.yml not found — run the builder setup first")
    dist = x.c["dist_codename"]
    names = x.c["tier2_templates"]

    # template-root-size and timeout are documented as TOP-LEVEL builder.yml
    # keys. Per-template 'timeout' is not documented, so it is not emitted here.
    merge_builder_config(x, {
        "template-root-size": x.c["template_root_size"],
        "timeout": x.c["build_timeout"],
        "templates": [{n: {"dist": dist, "flavor": n}} for n in names],
        "components": [{"template-investigator": {
            "packages": False,
            "url": f"file://{x.component}",
            "verification-mode": "insecure-skip-checking",
        }}],
    }, "investigator templates")

    x.warn(f"the long one: {len(names)} templates, each a full debootstrap. "
           f"Kali dominates.")
    for n in names:
        x.say("")
        x.info(f"building template: {n}")
        x.run("./qb", "-t", n, "template", "all", cwd=x.builder, live=True)
        x.ok(f"{n} built")

    rpmdir = x.builder / "artifacts" / "templates" / "rpm"
    if not x.args.dry_run:
        missing = missing_template_rpms(x)
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
def write_builder_iso_config(x: Ctx, base_ks: str, iso_tpls: list[str], kickstart: str):
    iso: dict = {
        "kickstart": kickstart,
        "comps": x.c["comps_file"],
        "flavor": x.c["iso_flavor"],
        "is-final": False,
        "use-kernel-latest": True,
        "templates": list(iso_tpls),
    }
    if x.c["iso_version"]:
        iso["version"] = str(x.c["iso_version"])
    updates: dict = {"iso": iso}
    # Only when there is something to cache: an empty 'cache: {templates: []}'
    # would replace whatever the upstream example config put there.
    if x.c["cache_templates"]:
        updates["cache"] = {"templates": list(x.c["cache_templates"])}
    if x.c["iso_sign_key"]:
        # Merged into the existing sign-key mapping, which also carries the rpm
        # and deb fingerprints. Replacing it wholesale left the packages inside
        # a signed ISO unsigned.
        updates["sign-key"] = {"iso": x.c["iso_sign_key"]}
    merge_builder_config(x, updates, "iso block")


def write_kickstart(x: Ctx, base_ks: str, payload: Path,
                    extra_packages: list[str]) -> str:
    """Write investigator.ks and return the path to put in builder.yml.

    It goes into qubes-release/conf/ beside the kickstart it includes. %include
    resolves relative to the including file, so a kickstart written to the
    builder root could never find `conf/<base>` — that directory only exists
    inside the qubes-release source tree.
    """
    x.phase("2", "generate the custom kickstart")
    conf = release_dir(x) / "conf"
    ks = conf / "investigator.ks"
    rel = "conf/investigator.ks"
    if x.args.dry_run:
        x.info(f"[dry-run] write {ks} (%include {base_ks} + %post payload)")
        return rel
    if not conf.is_dir():
        raise Fatal(f"{conf} does not exist — the qubes-release sources are not "
                    "fetched. Run the builder setup first.")
    if not (conf / base_ks).is_file():
        raise Fatal(f"base kickstart {base_ks} is not in {conf}")
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

%include {base_ks}
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

  {x.c['iso_flavor']}
  {'-' * len(x.c['iso_flavor'])}
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
    x.info(f"%include {base_ks}  (resolved from {conf})")
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
    return rel


def build_iso(x: Ctx, payload: Path):
    tier2 = int(x.c["tier"]) == 2
    build_started = datetime.now().timestamp()

    x.phase("2a", "resolve kickstart and template names from the real sources")
    ks_list = list_kickstarts(x)
    if not ks_list:
        if x.args.dry_run:
            # Let the plan be printed on a host that has not fetched anything
            # yet — that is the documented first command in the guide.
            x.warn("qubes-release sources are not fetched yet; planning against "
                   "the release4.3 names recorded in this script's docstring")
            ks_list = ["iso-online.ks", "iso-online-testing.ks",
                       "iso-online-testing-no-templates.ks", "iso-unsigned.ks"]
        else:
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
        missing = missing_template_rpms(x)
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

    if not x.c["iso_sign_key"]:
        x.warn("iso_sign_key is empty — the ISO will be UNSIGNED")
        x.warn('  ./build_iso.py gen-key --uid "Your Unit <you@example.org>"')

    kickstart_rel = write_kickstart(x, base_ks, payload, extra)
    x.phase("2b", "builder.yml iso: block")
    write_builder_iso_config(x, base_ks, iso_tpls, kickstart_rel)

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
    # artifacts/ accumulates across runs and this phase is resume-friendly, so
    # the alphabetically first match is frequently a previous build. Take the
    # newest, and refuse anything older than this run.
    if len(cands) > 1:
        x.warn(f"{len(cands)} images under artifacts/:")
        for c in cands:
            x.say(f"      {c}  ({datetime.fromtimestamp(c.stat().st_mtime):%F %T})")
    built = max(cands, key=lambda c: c.stat().st_mtime)
    if built.stat().st_mtime < build_started:
        raise Fatal(
            f"the newest image under artifacts/ ({built.name}, "
            f"{datetime.fromtimestamp(built.stat().st_mtime):%F %T}) predates this "
            f"run.\n     The build produced no new image. Shipping the old one as "
            f"the new one is exactly\n     the mistake this check exists to stop.")
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
        sig = x.out_dir / f"{x.c['iso_name']}.asc"
        # Not quiet(): that has a 180 s timeout, and gpg has to hash an image
        # this script's own warnings describe as "tens of GB". A signing run
        # that timed out was swallowed into "signing failed", the build still
        # exited 0, and BUILD-RECORD.txt was the only place that said so.
        # --batch --yes so a re-run overwrites the previous signature instead
        # of stopping on a prompt nobody is there to answer.
        sig.unlink(missing_ok=True)
        x.info("signing the image (gpg hashes the whole file — expect minutes)")
        try:
            x.run("gpg", "--batch", "--yes", "--local-user", x.c["iso_sign_key"],
                  "--detach-sign", "--armor", "--output", str(sig), str(target),
                  live=True)
            x.ok(f"signed: {sig.name}")
            signed = f"yes, key {x.c['iso_sign_key']}"
        except Fatal as e:
            raise Fatal(f"signing failed: {e}\n"
                        f"     The image is at {target} but is NOT signed. Do not "
                        f"distribute it.\n     Sign it on the machine holding the "
                        f"key, or fix the key and re-run './build_iso.py iso'.")
    else:
        x.warn("UNSIGNED. Set iso_sign_key and re-run to sign before distributing.")
        x.warn("  ./build_iso.py gen-key --use-key auto   (or --uid \"...\")")

    # Everything a colleague needs to check the image, in one command, beside
    # the image. GUIDE section 7 used to be three commands typed from memory.
    write_verify_script(x, digest)
    if x.c["iso_sign_key"]:
        write_fingerprint_sheet(x, x.c["iso_sign_key"])

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

  Verify (hand this to colleagues along with the image):
    ./verify-iso.sh

  Write to USB — checks the checksum and signature first, refuses a
  non-removable target, and reads the stick back to prove the write landed:
    ./build_iso.py write-usb --device /dev/sdX

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
#  Automation — everything docs/GUIDE.md used to ask a human to do by hand
#
#  Sections 1-4 of the guide were a checklist: install Docker, join its group,
#  make a signing key, hand-edit JSON, keep a "still unverified" list in your
#  head. A checklist that has to be followed identically on every build host is
#  a script that has not been written yet. These are those scripts.
# ===========================================================================
OK, WARN, FAIL = "ok", "warn", "fail"


class Check:
    """One thing that must be true before a multi-hour build starts."""

    def __init__(self, name: str, state: str, detail: str = "", fix: str = ""):
        self.name, self.state, self.detail, self.fix = name, state, detail, fix


def _print_checks(x: Ctx, checks: list[Check]) -> int:
    sym = {OK: (G, "✓"), WARN: (Y, "!"), FAIL: (R, "✗")}
    for c in checks:
        col, mark = sym[c.state]
        line = f"  {col}{mark}{RST} {c.name}"
        if c.detail:
            line += f"  {D}{c.detail}{RST}"
        print(line)
        x._log(f"{c.state.upper():5} {c.name} {c.detail}")
        if c.state != OK and c.fix:
            print(f"      {D}fix: {c.fix}{RST}")
    bad = [c for c in checks if c.state == FAIL]
    warns = [c for c in checks if c.state == WARN]
    print(f"\n  {G}{len(checks) - len(bad) - len(warns)} ok{RST}   "
          f"{Y}{len(warns)} warnings{RST}   {R}{len(bad)} blocking{RST}")
    return 1 if bad else 0


def host_family() -> str:
    if shutil.which("apt-get"):
        return "debian"
    if shutil.which("dnf"):
        return "fedora"
    return "unknown"


def in_qube() -> bool:
    return Path("/usr/share/qubes/marker-vm").exists()


def _sudo(argv: list[str]) -> list[str]:
    return argv if os.geteuid() == 0 else ["sudo", *argv]


def _free_gb(path: Path) -> int | None:
    try:
        st = os.statvfs(path)
        return st.f_bavail * st.f_frsize // (1024 ** 3)
    except OSError:
        return None


def secret_key_fingerprints() -> list[tuple[str, str]]:
    """(fingerprint, uid) for every secret key in the build host's keyring."""
    try:
        p = subprocess.run(["gpg", "--list-secret-keys", "--with-colons"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return []
    out, fpr = [], None
    for line in p.stdout.splitlines():
        f = line.split(":")
        if f[0] == "fpr" and fpr is None:
            fpr = f[9]
        elif f[0] == "uid" and fpr:
            out.append((fpr, f[9]))
            fpr = None
        elif f[0] == "sec":
            fpr = None
    return out


# ---------------------------------------------------------------------------
#  doctor — read-only readiness report
# ---------------------------------------------------------------------------
def doctor(x: Ctx) -> int:
    x.phase("doctor", "is this build host ready?")
    c: list[Check] = []
    ce = x.c["container_engine"]
    tier2 = int(x.c["tier"]) == 2

    if Path("/etc/qubes-release").exists() and not in_qube():
        c.append(Check("not running in dom0", FAIL,
                       "dom0 has no network and must not build images",
                       "run this on a separate Debian 13 or Fedora host"))
    else:
        c.append(Check("not running in dom0", OK))

    fam = host_family()
    c.append(Check("supported build host", OK if fam != "unknown" else FAIL, fam,
                   "qubes-builderv2 ships dependency lists for Debian and Fedora only"))

    for tool in ("git", "curl", "gpg", "rsync"):
        c.append(Check(f"{tool} installed", OK if shutil.which(tool) else FAIL,
                       fix=f"./build_iso.py setup-host"))

    if not shutil.which(ce):
        c.append(Check(f"{ce} installed", FAIL, fix="./build_iso.py setup-host"))
    else:
        c.append(Check(f"{ce} installed", OK))
        if x.quiet(ce, "ps"):
            c.append(Check(f"{ce} usable without sudo", OK))
        else:
            in_group = ce in subprocess.run(["id", "-nG"], capture_output=True,
                                            text=True).stdout.split()
            c.append(Check(f"{ce} usable without sudo", FAIL,
                           "group membership not active in this shell" if in_group
                           else "not a member of the group",
                           "./build_iso.py setup-host  (it re-execs through "
                           "'sg' so you do not have to log out)"))
    if ce == "podman":
        c.append(Check("container engine builds DEB packages", WARN,
                       "upstream states the podman executor cannot",
                       './build_iso.py --set container_engine=docker'))

    # doctor changes nothing, so it measures the nearest existing ancestor
    # rather than creating the work tree to look at it.
    probe = x.work
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    free = _free_gb(probe)
    c.append(Check(f"work_dir {x.work}",
                   OK if os.access(probe, os.W_OK) else FAIL,
                   "exists" if x.work.exists() else f"will be created under {probe}",
                   "./build_iso.py --set work_dir=/path/you/can/write"))
    need = 250 if tier2 else 100
    if free is not None:
        c.append(Check(f"disk at {probe}", OK if free >= need else FAIL,
                       f"{free}G free, {need}G needed for tier {x.c['tier']}",
                       "./build_iso.py --set work_dir=/path/with/space"))

    try:
        kb = int(next(l for l in Path("/proc/meminfo").read_text().splitlines()
                      if l.startswith("MemTotal")).split()[1])
        gb = kb // 1024 // 1024
        c.append(Check("RAM", OK if gb >= 8 else WARN, f"{gb}G",
                       "builds can OOM below 8G"))
    except (OSError, StopIteration, ValueError):
        pass

    fp = (x.c.get("iso_sign_key") or "").strip()
    if not fp:
        c.append(Check("ISO signing key configured", FAIL, "iso_sign_key is empty",
                       './build_iso.py gen-key --uid "Your Unit <you@example.org>"'
                       "   (or --use-key auto)"))
    elif "BEGIN PGP" in fp or "PRIVATE KEY" in fp:
        c.append(Check("ISO signing key configured", FAIL,
                       "PRIVATE KEY MATERIAL is pasted into iso-build.json",
                       "treat that key as compromised: revoke it, generate a new "
                       "one, and store only the fingerprint"))
    elif not re.fullmatch(r"[0-9A-F]{40}", fp.replace(" ", "").upper()):
        c.append(Check("ISO signing key configured", FAIL,
                       "not a 40-hex fingerprint",
                       "./build_iso.py gen-key --use-key <fingerprint>"))
    else:
        clean = fp.replace(" ", "").upper()
        have = x.quiet("gpg", "--list-secret-keys", clean)
        c.append(Check("signing key present in the local keyring",
                       OK if have else FAIL, clean,
                       "import it here, or build unsigned and sign on the machine "
                       "that holds it"))
        if have:
            exp = key_expiry(clean)
            if exp is not None:
                days = exp
                c.append(Check("signing key not about to expire",
                               OK if days > 90 else WARN, f"{days} days left",
                               "renew before the next build cycle"))

    if in_qube():
        conf = Path("/rw/config/qubes-bind-dirs.d/50_docker.conf")
        c.append(Check("Docker storage persists across reboots (app qube)",
                       OK if conf.exists() else FAIL,
                       "this is a Qubes app qube",
                       "./build_iso.py setup-host  (writes the bind-dirs entry)"))

    try:
        import yaml                                          # noqa: F401
        c.append(Check("python3-yaml present (builder.yml is merged, not appended)",
                       OK))
    except ImportError:
        c.append(Check("python3-yaml present (builder.yml is merged, not appended)",
                       FAIL, "missing", "./build_iso.py setup-host"))

    payload = Path(__file__).resolve().parent / "golden_image.py"
    c.append(Check("provisioning payload beside this script",
                   OK if payload.is_file() else FAIL, payload.name,
                   "golden_image.py is base64-embedded into the ISO"))

    unknown = unknown_config_keys(x.c)
    c.append(Check("no unknown keys in iso-build.json",
                   OK if not unknown else WARN, ", ".join(sorted(unknown)),
                   "a misspelled key is silently ignored — remove or correct it"))

    rc = _print_checks(x, c)
    if rc == 0:
        print(f"\n  Ready. Next:  ./build_iso.py --dry-run all\n")
    else:
        print(f"\n  Run  ./build_iso.py setup-host  to fix what can be fixed "
              f"automatically.\n")
    return rc


def key_expiry(fpr: str) -> int | None:
    """Days until the signing key expires, or None if it does not."""
    try:
        p = subprocess.run(["gpg", "--list-keys", "--with-colons", fpr],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in p.stdout.splitlines():
        f = line.split(":")
        if f[0] == "pub" and len(f) > 6 and f[6]:
            try:
                return int((int(f[6]) - datetime.now().timestamp()) // 86400)
            except ValueError:
                return None
    return None


# ---------------------------------------------------------------------------
#  setup-host — GUIDE section 2, performed instead of described
# ---------------------------------------------------------------------------
# python3-yaml is not optional: builder.yml is merged rather than appended, and
# without it this script refuses to edit builder.yml at all.
DEB_PACKAGES = ["docker.io", "git", "curl", "gnupg", "rsync", "python3",
                "python3-yaml"]
RPM_PACKAGES = ["docker", "git", "curl", "gnupg2", "rsync", "python3",
                "python3-pyyaml"]


def setup_host(x: Ctx) -> int:
    x.phase("setup-host", "install and configure the build host")
    fam = host_family()
    if fam == "unknown":
        raise Fatal("unsupported host: need apt-get (Debian/Ubuntu) or dnf (Fedora)")
    ce = x.c["container_engine"]
    plan: list[list[str]] = []

    pkgs = DEB_PACKAGES if fam == "debian" else RPM_PACKAGES
    missing_tools = [t for t in ("git", "curl", "gpg", "rsync", ce)
                     if not shutil.which(t)]
    if missing_tools:
        if fam == "debian":
            plan.append(_sudo(["apt-get", "update"]))
            plan.append(_sudo(["apt-get", "install", "-y", *pkgs]))
        else:
            plan.append(_sudo(["dnf", "install", "-y", *pkgs]))

    if ce == "docker":
        plan.append(_sudo(["systemctl", "enable", "--now", "docker"]))
        user = os.environ.get("SUDO_USER") or os.environ.get("USER") or ""
        groups = subprocess.run(["id", "-nG"], capture_output=True, text=True).stdout.split()
        if user and "docker" not in groups:
            plan.append(_sudo(["usermod", "-aG", "docker", user]))

    if in_qube():
        plan.append(["__bind_dirs__"])

    plan.append(["__mkdir__", str(x.work)])

    if not plan:
        x.ok("nothing to do — the host is already set up")
        return doctor(x)

    print("\n  This will run:")
    for cmd in plan:
        if cmd[0] == "__bind_dirs__":
            print("      write /rw/config/qubes-bind-dirs.d/50_docker.conf "
                  "(persist /var/lib/docker across reboots)")
        elif cmd[0] == "__mkdir__":
            print(f"      mkdir -p {cmd[1]}")
        else:
            print("      " + " ".join(shlex.quote(a) for a in cmd))
    print()
    if x.args.dry_run:
        x.info("[dry-run] nothing executed")
        return 0
    if not confirmed(x, "Proceed?"):
        raise Fatal("aborted")

    for cmd in plan:
        if cmd[0] == "__mkdir__":
            Path(cmd[1]).mkdir(parents=True, exist_ok=True)
            x.ok(f"created {cmd[1]}")
        elif cmd[0] == "__bind_dirs__":
            setup_qube_bind_dirs(x)
        else:
            x.run(*cmd, live=True)
            x.ok(" ".join(cmd[:3]))

    # Group membership does not apply to an already-running shell. Rather than
    # telling the operator to log out and back in, verify through 'sg' so the
    # very next command in this session works.
    if ce == "docker" and not x.quiet("docker", "ps"):
        if shutil.which("sg") and x.quiet("sg", "docker", "-c", "docker ps"):
            x.ok("docker works via the docker group")
            x.info("Your CURRENT shell predates the group change. Either open a new")
            x.info("  shell, or prefix the build with:  sg docker -c './build_iso.py all'")
        else:
            x.warn("docker still needs sudo — log out and back in, then re-run "
                   "./build_iso.py doctor")

    print()
    return doctor(x)


def setup_qube_bind_dirs(x: Ctx) -> None:
    """In a Qubes app qube, /var/lib/docker is lost on every reboot unless it
    is bind-mounted from the persistent volume."""
    conf = Path("/rw/config/qubes-bind-dirs.d/50_docker.conf")
    try:
        conf.parent.mkdir(parents=True, exist_ok=True)
        conf.write_text("binds+=( '/var/lib/docker' )\n")
        seed = Path("/rw/bind-dirs/var/lib/docker")
        if not seed.exists():
            seed.mkdir(parents=True, exist_ok=True)
        x.ok(f"wrote {conf} and seeded {seed}")
        x.info("bind-dirs copies the existing directory on first use; seeding it "
               "explicitly avoids the copy failing silently")
    except OSError as e:
        x.warn(f"could not configure bind-dirs ({e}) — run as root inside the qube")


def confirmed(x: Ctx, question: str) -> bool:
    if getattr(x.args, "assume_yes", False):
        return True
    if not sys.stdin.isatty():
        raise Fatal(f"{question} — no terminal to ask on. Re-run with --yes.")
    return input(f"  {question} [y/N] ").strip().lower() in ("y", "yes")


# ---------------------------------------------------------------------------
#  gen-key — GUIDE section 3, performed instead of described
# ---------------------------------------------------------------------------
def gen_key(x: Ctx) -> int:
    x.phase("gen-key", "ISO signing key")
    have = secret_key_fingerprints()

    sel = getattr(x.args, "use_key", None)
    if sel:
        if sel == "auto":
            if not have:
                raise Fatal("no secret key in this keyring to select.\n"
                            '     Create one:  ./build_iso.py gen-key --uid "Unit <you@example.org>"')
            if len({f for f, _ in have}) > 1:
                x.warn("more than one secret key in this keyring:")
                for f, uid in have:
                    x.say(f"      {f}  {uid}")
                raise Fatal("--use-key auto needs exactly one. Pass the fingerprint.")
            fpr = have[0][0]
        else:
            fpr = sel.replace(" ", "").upper()
            if not re.fullmatch(r"[0-9A-F]{40}", fpr):
                raise Fatal(f"'{sel}' is not a 40-hex-character fingerprint")
            if not x.quiet("gpg", "--list-secret-keys", fpr):
                raise Fatal(f"no SECRET key for {fpr} in this keyring")
        return _adopt_key(x, fpr)

    uid = getattr(x.args, "uid", None)
    if not uid:
        raise Fatal('gen-key needs an identity:\n'
                    '     ./build_iso.py gen-key --uid "Kapo Cyber Image Signing <cyber@example.ch>"\n'
                    '     or adopt a key already in this keyring:\n'
                    '     ./build_iso.py gen-key --use-key auto')

    for fpr, existing in have:
        if uid.lower() in existing.lower():
            x.warn(f"a secret key for this identity already exists: {fpr}")
            if not confirmed(x, "Create a SECOND key anyway?"):
                return _adopt_key(x, fpr)

    expire = getattr(x.args, "expire", None) or "3y"
    nopass = getattr(x.args, "no_passphrase", False)
    x.info(f"identity: {uid}")
    x.info(f"algorithm: rsa4096, usage: sign, expires in {expire}")
    x.info("An image-signing key should outlive a build cycle but not the team.")
    if nopass:
        x.warn("--no-passphrase: the private key will sit UNPROTECTED on this host.")
        x.warn("  Anyone who can read the keyring can sign an image your unit trusts.")
        x.warn("  Acceptable for a throwaway lab build; never for an issued laptop.")
    else:
        x.info("gpg will ask for a passphrase — it protects the key at rest.")
    if x.args.dry_run:
        x.info("[dry-run] gpg --quick-generate-key ...")
        return 0
    if not confirmed(x, "Generate this key now?"):
        raise Fatal("aborted")

    before = {f for f, _ in secret_key_fingerprints()}
    if nopass:
        x.run("gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
              "--passphrase", "", "--quick-generate-key", uid,
              "rsa4096", "sign", expire, live=True)
    else:
        if not sys.stdin.isatty():
            raise Fatal("generating a passphrase-protected key needs a terminal.\n"
                        "     Run this in an interactive shell, or accept an\n"
                        "     unprotected key with --no-passphrase.")
        # pinentry needs the real terminal, so stdio is inherited rather than
        # captured. Nothing here belongs in the build log anyway.
        rc = subprocess.run(["gpg", "--quick-generate-key", uid,
                             "rsa4096", "sign", expire]).returncode
        if rc != 0:
            raise Fatal(f"gpg exited {rc} — no key was generated")
    after = [(f, u) for f, u in secret_key_fingerprints() if f not in before]
    if not after:
        raise Fatal("gpg reported success but no new secret key appeared")
    fpr = after[0][0]
    x.ok(f"generated {fpr}")
    return _adopt_key(x, fpr)


def _adopt_key(x: Ctx, fpr: str) -> int:
    """Record the fingerprint in iso-build.json so nobody has to edit JSON."""
    config_set(x, "iso_sign_key", fpr, quiet=True)
    x.ok(f"iso_sign_key set to {fpr} in {CONF_PATH.name}")
    days = key_expiry(fpr)
    if days is not None:
        x.info(f"expires in {days} days")
    pub = x.out_dir / "unit-signing-key.asc"
    if not x.args.dry_run and x.quiet("gpg", "--armor", "--output", str(pub),
                                      "--yes", "--export", fpr):
        x.ok(f"public key exported: {pub}")
    write_fingerprint_sheet(x, fpr)
    print()
    x.warn("Distribute this fingerprint through a channel INDEPENDENT of the ISO.")
    x.warn("  A public key shipped on the same USB stick as the image it signs")
    x.warn("  proves nothing. FINGERPRINT.txt is formatted to be read aloud.")
    return 0


def write_fingerprint_sheet(x: Ctx, fpr: str) -> None:
    """The one step that genuinely cannot be automated is reading the
    fingerprint out over an independent channel. Make that step trivial."""
    if x.args.dry_run:
        return
    # Two rows of five groups — the layout gpg --fingerprint prints, so the
    # reader can compare them character for character.
    g = [fpr[i:i + 4] for i in range(0, 40, 4)]
    row1, row2 = " ".join(g[:5]), " ".join(g[5:])
    uids = [u for f, u in secret_key_fingerprints() if f == fpr]
    sheet = x.out_dir / "FINGERPRINT.txt"
    sheet.write_text(f"""\
{x.c['iso_flavor']} — image signing key
{'=' * 60}

Identity   {uids[0] if uids else '(unknown)'}
Fingerprint

    {row1}
    {row2}

Read this out over the phone, publish it on an internal page colleagues
already trust, or hand it over on paper. Do NOT send it on the same channel
as the ISO: anyone who can replace the image can replace a key beside it.

To verify an image against this key:

    gpg --import unit-signing-key.asc
    gpg --fingerprint {fpr}      # must match the two lines above
    sha256sum -c {x.c['iso_name']}.sha256
    gpg --verify {x.c['iso_name']}.asc {x.c['iso_name']}

Or run the script shipped beside the ISO:  ./verify-iso.sh
""")
    x.ok(f"fingerprint sheet written: {sheet}")


# ---------------------------------------------------------------------------
#  config get/set — GUIDE section 4, without $EDITOR
# ---------------------------------------------------------------------------
def _flat_keys(d: dict, prefix: str = "") -> set[str]:
    out = set()
    for k, v in d.items():
        out.add(prefix + k)
        if isinstance(v, dict):
            out |= _flat_keys(v, prefix + k + ".")
    return out


def unknown_config_keys(cfg: dict) -> set[str]:
    """Keys the user set that the script never reads. A silently ignored
    setting is worse than an error: it looks configured."""
    if not CONF_PATH.exists():
        return set()
    try:
        user = json.loads(CONF_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return set()
    return _flat_keys(user) - _flat_keys(DEFAULT_CONFIG)


def config_get(x: Ctx, dotted: str) -> int:
    node = x.c
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            raise Fatal(f"no such config key: {dotted}")
        node = node[part]
    print(json.dumps(node, indent=2) if isinstance(node, (dict, list)) else node)
    return 0


def config_set(x: Ctx, dotted: str, raw: str, quiet: bool = False) -> int:
    if dotted not in _flat_keys(DEFAULT_CONFIG):
        near = [k for k in sorted(_flat_keys(DEFAULT_CONFIG))
                if dotted.split(".")[-1] in k]
        raise Fatal(f"'{dotted}' is not a configuration key."
                    + (f"\n     did you mean: {', '.join(near[:5])}" if near else ""))
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        value = raw

    stored: dict = {}
    if CONF_PATH.exists():
        try:
            stored = json.loads(CONF_PATH.read_text())
        except json.JSONDecodeError as e:
            raise Fatal(f"{CONF_PATH.name} is not valid JSON: {e}")
    node = stored
    parts = dotted.split(".")
    for part in parts[:-1]:
        node = node.setdefault(part, {})
        if not isinstance(node, dict):
            raise Fatal(f"cannot set {dotted}: {part} is not a section")
    node[parts[-1]] = value

    if x.args.dry_run:
        x.info(f"[dry-run] {dotted} = {value!r}")
        return 0
    CONF_PATH.write_text(json.dumps(stored, indent=2) + "\n")
    x.c = deep_merge(DEFAULT_CONFIG, stored)
    if not quiet:
        x.ok(f"{dotted} = {value!r}   ({CONF_PATH.name})")
    return 0


def resolve_auto_values(x: Ctx) -> None:
    """Derive the settings the guide used to make the operator match by hand."""
    if str(x.c.get("mock_config", "")).lower() in ("", "auto"):
        rel = str(x.c["qubes_release"]).lstrip("rR")
        # The Mock chroot must match the HOST distribution of the Qubes release,
        # which is the Fedora dom0 is built on. Read it from the fetched builder
        # rather than guessing; fall back to the release's known host.
        derived = mock_config_from_builder(x) or {"4.3": "fedora-41-x86_64",
                                                  "4.2": "fedora-37-x86_64"}.get(rel)
        if not derived:
            raise Fatal(f"cannot derive mock_config for Qubes {rel}. "
                        f'Set it explicitly:  ./build_iso.py --set mock_config=fedora-NN-x86_64')
        x.c["mock_config"] = derived
        x.info(f"mock_config derived as {derived}")


def mock_config_from_builder(x: Ctx) -> str | None:
    """qubes-builderv2 ships example configs naming the right Mock chroot."""
    for name in (f"example-configs/qubes-os-{x.c['qubes_release']}.yml",
                 "example-configs/qubes-os-master.yml"):
        p = x.builder / name
        if not p.is_file():
            continue
        m = re.search(r"fedora-\d+-x86_64", p.read_text())
        if m:
            return m.group(0)
    return None


# ---------------------------------------------------------------------------
#  check-upstream — the monthly checklist in GUIDE section 12, automated
#
#  docs/VERIFICATION.md asks a human to re-verify three signing keys and one
#  version number "before each image version bump", and GUIDE.md adds "monthly,
#  check the Zeek OBS key has not expired". Nobody does that reliably. This
#  does it, records what it saw in supply-chain.lock.json, and exits non-zero
#  when anything moved — so it can run from CI on a schedule instead.
# ---------------------------------------------------------------------------
LOCK_PATH = Path(__file__).resolve().parent / "supply-chain.lock.json"
# Primary sources, deliberately not the GitHub API: no token, no rate limit,
# and each one is the artefact the image actually consumes rather than a
# release announcement about it.
QSB_INDEX = "https://www.qubes-os.org/security/qsb/"
QSB_RAW = "https://raw.githubusercontent.com/QubesOS/qubes-secpack/master/QSBs/{name}"
WAZUH_PACKAGES = ("https://packages.wazuh.com/4.x/apt/dists/stable/main/"
                  "binary-amd64/Packages")


def _fetch(url: str, timeout: int = 45) -> bytes:
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "InQubestigationOS/check-upstream"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _gpg_scan(blob: bytes) -> list[dict]:
    """Fingerprint, uid and expiry of every key in a keyring or armoured key."""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".gpg", delete=False) as fh:
        fh.write(blob)
        path = fh.name
    try:
        p = subprocess.run(["gpg", "--show-keys", "--with-colons", path],
                           capture_output=True, text=True, timeout=60)
    finally:
        os.unlink(path)
    keys: list[dict] = []
    for line in p.stdout.splitlines():
        f = line.split(":")
        if f[0] == "pub":
            keys.append({"expires": f[6] if len(f) > 6 else "", "fpr": "", "uid": ""})
        elif f[0] == "fpr" and keys and not keys[-1]["fpr"]:
            keys[-1]["fpr"] = f[9]
        elif f[0] == "uid" and keys and not keys[-1]["uid"]:
            keys[-1]["uid"] = f[9]
    return keys


def _vkey(v: str) -> tuple:
    """Sortable key for a dotted version string."""
    return tuple(int(p) if p.isdigit() else 0 for p in v.split("."))


def _days_left(epoch: str) -> int | None:
    if not epoch:
        return None
    try:
        return int((int(epoch) - datetime.now().timestamp()) // 86400)
    except ValueError:
        return None


def check_upstream(x: Ctx) -> int:
    x.phase("check-upstream", "are the pinned keys and versions still current?")
    update = getattr(x.args, "update", False)
    lock: dict = {}
    if LOCK_PATH.exists():
        try:
            lock = json.loads(LOCK_PATH.read_text())
        except json.JSONDecodeError:
            x.warn(f"{LOCK_PATH.name} is not valid JSON — treating as empty")
    seen: dict = {"checked": f"{datetime.now():%Y-%m-%d}"}
    c: list[Check] = []

    # --- Kali ---------------------------------------------------------
    k = x.c["kali"]
    try:
        blob = _fetch(k["keyring_url"])
        import hashlib
        sha1 = hashlib.sha1(blob).hexdigest()
        keys = _gpg_scan(blob)
        fprs = [key["fpr"] for key in keys]
        seen["kali"] = {"key_fpr": k["key_fpr"], "fingerprints": fprs,
                        "keyring_sha1": sha1,
                        "expiries": {key["fpr"]: _days_left(key["expires"]) for key in keys}}
        c.append(Check("Kali: pinned signing key is in the published keyring",
                       OK if k["key_fpr"] in fprs else FAIL,
                       k["key_fpr"],
                       "confirm the new fingerprint at kali.org/blog, then "
                       "./build_iso.py --set kali.key_fpr=<new>"))
        days = next((_days_left(key["expires"]) for key in keys
                     if key["fpr"] == k["key_fpr"]), None)
        if days is not None:
            c.append(Check("Kali: signing key not expiring soon",
                           OK if days > 180 else (WARN if days > 0 else FAIL),
                           f"{days} days left"))
        old_sha1 = lock.get("kali", {}).get("keyring_sha1")
        c.append(Check("Kali: keyring file unchanged since the last check",
                       OK if old_sha1 in (None, sha1) else WARN,
                       f"sha1 {sha1}",
                       "the fingerprint is authoritative; a changed file with a "
                       "matching fingerprint just means it was regenerated"))
        extra = [f for f in fprs if f not in (k["key_fpr"], k["key_fpr_legacy"])]
        c.append(Check("Kali: keyring holds no unexpected key",
                       OK if not extra else WARN, ", ".join(extra)))
    except Exception as e:                                   # noqa: BLE001
        c.append(Check("Kali: keyring reachable", WARN, f"{type(e).__name__}: {e}",
                       "network check skipped — re-run where the build host has "
                       "outbound HTTPS"))

    # --- Zeek ---------------------------------------------------------
    z = x.c["zeek"]
    try:
        blob = _fetch(z["key_url"])
        keys = _gpg_scan(blob)
        seen["zeek"] = {"fingerprints": [key["fpr"] for key in keys],
                        "expiries": {key["fpr"]: _days_left(key["expires"]) for key in keys}}
        recorded = lock.get("zeek", {}).get("fingerprints")
        if recorded is None:
            c.append(Check("Zeek: OBS key fingerprint recorded for the first time",
                           WARN, ", ".join(seen["zeek"]["fingerprints"]),
                           "re-run with --update to pin it, then compare on every "
                           "later build"))
        else:
            c.append(Check("Zeek: OBS key unchanged since the last check",
                           OK if recorded == seen["zeek"]["fingerprints"] else FAIL,
                           ", ".join(seen["zeek"]["fingerprints"]),
                           "the openSUSE Build Service rotated the key — confirm "
                           "at docs.zeek.org before accepting it"))
        for key in keys:
            days = _days_left(key["expires"])
            if days is None:
                continue
            # Zeek's own docs warn that on Debian you must re-add the key by
            # hand when it expires; an expired key silently stops DPI updates.
            c.append(Check(f"Zeek: OBS key {key['fpr'][-8:]} not expiring",
                           OK if days > 60 else (WARN if days > 0 else FAIL),
                           f"{days} days left",
                           "re-add the key in tpl-ids before it expires or the "
                           "DPI recorder quietly stops receiving updates"))
    except Exception as e:                                   # noqa: BLE001
        c.append(Check("Zeek: OBS key reachable", WARN, f"{type(e).__name__}: {e}"))

    # --- Wazuh --------------------------------------------------------
    #  Read the apt index this image actually installs from, not a release
    #  announcement: what matters is the version the templates would receive.
    try:
        index = _fetch(WAZUH_PACKAGES).decode("utf-8", "replace")
        versions = []
        pkg = None
        for line in index.splitlines():
            if line.startswith("Package: "):
                pkg = line.split(" ", 1)[1].strip()
            elif line.startswith("Version: ") and pkg == "wazuh-agent":
                versions.append(line.split(" ", 1)[1].strip().split("-")[0])
        latest = max(versions, key=_vkey) if versions else ""
        pinned = x.c["wazuh"]["version"]
        seen["wazuh"] = {"latest": latest, "pinned": pinned}
        c.append(Check("Wazuh: pinned version is what the repository now offers",
                       OK if latest == pinned else WARN,
                       f"pinned {pinned}, repository {latest or 'unknown'}",
                       "upgrade wazuh-srv FIRST, then release the template holds "
                       "and upgrade the agents:  sudo golden-image-provision "
                       "--upgrade-wazuh"))
        if latest and _vkey(latest) < _vkey(pinned):
            c.append(Check("Wazuh: pinned version exists upstream", FAIL,
                           f"{pinned} is newer than anything in the repository",
                           "the agents would never install"))
    except Exception as e:                                   # noqa: BLE001
        c.append(Check("Wazuh: package index reachable", WARN, f"{type(e).__name__}: {e}"))

    # --- Wazuh signing key --------------------------------------------
    try:
        wk = x.c["wazuh"].get("key_fpr", "")
        keys = _gpg_scan(_fetch(x.c["wazuh"]["key_url"]))
        fprs = [key["fpr"] for key in keys]
        seen["wazuh_key"] = {"fingerprints": fprs, "pinned": wk,
                             "expiries": {key["fpr"]: _days_left(key["expires"])
                                          for key in keys}}
        c.append(Check("Wazuh: pinned signing key is the published key",
                       OK if wk and wk in fprs else FAIL,
                       ", ".join(fprs),
                       "confirm at documentation.wazuh.com, then "
                       "./build_iso.py --set wazuh.key_fpr=<new>"))
        for key in keys:
            days = _days_left(key["expires"])
            if days is not None:
                c.append(Check(f"Wazuh: signing key {key['fpr'][-8:]} not expiring",
                               OK if days > 90 else (WARN if days > 0 else FAIL),
                               f"{days} days left"))
    except Exception as e:                                   # noqa: BLE001
        c.append(Check("Wazuh: signing key reachable", WARN, f"{type(e).__name__}: {e}"))

    # --- Qubes security bulletins ------------------------------------
    #  "Rebuild on every QSB affecting dom0 or Xen" was a line in a table that
    #  assumed somebody was reading the mailing list.
    try:
        page = _fetch(QSB_INDEX).decode("utf-8", "replace")
        qsbs = sorted(set(re.findall(r"qsb-\d{3}-\d{4}\.txt", page)))
        seen["qsb"] = {"latest": qsbs[-1] if qsbs else "", "count": len(qsbs)}
        known = lock.get("qsb", {}).get("latest")
        fresh = [q for q in qsbs if known and q > known]
        if not known:
            c.append(Check("Qubes: security bulletin baseline recorded", WARN,
                           f"latest is {seen['qsb']['latest']}",
                           "re-run with --update to pin it; later runs then report "
                           "only what is new"))
        elif not fresh:
            c.append(Check("Qubes: no new security bulletin since the last build",
                           OK, f"latest {seen['qsb']['latest']}"))
        else:
            # Classify them, because only dom0/Xen/kernel bulletins force a
            # rebuild and reading eleven advisories by hand is how that step
            # stops happening.
            hits = []
            for q in fresh:
                try:
                    body = _fetch(QSB_RAW.format(name=q), timeout=30).decode(
                        "utf-8", "replace").lower()
                except Exception:                            # noqa: BLE001
                    hits.append(f"{q}(unread)")
                    continue
                if any(w in body for w in ("dom0", "xen", "hypervisor", "kernel")):
                    hits.append(q)
            c.append(Check("Qubes: no new bulletin affects dom0, Xen or the kernel",
                           OK if not hits else FAIL,
                           (f"{len(fresh)} new; affecting this image: "
                            f"{', '.join(hits)}" if hits
                            else f"{len(fresh)} new, none touching dom0/Xen"),
                           "rebuild the templates and re-cut the ISO — an image "
                           "older than its dom0 patch level installs known-"
                           "vulnerable dom0 before its first update"))
    except Exception as e:                                   # noqa: BLE001
        c.append(Check("Qubes: security bulletin index reachable", WARN,
                       f"{type(e).__name__}: {e}"))

    rc = _print_checks(x, c)

    if update and not x.args.dry_run:
        merged = deep_merge(lock, seen)
        LOCK_PATH.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n")
        x.ok(f"recorded in {LOCK_PATH.name} — commit it so the next check has a "
             f"baseline")
        # The verdict stands. Zeroing it here meant a scheduled CI run with
        # --update could never fail on a rotated key or a dom0 security
        # bulletin, which is the entire reason this command exists.
        if rc:
            x.warn("baseline recorded, but the blocking findings above still "
                   "stand — this exits non-zero on purpose")
    elif not update:
        x.info("re-run with --update to record what was seen as the new baseline")
    return rc


# ---------------------------------------------------------------------------
#  distribution bundle — GUIDE section 7, so colleagues run one command
# ---------------------------------------------------------------------------
def write_verify_script(x: Ctx, digest: str) -> None:
    fp = x.c.get("iso_sign_key") or ""
    script = x.out_dir / "verify-iso.sh"
    script.write_text(f"""\
#!/bin/sh
# Verify {x.c['iso_name']} before installing it.
#
# This checks the image against the unit signing key. It CANNOT tell you the
# key itself is genuine — compare the fingerprint below against the one you
# were given through a channel independent of this USB stick.
set -eu
cd "$(dirname "$0")"

ISO={shlex.quote(x.c['iso_name'])}
FPR={shlex.quote(fp)}

printf '  checksum ... '
sha256sum -c "$ISO.sha256" >/dev/null
printf 'ok\\n'

if [ -n "$FPR" ] && [ -f "$ISO.asc" ]; then
    printf '  importing the signing key ... '
    gpg --quiet --import unit-signing-key.asc 2>/dev/null || true
    printf 'ok\\n'
    printf '  signature ... '
    # --status-fd tells us WHICH key made the signature. Printing a fingerprint
    # baked into this script would prove nothing: the script travels with the
    # image, so whoever replaced one could replace the other.
    status=$(gpg --batch --status-fd 1 --verify "$ISO.asc" "$ISO" 2>/dev/null)
    if ! echo "$status" | grep -q '^\\[GNUPG:\\] GOODSIG'; then
        printf 'BAD\\n\\n  The signature does not verify. Do not install this image.\\n\\n'
        exit 1
    fi
    printf 'ok\\n'
    signer=$(echo "$status" | sed -n 's/^\\[GNUPG:\\] VALIDSIG \\([0-9A-F]*\\).*/\\1/p' | head -1)
    printf '\\n  Signed by:  %s\\n' "$signer"
    if [ -n "$FPR" ] && [ "$signer" != "$FPR" ]; then
        printf '  Expected:   %s\\n' "$FPR"
        printf '\\n  *** The signer is NOT the key this image was built with. ***\\n'
        printf '  Stop. Do not install this image.\\n\\n'
        exit 1
    fi
    printf '\\n  COMPARE that fingerprint against the one you were given through a\\n'
    printf '  channel INDEPENDENT of this media. If they differ, stop.\\n\\n'
else
    printf '\\n  WARNING: this image is UNSIGNED. Do not install it.\\n\\n'
    exit 1
fi
""")
    script.chmod(0o755)
    x.ok(f"verification script written: {script.name}")


# ---------------------------------------------------------------------------
#  write-usb — GUIDE section 7, with the safety rails dd does not have
# ---------------------------------------------------------------------------
def removable_devices() -> list[dict]:
    out = []
    for blk in sorted(Path("/sys/block").glob("*")):
        try:
            if (blk / "removable").read_text().strip() != "1":
                continue
            size = int((blk / "size").read_text().strip()) * 512
            if size == 0:
                continue
            model = ""
            for cand in (blk / "device" / "model", blk / "device" / "name"):
                if cand.is_file():
                    model = cand.read_text().strip()
                    break
            out.append({"dev": f"/dev/{blk.name}", "size": size, "model": model})
        except (OSError, ValueError):
            continue
    return out


def _mounted_partitions(dev: str) -> list[str]:
    base = Path(dev).name
    try:
        mounts = Path("/proc/mounts").read_text()
    except OSError:
        return []
    return [l.split()[0] for l in mounts.splitlines()
            if l.split()[0].startswith(f"/dev/{base}")]


def write_usb(x: Ctx) -> int:
    x.phase("write-usb", "verify the image, then write it to removable media")
    iso = x.out_dir / x.c["iso_name"]
    if not iso.is_file():
        raise Fatal(f"no image at {iso}. Build it first:  ./build_iso.py iso")

    # 1. Never write an image you have not just verified.
    sha = x.out_dir / f"{x.c['iso_name']}.sha256"
    if sha.is_file():
        import hashlib
        h = hashlib.sha256()
        with iso.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 22), b""):
                h.update(chunk)
        want = sha.read_text().split()[0]
        if h.hexdigest() != want:
            raise Fatal(f"checksum mismatch for {iso.name} — the image on disk is "
                        f"not the one that was built. Do not distribute it.")
        x.ok("checksum matches the build record")
    else:
        x.warn("no .sha256 beside the image — cannot verify it before writing")

    asc = x.out_dir / f"{x.c['iso_name']}.asc"
    if asc.is_file():
        # Not quiet(): it has a 180 s timeout, and verifying a detached
        # signature means hashing the entire image. A timeout would have been
        # swallowed into False and reported as a forged signature.
        x.info("verifying the signature (gpg hashes the whole image)")
        try:
            x.run("gpg", "--batch", "--verify", str(asc), str(iso), live=True)
        except Fatal:
            raise Fatal("the detached signature does not verify. Do not write "
                        "this image to media.")
        x.ok(f"signature verifies against {x.c['iso_sign_key']}")
    else:
        x.warn("image is UNSIGNED — colleagues will have nothing to verify against")

    # 2. Pick a device, and refuse anything that is not removable.
    devs = removable_devices()
    dev_path = getattr(x.args, "device", None)
    if not dev_path:
        if not devs:
            raise Fatal("no removable device found. Plug the USB stick in, or pass "
                        "--device /dev/sdX explicitly.")
        print("\n  Removable devices:")
        for d in devs:
            print(f"      {d['dev']:12s} {d['size'] / 1e9:6.1f} GB  {d['model']}")
        if len(devs) > 1:
            raise Fatal("more than one removable device — name the one you mean "
                        "with --device")
        dev_path = devs[0]["dev"]
        x.info(f"selected the only removable device: {dev_path}")

    match = next((d for d in devs if d["dev"] == dev_path), None)
    if match is None:
        if not getattr(x.args, "allow_fixed_disk", False):
            raise Fatal(f"{dev_path} is not a removable device. Refusing — this command "
                        f"destroys everything on its target.\n"
                        f"     If you are certain, pass --allow-fixed-disk.")
        x.warn(f"{dev_path} is NOT removable and will be destroyed")

    mounted = _mounted_partitions(dev_path)
    if mounted:
        raise Fatal(f"{dev_path} has mounted partitions ({', '.join(mounted)}). "
                    f"Unmount them first.")

    size_gb = iso.stat().st_size / 1e9
    if match and iso.stat().st_size > match["size"]:
        raise Fatal(f"the image is {size_gb:.1f} GB and {dev_path} holds only "
                    f"{match['size'] / 1e9:.1f} GB")

    print()
    x.warn(f"EVERYTHING ON {dev_path} WILL BE DESTROYED.")
    if match:
        x.warn(f"  {match['size'] / 1e9:.1f} GB  {match['model']}")
    x.warn(f"  writing {iso.name} ({size_gb:.1f} GB)")
    print()
    if x.args.dry_run:
        x.info(f"[dry-run] dd if={iso} of={dev_path} bs=4M oflag=direct")
        return 0
    if not confirmed(x, f"Write to {dev_path}?"):
        raise Fatal("aborted")

    x.run(*_sudo(["dd", f"if={iso}", f"of={dev_path}", "bs=4M", "status=progress",
                  "oflag=direct"]), live=True)
    x.run(*_sudo(["sync"]))
    x.ok("written")

    # 3. Read it back. A stick that writes without error and reads back wrong
    #    is the failure mode that shows up at the install, on someone else's
    #    desk, with no way to tell whether the image or the media was at fault.
    x.info("reading back and comparing — this takes as long as the write did")
    import hashlib
    h = hashlib.sha256()
    remaining = iso.stat().st_size
    try:
        with open(dev_path, "rb") as dev:
            while remaining > 0:
                chunk = dev.read(min(1 << 22, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
    except PermissionError:
        x.warn(f"cannot read {dev_path} back without root — re-run readback with sudo")
        return 0
    if h.hexdigest() == want_digest(x):
        x.ok("readback matches the image byte for byte")
    else:
        raise Fatal("readback does NOT match the image. The write failed silently "
                    "or the media is faulty. Do not distribute this stick.")

    print(f"""
  Also copy these onto a SEPARATE stick or an internal page — never only the
  one carrying the image:

      {x.out_dir / 'FINGERPRINT.txt'}
      {x.out_dir / 'unit-signing-key.asc'}
      {x.out_dir / 'verify-iso.sh'}
""")
    return 0


def want_digest(x: Ctx) -> str:
    sha = x.out_dir / f"{x.c['iso_name']}.sha256"
    if sha.is_file():
        return sha.read_text().split()[0]
    import hashlib
    h = hashlib.sha256()
    with (x.out_dir / x.c["iso_name"]).open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


# ===========================================================================
def deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        out[k] = deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def load_config(write_only=False, dry_run=False) -> dict:
    if CONF_PATH.exists():
        if write_only:
            print(f"iso-build.json already exists — not overwriting: {CONF_PATH}",
                  file=sys.stderr)
            sys.exit(1)
        try:
            return deep_merge(DEFAULT_CONFIG, json.loads(CONF_PATH.read_text()))
        except json.JSONDecodeError as e:
            print(f"{R}FATAL:{RST} {CONF_PATH.name} is not valid JSON: {e}",
                  file=sys.stderr)
            sys.exit(1)
    if dry_run and not write_only:
        print(f"  {Y}!{RST} no iso-build.json — planning against the embedded "
              f"defaults (a dry run writes nothing)\n")
        return dict(DEFAULT_CONFIG)
    CONF_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2) + "\n")
    if write_only:
        print(f"Wrote {CONF_PATH}")
        print("Review and edit it, then run:  ./build_iso.py --dry-run iso")
        sys.exit(0)
    print(f"  {Y}!{RST} no iso-build.json found — wrote embedded defaults to {CONF_PATH}\n")
    return dict(DEFAULT_CONFIG)


def main() -> int:
    p = argparse.ArgumentParser(
        description="InQubestigationOS — build custom templates and a bootable ISO",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
lifecycle
  setup-host       install and configure everything the build host needs
  gen-key          create (or adopt) the ISO signing key and record it
  doctor           check the host is ready; change nothing
  config           read or write settings without an editor
  check-upstream   compare pinned keys and versions against upstream
  templates        build the five investigator templates
  iso              build, checksum and sign the ISO
  all              templates, then the ISO
  write-usb        verify the image and write it to removable media
  list-kickstarts  show what the fetched Qubes sources offer
""")
    p.add_argument("action", nargs="?", default="iso",
                   choices=["iso", "templates", "all", "list-kickstarts",
                            "doctor", "setup-host", "gen-key", "check-upstream",
                            "write-usb", "config"],
                   help="what to do (default: iso)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--force", action="store_true", help="skip the warning prompt")
    p.add_argument("--yes", action="store_true",
                   help="answer every prompt with yes (for unattended runs)")
    p.add_argument("--write-config", action="store_true")
    p.add_argument("--set", dest="set_kv", action="append", metavar="KEY=VALUE",
                   help="set a configuration key (repeatable); implies action 'config'")
    p.add_argument("--get", dest="get_key", metavar="KEY",
                   help="print a configuration key; implies action 'config'")
    g = p.add_argument_group("gen-key")
    g.add_argument("--uid", metavar='"Name <email>"',
                   help="identity for a new signing key")
    g.add_argument("--use-key", metavar="FPR|auto",
                   help="adopt a key already in this keyring instead of creating one")
    g.add_argument("--expire", default="3y", metavar="3y",
                   help="expiry for a new signing key (default: 3y)")
    g.add_argument("--no-passphrase", action="store_true",
                   help="generate the key without a passphrase (lab builds only)")
    u = p.add_argument_group("write-usb")
    u.add_argument("--device", metavar="/dev/sdX", help="target device")
    u.add_argument("--allow-fixed-disk", action="store_true",
                   help="permit a non-removable target (destroys it)")
    c = p.add_argument_group("check-upstream")
    c.add_argument("--update", action="store_true",
                   help="record what upstream currently offers as the new baseline")
    args = p.parse_args()
    # --yes answers prompts. It must NOT imply --force, which also means
    # "rebuild the templates even though their RPMs are present" — an
    # unattended run would have re-debootstrapped all five every time.
    args.assume_yes = args.yes or args.force
    if (args.set_kv or args.get_key) and args.action == "iso":
        args.action = "config"

    try:
        # doctor and list-kickstarts report; they do not create anything, not
        # even the default config. ('config' writes it — that is its job.)
        cfg = load_config(write_only=args.write_config,
                          dry_run=args.dry_run
                          or args.action in ("doctor", "list-kickstarts"))
        x = Ctx(cfg, args)
        tier2 = int(cfg["tier"]) == 2

        print(f"\n{B}{C}{cfg['iso_name']}{RST}")
        if args.dry_run:
            print(f"{Y}DRY RUN — nothing will be changed{RST}")
        x.say(f"work dir: {x.work}")
        x.say(f"log:      {x.log}")

        if args.action == "config":
            rc = 0
            for kv in (args.set_kv or []):
                if "=" not in kv:
                    raise Fatal(f"--set expects KEY=VALUE, got '{kv}'")
                k, v = kv.split("=", 1)
                rc |= config_set(x, k.strip(), v.strip())
            if args.get_key:
                rc |= config_get(x, args.get_key)
            if not args.set_kv and not args.get_key:
                for k in sorted(_flat_keys(x.c)):
                    node, val = x.c, None
                    for part in k.split("."):
                        node = node[part]
                    val = node
                    if not isinstance(val, dict):
                        print(f"  {k} = {json.dumps(val)}")
            return rc

        if args.action == "doctor":
            return doctor(x)
        if args.action == "setup-host":
            return setup_host(x)
        if args.action == "gen-key":
            return gen_key(x)
        if args.action == "check-upstream":
            return check_upstream(x)
        if args.action == "write-usb":
            return write_usb(x)

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
            # The state file recorded a 'templates' mark that nothing ever read,
            # so a multi-hour phase restarted from zero on every resume. Honour
            # it, but only when the RPMs it claims to have produced are still
            # there.
            if x.done("templates") and not args.force and not args.dry_run \
                    and not missing_template_rpms(x):
                x.skip("template build — every RPM is present in artifacts/")
                x.info("./build_iso.py --force templates  to rebuild them anyway")
            else:
                fetch_kali_key(x)
                gen_component(x)
                build_templates(x)
            if args.action == "templates":
                print(f"\n  Next:  ./build_iso.py iso\n")
                return 0

        if args.action in ("iso", "all"):
            resolve_auto_values(x)
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
