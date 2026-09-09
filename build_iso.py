#!/usr/bin/env python3
"""
build_iso.py — InQubestigationOS.iso

Builds a custom bootable Qubes installer with qubes-builderv2, optionally with
the investigator templates baked in (Tier 2) so the target installs with no
network at all.

*** RUNS ON A BUILD HOST, NEVER IN DOM0 ***
Needs a Debian-family host (Debian, Kali, Ubuntu) or a Fedora-family one,
Docker or Podman, ~100 GB free (Tier 1) or ~250 GB (Tier 2), and several
hours. `doctor` names the distribution it found; a VM is a first-class host
and needs no nested virtualisation, because the build cages are containers.

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
import time
import sys
from datetime import datetime
from pathlib import Path

# ===========================================================================
DEFAULT_CONFIG: dict = {
    "iso_name": "InQubestigationOS.iso",
    "iso_flavor": "InQubestigationOS",
    "iso_version": "",
    "qubes_release": "r4.3",
    # qubes-builderv2 has ONE branch: main. There is no release4.3 branch —
    # `git ls-remote --heads` returns refs/heads/main and nothing else. Passing
    # a branch that does not exist makes the clone fail outright.
    "builder_branch": "main",
    # Verify the builder before building a police workstation with it. Only the
    # Qubes Master Signing Key is pinned here; the core developer keys are
    # trusted because that key has signed them, which is the trust model Qubes
    # publishes. Confirmed against keys.qubes-os.org on 2026-09-09.
    "verify_builder": True,
    "qubes_master_key": "427F11FD0FAA4B080123F01CDDFA1A3E36879494",
    "secpack_url": "https://github.com/QubesOS/qubes-secpack.git",

    # TIER 2 IS THE DEFAULT AND THE INTENDED PATH.
    #   2 = investigator templates baked into the ISO as RPMs. Installs with no
    #       network. First boot only wires the topology — minutes, not hours.
    #   1 = stock templates only; the investigator templates get built on first
    #       boot from the network. Smaller ISO, but 1-3 hours of first-boot work
    #       and a hard dependency on connectivity at install time. Fallback only.
    "tier": 2,

    # "auto" picks the largest writable local filesystem with room for the
    # build, so "somewhere with 250 GB free" stops being something to work out.
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
    # How stale the recorded supply-chain baseline may be before a build
    # re-checks it automatically. 0 disables the automatic check entirely.
    "check_upstream_max_age_days": 7,

    # Anaconda answers. With "unattended": false (the default) the installer
    # behaves exactly as before and a person drives it.
    #
    # Turning it on emits standard kickstart directives so the install stops
    # being a sequence of clicks. Disk encryption is deliberately NOT made
    # passwordless: `autopart --encrypted` makes Anaconda REQUIRE a passphrase,
    # so the one decision that must stay human stays human, and cannot be
    # clicked past by someone in a hurry.
    "install": {
        "unattended": False,
        "lang": "en_US.UTF-8",
        "keyboard": "ch",
        "timezone": "Europe/Zurich",
        "encrypt_disk": True,
        # luks2 is what Anaconda defaults to on current releases; set it
        # explicitly so a future default change does not alter your images.
        "luks_version": "luks2",
        # Wipe and use the whole disk. Blank leaves partitioning to the operator.
        "disk": "",
        # Complete Qubes' own initial setup non-interactively at first boot.
        "auto_initial_setup": True,
    },

    # GPG fingerprint (40 hex chars) of the unit key that signs the ISO.
    # THIS IS A FINGERPRINT, NOT A KEY. The private key stays in the build
    # host's GPG keyring and must never appear in this file or in the repo.
    # The script exports the matching PUBLIC key next to the ISO so colleagues
    # can verify, and refuses to run if key material is pasted here.
    "iso_sign_key": "",

    # --- Tier 2 template build -------------------------------------------
    # The generated template component. Left local, it is fetched with
    # signature checking OFF — acceptable only because you generated it on your
    # own build host, and the build says so every time. Set component_remote to
    # your unit's git server and component_sign_key to a signing fingerprint and
    # the build pushes a signed tag there and turns verification back on.
    "component_remote": "",
    "component_sign_key": "",
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
        # An independent second source for the same key. docs/VERIFICATION.md
        # asks for this cross-check; check-upstream performs it.
        "keyserver_url": "https://keyserver.ubuntu.com/pks/lookup?search=827C8569F2518CC677FECA1AED65462EC8D5E4C5&fingerprint=on&op=index",
        "metapackage": "kali-linux-default",
    },
    "zeek": {
        "repo_line": "deb [signed-by=/usr/share/keyrings/security_zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/Debian_13/ /",
        "key_url": "https://download.opensuse.org/repositories/security:zeek/Debian_13/Release.key",
        # zeek-8.0 in the OBS repository is frozen at 8.0.1-0; the 8.0 LTS line
        # is published as zeek-lts (8.0.10-0 today).
        "package": "zeek-lts",
        # Pinned like every other key in this image. Confirmed 2026-09-08;
        # expires 2026-12-02, which check-upstream and the golden-key-expiry
        # timer both watch.
        "key_fpr": "F9FA0223B56B116C363737EF5DA57BDD6DD785CA",
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
    def run(self, *argv, cwd=None, check=True, capture=False, live=False, env=None):
        cmd = [str(a) for a in argv]
        if self.args.dry_run:
            print(f"  {D}[dry-run]{RST} {' '.join(shlex.quote(a) for a in cmd)}")
            return ""
        self._log("EXEC  " + " ".join(cmd))
        if live:
            p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, env=env)
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
                           stdin=subprocess.DEVNULL, env=env)
        self._log(f"      rc={p.returncode}\n{p.stdout[-4000:]}{p.stderr[-4000:]}")
        if check and p.returncode != 0:
            raise Fatal(f"failed: {' '.join(cmd)} — see {self.log}")
        return (p.stdout + p.stderr) if capture else ""

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
            # Fail here, not four hours later next to the finished image.
            if self.args.action in ("iso", "all") and not self.args.dry_run \
                    and not getattr(self.args, "allow_unsigned", False):
                raise Fatal(
                    "iso_sign_key is empty, so this build would produce an "
                    "UNSIGNED image.\n"
                    "     An unsigned image passed around on USB sticks is "
                    "exactly the supply-chain\n     problem this design exists "
                    "to prevent.\n\n"
                    '     ./build_iso.py gen-key --uid "Your Unit <you@example.org>"\n'
                    "     ./build_iso.py gen-key --use-key auto      (adopt an "
                    "existing key)\n\n"
                    "     Or --allow-unsigned to build one deliberately for "
                    "testing.")
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
    # Measure the nearest existing ancestor. statvfs on a directory that does
    # not exist yet raises, and the check used to disappear silently on exactly
    # the two occasions it matters most: a fresh host, and any --dry-run.
    probe = x.work
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    free = _free_gb(probe)
    if free is None:
        x.warn(f"could not measure free space at {probe}")
    else:
        x.info(f"free space at {probe}: {free}G")
        if free < need:
            x.warn(f"under {need}G free — this build will very likely fail")

    # In a dry run the environment gates become warnings: the whole point of
    # "print the plan and change nothing" is that you can read it before the
    # host is ready. Configuration errors stay fatal either way.
    def gate(message: str) -> None:
        if x.args.dry_run:
            x.warn(message.splitlines()[0] + "  (dry run: continuing)")
        else:
            raise Fatal(message)

    for tool in ("git", "curl", "gpg"):
        if not shutil.which(tool):
            gate(f"{tool} not installed — ./build_iso.py setup-host")

    # A third place that used to guess the distribution from $PATH, in yet
    # another order. One function answers this now, from /etc/os-release.
    d = host_distro()
    host = d.family
    x.info(f"build host: {d.described()}  [detected via {d.how}]")
    if x.c["prefer_debian_build_host"] and host == "fedora":
        x.info("a Debian 13 build host is preferred here, but Fedora works — "
               "qubes-builderv2 ships dependency lists for both")
    if x.c["container_engine"] == "podman":
        x.warn("podman selected: upstream states its executor currently cannot build")
        x.warn("  DEB packages, and every custom template in this image is Debian.")
        x.warn("  Use docker unless you have verified otherwise.")

    ce = x.c["container_engine"]
    if not shutil.which(ce):
        gate(f"{ce} is required for the builder cages — ./build_iso.py setup-host")
    elif not x.quiet(ce, "ps"):
        gate(f"cannot talk to {ce} without sudo.\n"
                    f"     Fix it in one step:  ./build_iso.py setup-host\n"
                    f"     (adds you to the {ce} group, enables the service, and in "
                    f"an app qube\n      persists /var/lib/docker through bind-dirs)")
    else:
        x.ok(f"{ce} usable without sudo")

    payload = Path(__file__).resolve().parent / "golden_image.py"
    if not payload.is_file():
        gate(f"provisioning payload not found: {payload}\n"
                    "     golden_image.py must sit beside this script — it is what "
                    "gets embedded into the ISO.")
    x.ok(f"provisioning payload found: {payload.name}")

    # doctor was a separate step somebody had to remember. It reports every
    # blocking condition this build would hit, so run it as part of the build.
    if x.args.action in ("templates", "iso", "all") and not x.args.dry_run \
            and not getattr(x.args, "skip_doctor", False):
        x.say("")
        if doctor(x):
            raise Fatal("this host is not ready — see the blocking rows above.\n"
                        "     ./build_iso.py doctor --fix   fixes what this script "
                        "owns.\n"
                        "     --skip-doctor builds anyway.")
    return payload


# ===========================================================================
#  Builder setup
# ===========================================================================
def setup_builder(x: Ctx):
    x.phase("1", "fetch qubes-builderv2 and build the container image")
    branch = x.c["builder_branch"]
    if x.args.dry_run and not (x.builder / ".git").is_dir():
        x.info(f"[dry-run] clone qubes-builderv2 @ {branch}, install its "
               f"dependencies, build the container image, fetch qubes-release")
        x.info("[dry-run] nothing below can be checked until that has happened")
        return
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

    verify_builder(x)

    if not x.args.dry_run:
        # host_family(), not a second `which` probe in the opposite order:
        # this asked dnf first while host_family() asked apt-get first, so a
        # host with both was classified one way here and the other way in
        # setup-host. _sudo() rather than a literal "sudo" so this still works
        # when already running as root, where sudo may not be installed.
        fam = host_family()
        deps_file = {"debian": "dependencies-debian.txt",
                     "fedora": "dependencies-fedora.txt"}.get(fam)
        if not deps_file:
            raise Fatal(f"unsupported build host: {host_distro().described()} — "
                        "builderv2 supports Fedora and Debian families")
        deps = (x.builder / deps_file).read_text().split()
        # Same reasoning as setup-host: one name the host does not have fails
        # the whole apt-get batch, and upstream's list targets Debian proper —
        # Kali and older Ubuntu do not carry all of it. Report what looks
        # missing, but do NOT drop it: a Debian virtual package with a single
        # provider installs by name while reporting Candidate: (none), and
        # dropping those would lose dependencies the unfiltered install used
        # to get. Anything genuinely absent costs only its own retry.
        avail = packages_available(fam, deps)
        if avail is not None and set(deps) - avail:
            x.warn("upstream lists these but this host's package sources do "
                   "not appear to have them: " + " ".join(sorted(set(deps) - avail)))
        install_packages(x, fam, deps)
        x.info("builder dependencies installed (failures above are not fatal — the "
               "container image build below is the real test)")

    x.info("building the container image for the build cages (slow, one-off)")
    resolve_auto_values(x)
    # tools/generate-container-image.sh takes the mock configuration as an
    # OPTIONAL second argument, and passing it selects a completely different
    # code path: `sudo mock -r <conf> --scrub=all`, then --init, then a build
    # from dockerfiles/fedora-mock.Dockerfile with the mock root cache as
    # context. `mock` is a Fedora tool. It was dropped from Debian in 2019 and
    # is in no current Debian or Kali suite, and the script runs under
    # `set -ex`, so passing the argument unconditionally — which this did —
    # aborted the container image build on EVERY Debian-family host, including
    # the Debian 13 host the guide recommends.
    #
    # Omitting it builds from dockerfiles/fedora.Dockerfile instead, which
    # pulls the pinned Fedora image and installs mock, rpm-build, createrepo_c
    # and the rest INSIDE the container, so the host needs only the container
    # engine.
    #
    # The two images are NOT identical: one is seeded from a digest-pinned
    # Fedora image on Docker Hub, the other from a chroot mock built on this
    # host, and the mock variant additionally installs sudo while the other
    # pre-creates /builder/cache/mock. What was checked against upstream is
    # narrower and is what actually matters here: both branches tag the result
    # `qubes-builder-fedora`, and every consumer in qubes-builderv2 — the
    # example configs, ci/benchmark.sh, the container executor — refers to it
    # by that name and nothing else. So the builder finds an image either way;
    # it is not that the image is the same.
    #
    # Keyed on whether `mock` is actually present rather than on the
    # distribution, because that is the real precondition: a Fedora host picks
    # up mock from dependencies-fedora.txt just above and keeps upstream's
    # preferred path, and a Debian host that has built mock by hand keeps it
    # too.
    gci = ["tools/generate-container-image.sh", x.c["container_engine"]]
    if shutil.which("mock"):
        gci.append(x.c["mock_config"])
        x.info(f"mock is present — seeding the build cage from the "
               f"{x.c['mock_config']} chroot, the path upstream's own Fedora "
               f"dependency list equips a host for")
    else:
        x.info("mock is not installed here (it is not packaged for Debian or "
               "Kali), so the build cage is built from "
               "dockerfiles/fedora.Dockerfile — seeded from the pinned Fedora "
               "container rather than a host chroot, and carrying the same "
               "qubes-builder-fedora tag the builder looks for")
    # check=True: without the container image nothing downstream can build, and
    # marking the phase done anyway meant every later run skipped the setup and
    # failed somewhere far less obvious.
    x.run(*gci, cwd=x.builder, live=True)

    bcfg = x.builder / "builder.yml"
    if not bcfg.exists():
        example = x.builder / "example-configs" / f"qubes-os-{x.c['qubes_release']}.yml"
        if not example.exists() and x.args.dry_run:
            x.info(f"[dry-run] seed builder.yml from "
                   f"example-configs/qubes-os-{x.c['qubes_release']}.yml")
            return
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



# ---------------------------------------------------------------------------
#  bootstrap — the whole build side, in the right order
#
#  Getting from a freshly cloned repository to a written USB was seven separate
#  invocations that had to happen in a particular order, and `all` covered only
#  two of them. Each step here is the command the guide documents; running them
#  in sequence is what nobody should have to remember.
# ---------------------------------------------------------------------------
def bootstrap(x: Ctx, args) -> int:
    steps: list[tuple[str, str, list[str]]] = [
        ("setup-host", "install and configure the build host", ["setup-host"]),
        ("gen-key", "create or adopt the signing key", ["gen-key"]),
        ("backup-key", "back up the signing key before anything can lose it",
         ["backup-key"]),
        ("doctor", "confirm the host is ready", ["doctor"]),
        ("check-upstream", "confirm the pinned keys and versions are current",
         ["check-upstream", "--update"]),
        ("plan", "print the whole build plan", ["--dry-run", "all"]),
        ("build", "build the templates and the ISO", ["all"]),
    ]
    if getattr(args, "uid", None):
        steps[1] = ("gen-key", steps[1][1], ["gen-key", "--uid", args.uid])
    if getattr(args, "to", None):
        steps[2] = ("backup-key", steps[2][1], ["backup-key", "--to", args.to])

    print(f"\n{B}{C}══ bootstrap{RST}")
    print("\n  This runs, stopping at the first failure:\n")
    for i, (name, why, argv) in enumerate(steps, start=1):
        print(f"    {i}. {name:15s} {why}")
    print(f"""
  Each is resumable and each is idempotent, so if one fails you can fix the
  cause and run bootstrap again — the completed ones are skipped.

  Not included, because they need you: writing the USB (plug the stick in, then
  ./build_iso.py write-usb --wait), and reading the fingerprint out over a
  channel independent of the image.
""")
    if args.dry_run:
        x.info("[dry-run] nothing executed")
        return 0
    if not confirmed(x, "Start?"):
        raise Fatal("aborted")

    me = [sys.executable, str(Path(__file__).resolve())]
    passthrough = ["--yes"] if getattr(args, "assume_yes", False) else []
    for i, (name, _why, argv) in enumerate(steps, start=1):
        print(f"\n{B}{C}══ bootstrap {i}/{len(steps)}: {name}{RST}")
        rc = subprocess.run(me + argv + passthrough).returncode
        if rc != 0:
            raise Fatal(f"bootstrap stopped at step {i} ({name}), exit {rc}.\n"
                        f"     Fix the cause and run bootstrap again — completed "
                        f"steps are skipped.")
    print(f"""
{B}{C}══ bootstrap complete{RST}

  The image, its checksum, its signature, the public key, verify-iso.sh,
  verify-iso.ps1 and FINGERPRINT.txt are in {x.out_dir}

  Next:
    plug the stick in, then  ./build_iso.py write-usb --wait
    and give colleagues the fingerprint through a channel that is NOT the stick.
""")
    return 0


# ---------------------------------------------------------------------------
#  Verify the builder itself
#
#  "The builder verifies what it fetches; nothing verifies the builder for you"
#  was a [VERIFY] note. It does not have to be. Qubes publishes a trust chain:
#  every core developer's key is signed by the Qubes Master Signing Key, and
#  every commit in qubes-builderv2 carries a signed tag named mm_<short-sha>.
#  So exactly ONE fingerprint needs pinning here — the master key — and the
#  developer keys are trusted because it says so.
# ---------------------------------------------------------------------------
def verify_builder(x: Ctx) -> None:
    if not x.c["verify_builder"]:
        x.warn("verify_builder is off. Nothing is checking the tool that builds "
               "the image you hand to colleagues.")
        return
    if x.args.dry_run:
        x.info("[dry-run] verify the builder's signed tag against the Qubes "
               "master signing key")
        return

    secpack = x.work / ".qubes-secpack"
    if (secpack / ".git").is_dir():
        if not x.quiet("git", "-C", str(secpack), "fetch", "-q", "--depth", "1",
                       "origin", "HEAD"):
            shutil.rmtree(secpack, ignore_errors=True)
        else:
            x.run("git", "-C", str(secpack), "reset", "-q", "--hard",
                  "FETCH_HEAD", check=False)
    if not (secpack / ".git").is_dir():
        x.run("git", "clone", "-q", "--depth", "1", x.c["secpack_url"],
              str(secpack), live=True)

    master_dir, devs_dir = secpack / "keys" / "master-key", secpack / "keys" / "core-devs"
    if not master_dir.is_dir() or not devs_dir.is_dir():
        x.verify(f"qubes-secpack does not have the expected keys/master-key and "
                 f"keys/core-devs layout at {secpack}. Verify the builder "
                 f"checkout by hand before trusting this build.")
        return

    keyring = x.work / ".builder-keyring"
    shutil.rmtree(keyring, ignore_errors=True)
    keyring.mkdir(parents=True)
    keyring.chmod(0o700)
    env = dict(os.environ, GNUPGHOME=str(keyring))

    pinned = x.c["qubes_master_key"].replace(" ", "").upper()
    x.run("gpg", "--batch", "--quiet", "--import",
          *[str(f) for f in sorted(master_dir.glob("*.asc"))], env=env)
    have = {ln.split(":")[9] for ln in
            x.run("gpg", "--with-colons", "--fingerprint", capture=True,
                  check=False, env=env).splitlines()
            if ln.startswith("fpr:")}
    if pinned not in have:
        raise Fatal(f"the Qubes Master Signing Key in {secpack} is not {pinned}.\n"
                    f"     Found: {', '.join(sorted(have)) or 'nothing'}\n"
                    "     Confirm the fingerprint at https://keys.qubes-os.org and "
                    "at\n     https://www.qubes-os.org/security/verifying-signatures/ "
                    "before going further.")
    x.ok(f"Qubes Master Signing Key verified: {pinned}")

    x.run("gpg", "--batch", "--quiet", "--import",
          *[str(f) for f in sorted(devs_dir.glob("*.asc"))], env=env)
    master_longid = pinned[-16:]
    dev_fprs, current, certified = set(), None, set()
    for ln in x.run("gpg", "--with-colons", "--check-signatures", capture=True,
                    check=False, env=env).splitlines():
        f = ln.split(":")
        if f[0] == "pub":
            current = None
        elif f[0] == "fpr" and current is None:
            current = f[9]
            if current != pinned:
                dev_fprs.add(current)
        elif f[0] == "sig" and current and len(f) > 4 and f[4] == master_longid:
            certified.add(current)
    uncertified = dev_fprs - certified
    if not dev_fprs:
        raise Fatal(f"no developer keys found in {devs_dir}")
    if uncertified:
        x.warn(f"not signed by the master key, so not trusted here: "
               f"{', '.join(sorted(uncertified))}")
    trusted = dev_fprs & certified
    if not trusted:
        raise Fatal("no Qubes developer key is certified by the master key. "
                    "Something is wrong with the secpack checkout.")
    x.ok(f"{len(trusted)} developer key(s) certified by the master key")

    tags = x.run("git", "-C", str(x.builder), "tag", "--points-at", "HEAD",
                 check=False, capture=True).split()
    if not tags:
        raise Fatal(
            "the builder checkout has no tag on HEAD, so there is nothing to "
            "verify.\n     Every qubes-builderv2 commit normally carries a "
            "signed mm_<sha> tag.\n     Run 'git -C "
            f"{x.builder} fetch --tags', or set verify_builder=false and accept "
            "an unverified builder.")
    raw = x.run("git", "-C", str(x.builder), "verify-tag", "--raw", tags[0],
                check=False, capture=True, env=env)
    signer = next((ln.split()[2] for ln in raw.splitlines()
                   if ln.startswith("[GNUPG:] VALIDSIG")), "")
    good = any(ln.startswith("[GNUPG:] GOODSIG") for ln in raw.splitlines())
    if not good or signer.upper() not in trusted:
        raise Fatal(
            f"the builder tag {tags[0]} does not verify against a Qubes "
            f"developer key.\n     Signer: {signer or 'none'}\n"
            "     Do not build a police workstation with an unverified builder.")
    x.ok(f"builder tag {tags[0]} signed by {signer}")


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
        x.info(f"[dry-run] generate component at {x.component} with "
               f"{len(x.c['tier2_templates'])} flavors: "
               f"{', '.join(x.c['tier2_templates'])}")
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
chroot_cmd bash -c "gpg --no-default-keyring --keyring /usr/share/keyrings/security_zeek.gpg --with-colons --fingerprint | awk -F: '\\$1==\\"fpr\\"{{print toupper(\\$10)}}' | grep -qxF '{z['key_fpr']}'" \\
    || error 'openSUSE Build Service key is not {z['key_fpr']} — refusing to bake an unverified key into the image'
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
    publish_component(x, comp)


def component_source(x: Ctx) -> tuple[str, str]:
    """(url, verification-mode) for the template component in builder.yml."""
    if x.c["component_remote"] and x.c["component_sign_key"]:
        return x.c["component_remote"], "signed-tag"
    return f"file://{x.component}", "insecure-skip-checking"


def publish_component(x: Ctx, comp: Path) -> None:
    """Tag the generated component and push it, when a remote is configured.

    Until then the component is fetched from a local path with signature
    checking off. That is defensible on your own build host and indefensible in
    production, which is why the build says so every single time.
    """
    remote, mode = x.c["component_remote"], x.c["component_sign_key"]
    if not remote or not mode:
        x.warn("This component is fetched from a local path with signature "
               "checking OFF.")
        x.warn("  Acceptable only because you generated it on your own build "
               "host. For production:")
        x.warn("    ./build_iso.py --set component_remote=<git url> \\")
        x.warn("                   --set component_sign_key=<fingerprint>")
        x.warn("  The build then pushes a signed tag there and verifies it.")
        return
    fpr = mode.replace(" ", "").upper()
    if not re.fullmatch(r"[0-9A-F]{40}", fpr):
        raise Fatal(f"component_sign_key '{mode}' is not a 40-hex fingerprint")
    tag = f"investigator-{datetime.now():%Y%m%d%H%M%S}"
    if x.args.dry_run:
        x.info(f"[dry-run] tag {tag} signed by {fpr}, push to {remote}")
        return
    if not x.quiet("gpg", "--list-secret-keys", fpr):
        raise Fatal(f"no SECRET key for {fpr} — cannot sign the component tag")
    x.run("git", "-C", str(comp), "-c", f"user.signingkey={fpr}",
          "tag", "-s", "-m", f"investigator templates {datetime.now():%F %T}", tag)
    x.run("git", "-C", str(comp), "remote", "remove", "origin", check=False)
    x.run("git", "-C", str(comp), "remote", "add", "origin", remote)
    x.run("git", "-C", str(comp), "push", "--force", "origin", "HEAD:main",
          live=True)
    x.run("git", "-C", str(comp), "push", "origin", tag, live=True)
    x.ok(f"component pushed to {remote} as signed tag {tag}")
    x.info("builder.yml will fetch it from there with verification-mode: "
           "signed-tag")



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
            "PyYAML is needed to edit builder.yml safely "
            "(python3-yaml on Debian and Kali, python3-pyyaml on Fedora).\n"
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
    if not bcfg.exists() and not x.args.dry_run:
        raise Fatal("builder.yml not found — run the builder setup first")
    dist = x.c["dist_codename"]
    names = x.c["tier2_templates"]

    # template-root-size and timeout are documented as TOP-LEVEL builder.yml
    # keys. Per-template 'timeout' is not documented, so it is not emitted here.
    merge_builder_config(x, {
        "template-root-size": x.c["template_root_size"],
        "timeout": x.c["build_timeout"],
        "templates": [{n: {"dist": dist, "flavor": n}} for n in names],
        "components": [{"template-investigator": dict(zip(
            ("packages", "url", "verification-mode"),
            (False, *component_source(x))))}],
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

    auto_setup = "yes" if x.c["install"]["auto_initial_setup"] else "no"
    autotimer = ("systemctl enable golden-image-firstboot.timer"
                 if x.c["auto_provision"] else
                 "# auto_provision is off — no retry timer")
    autoline = ("systemctl enable golden-image-firstboot.service"
                if x.c["auto_provision"]
                else "# auto_provision disabled — operator runs it manually")
    auto_setup = "yes" if x.c["install"]["auto_initial_setup"] else "no"
    autotimer = ("systemctl enable golden-image-firstboot.timer"
                 if x.c["auto_provision"]
                 else "# auto_provision disabled — no retry timer")
    installer = build_installer_directives(x)

    ks.write_text(f"""\
# =============================================================================
#  investigator.ks — {x.c['iso_name']}
#  Generated by build_iso.py on {datetime.now():%Y-%m-%d %H:%M:%S}
#  Includes the stock Qubes kickstart unchanged, then plants the golden-image
#  provisioning payload into dom0.
# =============================================================================

{installer}%include {base_ks}
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

# Retry rather than latch. A machine left at the initial-setup wizard overnight
# used to need someone to remember to run the provisioner by hand afterwards.
cat > /etc/systemd/system/golden-image-firstboot.timer <<'TMR_EOF'
[Unit]
Description=Retry golden image provisioning until it succeeds
ConditionPathExists=!/var/lib/golden-image/provisioned

[Timer]
OnBootSec=10min
OnUnitActiveSec=30min

[Install]
WantedBy=timers.target
TMR_EOF

cat > /usr/local/sbin/golden-image-firstboot <<'FB_EOF'
#!/bin/bash
# Guarded first-boot runner. Waits until Qubes initial setup has produced the
# default qubes, because provisioning re-templates and re-wires them.
set -u
MARKER=/var/lib/golden-image/provisioned
mkdir -p /var/lib/golden-image
[ -e "$MARKER" ] && exit 0

STATUS=/var/lib/golden-image/firstboot-status
note() {{ echo "$(date '+%F %T') $*" >> "$STATUS"; logger -t golden-image "$*"; }}

note "first-boot runner started"

for i in $(seq 1 20); do
    if qvm-check --quiet sys-net 2>/dev/null && qvm-check --quiet sys-firewall 2>/dev/null; then
        break
    fi
    sleep 30
done

if ! qvm-check --quiet sys-net 2>/dev/null; then
    if [ "{auto_setup}" = "yes" ]; then
        # Nobody is here to click through the wizard on an unattended install.
        note "initial setup not done after 10 min; running it non-interactively"
        if /usr/local/sbin/golden-image-provision --initial-setup \\
                >> /var/log/golden-image-firstboot.log 2>&1; then
            note "initial setup completed by the runner"
        else
            note "automatic initial setup FAILED"
        fi
    fi
fi

if ! qvm-check --quiet sys-net 2>/dev/null; then
    note "initial setup incomplete; not provisioning"
    mkdir -p /etc/motd.d
    echo "Golden image provisioning deferred. Run: sudo golden-image-provision" \\
        > /etc/motd.d/golden-image
    # Not a one-shot give-up: try again on the next boot, and on a timer, so a
    # machine that was simply left at the wizard overnight still provisions.
    exit 0
fi

note "starting provisioning"
/usr/local/sbin/golden-image-provision >> /var/log/golden-image-firstboot.log 2>&1
rc=$?
if [ $rc -eq 0 ]; then
    touch "$MARKER"
    note "provisioned"
    rm -f /etc/motd.d/golden-image
else
    note "provisioning ran and failed rc=$rc; resume: sudo golden-image-provision"
fi
exit 0
FB_EOF
chmod 755 /usr/local/sbin/golden-image-firstboot

{autoline}
{autotimer}

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
        validate_kickstart(x, ks, extra_packages)
    x.info(f"auto-provision on first boot: {x.c['auto_provision']}")
    x.info("the runner records what it did in /var/lib/golden-image/firstboot-status, "
           "and acceptance group 13 reads it — no hardware check needed")
    x.warn("the ISO embeds the provisioning script. It contains NO secrets: credentials")
    x.warn("  are generated on the target machine, never baked into the image.")
    return rel


def build_installer_directives(x: Ctx) -> str:
    """Anaconda answers, when the operator asked for an unattended install.

    Everything here is a standard kickstart directive. Encryption is the one
    thing deliberately left interactive: `autopart --encrypted` makes Anaconda
    demand a passphrase, so the decision that must stay human cannot be clicked
    past — while the twenty that need not be, are not asked at all.
    """
    inst = x.c["install"]
    if not inst["unattended"]:
        return ""
    lines = [
        "# --- unattended install (iso-build.json: install.unattended) --------",
        f"lang {inst['lang']}",
        f"keyboard --vckeymap={inst['keyboard']} --xlayouts='{inst['keyboard']}'",
        f"timezone {inst['timezone']} --utc",
    ]
    if inst["encrypt_disk"]:
        disk = f" --drives={inst['disk']}" if inst["disk"] else ""
        if inst["disk"]:
            lines.append(f"ignoredisk --only-use={inst['disk']}")
            lines.append(f"clearpart --all --initlabel{disk}")
        else:
            lines.append("clearpart --all --initlabel")
        # No --passphrase= here, on purpose: Anaconda then prompts, and full-disk
        # encryption on an investigator laptop is not a thing to bake a shared
        # secret into.
        lines.append(f"autopart --encrypted --luks-version={inst['luks_version']}")
        lines.append("# Anaconda will PROMPT for the LUKS passphrase. That is")
        lines.append("# deliberate — see iso-build.json: install.encrypt_disk.")
    x.info(f"unattended install directives: {inst['lang']}, {inst['keyboard']}, "
           f"{inst['timezone']}"
           + (", full-disk encryption (passphrase prompted)"
              if inst["encrypt_disk"] else ""))
    if inst["encrypt_disk"]:
        x.warn("the installer will still ask for the disk encryption passphrase. "
               "That is the point: it cannot be skipped.")
    return "\n".join(lines) + "\n\n"


def validate_kickstart(x: Ctx, ks: Path, extra_packages: list[str]) -> None:
    """Parse the generated kickstart with pykickstart, if it is available.

    The open question was whether pykickstart merges two %packages sections or
    lets one override the other. Rather than asking the operator to confirm
    standard Anaconda behaviour, parse the file and read the package list back:
    if every added template is in it, the merge happened.
    """
    if x.args.dry_run:
        return
    probe = """
import sys
from pykickstart.parser import KickstartParser
from pykickstart.version import makeVersion
p = KickstartParser(makeVersion())
p.readKickstart(sys.argv[1])
print("\\n".join(str(g) for g in p.handler.packages.packageList))
"""
    # Whichever interpreter can import pykickstart: this one on Fedora, or the
    # virtualenv setup-host builds on Debian and Kali, which have no package
    # for it at all.
    py, _ = kickstart_python(x)
    if not py:
        x.verify("pykickstart is not installed here, so the generated kickstart "
                 "was not parsed. The build checks the template RPMs are in the "
                 "finished ISO, which answers the same question after the fact.")
        return
    out = x.run(py, "-c", probe, str(ks), check=False, capture=True)
    if "ModuleNotFoundError" in out or "ImportError" in out:
        x.verify("pykickstart is not installed here, so the generated kickstart "
                 "was not parsed. The build checks the template RPMs are in the "
                 "finished ISO, which answers the same question after the fact.")
        return
    if "Traceback" in out:
        raise Fatal(f"pykickstart cannot parse the generated kickstart:\n{out[-800:]}")
    missing = [f"qubes-template-{n}" for n in extra_packages
               if f"qubes-template-{n}" not in out]
    if missing:
        raise Fatal(
            f"pykickstart parsed the kickstart but these packages are not in the "
            f"package list: {', '.join(missing)}\n"
            "     The second %packages section did not merge — it overrode, or was "
            "overridden.\n     The ISO would install without the investigator "
            "templates.")
    if extra_packages:
        x.ok(f"pykickstart merges both %packages sections "
             f"({len(extra_packages)} templates present in the parsed list)")


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
    if not iso_tpls and x.args.dry_run:
        # The names release4.3's comps-dom0.xml carries, recorded in this
        # script's docstring. Only for planning: a real build derives them.
        iso_tpls = ["debian-13-xfce", "fedora-43-xfce",
                    "whonix-gateway-18", "whonix-workstation-18"]
        x.warn("planning against the release4.3 template names; a real build "
               "derives them from the fetched comps file")
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

    if not x.c["iso_sign_key"] and x.args.dry_run:
        # A dry run prints a plan; it produces nothing to distribute. Say what
        # would happen rather than refusing to describe it.
        x.warn("iso_sign_key is empty — a real build would REFUSE to produce an "
               "unsigned image")
        x.warn('  ./build_iso.py gen-key --uid "Your Unit <you@example.org>"')
    elif not x.c["iso_sign_key"] and not getattr(x.args, "allow_unsigned", False):
        raise Fatal(
            "iso_sign_key is empty, so this image would be UNSIGNED — and an "
            "unsigned image\n     passed around on USB sticks is exactly the "
            "supply-chain problem this design\n     exists to prevent.\n\n"
            '     ./build_iso.py gen-key --uid "Your Unit <you@example.org>"\n'
            "     ./build_iso.py gen-key --use-key auto      (adopt an existing key)\n\n"
            "     Or --allow-unsigned to build one deliberately for testing.")
    if not x.c["iso_sign_key"]:
        x.warn("--allow-unsigned: this image will be UNSIGNED. Do not distribute it.")

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
        x.warn("UNSIGNED, because --allow-unsigned was passed. Do not distribute "
               "this image.")

    # The %packages question, answered against the artefact rather than left as
    # a note: are the custom template RPMs actually inside the image?
    if tier2:
        listing = iso_listing(x, target)
        if listing is None:
            raise Fatal(
                "could not read the ISO's contents with bsdtar, 7z, isoinfo or a "
                "loop mount, so\n     there is no evidence the investigator "
                "templates are actually in it — which is\n     the whole Tier 2 "
                "promise. Install one of those tools "
                "(./build_iso.py setup-host)\n     and re-run './build_iso.py "
                "iso', or verify the image by hand before distributing.")
        absent = [n for n in x.c["tier2_templates"]
                  if f"qubes-template-{n}" not in listing]
        if absent:
            raise Fatal(f"these templates are NOT in the ISO: {', '.join(absent)}\n"
                        "     The %packages section did not take effect. Do not "
                        "distribute this image — it installs a broken workstation.")
        x.ok(f"all {len(x.c['tier2_templates'])} investigator templates are "
             f"present in the ISO")

    # Everything a colleague needs to check the image, in one command, beside
    # the image. GUIDE section 7 used to be three commands typed from memory.
    write_verify_script(x, digest)
    write_verify_script_windows(x)
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


def host_os_release() -> dict[str, str]:
    """/etc/os-release as a dict, or {} if there is no readable one.

    systemd defines the format: shell-style KEY=VALUE, values optionally
    quoted. Reading it is the only way to learn that a host calling itself
    "debian" underneath is actually Kali, or Ubuntu, or Mint.
    """
    out: dict[str, str] = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            text = Path(path).read_text()
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip().strip('"').strip("'")
        if out:
            break
    return out


# ID and ID_LIKE values that mean "packages are installed the Debian way" and
# "…the Fedora way". Kali is why this table exists: it is Debian testing
# underneath and declares ID_LIKE=debian, but nothing here could say so, so
# every Debian derivative was reported to the operator as the bare word
# "debian" and the one distribution-specific bug (no `mock`, no
# `python3-pykickstart`) was invisible.
DEBIAN_IDS = {"debian", "ubuntu", "kali", "raspbian", "linuxmint", "pop",
              "elementary", "devuan", "parrot", "neon", "zorin", "trisquel"}
FEDORA_IDS = {"fedora", "rhel", "centos", "rocky", "almalinux", "ol",
              "scientific"}
# "qubes" is deliberately in NEITHER table. dom0 is the only place that ID is
# expected, and doctor refuses to build there anyway; leaving it out means an
# ID this script does not know falls through to ID_LIKE, which is what
# actually says how packages are installed. Claiming "qubes" for one family
# would classify a Qubes app qube of the OTHER family wrongly, and an app qube
# is a supported build host.


class HostDistro:
    """What this build host actually is, and how we worked that out."""

    def __init__(self, family: str, ident: str, name: str, version: str,
                 how: str):
        self.family = family      # "debian", "fedora" or "unknown"
        self.id = ident           # os-release ID, e.g. "kali"
        self.name = name          # PRETTY_NAME, e.g. "Kali GNU/Linux Rolling"
        self.version = version    # VERSION_ID — empty on a rolling release
        self.how = how            # what decided the family

    def described(self) -> str:
        """A one-line description for the operator, never just the family."""
        # PRETTY_NAME normally carries the version already; fall back to
        # ID plus VERSION_ID for an os-release that omits it.
        label = (self.name or f"{self.id} {self.version}".strip()
                 or "unidentified")
        if self.family == "unknown":
            return f"{label} — neither apt-get nor dnf"
        if self.id and self.id not in ("debian", "fedora"):
            return f"{label} ({self.family}-family)"
        return label


def host_distro(osr: dict[str, str] | None = None) -> HostDistro:
    """Identify the build host from /etc/os-release, falling back to $PATH.

    `osr` overrides the file, so the mapping from a distribution's real
    os-release to a packaging family can be tested without a host of that
    distribution to hand.

    Detecting the distribution by which package manager happens to be on
    $PATH — which is all this used to do — cannot distinguish Kali from
    Debian from Ubuntu, and two code paths probed in opposite orders, so a
    host with both apt-get and dnf was classified differently depending on
    which function asked. os-release is the primary source; the $PATH probe
    stays as the fallback for a distribution not in the tables above, in one
    fixed order.
    """
    osr = host_os_release() if osr is None else osr
    ident = osr.get("ID", "").strip().lower()
    likes = osr.get("ID_LIKE", "").strip().lower().split()
    name = osr.get("PRETTY_NAME") or osr.get("NAME") or ""
    ver = osr.get("VERSION_ID", "")
    for cand in [ident, *likes]:
        if cand in DEBIAN_IDS:
            return HostDistro("debian", ident, name, ver, "/etc/os-release")
        if cand in FEDORA_IDS:
            return HostDistro("fedora", ident, name, ver, "/etc/os-release")
    if shutil.which("apt-get"):
        return HostDistro("debian", ident, name, ver, "apt-get on $PATH")
    if shutil.which("dnf"):
        return HostDistro("fedora", ident, name, ver, "dnf on $PATH")
    return HostDistro("unknown", ident, name, ver, "no package manager found")


def host_family() -> str:
    """"debian", "fedora" or "unknown" — the packaging convention to use."""
    return host_distro().family


def in_qube() -> bool:
    return Path("/usr/share/qubes/marker-vm").exists()


def in_wsl() -> str:
    """'' if this is not WSL, otherwise 'wsl2' or 'wsl1'."""
    try:
        rel = Path("/proc/sys/kernel/osrelease").read_text().lower()
    except OSError:
        return ""
    if "microsoft" not in rel:
        return ""
    return "wsl2" if "wsl2" in rel or os.environ.get("WSL_DISTRO_NAME") else "wsl1"


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


def fix_argv(fix_line: str) -> list[str]:
    """The argv `doctor --fix` should run for one `fix:` line.

    A fix line reads "./build_iso.py setup-host", which is only executable
    from the repository root and only if the file is marked executable. This
    used to build [sys.executable, *argv[1:]] — dropping the script path
    altogether — so every fix ran as `python3 setup-host` and died with
    "can't open file 'setup-host'". `doctor --fix` could not repair anything,
    on any host, ever. Re-running THIS file by its resolved path works from
    any directory. Split out so the invariant can be tested directly rather
    than by triggering a repair.
    """
    argv = shlex.split(fix_line.split("(")[0].strip())
    if argv and argv[0].endswith(".py"):
        return [sys.executable, str(Path(__file__).resolve()), *argv[1:]]
    return argv


# ---------------------------------------------------------------------------
#  doctor — read-only readiness report
# ---------------------------------------------------------------------------
def doctor(x: Ctx) -> int:
    x.phase("doctor", "is this build host ready?")
    # Before anything measures work_dir or reports where it will be.
    resolve_work_dir(x, fatal=False)
    c: list[Check] = []
    ce = x.c["container_engine"]
    tier2 = int(x.c["tier"]) == 2

    if Path("/etc/qubes-release").exists() and not in_qube():
        c.append(Check("not running in dom0", FAIL,
                       "dom0 has no network and must not build images",
                       "run this on a separate Debian-family or Fedora-family "
                       "host"))
    else:
        c.append(Check("not running in dom0", OK))

    d = host_distro()
    fam = d.family
    # Naming the distribution, not just the family: "debian" was printed for
    # Kali, Ubuntu and Mint alike, so this could not tell you what you were
    # actually running on — and the one thing that differs between them is
    # exactly which packages exist.
    c.append(Check("supported build host", OK if fam != "unknown" else FAIL,
                   f"{d.described()} — detected via {d.how}",
                   "qubes-builderv2 ships dependency lists for Debian and Fedora only"))

    # The docs called x86-64 the one real hardware requirement and nothing
    # checked it, so an ARM VM — an Apple Silicon Mac running Linux, say —
    # would have got hours in before failing. Every Qubes package and the
    # installer itself are built for x86-64.
    arch = os.uname().machine
    c.append(Check("x86-64 build host", OK if arch in ("x86_64", "amd64") else FAIL,
                   arch, "Qubes packages and the installer are x86-64 only — "
                         "this cannot be built on an ARM host or VM"))

    for tool in ("git", "curl", "gpg", "rsync"):
        c.append(Check(f"{tool} installed", OK if shutil.which(tool) else FAIL,
                       fix="./build_iso.py setup-host"))
    # Without one of these the build cannot confirm the investigator templates
    # actually made it into the finished image, which is the whole Tier 2 promise.
    reader = iso_reader()
    c.append(Check("a tool that can read an ISO's contents", OK if reader else FAIL,
                   reader or "none of bsdtar, 7z, isoinfo, xorriso",
                   fix="./build_iso.py setup-host"))
    ks_py, ks_from = kickstart_python(x)
    if ks_py:
        c.append(Check("pykickstart present (validates the generated kickstart)",
                       OK, ks_from))
    elif fam == "debian":
        # Telling a Debian or Kali operator to run setup-host here was advice
        # that could not work: pykickstart was removed from Debian in 2019 and
        # no suite of Debian or Kali carries it. setup-host now builds a
        # virtualenv for it, and if that is not wanted, saying what the
        # consequence actually is beats repeating an impossible fix.
        c.append(Check("pykickstart present (validates the generated kickstart)",
                       WARN, "no Debian or Kali package provides it",
                       "./build_iso.py setup-host  (installs it into a "
                       "virtualenv under work_dir)\n"
                       "           or accept it: the kickstart is then checked "
                       "after the build, by confirming the template RPMs are "
                       "in the finished ISO"))
    else:
        c.append(Check("pykickstart present (validates the generated kickstart)",
                       WARN, "missing — the kickstart is checked after the build "
                       "instead of before it", "./build_iso.py setup-host"))

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
                           "./build_iso.py setup-host  (it adds you to the group "
                           "and, if that is all that is missing, tells you the "
                           "'sg docker -c ...' line to use in THIS shell instead "
                           "of logging out)"))
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

    wsl = in_wsl()
    if wsl:
        # A real Linux kernel, so the scripts themselves run fine. What is NOT
        # established is that qubes-builderv2's Mock chroots and loop-device
        # work behave under WSL — upstream neither supports nor tests it.
        c.append(Check("running under WSL", WARN, wsl,
                       "qubes-builderv2 is not tested on WSL. A Debian 13 VM "
                       "(Hyper-V/VirtualBox/VMware) is the path that is known to "
                       "work. See docs/GUIDE.md section 2."))
        if wsl == "wsl1":
            c.append(Check("WSL version supports containers", FAIL,
                           "WSL1 has no real kernel — Docker cannot run",
                           "wsl --set-version <distro> 2"))
        if not Path("/dev/loop-control").exists():
            c.append(Check("loop devices available", FAIL, "no /dev/loop-control",
                           "the ISO build needs them; use a VM instead"))
        else:
            c.append(Check("loop devices available", OK))
        try:
            sysd = Path("/proc/1/comm").read_text().strip()
        except OSError:
            sysd = "?"
        c.append(Check("systemd is PID 1 (WSL needs it enabled)",
                       OK if sysd == "systemd" else WARN, f"PID 1 is {sysd}",
                       "put 'systemd=true' under [boot] in /etc/wsl.conf, then "
                       "'wsl --shutdown' from Windows"))

    if in_qube():
        conf = Path("/rw/config/qubes-bind-dirs.d/50_docker.conf")
        c.append(Check("Docker storage persists across reboots (app qube)",
                       OK if conf.exists() else FAIL,
                       "this is a Qubes app qube",
                       "./build_iso.py setup-host  (writes the bind-dirs entry)"))

    try:
        import yaml                                          # noqa: F401
        c.append(Check("PyYAML present (builder.yml is merged, not appended)",
                       OK))
    except ImportError:
        c.append(Check("PyYAML present (builder.yml is merged, not appended)",
                       FAIL, "missing — python3-yaml on Debian and Kali, "
                       "python3-pyyaml on Fedora", "./build_iso.py setup-host"))

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
        return 0

    if not getattr(x.args, "fix", False):
        print(f"\n  ./build_iso.py doctor --fix   runs the fixes above that this "
              f"script owns.\n")
        return rc

    # Only this script's own subcommands, and only for blocking rows. Nothing
    # here reaches for sudo on its own account beyond what setup-host already
    # does with your confirmation.
    blocking = [ch for ch in c if ch.state == FAIL and ch.fix]
    ran = set()
    for ch in blocking:
        fix = ch.fix.splitlines()[0].strip()
        if not fix.startswith("./build_iso.py") or fix in ran:
            continue
        ran.add(fix)
        argv = fix_argv(fix)
        print(f"\n  running: {fix}")
        rc2 = subprocess.run(argv).returncode
        if rc2 != 0:
            x.warn(f"that did not succeed (exit {rc2})")
    unfixable = [ch.name for ch in blocking
                 if not ch.fix.splitlines()[0].strip().startswith("./build_iso.py")]
    if unfixable:
        print()
        for n in unfixable:
            x.warn(f"not something this script can fix: {n}")
    print("\n  re-checking\n")
    x.args.fix = False
    return doctor(x)


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
# What the build host needs, by CAPABILITY rather than by package name.
#
# Two hardcoded lists — one for Debian, one for Fedora — asserted that a given
# name exists on every distribution in that family, and twice it did not:
#
#   * `python3-pykickstart` was removed from Debian in 2019 and has never been
#     in Kali. `apt-get install -y` fails the WHOLE batch on one unknown name
#     and exits 100, so setup-host died on a fresh Debian-family host before
#     installing anything at all.
#   * `pykickstart` and `bsdtar` are not Fedora binary package names either
#     (Fedora ships python3-kickstart, and bsdtar comes from libarchive).
#
# Naming several candidates per capability and asking the package manager
# which of them exists fixes the class of bug rather than the two instances.
# Order within a list is preference order; the first one the host can actually
# install wins.
def host_package_plan(fam: str, ce: str) -> list[tuple[str, list[str]]]:
    """(what it is for, candidate package names in preference order)."""
    if fam == "debian":
        engine = {"docker": ["docker.io", "docker-ce"],
                  "podman": ["podman"]}.get(ce, [ce])
        return [
            (f"{ce} (the build cages)", engine),
            ("git", ["git"]),
            ("curl", ["curl"]),
            ("gpg", ["gnupg", "gnupg2"]),
            ("rsync", ["rsync"]),
            ("python3", ["python3"]),
            # builder.yml is merged rather than appended, and without PyYAML
            # this script refuses to edit it at all.
            ("YAML, to edit builder.yml safely", ["python3-yaml"]),
            # Lets the build confirm the investigator templates are really
            # inside the finished ISO — the whole Tier 2 promise.
            ("a reader for the finished ISO",
             ["libarchive-tools", "p7zip-full", "xorriso"]),
            # For the pykickstart virtualenv below, when the distribution has
            # no package for it.
            ("venv support, for the kickstart validator",
             ["python3-venv", "python3-virtualenv"]),
            ("kickstart validation", ["python3-pykickstart"]),
        ]
    # "docker" is NOT a Fedora binary package name — it is a virtual provide of
    # moby-engine, so `dnf list docker` finds nothing and the old hardcoded
    # entry could never have been resolved by name. Fedora also splits the CLI
    # out of the engine, hence the separate docker-cli capability below.
    engine = {"docker": ["moby-engine", "docker-ce"],
              "podman": ["podman"]}.get(ce, [ce])
    plan = [
        (f"{ce} (the build cages)", engine),
        ("git", ["git"]),
        ("curl", ["curl"]),
        ("gpg", ["gnupg2", "gnupg"]),
        ("rsync", ["rsync"]),
        ("python3", ["python3"]),
        ("YAML, to edit builder.yml safely", ["python3-pyyaml"]),
        # bsdtar is its own Fedora binary package, built from the libarchive
        # source package but not shipped by the libarchive binary one.
        ("a reader for the finished ISO", ["bsdtar", "p7zip", "xorriso"]),
        # python3-kickstart is the importable module, which is all this needs
        # — nothing here runs ksvalidator or ksflatten. The package named
        # "pykickstart" is the command-line tool; it depends on the module, so
        # it works too, and is kept as a fallback for a Fedora that has only
        # that name.
        ("kickstart validation", ["python3-kickstart", "pykickstart"]),
    ]
    if ce == "docker":
        plan.insert(1, ("the docker command (split from the engine in Fedora)",
                        ["docker-cli"]))
    return plan


# `dnf list` prints "name.arch"; strip only a real architecture suffix, so a
# package whose name legitimately contains a dot is not truncated.
_RPM_ARCHES = ("x86_64", "noarch", "i686", "aarch64", "src")


def packages_available(fam: str, names: list[str]) -> set[str] | None:
    """Which of `names` this host's package manager can actually install.

    Returns None — meaning "could not tell" — rather than an empty set when
    the probe itself did not work, because an empty set and a broken probe
    demand opposite responses: skip those packages, versus try them anyway.
    A completely empty result is treated as a broken probe too, since an apt
    cache that has never been updated answers "no" to everything.

    Known limitation, and it fails safe: on Debian a purely virtual package
    with exactly ONE provider is installable by name, but `apt-cache policy`
    reports it as `Candidate: (none)`, so it is treated as unavailable here.
    The caller names every package it skips, so the worst case is a visible
    warning about something that would have installed — not a silent drop.
    """
    if not names:
        return set()
    # apt and dnf translate their output. Parsing "Candidate:" against a
    # localised host would find nothing, and this would report every package
    # as missing on, say, a French install.
    env = {**os.environ, "LC_ALL": "C", "LANGUAGE": "C", "LANG": "C"}
    try:
        if fam == "debian":
            if not shutil.which("apt-cache"):
                return None
            p = subprocess.run(["apt-cache", "policy", *names], env=env,
                               capture_output=True, text=True, timeout=180)
            found, cur = set(), ""
            for line in p.stdout.splitlines():
                if line[:1] not in (" ", "\t") and line.rstrip().endswith(":"):
                    cur = line.rstrip()[:-1].strip()
                elif cur and line.strip().startswith("Candidate:"):
                    if line.split(":", 1)[1].strip() not in ("(none)", ""):
                        found.add(cur)
                    cur = ""
            found &= set(names)
            return found or None
        if fam == "fedora":
            if not shutil.which("dnf"):
                return None
            found = set()
            # One call for the whole set rather than one per package: dnf
            # lists every name it knows and complains about the rest.
            p = subprocess.run(["dnf", "--quiet", "list", *names], env=env,
                               capture_output=True, text=True, timeout=300)
            want = {n.lower(): n for n in names}
            for line in p.stdout.splitlines():
                tok = line.split()[0].lower() if line.split() else ""
                stem, _, arch = tok.rpartition(".")
                for cand in (tok, stem if arch in _RPM_ARCHES else ""):
                    if cand in want:
                        found.add(want[cand])
                        break
            # `dnf list` matches package NAMES only, but `dnf install` also
            # resolves virtual provides — "docker" installs moby-engine,
            # which merely Provides it. Probing with list alone would report a
            # name as unavailable that installs perfectly well, so ask what
            # provides the ones that missed before giving up on them.
            for n in (n for n in names if n not in found):
                q = subprocess.run(
                    ["dnf", "--quiet", "repoquery", "--whatprovides", n],
                    env=env, capture_output=True, text=True, timeout=180)
                if q.returncode == 0 and q.stdout.strip():
                    found.add(n)
            return found or None
    except (OSError, subprocess.TimeoutExpired):
        return None
    return None


def resolve_host_packages(x: Ctx, fam: str,
                          ce: str) -> tuple[list[str], list[str], bool]:
    """Pick one real package per capability.

    Returns (install, unavailable, probed). `unavailable` names the
    capabilities this distribution has no package for at all, so setup-host
    can say which ones it is skipping and why instead of failing the whole
    batch on them. `probed` is False when the package manager could not be
    asked, which tells the caller not to bother with a batch install — a name
    in the list is then expected to be wrong.
    """
    plan = host_package_plan(fam, ce)
    every = sorted({n for _, cands in plan for n in cands})
    avail = packages_available(fam, every)
    if avail is None:
        x.info("could not ask the package manager what it has (no cache yet?) "
               "— trying the preferred name for each, one at a time so a "
               "single unknown name cannot fail the rest")
        return [cands[0] for _, cands in plan], [], False
    install, missing = [], []
    for purpose, cands in plan:
        pick = next((c for c in cands if c in avail), "")
        if pick:
            install.append(pick)
        else:
            missing.append(f"{purpose} (no package named {' or '.join(cands)})")
    return install, missing, True


# ---------------------------------------------------------------------------
#  pykickstart — available on Fedora as a package, nowhere on Debian
#
#  pykickstart was removed from Debian unstable in August 2019 and is in no
#  current Debian or Kali suite. `doctor` warned that it was missing and told
#  the operator to run `setup-host`, which could not install it either: advice
#  that cannot work is worse than no advice. It is a pure-Python package on
#  PyPI, so the honest options are to install it into a virtualenv owned by
#  this script, or to say plainly that the kickstart is checked after the
#  build instead of before it. Both are implemented; setup-host tries the
#  first, and doctor reports whichever is true.
# ---------------------------------------------------------------------------
def kickstart_venv(x: Ctx) -> Path:
    return x.work / ".venv-pykickstart"


def _can_import_pykickstart(python: str) -> bool:
    try:
        return subprocess.run([python, "-c", "import pykickstart"],
                              capture_output=True, stdin=subprocess.DEVNULL,
                              timeout=120).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def kickstart_python(x: Ctx) -> tuple[str, str]:
    """(interpreter that can import pykickstart, where it came from).

    ("", "") when there is none, which is not fatal anywhere — it downgrades
    kickstart validation from before the build to after it.
    """
    if _can_import_pykickstart(sys.executable):
        return sys.executable, "system"
    venv = kickstart_venv(x) / "bin" / "python3"
    if venv.is_file() and _can_import_pykickstart(str(venv)):
        return str(venv), f"virtualenv at {kickstart_venv(x)}"
    return "", ""


def ensure_pykickstart(x: Ctx) -> None:
    """Install pykickstart into a virtualenv when no package provides it.

    Deliberately not `pip install --break-system-packages`: Debian and Kali
    mark their system interpreter externally managed (PEP 668) and overriding
    that to satisfy a build-time validator is not a trade this script should
    make on the operator's behalf. A virtualenv under work_dir is disposable
    and touches nothing the distribution owns.
    """
    if kickstart_python(x)[0]:
        return
    venv = kickstart_venv(x)
    x.info(f"no distribution package provides pykickstart here — installing it "
           f"into {venv}")
    try:
        venv.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        x.warn(f"cannot create {venv.parent} ({e}) — the generated kickstart "
               "will be checked after the build instead of before it")
        return
    py = venv / "bin" / "python3"
    if not py.is_file():
        x.run(sys.executable, "-m", "venv", str(venv), check=False, live=True)
    if not py.is_file():
        x.warn("could not create the virtualenv — install python3-venv "
               "(Debian, Kali, Ubuntu) and re-run ./build_iso.py setup-host. "
               "Until then the generated kickstart is checked after the build "
               "instead of before it")
        return
    # A virtualenv left behind by an interrupted run, or one made with
    # --without-pip, has an interpreter but nothing to install with. Repair it
    # rather than running pip against it and reporting the failure as a
    # network problem, which is what the error would otherwise look like.
    if not x.quiet(str(py), "-m", "pip", "--version"):
        x.info("the virtualenv has no pip — repairing it")
        x.run(str(py), "-m", "ensurepip", "--upgrade", check=False, live=True)
    if not x.quiet(str(py), "-m", "pip", "--version"):
        x.warn(f"{venv} has no working pip and ensurepip could not add one — "
               "remove it and re-run ./build_iso.py setup-host, or accept "
               "that the kickstart is checked after the build instead")
        return
    x.run(str(py), "-m", "pip", "install", "--quiet", "--upgrade",
          "pykickstart", check=False, live=True)
    if kickstart_python(x)[0]:
        x.ok(f"pykickstart available via {venv}")
    else:
        x.warn("pip could not install pykickstart (no network?) — the "
               "generated kickstart will be checked after the build instead "
               "of before it")


def iso_reader() -> str:
    """The first tool on this host that can list an ISO's contents, or ""."""
    return next((t for t in ("bsdtar", "7z", "7za", "isoinfo", "xorriso")
                 if shutil.which(t)), "")


def _have_module(name: str) -> bool:
    """Whether this interpreter can import `name`.

    Catches every exception, not just ImportError: a half-installed or
    version-mismatched module can raise almost anything at import time, and a
    host-readiness probe must report "no" rather than take setup-host down
    with it.
    """
    try:
        __import__(name)
        return True
    except Exception:
        return False


def host_gaps(ce: str, need_ks: bool = False) -> list[str]:
    """Everything the build host is missing that a package can supply.

    This used to probe five binaries and nothing else, so on a host that
    already had git, curl, gpg, rsync and Docker — which is to say, most
    hosts — setup-host installed no packages at all. python3-yaml and the ISO
    reader stayed missing, and `doctor` then blocked on python3-yaml with the
    fix "./build_iso.py setup-host", which had just decided there was nothing
    to do. Probing the capabilities that are actually required breaks that
    loop.
    """
    gaps = [t for t in ("git", "curl", "gpg", "rsync", ce) if not shutil.which(t)]
    if not _have_module("yaml"):
        # Named by what it is, not by one distribution's package name: this
        # message is printed on Fedora hosts too, where it is python3-pyyaml.
        gaps.append("PyYAML")
    if not iso_reader():
        gaps.append("an ISO reader (bsdtar/7z/isoinfo/xorriso)")
    # A missing kickstart validator is a gap on BOTH families, and probing
    # only Debian's half of it — ensurepip, which python3-venv supplies — left
    # the worse case unfixed: a Fedora host that already had everything else
    # skipped the package step entirely and went to PyPI for a module dnf
    # packages as python3-kickstart. Whatever the distribution has for this,
    # the install step is what fetches it.
    if need_ks:
        gaps.append("a kickstart validator (a package where one exists, or "
                    "the venv support to install one where none does)")
    return gaps


def install_packages(x: Ctx, fam: str, pkgs: list[str], batch: bool = True) -> None:
    """Install pkgs so that one bad name cannot cost you the rest.

    `apt-get install -y` exits 100 on a single unknown name and installs
    nothing at all — which is how one package removed from Debian in 2019
    stopped setup-host from installing the other eight. The batch is tried
    first because it is much faster; on failure every package is retried on
    its own. Pass batch=False when the availability probe did not work, since
    then a name in the list is expected to be wrong.
    """
    if not pkgs:
        x.warn("nothing left to install")
        return
    base = ["apt-get", "install", "-y"] if fam == "debian" else ["dnf", "install", "-y"]
    if batch:
        try:
            x.run(*_sudo([*base, *pkgs]), live=True)
            x.ok(f"installed: {' '.join(pkgs)}")
            return
        except Fatal:
            x.warn("the batch install failed — retrying one package at a time "
                   "so one unavailable package cannot block the rest")
    done, failed = [], []
    for pkg in pkgs:
        try:
            x.run(*_sudo([*base, pkg]), live=True)
            done.append(pkg)
        except Fatal:
            failed.append(pkg)
    if done:
        x.ok(f"installed: {' '.join(done)}")
    if failed:
        x.warn(f"could not install: {' '.join(failed)} — "
               "./build_iso.py doctor says whether that actually blocks a build")


def install_host_packages(x: Ctx, fam: str, ce: str) -> None:
    """Install one real package per capability, and say what it could not."""
    install, unavailable, probed = resolve_host_packages(x, fam, ce)
    for gap in unavailable:
        x.warn(f"no package on this host for {gap} — skipping it rather than "
               "failing the whole install")
    install_packages(x, fam, install, batch=probed)


def setup_host(x: Ctx) -> int:
    x.phase("setup-host", "install and configure the build host")
    d = host_distro()
    fam = d.family
    if fam == "unknown":
        raise Fatal(f"unsupported build host: {d.described()}.\n"
                    "     qubes-builderv2 ships dependency lists for Debian and\n"
                    "     Fedora families only, and this needs apt-get or dnf.")
    x.info(f"build host: {d.described()}  [detected via {d.how}]")
    # Before the plan names a directory to create and a virtualenv to put
    # inside it.
    resolve_work_dir(x, fatal=False)
    ce = x.c["container_engine"]
    plan: list[list[str]] = []

    # Resolved once: it decides both whether the package step has something to
    # fetch for the kickstart validator and whether the virtualenv step is
    # listed at all. The virtualenv step re-checks and does nothing if the
    # package install satisfied it, so a Fedora host uses its own package.
    need_ks = not kickstart_python(x)[0]
    gaps = host_gaps(ce, need_ks)
    if gaps:
        x.info("missing on this host: " + ", ".join(gaps))
        if fam == "debian":
            plan.append(_sudo(["apt-get", "update"]))
        plan.append(["__packages__", fam, ce])

    if ce == "docker":
        plan.append(_sudo(["systemctl", "enable", "--now", "docker"]))
        user = os.environ.get("SUDO_USER") or os.environ.get("USER") or ""
        groups = subprocess.run(["id", "-nG"], capture_output=True, text=True).stdout.split()
        if user and "docker" not in groups:
            plan.append(_sudo(["usermod", "-aG", "docker", user]))

    # pykickstart is not packaged on every distribution, and where it is not
    # the only way to have it is a virtualenv and a download from PyPI. That
    # is a network install of third-party code: it belongs in the plan the
    # operator approves, not quietly after it. Listed conditionally because
    # the package install above may still provide it — ensure_pykickstart
    # re-checks and does nothing if it did.
    # Before the virtualenv that goes inside it, so the plan reads in the
    # order it runs. Only when it is actually absent: appending it
    # unconditionally made the "nothing to do — the host is already set up"
    # branch below unreachable, so a fully prepared host was still asked to
    # approve a plan.
    if not x.work.is_dir():
        plan.append(["__mkdir__", str(x.work)])

    if need_ks:
        plan.append(["__pykickstart__"])

    if in_qube():
        plan.append(["__bind_dirs__"])

    if not plan:
        x.ok("nothing to do — the host is already set up")
        return doctor(x)

    print("\n  This will run:")
    for cmd in plan:
        if cmd[0] == "__bind_dirs__":
            print("      write /rw/config/qubes-bind-dirs.d/50_docker.conf "
                  "(persist /var/lib/docker across reboots)")
        elif cmd[0] == "__packages__":
            mgr = "apt-get" if cmd[1] == "debian" else "dnf"
            print(f"      {mgr} install -y  — one package per capability below,")
            for purpose, cands in host_package_plan(cmd[1], cmd[2]):
                print(f"          {purpose}: {' or '.join(cands)}")
            print("        whichever of each line this host actually has; "
                  "anything it has none of is reported and skipped")
        elif cmd[0] == "__pykickstart__":
            print("      IF no package on this host provides pykickstart:")
            print(f"          python3 -m venv {kickstart_venv(x)}")
            print("          then, inside it:  pip install pykickstart   "
                  "(downloaded from PyPI)")
            print("        it validates the generated kickstart BEFORE the "
                  "build. Decline and the")
            print("        build still runs — the same thing is confirmed "
                  "afterwards from the ISO.")
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
        elif cmd[0] == "__packages__":
            install_host_packages(x, cmd[1], cmd[2])
        elif cmd[0] == "__pykickstart__":
            ensure_pykickstart(x)
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
    if not uid and len({f for f, _ in have}) == 1:
        # Exactly one signing key in this keyring and no identity given: adopting
        # it is the only thing the operator can have meant.
        fpr = have[0][0]
        x.info(f"one secret key in this keyring — adopting it rather than making "
               f"a second")
        return _adopt_key(x, fpr)
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
    pf = getattr(x.args, "passphrase_file", None)
    if pf and not nopass:
        x.run("gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
              "--passphrase-file", str(pf), "--quick-generate-key", uid,
              "rsa4096", "sign", expire, live=True)
    elif nopass:
        x.run("gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
              "--passphrase", "", "--quick-generate-key", uid,
              "rsa4096", "sign", expire, live=True)
    else:
        if not sys.stdin.isatty():
            raise Fatal("generating a passphrase-protected key needs a terminal.\n"
                        "     Run this in an interactive shell, pass\n"
                        "     --passphrase-file <path> for a scripted process, or\n"
                        "     accept an unprotected key with --no-passphrase.")
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
#  backup-key / restore-key
#
#  The signing key lives in the build host's GPG keyring, and nothing was
#  keeping a copy of it. Lose the build host — a reinstalled machine, a deleted
#  WSL distro, a discarded VM — and every image you ever signed becomes
#  unverifiable and unrenewable, because the fingerprint your colleagues trust
#  is gone. That is not a step to remember; it is a command.
# ---------------------------------------------------------------------------
def backup_key(x: Ctx) -> int:
    x.phase("backup-key", "back up the signing key")
    fpr = (getattr(x.args, "use_key", None) or x.c["iso_sign_key"] or "").replace(
        " ", "").upper()
    if not re.fullmatch(r"[0-9A-F]{40}", fpr or ""):
        raise Fatal("no signing key to back up. ./build_iso.py gen-key first, or "
                    "pass --use-key <fingerprint>.")
    if not x.quiet("gpg", "--list-secret-keys", fpr):
        raise Fatal(f"no SECRET key for {fpr} in this keyring")
    dest = Path(getattr(x.args, "to", None) or (x.out_dir / "key-backup"))
    if x.args.dry_run:
        x.info(f"[dry-run] export {fpr} (secret key, revocation certificate, "
               f"public key) to {dest}")
        return 0
    dest.mkdir(parents=True, exist_ok=True)
    dest.chmod(0o700)
    old_umask = os.umask(0o077)
    try:
        sec = dest / f"{fpr}-secret.asc"
        if not getattr(x.args, "passphrase_file", None):
            if not sys.stdin.isatty():
                raise Fatal("backing up a key needs a terminal for the "
                            "passphrase prompts, or --passphrase-file <path> "
                            "to encrypt the backup non-interactively.")
            x.info("gpg will ask for the key's passphrase, and then for a "
                   "passphrase to encrypt the backup with. They may differ; both "
                   "are needed to restore.")
        # Encrypted at rest with a passphrase, not a bare export: this file is
        # about to be carried somewhere.
        rc = subprocess.run(
            ["gpg", "--export-secret-keys", "--armor", "--output", str(sec), fpr]
        ).returncode
        if rc != 0 or not sec.exists():
            raise Fatal(f"gpg could not export the secret key (exit {rc})")
        sec.chmod(0o600)
        enc = dest / f"{fpr}-secret.asc.gpg"
        enc.unlink(missing_ok=True)
        pf = getattr(x.args, "passphrase_file", None)
        argv = ["gpg", "--symmetric", "--cipher-algo", "AES256",
                "--output", str(enc)]
        if pf:
            # For a unit that scripts this into its own key-management process.
            argv[1:1] = ["--batch", "--yes", "--pinentry-mode", "loopback",
                         "--passphrase-file", str(pf)]
        rc = subprocess.run(argv + [str(sec)]).returncode
        if rc != 0 or not enc.exists():
            sec.unlink(missing_ok=True)
            raise Fatal("could not encrypt the exported key; the plaintext export "
                        "has been removed.")
        # Overwrite the plaintext export rather than merely unlinking it.
        with sec.open("r+b") as fh:
            n = fh.seek(0, 2)
            fh.seek(0)
            fh.write(b"\0" * n)
            fh.flush()
            os.fsync(fh.fileno())
        sec.unlink()
        enc.chmod(0o600)
        x.ok(f"secret key -> {enc.name} (AES256, passphrase-protected)")

        rev = dest / f"{fpr}-revocation.asc"
        if not rev.exists():
            # GNUPGHOME, not an assumed ~/.gnupg: a unit that keeps its keyring
            # elsewhere would otherwise silently get a backup with no way to
            # revoke the key it contains.
            home = Path(os.environ.get("GNUPGHOME") or (Path.home() / ".gnupg"))
            src = home / "openpgp-revocs.d" / f"{fpr}.rev"
            if src.is_file():
                shutil.copy2(src, rev)
                rev.chmod(0o600)
                x.ok(f"revocation certificate -> {rev.name}")
            else:
                x.warn("no pre-generated revocation certificate found; generate "
                       "one with 'gpg --gen-revoke' and keep it with this backup")
        pub = dest / f"{fpr}-public.asc"
        x.quiet("gpg", "--batch", "--yes", "--armor", "--output", str(pub),
                "--export", fpr)
        (dest / "README.txt").write_text(f"""\
Signing key backup — {x.c['iso_flavor']}
Fingerprint: {fpr}
Taken: {datetime.now():%Y-%m-%d %H:%M:%S} on {os.uname().nodename}

  {fpr}-secret.asc.gpg   the private key, AES256, passphrase-protected
  {fpr}-revocation.asc   use this if the key is ever compromised
  {fpr}-public.asc       hand this to colleagues

Restore on another machine:

    ./build_iso.py restore-key --from <this directory>

THIS IS THE KEY THAT SIGNS IMAGES YOUR UNIT INSTALLS. Whoever holds it and its
passphrase can sign an image your colleagues will trust. Store it the way you
store other private key material — not beside the ISOs it signs.
""")
        x.ok(f"backup written to {dest}")
    finally:
        os.umask(old_umask)
    x.warn("carry this off the build host. A backup on the machine that would "
           "lose the key protects you from nothing.")
    return 0


def restore_key(x: Ctx) -> int:
    x.phase("restore-key", "restore the signing key")
    src = Path(getattr(x.args, "from_dir", None) or (x.out_dir / "key-backup"))
    if not src.is_dir():
        raise Fatal(f"no backup directory at {src} — pass --from <directory>")
    enc = sorted(src.glob("*-secret.asc.gpg"))
    if not enc:
        raise Fatal(f"no *-secret.asc.gpg in {src}")
    fpr = enc[0].name.split("-secret")[0].upper()
    if x.args.dry_run:
        x.info(f"[dry-run] import {fpr} from {enc[0]}")
        return 0
    if x.quiet("gpg", "--list-secret-keys", fpr):
        x.ok(f"{fpr} is already in this keyring")
    else:
        x.info("gpg will ask for the backup passphrase, then the key's own.")
        pf = getattr(x.args, "passphrase_file", None)
        argv = ["gpg", "--decrypt"]
        if pf:
            argv[1:1] = ["--batch", "--pinentry-mode", "loopback",
                         "--passphrase-file", str(pf)]
        dec = subprocess.run(argv + [str(enc[0])], capture_output=True)
        if dec.returncode != 0 or not dec.stdout:
            raise Fatal("could not decrypt the backup — wrong passphrase?")
        imp = subprocess.run(["gpg", "--batch", "--import"], input=dec.stdout,
                             capture_output=True)
        if imp.returncode != 0:
            raise Fatal(f"gpg could not import the key: "
                        f"{imp.stderr.decode(errors='replace')[:300]}")
        if not x.quiet("gpg", "--list-secret-keys", fpr):
            raise Fatal(f"import reported success but {fpr} is not in the keyring")
        x.ok(f"imported {fpr}")
    return _adopt_key(x, fpr)


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


def largest_writable_mount(need_gb: int) -> Path | None:
    """The biggest local filesystem with room for the build, or None."""
    best, best_free = None, -1
    try:
        mounts = Path("/proc/mounts").read_text().splitlines()
    except OSError:
        return None
    for line in mounts:
        f = line.split()
        if len(f) < 3 or not f[0].startswith("/dev/"):
            continue
        if f[2] in ("squashfs", "iso9660", "vfat", "tmpfs", "overlay"):
            continue
        mp = Path(f[1])
        free = _free_gb(mp)
        if free is None or free < need_gb or not os.access(mp, os.W_OK):
            continue
        if free > best_free:
            best, best_free = mp, free
    return best


def resolve_work_dir(x: Ctx, fatal: bool = True) -> None:
    """Turn work_dir "auto" into a real path and re-point everything at it.

    This used to happen only on the build path, so `doctor` and `setup-host`
    saw the literal string "auto" — a RELATIVE path. `doctor` then measured
    free space on the current directory and reported "will be created under
    .", and `setup-host` planned `mkdir -p auto`, creating a directory of that
    name wherever you happened to be standing. Both are asked, by name, to
    tell you whether the host is ready; both have to resolve it first.

    `fatal` is False for those two, because a read-only report and a host
    setup step should say what is wrong rather than abort.
    """
    if str(x.c.get("work_dir", "")).lower() != "auto":
        return
    need = 250 if int(x.c["tier"]) == 2 else 100
    mp = largest_writable_mount(need)
    if mp is None and not fatal:
        # Nothing is big enough. Still resolve somewhere real, so the report
        # that follows is about a filesystem rather than about "auto".
        mp = largest_writable_mount(0)
        if mp is not None:
            x.warn(f"work_dir is 'auto' and no writable filesystem has {need}G "
                   f"free — reporting against the largest one, {mp}")
    if mp is None:
        if not fatal:
            x.warn("work_dir is 'auto' and no writable filesystem could be "
                   "found to resolve it against")
            return
        raise Fatal(f"work_dir is 'auto' but no writable filesystem has "
                    f"{need}G free. Point it somewhere explicitly:\n"
                    f"     ./build_iso.py --set work_dir=/path/with/space")
    chosen = mp / "investigator-iso"
    x.c["work_dir"] = str(chosen)
    x.work = chosen
    x.builder = chosen / "qubes-builderv2"
    x.component = chosen / "qubes-template-investigator"
    x.out_dir = chosen / "output"
    x.log = chosen / "build.log"
    x.state = chosen / ".state"
    x.info(f"work_dir resolved to {chosen} ({_free_gb(mp)}G free)")


def resolve_auto_values(x: Ctx) -> None:
    """Derive the settings the guide used to make the operator match by hand."""
    resolve_work_dir(x)
    if str(x.c.get("mock_config", "")).lower() in ("", "auto"):
        rel = str(x.c["qubes_release"]).lstrip("rR")
        # The Mock chroot must match the HOST distribution of the Qubes release,
        # which is the Fedora dom0 is built on. Read it from the fetched builder
        # rather than guessing; fall back to the release's known host.
        derived = mock_config_from_builder(x) or {"4.3": "fedora-41-x86_64",
                                                  "4.2": "fedora-37-x86_64"}.get(rel)
        if derived:
            x.c["mock_config"] = derived
            x.info(f"mock_config derived as {derived}")
        elif not shutil.which("mock"):
            # Only the mock branch of tools/generate-container-image.sh reads
            # this value, and that branch is taken only when mock is on the
            # host. Failing the whole run over a value about to be discarded
            # made a release this script has no fallback for unbuildable on
            # exactly the hosts — Debian, Kali — where mock does not exist.
            # mock_config is left as "auto" rather than blanked: nothing reads
            # it on this path, and a later run on a host that HAS mock derives
            # it properly.
            x.info(f"no mock_config for Qubes {rel}, but mock is not installed "
                   "here, so the container image is built from the pinned "
                   "Fedora image and does not need one")
        else:
            raise Fatal(f"cannot derive mock_config for Qubes {rel}. "
                        f'Set it explicitly:  ./build_iso.py --set mock_config=fedora-NN-x86_64')


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


def upstream_check_is_stale(x: Ctx) -> bool:
    """Has the supply chain been checked recently enough to skip it now?"""
    days = int(x.c["check_upstream_max_age_days"])
    if days <= 0:
        return False
    if not LOCK_PATH.exists():
        return True
    try:
        when = json.loads(LOCK_PATH.read_text()).get("checked", "")
        age = (datetime.now() - datetime.strptime(when, "%Y-%m-%d")).days
    except (OSError, ValueError, json.JSONDecodeError):
        return True
    if age < days:
        x.info(f"supply chain last checked {age} day(s) ago — skipping "
               f"(check_upstream_max_age_days = {days})")
        return False
    return True


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
        # docs/VERIFICATION.md says: "Do this cross-check on first build rather
        # than trusting the blog post alone. Two independent sources agreeing is
        # the standard you want before a police workstation trusts a package
        # repository." So do it, every time, rather than asking.
        try:
            page = _fetch(k["keyserver_url"]).decode("utf-8", "replace")
            c.append(Check("Kali: an independent keyserver knows this key",
                           OK if k["key_fpr"].upper() in page.upper().replace(" ", "")
                           else WARN,
                           "keyserver.ubuntu.com",
                           "two independent sources agreeing is the standard "
                           "before a police workstation trusts a repository"))
        except Exception as e:                               # noqa: BLE001
            c.append(Check("Kali: independent keyserver reachable", WARN,
                           f"{type(e).__name__}: {e}"))
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

    # --- the vendor scripts phase 8 runs as root ----------------------
    try:
        import hashlib
        series = ".".join(str(x.c["wazuh"]["version"]).split(".")[:2])
        seen["wazuh_tools"] = {}
        for tool in ("wazuh-certs-tool.sh", "wazuh-passwords-tool.sh"):
            digest = hashlib.sha256(
                _fetch(f"https://packages.wazuh.com/{series}/{tool}")).hexdigest()
            seen["wazuh_tools"][tool] = digest
            known = lock.get("wazuh_tools", {}).get(tool)
            c.append(Check(f"Wazuh: {tool} unchanged since the last check",
                           OK if known in (None, digest) else WARN,
                           digest[:16] + "…",
                           "it runs as root against the SIEM — read the diff, then "
                           "update wazuh.certs_tool_sha256 / "
                           "wazuh.passwords_tool_sha256 in golden-image.json"))
    except Exception as e:                                   # noqa: BLE001
        c.append(Check("Wazuh: vendor scripts reachable", WARN,
                       f"{type(e).__name__}: {e}"))

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

# The fingerprint you were given through a channel INDEPENDENT of this media.
# Pass it and the comparison stops being something you do by eye:
#     ./verify-iso.sh <fingerprint>       or   EXPECT_FPR=... ./verify-iso.sh
EXPECT=$(printf '%s' "${{1:-${{EXPECT_FPR:-}}}}" | tr -d ' ' | tr 'a-f' 'A-F')

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
    if [ -n "$EXPECT" ]; then
        if [ "$signer" = "$EXPECT" ]; then
            printf '  Matches the fingerprint you supplied.\\n\\n'
        else
            printf '  Expected:   %s\\n' "$EXPECT"
            printf '\\n  *** MISMATCH. Do not install this image. ***\\n\\n'
            exit 1
        fi
    else
        printf '\\n  COMPARE that fingerprint against the one you were given through a\\n'
        printf '  channel INDEPENDENT of this media. If they differ, stop.\\n'
        printf '  Or let the script compare it for you:\\n'
        printf '      ./verify-iso.sh <fingerprint>\\n\\n'
    fi
else
    printf '\\n  WARNING: this image is UNSIGNED. Do not install it.\\n\\n'
    exit 1
fi
""")
    script.chmod(0o755)
    x.ok(f"verification script written: {script.name}")


# ---------------------------------------------------------------------------
#  sign — for the key that lives somewhere else
#
#  docs/SIGNING.md says: if the key is on a smartcard or a different machine,
#  build unsigned and sign afterwards on the machine that holds it. That was
#  three commands typed from memory on a machine that has never seen this
#  repository, and it left the checksum, the exported public key, the
#  fingerprint sheet and verify-iso.sh unregenerated.
# ---------------------------------------------------------------------------
def sign_iso(x: Ctx) -> int:
    x.phase("sign", "sign an image built elsewhere")
    iso = Path(getattr(x.args, "iso", None) or (x.out_dir / x.c["iso_name"]))
    if not iso.is_file():
        raise Fatal(f"no image at {iso} — pass --iso <path>")
    fpr = (getattr(x.args, "use_key", None) or x.c["iso_sign_key"] or "").replace(
        " ", "").upper()
    if not re.fullmatch(r"[0-9A-F]{40}", fpr or ""):
        raise Fatal("no signing key. Pass --use-key <fingerprint>, or set "
                    "iso_sign_key with ./build_iso.py gen-key.")
    if not x.quiet("gpg", "--list-secret-keys", fpr):
        raise Fatal(f"no SECRET key for {fpr} in this keyring. This command is "
                    f"meant to run on the machine that holds the key.")
    x.c["iso_sign_key"] = fpr
    if iso.parent != x.out_dir:
        x.out_dir = iso.parent

    import hashlib
    h = hashlib.sha256()
    with iso.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    digest = h.hexdigest()
    sha = iso.parent / f"{iso.name}.sha256"
    if sha.is_file() and sha.read_text().split()[0] != digest:
        raise Fatal(f"{iso.name} does not match {sha.name}. The image changed "
                    f"after it was built; do not sign it.")
    if x.args.dry_run:
        x.info(f"[dry-run] sign {iso} with {fpr} and regenerate the bundle")
        return 0
    sha.write_text(f"{digest}  {iso.name}\n")
    sig = iso.parent / f"{iso.name}.asc"
    sig.unlink(missing_ok=True)
    x.info("signing (gpg hashes the whole image — expect minutes)")
    x.run("gpg", "--batch", "--yes", "--local-user", fpr, "--detach-sign",
          "--armor", "--output", str(sig), str(iso), live=True)
    x.ok(f"signed: {sig.name}")
    # Everything that has to travel with, or beside, the signature.
    x.export_pubkey()
    write_verify_script(x, digest)
    write_verify_script_windows(x)
    write_fingerprint_sheet(x, fpr)
    print(f"""
  Copy back to the build host, or hand out from here:
    {iso.name}, {sha.name}, {sig.name}
    unit-signing-key.asc, verify-iso.sh
  And, through a channel independent of all of those:
    {iso.parent / 'FINGERPRINT.txt'}
""")
    return 0


def iso_listing(x: Ctx, iso: Path) -> str | None:
    """Every file name in the ISO, by whichever tool this host has.

    This answers the pykickstart question the build used to leave as a note:
    if the templates are in the image, the %packages section took effect.
    """
    for argv in (["bsdtar", "-tf", str(iso)],
                 ["7z", "l", "-ba", "-slt", str(iso)],
                 ["7za", "l", "-ba", str(iso)],
                 ["isoinfo", "-f", "-i", str(iso)],
                 ["xorriso", "-indev", str(iso), "-find", "/"]):
        if not shutil.which(argv[0]):
            continue
        out = x.run(*argv, check=False, capture=True)
        if out.strip():
            x.info(f"read the ISO's contents with {argv[0]}")
            return out
    # Last resort: mount it. Needs root, so it is tried last and never assumed.
    mnt = x.work / ".isomount"
    mnt.mkdir(parents=True, exist_ok=True)
    if x.quiet(*_sudo(["mount", "-o", "loop,ro", str(iso), str(mnt)])):
        try:
            return "\n".join(str(q.relative_to(mnt)) for q in mnt.rglob("*"))
        finally:
            x.quiet(*_sudo(["umount", str(mnt)]))
    return None


def write_verify_script_windows(x: Ctx) -> None:
    """The same check, for a colleague on Windows.

    They cannot run verify-iso.sh, and telling them to install a POSIX shell to
    check an ISO is how verification stops happening. Gpg4win provides gpg.exe;
    the checksum needs nothing but Windows itself.
    """
    fp = x.c.get("iso_sign_key") or ""
    ps = x.out_dir / "verify-iso.ps1"
    ps.write_text(f"""\
# Verify {x.c['iso_name']} on Windows.  PowerShell:  .\\verify-iso.ps1 [fingerprint]
#
# Checks the checksum with Windows' own tooling, then the GPG signature if
# Gpg4win is installed (https://gpg4win.org). Pass the fingerprint you were
# given through a channel INDEPENDENT of this media and the script compares it
# for you; otherwise it prints the signer for you to compare by eye.
param([string]$Expect = $env:EXPECT_FPR)
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

$Iso = '{x.c["iso_name"]}'
$Fpr = '{fp}'

if (-not (Test-Path $Iso)) {{ Write-Host "  $Iso not found" -f Red; exit 1 }}

Write-Host '  checksum ... ' -NoNewline
$want = (Get-Content "$Iso.sha256" -Raw).Trim().Split()[0].ToLower()
$got  = (Get-FileHash $Iso -Algorithm SHA256).Hash.ToLower()
if ($want -ne $got) {{
    Write-Host 'MISMATCH' -f Red
    Write-Host "  expected $want"
    Write-Host "  actual   $got"
    Write-Host '  Do not install this image.' -f Red
    exit 1
}}
Write-Host 'ok' -f Green

$gpg = Get-Command gpg.exe -ErrorAction SilentlyContinue
if (-not $gpg) {{
    Write-Host ''
    Write-Host '  gpg.exe not found. The checksum proves the file is intact,' -f Yellow
    Write-Host '  NOT that it came from your unit. Install Gpg4win from' -f Yellow
    Write-Host '  https://gpg4win.org and run this again.' -f Yellow
    exit 2
}}

& gpg.exe --quiet --import unit-signing-key.asc 2>$null
Write-Host '  signature ... ' -NoNewline
$status = & gpg.exe --batch --status-fd 1 --verify "$Iso.asc" $Iso 2>$null
if (-not ($status -match 'GOODSIG')) {{
    Write-Host 'BAD' -f Red
    Write-Host '  The signature does not verify. Do not install this image.' -f Red
    exit 1
}}
Write-Host 'ok' -f Green

$signer = ($status | Select-String 'VALIDSIG ([0-9A-F]{{40}})').Matches.Groups[1].Value
Write-Host ''
Write-Host "  Signed by:  $signer"
if ($Fpr -and $signer -ne $Fpr) {{
    Write-Host "  Expected:   $Fpr" -f Red
    Write-Host '  The signer is NOT the key this image was built with. Stop.' -f Red
    exit 1
}}
if ($Expect) {{
    $e = ($Expect -replace '\s','').ToUpper()
    if ($e -eq $signer) {{ Write-Host '  Matches the fingerprint you supplied.' -f Green }}
    else {{
        Write-Host "  Expected:   $e" -f Red
        Write-Host '  MISMATCH. Do not install this image.' -f Red
        exit 1
    }}
}} else {{
    Write-Host ''
    Write-Host '  COMPARE that fingerprint against the one you were given through'
    Write-Host '  a channel INDEPENDENT of this media. Or let the script do it:'
    Write-Host '      .\\verify-iso.ps1 <fingerprint>'
}}
Write-Host ''
""")
    x.ok(f"Windows verification script written: {ps.name}")


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
        # --status-fd, not a bare --verify: `gpg --verify` exits 0 for a good
        # signature from ANY key in the keyring, so reporting "verifies against
        # <the unit key>" after it asserted a binding that was never tested —
        # on the last checkpoint before an image reaches removable media.
        out = x.run("gpg", "--batch", "--status-fd", "1", "--verify",
                    str(asc), str(iso), check=False, capture=True)
        signer = ""
        for line in out.splitlines():
            if line.startswith("[GNUPG:] VALIDSIG "):
                signer = line.split()[2]
                break
        if not signer:
            raise Fatal("the detached signature does not verify. Do not write "
                        "this image to media.")
        want = (x.c["iso_sign_key"] or "").upper()
        if want and signer.upper() != want:
            raise Fatal(f"the image is signed by {signer}, not by the configured "
                        f"key {want}.\n     Do not write it to media.")
        x.ok(f"signature verifies, signed by {signer}")
    else:
        x.warn("image is UNSIGNED — colleagues will have nothing to verify against")

    # 2. Pick a device, and refuse anything that is not removable.
    devs = removable_devices()
    if getattr(x.args, "wait", False) and not getattr(x.args, "device", None):
        # Plugging the stick in cannot be automated. Waiting for it can.
        before = {d["dev"] for d in devs}
        x.info("waiting for a removable device to appear — plug the stick in "
               "(Ctrl-C to give up)")
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            time.sleep(2)
            devs = removable_devices()
            fresh = [d for d in devs if d["dev"] not in before]
            if len(fresh) == 1:
                x.args.device = fresh[0]["dev"]
                x.ok(f"{fresh[0]['dev']} appeared "
                     f"({fresh[0]['size'] / 1e9:.1f} GB {fresh[0]['model']})")
                break
            if len(fresh) > 1:
                raise Fatal("more than one device appeared at once — name the one "
                            "you mean with --device")
        else:
            raise Fatal("no new removable device appeared within five minutes")
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
        # Elevate, exactly as the write already does. Skipping the readback is
        # skipping the check that a stick wrote without error and reads back
        # wrong — the failure that otherwise shows up at the install.
        x.info("reading back through sudo")
        h = hashlib.sha256()
        proc = subprocess.Popen(
            _sudo(["dd", f"if={dev_path}", "bs=4M", "iflag=fullblock",
                   f"count={(iso.stat().st_size + (1 << 22) - 1) // (1 << 22)}"]),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        assert proc.stdout
        remaining = iso.stat().st_size
        while remaining > 0:
            chunk = proc.stdout.read(min(1 << 22, remaining))
            if not chunk:
                break
            h.update(chunk)
            remaining -= len(chunk)
        proc.stdout.close()
        proc.wait()
        if remaining > 0:
            x.warn("could not read the device back even with sudo — verify the "
                   "stick by hand before distributing it")
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
  bootstrap        all of the below, in order, stopping at the first failure
  setup-host       install and configure everything the build host needs
  gen-key          create (or adopt) the ISO signing key and record it
  doctor           check the host is ready; change nothing
  config           read or write settings without an editor
  check-upstream   compare pinned keys and versions against upstream
  templates        build the five investigator templates
  iso              build, checksum and sign the ISO
  all              templates, then the ISO
  sign             sign an image on the machine that holds the key
  backup-key       export the signing key, its revocation certificate and public key
  restore-key      import a signing-key backup on another machine
  write-usb        verify the image and write it to removable media
  list-kickstarts  show what the fetched Qubes sources offer
""")
    p.add_argument("action", nargs="?", default="iso",
                   choices=["iso", "templates", "all", "list-kickstarts",
                            "doctor", "setup-host", "gen-key", "check-upstream",
                            "write-usb", "config", "sign",
                            "backup-key", "restore-key", "bootstrap"],
                   help="what to do (default: iso)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--force", action="store_true", help="skip the warning prompt")
    p.add_argument("--fix", action="store_true",
                   help="doctor: run the fixes it would otherwise only print")
    p.add_argument("--allow-unsigned", action="store_true",
                   help="build an unsigned image deliberately (testing only)")
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
    u.add_argument("--wait", action="store_true",
                   help="wait for a removable device to be plugged in")
    b = p.add_argument_group("backup-key / restore-key")
    b.add_argument("--to", metavar="DIR", help="where to write the key backup")
    b.add_argument("--from", dest="from_dir", metavar="DIR",
                   help="the key backup to restore from")
    b.add_argument("--passphrase-file", metavar="PATH",
                   help="encrypt/decrypt the backup with this passphrase instead "
                        "of prompting (for a scripted key-management process)")
    p.add_argument("--iso", metavar="PATH",
                   help="sign: the image to sign (default: the built one)")
    c = p.add_argument_group("check-upstream")
    p.add_argument("--skip-doctor", action="store_true",
                   help="do not run the readiness checks before building")
    p.add_argument("--skip-upstream", action="store_true",
                   help="do not check the supply chain before building")
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

        if args.action == "bootstrap":
            return bootstrap(x, args)

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
        if args.action == "sign":
            return sign_iso(x)
        if args.action == "backup-key":
            return backup_key(x)
        if args.action == "restore-key":
            return restore_key(x)
        if args.action == "write-usb":
            return write_usb(x)

        if args.action == "list-kickstarts":
            for k in list_kickstarts(x):
                print(f"  {k}")
            names, marker = comps_template_names(x, cfg["comps_file"])
            print(f"\n  comps templates: {', '.join(names) or '(none found)'}")
            print(f"  @QUBES_TEMPLATES@ marker: {'PRESENT' if marker else 'ABSENT'}")
            return 0

        resolve_auto_values(x)
        payload = preflight(x, tier2)
        if args.action in ("templates", "iso", "all") and not args.dry_run \
                and not args.skip_upstream and upstream_check_is_stale(x):
            # "Remember to run check-upstream before a first build" is not a
            # thing to remember. A rotated key or a dom0 bulletin found here
            # costs a minute; found afterwards it costs the build. Gated on the
            # age of the recorded baseline so a same-day rebuild is not slowed
            # down, and skipped entirely when the host has no network.
            if check_upstream(x):
                raise Fatal(
                    "the supply-chain check above found something blocking.\n"
                    "     Resolve it, or pass --skip-upstream to build anyway "
                    "(and record why).")
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
