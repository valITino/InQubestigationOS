#!/usr/bin/env python3
"""Behavioral checks for generated installation and first-boot contracts."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bi, gi = load("build_iso"), load("golden_image")


def arguments(**over):
    values = dict(action="iso", dry_run=False, allow_unsigned=False,
                  passphrase_file=None, force=False)
    values.update(over)
    return SimpleNamespace(**values)


def fatal(call, contains):
    try:
        call()
    except bi.Fatal as exc:
        assert contains in str(exc), str(exc)
    else:
        raise AssertionError(f"expected Fatal containing {contains!r}")


def main():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cfg = dict(bi.DEFAULT_CONFIG)
        cfg["work_dir"] = str(root / "work")
        cfg["install"] = dict(cfg["install"], unattended=True,
                               disk="/dev/disk/by-id/wwn-test")
        x = bi.Ctx(cfg, arguments())
        conf = bi.release_dir(x) / "conf"
        conf.mkdir(parents=True)
        # Mirrors the real release4.3 layout: iso-online.ks carries repo lines
        # and %includes qubes-kickstart.cfg, and the %packages block lives in
        # the included file. Nothing upstream answers lang/user/autopart.
        stock = conf / "iso-online.ks"
        stock.write_text(
            "%include qubes-kickstart.cfg\n"
            "repo --name=qubes-r4.3 --gpgkey=file:///tmp/qubes-installer/k "
            "--baseurl=http://yum.qubes-os.org/r4.3 --ignoregroups=true\n")
        (conf / "qubes-kickstart.cfg").write_text(
            "repo --name=fedora --gpgkey=file:///etc/pki/k --ignoregroups=true\n"
            "%packages\n@core\n@standard\n@qubes\nkernel-latest\n-avahi\n%end\n")
        custom = root / "target.json"
        custom.write_text(json.dumps({"wazuh": {"mode": "central",
                                                 "central_address": "10.0.0.5"},
                                      # Read from the provisioner rather than
                                      # written here: a hardcoded copy silently
                                      # drifts at the next version bump, and
                                      # this fixture exists to exercise the
                                      # check that catches exactly that.
                                      "image_version":
                                          gi.DEFAULT_CONFIG["image_version"]}))
        x.c["provisioner_config"] = str(custom)
        with mock.patch.object(bi, "kickstart_python", return_value=(None, "")):
            rel = bi.write_kickstart(x, stock.name, [])
            oem = bi.write_oem_kickstart(x, stock.name, ROOT / "golden_image.py", [])

        # The compose kickstart is a manifest for the builder, not an answer
        # file: qubes-builderv2 feeds it to scripts/ksparser and hands lorax no
        # kickstart at all, so anything installer-side written here would be
        # silently dropped.
        compose = (conf / Path(rel).name).read_text()
        assert "%post" not in compose, "compose kickstart must carry no %post"
        assert "golden_image.py" not in compose
        assert "autopart" not in compose and "clearpart" not in compose
        assert f"%include {stock.name}" in compose

        # One build yields a signed kickstart per edition, and oem/ks.cfg is
        # the configured one. The edition reaches the provisioner through the
        # embedded golden-image.json, and every install carries the guide.
        import base64 as _b64
        import re as _re

        def embedded_config(path):
            m = _re.search(r"<<'CONFIG_B64_EOF'\n(.*?)\nCONFIG_B64_EOF",
                           path.read_text(), _re.S)
            return json.loads(_b64.b64decode(m.group(1).replace("\n", "")))

        for ed in bi.EDITIONS:
            eks = bi.edition_kickstart_path(x, ed)
            assert eks.is_file(), f"no kickstart for the {ed} edition"
            assert embedded_config(eks)["edition"] == ed
            assert "WORKSTATION-GUIDE.md" in eks.read_text()
            assert f"({ed} edition)" in eks.read_text()
        assert oem.read_text() == bi.edition_kickstart_path(x, "wired").read_text(), \
            "oem/ks.cfg must be the configured (default: wired) edition"
        # The custom provisioner_config is still carried, edition added.
        assert embedded_config(oem)["wazuh"]["mode"] == "central"

        # Everything installer-side lives in the QUBES_OEM kickstart instead.
        text = oem.read_text()
        assert oem.name == "ks.cfg" and oem.parent.name == "oem"
        # The stock dom0 selection is carried through; a %packages block
        # replaces Anaconda's default rather than adding to it, so dropping it
        # would install a machine with no dom0 on it.
        for group in ("@core", "@standard", "@qubes", "kernel-latest", "-avahi"):
            assert group in text, f"OEM kickstart lost stock package entry {group}"
        # Build-cage-only repo paths must not be copied into an install-time file.
        assert "file:///tmp/qubes-installer" not in text
        assert "RemainAfterExit" not in text
        assert "OnUnitInactiveSec=30min" in text and "flock -n 9" in text
        assert "exit 75" in text and "exit $rc" in text
        assert "--verify --offline-checks" in text
        assert "touch \"$MARKER\"" in text and text.index("--verify --offline-checks") < text.index("touch \"$MARKER\"")
        assert "TARGET_ID=/dev/disk/by-id/wwn-test" in text
        assert "clearpart --all --initlabel --drives=%s" in text
        assert "golden-image.json.b64" in text

        # No target and a non-stable target both fail before any clearpart is emitted.
        x.c["install"]["disk"] = ""
        fatal(lambda: bi.build_installer_directives(x), "stable target")
        x.c["install"]["disk"] = "/dev/sda"
        fatal(lambda: bi.build_installer_directives(x), "by-id")

        # Account enrollment no longer depends on the selected upstream file:
        # the generated target kickstart creates it locked and first boot asks
        # for its unique secret on the physical laptop.
        bi.validate_install_contract(x, oem)
        assert "user --name=investigator --groups=wheel --lock" in text
        assert "systemd-ask-password" in text and "| chpasswd" in text
        assert text.index("flock -n 9") < text.index("systemd-ask-password")
        assert "if ! printf '%s:%s" in text and '"$ACCOUNT" "$PW1" | chpasswd; then' in text

        # Execute the account-enrollment portion of the actual generated
        # first-boot script, with stubs, under three conditions. The contract:
        # enrollment NEVER gates provisioning. A failing chpasswd, or nobody at
        # the console, publishes no marker and lets the run continue; a
        # successful enrollment publishes the marker. The old runner blocked on
        # systemd-ask-password with no timeout before provisioning began.
        sentinel = "\n# --- provisioning (never gated on the login password) ---"
        assert sentinel in text, "runner lost its provisioning sentinel"
        assert "--timeout=0" not in text, "an untimed console prompt would block provisioning"
        assert "--timeout=90" in text
        assert text.index("enroll || true") < text.index('note "first-boot runner started"')
        assert text.index('touch "$PROV_MARKER"') < text.index('touch "$MARKER"'), \
            "provisioning must record its own completion before the final marker"
        assert 'if [ -e "$ACCOUNT_MARKER" ]; then\n    touch "$MARKER"' in text, \
            "the final marker must require the login password to be enrolled"
        generated = text.split("cat > /usr/local/sbin/golden-image-firstboot <<'FB_EOF'\n", 1)[1]
        generated = generated.split(sentinel, 1)[0] + "\nexit 0\n"
        state = root / "target-state"
        run = root / "run"
        stubs = root / "stubs"
        for d in (state, run, stubs):
            d.mkdir(exist_ok=True)
        generated = generated.replace("/var/lib/golden-image", str(state)).replace(
            "/run/golden-image-firstboot.lock", str(run / "lock"))

        def stub(name: str, body: str) -> None:
            path = stubs / name
            path.write_text("#!/bin/sh\n" + body + "\n")
            path.chmod(0o755)

        def enroll_run(*, ask_rc: int, chpasswd_rc: int) -> subprocess.CompletedProcess:
            for f in ("account-enrolled", "firstboot-status"):
                (state / f).unlink(missing_ok=True)
            (stubs / ".set").unlink(missing_ok=True)
            stub("getent", "exit 0")
            # Stateful: reports P (password set) only after chpasswd succeeded.
            stub("passwd", f'[ -e "{stubs}/.set" ] && echo "investigator P 0 0 99999 7 -1" '
                           '|| echo "investigator L 0 0 99999 7 -1"')
            stub("systemd-ask-password", f"echo correct-horse; exit {ask_rc}")
            stub("chpasswd", f'cat >/dev/null; [ {chpasswd_rc} -eq 0 ] && touch "{stubs}/.set"; exit {chpasswd_rc}')
            stub("logger", "exit 0")
            env = dict(os.environ, PATH=f"{stubs}:{os.environ['PATH']}")
            return subprocess.run(["bash"], input=generated, text=True,
                                  capture_output=True, env=env)

        # The whole runner, not just the half executed below, must parse: a
        # syntax error after the sentinel would only surface on the laptop.
        whole = text.split("cat > /usr/local/sbin/golden-image-firstboot <<'FB_EOF'\n", 1)[1]
        whole = whole.split("\nFB_EOF\n", 1)[0]
        parsed = subprocess.run(["bash", "-n"], input=whole, text=True, capture_output=True)
        assert parsed.returncode == 0, parsed.stderr[-300:]

        status = state / "firstboot-status"
        # a. chpasswd fails: no marker, and the run continues to provisioning.
        r = enroll_run(ask_rc=0, chpasswd_rc=42)
        assert r.returncode == 0, (r.returncode, r.stderr[-300:])
        assert not (state / "account-enrolled").exists()
        assert "password setting failed" in status.read_text()
        # b. nobody at the console: no marker, provisioning still continues.
        r = enroll_run(ask_rc=1, chpasswd_rc=0)
        assert r.returncode == 0, (r.returncode, r.stderr[-300:])
        assert not (state / "account-enrolled").exists()
        assert "no input" in status.read_text()
        # c. a person answers: the marker is published, mode 0600.
        r = enroll_run(ask_rc=0, chpasswd_rc=0)
        assert r.returncode == 0, (r.returncode, r.stderr[-300:])
        marker = state / "account-enrolled"
        assert marker.exists() and (marker.stat().st_mode & 0o777) == 0o600
        assert "account enrolled" in status.read_text()

        # ---------------------------------------------------------------
        # Hand the generated file to the real parser. Without this the only
        # thing proving the kickstart is valid is that we wrote it.
        # Both modes, because the unattended one takes a different path:
        # its partitioning is written by %pre and pulled in by %include, and
        # a naive parse dies on the include target not existing yet.
        try:
            import pykickstart  # noqa: F401
            have_ks = True
        except ImportError:
            have_ks = False
        if have_ks:
            for unattended in (False, True):
                x.c["install"] = dict(x.c["install"], unattended=unattended,
                                      disk="/dev/disk/by-id/wwn-test")
                parsed = bi.write_oem_kickstart(x, stock.name,
                                                ROOT / "golden_image.py",
                                                ["investigator-kali"])
                body = parsed.read_text()
                assert "%post" in body
                assert ("autopart --encrypted" in body) == unattended, (
                    "unattended must answer partitioning; manual must not")
            x.c["install"] = dict(x.c["install"], unattended=True,
                                  disk="/dev/disk/by-id/wwn-test")
        else:
            print("  ! pykickstart absent — generated kickstart not parsed")

        # write-usb refuses before device discovery if integrity metadata is absent.
        iso = x.out_dir / x.c["iso_name"]
        iso.write_bytes(b"fixture")
        fatal(lambda: bi.write_usb(x), ".sha256")
        # With the checksum in place, the next thing it wants is the install-
        # time kickstart AND its signature: the kickstart runs as root inside
        # the installer and the image's signature does not cover it, so an
        # unsigned one is refused before any device is even looked for.
        import hashlib
        (x.out_dir / f"{x.c['iso_name']}.sha256").write_text(
            f"{hashlib.sha256(b'fixture').hexdigest()}  {x.c['iso_name']}\n")
        for f in (bi.oem_kickstart_path(x), bi.oem_kickstart_signature_path(x)):
            f.unlink(missing_ok=True)
        fatal(lambda: bi.write_usb(x), "no install-time kickstart")
        bi.oem_kickstart_path(x).parent.mkdir(parents=True, exist_ok=True)
        bi.oem_kickstart_path(x).write_text("%post\necho hi\n%end\n")
        fatal(lambda: bi.write_usb(x), "ks.cfg.asc")
        # --no-oem skips the kickstart gate and proceeds to the image's own
        # signature, which this fixture does not have.
        x.args.no_oem = True
        fatal(lambda: bi.write_usb(x), "no detached signature")
        x.args.no_oem = False

        runner = SimpleNamespace(run=lambda *a, **k: "total_memory : 32768\n")
        assert gi.physical_memory_gb(runner) == 32

        # package-release publishes only a complete, signed set, and never a
        # part GitHub would reject (2 GiB and up).
        fatal(lambda: bi.package_release(x), "cannot package a release without")
        fatal(lambda: bi.package_release(x), "InQubestigationOS.iso.asc")
        for ed in bi.EDITIONS:
            eks = bi.edition_kickstart_path(x, ed)
            eks.parent.mkdir(parents=True, exist_ok=True)
            eks.write_text("%post\n%end\n")
            eks.with_name("ks.cfg.asc").write_text("sig")
        for f in (f"{x.c['iso_name']}.asc", "unit-signing-key.asc",
                  "FINGERPRINT.txt", "verify-iso.sh", "oem/ks.cfg.asc"):
            (x.out_dir / f).write_text("fixture")
        x.c["iso_sign_key"] = "A" * 40
        x.args.part_size = 2048
        fatal(lambda: bi.package_release(x), "--part-size")
        x.args.part_size = None
        # The repository's SIGNING-KEY.md is what downloaders compare against:
        # its placeholder is filled on first use, a different key is refused.
        page = Path(td) / "SIGNING-KEY.md"
        page.write_text("# key\n\n```\nFingerprint:  NOT-YET-PUBLISHED\n```\n")
        assert bi.published_fingerprint(page) == ""
        with mock.patch.object(bi, "SIGNING_KEY_PAGE", page):
            x.args.dry_run = True
            assert bi.check_published_fingerprint(x, "a" * 40) == "would-fill"
            assert bi.published_fingerprint() == ""
            x.args.dry_run = False
            assert bi.check_published_fingerprint(x, "a" * 40) == "filled"
            assert bi.published_fingerprint() == "A" * 40
            assert "AAAA AAAA AAAA AAAA AAAA  AAAA" in page.read_text()
            assert bi.check_published_fingerprint(x, "A" * 40) == "matches"
            fatal(lambda: bi.check_published_fingerprint(x, "B" * 40),
                  "publishes " + "A" * 40)
            page.write_text("no fingerprint line\n")
            fatal(lambda: bi.check_published_fingerprint(x, "A" * 40),
                  "no readable 'Fingerprint:' line")
            page.unlink()
            assert bi.check_published_fingerprint(x, "A" * 40) == "absent"
        # A signing subkey resolves to its primary key; that is what gpg shows
        # downloaders as "Primary key fingerprint", so that is what is published.
        colons = ("pub:u:4096:1:AAAA:1::::::scESC:\nfpr:::::::::" + "P" * 40 + ":\n"
                  "sub:u:4096:1:BBBB:1::::::s:\nfpr:::::::::" + "S" * 40 + ":\n")
        assert bi.primary_fingerprint(colons, "s" * 40) == "P" * 40
        assert bi.primary_fingerprint(colons, "P" * 40) == "P" * 40
        assert bi.primary_fingerprint(colons, "C" * 40) == ""
        for remote, want in (
                ("https://github.com/o/r.git", "https://github.com/o/r/blob/HEAD/SIGNING-KEY.md"),
                ("git@github.com:o/r.git", "https://github.com/o/r/blob/HEAD/SIGNING-KEY.md"),
                ("https://gitlab.example/o/r", "")):
            assert bi.signing_key_url(remote) == want, remote
        readme = bi.release_readme("I.iso", ["I.iso.part01"], "k.tar.gz", "A" * 40,
                                   "https://github.com/o/r/blob/HEAD/SIGNING-KEY.md")
        assert "published at  https://github.com/o/r/blob/HEAD/SIGNING-KEY.md" in readme
        # USB media: flagged removable, OR attached over USB with the
        # removable bit cleared (many sticks' firmware); never a SATA/NVMe disk.
        sysb = Path(td) / "sys" / "block"
        def disk(name, removable, bus, size="30000000"):
            d = sysb / name
            d.mkdir(parents=True)
            (d / "removable").write_text(removable + "\n")
            (d / "size").write_text(size + "\n")
            target = Path(td) / "devices" / bus / name
            target.mkdir(parents=True)
            (target / "model").write_text(name.upper() + "\n")
            (d / "device").symlink_to(target)
        disk("sda", "0", "pci0000:00/ata1/host0")                 # internal SATA
        disk("sdb", "0", "pci0000:00/usb2/2-1/2-1:1.0/host3")     # USB, bit cleared
        disk("sdc", "1", "pci0000:00/mmc0")                       # card reader
        disk("sdd", "0", "pci0000:00/usb3/3-1/host4", size="0")   # empty USB slot
        with mock.patch.object(bi, "SYS_BLOCK", sysb):
            found = {d["dev"]: d["usb"] for d in bi.removable_devices()}
        assert found == {"/dev/sdb": True, "/dev/sdc": False}, found

        # A stick plugged in before write-usb --wait started is used, not
        # waited for (the wait only ever saw NEW devices and timed out).
        one = [{"dev": "/dev/sdb", "size": 3e10, "model": "STICK", "usb": True}]
        two = one + [{"dev": "/dev/sdc", "size": 3e10, "model": "CARD", "usb": False}]
        x.args.device, x.args.wait = None, True
        with mock.patch.object(bi, "removable_devices", return_value=one), \
                mock.patch.object(bi.time, "sleep", side_effect=AssertionError("waited")):
            assert bi.select_device(x)[0] == "/dev/sdb"
        x.args.device = None
        clock = iter(range(0, 10_000, 100))
        with mock.patch.object(bi, "removable_devices", return_value=two), \
                mock.patch.object(bi.time, "sleep"), \
                mock.patch.object(bi.time, "monotonic", side_effect=lambda: next(clock)):
            fatal(lambda: bi.select_device(x), "/dev/sdb, /dev/sdc")
        x.args.device = None
        seq = iter([[], [], one])
        with mock.patch.object(bi, "removable_devices", side_effect=lambda: next(seq)), \
                mock.patch.object(bi.time, "sleep"):
            assert bi.select_device(x)[0] == "/dev/sdb"
        x.args.device, x.args.wait = None, False

        # The download kit's writer must at least be valid bash.
        mk = Path(td) / "make-usb.sh"
        mk.write_text(bi.MAKE_USB_SH.replace("@ISO@", "x.iso"))
        assert subprocess.run(["bash", "-n", str(mk)]).returncode == 0

    print("  70/70 installation-path checks pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
