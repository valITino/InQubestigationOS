#!/usr/bin/env python3
"""Behavioral checks for generated installation and first-boot contracts."""
from __future__ import annotations

import importlib.util
import json
import tempfile
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
        stock = conf / "iso-online.ks"
        stock.write_text("user --name=user --groups=wheel\n")
        custom = root / "target.json"
        custom.write_text(json.dumps({"wazuh": {"mode": "central",
                                                 "central_address": "10.0.0.5"},
                                      "image_version": "2.2"}))
        x.c["provisioner_config"] = str(custom)
        with mock.patch.object(bi, "kickstart_python", return_value=(None, "")):
            rel = bi.write_kickstart(x, stock.name, ROOT / "golden_image.py", [])
        text = (conf / Path(rel).name).read_text()
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
        stock.write_text("lang en_US.UTF-8\n")
        bi.validate_install_contract(x, conf / Path(rel).name, stock)
        assert "user --name=investigator --groups=wheel --lock" in text
        assert "systemd-ask-password" in text and "| chpasswd" in text

        # write-usb refuses before device discovery if integrity metadata is absent.
        iso = x.out_dir / x.c["iso_name"]
        iso.write_bytes(b"fixture")
        fatal(lambda: bi.write_usb(x), ".sha256")

        runner = SimpleNamespace(run=lambda *a, **k: "total_memory : 32768\n")
        assert gi.physical_memory_gb(runner) == 32

    print("  16/16 installation-path checks pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
