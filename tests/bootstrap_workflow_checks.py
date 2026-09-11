#!/usr/bin/env python3
"""Deterministic tests for bootstrap onboarding/status/export contracts."""
from __future__ import annotations

import json
import tempfile
import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import sys
import os
import subprocess
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bootstrap_workflow as bw


class Context:
    def __init__(self, root: Path):
        self.work = root / "work"
        self.out_dir = self.work / "output"
        self.log = self.work / "build.log"
        self.work.mkdir(exist_ok=True)
        self.out_dir.mkdir(exist_ok=True)
        self.log.touch()
        self.c = {"iso_name": "image with space.iso", "iso_sign_key": "A" * 40,
                  "install": {"unattended": False, "disk": "", "username": "investigator"},
                  "bootstrap": {"backup_path": str(root / "backup"),
                                "dependencies_authorized": True,
                                "backup_source": "/dev/disk/by-uuid/BACKUP",
                                "backup_fstype": "ext4", "backup_kind": "physical-device",
                                "export_path": str(root / "host share"),
                                "export_source": "hostshare", "export_fstype": "virtiofs",
                                "export_kind": "host-share",
                                "host_path": "", "build_only": False,
                                "min_backup_mb": 1, "min_export_mb": 1}}

    def state_digest(self, _key):
        return "b" * 64


def arguments(secret: Path):
    return SimpleNamespace(to=None, uid=None, use_key="A" * 40,
                           passphrase_file=str(secret))


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "backup").mkdir()
        (root / "host share").mkdir()
        secret = root / "runtime-secret"
        secret.write_text("DO-NOT-LOG-THIS")
        secret.chmod(0o600)
        x = Context(root)
        flow = bw.BootstrapWorkflow(x)

        def mount(path):
            backup = Path(path) == root / "backup"
            return {"target": str(path),
                    "source": "/dev/disk/by-uuid/BACKUP" if backup else "hostshare",
                    "fstype": "ext4" if backup else "virtiofs", "options": "rw"}

        real_stat = os.stat
        def device_stat(path, *args, **kwargs):
            if str(path).startswith("/dev/"):
                return SimpleNamespace(st_rdev=2049)
            return real_stat(path, *args, **kwargs)
        with mock.patch.object(flow, "_mount", side_effect=mount), \
                mock.patch("bootstrap_workflow.os.stat", side_effect=device_stat), \
                mock.patch("bootstrap_workflow.shutil.disk_usage",
                           return_value=SimpleNamespace(free=100 * 1024**3)):
            flow.onboard(arguments(secret))
            flow.acquire_lock()
            flow.stage("onboarding", "complete", "ready")
            for name in bw.EXPORT_ALLOWLIST:
                mapped = name.replace("InQubestigationOS.iso", "image with space.iso")
                (x.out_dir / mapped).write_bytes((mapped + "\n").encode())
            iso = x.out_dir / "image with space.iso"
            (x.out_dir / "image with space.iso.sha256").write_text(
                hashlib.sha256(iso.read_bytes()).hexdigest() + "  image with space.iso\n")
            valid = SimpleNamespace(returncode=0,
                                    stdout="[GNUPG:] VALIDSIG " + "A" * 40 + " 0 0 0 0 0 0 0 0 " + "A" * 40,
                                    stderr="")
            with mock.patch("bootstrap_workflow.subprocess.run", return_value=valid):
                flow.export_release()
            flow.finish()

        status = json.loads(flow.status_path.read_text())
        inventory = json.loads(flow.inventory_path.read_text())
        assert status["state"] == "complete"
        assert inventory["export"]["verified"] is True
        assert inventory["export"]["host_path"] is None
        assert "DO-NOT-LOG-THIS" not in flow.status_path.read_text()
        assert "DO-NOT-LOG-THIS" not in flow.inventory_path.read_text()
        assert len(list((root / "host share").glob("release-*"))) == 1

        # Exercise the real discovery function with lsblk's unmounted shape,
        # mixed nulls, and a malformed field. Labels are data, not formatting.
        discovered = SimpleNamespace(returncode=0, stdout=json.dumps({"blockdevices": [
            {"name": "/dev/vda1", "type": "part", "size": 1,
             "fstype": "ext4", "uuid": "U", "label": "x\\x1b[31m",
             "mountpoints": [None, "/media/x"]}]}))
        with mock.patch("bootstrap_workflow.subprocess.run", return_value=discovered):
            assert bw.BootstrapWorkflow.discover_block_filesystems()[0]["mountpoints"] == ["/media/x"]
        malformed = SimpleNamespace(returncode=0, stdout=json.dumps({"blockdevices": [
            {"name": "/dev/vda1", "type": "part", "fstype": "ext4",
             "mountpoints": "not-an-array"}]}))
        with mock.patch("bootstrap_workflow.subprocess.run", return_value=malformed):
            assert bw.BootstrapWorkflow.discover_block_filesystems() == []

        # Mountpoint creation is delegated to the narrow privileged argv helper;
        # no unprivileged mkdir beneath a root-owned parent occurs first.
        fresh = Context(root)
        fresh.c["bootstrap"]["backup_path"] = str(root / "privileged" / "backup")
        prep = bw.BootstrapWorkflow(fresh)
        commands = []
        def privileged(argv):
            commands.append(argv)
            if argv[0] == "install":
                Path(argv[-1]).mkdir(parents=True)
        with mock.patch.object(prep, "_run_privileged", side_effect=privileged), \
                mock.patch.object(prep, "_mount", return_value={"target": str(root / "privileged" / "backup"),
                    "source": "/dev/disk/by-uuid/BACKUP", "fstype": "ext4", "options": "rw"}), \
                mock.patch("bootstrap_workflow.os.stat", side_effect=device_stat):
            prep.prepare_mount("backup")
        assert commands[0][:5] == ["install", "-d", "-m", "0700", "--"]

        # Missing values are aggregated before any build; root/lookalike mounts
        # and changed identities are blocking, never writable fallbacks.
        broken = Context(root)
        broken.c["iso_sign_key"] = ""
        broken.c["bootstrap"]["backup_source"] = "expected"
        check = bw.BootstrapWorkflow(broken)
        with mock.patch.object(check, "_mount", return_value={
                "target": "/", "source": "/dev/root", "fstype": "ext4", "options": "rw"}), \
                mock.patch.object(check, "_run_privileged",
                                  side_effect=ValueError("mount authorization unavailable")):
            try:
                check.onboard(SimpleNamespace(to=None, uid=None, use_key=None,
                                              passphrase_file=None))
            except ValueError as exc:
                message = str(exc)
                assert "signing identity" in message and "runtime signing" in message
                assert "mount authorization unavailable" in message
            else:
                raise AssertionError("incomplete onboarding was accepted")

        # The generic yes flag is absent from this API: no operation can format,
        # repartition, erase, or silently approve a device.
        assert not any(word in Path(bw.__file__).read_text() for word in ("mkfs", "wipefs"))

        # Save and reload every supported destination classification through
        # the real CLI/config loader in a child process.  Guest block storage
        # is valid for backup, never for physical-host distribution.
        import build_iso as bi
        for backup_kind, backup_fstype in (("physical-device", "ext4"),
                                            ("host-share", "virtiofs")):
            candidate = json.loads(json.dumps(bi.DEFAULT_CONFIG))
            candidate["bootstrap"].update({
                "dependencies_authorized": True,
                "backup_path": "/mnt/backup", "backup_source": "backup-source",
                "backup_fstype": backup_fstype, "backup_kind": backup_kind,
                "export_path": "/mnt/export", "export_source": "hostshare",
                "export_fstype": "virtiofs", "export_kind": "host-share"})
            profile = root / f"{backup_kind}.json"
            profile.write_text(json.dumps(candidate))
            reloaded = subprocess.run(
                [sys.executable, str(Path(bi.__file__)), "config", "--get",
                 "bootstrap.export_kind"], text=True, capture_output=True,
                env={**os.environ, "INQUBESTIGATION_CONFIG": str(profile)})
            assert reloaded.returncode == 0, reloaded.stderr
            assert "host-share" in reloaded.stdout
        invalid = json.loads(json.dumps(candidate))
        invalid["bootstrap"].update(export_kind="physical-device", export_fstype="ext4")
        profile = root / "invalid-export.json"
        profile.write_text(json.dumps(invalid))
        rejected = subprocess.run(
            [sys.executable, str(Path(bi.__file__)), "config"], text=True,
            capture_output=True, env={**os.environ, "INQUBESTIGATION_CONFIG": str(profile)})
        assert rejected.returncode == 1
        assert "cannot be classified as physical-host distribution" in rejected.stderr
    print("  12/12 bootstrap workflow checks pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
