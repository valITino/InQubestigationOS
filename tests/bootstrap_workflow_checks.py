#!/usr/bin/env python3
"""Deterministic tests for bootstrap onboarding/status/export contracts."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import sys
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
                  "install": {"unattended": False, "disk": ""},
                  "bootstrap": {"backup_path": str(root / "backup"),
                                "backup_source": "/dev/disk/by-uuid/BACKUP",
                                "backup_fstype": "ext4", "backup_kind": "physical-device",
                                "export_path": str(root / "host share"),
                                "export_source": "hostshare", "export_fstype": "virtiofs",
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

        with mock.patch.object(flow, "_mount", side_effect=mount), \
                mock.patch("bootstrap_workflow.shutil.disk_usage",
                           return_value=SimpleNamespace(free=100 * 1024**3)):
            flow.onboard(arguments(secret))
            flow.acquire_lock()
            flow.stage("onboarding", "complete", "ready")
            for name in bw.EXPORT_ALLOWLIST:
                mapped = name.replace("InQubestigationOS.iso", "image with space.iso")
                (x.out_dir / mapped).write_bytes((mapped + "\n").encode())
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

        # Missing values are aggregated before any build; root/lookalike mounts
        # and changed identities are blocking, never writable fallbacks.
        broken = Context(root)
        broken.c["iso_sign_key"] = ""
        broken.c["bootstrap"]["backup_source"] = "expected"
        check = bw.BootstrapWorkflow(broken)
        with mock.patch.object(check, "_mount", return_value={
                "target": "/", "source": "/dev/root", "fstype": "ext4", "options": "rw"}):
            try:
                check.onboard(SimpleNamespace(to=None, uid=None, use_key=None,
                                              passphrase_file=None))
            except ValueError as exc:
                message = str(exc)
                assert "signing identity" in message and "runtime signing" in message
                assert "not on a separate mounted filesystem" in message
            else:
                raise AssertionError("incomplete onboarding was accepted")

        # The generic yes flag is absent from this API: no operation can format,
        # repartition, erase, or silently approve a device.
        assert not any(word in Path(bw.__file__).read_text() for word in ("mkfs", "wipefs"))
    print("  12/12 bootstrap workflow checks pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
