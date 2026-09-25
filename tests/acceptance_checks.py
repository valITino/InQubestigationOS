#!/usr/bin/env python3
"""Behavioral checks for acceptance evidence and maintenance failure gates."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("acceptance_runner", ROOT / "acceptance_runner.py")
ar = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ar)


def main():
    with tempfile.TemporaryDirectory() as td:
        report = Path(td) / "report.json"
        cmd = [sys.executable, str(ROOT / "acceptance_runner.py"), "--report",
               str(report), "--revision", "A" * 40, "--prepare-pending"]
        made = subprocess.run(cmd, capture_output=True, text=True)
        assert made.returncode == 0
        data = json.loads(report.read_text())
        assert data["release_status"] == "release-candidate-not-hardware-verified"
        assert data["summary"]["pending"] == len(ar.CHECKS)
        assert all(v["status"] == "pending" for v in data["checks"].values())

        denied = subprocess.run([sys.executable, str(ROOT / "acceptance_runner.py"),
                                 "--report", str(report), "--collect"],
                                capture_output=True, text=True)
        assert denied.returncode == 2 and "authorized Qubes" in denied.stderr

        updated = subprocess.run(cmd[:4] + ["--record",
            "backup_media_absent=fail:service rc=1; passphrase=hunter2"],
            capture_output=True, text=True)
        assert updated.returncode == 1
        data = json.loads(report.read_text())
        assert data["checks"]["backup_media_absent"]["status"] == "fail"
        assert "hunter2" not in report.read_text() and "[REDACTED]" in report.read_text()

        issue = subprocess.run(cmd[:4] + ["--issue", "--operator", "Authorized Tester"],
                               capture_output=True, text=True)
        assert issue.returncode == 2 and "failed or remain pending" in issue.stderr

        # A report written before a check existed has no entry for it. That
        # check is pending, not passed: everything else passing must not add
        # up to "hardware-accepted".
        old = json.loads(report.read_text())
        old["checks"] = {k: {"status": "pass"} for k in list(ar.CHECKS)[1:]}
        old["release_status"] = "issued"        # an earlier, now stale, status
        report.write_text(json.dumps(old))
        subprocess.run(cmd[:4], capture_output=True, text=True)
        data = json.loads(report.read_text())
        assert data["summary"]["pending"] == 1, data["summary"]
        assert data["release_status"] == "release-candidate-not-hardware-verified", \
            data["release_status"]

    source = (ROOT / "golden_image.py").read_text()
    assert "set -uo pipefail" in source
    assert "full restore remains pending" in source
    assert "backup archive integrity check PASSED" in source
    assert source.count("    exit 1\nfi") >= 3
    assert '"ExecMainStatus"' in source and '"Result"' in source
    guide = (ROOT / "docs/ACCEPTANCE.md").read_text()
    assert "never automates a dom0 reboot" in guide
    assert "Never restore over" in guide and "--verify-only" in guide
    print("  19/19 acceptance evidence checks pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
