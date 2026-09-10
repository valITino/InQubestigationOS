#!/usr/bin/env python3
"""Offline policy checks for the trusted release-candidate entry point."""
from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "release_candidate", ROOT / "release_candidate.py")
rc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rc)


def main():
    workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text()
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "workflow_dispatch:" in workflow and "pull_request:" not in workflow
    assert "inqubestigation-trusted-build" in workflow
    assert "environment: production-build" in workflow
    assert "inputs.trusted_commit == vars.TRUSTED_BUILD_REF" in workflow
    assert "github.event.repository.default_branch" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "persist-credentials: false" in workflow
    assert "upload-artifact" not in workflow and "IQ_GPG_SESSION_SECRET" in workflow
    assert "run: ./build_iso.py check-upstream" in ci
    assert "check-upstream --update" not in ci
    assert rc.ALLOWLIST == (
        "InQubestigationOS.iso", "InQubestigationOS.iso.sha256",
        "InQubestigationOS.iso.asc", "unit-signing-key.asc", "verify-iso.sh",
        "verify-iso.ps1", "FINGERPRINT.txt", "BUILD-RECORD.txt")
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "x"
        p.write_bytes(b"release-candidate")
        assert rc.sha256(p) == "43fa9551602fcc315bc3e752d5f18b5a1646c70f846afc4baa996ce5d239f41c"
        log, secret, clean = Path(td) / "log", Path(td) / "secret", Path(td) / "clean"
        secret.write_text("never-publish")
        log.write_text("before never-publish after")
        rc.copy_redacted_log(log, clean, secret)
        assert clean.read_text() == "before [REDACTED RUNTIME SECRET] after"
    source = (ROOT / "release_candidate.py").read_text()
    for gate in ("min-work-gb", "min-docker-gb", "sudo", "docker", "list-secret-keys",
                 "check-upstream", "signature signer mismatch", "allowlist mismatch"):
        assert gate in source, gate
    print("  19/19 release-candidate policy checks pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
