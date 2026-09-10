#!/usr/bin/env python3
"""Offline policy checks for the trusted release-candidate entry point."""
from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "release_candidate", ROOT / "release_candidate.py")
rc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rc)


def main():
    workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text()
    validation_name = "- name: Validate the environment-approved immutable commit"
    checkout_name = "- name: Check out only the environment-approved immutable commit"
    secret_name = "- name: Materialize the short-lived signing session"
    start = workflow.index(validation_name)
    run_at = workflow.index("        run: |\n", start) + len("        run: |\n")
    end = workflow.index("      - name:", run_at)
    validation_script = "\n".join(
        line[10:] if line.startswith("          ") else line
        for line in workflow[run_at:end].splitlines()) + "\n"
    assert start < workflow.index(checkout_name) < workflow.index(secret_name)
    assert "${{ inputs.trusted_commit }}" not in validation_script
    assert "${{ vars.TRUSTED_BUILD_REF }}" not in validation_script
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "workflow_dispatch:" in workflow and "pull_request:" not in workflow
    assert "inqubestigation-trusted-build" in workflow
    assert "environment: production-build" in workflow
    assert "inputs.trusted_commit == vars.TRUSTED_BUILD_REF" not in workflow
    assert "github.event.repository.default_branch" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "persist-credentials: false" in workflow
    assert "upload-artifact" not in workflow and "IQ_GPG_SESSION_SECRET" in workflow

    # Execute the exact shell used before checkout, not a reimplementation.
    cases = (
        ({}, 1),
        ({"REQUESTED_SHA": "", "APPROVED_SHA": "a" * 40}, 1),
        ({"REQUESTED_SHA": "a" * 40}, 1),
        ({"REQUESTED_SHA": "a" * 40, "APPROVED_SHA": ""}, 1),
        ({"REQUESTED_SHA": "main", "APPROVED_SHA": "a" * 40}, 1),
        ({"REQUESTED_SHA": "a" * 39, "APPROVED_SHA": "a" * 40}, 1),
        ({"REQUESTED_SHA": "a" * 41, "APPROVED_SHA": "a" * 40}, 1),
        ({"REQUESTED_SHA": "g" * 40, "APPROVED_SHA": "a" * 40}, 1),
        ({"REQUESTED_SHA": "a" * 40, "APPROVED_SHA": "b" * 40}, 1),
        ({"REQUESTED_SHA": "A" * 40, "APPROVED_SHA": "a" * 40}, 0),
    )
    with tempfile.TemporaryDirectory() as td:
        github_env = Path(td) / "github-env"
        for values, expected in cases:
            github_env.write_text("")
            env = {**os.environ, "GITHUB_ENV": str(github_env), **values}
            result = subprocess.run(["bash", "-c", validation_script], env=env,
                                    capture_output=True, text=True)
            assert result.returncode == expected, (values, result.stderr)
        assert github_env.read_text() == f"TRUSTED_SHA={'a' * 40}\n"
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
    print("  23/23 release-candidate policy checks pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
