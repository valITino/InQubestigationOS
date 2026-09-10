#!/usr/bin/env python3
"""Build, verify, and stage one explicitly allowlisted release candidate."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
ALLOWLIST = (
    "InQubestigationOS.iso", "InQubestigationOS.iso.sha256",
    "InQubestigationOS.iso.asc", "unit-signing-key.asc", "verify-iso.sh",
    "verify-iso.ps1", "FINGERPRINT.txt", "BUILD-RECORD.txt",
)


class Gate(Exception):
    pass


def run(argv, **kw):
    return subprocess.run(argv, text=True, **kw)


def free_gb(path: Path) -> int:
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize // 1024**3


def git(*args: str) -> str:
    p = run(["git", *args], cwd=ROOT, capture_output=True)
    if p.returncode:
        raise Gate(p.stderr.strip() or f"git {' '.join(args)} failed")
    return p.stdout.strip()


def verify_signature(iso: Path, signature: Path, expected: str) -> None:
    p = run(["gpg", "--batch", "--status-fd", "1", "--verify",
             str(signature), str(iso)], capture_output=True)
    valid = [line.split()[2].upper() for line in p.stdout.splitlines()
             if line.startswith("[GNUPG:] VALIDSIG ")]
    if p.returncode or valid != [expected.upper()]:
        raise Gate(f"signature signer mismatch: expected {expected}, got {valid}")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(4 << 20), b""):
            h.update(block)
    return h.hexdigest()


def copy_redacted_log(source: Path, destination: Path, secret_file: Path) -> None:
    """Copy the audit log while defensively removing the runtime secret value."""
    data = source.read_bytes()
    secret = secret_file.read_bytes().rstrip(b"\r\n")
    if secret:
        data = data.replace(secret, b"[REDACTED RUNTIME SECRET]")
    destination.write_bytes(data)
    destination.chmod(0o600)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--expected-ref", required=True, help="approved full commit SHA")
    p.add_argument("--config", required=True, type=Path)
    p.add_argument("--work-dir", required=True, type=Path)
    p.add_argument("--backup-dir", required=True, type=Path)
    p.add_argument("--candidate-dir", required=True, type=Path)
    p.add_argument("--passphrase-file", required=True, type=Path)
    p.add_argument("--signing-fingerprint", required=True)
    p.add_argument("--min-work-gb", type=int, default=250)
    p.add_argument("--min-docker-gb", type=int, default=100)
    p.add_argument("--max-artifact-gb", type=int, default=20)
    a = p.parse_args()

    expected = a.expected_ref.upper()
    if not re.fullmatch(r"[0-9A-F]{40}", expected):
        raise Gate("--expected-ref must be an exact 40-hex commit, never a branch")
    actual = git("rev-parse", "HEAD").upper()
    if actual != expected:
        raise Gate(f"checkout {actual} is not approved ref {expected}")
    if os.uname().machine not in ("x86_64", "amd64"):
        raise Gate("release candidates require a dedicated x86-64 runner")
    if os.geteuid() == 0:
        raise Gate("run as the non-root build identity")
    if run(["sudo", "-n", "true"]).returncode:
        raise Gate("sudo session is not ready for unattended host setup")
    for tool in ("docker", "gpg", "git", "python3"):
        if not shutil.which(tool):
            raise Gate(f"required dependency missing: {tool}")
    if run(["docker", "ps"], stdout=subprocess.DEVNULL,
           stderr=subprocess.DEVNULL).returncode:
        raise Gate("Docker is not usable by the build identity")
    docker_root = run(["docker", "info", "--format", "{{.DockerRootDir}}"],
                      capture_output=True, check=True).stdout.strip()
    for path, minimum, label in ((a.work_dir, a.min_work_gb, "work_dir"),
                                  (Path(docker_root), a.min_docker_gb, "Docker storage")):
        path.mkdir(parents=True, exist_ok=True)
        available = free_gb(path)
        if available < minimum:
            raise Gate(f"{label} has {available} GiB free; {minimum} GiB required")
    if not a.config.is_file():
        raise Gate(f"approved release config missing: {a.config}")
    cfg = json.loads(a.config.read_text())
    fingerprint = a.signing_fingerprint.replace(" ", "").upper()
    if cfg.get("tier") != 2 or cfg.get("iso_sign_key", "").upper() != fingerprint:
        raise Gate("release config must set tier=2 and the approved signing fingerprint")
    if str(cfg.get("work_dir")) != str(a.work_dir):
        raise Gate("release config work_dir does not match --work-dir")
    remote = str(cfg.get("component_remote", ""))
    parsed_remote = urlsplit(remote)
    if parsed_remote.username or parsed_remote.password:
        raise Gate("component_remote must not embed credentials; use a protected "
                   "runner credential helper")
    st = a.passphrase_file.stat()
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise Gate("runtime passphrase file must be owned by this user and mode 0600")
    if run(["gpg", "--batch", "--list-secret-keys", fingerprint],
           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        raise Gate("approved secret signing key is unavailable")
    for mounted in (a.backup_dir, a.candidate_dir):
        mounted.mkdir(parents=True, exist_ok=True)
        probe = mounted.resolve()
        while probe != probe.parent and not os.path.ismount(probe):
            probe = probe.parent
        if probe == Path("/"):
            raise Gate(f"{mounted} must be on an owner-mounted external filesystem")

    shutil.copy2(a.config, ROOT / "iso-build.json")
    # Drift is a separate blocking gate. It never updates the committed baseline.
    subprocess.run([sys.executable, "build_iso.py", "check-upstream"], cwd=ROOT,
                   check=True)
    command = [sys.executable, "build_iso.py", "bootstrap", "--yes",
               "--use-key", fingerprint, "--passphrase-file",
               str(a.passphrase_file), "--to", str(a.backup_dir)]
    subprocess.run(command, cwd=ROOT, check=True)

    output = a.work_dir / "output"
    missing = [name for name in ALLOWLIST if not (output / name).is_file()]
    extras = [p.name for p in output.iterdir() if p.is_file() and p.name not in ALLOWLIST]
    if missing or extras:
        raise Gate(f"release allowlist mismatch; missing={missing}, unexpected={extras}")
    iso = output / ALLOWLIST[0]
    digest = sha256(iso)
    if (output / ALLOWLIST[1]).read_text().split()[0].lower() != digest:
        raise Gate("ISO checksum does not match")
    verify_signature(iso, output / ALLOWLIST[2], fingerprint)
    size = sum((output / name).stat().st_size for name in ALLOWLIST)
    if size > a.max_artifact_gb * 1024**3:
        raise Gate(f"candidate is {size / 1024**3:.1f} GiB; owner limit is "
                   f"{a.max_artifact_gb} GiB")

    builder = a.work_dir / "qubes-builderv2"
    result = {
        "status": "verified-release-candidate", "created_utc": datetime.now(timezone.utc).isoformat(),
        "repository_commit": actual, "builder_commit": run(
            ["git", "rev-parse", "HEAD"], cwd=builder, capture_output=True,
            check=True).stdout.strip(), "config_sha256": sha256(a.config),
        "iso_sha256": digest, "signer": fingerprint,
        "artifacts": {name: sha256(output / name) for name in ALLOWLIST},
    }
    audit = a.work_dir / "release-audit"
    audit.mkdir(mode=0o700, exist_ok=True)
    (audit / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    copy_redacted_log(a.work_dir / "build.log", audit / "build.log",
                      a.passphrase_file)

    candidate = a.candidate_dir / f"rc-{actual[:12]}"
    if candidate.exists():
        raise Gate(f"candidate already exists: {candidate}")
    candidate.mkdir(mode=0o755)
    for name in ALLOWLIST:
        shutil.copy2(output / name, candidate / name)
    print(json.dumps(result, sort_keys=True))
    print(f"staged only {len(ALLOWLIST)} allowlisted files at {candidate}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Gate, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"RELEASE GATE FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
