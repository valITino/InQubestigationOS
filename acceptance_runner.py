#!/usr/bin/env python3
"""Create and update an evidence-based Qubes hardware acceptance report."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

CHECKS = {
    "installation_encryption": "Installation and unique per-machine LUKS enrollment",
    "initial_setup_recovery_reboot": "Initial setup, interrupted provisioning, recovery and reboot",
    "inspected_path_fail_closed": "Complete inspected path and Suricata fail-closed behavior",
    "tor_and_offline_qubes": "Tor routing and offline-qube isolation (not an anonymity guarantee)",
    "services_and_agent_identity": "Squid, Suricata, Zeek, Wazuh and distinct agent identities",
    "credential_handover": "Credential rotation, verified escrow and dom0-copy removal",
    "real_isolated_restore": "Encrypted backup fully restored into an isolated destination",
    "backup_media_absent": "Backup operation fails observably when media is absent",
    "changed_credentials": "Changed credentials invalidate prior escrow and prevent shredding",
    "repository_key_mismatch": "Repository-key mismatch rolls back and fails",
    "wazuh_upgrade_order": "Wazuh manager upgrades before all agents",
    "maintenance_failures": "Maintenance failures reach systemd and status output",
    "golden_verify": "golden-image-provision --verify acceptance suite",
}
SECRET = re.compile(r"(?i)(pass(word|phrase)?|token|secret)(\s*[:=]\s*)(\S+)")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def command(*argv: str) -> tuple[int, str]:
    p = subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    return p.returncode, (p.stdout + p.stderr).strip()


def redact(text: str) -> str:
    return SECRET.sub(lambda m: m.group(1) + m.group(3) + "[REDACTED]", text)[-12000:]


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(4 << 20), b""):
            h.update(block)
    return h.hexdigest()


def pending_report(revision: str, image: Path | None) -> dict:
    return {
        "schema": 1, "kind": "Qubes hardware acceptance",
        "release_status": "release-candidate-not-hardware-verified",
        "created_utc": now(), "updated_utc": now(), "repository_revision": revision,
        "image": {"path": str(image) if image else None,
                  "sha256": digest(image) if image and image.is_file() else None},
        "hardware": {}, "platform": {}, "provisioning": {}, "logs": {},
        "checks": {key: {"description": desc, "status": "pending",
                         "evidence": "not executed on an authorized Qubes spare"}
                   for key, desc in CHECKS.items()},
    }


def collect(report: dict) -> None:
    if not Path("/etc/qubes-release").is_file() or not shutil_which("qvm-ls"):
        raise RuntimeError("collect must run in the authorized Qubes test machine's dom0")
    report["platform"]["qubes_release"] = Path("/etc/qubes-release").read_text().strip()
    for key, argv in {
        "xen": ("xl", "info"), "dom0_kernel": ("uname", "-a"),
        "hardware": ("dmidecode", "-t", "system"),
    }.items():
        rc, out = command(*argv)
        if key == "hardware":
            serial = re.search(r"(?m)^\s*Serial Number:\s*(.+)$", out)
            out = re.sub(r"(?m)^(\s*Serial Number:\s*).+$",
                         lambda m: m.group(1) + "sha256:" + hashlib.sha256(
                             serial.group(1).encode()).hexdigest()[:16] if serial else m.group(0), out)
            report["hardware"] = {"dmidecode_rc": rc, "identification": redact(out)}
        else:
            report["platform"][key] = {"rc": rc, "output": redact(out)}
    state = Path.home() / "golden-image/.build-state"
    firstboot = Path("/var/lib/golden-image/firstboot-status")
    report["provisioning"] = {
        "phase_state": state.read_text().split() if state.is_file() else [],
        "firstboot": redact(firstboot.read_text()) if firstboot.is_file() else "missing",
        "completion_marker": Path("/var/lib/golden-image/provisioned").exists(),
        "issuance_record": Path("/var/lib/golden-image/issuance").exists(),
    }
    rc, out = command("golden-image-provision", "--verify")
    report["checks"]["golden_verify"] = {
        "description": CHECKS["golden_verify"], "status": "pass" if rc == 0 else "fail",
        "evidence": redact(f"rc={rc}\n{out}")}
    for name, path in {
        "firstboot": "/var/lib/golden-image/firstboot-status",
        "selfcheck": "/var/log/golden-image-selfcheck.log",
        "backup_integrity": "/var/log/golden-image-restore-test.log",
        "key_refresh": "/var/log/golden-image-key-refresh.log",
    }.items():
        p = Path(path)
        report["logs"][name] = redact(p.read_text()) if p.is_file() else "missing"


def shutil_which(name: str) -> str | None:
    import shutil
    return shutil.which(name)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", required=True, type=Path)
    p.add_argument("--revision", default="unknown")
    p.add_argument("--image", type=Path)
    p.add_argument("--prepare-pending", action="store_true")
    p.add_argument("--collect", action="store_true")
    p.add_argument("--record", action="append", default=[], metavar="CHECK=STATUS:EVIDENCE")
    p.add_argument("--issue", action="store_true")
    p.add_argument("--operator", help="actual authorized operator; no default")
    a = p.parse_args()
    report = json.loads(a.report.read_text()) if a.report.exists() else pending_report(
        a.revision, a.image)
    if a.collect:
        collect(report)
    for item in a.record:
        key, value = item.split("=", 1)
        status, evidence = value.split(":", 1)
        if key not in CHECKS or status not in ("pass", "fail", "pending"):
            raise ValueError(f"invalid acceptance record: {item}")
        report["checks"][key] = {"description": CHECKS[key], "status": status,
                                 "evidence": redact(evidence), "recorded_utc": now()}
    report["updated_utc"] = now()
    failures = [k for k, v in report["checks"].items() if v["status"] == "fail"]
    pending = [k for k, v in report["checks"].items() if v["status"] == "pending"]
    report["summary"] = {"pass": len(CHECKS) - len(failures) - len(pending),
                         "fail": len(failures), "pending": len(pending),
                         "failures": failures, "pending_checks": pending}
    if not failures and not pending:
        report["release_status"] = "hardware-accepted-not-issued"
    a.report.parent.mkdir(parents=True, exist_ok=True)
    a.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    a.report.chmod(0o600)
    if a.issue:
        if not a.operator:
            raise RuntimeError("--issue requires the actual authorized --operator identity")
        if failures or pending:
            raise RuntimeError("cannot issue while acceptance checks failed or remain pending")
        escrow = Path.home() / "golden-image/escrow.json"
        credentials = Path.home() / "golden-image/credentials.json"
        if credentials.exists() or not escrow.exists():
            raise RuntimeError("credential handover is incomplete")
        subprocess.run(["golden-image-provision", "--issue", "--operator", a.operator],
                       check=True)
        report["release_status"] = "issued"
        report["operator"] = a.operator
        report["issued_utc"] = now()
        a.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"report: {a.report}; fail={len(failures)} pending={len(pending)}")
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"ACCEPTANCE FAILED: {exc}", file=sys.stderr)
        raise SystemExit(2)
