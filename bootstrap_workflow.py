#!/usr/bin/env python3
"""Non-secret bootstrap onboarding, destination validation, status and export.

This module intentionally supports one transport: an already guest-visible
mounted filesystem.  It never guesses a hypervisor, mounts an arbitrary block
device, or mistakes a directory on ``/`` for host storage.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path


EXPORT_ALLOWLIST = (
    "InQubestigationOS.iso", "InQubestigationOS.iso.sha256",
    "InQubestigationOS.iso.asc", "unit-signing-key.asc", "verify-iso.sh",
    "verify-iso.ps1", "FINGERPRINT.txt", "BUILD-RECORD.txt",
)


class BootstrapWorkflow:
    VERSION = 1

    def __init__(self, ctx):
        self.x = ctx
        self.cfg = ctx.c["bootstrap"]
        self.started = datetime.now(timezone.utc)
        self.run_id = str(uuid.uuid4())
        self.status_path = ctx.work / "bootstrap-status.json"
        self.summary_path = ctx.work / "bootstrap-status.txt"
        self.inventory_path = ctx.work / "location-inventory.json"
        self.lock_path = ctx.work / ".bootstrap.lock"
        self.lock_file = None
        self.completed: list[str] = []

    @property
    def backup_path(self) -> Path | None:
        value = self.cfg.get("backup_path", "")
        return Path(value) if value else None

    def _mount(self, path: Path) -> dict | None:
        """Return kernel mount identity using findmnt's structured interface."""
        p = subprocess.run(
            ["findmnt", "--json", "--target", str(path),
             "--output", "TARGET,SOURCE,FSTYPE,OPTIONS"],
            capture_output=True, text=True)
        if p.returncode:
            return None
        rows = json.loads(p.stdout).get("filesystems", [])
        return rows[0] if len(rows) == 1 else None

    def _validate(self, role: str, *, minimum_mb: int) -> tuple[Path, dict]:
        path = Path(self.cfg.get(f"{role}_path", ""))
        expected_source = self.cfg.get(f"{role}_source", "")
        expected_type = self.cfg.get(f"{role}_fstype", "")
        kind = self.cfg.get(f"{role}_kind", "") if role == "backup" else "host-share"
        if not str(path) or str(path) == ".":
            raise ValueError(f"{role}: guest-visible path is not configured")
        if not path.is_dir():
            raise ValueError(f"{role}: configured path is unavailable: {path}")
        mount = self._mount(path)
        if not mount or mount.get("target") == "/":
            raise ValueError(f"{role}: {path} is not on a separate mounted filesystem")
        if not expected_source or not expected_type:
            raise ValueError(f"{role}: approved mount source and filesystem type are missing")
        if mount.get("source") != expected_source or mount.get("fstype") != expected_type:
            raise ValueError(f"{role}: mount identity changed (expected {expected_source} "
                             f"{expected_type}; found {mount.get('source')} {mount.get('fstype')})")
        opts = set(mount.get("options", "").split(","))
        if "ro" in opts or not os.access(path, os.W_OK | os.X_OK):
            raise ValueError(f"{role}: destination is read-only or not writable")
        if shutil.disk_usage(path).free < minimum_mb * 1024**2:
            raise ValueError(f"{role}: less than {minimum_mb} MiB is available")
        if role == "backup" and kind not in ("physical-device", "host-share"):
            raise ValueError("backup: kind must establish physical-device or host-share; "
                             "unknown/guest virtual storage is not an approved backup")
        return path, mount

    def onboard(self, args) -> None:
        """Aggregate every knowable failure before any expensive child runs."""
        if args.to and not self.cfg.get("backup_path"):
            raise ValueError("--to supplies only a path and cannot establish media identity; "
                             "configure bootstrap.backup_path/source/fstype/kind")
        missing = []
        if not self.x.c.get("iso_sign_key") and not (args.uid or args.use_key):
            missing.append("signing identity: pass --uid/--use-key or configure iso_sign_key")
        if not args.passphrase_file:
            missing.append("runtime signing/backup authorization: --passphrase-file is required")
        else:
            try:
                from build_iso import protected_secret_file
                protected_secret_file(args)
            except Exception as exc:
                missing.append(f"runtime secret source: {exc}")
        for role, minimum in (("backup", self.cfg["min_backup_mb"]),
                              ("export", self.cfg["min_export_mb"])):
            if role == "export" and self.cfg.get("build_only"):
                continue
            try:
                self._validate(role, minimum_mb=int(minimum))
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                missing.append(str(exc))
        if self.backup_path and self.cfg.get("export_path"):
            if self.backup_path.resolve() == Path(self.cfg["export_path"]).resolve():
                missing.append("backup and export destinations must be distinct")
        install = self.x.c["install"]
        if install.get("unattended") and not install.get("disk"):
            missing.append("unattended install requires a stable target disk identity")
        if missing:
            raise ValueError("upfront onboarding blocked before build:\n - " + "\n - ".join(missing))
        print("\nUPFRONT REVIEW (non-secret)")
        print(f"  work: {self.x.work}")
        print(f"  backup: {self.cfg['backup_kind']} {self.cfg['backup_source']} -> {self.backup_path}")
        if self.cfg.get("build_only"):
            print("  export: DISABLED (explicit build-only mode; no host export success)")
        else:
            host = self.cfg.get("host_path") or "unknown (no reliable mapping supplied)"
            print(f"  export guest path: {self.cfg['export_path']}; physical-host path: {host}")
        print("  runtime secret: protected source ready; value is neither logged nor persisted")
        print("  target install: physical boot/media selection, target-bound disk approval, "
              "LUKS enrollment, reboot unlock and local login remain separate actions")
        print("  acceptance/issuance: installed laptop reports these separately; online checks "
              "may remain pending")

    def acquire_lock(self) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_file = self.lock_path.open("a+")
        try:
            fcntl.flock(self.lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError(f"another bootstrap owns {self.lock_path}") from exc

    def _write_status(self, state: str, stage: str, detail: str = "") -> None:
        now = datetime.now(timezone.utc)
        record = {"schema": self.VERSION, "run_id": self.run_id,
                  "environment": "build-vm", "state": state, "stage": stage,
                  "started_utc": self.started.isoformat(), "updated_utc": now.isoformat(),
                  "elapsed_seconds": round((now - self.started).total_seconds(), 3),
                  "completed_stages": self.completed, "detail": detail,
                  "log": str(self.x.log), "resume": "./build_iso.py bootstrap --yes "
                  "--passphrase-file <protected-runtime-file>"}
        tmp = self.status_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        os.replace(tmp, self.status_path)
        self.summary_path.write_text(f"{state}: {stage}\n{detail}\nstatus: {self.status_path}\n")

    def stage(self, name: str, state: str, detail: str) -> None:
        if state == "complete" and name not in self.completed:
            self.completed.append(name)
        self._write_status(state, name, detail)
        print(f"[bootstrap:{state}] {name}: {detail}")

    @staticmethod
    def _hash(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(4 << 20), b""):
                h.update(block)
        return h.hexdigest()

    def export_release(self) -> None:
        if self.cfg.get("build_only"):
            self.stage("export", "blocked", "explicit build-only mode")
            return
        destination, identity = self._validate("export", minimum_mb=int(self.cfg["min_export_mb"]))
        names = list(EXPORT_ALLOWLIST)
        names[0] = self.x.c["iso_name"]
        names[1] = self.x.c["iso_name"] + ".sha256"
        names[2] = self.x.c["iso_name"] + ".asc"
        missing = [name for name in names if not (self.x.out_dir / name).is_file()]
        if missing:
            raise ValueError(f"export allowlist incomplete: {missing}")
        release = f"release-{self.x.state_digest('build')[:12]}"
        final = destination / release
        staging = destination / (release + f".incomplete-{self.run_id}")
        if final.exists():
            # A prior valid publication is immutable; verify rather than replace.
            for name in names:
                if not (final / name).is_file() or self._hash(final / name) != self._hash(self.x.out_dir / name):
                    raise ValueError(f"existing release differs: {final}")
        else:
            staging.mkdir(mode=0o755)
            for name in names:
                source, target = self.x.out_dir / name, staging / name
                shutil.copy2(source, target)
                if self._hash(source) != self._hash(target):
                    raise ValueError(f"destination readback mismatch: {name}")
                self._validate("export", minimum_mb=0)  # detect share disappearance
            os.replace(staging, final)
        artifacts = {name: {"bytes": (final / name).stat().st_size,
                            "sha256": self._hash(final / name)} for name in names}
        inventory = {"schema": self.VERSION, "repository": str(Path(__file__).parent),
                     "machine": "build-vm", "work": str(self.x.work),
                     "output": str(self.x.out_dir), "log": str(self.x.log),
                     "status": str(self.status_path), "gnupg_home": os.environ.get(
                         "GNUPGHOME", str(Path.home() / ".gnupg")),
                     "signing_fingerprint": self.x.c.get("iso_sign_key"),
                     "backup": {"path": str(self.backup_path), "source": self.cfg["backup_source"],
                                "kind": self.cfg["backup_kind"], "verification": "bootstrap stage"},
                     "export": {"guest_path": str(final), "mount": identity,
                                "host_path": self.cfg.get("host_path") or None,
                                "host_mapping_source": "operator-configured" if self.cfg.get("host_path") else "unknown",
                                "verified": True, "artifacts": artifacts},
                     "runtime_secret": {"persisted": False, "value_reported": False}}
        self.inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")
        self.stage("export", "complete", f"readback verified at {final}")

    def finish(self) -> None:
        self._write_status("complete", "bootstrap", "build and required export verified")
