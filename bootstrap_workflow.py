#!/usr/bin/env python3
"""Guided bootstrap, safe mount preparation, truthful status and export."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import sys
import getpass
import tempfile
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
        self.mounted: list[Path] = []
        self.secret_files: list[Path] = []
        self.data_paths: dict[str, Path] = {}
        self.current_stage = "starting"

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

    @staticmethod
    def discover_block_filesystems() -> list[dict]:
        """Return only existing filesystems; never propose blank disks."""
        p = subprocess.run(["lsblk", "--json", "--paths", "--bytes",
                            "--output", "NAME,TYPE,SIZE,FSTYPE,UUID,LABEL,MODEL,MOUNTPOINTS,RM"],
                           capture_output=True, text=True)
        if p.returncode:
            return []
        result = []
        def walk(rows):
            if not isinstance(rows, list):
                raise TypeError("block device collection is not a list")
            for row in rows:
                if not isinstance(row, dict):
                    raise TypeError("block device entry is not an object")
                mountpoints = row.get("mountpoints")
                if mountpoints is None:
                    row["mountpoints"] = []
                elif not isinstance(mountpoints, list) or any(
                        value is not None and not isinstance(value, str)
                        for value in mountpoints):
                    raise TypeError("mountpoints is not a string/null array")
                else:
                    row["mountpoints"] = [value for value in mountpoints if value]
                if row.get("fstype") and row.get("type") in ("part", "crypt", "lvm"):
                    result.append(row)
                walk(row.get("children") or [])
        try:
            walk(json.loads(p.stdout).get("blockdevices", []))
        except (TypeError, json.JSONDecodeError, AttributeError):
            return []
        return result

    def _run_privileged(self, argv: list[str]) -> None:
        command = argv if os.geteuid() == 0 else ["sudo", *argv]
        rc = subprocess.run(command).returncode
        if rc:
            raise ValueError(f"authorized command failed ({rc}): {' '.join(argv)}")

    def _privileged_directory_empty(self, path: Path) -> bool:
        command = ["find", str(path), "-mindepth", "1", "-maxdepth", "1", "-print", "-quit"]
        if os.geteuid() != 0:
            command.insert(0, "sudo")
        probe = subprocess.run(command, capture_output=True, text=True)
        if probe.returncode:
            raise ValueError(f"cannot safely inspect workflow mountpoint {path}")
        return not probe.stdout

    def prepare_mount(self, role: str) -> tuple[Path, dict]:
        """Mount an explicitly selected, preformatted block/share resource."""
        path = Path(self.cfg[f"{role}_path"])
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError(f"{role}: mountpoint must be an absolute normalized path")
        source = self.cfg[f"{role}_source"]
        fstype = self.cfg[f"{role}_fstype"]
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent.exists()):
            raise ValueError(f"{role}: mountpoint or parent is an unsafe symlink")
        existing = self._mount(path) if path.exists() else None
        if existing and existing.get("target") == str(path):
            return self._validate(role, minimum_mb=0, prepare_data=True)
        if path.exists():
            if not path.is_dir():
                raise ValueError(f"{role}: unmounted mountpoint is not an empty directory")
            try:
                occupied = any(path.iterdir())
            except PermissionError:
                # install(1) creates these restricted directories. Inspect a
                # retry through the same narrow privilege boundary rather than
                # assuming the old process can enumerate it.
                st = path.stat()
                owned_mountpoint = (st.st_uid == 0 and st.st_mode & 0o777 == 0o700
                                    and path.name == f"inqubestigation-{role}")
                if not owned_mountpoint:
                    raise ValueError(f"{role}: cannot safely inspect unmounted mountpoint")
                occupied = not self._privileged_directory_empty(path)
            if occupied:
                raise ValueError(f"{role}: unmounted mountpoint is not an empty directory")
        if not source or not fstype:
            raise ValueError(f"{role}: no approved mount identity")
        if fstype not in {"ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "exfat",
                          "ntfs3", "virtiofs", "9p", "cifs", "nfs", "nfs4"}:
            raise ValueError(f"{role}: unsupported mount filesystem {fstype}")
        # Credentials must be supplied by the provider/kernel mechanism; never
        # place them in configuration or argv.
        options = "nodev,nosuid"
        if fstype in {"virtiofs", "9p"}:
            options += ",noexec"
        if fstype in {"vfat", "exfat", "ntfs3"}:
            options += f",uid={os.getuid()},gid={os.getgid()},umask=0077"
        self.stage(role, "preparing", f"mounting approved {source} at {path}")
        # Creation beneath /mnt is intentionally privileged.  install(1) is
        # argv-only and does not traverse a caller-provided shell expression.
        self._run_privileged(["install", "-d", "-m", "0700", "--", str(path)])
        self._run_privileged(["mount", "-t", fstype, "-o", options, source, str(path)])
        self.mounted.append(path)
        try:
            return self._validate(role, minimum_mb=0, prepare_data=True)
        except Exception:
            self._run_privileged(["umount", str(path)])
            self.mounted.remove(path)
            raise

    def _ask(self, heading: str, explanation: str, default: str = "") -> str:
        print(f"\n[{heading}] {explanation}")
        suffix = f" [{default}]" if default else ""
        answer = input(f">{suffix}: ").strip()
        return answer or default

    def _secret(self, label: str) -> Path:
        first = getpass.getpass(f"{label} (hidden; held only for this run): ")
        second = getpass.getpass(f"Confirm {label}: ")
        if not first or first != second:
            raise ValueError(f"{label}: values were empty or did not match")
        runtime = Path(os.environ.get("XDG_RUNTIME_DIR", tempfile.gettempdir()))
        fd, name = tempfile.mkstemp(prefix="inqubestigation-", dir=runtime)
        path = Path(name)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(first)
        self.secret_files.append(path)
        return path

    def guided_setup(self, args) -> None:
        """Collect and persist non-secret choices; secrets remain run-scoped."""
        profile_complete = (self.cfg.get("profile_version") == self.VERSION and
                            all(self.cfg.get(k) for k in
                            ("backup_path", "backup_source", "backup_fstype",
                             "backup_kind")) and
                            (self.cfg.get("build_only") or all(self.cfg.get(k) for k in
                             ("export_path", "export_source", "export_fstype", "export_kind"))) and
                            (self.x.c.get("iso_sign_key") or args.uid or args.use_key))
        if (profile_complete and not getattr(args, "review_profile", False)) or getattr(args, "non_interactive", False):
            return
        if not sys.stdin.isatty():
            return
        print("\nGUIDED SETUP — build VM")
        print("Measured resources are shown first. Mounting changes no filesystem; "
              "formatting and target-disk selection are never inferred or approved by --yes.")
        devices = self.discover_block_filesystems()
        for i, d in enumerate(devices, 1):
            print(f"  {i}. {d.get('name')}  {d.get('label') or '(no label)'}  "
                  f"{d.get('fstype')}  {int(d.get('size') or 0)//(1024**3)} GiB  "
                  f"mounted: {', '.join(d.get('mountpoints', [])) or 'unmounted'}")
        changed = False
        for role, kind in (("backup", "physical-device"), ("export", "host-share")):
            if self.cfg.get(f"{role}_source"):
                continue
            print(f"\n{role.title()} storage is reusable, non-secret, and stored in iso-build.json.")
            if role == "export":
                choice = self._ask(role, "Type 'share' for an authenticated physical-host "
                                   "share, or 'build-only' to defer distribution")
                if choice == "build-only":
                    self.cfg["build_only"] = True
                    changed = True
                    continue
            else:
                choice = self._ask(role, "Select a detected preformatted filesystem number, "
                                   "or type 'share' for an already exposed host share")
            if choice.isdigit() and 1 <= int(choice) <= len(devices):
                if role == "export":
                    raise ValueError("export: a guest block device cannot establish an "
                                     "authenticated physical-host publication")
                d = devices[int(choice)-1]
                stable = f"/dev/disk/by-uuid/{d['uuid']}" if d.get("uuid") else d["name"]
                self.cfg[f"{role}_source"] = stable
                self.cfg[f"{role}_fstype"] = d["fstype"]
                self.cfg["backup_kind"] = "physical-device"
            elif choice == "share":
                self.cfg[f"{role}_source"] = self._ask(role, "Provider mount source/tag "
                                                        "(not a password or host path)")
                self.cfg[f"{role}_fstype"] = self._ask(role, "Supported type: virtiofs, 9p, cifs, nfs4")
                if role == "backup":
                    self.cfg["backup_kind"] = "host-share"
                else:
                    self.cfg["export_kind"] = "host-share"
            else:
                raise ValueError(f"{role}: no unambiguous resource selected")
            self.cfg[f"{role}_path"] = self._ask(role, "Guest mountpoint (created automatically)",
                                                   f"/mnt/inqubestigation-{role}")
            changed = True
        install = self.x.c["install"]
        mode = self._ask("Installation mode", "Choose 'manual' for target-side Anaconda "
                         "choices or 'unattended' for an exact destructive target binding",
                         "unattended" if install.get("unattended") else "manual")
        if mode not in ("manual", "unattended"):
            raise ValueError("installation mode must be manual or unattended")
        install["unattended"] = mode == "unattended"
        install["disk"] = (self._ask("Target binding", "Stable /dev/disk/by-id identity "
                            "obtained and approved on the investigator laptop; not a build-VM disk")
                           if install["unattended"] else "")
        for key, title in (("username", "Target username"), ("lang", "Language"),
                           ("keyboard", "Keyboard"), ("timezone", "Timezone")):
            install[key] = self._ask(title, "Non-secret reusable installer setting; stored in iso-build.json",
                                     install[key])
        changed = True
        self.cfg["profile_version"] = self.VERSION
        if not self.x.c.get("iso_sign_key") and not (args.uid or args.use_key):
            keys = __import__("build_iso").secret_key_fingerprints()
            if len(keys) == 1:
                args.use_key = keys[0][0]
                print(f"Using the one existing signing key: {keys[0][0]} ({keys[0][1]})")
            else:
                args.uid = self._ask("Signing identity", "Public name/email for a new signing key. "
                                     "The private key remains in this user's GnuPG home")
        if changed:
            from build_iso import CONF_PATH, validate_config
            validate_config(self.x.c)
            tmp = CONF_PATH.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self.x.c, indent=2, sort_keys=True) + "\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, CONF_PATH)

    def prepare_dependencies(self, args) -> None:
        """Prepare discovery/transport tools before discovery or mounting."""
        authorized = bool(self.cfg.get("dependencies_authorized"))
        if not authorized:
            if getattr(args, "non_interactive", False) or not sys.stdin.isatty():
                raise ValueError("host dependency installation is not authorized; run bootstrap "
                                 "interactively once or set bootstrap.dependencies_authorized=true")
            print("\n[Host preparation] Discovery, filesystem, container, and installer "
                  "validation tools must be prepared before storage is inspected or mounted. "
                  "This uses the supported package manager with narrow sudo commands; no sudo "
                  "credential is stored.")
            answer = input("Authorize host prerequisite preparation? [y/N]: ").strip().lower()
            if answer not in ("y", "yes"):
                raise ValueError("host prerequisite preparation was not authorized")
            self.cfg["dependencies_authorized"] = True
            from build_iso import CONF_PATH, validate_config
            validate_config(self.x.c)
            tmp = CONF_PATH.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self.x.c, indent=2, sort_keys=True) + "\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, CONF_PATH)
        self.stage("setup-host", "running", "preparing helpers before discovery and mounts")
        child = [sys.executable, str(Path(__file__).resolve().parent / "build_iso.py"),
                 "setup-host", "--yes"]
        rc = subprocess.run(child).returncode
        if rc:
            raise ValueError(f"setup-host prerequisite preparation failed (child exited {rc})")
        self.stage("setup-host", "complete", "discovery and transport helpers prepared")

    def cleanup(self) -> list[str]:
        errors = []
        for path in self.secret_files:
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:
                errors.append(f"could not remove runtime secret {path}: {exc}")
        # Preserve mounts during a resumable workflow. They are unmounted only
        # after completion, and only if this run created them.
        for path in reversed(self.mounted):
            try:
                self._run_privileged(["umount", str(path)])
            except ValueError:
                errors.append(f"could not unmount workflow mount {path}")
        if self.lock_file is not None:
            fcntl.flock(self.lock_file, fcntl.LOCK_UN)
            self.lock_file.close()
            self.lock_file = None
        return errors

    def _validate(self, role: str, *, minimum_mb: int,
                  prepare_data: bool = False) -> tuple[Path, dict]:
        path = Path(self.cfg.get(f"{role}_path", ""))
        expected_source = self.cfg.get(f"{role}_source", "")
        expected_type = self.cfg.get(f"{role}_fstype", "")
        kind = self.cfg.get(f"{role}_kind", "")
        if not str(path) or str(path) == ".":
            raise ValueError(f"{role}: guest-visible path is not configured")
        if not path.is_dir():
            raise ValueError(f"{role}: configured path is unavailable: {path}")
        mount = self._mount(path)
        if not mount or mount.get("target") == "/":
            raise ValueError(f"{role}: {path} is not on a separate mounted filesystem")
        if not expected_source or not expected_type:
            raise ValueError(f"{role}: approved mount source and filesystem type are missing")
        actual_source = mount.get("source")
        same_source = actual_source == expected_source
        # Block aliases (/dev/disk/by-uuid, by-id, mapper and /dev nodes) are
        # equivalent only when the kernel reports the same device number.
        if expected_type not in {"virtiofs", "9p", "cifs", "nfs", "nfs4"}:
            try:
                expected_stat = os.stat(os.path.realpath(expected_source))
                actual_stat = os.stat(os.path.realpath(str(actual_source)))
                same_source = (expected_stat.st_rdev != 0 and
                               expected_stat.st_rdev == actual_stat.st_rdev)
            except (OSError, TypeError):
                # An unresolved configured identity is not silently trusted.
                same_source = False
        if not same_source or mount.get("fstype") != expected_type:
            raise ValueError(f"{role}: mount identity changed (expected {expected_source} "
                             f"{expected_type}; found {mount.get('source')} {mount.get('fstype')})")
        opts = set(mount.get("options", "").split(","))
        if "ro" in opts:
            raise ValueError(f"{role}: destination is read-only or not writable")
        data = path / ".inqubestigation" / role
        if prepare_data and not data.exists():
            self._run_privileged(["install", "-d", "-m", "0700", "-o", str(os.getuid()),
                                  "-g", str(os.getgid()), "--", str(data)])
        if not data.is_dir() or data.is_symlink() or not os.access(data, os.W_OK | os.X_OK):
            raise ValueError(f"{role}: dedicated data directory is unavailable or not writable")
        if shutil.disk_usage(data).free < minimum_mb * 1024**2:
            raise ValueError(f"{role}: less than {minimum_mb} MiB is available")
        if role == "backup" and kind not in ("physical-device", "host-share"):
            raise ValueError("backup: kind must establish physical-device or host-share; "
                             "unknown/guest virtual storage is not an approved backup")
        if role == "export" and (kind != "host-share" or expected_type not in
                                  {"virtiofs", "9p", "cifs", "nfs", "nfs4"}):
            raise ValueError("export: authenticated physical-host share transport is required")
        self.data_paths[role] = data
        return data, mount

    def onboard(self, args) -> None:
        """Aggregate every knowable failure before any expensive child runs."""
        if args.to and not self.cfg.get("backup_path"):
            raise ValueError("--to supplies only a path and cannot establish media identity; "
                             "configure bootstrap.backup_path/source/fstype/kind")
        self.guided_setup(args)
        missing = []
        if not self.x.c.get("iso_sign_key") and not (args.uid or args.use_key):
            missing.append("signing identity: pass --uid/--use-key or configure iso_sign_key")
        interactive = not getattr(args, "non_interactive", False) and sys.stdin.isatty()
        if not args.passphrase_file and not args.no_passphrase and interactive:
            args.passphrase_file = str(self._secret("signing-key authorization"))
        if not getattr(args, "backup_passphrase_file", None) and interactive:
            args.backup_passphrase_file = str(self._secret("backup-encryption authorization"))
        if not args.passphrase_file and not args.no_passphrase:
            missing.append("runtime signing authorization provider is missing in non-interactive mode")
        if not getattr(args, "backup_passphrase_file", None):
            missing.append("runtime backup-encryption authorization provider is missing in non-interactive mode")
        for label, raw in (("signing", args.passphrase_file),
                           ("backup encryption", getattr(args, "backup_passphrase_file", None))):
            if not raw:
                continue
            try:
                from build_iso import protected_secret_file, validate_config
                validate_config(self.x.c)
                protected_secret_file(type("SecretArgs", (), {"passphrase_file": raw})())
            except Exception as exc:
                missing.append(f"runtime {label} secret source: {exc}")
        for role, minimum in (("backup", self.cfg["min_backup_mb"]),
                              ("export", self.cfg["min_export_mb"])):
            if role == "export" and self.cfg.get("build_only"):
                continue
            try:
                self.prepare_mount(role)
                self._validate(role, minimum_mb=int(minimum), prepare_data=True)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                missing.append(str(exc))
        if self.backup_path and self.cfg.get("export_path"):
            if self.backup_path.resolve() == Path(self.cfg["export_path"]).resolve():
                missing.append("backup and export destinations must be distinct")
        install = self.x.c["install"]
        if install.get("unattended") and not install.get("disk"):
            missing.append("unattended install requires a stable target disk identity")
        if missing:
            self.current_stage = "onboarding"
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

    def initialize_inventory(self) -> None:
        """Publish planned locations immediately; never imply verification."""
        def item(machine, path, purpose, sensitivity, retention):
            return {"machine": machine, "path": str(Path(path).expanduser().absolute()) if path else None,
                    "purpose": purpose, "sensitivity": sensitivity, "state": "planned",
                    "verified": False, "retention": retention}
        inventory = {"schema": self.VERSION, "run_id": self.run_id,
                     "effective_config": item("build-vm", __import__("build_iso").CONF_PATH, "validated settings",
                                              "restricted", "retained"),
                     "work": item("build-vm", self.x.work, "build/cache/Docker working tree",
                                  "restricted", "retained for resume"),
                     "log": item("build-vm", self.x.log, "operation log", "restricted", "retained"),
                     "gnupg": item("build-vm", os.environ.get("GNUPGHOME", Path.home()/".gnupg"),
                                   "signing keyring", "secret", "retained"),
                     "backup": item("build-vm", self.cfg.get("backup_path"), "encrypted key backup",
                                    "secret-encrypted", "versioned"),
                     "export": item("build-vm", self.cfg.get("export_path"), "authenticated release",
                                    "public", "preserve verified releases"),
                     "native_host_export": {"machine": "physical-host",
                         "path": self.cfg.get("host_path") or None, "purpose": "release mapping",
                         "sensitivity": "public", "state": "operator-attested" if self.cfg.get("host_path") else "unknown",
                         "verified": False, "retention": "host policy"}}
        tmp = self.inventory_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.inventory_path)

    def _write_status(self, state: str, stage: str, detail: str = "") -> None:
        now = datetime.now(timezone.utc)
        record = {"schema": self.VERSION, "run_id": self.run_id,
                  "environment": "build-vm", "state": state, "stage": stage,
                  "started_utc": self.started.isoformat(), "updated_utc": now.isoformat(),
                  "elapsed_seconds": round((now - self.started).total_seconds(), 3),
                  "completed_stages": self.completed, "detail": detail,
                  "log": str(self.x.log), "resume": "./build_iso.py bootstrap --yes "
                  "(runtime authorizations are collected afresh)"}
        tmp = self.status_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        os.replace(tmp, self.status_path)
        self.summary_path.write_text(f"{state}: {stage}\n{detail}\nstatus: {self.status_path}\n")

    def stage(self, name: str, state: str, detail: str) -> None:
        self.current_stage = name
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
        destination, identity = self._validate("export", minimum_mb=0)
        names = list(EXPORT_ALLOWLIST)
        names[0] = self.x.c["iso_name"]
        names[1] = self.x.c["iso_name"] + ".sha256"
        names[2] = self.x.c["iso_name"] + ".asc"
        missing = [name for name in names if not (self.x.out_dir / name).is_file()]
        if missing:
            raise ValueError(f"export allowlist incomplete: {missing}")
        total = sum((self.x.out_dir / name).stat().st_size for name in names)
        if shutil.disk_usage(destination).free < total:
            raise ValueError(f"export needs {total} bytes but the destination has insufficient space")
        self._verify_release(self.x.out_dir, names)
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
            # Authenticate bytes at the destination before publishing the
            # release name.  A failed signature leaves only `.incomplete-*`.
            self._verify_release(staging, names)
            self._validate("export", minimum_mb=0)
            os.replace(staging, final)
        self._verify_release(final, names)
        artifacts = {name: {"bytes": (final / name).stat().st_size,
                            "sha256": self._hash(final / name)} for name in names}
        inventory = json.loads(self.inventory_path.read_text())
        inventory["signing_fingerprint"] = self.x.c.get("iso_sign_key")
        inventory["runtime_secret"] = {"persisted": False, "value_reported": False}
        inventory["backup"].update(
            path=str(self.data_paths.get("backup", self.backup_path)), state="verified",
            verified=True, source=self.cfg["backup_source"], kind=self.cfg["backup_kind"])
        inventory["export"].update(
            path=str(final), state="verified", verified=True, mount=identity,
            artifacts=artifacts)
        host_root = self.cfg.get("host_path")
        inventory["native_host_export"].update(
            path=str(Path(host_root) / release) if host_root else None,
            state="operator-attested" if host_root else "unknown", verified=False)
        tmp = self.inventory_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.inventory_path)
        self.stage("export", "complete", f"checksum, trusted signature and readback verified at {final}")

    def _verify_release(self, directory: Path, names: list[str]) -> None:
        iso, checksum, signature = (directory / names[i] for i in range(3))
        fields = checksum.read_text().split()
        if not fields or fields[0].lower() != self._hash(iso):
            raise ValueError("ISO checksum authentication failed")
        expected = self.x.c["iso_sign_key"].replace(" ", "").upper()
        p = subprocess.run(["gpg", "--batch", "--status-fd", "1", "--verify",
                            str(signature), str(iso)], capture_output=True, text=True)
        valid = []
        for line in p.stdout.splitlines():
            parts = line.split()
            if line.startswith("[GNUPG:] VALIDSIG "):
                valid.extend([parts[2].upper(), parts[-1].upper()])
        if p.returncode or expected not in valid:
            raise ValueError(f"ISO signature is not authenticated by configured identity {expected}")

    def finish(self) -> None:
        detail = ("build complete; export not requested" if self.cfg.get("build_only") else
                  "build complete; exported bytes and trusted signature verified")
        self._write_status("complete", "bootstrap", detail)
