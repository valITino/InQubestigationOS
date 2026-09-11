#!/usr/bin/env python3
"""Focused, disk/key-free checks for unattended build-host orchestration."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("build_iso", ROOT / "build_iso.py")
bi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bi)


def args(**kw):
    base = dict(action="gen-key", dry_run=False, uid=None, use_key=None,
                expire="3y", no_passphrase=False, passphrase_file=None,
                assume_yes=True, yes=True, force=False, to=None)
    base.update(kw)
    return SimpleNamespace(**base)


def ctx(td, a=None):
    cfg = dict(bi.DEFAULT_CONFIG)
    cfg["work_dir"] = str(Path(td) / "work")
    return bi.Ctx(cfg, a or args())


def expect_fatal(fn, text):
    try:
        fn()
    except bi.Fatal as exc:
        assert text in str(exc), str(exc)
    else:
        raise AssertionError(f"expected Fatal containing {text!r}")


def main():
    fp = "A" * 40
    with tempfile.TemporaryDirectory() as td:
        x = ctx(td)
        x.c["iso_sign_key"] = fp
        with mock.patch.object(bi, "secret_key_fingerprints", return_value=[(fp, "Unit")]), \
                mock.patch.object(x, "quiet", return_value=True), \
                mock.patch.object(bi, "_adopt_key", return_value=0) as adopt:
            assert bi.gen_key(x) == 0
            adopt.assert_called_once_with(x, fp)

        # --yes is retry approval, never authorization to create another key.
        x = ctx(td, args(uid="Unit <u@example>"))
        with mock.patch.object(bi, "secret_key_fingerprints",
                               return_value=[(fp, "Unit <u@example>")]), \
                mock.patch.object(bi, "_adopt_key", return_value=0) as adopt:
            bi.gen_key(x)
            adopt.assert_called_once_with(x, fp)

        x = ctx(td, args(uid="Unit <u@example>"))
        with mock.patch.object(bi, "secret_key_fingerprints", return_value=[
                (fp, "Unit <u@example>"), ("B" * 40, "Unit <u@example>")]):
            expect_fatal(lambda: bi.gen_key(x), "more than one")

        secret = Path(td) / "secret"
        secret.write_text("not-a-real-passphrase")
        secret.chmod(0o644)
        expect_fatal(lambda: bi.protected_secret_file(args(passphrase_file=str(secret))),
                     "permissions")
        secret.chmod(0o600)
        assert bi.protected_secret_file(args(passphrase_file=str(secret))) == secret
        secret.unlink()
        expect_fatal(lambda: bi.protected_secret_file(args(passphrase_file=str(secret))),
                     "cannot access")

        x = ctx(td, args(action="backup-key", use_key=fp,
                         to=str(Path(td) / "not-mounted")))
        x.c["iso_sign_key"] = fp
        with mock.patch.object(x, "quiet", return_value=True), \
                mock.patch("os.path.ismount", return_value=False):
            expect_fatal(lambda: bi.backup_key(x), "separately mounted")

        # Bootstrap forwards every option only to children where it applies,
        # and stops immediately when a child fails.
        secret = Path(td) / "secret2"
        secret.write_text("x")
        secret.chmod(0o600)
        a = args(action="bootstrap", uid="Unit", use_key=fp, expire="2y",
                 passphrase_file=str(secret), to="/media/backup")
        x = ctx(td, a)
        x.c["bootstrap"]["backup_path"] = "/media/backup"
        x.c["bootstrap"]["dependencies_authorized"] = True
        calls = []

        def child(argv, **_kw):
            calls.append(argv)
            return SimpleNamespace(returncode=7 if "doctor" in argv else 0)

        with mock.patch("os.geteuid", return_value=1000), \
                mock.patch.object(bi, "confirmed", return_value=True), \
                mock.patch.object(x, "quiet", return_value=True), \
                mock.patch("bootstrap_workflow.BootstrapWorkflow.onboard"), \
                mock.patch("bootstrap_workflow.BootstrapWorkflow.acquire_lock"), \
                mock.patch("bootstrap_workflow.BootstrapWorkflow.stage"), \
                mock.patch.object(bi.subprocess, "run", side_effect=child):
            expect_fatal(lambda: bi.bootstrap(x, a), "doctor")
        flat = [item for command in calls for item in command]
        assert "--uid" in flat and "--use-key" in flat and "--expire" in flat
        assert "--to" in flat and flat.count("--passphrase-file") >= 3
        assert not any("check-upstream" in command for command in calls)

        # Legacy/stale marks cannot resume; current input-bound marks can.
        x = ctx(td)
        x.state.write_text("templates\n")
        assert not x.done("templates")
        x.mark("templates")
        assert x.done("templates")
        x.c["tier"] = 1
        assert not x.done("templates")

        # Bootstrap applies --set before Ctx derives work/output paths. Mock
        # only the expensive dispatcher: relying on the caller being root made
        # this regression test pass locally but fail on non-root CI runners.
        config = Path(td) / "override-config.json"
        chosen = Path(td) / "chosen work"
        observed = {}

        def dispatch(effective, _args):
            observed["work"] = effective.work
            observed["configured"] = effective.c["work_dir"]
            return 0

        argv = ["build_iso.py", "bootstrap", "--set", f"work_dir={chosen}",
                "--yes"]
        with mock.patch.object(bi, "CONF_PATH", config), \
                mock.patch.object(bi, "bootstrap", side_effect=dispatch), \
                mock.patch.object(sys, "argv", argv):
            assert bi.main() == 0
        assert observed == {"work": chosen, "configured": str(chosen)}
        assert config.is_file() and str(chosen) in config.read_text()

    print("  16/16 unattended orchestration checks pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
