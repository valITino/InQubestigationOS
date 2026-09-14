#!/usr/bin/env python3
"""Focused, disk/key-free checks for unattended build-host orchestration."""
from __future__ import annotations

import importlib.util
import json
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
                backup_passphrase_file=None, non_interactive=False, review_profile=False,
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
        # Two DISTINCT secrets, so the assertions below can tell which one
        # reached which flag. With one file used for both, a mapping that sent
        # the backup secret to --passphrase-file looked identical to a correct
        # one — which is how that bug survived.
        secret = Path(td) / "secret2"
        secret.write_text("x")
        secret.chmod(0o600)
        backup_secret = Path(td) / "secret2-backup"
        backup_secret.write_text("y")
        backup_secret.chmod(0o600)
        a = args(action="bootstrap", uid="Unit", use_key=fp, expire="2y",
                 passphrase_file=str(secret),
                 backup_passphrase_file=str(backup_secret),
                 to="/media/backup")
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

        # backup-key takes two different secrets: --passphrase-file unlocks
        # the signing key so it can be exported, --backup-passphrase-file
        # encrypts the resulting backup. gpg is asked to do two separate
        # things and they are not the same passphrase.
        backup_argv = next(c for c in calls if "backup-key" in c)
        assert backup_argv[backup_argv.index("--passphrase-file") + 1] \
            == str(secret), backup_argv
        assert "--backup-passphrase-file" in backup_argv, backup_argv
        assert backup_argv[backup_argv.index("--backup-passphrase-file") + 1] \
            == str(backup_secret), backup_argv

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

        # ---------------------------------------------------------------
        # builder.yml must select an executor this build host can actually
        # run. Upstream's example-configs/qubes-os-r4.3.yml ships the
        # container executor commented out and the Qubes DispVM executor
        # live; that one drives qrexec into a disposable qube, which does
        # not exist on the Debian/Fedora build host this project documents.
        # The shape below is upstream's, verbatim.
        import yaml

        x = ctx(td)
        x.builder.mkdir(parents=True, exist_ok=True)
        bcfg = x.builder / "builder.yml"
        bcfg.write_text(
            "git:\n"
            "  branch: release4.3\n"
            "components:\n"
            "  - builder-rpm:\n"
            "      branch: main\n"
            "  - qubes-release\n"
            "sign-key:\n"
            "  rpm: DEADBEEF\n"
            "  deb: DEADBEEF\n"
            "executor:\n"
            "  type: qubes\n"
            "  options:\n"
            '    dispvm: "@dispvm"\n')

        # qb is absent here, so the merge reports it could not verify through
        # the builder rather than claiming a verification it did not perform.
        with mock.patch.object(x, "run", return_value=""):
            bi.write_builder_executor(x)
        merged = yaml.safe_load(bcfg.read_text())

        assert merged["executor"]["type"] == "docker", merged["executor"]
        # Replaced, not deep-merged: ContainerExecutor's signature is
        # (container_client, image, ...) and a surviving `dispvm` would ride
        # into its **kwargs.
        assert merged["executor"]["options"] == {
            "image": "qubes-builder-fedora:latest"}, merged["executor"]
        assert "dispvm" not in yaml.safe_dump(merged["executor"])
        # Everything else in the upstream config survives the merge.
        assert merged["sign-key"] == {"rpm": "DEADBEEF", "deb": "DEADBEEF"}
        assert merged["git"]["branch"] == "release4.3"
        assert len(merged["components"]) == 2

        # podman is a supported engine; anything else is refused rather than
        # written into builder.yml for ./qb to choke on later.
        x.c["container_engine"] = "podman"
        with mock.patch.object(x, "run", return_value=""):
            bi.write_builder_executor(x)
        assert yaml.safe_load(bcfg.read_text())["executor"]["type"] == "podman"
        x.c["container_engine"] = "nspawn"
        expect_fatal(lambda: bi.write_builder_executor(x),
                     "container_engine must be docker or podman")

        # A builder that answers with a different executor than the one just
        # written is a hard failure, not a warning: this is the check that
        # catches config precedence putting something else in front.
        x.c["container_engine"] = "docker"
        with mock.patch.object(x, "run", return_value='{"type": "qubes"}'):
            expect_fatal(lambda: bi.write_builder_executor(x),
                         "reports type='qubes'")

        # ---------------------------------------------------------------
        # Wiring, not just the helper: setup_builder must fix the executor
        # BEFORE it runs ./qb for anything. Testing the helper alone let
        # deleting its call site go unnoticed.
        x = ctx(td)
        x.builder.mkdir(parents=True, exist_ok=True)
        (x.builder / ".git").mkdir(exist_ok=True)
        (x.builder / "dependencies-debian.txt").write_text("git curl\n")
        bcfg = x.builder / "builder.yml"
        bcfg.write_text("executor:\n  type: qubes\n  options:\n"
                        '    dispvm: "@dispvm"\n')
        # The fetch is mocked, so stand in for what it would have produced.
        conf = bi.release_dir(x) / "conf"
        conf.mkdir(parents=True, exist_ok=True)
        (conf / "iso-online.ks").write_text("%include qubes-kickstart.cfg\n")

        qb_calls = []

        def record(*argv, **kw):
            cmd = [str(a) for a in argv]
            if cmd and cmd[0] == "./qb":
                # What did builder.yml say at the moment ./qb was invoked?
                try:
                    live = yaml.safe_load(bcfg.read_text()) or {}
                except Exception:
                    live = {}
                qb_calls.append((cmd, (live.get("executor") or {}).get("type")))
                if cmd[1:3] == ["config", "get-var"]:
                    return '{"type": "docker", "options": ' \
                           '{"image": "qubes-builder-fedora:latest"}}'
                return ""
            if cmd[:3] == ["git", "-C", str(x.builder)] and "rev-parse" in cmd:
                return x.c["builder_branch"]
            return ""

        with mock.patch.object(x, "run", side_effect=record), \
                mock.patch.object(bi, "verify_builder", return_value=None), \
                mock.patch.object(bi, "host_family", return_value="debian"), \
                mock.patch.object(bi, "packages_available", return_value=None), \
                mock.patch.object(bi, "install_packages", return_value=None), \
                mock.patch.object(bi, "resolve_auto_values", return_value=None), \
                mock.patch.object(bi.shutil, "which", return_value=None):
            bi.setup_builder(x)

        assert qb_calls, "setup_builder ran no ./qb commands at all"
        for cmd, executor_type in qb_calls:
            assert executor_type == "docker", (
                f"./qb {' '.join(cmd[1:3])} ran while builder.yml still said "
                f"executor={executor_type!r} — that call needs qrexec and "
                f"cannot work on a Debian/Fedora build host")

        # ---------------------------------------------------------------
        # A --set that would produce an unusable configuration must change
        # nothing. The documented GUIDE command set install.unattended=true
        # with a kernel-name disk; both writes reported success and every
        # later invocation — including the --set needed to fix it — then died
        # in load_config before doing anything.
        conf = Path(td) / "lockout.json"
        with mock.patch.object(bi, "CONF_PATH", conf):
            conf.write_text(json.dumps({}))
            x = ctx(td)
            expect_fatal(
                lambda: bi.config_set_many(
                    x, [("install.unattended", "true"),
                        ("install.disk", "/dev/nvme0n1")]),
                "by-id")
            # Nothing written: the file is still loadable and still says the
            # install is manual.
            assert json.loads(conf.read_text()) == {}, conf.read_text()
            reloaded = bi.load_config()
            assert reloaded["install"]["unattended"] is False

            # The same pair with a stable identity is accepted, and both
            # values land together — they are only valid as a pair.
            assert bi.config_set_many(
                x, [("install.unattended", "true"),
                    ("install.disk", "/dev/disk/by-id/nvme-TEST")], quiet=True) == 0
            stored = json.loads(conf.read_text())
            assert stored["install"]["unattended"] is True
            assert stored["install"]["disk"] == "/dev/disk/by-id/nvme-TEST"

            # A file already in a bad state stays repairable with the tool.
            conf.write_text(json.dumps(
                {"install": {"unattended": True, "disk": "/dev/nvme0n1"}}))
            assert bi.load_config(validate_semantics=False)["install"]["disk"] \
                == "/dev/nvme0n1"
            assert bi.config_set_many(
                x, [("install.disk", "/dev/disk/by-id/nvme-FIXED")],
                quiet=True) == 0
            assert bi.load_config()["install"]["disk"] == "/dev/disk/by-id/nvme-FIXED"

        # ---------------------------------------------------------------
        # backup-key needs two different secrets: one unlocks the signing key
        # so it can be exported, the other encrypts the backup. bootstrap used
        # to hand the backup secret to --passphrase-file, so the export step
        # tried to unlock the signing key with it.
        sign_pf = Path(td) / "sign.secret"
        back_pf = Path(td) / "backup.secret"
        for f in (sign_pf, back_pf):
            f.write_text("x")
            f.chmod(0o600)
        # The two secrets must reach gpg as two distinct options.
        sel = SimpleNamespace(passphrase_file=str(sign_pf),
                              backup_passphrase_file=str(back_pf))
        assert str(sign_pf) in bi.gpg_secret_options(sel, attr="passphrase_file")
        assert str(back_pf) in bi.gpg_secret_options(
            sel, attr="backup_passphrase_file")

        # ---------------------------------------------------------------
        # "I looked and it is wrong" and "I could not look" are different
        # answers. Every upstream fetch failure in check-upstream used to be a
        # WARN, and only FAIL was blocking, so a total network outage exited 0
        # having verified nothing — satisfying the bootstrap step, the
        # pre-build gate, the release-candidate gate and the one CI job that
        # is supposed to block.
        x = ctx(td)
        unreachable = [bi.Check("Kali: keyring reachable", bi.UNKNOWN, "URLError")]
        assert bi._print_checks(x, unreachable, unknown_blocks=True) == 1
        assert bi._print_checks(x, unreachable, unknown_blocks=False) == 0
        # A real finding still blocks regardless.
        assert bi._print_checks(x, [bi.Check("drift", bi.FAIL)],
                                unknown_blocks=False) == 1
        # A plain warning still does not.
        assert bi._print_checks(x, [bi.Check("expiring", bi.WARN)],
                                unknown_blocks=True) == 0

        # Every "reachable" probe must report UNKNOWN, not WARN: a WARN there
        # is indistinguishable from "checked, minor finding".
        source = (ROOT / "build_iso.py").read_text()
        assert 'reachable", WARN' not in source, \
            "an unreachable upstream must be UNKNOWN, not WARN"
        assert source.count('reachable", UNKNOWN') >= 6, \
            "the upstream reachability probes lost their UNKNOWN state"
        # And the gate must block on them unless explicitly overridden.
        assert 'unknown_blocks=not getattr(x.args, "allow_unreachable", False)' \
            in source

    print("  41/41 unattended orchestration checks pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
