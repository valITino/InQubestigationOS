#!/usr/bin/env python3
"""Ordering and safety checks for the one-command `quickstart` path.

Everything expensive is mocked; what is asserted is the contract:

  * every host check runs BEFORE any long step, with the signing key deferred
    (it is step 2's job, so its absence must not block step 1);
  * setup-host runs only when doctor found something, and its return value —
    which is itself a re-check — decides whether to continue;
  * the key backup lands on this host only with the explicit allow flag;
  * the preflight acknowledgement is scoped: it must not leak into the USB
    write's own "erase this device?" confirmation;
  * the supply-chain gate stops the build on a non-zero result;
  * a dry run never prompts for a secret;
  * re-exec under `sg docker` is guarded against looping.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("build_iso", ROOT / "build_iso.py")
bi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bi)

CHECKS = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if not ok:
        raise AssertionError(f"{name}{': ' + detail if detail else ''}")


def args(**kw):
    base = dict(action="quickstart", dry_run=False, uid=None, use_key=None,
                expire="3y", no_passphrase=False, passphrase_file=None,
                backup_passphrase_file=None, non_interactive=False,
                assume_yes=False, yes=False, force=False, to=None, fix=False,
                usb=False, device=None, wait=False, oem_device=None,
                no_oem=False, allow_local_key_backup=False,
                allow_unreachable=False, allow_unsigned=False)
    base.update(kw)
    return SimpleNamespace(**base)


def ctx(td: Path, a) -> bi.Ctx:
    cfg = dict(bi.DEFAULT_CONFIG)
    cfg["work_dir"] = str(td / "work")
    return bi.Ctx(cfg, a)


def run_quickstart(td: Path, a, *, doctor_rc=0, setup_rc=0, upstream_rc=0,
                   configured_key=""):
    """Run quickstart with every expensive step replaced by a recorder."""
    calls = []
    x = ctx(td, a)
    x.c["iso_sign_key"] = configured_key

    def rec(name, rc=0):
        def _f(*_a, **kw):
            calls.append((name, kw))
            return rc
        return _f

    def fake_gen_key(_x):
        calls.append(("gen_key", {}))
        _x.c["iso_sign_key"] = "C" * 40
        return 0

    def fake_preflight(_x, _tier2):
        # Record what assume_yes was WHILE preflight ran.
        calls.append(("preflight", {"assume_yes": _x.args.assume_yes}))
        return ROOT / "golden_image.py"

    patches = [
        mock.patch.object(bi, "doctor", side_effect=rec("doctor", doctor_rc)),
        mock.patch.object(bi, "setup_host", side_effect=rec("setup_host", setup_rc)),
        mock.patch.object(bi, "gen_key", side_effect=fake_gen_key),
        mock.patch.object(bi, "load_config", side_effect=lambda **kw: dict(x.c)),
        mock.patch.object(bi, "backup_key", side_effect=rec("backup_key")),
        mock.patch.object(bi, "check_upstream", side_effect=rec("check_upstream", upstream_rc)),
        mock.patch.object(bi, "preflight", side_effect=fake_preflight),
        mock.patch.object(bi, "resolve_auto_values", side_effect=rec("resolve_auto_values")),
        mock.patch.object(bi, "setup_builder", side_effect=rec("setup_builder")),
        mock.patch.object(bi, "fetch_kali_key", side_effect=rec("fetch_kali_key")),
        mock.patch.object(bi, "gen_component", side_effect=rec("gen_component")),
        mock.patch.object(bi, "build_templates", side_effect=rec("build_templates")),
        mock.patch.object(bi, "missing_template_rpms", return_value=["x"]),
        mock.patch.object(bi, "build_iso", side_effect=rec("build_iso")),
        mock.patch.object(bi, "write_usb", side_effect=rec("write_usb")),
        mock.patch.object(bi, "prompt_secret", side_effect=rec("prompt_secret")),
        mock.patch.object(bi, "secret_key_fingerprints", return_value=[]),
        mock.patch.object(x, "quiet", return_value=True),  # docker works
    ]
    for p in patches:
        p.start()
    try:
        rc = bi.quickstart(x, a)
    finally:
        for p in patches:
            p.stop()
    return rc, calls, x


def names(calls):
    return [c[0] for c in calls]


def main() -> int:
    with tempfile.TemporaryDirectory() as td_s:
        td = Path(td_s)

        # 1. Happy path, host already ready: no setup-host, key generated,
        #    backed up locally with the explicit allow flag, upstream checked,
        #    then built. Every check precedes every long step.
        a = args()
        rc, calls, x = run_quickstart(td, a)
        check("quickstart succeeds on a ready host", rc == 0)
        seq = names(calls)
        check("doctor runs first", seq[0] == "doctor", str(seq))
        check("doctor defers the signing key to step 2",
              calls[0][1].get("signing") is False, str(calls[0][1]))
        check("setup-host is not run when doctor is clean",
              "setup_host" not in seq, str(seq))
        check("the key is generated before it is backed up",
              seq.index("gen_key") < seq.index("backup_key"), str(seq))
        check("one passphrase is asked for, before gen-key",
              seq.count("prompt_secret") == 1
              and seq.index("prompt_secret") < seq.index("gen_key"), str(seq))
        check("a default signing identity is derived rather than demanded",
              a.uid and "<" in a.uid and "@" in a.uid, repr(a.uid))
        check("the backup goes next to the build", a.to == str(x.work / "key-backup"))
        check("keeping the backup on this host requires the explicit allow flag",
              a.allow_local_key_backup is True)
        check("supply chain is checked before the build",
              seq.index("check_upstream") < seq.index("build_iso"), str(seq))
        # main()'s own `iso` order: resolve -> preflight -> setup_builder ->
        # build. A first version of quickstart skipped setup_builder entirely
        # and would have failed hours in at "no kickstarts found".
        check("auto values are resolved before preflight",
              seq.index("resolve_auto_values") < seq.index("preflight"), str(seq))
        check("the builder is set up after preflight and before the build",
              seq.index("preflight") < seq.index("setup_builder") < seq.index("build_iso"),
              str(seq))
        check("tier 1 builds no templates",
              "build_templates" not in seq and "gen_component" not in seq, str(seq))
        check("the build is the last long step", seq[-1] == "build_iso", str(seq))

        # Tier 2 builds the templates, after the builder exists and before
        # the ISO; a completed template set is skipped rather than rebuilt.
        a = args()
        with mock.patch.dict(bi.DEFAULT_CONFIG, {"tier": 2}):
            rc, calls, _ = run_quickstart(td, a)
        seq2 = names(calls)
        check("tier 2 builds the templates between builder setup and the ISO",
              seq2.index("setup_builder") < seq2.index("build_templates") < seq2.index("build_iso"),
              str(seq2))
        check("tier 2 generates the component before building templates",
              seq2.index("gen_component") < seq2.index("build_templates"), str(seq2))
        check("no USB write without --usb", "write_usb" not in seq)

        # 2. Preflight's acknowledgement is scoped to preflight. Leaking it
        #    would auto-confirm write-usb's "erase this device?" question.
        pre = next(c for c in calls if c[0] == "preflight")
        check("preflight warnings are acknowledged non-interactively",
              pre[1]["assume_yes"] is True)
        check("the acknowledgement does not outlive preflight",
              a.assume_yes is False)

        # 3. Doctor found blockers: setup-host runs, and ITS return value
        #    (a re-check) decides. A failed re-check stops before anything
        #    long, with nothing built.
        a = args()
        rc, calls, _ = run_quickstart(td, a, doctor_rc=1, setup_rc=0)
        check("setup-host runs when doctor found blockers",
              names(calls)[:2] == ["doctor", "setup_host"], str(names(calls)))
        check("a clean re-check continues to the build", "build_iso" in names(calls))
        a = args()
        try:
            run_quickstart(td, a, doctor_rc=1, setup_rc=1)
        except bi.Fatal as exc:
            check("a failed re-check stops the run", "still not ready" in str(exc))
        else:
            raise AssertionError("expected Fatal when the host stays unready")

        # 4. The supply-chain gate is a gate.
        a = args()
        try:
            run_quickstart(td, a, upstream_rc=1)
        except bi.Fatal as exc:
            check("a failed supply-chain check stops before the build",
                  "Nothing has been built" in str(exc))
        else:
            raise AssertionError("expected Fatal on a failed supply-chain check")

        # 5. A configured key is reused, not regenerated, and the passphrase
        #    is still asked for (it is needed to export the backup).
        a = args()
        rc, calls, _ = run_quickstart(td, a, configured_key="D" * 40)
        check("an existing key is reused", "gen_key" not in names(calls))
        check("the passphrase is still collected for the backup",
              "prompt_secret" in names(calls))

        # 6. Lab mode: no passphrase, no backup, but still every check.
        a = args(no_passphrase=True)
        rc, calls, _ = run_quickstart(td, a)
        check("lab mode asks for nothing", "prompt_secret" not in names(calls))
        check("lab mode makes no key backup", "backup_key" not in names(calls))
        check("lab mode still checks the supply chain", "check_upstream" in names(calls))

        # 7. A dry run never prompts for a secret.
        a = args(dry_run=True)
        rc, calls, _ = run_quickstart(td, a)
        check("a dry run never prompts for a secret",
              "prompt_secret" not in names(calls), str(names(calls)))

        # 8. --usb hands over to write-usb, waiting for a stick when no device
        #    was named.
        a = args(usb=True)
        rc, calls, _ = run_quickstart(td, a)
        check("--usb writes the stick after the build",
              names(calls)[-1] == "write_usb", str(names(calls)))
        check("--usb without --device waits for a stick", a.wait is True)
        # A dry run of the same command plans the media step instead: there
        # is no image for write-usb to verify, so calling it would abort the
        # plan at its first check.
        a = args(usb=True, dry_run=True)
        rc, calls, _ = run_quickstart(td, a)
        check("--dry-run --usb completes", rc == 0)
        check("--dry-run --usb does not call write-usb",
              "write_usb" not in names(calls), str(names(calls)))

        # 9. Re-exec under sg docker must not loop: with the guard set, the
        #    exec is skipped even when docker only works through sg.
        a = args()
        x = ctx(td, a)
        with mock.patch.object(bi, "doctor", return_value=0), \
                mock.patch.object(bi, "gen_key", side_effect=lambda _x: 0), \
                mock.patch.object(bi, "load_config", side_effect=lambda **kw: dict(x.c)), \
                mock.patch.object(bi, "backup_key", return_value=0), \
                mock.patch.object(bi, "check_upstream", return_value=0), \
                mock.patch.object(bi, "preflight", return_value=ROOT / "golden_image.py"), \
                mock.patch.object(bi, "resolve_auto_values", return_value=None), \
                mock.patch.object(bi, "setup_builder", return_value=None), \
                mock.patch.object(bi, "build_iso", return_value=None), \
                mock.patch.object(bi, "prompt_secret", return_value=Path("/dev/null")), \
                mock.patch.object(bi, "secret_key_fingerprints", return_value=[]), \
                mock.patch.object(bi.shutil, "which", return_value="/usr/bin/sg"), \
                mock.patch.object(bi.os, "execvp") as execvp, \
                mock.patch.dict(os.environ, {"INQUBESTIGATION_SG": "1"}):
            # docker ps fails directly, works via sg
            x.quiet = lambda *argv, **kw: argv[:2] == ("sg", "docker")
            bi.quickstart(x, a)
            check("no re-exec when the guard variable is set", not execvp.called)
        with mock.patch.object(bi, "doctor", return_value=0), \
                mock.patch.object(bi.shutil, "which", return_value="/usr/bin/sg"), \
                mock.patch.object(bi.os, "execvp", side_effect=SystemExit(99)) as execvp, \
                mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("INQUBESTIGATION_SG", None)
            x = ctx(td, args())
            x.quiet = lambda *argv, **kw: argv[:2] == ("sg", "docker")
            try:
                bi.quickstart(x, args())
            except SystemExit as exc:
                check("re-exec happens under sg docker before any secret is collected",
                      exc.code == 99 and execvp.call_args[0][0] == "sg")
            else:
                raise AssertionError("expected re-exec under sg docker")
            check("the loop guard is set before re-exec",
                  os.environ.get("INQUBESTIGATION_SG") == "1")

    print(f"  {CHECKS}/{CHECKS} quickstart checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
