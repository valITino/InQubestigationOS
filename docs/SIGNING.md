# ISO signing — what to send me, and what never to send

## Send only the fingerprint

A GPG **fingerprint** is public. It is safe to paste into a chat, commit to the
repo, print on a wall. It is 40 hex characters:

    gpg --fingerprint <your-key-id>

    pub   rsa4096 2026-09-01 [SC]
          A1B2 C3D4 E5F6 0718 2939  4A5B 6C7D 8E9F A0B1 C2D3
    uid   Kapo Cyber Image Signing <cyber@example.ch>

Send me `A1B2C3D4E5F607182939 4A5B6C7D8E9FA0B1C2D3` — spaces are fine, the script
normalises them. I set `iso_sign_key` and you never touch it again.

## Never send the private key

Do not paste the output of `gpg --export-secret-keys`, and do not put a
`-----BEGIN PGP PRIVATE KEY BLOCK-----` anywhere near a config file or a repo.
Anything pasted into a conversation or committed to git must be treated as
compromised from that moment — you would have to revoke the key and reissue it
to the whole unit.

The build script now refuses to start if it finds key material in
`iso_sign_key`, and validates the fingerprint format before it checks anything
else, so this fails in the first second rather than after a Docker error.

## What the build host needs

The **private key must be in the build host's GPG keyring**, because signing
happens there. The script checks this before starting a multi-hour build:

    gpg --list-secret-keys <fingerprint>

If the key lives on a smartcard or a different machine, build unsigned, copy the
image to the machine that holds the key, and sign it there:

    ./build_iso.py sign --iso /path/to/InQubestigationOS.iso --use-key <fingerprint>

That re-checksums the image and refuses if it no longer matches its `.sha256` —
an image that changed after it was built must not be signed — then signs it and
regenerates everything that travels with the signature: the checksum file, the
exported public key, `verify-iso.sh` and `FINGERPRINT.txt`. Doing it as three
commands by hand left those four stale.

## Creating the key, if you have not yet

    ./build_iso.py gen-key --uid "Kapo Cyber Image Signing <cyber@example.ch>"

That generates an rsa4096 signing key with a three-year expiry, writes the
fingerprint into `iso-build.json` for you, exports the public key beside the
ISO, and writes `FINGERPRINT.txt` — the sheet formatted to be read out over the
phone. Nothing to copy by hand, so nothing to mistype.

Three-year expiry is deliberate — an image-signing key should outlive a build
cycle but not outlive the team that made it. Generate it on the build host, or
on an offline machine and import the secret key there.

Already have a unit key in this keyring? Adopt it instead of making another:

    ./build_iso.py gen-key --use-key auto          # if there is exactly one
    ./build_iso.py gen-key --use-key <fingerprint> # otherwise

For unattended protected-key operations, pass a build-user-owned, mode-0600
runtime file (or protected FIFO/inherited `/proc/self/fd/N`) with
`--passphrase-file`. The same option covers generation, secret export and
backup encryption, component-tag signing, the readiness probe, and final ISO
signing. The secret is supplied to GPG through that file, never as a literal
argument or stored configuration. A configured `iso_sign_key` is always reused;
ordinary retries and `--yes` cannot rotate it.

`./build_iso.py doctor` then confirms the secret key is present and warns if it
expires within 90 days, before a multi-hour build rather than after it.

## What the build produces

| File | Purpose |
|---|---|
| `InQubestigationOS.iso` | The image |
| `…iso.sha256` | Integrity check |
| `…iso.asc` | Detached signature |
| `unit-signing-key.asc` | Your public key, exported for colleagues |
| `BUILD-RECORD.txt` | Build date, tier, templates, hashes, expiry warning |
| `verify-iso.sh` | One-command verification, for colleagues |
| `FINGERPRINT.txt` | The fingerprint, laid out to be read aloud |

Colleagues verify with one command — `verify-iso.sh` is generated beside the
image and checks the checksum, imports the key and verifies the signature, then
prints the fingerprint they must compare against the one you gave them:

    ./verify-iso.sh

Or by hand:

    sha256sum -c InQubestigationOS.iso.sha256
    gpg --import unit-signing-key.asc
    gpg --verify InQubestigationOS.iso.asc InQubestigationOS.iso

## The part that actually matters

**Distribute the fingerprint through a channel independent of the ISO.** A
public key shipped on the same USB stick as the image it signs proves nothing —
anyone who can replace the image can replace the key beside it. Read the
fingerprint out over the phone, publish it on an internal page colleagues
already trust, or hand it over on paper. The signature is only as good as the
independence of that channel.
