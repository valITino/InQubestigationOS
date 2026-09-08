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

If the key lives on a smartcard or a different machine, build unsigned and sign
afterwards on the machine that holds it:

    gpg --local-user <fingerprint> --detach-sign --armor \
        --output QubesOS-Cybercrime-Investigator.iso.asc \
        QubesOS-Cybercrime-Investigator.iso

## Creating the key, if you have not yet

    gpg --quick-generate-key "Kapo Cyber Image Signing <cyber@example.ch>" \
        rsa4096 sign 3y
    gpg --fingerprint

Three-year expiry is deliberate — an image-signing key should outlive a build
cycle but not outlive the team that made it. Generate it on the build host, or
on an offline machine and import the secret key there.

## What the build produces

| File | Purpose |
|---|---|
| `QubesOS-Cybercrime-Investigator.iso` | The image |
| `…iso.sha256` | Integrity check |
| `…iso.asc` | Detached signature |
| `unit-signing-key.asc` | Your public key, exported for colleagues |
| `BUILD-RECORD.txt` | Build date, tier, templates, hashes, expiry warning |

Colleagues verify with:

    sha256sum -c QubesOS-Cybercrime-Investigator.iso.sha256
    gpg --import unit-signing-key.asc
    gpg --verify QubesOS-Cybercrime-Investigator.iso.asc \
                 QubesOS-Cybercrime-Investigator.iso

## The part that actually matters

**Distribute the fingerprint through a channel independent of the ISO.** A
public key shipped on the same USB stick as the image it signs proves nothing —
anyone who can replace the image can replace the key beside it. Read the
fingerprint out over the phone, publish it on an internal page colleagues
already trust, or hand it over on paper. The signature is only as good as the
independence of that channel.
