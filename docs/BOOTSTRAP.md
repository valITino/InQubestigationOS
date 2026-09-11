# Bootstrap operator contract

`./build_iso.py bootstrap` is the build-VM entry point. It performs mandatory
upfront onboarding, validates both destinations, prepares the host, creates or
adopts a signing key, makes the encrypted key backup, runs readiness and
supply-chain gates, builds and signs the image, and readback-verifies an
allowlisted release on host-accessible storage. A failed required export is a
failed bootstrap; valid guest output is retained. `bootstrap.build_only=true`
is explicitly reported as build-only, never exported.

## Supported storage contract

The implemented backend is an **already guest-visible mounted filesystem**.
Configure its measured `findmnt` source and type. Bootstrap does not invent a
share, host address, or configure a hypervisor. Mounted virtiofs, 9p, vboxsf or
SSHFS can satisfy the filesystem contract, but this is not a claim that every
platform was tested. `bootstrap.host_path` is an optional operator-supplied
mapping; otherwise the physical-host path is reported as unknown. A host folder
is outside the VM, not offline/removable media. Use `backup_kind=physical-device`
only when attachment is independently established, or `host-share` when policy
allows it. Root-filesystem directories and unknown backing are rejected.

Example initial configuration (replace every measured value; none are defaults):

```sh
./build_iso.py bootstrap --set bootstrap.backup_path=/media/unit-key \
  --set bootstrap.backup_source=/dev/disk/by-uuid/BACKUP \
  --set bootstrap.backup_fstype=ext4 \
  --set bootstrap.backup_kind=physical-device \
  --set bootstrap.export_path='/mnt/host releases' \
  --set bootstrap.export_source=hostshare \
  --set bootstrap.export_fstype=virtiofs \
  --use-key FINGERPRINT --passphrase-file /run/user/1000/iq-build-secret
```

`--set` applies before paths are constructed. `--yes` answers routine prompts;
it does not imply `--force`, erasure, USB writing, or destructive installation.
A repeat reuses approved non-secret configuration but requires fresh runtime
authorization:

```sh
./build_iso.py bootstrap --yes --use-key FINGERPRINT \
  --passphrase-file /run/user/1000/iq-build-secret
./build_iso.py bootstrap-status
./build_iso.py bootstrap-status --watch
```

The passphrase file must be owned by the build identity and mode `0600`. Its
value is not stored in configuration, status, inventory, logs, bundle, or ISO.
Signing-key and backup-encryption passphrases remain distinct concepts; the
workflow does not introduce unrelated password reuse.

## Interaction inventory

| Group / machine | Input or action | Secret | Safe source and reuse |
|---|---|---:|---|
| first run / build VM | measured work/backup/export mount identities and kind; optional host mapping; signing UID/fingerprint; install locale/disk and provisioner/SIEM/backup policy | no | reviewed `iso-build.json`; reusable only while validation matches |
| each build / build VM | sudo and signing authorization; encrypted-backup passphrase | yes | OS prompt/agent or owner-only runtime file; readiness checked each run |
| host | create/attach configured share or authenticated mount and approve a host key if the chosen external tool requires it | sometimes | trusted host UI/tool; no platform or credential is guessed |
| target installer | separately write/attach USB; physically confirm laptop and whole-disk identity; enroll unique LUKS passphrase | yes/physical | target only; export neither writes nor boots USB |
| reboot/login | unlock LUKS; then authenticate to a real local account | yes | separate target prompts, not implied by encryption enrollment |
| first boot / target | local-account enrollment where upstream setup requires it; enterprise network/certificate/proxy and authenticated central SIEM enrollment | yes | target-approved mechanisms; no shared password/hash in ISO |
| acceptance / target | resolve offline failures; run pending DNS/Tor/network checks; approve credential escrow and issuance | sometimes | `golden_image.py --status`, `golden_image.py --verify`, or `golden_image.py --issue`; pending is not passed |

The upstream Anaconda path is interactive unless `install.unattended=true`.
Unattended mode requires an exact stable disk identity and deliberately enrolls
encryption on that laptop. This project does not inject a reusable local-account
password/hash into a distributable ISO, so account enrollment remains a target
action. No prompt-free physical installation or boot is claimed or tested.

## Status, locations, and recovery

An atomic JSON status record and a readable summary live in the effective work
directory and separate onboarding, backup, build, and export. A process lock
rejects concurrent runs. The generated location inventory records actual work/output/
log/GNUPG paths, fingerprint, backup identity, guest export, known or unknown
host mapping, sizes, hashes, and verification—never secret values. The sanitized
release contains only the allowlist; private backup, revocation data,
credentials, config, and logs are excluded. A bundled public key is not an
independent trust anchor; distribute its fingerprint independently.

Correct a reported mount/authentication/supply-chain failure and repeat
bootstrap. Input-bound markers avoid unnecessary template/ISO builds, while
destination identities are revalidated at use. Mock tests cover these contracts.
Live mounts, hypervisor setup, real GPG, full ISO build, USB writing, physical
installation/boot, and enterprise enrollment remain environment-specific tests.
