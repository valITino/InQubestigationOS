# InQubestigationOS

> **Primary build entry point:** use `./build_iso.py bootstrap`. It performs mandatory upfront destination/security review and verified host-accessible export. See [the bootstrap operator contract](docs/BOOTSTRAP.md); paths and hypervisor details are never guessed.

A hardened Qubes OS build for cybercrime investigation workstations. Every
clearnet connection is forced through a proxy, an inline IPS and a DPI recorder
before it reaches the firewall; Tor traffic takes a separate, uninspected road;
every compartment reports to a local SIEM. Ships as a bootable ISO that installs
with no network and configures itself on first boot.

```
                                Internet
                                    ▲
                              ┌─────┴─────┐
                              │  sys-net  │  red · NIC · untrusted
                              └─────▲─────┘
                              ┌─────┴──────┐
                              │sys-firewall│ orange · DNS → 9.9.9.9 over TLS
                              └──▲──────▲──┘
                     ┌───────────┘      └──────────┐
               ┌─────┴─────┐                 ┌─────┴──────┐
               │  sys-dpi  │ Zeek            │ sys-whonix │ purple · Tor
               └─────▲─────┘                 └─────▲──────┘
               ┌─────┴─────┐                 ┌─────┴──────┐
               │  sys-ids  │ Suricata IPS    │  kali-tor  │
               └─────▲─────┘                 │anon-whonix │
               ┌─────┴─────┐                 └────────────┘
               │ sys-proxy │ Squid + attribution
               └─────▲─────┘
        ┌────────────┼────────────┬─────────────┬────────────┐
    personal       work        case-*      kali-clear   wazuh-srv
```

## What you get

| | |
|---|---|
| **Five-hop inspected chain** | `qube → sys-proxy → sys-ids → sys-dpi → sys-firewall → sys-net` — no clearnet qube can bypass it |
| **Separate Tor branch** | Joins at the firewall; never inspected, never logged against your identity |
| **Forced DNS** | All clearnet DNS captured and sent to Quad9 over TLS; Whonix exempt by design |
| **SIEM in every compartment** | Wazuh agent in all nine templates in service, version-held, per-qube identity |
| **Investigator tooling** | Kali + Maltego, LibreOffice, Suricata, Zeek, Squid — all baked into the ISO |
| **Weekly encrypted backups** | Profile-mode `qvm-backup` on a timer, with monthly restore verification |
| **Acceptance tests** | Thirteen groups, re-runnable, that prove the design is actually in force |
| **Runs itself afterwards** | Updates, rule refreshes, key-expiry watch, self-checks and staleness warnings are all timers, not a checklist |

Base is Qubes OS 4.3.1. dom0 is Fedora because Qubes builds it that way and
cannot be changed; **everything else is Debian 13** — service qubes, all custom
templates, and Whonix.

## Quick start

```bash
# On a Debian-family (Debian 13, Kali, Ubuntu) or Fedora host with ~250 GB
# free — nothing pre-installed
git clone <your-internal-url>/InQubestigationOS.git && cd InQubestigationOS
# The wizard discovers approved preformatted storage, creates safe mountpoints,
# mounts it, and collects the signing authorization with hidden input.
./build_iso.py bootstrap
./build_iso.py write-usb --wait   # plug the stick in when it asks
```

`bootstrap` runs `setup-host`, `gen-key`, `backup-key`, `doctor`,
`check-upstream`, the dry-run plan and the build, stopping at the first failure.
Every step is idempotent, so fixing a cause and re-running skips what already
succeeded. Each is also available on its own — `make` lists them.

Boot the USB and install. First boot provisions itself; there is nothing to do
by hand, and the recurring maintenance installs itself as timers.

Full walkthrough: **[docs/GUIDE.md](docs/GUIDE.md)**.
Trusted release-candidate runner setup: **[docs/RELEASE.md](docs/RELEASE.md)**.
Spare-machine acceptance and pending report: **[docs/ACCEPTANCE.md](docs/ACCEPTANCE.md)**.

## Repository layout

```
InQubestigationOS/
├── golden_image.py            provisioner — runs in dom0 on each laptop
├── build_iso.py               ISO + template builder — runs on a build host
├── Makefile                   one entry point for the whole lifecycle
├── supply-chain.lock.json     what upstream offered last time we looked
├── docs/
│   ├── GUIDE.md               step-by-step, start to finish
│   ├── DESIGN.html            the visual design specification
│   ├── SIGNING.md             GPG signing — read before sending anyone a key
│   ├── VERIFICATION.md        supply chain: every repository and key, with sources
│   └── REVIEW.md              defects found during verification, and the test results
├── tests/
│   ├── run_tests.py           fake-dom0 harness: runs all 12 phases off Qubes
│   ├── static_checks.py       assertions over every generated config file
│   ├── host_checks.py         the build-host support must hold up per distro
│   ├── doc_checks.py          the docs must not drift from the code
│   ├── config_checks.py       the code and its configuration must agree
│   └── qubes_stub.py          one stand-in for every dom0 command
├── .github/workflows/ci.yml   harness on every push, supply chain every Monday
└── .gitignore                 keeps credentials and build artifacts out of git
```

`golden_image.py` must stay beside `build_iso.py` — it is base64-embedded into
the installer kickstart.

## Two scripts, two machines

| Script | Runs on | Does |
|---|---|---|
| `build_iso.py` | Build host (Debian-family — Debian 13, Kali, Ubuntu — or Fedora; Docker; ~250 GB) | Builds five investigator templates, then a signed bootable ISO |
| `golden_image.py` | dom0, each laptop | Twelve phases: templates, chain, SIEM, segmentation, backups, tests |

`golden_image.py` is standard-library Python 3 — no `pip install`, which
matters because dom0 has no network by design. `build_iso.py` runs on a
networked build host, and needs PyYAML to edit `builder.yml` safely;
`setup-host` installs your distribution's package for it. It also uses
pykickstart to check the generated kickstart before the build, and on Debian
and Kali — which have not packaged pykickstart since 2019 — `setup-host` puts
that one, alone, in a virtualenv under `work_dir` rather than installing into
the system interpreter. Both scripts embed their configuration, write it as
JSON on first run, and never overwrite your edits. Both are resumable:
completed phases are recorded and skipped.

## Before you ship this to anyone

**A self-built ISO is not signed by the Qubes team.** Colleagues cannot verify
it against the Qubes release key, because it is not a Qubes release. You become
the signing authority — set `iso_sign_key`, and distribute that fingerprint
through a channel *independent of the ISO*. See [docs/SIGNING.md](docs/SIGNING.md).

**The ISO goes stale and becomes a liability.** It freezes dom0, Xen and the
kernel at build time. An image built today and installed in six months installs
six months of known-vulnerable dom0 before its first update. Rebuild on every
Qubes Security Bulletin affecting dom0 or Xen. `BUILD-RECORD.txt` stamps each
build with that warning.

**No credentials are baked in.** Four secrets are generated per machine at
provisioning into `~/golden-image/credentials.json`, mode 600. Change them,
escrow them, `shred -u` the file.

**Test on a spare machine first.** Not one you intend to issue.

## What runs by itself

The lifecycle used to be a procedure with a person in the loop at every step.
Most of those steps are now commands or timers.

| Was | Now |
|---|---|
| Seven commands in the right order to get from a clone to a signed image | `./build_iso.py bootstrap` |
| Install Docker, join its group, log out and back in | `./build_iso.py setup-host` |
| `gpg --quick-generate-key`, copy the fingerprint into JSON | `./build_iso.py gen-key --uid "..."` |
| `$EDITOR iso-build.json`, match `mock_config` to the release by hand | `./build_iso.py --set key=value`; the chroot derives itself |
| Merge duplicate `templates:`/`components:` blocks in builder.yml by hand | merged properly, then verified with `qb config get-var` |
| Re-verify three signing keys and a version, monthly, from the docs | `./build_iso.py check-upstream`, weekly in CI, with a committed baseline |
| Read the Qubes bulletin list and decide whether to rebuild | the same command classifies new bulletins by whether they touch dom0/Xen |
| `dd` to a device you hope is the right one | `./build_iso.py write-usb` — verifies the signature, refuses fixed disks, reads the stick back (elevating if it must) |
| "Build unsigned and sign afterwards on the machine that holds the key" | `./build_iso.py sign` — re-checksums, signs, and regenerates everything that travels with the signature |
| Compare the printed fingerprint against the one you were given, by eye | `./verify-iso.sh <fingerprint>` compares them and exits non-zero |
| Pick a `work_dir` "somewhere with 250 GB free" | `--set work_dir=auto` |
| "Verify the builder itself — nothing verifies the builder for you" | `verify_builder` checks the signed tag against the Qubes master signing key's web of trust; one pinned fingerprint, developer keys derived from it |
| Keep the signing key safe by remembering to | `backup-key` / `restore-key` — encrypted key, revocation certificate, public key |
| `mkfs.ext4 -L GOLDEN-BACKUP /dev/sdX1` against a device you identified by eye | `--prepare-backup-media` |
| Click through Anaconda, then through Qubes' initial-setup wizard | `install.unattended` + `install.auto_initial_setup` — everything except the disk passphrase, which stays human on purpose |
| "Confirm on your hardware that the first-boot service fires" | the runner records what it did; group 13 reads the record, and a timer retries until the machine is provisioned |
| "Confirm pykickstart merges two %packages sections" | the generated kickstart is parsed and its package list read back; the finished ISO is opened and the template RPMs confirmed present |
| Move the component to your git server and sign its tags "before production" | `component_remote` + `component_sign_key` — the build pushes a signed tag and turns `verification-mode` back on |
| Read each `doctor` row and run the fix it printed | `doctor --fix` runs the ones this script owns |
| Remember to run `check-upstream` before a first build | `templates`, `iso` and `all` run it themselves and refuse to start on a blocking finding |
| Notice `iso_sign_key` is empty before shipping an unsigned image | a real build refuses; `--allow-unsigned` is an explicit, testing-only choice |
| "Disable the agent in kali-tor for the duration and note it in the case log" | `--case-mode anonymous --case <id>`, which masks the agent and writes the log entry |
| `journalctl -f`, `systemctl list-timers`, and knowing which files to read | `--status` |
| "All must pass before the laptop leaves your desk" | `--issue --operator "<name>"` re-runs the tests, refuses if the credentials are still on the machine, and writes the release record |
| Re-add an expiring repository key when the watch tells you to | a timer runs `--refresh-repo-keys`, which renews against the pinned fingerprint and rolls back on mismatch — a genuinely *rotated* key still stops for a person |
| Click through Anaconda | `install.unattended` — everything but the disk passphrase |
| Give the template a netvm when apt fails through the update proxy, then clear it | done automatically for that one install, and the netvm is always restored |
| Install the SIEM stack by hand on a Tier 1 build | phase 8 installs it from the already-configured, already-verified repository |
| Decide whether this machine has the RAM for a local SIEM | `wazuh.mode: auto` |
| Three verification commands emailed to colleagues | `verify-iso.sh` and `FINGERPRINT.txt`, generated beside the image |
| "Confirm by hand the four things the tests cannot check" | acceptance-test group 13 |
| Read credentials.json, rotate four secrets in a web UI, escrow, `shred -u` | `--rotate-credentials`, `--escrow-credentials`, `--shred-credentials` — or `--handover` for all three |
| Re-add an expired repository key by hand in the template | `--refresh-repo-keys`, re-verified against the pinned fingerprint, rolled back if it does not match |
| "Do this cross-check on first build rather than trusting the blog post alone" | `check-upstream` asks an independent keyserver about the Kali key, every run |
| `qvm-connect-tcp 8443:wazuh-srv:443` from memory | a "SIEM dashboard" launcher in `work` |
| Weekly template updates, weekly `suricata-update`, monthly key-expiry check, monthly restore test | seven timers, installed by phase 10, that raise a login banner when they fail |
| Upgrade Wazuh in the right order and remember which order that is | `--upgrade-wazuh` |

What is deliberately still yours: reading the fingerprint out over an
independent channel, plugging in the backup disk the first time, and deciding
that a machine is fit to issue.

## Status

Verified against primary sources on 2026-09-08 — Kali's signing keys and
published keyring checksum, the Zeek OBS repository and its key expiry, the
Wazuh release the repository actually offers and its signing key, the Qubes
4.3 template names and firewall chains, and the `qvm-backup` profile schema in
qubes-core-admin. `supply-chain.lock.json` records what was seen;
`./build_iso.py check-upstream` re-checks it and fails on drift.

Neither script has been run end-to-end against a live Qubes 4.3.1 system. Both
are exercised on every push by `tests/run_tests.py`, a fake-dom0 harness that
runs all twelve phases against stub `qvm-*` binaries and then asserts on every
configuration file they generated. Run it yourself: `make check`.

Defects found during verification are documented in
[docs/REVIEW.md](docs/REVIEW.md) rather than quietly patched, so nobody
reintroduces them.

## Contributing

Changes to chain order, DNS, segmentation, agent coverage or the supply chain
bump the image version and reach every laptop through this repository — never by
hand-editing a single machine. The golden image is the git tag, not any one
laptop.

Before merging anything that touches the firewall or the SIEM: `make check`
must pass, and `sudo ./golden_image.py --verify` must pass on a test install.
Both exit non-zero on failure, so they can gate a merge rather than being
something a reviewer is asked to remember.
