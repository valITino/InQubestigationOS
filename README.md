# InQubestigationOS

A hardened Qubes OS build for cybercrime investigation workstations. Every
clearnet connection is forced through a proxy, an inline IPS and a DPI recorder
before it reaches the firewall; Tor traffic takes a separate, uninspected road;
every compartment reports to a local SIEM. Ships as a signed, bootable ISO; the
installed machine configures itself on first boot. Two editions come from the
same image: **wired** builds and wires the whole design below, **unwired**
builds the same templates and leaves the wiring to you.

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
| **Investigator tooling** | Kali + Maltego, LibreOffice, Suricata, Zeek, Squid — built on the target at first boot (`tier=1`, the default), or baked into the ISO with `tier=2` |
| **Weekly encrypted backups** | Profile-mode `qvm-backup` on a timer, with a monthly archive integrity check |
| **Acceptance tests** | Fourteen groups, re-runnable, that prove the design is actually in force |
| **Runs itself afterwards** | Updates, rule refreshes, key-expiry watch, self-checks and staleness warnings are all timers, not a checklist |

Base is Qubes OS 4.3.1. dom0 is Fedora because Qubes builds it that way and
cannot be changed; **everything else is Debian 13** — service qubes, all custom
templates, and Whonix.

## Quick start

```bash
# On an x86-64 Linux: Debian 13, Kali, Ubuntu or Fedora. A VM is fine.
# Clone as your normal user; never run the scripts with sudo.
git clone <your-internal-url>/InQubestigationOS.git && cd InQubestigationOS
./build_iso.py --set work_dir=/big/disk/investigator-iso   # only if ~ has < 100 GB free
./build_iso.py quickstart --usb   # one passphrase, then walk away
```

That checks and fixes the host, creates or reuses your signing key, builds
and signs the image, and writes a USB stick. Boot the stick on the laptop and
install. On first boot the laptop configures itself. The step-by-step version,
with what each step does and what to do when one fails, is
**[docs/GUIDE.md](docs/GUIDE.md)**.

- **Two editions, one image.** `wired` (the default) builds and tests the whole
  design. `unwired` installs the templates only and leaves the wiring to you.
  Pick one per stick: `./build_iso.py write-usb --edition unwired`.
- **Publishing a download.** `./build_iso.py package-release` turns a build into
  GitHub release files, see [GUIDE §3.2](docs/GUIDE.md#32-publish-a-download-github-releases).
  Downloaders need only your fingerprint, never your passphrase.
- **Production release.** `./build_iso.py bootstrap` adds a separate key-backup
  medium and a verified export, see [docs/BOOTSTRAP.md](docs/BOOTSTRAP.md).

## Which document do I read?

| I want to… | Read |
|---|---|
| Build, install and issue a laptop, start to finish | [docs/GUIDE.md](docs/GUIDE.md) |
| Wire an unwired machine, or understand the wired layout | [docs/WORKSTATION-GUIDE.md](docs/WORKSTATION-GUIDE.md), also shipped on every laptop |
| Know what to share about the signing key, and what never to | [docs/SIGNING.md](docs/SIGNING.md) |
| Run the production `bootstrap` path | [docs/BOOTSTRAP.md](docs/BOOTSTRAP.md) |
| Set up the trusted CI runner for release candidates | [docs/RELEASE.md](docs/RELEASE.md) |
| Record hardware acceptance on a spare machine | [docs/ACCEPTANCE.md](docs/ACCEPTANCE.md) |
| See the design: chain, colours, trust levels | [docs/DESIGN.html](docs/DESIGN.html) |
| Check where every key and repository comes from | [docs/VERIFICATION.md](docs/VERIFICATION.md) |
| Read what was found and fixed during review | [docs/REVIEW.md](docs/REVIEW.md), [CHANGELOG.md](CHANGELOG.md) |

## Repository layout

```
InQubestigationOS/
├── build_iso.py               ISO builder: runs on the build host (start here)
├── golden_image.py            the provisioner: runs in dom0 on each laptop
├── bootstrap_workflow.py      helper for `build_iso.py bootstrap` (onboarding, export)
├── release_candidate.py       trusted release-candidate gate (docs/RELEASE.md)
├── acceptance_runner.py       spare-machine acceptance evidence (docs/ACCEPTANCE.md)
├── Makefile                   short aliases for common commands (`make` lists them)
├── supply-chain.lock.json     what upstream offered at the last check-upstream
├── requirements-dev.txt       lint and test tools for contributors and CI only
├── CHANGELOG.md               what changed in each version
├── docs/
│   ├── GUIDE.md               the guide: build host to issued laptop
│   ├── WORKSTATION-GUIDE.md   the wired design and best practice (shipped in dom0)
│   ├── SIGNING.md             the signing key: what to share, what never to
│   ├── BOOTSTRAP.md           the production bootstrap path
│   ├── RELEASE.md             the trusted release-candidate runner
│   ├── ACCEPTANCE.md          acceptance on a spare machine
│   ├── acceptance-pending.json  the current acceptance report (all pending)
│   ├── DESIGN.html            the visual design specification
│   ├── VERIFICATION.md        every repository and key, with its source
│   └── REVIEW.md              defects found during review, and the test results
├── tests/                     run them all with `make check`
│   ├── run_tests.py           fake-dom0 harness: runs all 12 phases off Qubes, then every suite
│   ├── qubes_stub.py          one stand-in for every dom0 command
│   ├── static_checks.py       assertions over every generated config file
│   ├── doc_checks.py          the docs must not drift from the code
│   ├── config_checks.py       the code and its configuration must agree
│   ├── host_checks.py         build-host support per distribution
│   ├── quickstart_checks.py   ordering and safety of `quickstart`
│   ├── orchestration_checks.py  unattended build-host orchestration
│   ├── bootstrap_workflow_checks.py  the bootstrap onboarding and export
│   ├── install_path_checks.py the generated installer and first-boot scripts
│   ├── oem_media_checks.py    the QUBES_OEM partition on real media images
│   ├── signature_checks.py    signature checks against real GnuPG keys
│   ├── release_checks.py      the release-candidate gate
│   └── acceptance_checks.py   acceptance evidence and maintenance gates
└── .github/workflows/
    ├── ci.yml                 every push: the tests; every Monday: check-upstream
    └── release-candidate.yml  manual, trusted-runner release candidate
```

`golden_image.py` must stay beside `build_iso.py`, and
`docs/WORKSTATION-GUIDE.md` in `docs/` — both are base64-embedded into the
installer kickstart.

## Two scripts, two machines

| Script | Runs on | Does |
|---|---|---|
| `build_iso.py` | Build host (Debian-family — Debian 13, Kali, Ubuntu — or Fedora; Docker; ~100 GB, ~250 GB for tier=2) | Builds a signed bootable ISO, and with `tier=2` the five investigator templates too |
| `golden_image.py` | dom0, each laptop | Twelve phases: templates, chain, SIEM, segmentation, backups, tests (the unwired edition: the four template phases only) |

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

**No credentials are baked in.** The wired edition generates four secrets per
machine at provisioning into `~/golden-image/credentials.json`, mode 600.
Change them, escrow them, `shred -u` the file. The unwired edition generates
none. The build refuses a `provisioner_config` that would embed shared ones.

**Test on a spare machine first.** Not one you intend to issue.

## What runs by itself

Almost every step that used to be a manual checklist is now a command or a timer:

| Stage | Automated by |
|---|---|
| Preparing the build host | `setup-host`, `doctor --fix` |
| Creating, backing up and restoring the signing key | `gen-key`, `backup-key`, `restore-key` |
| Checking upstream keys, versions and Qubes security bulletins | `check-upstream`, and CI every Monday. Builds refuse to start on a blocking finding. |
| Verifying the Qubes builder itself | the signed tag is checked against the pinned Qubes master key |
| Writing and checking USB sticks | `write-usb`, `make-usb.sh`, `verify-iso.sh` |
| Publishing a download | `package-release` |
| Installing without clicking | `install.unattended`, `install.auto_initial_setup`. Only the disk passphrase stays human. |
| Building, wiring and testing the laptop | first boot, the twelve provisioner phases |
| Credentials after provisioning | `--handover` (rotate, escrow into `vault`, shred) |
| Releasing a laptop | `--issue`, which re-tests and refuses while credentials remain |
| Updates, IPS rules, backups, key expiry, self-checks, staleness | eight timers, which show a login banner when they fail |
| Wazuh upgrades in the right order | `--upgrade-wazuh` |
| Seeing where a machine stands | `--status` |

What is deliberately still yours: reading the fingerprint out over an
independent channel, plugging in the backup disk the first time, and deciding
that a machine is fit to issue.

## Status

Verified against primary sources on 2026-09-08 — Kali's signing keys and
published keyring checksum, the Zeek OBS repository and its key expiry, the
Wazuh release the repository actually offers and its signing key, the Qubes
4.3 template names and firewall chains, and the `qvm-backup` profile schema in
qubes-core-admin. `supply-chain.lock.json` records what was seen;
`./build_iso.py check-upstream` re-checks it and fails on drift. Its run on
2026-09-25 found nothing blocking and two warnings: Wazuh 4.14.8 was out and
upstream's `wazuh-passwords-tool.sh` had changed. Both were reviewed — the tool
change from 4.14.7 to 4.14.8 only adds retries and service-state polling,
no new endpoints — and the pins moved to 4.14.8 in 2.6.

`build_iso.py` has built and signed an image end to end on one real host:
`./build_iso.py quickstart --usb` on Kali Linux rolling, in a VirtualBox VM with
the Docker executor at tier 1, produced a signed 7.8 GB `InQubestigationOS.iso`
([docs/REVIEW.md](docs/REVIEW.md), pass 5). Nobody has installed it on a laptop
yet, so `golden_image.py` has still never run on a live Qubes 4.3.1 system. Both
are exercised on every push by `tests/run_tests.py`, a fake-dom0 harness that
runs all twelve phases — and the unwired edition — against stub `qvm-*` binaries
and then asserts on every configuration file they generated. Run it yourself:
`make check`.

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
