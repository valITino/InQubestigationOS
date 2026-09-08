# InQubestigationOS

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
                              ┌─────┴─────┐
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
| **SIEM in every compartment** | Wazuh agent in all nine templates, version-held, per-qube identity |
| **Investigator tooling** | Kali + Maltego, LibreOffice, Suricata, Zeek, Squid — all baked into the ISO |
| **Weekly encrypted backups** | Profile-mode `qvm-backup` on a systemd timer |
| **Acceptance tests** | Eleven groups, re-runnable, that prove the design is actually in force |

Base is Qubes OS 4.3.1. dom0 is Fedora because Qubes builds it that way and
cannot be changed; **everything else is Debian 13** — service qubes, all custom
templates, and Whonix.

## Quick start

```bash
# On a Debian 13 build host with Docker and ~250 GB free
./build_iso.py --write-config     # emit iso-build.json, review it
$EDITOR iso-build.json            # set iso_sign_key to your GPG fingerprint
./build_iso.py --dry-run all      # read the whole plan, change nothing
./build_iso.py all                # build templates, then the ISO
```

Write the ISO to USB, boot it, install. First boot provisions itself and there
is nothing to do by hand.

Full walkthrough: **[docs/GUIDE.md](docs/GUIDE.md)**.

## Repository layout

```
InQubestigationOS/
├── golden_image.py       provisioner — runs in dom0 on each laptop
├── build_iso.py          ISO + template builder — runs on a build host
├── docs/
│   ├── GUIDE.md          step-by-step, start to finish
│   ├── DESIGN.html       the visual design specification
│   ├── SIGNING.md        GPG signing — read before sending anyone a key
│   ├── VERIFICATION.md   supply chain: every repository and key, with sources
│   └── REVIEW.md         defects found during verification, and the test results
└── .gitignore            keeps credentials and build artifacts out of git
```

`golden_image.py` must stay beside `build_iso.py` — it is base64-embedded into
the installer kickstart.

## Two scripts, two machines

| Script | Runs on | Does |
|---|---|---|
| `build_iso.py` | Build host (Debian 13, Docker, ~250 GB) | Builds five investigator templates, then a signed bootable ISO |
| `golden_image.py` | dom0, each laptop | Twelve phases: templates, chain, SIEM, segmentation, backups, tests |

Both are standard-library Python 3 — no `pip install`, which matters because
dom0 has no network by design. Both embed their configuration, write it as JSON
on first run, and never overwrite your edits. Both are resumable: completed
phases are recorded and skipped.

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

## Status

Verified against primary sources on 2026-09-01: official Qubes documentation,
the QubesOS GitHub repositories, and vendor documentation for Kali, Zeek and
Wazuh. Six defects were found and fixed during that pass — three of which would
have failed *silently* in production. They are documented in
[docs/REVIEW.md](docs/REVIEW.md) rather than quietly patched, so nobody
reintroduces them.

Neither script has been run end-to-end against a live Qubes 4.3.1 system. They
have been exercised against a simulated dom0 (all twelve phases, 180 planned
actions, exit 0) and every generated configuration file passes 58 static
checks. Items that need real hardware print as `[VERIFY]` at the moment they
matter and are collected at the end of every run.

## Contributing

Changes to chain order, DNS, segmentation, agent coverage or the supply chain
bump the image version and reach every laptop through this repository — never by
hand-editing a single machine. The golden image is the git tag, not any one
laptop.

Before merging anything that touches the firewall or the SIEM, re-run
`sudo ./golden_image.py --verify` on a test install and confirm all acceptance
tests pass.
