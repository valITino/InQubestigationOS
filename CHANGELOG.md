# Changelog

## 2.1 — 2026-09-01

Verification pass against primary sources. Six defects found and fixed, three of
which would have failed silently in production. Full detail in
[docs/REVIEW.md](docs/REVIEW.md).

**Fixed**

- `custom-prerouting` chain does not exist in Qubes — the Squid redirect was
  never installed. Replaced with a created `custom-dnat-squid` chain, the
  documented pattern.
- Missing `custom-input` accept — redirected packets terminate locally, so Squid
  would have received nothing even with a working redirect.
- DNS rules were written into `dnat-dns`, which `qubes-setup-dnat-to-ns`
  regenerates at every network start. Now replaced wholesale from
  `/rw/config/qubes-firewall.d/`.
- `qvm-backup` has no `--yes` flag — the weekly timer would have hung forever.
  Switched to profile mode.
- `qvm-firewall reset` is not in the official manpage. Now capability-checked
  with a documented fallback.
- `/rw/bind-dirs/var/ossec` was never seeded, so Wazuh agents would have
  re-enrolled as new hosts on every reboot.

**Changed**

- Tier 2 is now the default: investigator templates baked into the ISO, installs
  with no network.
- Added a fifth template flavor, `investigator-wazuh`, baking the SIEM stack in.
  Phase 8 now generates per-machine certificates and starts the services — the
  last manual step is gone.
- Debian everywhere possible: `tpl-sys` (sys-net, sys-firewall, sys-usb) moved
  from Fedora to Debian 13. dom0 remains Fedora because Qubes builds it that way.
- GPG signing hardened: fingerprint-only, refuses pasted key material, validates
  before any environment check, exports the public key beside the ISO.
- Ported from bash to standard-library Python 3.

**Verified**

- Kali 2025 signing key `827C…E4C5` confirmed current (expires 2028-04-17); the
  retired key is `44C6…0BF6`. Repository line now uses `signed-by=`.
- Zeek 8.0 LTS via the openSUSE Build Service `Debian_13` repository.
- Wazuh 4.14.7; agent must be at or below the manager version, so agents are
  version-held in every template.
- Qubes 4.3 template naming: `debian-13-xfce`, `whonix-*-18`, and Fedora 42, 43
  and 44 all exist — the ISO builder derives names from `comps-dom0.xml`.

## 1.0 — 2026-09-01

Initial design and bash implementation. Superseded.
