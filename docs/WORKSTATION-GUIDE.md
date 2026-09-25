# InQubestigationOS — workstation guide

This file ships inside every InQubestigationOS install, at
`/usr/share/doc/inqubestigationos/WORKSTATION-GUIDE.md` in dom0. It is written
for the person sitting at the machine, and matters most on the **unwired
edition**. That edition gives you the templates and leaves the wiring to you.
Below is how the wired edition connects everything, so you can copy it, adapt
it, or finish the job with one command.

**Contents**

1. [Which edition do I have?](#1-which-edition-do-i-have)
2. [The templates you have](#2-the-templates-you-have)
3. [The wired design at a glance](#3-the-wired-design-at-a-glance)
4. [Wiring it yourself, step by step](#4-wiring-it-yourself-step-by-step)
5. [Or let the provisioner wire it](#5-or-let-the-provisioner-wire-it)
6. [Best practice](#6-best-practice)
7. [Useful commands](#7-useful-commands)

---

## 1. Which edition do I have?

```bash
sudo golden-image-provision --status
```

Under the version header it says `edition: wired` or `edition: unwired`.

| | Wired | Unwired |
|---|---|---|
| Templates with their tools installed | yes | yes |
| Wazuh agent installed, disabled, in the templates | every template | the new `tpl-*` templates only |
| Inspection chain (proxy, IPS, DPI) created | yes | **no** |
| Wazuh manager (SIEM) created | yes | **no** |
| App qubes re-templated and re-routed | yes | **no** |
| Per-machine secrets generated | yes | **no** |
| dom0 policy, backups, maintenance timers | yes | **no** |

On the unwired edition, nothing you already had is changed: `sys-net`,
`sys-firewall`, `personal`, `work`, `vault`, the stock templates and the rest
stay as Qubes installed them.

## 2. The templates you have

Every custom template is Debian 13: a clone of `debian-13-xfce`, or, on a tier 2
image, of the matching prebuilt `investigator-*` template, which is Debian too.
One distribution, one package manager, one update cadence.

| Template | What is in it | Meant for |
|---|---|---|
| `tpl-sys` | the Debian service-qube packages (networking, USB, firmware), and unbound for `sys-firewall`'s DNS over TLS | `sys-net`, `sys-firewall`, `sys-usb` |
| `tpl-proxy` | Squid | an attribution/logging web proxy qube |
| `tpl-ids` | Suricata and Zeek | an inline IPS qube and a DPI qube |
| `tpl-kali` | Kali (dist-upgraded, `kali-linux-default`) | investigation qubes |
| `tpl-personal` | LibreOffice and the office payload | `personal`, `work`, `vault`, offline viewers |
| `tpl-wazuh` | the verified Wazuh package repository (the SIEM stack itself is installed into its qube when wiring) | a SIEM manager qube |

Each carries the Wazuh agent **installed but disabled**. A template is a
shared filesystem: an agent enabled there would beacon during updates, and
every qube cloned from it would share one agent identity. Enable it per qube,
never in the template.

## 3. The wired design at a glance

```
<app qubes> -> sys-proxy -> sys-ids -> sys-dpi -> sys-firewall -> sys-net -> internet
<tor qubes> -> sys-whonix -> sys-firewall -> sys-net -> internet
vault, dvm-offline: no network at all
```

| Qube | Template | netvm | Role |
|---|---|---|---|
| `sys-dpi` | `tpl-ids` | `sys-firewall` | Zeek: records what crossed the wire |
| `sys-ids` | `tpl-ids` | `sys-dpi` | Suricata inline IPS: blocks what matches |
| `sys-proxy` | `tpl-proxy` | `sys-ids` | Squid: intercepts and attributes web traffic |
| `wazuh-srv` | `tpl-wazuh` | `sys-proxy` | Wazuh indexer, manager and dashboard (a StandaloneVM clone, fixed IP) |
| `kali-clear` | `tpl-kali` | `sys-proxy` | Kali on the inspected clearnet path |
| `kali-tor` | `tpl-kali` | `sys-whonix` | Kali over Tor (TCP only: no SYN scans, UDP or ICMP) |
| `dvm-offline` | `tpl-personal` | none | disposable template: evidence opens here, destroyed on close |
| `personal`, `work` | `tpl-personal` | `sys-proxy` | everyday work; egress limited to web and DNS |
| `vault` | `tpl-personal` | none | secrets, offline |

The chain is built from the top down, so each upstream qube exists before
anything points at it. `sys-whonix` joins at `sys-firewall` and deliberately
skips the proxy, IPS and DPI.

## 4. Wiring it yourself, step by step

These are the Qubes commands the wired edition runs, in its order. Adapt names,
memory and labels to taste. Run them in dom0.

**The inspection chain** (a network-providing qube for each hop):

```bash
qvm-create --class AppVM --template tpl-ids   --label orange sys-dpi
qvm-prefs sys-dpi   provides_network True
qvm-prefs sys-dpi   netvm sys-firewall
qvm-create --class AppVM --template tpl-ids   --label orange sys-ids
qvm-prefs sys-ids   provides_network True
qvm-prefs sys-ids   netvm sys-dpi
qvm-create --class AppVM --template tpl-proxy --label orange sys-proxy
qvm-prefs sys-proxy provides_network True
qvm-prefs sys-proxy netvm sys-ids
```

The wired edition gives `sys-ids` and `sys-dpi` 1024 MB (up to 3072) and two
vCPUs, and `sys-proxy` 512 MB (up to 2048). The qubes above only carry the
software. Configuring Squid interception, Suricata's NFQUEUE inline mode and
Zeek is the part the provisioner automates in its phase 7. See section 5.

**Service qubes on the Debian template** (shut each down first):

```bash
qvm-shutdown --wait sys-usb sys-firewall sys-net
qvm-prefs sys-net      template tpl-sys
qvm-prefs sys-firewall template tpl-sys
qvm-prefs sys-usb      template tpl-sys
```

If your keyboard or mouse goes through `sys-usb`, expect input to drop while it
restarts.

**Everyday qubes onto the office template, and behind the proxy** (shut them
down first):

```bash
qvm-shutdown --wait personal work vault
qvm-prefs personal template tpl-personal
qvm-prefs work     template tpl-personal
qvm-prefs vault    template tpl-personal
qvm-prefs personal    netvm sys-proxy
qvm-prefs work        netvm sys-proxy
qvm-prefs untrusted   netvm sys-proxy
qvm-prefs default-dvm netvm sys-proxy
qvm-prefs vault netvm none
```

**Investigation qubes, and an offline disposable for evidence:**

```bash
qvm-create --class AppVM --template tpl-kali --label yellow kali-clear
qvm-prefs kali-clear netvm sys-proxy
qvm-create --class AppVM --template tpl-kali --label purple kali-tor
qvm-prefs kali-tor netvm sys-whonix
qvm-create --class AppVM --template tpl-personal --label red dvm-offline
qvm-prefs dvm-offline netvm none
qvm-prefs dvm-offline template_for_dispvms True
qvm-features dvm-offline appmenus-dispvm 1
```

**Egress limits** for `personal` and `work` (web and DNS only). Clear the
qube's existing rules first — rules are added, not replaced, and an earlier
broad accept would still match ahead of the final drop — then repeat the same
for `personal`:

```bash
qvm-firewall work reset          # remove the existing rules
qvm-firewall work add accept proto=tcp dstports=80
qvm-firewall work add accept proto=tcp dstports=443
qvm-firewall work add accept specialtarget=dns
qvm-firewall work add drop
qvm-firewall work list           # check what is now in force
```

## 5. Or let the provisioner wire it

The templates were built by the same provisioner the wired edition uses. It
can finish the job at any time: it skips what is already done, generates the
per-machine secrets, and builds, configures and tests everything in section 3.

```bash
sudo golden-image-provision --edition wired --dry-run   # see every action first
sudo golden-image-provision --edition wired             # wire it
sudo golden-image-provision --verify                    # the full acceptance tests
```

Running it with `--edition wired` records the change in the machine's
configuration, so `--status`, `--verify`, `--issue` and the weekly self-check
treat the machine as wired from then on. There is no way back to unwired short
of reinstalling: the unwired edition skips the wiring, it does not remove it.

After wiring, the credentials land in `~/golden-image/credentials.json`
(mode 600). Rotate, escrow and shred them with
`sudo golden-image-provision --handover`.

## 6. Best practice

- **Nothing on the clearnet path should attach above `sys-proxy`.** A qube
  pointed straight at `sys-firewall` or `sys-net` skips every inspection hop.
  Only `sys-whonix` belongs there, by design.
- **Open evidence offline.** Files from outside go into a disposable based on
  `dvm-offline` (no network, destroyed on close), never into `work`.
- **Keep `vault` offline** (`netvm none`), and keep secrets there rather than in
  dom0.
- **Separate identities.** Use `kali-tor` for anything that must not be linked
  to you, and `kali-clear` only for what may be. A Tor qube cannot run SYN
  scans, UDP or ICMP; do those from `kali-clear`.
- **Enable the Wazuh agent per qube, never in a template.** Otherwise every
  clone reports as the same host.
- **Update templates, not qubes.** App qubes reset to their template on every
  restart: `sudo qubes-vm-update` updates all templates at once.
- **dom0 stays offline.** Do not install software in dom0 or copy files into
  it. It is Fedora by Qubes' architecture, and the one place a compromise
  reaches everything.
- **Back up.** `qvm-backup` to an encrypted external disk, and test a restore
  now and then. A backup you have never restored from is a guess.

## 7. Useful commands

```bash
sudo golden-image-provision --status            # edition, phases, timers, recent results
sudo golden-image-provision --verify            # acceptance tests for your edition
sudo golden-image-provision --list-phases       # what each phase does
journalctl -t golden-image -f                   # watch first-boot provisioning live
qvm-ls --format network                         # every qube and its netvm
```
