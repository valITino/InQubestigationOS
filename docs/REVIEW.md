# Review and fixes — v2.1

Deep verification against primary sources (official Qubes docs, QubesOS GitHub
repos, upstream vendor docs) turned up **six real bugs**, three of which would
have caused silent failures in production. All are fixed and re-tested.

## Bugs found and fixed

### 1. `custom-prerouting` does not exist (would have broken the proxy entirely)

The Squid intercept redirect was written into a chain named `custom-prerouting`.
Qubes has **no such chain**. The documented user hooks are `custom-forward` and
`custom-input` only; for NAT you must create your own chain. A request to add a
`custom-nat` chain is still open upstream (qubes-issues #8629).

Now follows the pattern in the official firewall documentation:

```sh
nft add chain ip qubes custom-dnat-squid \
    '{ type nat hook prerouting priority filter + 1 ; policy accept; }'
nft add rule ip qubes custom-dnat-squid iifname "vif*" tcp dport 80  redirect to :3128
nft add rule ip qubes custom-dnat-squid iifname "vif*" tcp dport 443 redirect to :3129
```

### 2. Missing `custom-input` accept (Squid would have received nothing)

Redirected packets terminate **locally** on `sys-proxy`, so they hit the input
path, not forward. The old script only touched forward chains, so even with a
working redirect the traffic would have been dropped before reaching Squid. This
was a genuine "looks configured, silently broken" bug. Added:

```sh
nft add rule ip qubes custom-input iifname "vif*" tcp dport { 3128, 3129 } counter accept
```

The same omission applied to DNS; `custom-input` now accepts port 53 from `vif*`.

### 3. DNS rules were written into a chain Qubes regenerates

The old code did `nft flush chain ip qubes dnat-dns` from
`qubes-firewall-user-script`. Two problems: modifying Qubes-managed chains is
explicitly unsupported, and `qubes-setup-dnat-to-ns` **rewrites `dnat-dns` when
the network comes up**, silently discarding the rules. DNS enforcement would
have appeared configured and quietly not applied.

Now uses the working pattern from qubes-issues #9056 — replace the chain
wholesale from a `#!/usr/sbin/nft -f` script in `/rw/config/qubes-firewall.d/`,
which runs as part of qubes-firewall startup:

```
add chain ip qubes dnat-dns
delete chain ip qubes dnat-dns
table ip qubes {
    chain dnat-dns {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "vif*" meta l4proto { tcp, udp } th dport 53 redirect to :53
    }
}
```

`redirect` rather than `dnat to 127.0.0.1` avoids needing `route_localnet`.
unbound now binds all interfaces with `access-control` limited to the qube
subnets, so it is not an open resolver, plus `forward-first: no` to stop
cleartext fallback.

### 4. `qvm-backup` has no `--yes` flag

The weekly backup would have hung waiting for confirmation, forever, every
Sunday at 03:00 — the kind of failure nobody notices until they need a restore.
Profile mode is the documented non-interactive path. The wrapper script now
regenerates `/etc/qubes/backup/golden-image.conf` (so current `case-*` qubes are
picked up) and runs `qvm-backup --profile golden-image`.

### 5. `qvm-firewall reset` is not in the official manpage

Widely used in community scripts, absent from the documented subcommands
(`add`, `del`, `list`). Replaced with a capability check: use `reset` only if
`qvm-firewall --help` advertises it, otherwise delete by rule number.

### 6. bind-dirs would have lost the Wazuh agent identity

`/var/ossec` was declared in bind-dirs but `/rw/bind-dirs/var/ossec` was never
seeded. If the directory does not already exist there, the first-boot copy fails
and the agent re-enrols as a new agent on every reboot. Now pre-created before
the bind takes effect. File names also changed to the documented
`NN_name.conf` convention (`50_golden_wazuh.conf`).

## Corrections to the documentation

**The Kali fingerprint.** `827C8569F2518CC677FECA1AED65462EC8D5E4C5` **is the
current 2025 key** (rsa4096, created 2025-04-17, expires 2028-04-17, short id
`ED65462EC8D5E4C5`). The retired key is `44C6513A…ED444FF07D8D0BF6`. The scripts
already treated it correctly, but the comments now say so explicitly so nobody
"corrects" it later. The repository line now uses
`signed-by=/usr/share/keyrings/kali-archive-keyring.gpg` rather than relying on
the global trust store.

**Qubes 4.3 template names.** Fedora 42, 43 **and** 44 all exist for 4.3 (43 was
added 2026-02, 44 in 2026-07). `debian-13-xfce` is the default Debian template;
bare `debian-13` is the GNOME build. dom0 is Fedora 41. The ISO builder derives
names from `comps-dom0.xml` rather than hardcoding, and the provisioner config
documents the choice.

**builder.yml keys.** `template-root-size` and `timeout` are top-level keys, not
per-template. The per-template `timeout` entries were removed.

**Debian service qubes.** `tpl-sys` now explicitly installs
`qubes-core-agent-networking`, `qubes-core-agent-network-manager`,
`qubes-usb-proxy`, `qubes-input-proxy-sender` and firmware. The full
`debian-13-xfce` template already has these via `qubes-vm-recommended`, but a
minimal base would not — this makes either work.

**Wazuh.** Confirmed 4.14.7 current, and that the agent must be **at or below**
the manager version. Upgrade order is now printed during provisioning: manager
first, then release the holds and upgrade agents.

## What was actually tested

A fake-dom0 harness (stub `qvm-*` binaries plus patched `/etc/qubes-release`)
runs the provisioner end to end.

| Test | Result |
|---|---|
| Both scripts compile | pass |
| Dry run, all 12 phases | 180 actions planned, no aborts |
| Real run against the harness | exit 0, 11/12 phases marked complete |
| Phase 12 correctly refuses to mark complete when tests fail | pass |
| Generated config files captured and validated | **58/58 checks pass** |
| systemd unit structural validation (`systemd-analyze verify`) | pass |
| Credentials file mode 600, four unique 24-char secrets | pass |
| Backup profile and qrexec policy written correctly | pass |

The 58 static checks cover: nftables brace balance, chain types and hooks
against the valid sets, `redirect` used only in a nat prerouting context, no
reference to the non-existent `custom-prerouting`, nft set spacing, the
add-then-delete idiom and `dstnat` priority in the DNS script, Squid
peek-then-splice with no decryption plus `%>a` attribution logging, unbound DoT
syntax and non-open-resolver posture, Suricata `queue num` (not `queue to`) and
genuine fail-closed with no `bypass` in any executable line, and absence of
unsubstituted template placeholders in every file.

Two bugs were found *by* the harness rather than by reading: dry-run aborted at
phase 8 because it did not track qubes it would have created, and a backslash in
a comment silently swallowed the following line. Both fixed.

## Still not verified — requires real hardware

These cannot be checked without a live Qubes 4.3.1 install. Each prints as
`[VERIFY]` at the moment it matters and is collected at the end of every run.

- That `dnat-dns` survives with the golden-image rule after reboot:
  `nft list chain ip qubes dnat-dns`
- That the `custom-dnat-squid` counters increment under load
- The `qvm-backup` profile schema — confirm with one manual
  `sudo qvm-backup --profile golden-image`; if the keys are rejected, generate a
  reference with `--save-profile` and copy its key names
- `qvm-prefs <vm> ip` accepted on your build
- `qubes.ConnectTCP` policy grammar and `qvm-connect-tcp` port ordering
- Squid peek/splice directive names against the shipped Squid 6.13 config
- Zeek install prefix (`/opt/zeek` assumed)
- Wi-Fi in a Debian `sys-net` on the issued NIC — drivers come from the dom0
  kernel, firmware from the template
- pykickstart merging two `%packages` sections (standard Anaconda behaviour, not
  confirmed against a Qubes-specific source)
