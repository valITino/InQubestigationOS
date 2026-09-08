# Supply chain verification record

Every third-party repository and signing key used by this image, with the primary
source it came from. Verified **2026-09-01**. Re-verify before each image version
bump and record the date below.

The build script enforces the Kali fingerprint automatically and aborts if it does
not match. The other two are recorded here for manual comparison.

---

## Kali Linux

| | |
|---|---|
| Primary source | `https://www.kali.org/blog/new-kali-archive-signing-key/` (published 2025-04-28) |
| Repository | `deb https://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware` |
| Keyring URL | `https://archive.kali.org/archive-keyring.gpg` |
| Install path | `/usr/share/keyrings/kali-archive-keyring.gpg` |

Keys inside that keyring:

| Fingerprint | Identity | Created | Expires |
|---|---|---|---|
| `827C8569F2518CC677FECA1AED65462EC8D5E4C5` | Kali Linux Archive Automatic Signing Key (2025), rsa4096 | 2025-04-17 | 2028-04-17 |
| `44C6513A8E4FB3D30875F758ED444FF07D8D0BF6` | Kali Linux Repository, rsa4096 (legacy) | 2012-03-05 | 2027-02-04 |

Published file checksum (SHA1, as of 2025-04-28):
`603374c107a90a69d983dbcb4d31e0d6eedfc325`

**Context worth knowing.** Kali lost access to their old repository signing key in
April 2025 and had to roll a new one; every Kali system worldwide failed `apt update`
until users installed the new key by hand. Kali state this was not a compromise —
the old key is still shipped in the keyring rather than revoked. The practical
lesson for this image: a Kali key roll will break `tpl-kali` updates without warning.
When that happens, update `KALI_KEY_FPR` in `golden-image.conf` after confirming the
new fingerprint at the source, and re-run phase 4.

**Independent cross-check.** Kali developers signed the 2025 key and published those
signatures on the Ubuntu keyserver:
`https://keyserver.ubuntu.com/pks/lookup?search=827C8569F2518CC677FECA1AED65462EC8D5E4C5&fingerprint=on&op=index`

Do this cross-check on first build rather than trusting the blog post alone. Two
independent sources agreeing is the standard you want before a police workstation
trusts a package repository.

**Fingerprint vs checksum.** The script treats the fingerprint as authoritative and
the SHA1 as advisory. The fingerprint identifies the key itself and only changes
when Kali rolls a key. The checksum identifies the *file*, and changes whenever the
keyring is regenerated for any reason. A checksum mismatch with a passing
fingerprint means the file was rebuilt — annoying, not alarming. A fingerprint
mismatch stops the build.

---

## Zeek

| | |
|---|---|
| Primary source | `https://docs.zeek.org/en/current/install.html` |
| Repository | `deb http://download.opensuse.org/repositories/security:/zeek/Debian_13/ /` |
| Key URL | `https://download.opensuse.org/repositories/security:zeek/Debian_13/Release.key` |
| Install path | `/etc/apt/trusted.gpg.d/security_zeek.gpg` |
| Package | `zeek-8.0` (LTS line) |
| Install prefix | `/opt/zeek` |

Zeek is not in Debian main. Upstream distributes binaries through the openSUSE Build
Service. A `Debian_13` repository exists and the key URL was confirmed reachable on
2026-09-01.

**Two things to carry into operations.** First, Zeek state plainly that these
packages are signed by the OBS, which is outside the Zeek project's control — you are
trusting the build service, not a Zeek-held key. Second, Zeek's own documentation
warns that on Debian-based systems you must manually re-add the key when the old one
expires. Put that on the monthly maintenance checklist; an expired OBS key silently
stops `tpl-ids` from receiving Zeek updates, which means your DPI recorder quietly
goes stale.

`zeek-8.0` pins the 8.0 LTS line rather than tracking feature releases, so the
template will not jump to a new LTS on its own. That is the right choice for
casework: predictable log formats matter more than new features.

**First-build action.** The script prints the imported OBS key fingerprint to the
build log. Record it here on first build and compare on every later build:

    OBS key fingerprint (record on first build): ____________________________________

---

## Wazuh

| | |
|---|---|
| Primary source | `https://documentation.wazuh.com/current/installation-guide/` |
| Version at verification | **4.14.7** |
| Key URL | `https://packages.wazuh.com/key/GPG-KEY-WAZUH` |
| APT repository | `deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main` |
| YUM base URL | `https://packages.wazuh.com/4.x/yum/` |
| Keyring path | `/usr/share/keyrings/wazuh.gpg` |

### The version-pinning requirement — this was a real bug

Wazuh guarantee compatibility only when the **manager version is greater than or
equal to the agent version**, and they recommend disabling the repository after
install to prevent accidental upgrades.

This image updates every template weekly. Without pinning, an ordinary
`apt upgrade` inside `tpl-kali` would eventually push `wazuh-agent` past the manager
version in `wazuh-srv`, and agents across the whole laptop would stop reporting —
silently, at some unpredictable future date, most likely noticed only when someone
went looking for evidence that was never collected.

`WAZUH_PIN_AGENT=true` (the default) therefore does both documented mitigations in
every template:

    echo "wazuh-agent hold" | dpkg --set-selections     # freeze the package
    sed -i 's|^deb |#deb |' /etc/apt/sources.list.d/wazuh.list

Phase 12 tests that the hold is actually in place across all Debian templates.

**Upgrade order, when the time comes:** upgrade `wazuh-srv` first, then release the
hold in the templates and upgrade the agents. Never the reverse.

### Enrollment method

The script uses Wazuh's documented password-authentication flow rather than the
`agent-auth` tool. On the manager: `<use_password>yes</use_password>` inside the
`<auth>` block, plus `/var/ossec/etc/authd.pass` at mode 640 owned `root:wazuh`.
On each agent: the same password file with the same mode and ownership, the manager
address in `<client><server><address>`, then restart. The agent enrolls itself on
start.

This is better for a golden image than `agent-auth` because it is declarative and
idempotent — re-running the build re-applies the same configuration instead of
attempting a fresh registration.

---

## Still unverified — check at build time

These are Qubes-side details I could not confirm against a running 4.3.1 system.
None is architectural; all are quick checks during the first build.

- [ ] nftables chain names `custom-forward`, `custom-prerouting`, `dnat-dns` on Qubes 4.3
- [ ] `qvm-prefs <vm> ip` is settable (used to pin the SIEM address)
- [ ] `qvm-connect-tcp` argument order and `qubes.ConnectTCP` policy grammar
- [ ] `qvm-backup` flags: `--passphrase-file`, `--dest-vm` semantics
- [ ] `qvm-firewall <vm> reset` exists
- [ ] Squid `peek`/`splice` option set for the packaged `squid-openssl` build
- [ ] Kali apt pin priorities suit your tool set in practice
- [ ] `10.137.0.50` free of collision after provisioning (`qvm-ls -O name,ip`)

---

## Revision log

| Date | Image version | What was re-verified | By |
|---|---|---|---|
| 2026-09-01 | 1.1 | Kali key + checksum, Zeek Debian_13 repo, Wazuh 4.14.7 and pinning requirement | initial research |
| | | | |
