# Supply chain verification record

Every third-party repository and signing key used by this image, with the primary
source it came from. Verified **2026-09-08**.

**This document is no longer the thing that has to be checked by hand.**
`./build_iso.py check-upstream` re-verifies every fact on this page against its
primary source — fingerprints, expiry dates, the published keyring checksum, the
Wazuh release the repository actually offers, and the Qubes security bulletin
index — and records what it saw in `supply-chain.lock.json`. It exits non-zero
when anything moved, and CI runs it every Monday. This page is the human-readable
account of the same data; the lock file is the machine-readable one.

    ./build_iso.py check-upstream            # report drift, change nothing
    ./build_iso.py check-upstream --update   # accept what upstream now offers
                                             # as the new baseline, then commit it

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
When that happens, confirm the new fingerprint at the source, then:

    ./build_iso.py --set kali.key_fpr=<new fingerprint>
    sudo ./golden_image.py --phase 4

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
| Repository | `deb [signed-by=/usr/share/keyrings/security_zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/Debian_13/ /` |
| Key URL | `https://download.opensuse.org/repositories/security:zeek/Debian_13/Release.key` |
| Install path | `/usr/share/keyrings/security_zeek.gpg` |
| Package | `zeek-lts` — the 8.0 LTS line, 8.0.10-0 as of 2026-09-08 |
| Install prefix | `/opt/zeek` |

Zeek is not in Debian main. Upstream distributes binaries through the openSUSE Build
Service. A `Debian_13` repository exists and the key URL was confirmed reachable on
2026-09-01.

**Two things to carry into operations.** First, Zeek state plainly that these
packages are signed by the OBS, which is outside the Zeek project's control — you are
trusting the build service, not a Zeek-held key. That is exactly why the key lives in
`/usr/share/keyrings/` and is scoped to this one repository with `signed-by=`: in
`/etc/apt/trusted.gpg.d/` it would have been a global trust anchor, and apt would
have accepted *any* repository the build service signed. Second, Zeek's own
documentation warns that on Debian-based systems you must manually re-add the key
when the old one expires — an expired OBS key silently stops `tpl-ids` from receiving
Zeek updates, which means your DPI recorder quietly goes stale. That check is no
longer on anyone's monthly checklist; see below.

**The package name matters more than it looks.** The OBS repository offers
`zeek` (the feature line, 8.2.2-0 today), `zeek-lts` (the 8.0 LTS line, 8.0.10-0)
and `zeek-8.0` — which sounds like the LTS pin and is in fact **frozen at
8.0.1-0**, nine point releases behind. This image was pinned to the frozen one
until 2026-09-08; a DPI recorder that never receives a fix is a DPI recorder you
should not be relying on. `zeek-lts` tracks the 8.0 LTS line and will not jump to
a new LTS on its own, which is the right choice for casework: predictable log
formats matter more than new features.

**The OBS key, recorded.** Confirmed 2026-09-08:

| Fingerprint | Expires |
|---|---|
| `F9FA0223B56B116C363737EF5DA57BDD6DD785CA` | 2026-12-02 (85 days from verification) |

`check-upstream` compares this against the published key on every run and fails
the check if it changes. It also warns once the key is inside 60 days of expiry,
and a `golden-key-expiry.timer` inside `sys-dpi` does the same from the running
machine — Zeek's own documentation warns that an expired OBS key silently stops
DPI updates on Debian, so neither of those checks is optional.

**This key is inside its warning window now.** Expect to re-add it before
December 2026.

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
| Signing key | `0DCFCA5547B19D2A6099506096B3EE5F29111145` — Wazuh.com (Wazuh Signing Key) <support@wazuh.com>, expires 2027-05 |

The Wazuh key is now pinned as `wazuh.key_fpr` and verified after import in every
template, exactly as the Kali key is. Before, whatever bytes came back from
`packages.wazuh.com` were imported into a keyring that `signed-by=` then trusted
for the SIEM's packages, with nothing checking what they were.

### The version-pinning requirement — this was a real bug

Wazuh guarantee compatibility only when the **manager version is greater than or
equal to the agent version**, and they recommend disabling the repository after
install to prevent accidental upgrades.

This image updates every template weekly. Without pinning, an ordinary
`apt upgrade` inside `tpl-kali` would eventually push `wazuh-agent` past the manager
version in `wazuh-srv`, and agents across the whole laptop would stop reporting —
silently, at some unpredictable future date, most likely noticed only when someone
went looking for evidence that was never collected.

`wazuh.pin_agent: true` in `golden-image.json` (the default) therefore does both
documented mitigations in every template, and the agent is installed at the
pinned `wazuh.version` rather than at whatever the repository happens to offer:

    echo "wazuh-agent hold" | dpkg --set-selections     # freeze the package
    sed -i 's|^deb |#deb |' /etc/apt/sources.list.d/wazuh.list

Phase 12 tests that the hold is actually in place across all Debian templates.

**Upgrade order, when the time comes:** manager first, then release the holds and
upgrade the agents. Never the reverse — and you no longer have to remember which
way round it goes:

    sudo ./golden_image.py --upgrade-wazuh

That upgrades `wazuh-srv`, reads back the version it actually reached, refuses to
touch a single agent if it cannot, then upgrades and re-pins every template agent
to that exact version.

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

## Qubes-side details — now checked by the machine, not by you

This used to be a checklist of things to confirm by hand on the first build.
Every item on it that could be turned into a test has been, and they run as
acceptance-test group 13 on the real hardware:

| Was a checklist item | Now |
|---|---|
| nftables chain names on Qubes 4.3 | group 13 reads `dnat-dns` and `custom-dnat-squid` back out of the running qubes and fails if the golden rule is not there |
| `custom-prerouting` exists? | **it does not** — see [REVIEW.md](REVIEW.md) defect 1. `tests/static_checks.py` fails the build if the name reappears in any generated config |
| `qvm-prefs <vm> ip` is settable | group 13 asserts `wazuh-srv`'s address is the configured one |
| `qubes.ConnectTCP` grammar and `qvm-connect-tcp` argument order | group 13 opens the dashboard from `work` over qrexec and fetches from it |
| `qvm-backup` profile keys | group 13 generates a reference profile with `--save-profile` and compares key names |
| `qvm-firewall <vm> reset` exists | capability-checked at runtime with a documented fallback; nothing to confirm |
| Squid `peek`/`splice` for the packaged build | group 13 runs `squid -k parse` in `sys-proxy` |
| `10.137.0.50` free of collision | phase 1 refuses to start if it is taken, and refuses to guess if `qvm-ls` fails |
| Zeek install prefix | discovered at boot; the qube logs a line if it is not where `zeek.prefix` says |
| Wi-Fi in a Debian `sys-net` | group 13 looks for a wireless interface and for firmware load failures |
| Tor actually carries the traffic | group 13 asks `check.torproject.org/api/ip` from `kali-tor` |

What is left for a person is genuinely a matter of judgement, not verification:

- [ ] Kali apt pin priorities suit your unit's tool set in practice
- [ ] the acceptance-test run on the specific hardware you are about to issue

---

## Revision log

| Date | Image version | What was re-verified | By |
|---|---|---|---|
| 2026-09-01 | 2.1 | Kali key + checksum, Zeek Debian_13 repo, Wazuh 4.14.7 and pinning requirement | initial research |
| 2026-09-08 | 2.2 | All of the above re-checked against primary sources by `./build_iso.py check-upstream`: Kali `827C…E4C5` present and valid for 586 days, published keyring SHA1 unchanged, Zeek OBS key `F9FA…85CA` recorded (85 days to expiry), Wazuh 4.14.7 confirmed current in the stable apt repository, Wazuh signing key `0DCF…1145` pinned, Qubes bulletin baseline at qsb-118-2026 | `check-upstream`, recorded in `supply-chain.lock.json` |
