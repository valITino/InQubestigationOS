# InQubestigationOS — the complete guide

From an empty build host to an issued investigator laptop. Follow it in order.

**Contents**

1. [What you need before starting](#1-what-you-need-before-starting)
2. [Prepare the build host](#2-prepare-the-build-host)
3. [Create the signing key](#3-create-the-signing-key)
4. [Configure the build](#4-configure-the-build)
5. [Build the templates](#5-build-the-templates)
6. [Build the ISO](#6-build-the-iso)
7. [Distribute the ISO](#7-distribute-the-iso)
8. [Install on a laptop](#8-install-on-a-laptop)
9. [First boot](#9-first-boot)
10. [Verify before issuing](#10-verify-before-issuing)
11. [Hand over to the investigator](#11-hand-over-to-the-investigator)
12. [Ongoing maintenance](#12-ongoing-maintenance)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. What you need before starting

**A build host.** Debian 13 preferred, Fedora works. This is *not* dom0 and not
the laptop you are building — it is a separate machine or VM.

| Requirement | Why | Who satisfies it |
|---|---|---|
| Debian 13 or Fedora | qubes-builderv2 ships dependency lists for both | you |
| Docker, usable without `sudo` | Build cages. Podman cannot currently build DEB packages | `setup-host` |
| ~250 GB free disk | Five templates plus the ISO. Tier 1 needs ~100 GB | you |
| 8 GB RAM minimum | Builds are slow and can OOM below this | you |
| Several hours | The Kali template dominates | you |

Everything in that table that a script can do, a script does. Ask first:

```bash
./build_iso.py doctor
```

It checks each requirement, changes nothing, and prints the command that fixes
whatever is missing. Every later step in this guide is also available as a
`make` target — run `make` on its own for the list.

**A target laptop** with VT-x and VT-d/IOMMU, 32 GB RAM comfortable (16 GB
workable), 512 GB SSD minimum. Check it against the Qubes Hardware
Compatibility List before committing.

**A GPG key** for signing. Section 3 covers creating one.

**A spare machine to test on.** Do not let the first install be on hardware you
intend to issue.

---

## 2. Prepare the build host

Clone the repository, then let it prepare the host:

```bash
git clone <your-internal-url>/InQubestigationOS.git
cd InQubestigationOS
./build_iso.py setup-host
```

It prints every command it intends to run and asks once before running any of
them. It installs Docker, git, curl, gnupg, rsync and python3-yaml, enables the
Docker service, adds you to its group, and — if the build host is a Qubes app
qube rather than a normal machine — writes the bind-dirs entry that keeps
`/var/lib/docker` across reboots and seeds the directory so the first copy does
not fail silently.

Group membership does not apply to a shell that was already open. Rather than
telling you to log out and back in, `setup-host` verifies through `sg` and tells
you how to run this session's build without one:

```bash
sg docker -c './build_iso.py all'
```

Then confirm the whole host in one command:

```bash
./build_iso.py doctor
```

For an unattended run, `--yes` answers every prompt.

---

## 3. Create the signing key

```bash
./build_iso.py gen-key --uid "Kapo Cyber Image Signing <cyber@example.ch>"
```

That generates an rsa4096 signing key with a three-year expiry — deliberate: an
image-signing key should outlive a build cycle but not outlive the team — and
then does the parts that used to be manual and easy to fumble:

- writes the fingerprint into `iso-build.json`, so nothing is retyped
- exports the public key beside the ISO
- writes `FINGERPRINT.txt`, laid out in the two rows of five groups that
  `gpg --fingerprint` prints, ready to be read out over the phone

gpg will ask for a passphrase. `--no-passphrase` skips it and says loudly why
that is a lab-only choice.

If your unit already has an image-signing key in this keyring, adopt it instead:

```bash
./build_iso.py gen-key --use-key auto          # exactly one secret key present
./build_iso.py gen-key --use-key <fingerprint> # otherwise
```

> **Never put private key material in a config file or this repository.** Only
> the fingerprint goes in `iso-build.json`. The private key stays in the build
> host's keyring. The build script refuses to start if it finds a key block, and
> validates the fingerprint format before anything else runs.
> Details in [SIGNING.md](SIGNING.md).

---

## 4. Configure the build

There is nothing you have to edit. Step 3 already set the only key that has no
sensible default. To change anything else, name it — no editor, and a typo is
rejected rather than silently ignored:

```bash
./build_iso.py --set work_dir=/srv/build --set tier=2
./build_iso.py --get tier
./build_iso.py config                    # print every effective setting
```

The settings that matter:

| Key | Set it to |
|---|---|
| `iso_sign_key` | set for you by `gen-key` |
| `tier` | `2` (default) — templates baked in, installs with no network |
| `qubes_release` | `r4.3` |
| `mock_config` | `auto` (default) — derived from the fetched builder for your release |
| `work_dir` | Somewhere with 250 GB free |
| `auto_provision` | `true` — first boot configures itself |

Before a first build, check that what the image trusts is still what upstream
publishes:

```bash
./build_iso.py check-upstream
```

It compares the pinned Kali, Zeek and Wazuh signing keys against the live
sources, reports how long each has before it expires, checks the Wazuh version
the repository actually offers, and lists any Qubes Security Bulletin published
since the recorded baseline — flagging the ones that touch dom0, Xen or the
kernel, which are the ones that mean rebuild. It exits non-zero if anything
moved. CI runs it every Monday.

Now read the plan without changing anything:

```bash
./build_iso.py --dry-run all
```

This prints every action it would take. Read it. It takes two minutes and will
save you hours.

---

## 5. Build the templates

```bash
./build_iso.py templates
```

What happens:

1. **Preflight** — refuses to run in dom0, checks disk, Docker and the signing
   key, then shows three warnings you must acknowledge by typing `UNDERSTOOD`.
   (`--yes` acknowledges them non-interactively and records that in the build
   log; without a terminal the build stops rather than hanging on a prompt.)
2. **Fetches qubes-builderv2** and builds the container image. Slow, one-off.
3. **Fetches and verifies the Kali archive keyring** against fingerprint
   `827C8569F2518CC677FECA1AED65462EC8D5E4C5`. A mismatch **aborts the build** —
   this key is about to be baked into an image you hand to colleagues, so it does
   not proceed on a guess.
4. **Generates the template component** at
   `~/investigator-iso/qubes-template-investigator`, structured like the upstream
   `qubes-template-kali` component.
5. **Builds five templates**, each a full debootstrap:

| Template | Contents |
|---|---|
| `investigator-kali` | Kali rolling, `kali-linux-default`, Maltego |
| `investigator-office` | LibreOffice, de-CH language, Thunderbird, KeePassXC |
| `investigator-ids` | Suricata, Zeek 8.0 LTS (`zeek-lts`) |
| `investigator-proxy` | Squid with peek/splice, unbound |
| `investigator-wazuh` | Wazuh indexer + server + dashboard |

Every one also gets the Wazuh agent, installed **disabled** and **version-held**.

> **Why disabled?** A template is a shared filesystem. An enabled agent would
> beacon during template updates, and every qube cloned from it would inherit the
> *same* agent identity and collide in the manager instead of appearing as
> separate hosts. The provisioner enables it per qube automatically in phase 11.
> This is correct ordering, not a manual step.

Expect several hours. If a template fails, fix the cause and resume — templates
build independently, and a completed set is skipped rather than rebuilt:

```bash
./build_iso.py templates          # skipped if every RPM is already present
./build_iso.py --force templates  # rebuild them anyway
```

---

## 6. Build the ISO

```bash
./build_iso.py iso
```

1. Reads the real kickstart and comps files from the fetched Qubes sources and
   **derives the stock template names from `comps-dom0.xml`** rather than
   assuming them.
2. Detects whether the comps file has the `@QUBES_TEMPLATES@` marker. On
   `release4.3` it does not, so the custom templates are added to a `%packages`
   section in the generated kickstart instead. The script tells you which path it
   took.
3. Writes `investigator.ks` into `qubes-release/conf/` — beside the kickstart it
   `%include`s, because `%include` resolves relative to the including file — and
   adds a `%post` planting the provisioner into dom0 plus a first-boot service.
4. **Merges** the `iso:`, `cache:` and `sign-key:` settings into `builder.yml`,
   rather than appending a second copy of those keys. YAML keeps only the last
   occurrence of a duplicate key, so appending silently replaced the upstream
   component list and dropped the rpm and deb signing fingerprints. The merge is
   then verified with `qb config get-var templates`.
5. Runs `qb installer init-cache all`.
6. Picks the **newest** image under `artifacts/`, refuses it if it predates this
   run, then checksums, signs and writes `BUILD-RECORD.txt`.

Output in `~/investigator-iso/output/`:

```
InQubestigationOS.iso
InQubestigationOS.iso.sha256
InQubestigationOS.iso.asc         detached signature
unit-signing-key.asc              your public key, for colleagues
verify-iso.sh                     one command for colleagues to run
FINGERPRINT.txt                   the fingerprint, laid out to be read aloud
BUILD-RECORD.txt                  date, tier, templates, hashes, expiry warning
```

---

## 7. Distribute the ISO

Write to USB:

```bash
./build_iso.py write-usb --device /dev/sdX
```

Rather than a `dd` line you have to get right at four in the afternoon, this:

- re-checks the image against its own `.sha256` and verifies the GPG signature
  **before** writing anything — an image that no longer matches the build record
  never reaches the media
- lists removable devices and refuses a fixed disk unless you pass
  `--allow-fixed-disk`, because this command destroys its target
- refuses a device with mounted partitions
- writes, syncs, then **reads the stick back** and compares it byte for byte. A
  stick that writes without error and reads back wrong is a failure you would
  otherwise discover at the install, on someone else's desk

With one removable device plugged in, `--device` can be omitted.

Colleagues verify before installing — one command, shipped beside the image:

```bash
./verify-iso.sh
```

It checks the checksum, imports the key, verifies the signature, and then prints
the fingerprint it verified against so they can compare it with the one you gave
them. By hand it is still:

```bash
sha256sum -c InQubestigationOS.iso.sha256
gpg --import unit-signing-key.asc
gpg --verify InQubestigationOS.iso.asc InQubestigationOS.iso
```

> **The fingerprint must travel separately from the ISO.** A public key shipped
> on the same USB stick as the image it signs proves nothing — anyone who can
> replace the image can replace the key beside it. Read the fingerprint out over
> the phone, or publish it somewhere colleagues already trust. `FINGERPRINT.txt`
> is formatted for exactly that, and `write-usb` reminds you to carry it
> separately. **This is the one step in the whole guide that must stay manual**:
> its entire value is that it does not travel with the image.

---

## 8. Install on a laptop

1. Boot the USB.
2. Install Qubes normally. Accept the defaults. **Enable full-disk encryption**
   with your unit's passphrase policy.
3. Reboot and complete Qubes initial setup — the step that creates `sys-net`,
   `sys-firewall`, `personal`, `work` and so on. The provisioner rewires these,
   so it waits for them to exist.

---

## 9. First boot

Provisioning starts automatically. On a Tier 2 image the templates are already
on disk, so this wires the topology only — minutes, not hours.

Watch it:

```bash
journalctl -t golden-image -f
```

Twelve phases run: preflight, credentials, template clones, payloads, agents,
chain qubes, chain configuration, the SIEM, app qubes, policy and backups,
enrollment, acceptance tests.

If it was deferred or failed, it is safe to run or resume by hand — completed
phases are skipped:

```bash
sudo golden-image-provision              # run or resume
sudo golden-image-provision --dry-run    # see what it would do
sudo golden-image-provision --from-phase 7
```

---

## 10. Verify before issuing

```bash
sudo golden-image-provision --verify
```

Thirteen groups of acceptance tests. **All must pass** before the laptop leaves
your desk — and the command exits non-zero if any fail, so it can gate a script
rather than relying on someone reading the output. Notably:

- Every hop in the chain points where it should
- **No clearnet qube attaches directly to `sys-firewall` or `sys-net`** — this
  walks every qube on the system and fails if anything bypasses the chain
- `vault` and `dvm-offline` have no netvm
- All nine templates carry `/var/ossec`
- Every custom template is Debian-based
- The Kali keyring carries the expected 2025 signing key
- `wazuh-agent` is version-held in every Debian template
- `8.8.8.8` is unreachable from `personal`, but name resolution works
- Suricata, Zeek and Squid are running; the NFQUEUE hook is present
- The backup timer is enabled

**There is no longer a "confirm by hand" list.** Group 13 is exactly that list,
turned into tests that run on the real hardware:

| Was a manual check | Group 13 does |
|---|---|
| `nft list chain ip qubes dnat-dns` and read it | reads the chain and fails if the golden rule is not in it |
| — | reads the `custom-dnat-squid` counters and fails if nothing has been redirected |
| — | runs `squid -k parse` in `sys-proxy` against the peek/splice config |
| `systemctl is-active wazuh-{manager,indexer,dashboard}` | asserts all three |
| — | asserts `qvm-prefs wazuh-srv ip` took the pinned address |
| — | opens the dashboard from `work` over qrexec and fetches from it, proving the `qubes.ConnectTCP` policy and argument order |
| `sudo qvm-backup --profile golden-image` | generates a reference profile with `--save-profile` and compares the key names — no backup is taken |
| Open Tor Browser and look at check.torproject.org | asks `check.torproject.org/api/ip` from `kali-tor` and fails if `IsTor` is false |
| "Also confirm Wi-Fi works" | looks for a wireless interface in `sys-net` and for firmware load failures in its kernel log |

Drivers come from the dom0 kernel but firmware comes from the Debian template,
and that last row is the one place the Debian switch could bite.

---

## 11. Hand over to the investigator

Three commands, in this order — or `sudo golden-image-provision --handover`,
which runs all three behind a single confirmation and stops the chain if any of
them fails:

```bash
sudo golden-image-provision --rotate-credentials
sudo golden-image-provision --escrow-credentials
sudo golden-image-provision --shred-credentials
```

Run them separately if your policy requires the values to reach the unit's
password process before the dom0 copy is destroyed — that is the gap between
steps 2 and 3.

**`--rotate-credentials`** generates four new secrets and applies them: the
manager's enrollment password and every enrolled agent's copy of it, the
dashboard admin password through the Wazuh passwords tool, and the backup
passphrase. If it cannot set the dashboard password it stops before writing
anything, so the old values stay valid rather than the file and the machine
disagreeing. The previous backup passphrase is kept in the file, because the
existing backup sets still need it.

**`--escrow-credentials`** copies the file into `vault` — verifying the copy by
SHA-256, and refusing outright if the target qube has a netvm — and records
where it went.

**`--shred-credentials`** refuses to run without that record, re-verifies the
escrowed copy is still there and still matches, and only then destroys the dom0
copy. It shreds the **build log** too: that log records every command run
against every qube, and leaving it behind was the quiet half of this step.

Copy the escrowed values into your unit's password process as well — a vault
qube is offline, but it is on the same disk as everything else. **Escrow the
backup passphrase especially:** no passphrase, no restore.

Then the dashboard. There is no `qvm-connect-tcp` line to remember: `work` has a
**SIEM dashboard** launcher that opens the qrexec tunnel and the browser.

Finally, label the backup disk once and plug it in:

```bash
sudo mkfs.ext4 -L GOLDEN-BACKUP /dev/sdX1
```

A udev rule and a mount unit in `sys-usb` mount it at `/mnt/backup` whenever it
appears — by label, never by device node, because `/dev/sdb` is whatever was
plugged in last and a backup written to the wrong disk is worse than none.

**Brief the investigator on three rules:**

- **Window colours mean trust.** Never move files from a redder window into a
  blacker one without a reason. `docs/DESIGN.html` has the legend.
- **Evidence opens in a disposable.** Right-click → open in `dvm-offline`. No
  network, destroyed on close, full office suite so anything renders.
- **Two Kali qubes, two exits.** `kali-clear` for scans and active work,
  inspected. `kali-tor` for OSINT where your IP must not appear — but Tor carries
  TCP only, so SYN scans, UDP scans and ICMP will not work there.

---

## 12. Ongoing maintenance

This used to be a table of things to remember. Phase 10 installs it as timers
instead. Nothing below needs a calendar entry or a named owner.

| Cadence | What runs | Where | Unit |
|---|---|---|---|
| Weekly | Template updates; dom0 updates *reported*, never applied unattended | dom0 | `golden-template-update.timer` |
| Weekly | The full acceptance suite, again | dom0 | `golden-selfcheck.timer` |
| Weekly | Encrypted backup, then prune to `backup.keep_sets` | dom0 | `golden-backup.timer` |
| Weekly | `suricata-update` + in-place `reload-rules` | `sys-ids` | `golden-suricata-update.timer` |
| Monthly | **Restore verification** of the newest set | dom0 | `golden-restore-test.timer` |
| Monthly | Zeek OBS, Kali and Wazuh key expiry watch | `sys-dpi` | `golden-key-expiry.timer` |
| Daily | "Is this image too old to install safely?" | dom0 | `golden-staleness.timer` |
| Weekly, in CI | Signing keys, versions and Qubes bulletins vs upstream | build host | `check-upstream` |

**Failures are not silent.** Each of these writes to the journal under
`golden-image` and raises a banner in `/etc/motd.d/`, so the next person to log
in sees it. Watch them with:

```bash
systemctl list-timers 'golden-*'
journalctl -t golden-image --since '1 week ago'
```

**Rebuilding is still yours to decide, but not yours to notice.**
`./build_iso.py check-upstream` on the build host lists every Qubes Security
Bulletin published since the recorded baseline and tells you which of them touch
dom0, Xen or the kernel. Those are the ones that mean rebuild and re-cut the ISO.
CI runs it every Monday and fails when they appear.

**Upgrade order for Wazuh** — manager first, then release the holds and upgrade
the agents; an agent newer than the manager is unsupported and stops reporting.
You no longer have to remember which way round that is:

```bash
sudo golden-image-provision --upgrade-wazuh
```

It upgrades `wazuh-srv`, reads back the version it actually reached, refuses to
touch a single agent if it cannot, then upgrades and re-pins every template — and
writes that version into `golden-image.json`, so the next provisioning run
installs the same thing rather than re-pinning to the old one. Commit that
change: the golden image is the git tag, not any one laptop.

**Signing keys expire, and Zeek's documentation says you must re-add theirs by
hand when it does.** The expiry watch tells you when; this is what it tells you
to run:

```bash
sudo golden-image-provision --refresh-repo-keys
```

It re-fetches the Zeek, Kali and Wazuh keys into the templates that use them and
re-verifies each against its pinned fingerprint, keeping the old key in place if
the new one does not match — a failed refresh must not leave a template unable to
update at all.

**Kali key rolls happen.** April 2025 broke `apt update` for every Kali system
worldwide. `check-upstream` catches the next one the Monday after it happens, and
cross-checks the key against an independent keyserver rather than trusting the
announcement alone. Confirm the new fingerprint at kali.org, then:

```bash
./build_iso.py --set kali.key_fpr=<new fingerprint>
sudo golden-image-provision --refresh-repo-keys
```

**The verification stamp maintains itself.** `supply-chain.lock.json` records
what upstream offered at the last check; `check-upstream --update` moves the
baseline forward and `tests/doc_checks.py` fails CI if the fingerprints in the
docs and the two scripts ever disagree.

---

## 13. Troubleshooting

**`build_iso.py` says it is running in dom0.** It is not meant to. Use a separate
build host. Only `golden_image.py` runs in dom0.

**Docker needs sudo.** `./build_iso.py setup-host` — it adds you to the group and
tells you how to run this session's build through `sg` rather than logging out.

**Kali fingerprint mismatch aborts the build.** Either Kali rolled the key —
check kali.org/blog, confirm the new fingerprint, update `kali.key_fpr` — or the
download was tampered with. Do not bypass this check.

**A template fails to build.** Templates build independently. Fix the cause and
re-run `./build_iso.py templates`; completed ones are skipped.

**`templates:` or `components:` appear twice in builder.yml.** They should not:
the script now loads the YAML, merges its entries into the existing lists and
mappings, writes a timestamped backup, and verifies the result with
`qb config get-var templates`. If you see a duplicate, it came from somewhere
else. (This needs `python3-yaml`, which `setup-host` installs; without it the
script refuses to edit builder.yml rather than appending a block that would
silently drop the upstream component list and the rpm/deb signing keys.)

**Provisioning was deferred at first boot.** The runner waits up to 30 minutes
for `sys-net` and `sys-firewall`, then writes a notice to the MOTD rather than
provisioning a half-built system. Complete Qubes initial setup, then
`sudo golden-image-provision`.

**An acceptance test fails.** Do not issue the laptop. The build log is at
`~/golden-image/build.log` (mode 600 — it records every command run against
every qube, with generated secrets redacted). Fix, then re-run `--verify`, which
exits non-zero while anything is still failing.

**A weekly self-check failed after the laptop was issued.** The login banner and
`journalctl -t golden-image` say which group. `sudo golden-image-provision
--verify` reproduces it. Something drifted — most often a netvm reassigned by
hand — and the machine is out of compliance with its own design until it passes.

**No network in a qube after provisioning.** Check its netvm is `sys-proxy`, and
that Suricata is running in `sys-ids` — the IPS is **fail-closed** by design, so
a dead Suricata stops the inspected chain rather than passing traffic
uninspected. `systemctl status suricata-nfqueue` in `sys-ids`.

**DNS resolves but goes to the wrong resolver.** Confirm the `dnat-dns` chain
survived the reboot (section 10, check 1). This is the failure mode that used to
be silent; see `docs/REVIEW.md` defect 3.
