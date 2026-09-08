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

| Requirement | Why |
|---|---|
| Debian 13 or Fedora | qubes-builderv2 ships dependency lists for both |
| Docker, usable without `sudo` | Build cages. Podman cannot currently build DEB packages |
| ~250 GB free disk | Five templates plus the ISO. Tier 1 needs ~100 GB |
| 8 GB RAM minimum | Builds are slow and can OOM below this |
| Several hours | The Kali template dominates |

**A target laptop** with VT-x and VT-d/IOMMU, 32 GB RAM comfortable (16 GB
workable), 512 GB SSD minimum. Check it against the Qubes Hardware
Compatibility List before committing.

**A GPG key** for signing. Section 3 covers creating one.

**A spare machine to test on.** Do not let the first install be on hardware you
intend to issue.

---

## 2. Prepare the build host

```bash
# Docker, and your user in its group
sudo apt install docker.io git curl gnupg
sudo usermod -aG docker "$USER"
```

Log out and back in — group membership does not apply to an existing session.
Confirm:

```bash
docker ps        # must work WITHOUT sudo
```

If the build host is a Qubes app qube rather than a normal machine, also add
`/var/lib/docker` to its bind-dirs, or the image is lost on every reboot.

Clone the repository:

```bash
git clone <your-internal-url>/InQubestigationOS.git
cd InQubestigationOS
```

---

## 3. Create the signing key

Skip if your unit already has an image-signing key.

```bash
gpg --quick-generate-key "Kapo Cyber Image Signing <cyber@example.ch>" \
    rsa4096 sign 3y
gpg --fingerprint
```

Copy the 40-character fingerprint. Three-year expiry is deliberate: an
image-signing key should outlive a build cycle but not outlive the team.

> **Never put private key material in a config file or this repository.** Only
> the fingerprint goes in `iso-build.json`. The private key stays in the build
> host's keyring. The build script refuses to start if it finds a key block, and
> validates the fingerprint format before anything else runs.
> Details in [SIGNING.md](SIGNING.md).

---

## 4. Configure the build

```bash
./build_iso.py --write-config
$EDITOR iso-build.json
```

The settings that matter:

| Key | Set it to |
|---|---|
| `iso_sign_key` | Your 40-hex fingerprint from step 3 |
| `tier` | `2` (default) — templates baked in, installs with no network |
| `qubes_release` | `r4.3` |
| `mock_config` | Must match the host distribution of your Qubes release |
| `work_dir` | Somewhere with 250 GB free |
| `auto_provision` | `true` — first boot configures itself |

Everything else has a working default. Read the comments; the file documents
itself.

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
| `investigator-ids` | Suricata, Zeek 8.0 LTS |
| `investigator-proxy` | Squid with peek/splice, unbound |
| `investigator-wazuh` | Wazuh indexer + server + dashboard |

Every one also gets the Wazuh agent, installed **disabled** and **version-held**.

> **Why disabled?** A template is a shared filesystem. An enabled agent would
> beacon during template updates, and every qube cloned from it would inherit the
> *same* agent identity and collide in the manager instead of appearing as
> separate hosts. The provisioner enables it per qube automatically in phase 11.
> This is correct ordering, not a manual step.

Expect several hours. If a template fails, fix the cause and resume — templates
build independently:

```bash
./build_iso.py templates          # completed phases are skipped
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
3. Writes `investigator.ks`, which `%include`s the stock Qubes kickstart and adds
   a `%post` planting the provisioner into dom0 plus a first-boot service.
4. Runs `qb installer init-cache all`.
5. Renames, checksums, signs, and writes `BUILD-RECORD.txt`.

Output in `~/investigator-iso/output/`:

```
InQubestigationOS.iso
InQubestigationOS.iso.sha256
InQubestigationOS.iso.asc         detached signature
unit-signing-key.asc              your public key, for colleagues
BUILD-RECORD.txt                  date, tier, templates, hashes, expiry warning
```

---

## 7. Distribute the ISO

Write to USB:

```bash
sudo dd if=~/investigator-iso/output/InQubestigationOS.iso \
        of=/dev/sdX bs=4M status=progress oflag=direct
```

Colleagues verify before installing:

```bash
sha256sum -c InQubestigationOS.iso.sha256
gpg --import unit-signing-key.asc
gpg --verify InQubestigationOS.iso.asc InQubestigationOS.iso
```

> **The fingerprint must travel separately from the ISO.** A public key shipped
> on the same USB stick as the image it signs proves nothing — anyone who can
> replace the image can replace the key beside it. Read the fingerprint out over
> the phone, or publish it somewhere colleagues already trust.

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

Eleven groups of acceptance tests. **All must pass** before the laptop leaves
your desk. Notably:

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

Then confirm by hand the four things the tests cannot check:

```bash
# 1. DNS enforcement survived the reboot — the highest-value check
qvm-run -u root sys-firewall 'nft list chain ip qubes dnat-dns'
#    must show the golden-image rule, not the default nameservers

# 2. The SIEM is actually up
qvm-run -u root wazuh-srv \
  'systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard'

# 3. The backup profile schema is accepted
sudo qvm-backup --profile golden-image

# 4. Tor works — open Tor Browser in kali-tor, visit check.torproject.org
```

Also confirm Wi-Fi works. Drivers come from the dom0 kernel but firmware comes
from the Debian template, and this is the one place the Debian switch could bite.

---

## 11. Hand over to the investigator

1. Read `~/golden-image/credentials.json` — four secrets generated for **this**
   machine. Rotation procedures are in `CREDENTIALS-README.txt` beside it.
2. Open the dashboard from `work`:
   ```bash
   qvm-connect-tcp 8443:wazuh-srv:443
   # then browse https://localhost:8443
   ```
3. Change all four secrets.
4. Escrow the new values in your unit's password process. **Escrow the backup
   passphrase especially** — no passphrase, no restore.
5. Shred the file:
   ```bash
   shred -u ~/golden-image/credentials.json
   ```
6. Attach the backup disk to `sys-usb` and mount it at `/mnt/backup`.

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

| Cadence | Action | Where |
|---|---|---|
| On notification | dom0 updates, Qubes Security Bulletins | dom0 |
| Weekly | Template updates (all nine) | Qubes Update |
| Weekly | `suricata-update` + `suricatasc -c reload-rules` | `sys-ids` |
| Weekly, automatic | Encrypted backup | dom0 timer |
| Monthly | **Restore verification** — calendared, named owner | dom0 |
| Monthly | Check the Zeek OBS key has not expired | `tpl-ids` |
| Per QSB affecting dom0 or Xen | **Rebuild and re-cut the ISO** | Build host |

**Upgrade order for Wazuh:** `wazuh-srv` first, then release the template holds
and upgrade the agents. Never the reverse — an agent newer than the manager is
unsupported and stops reporting.

**Kali key rolls happen.** April 2025 broke `apt update` for every Kali system
worldwide. When it recurs, confirm the new fingerprint at kali.org, update
`kali.key_fpr`, rebuild.

**Update the verification date.** `docs/VERIFICATION.md` has a revision log. The
"verified 2026-09-01" stamp is load-bearing — when Kali rolls a key or Wazuh
ships a new release, this repository becomes subtly wrong in ways that still look
authoritative.

---

## 13. Troubleshooting

**`build_iso.py` says it is running in dom0.** It is not meant to. Use a separate
build host. Only `golden_image.py` runs in dom0.

**Docker needs sudo.** `sudo usermod -aG docker $USER`, then log out and back in.

**Kali fingerprint mismatch aborts the build.** Either Kali rolled the key —
check kali.org/blog, confirm the new fingerprint, update `kali.key_fpr` — or the
download was tampered with. Do not bypass this check.

**A template fails to build.** Templates build independently. Fix the cause and
re-run `./build_iso.py templates`; completed ones are skipped.

**`templates:` or `components:` appear twice in builder.yml.** YAML keeps only
the last occurrence of a duplicate key. Merge them by hand — the script will not
silently rewrite arbitrary YAML for you. Check with
`./qb config get-var templates`.

**Provisioning was deferred at first boot.** The runner waits up to 30 minutes
for `sys-net` and `sys-firewall`, then writes a notice to the MOTD rather than
provisioning a half-built system. Complete Qubes initial setup, then
`sudo golden-image-provision`.

**An acceptance test fails.** Do not issue the laptop. The build log is at
`~/golden-image/build.log`; every command and its output is there. Fix, then
re-run `--verify`.

**No network in a qube after provisioning.** Check its netvm is `sys-proxy`, and
that Suricata is running in `sys-ids` — the IPS is **fail-closed** by design, so
a dead Suricata stops the inspected chain rather than passing traffic
uninspected. `systemctl status suricata-nfqueue` in `sys-ids`.

**DNS resolves but goes to the wrong resolver.** Confirm the `dnat-dns` chain
survived the reboot (section 10, check 1). This is the failure mode that used to
be silent; see `docs/REVIEW.md` defect 3.
