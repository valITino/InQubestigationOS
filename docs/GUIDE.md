# InQubestigationOS — the guide

From an empty Linux machine to an investigator laptop that is ready to issue.
Read [section 0](#0-the-big-picture) first. It shows the whole journey on
one screen. Then follow the parts in order.

**Contents**

0. [The big picture](#0-the-big-picture): what happens where, which path is
   yours, and the words this guide uses
1. [Prepare the build host](#1-prepare-the-build-host)
2. [Build and sign the image](#2-build-and-sign-the-image)
3. [Put it on a USB stick](#3-put-it-on-a-usb-stick)
4. [Install on the laptop](#4-install-on-the-laptop)
5. [First boot](#5-first-boot)
6. [Verify and hand over](#6-verify-and-hand-over)
7. [Living with it: maintenance](#7-living-with-it-maintenance)
8. [Command cheat sheet](#8-command-cheat-sheet)
9. [Troubleshooting](#9-troubleshooting)
- [Appendix A — Build host details](#appendix-a--build-host-details): Linux
  distributions, VMs, Windows
- [Appendix B — What the build does inside](#appendix-b--what-the-build-does-inside)

---

## 0. The big picture

Three places are involved, and each command belongs to exactly one of them:

```
 ┌─────────────────────────┐      ┌──────────────┐      ┌──────────────────────────────┐
 │ BUILD HOST              │      │ USB STICK    │      │ LAPTOP  (Qubes OS, dom0)     │
 │ any x86-64 Linux        │ ───▶ │ image +      │ ───▶ │ installs, then configures    │
 │ runs  ./build_iso.py    │      │ answer file  │      │ itself on first boot         │
 │                         │      │              │      │ runs  golden-image-provision │
 │ Parts 1–3               │      │ Part 3       │      │ Parts 4–7                    │
 └─────────────────────────┘      └──────────────┘      └──────────────────────────────┘
```

| Part | Where | You do | Takes |
|---|---|---|---|
| 1 Prepare | build host | `./build_iso.py doctor`, then `setup-host` if something is missing | 10 min |
| 2 Build | build host | `./build_iso.py quickstart --usb`, which asks for one passphrase | a few hours, unattended |
| 3 USB stick | build host | plug in a stick, and `quickstart --usb` writes it | 10–20 min |
| 4 Install | laptop | boot the stick and enter the disk-encryption passphrase | 20–40 min |
| 5 First boot | laptop | nothing: it configures itself | 1–3 h (tier 1) |
| 6 Verify and hand over | laptop | `--verify`, `--handover`, `--issue` | 15 min |
| 7 Maintenance | laptop | nothing routine: timers do it | — |

### Which path is yours?

| You want to… | Do this |
|---|---|
| Build a stick for a test machine | [Part 1](#1-prepare-the-build-host), then `./build_iso.py quickstart --usb` |
| Publish the image on GitHub for others to download | Build as above, then [3.2 Publish a download](#32-publish-a-download-github-releases) |
| Install from a release you downloaded | Skip Parts 1–2 and go to [3.3 From a downloaded release](#33-from-a-downloaded-release) |
| Make a production release for your unit | `./build_iso.py bootstrap`, see [2.5](#25-production-path-bootstrap) |
| Wire an **unwired** machine yourself | [WORKSTATION-GUIDE.md](WORKSTATION-GUIDE.md), which is also on every installed machine |

### Words used in this guide

| Word | Means |
|---|---|
| **Build host** | The Linux machine or VM that builds the image. It is *not* the laptop, and not dom0. |
| **Image / ISO** | `InQubestigationOS.iso`: a Qubes OS 4.3 installer carrying this project's additions. |
| **Signing key, fingerprint** | Your GPG key signs the image. Its **fingerprint** (40 hex characters) is how others check the signature. The fingerprint is public; the key and its passphrase are never shared. |
| **Kickstart** | The installer's answer file (`ks.cfg`). It carries the setup code that runs on the laptop. It is signed separately from the image. |
| **`QUBES_OEM` partition** | A small partition that `write-usb` adds to the stick. The installer finds the kickstart there. A stick without it is a plain Qubes installer. |
| **Edition** | Chosen per stick. **wired** (the default) builds the templates and the whole network design, then tests it. **unwired** builds the templates only and leaves the wiring to you. One build serves both. |
| **Tier** | **1** (the default): the image carries stock templates, and the investigator templates are built on the laptop at first boot, which needs network. **2**: the templates are built into the image. Implemented, but not yet built end to end. |
| **dom0** | Qubes' administrative VM on the laptop. The provisioner runs there. |
| **Template, qube** | A template is a base system. A qube is a VM that uses one. This design's templates are called `tpl-*` (`tpl-kali`, `tpl-ids` …), and its qubes `sys-proxy`, `kali-tor` and so on. |
| **Provisioner** | `golden_image.py`, installed on the laptop as `golden-image-provision`. It runs twelve **phases** that build and wire everything. |
| **`work_dir`** | Where the build puts its files (default `~/investigator-iso`). Needs ~100 GB free. |
| **Config files** | `iso-build.json` on the build host, beside `build_iso.py`: change it with `./build_iso.py --set`. `golden-image.json` on the laptop, in `/usr/local/sbin/`: edit it as root, since the provisioner has no `--set`. Both are written with defaults on first run. |

---

## 1. Prepare the build host

> **Where:** build host · **Time:** about 10 minutes

### 1.1 What you need

| | Minimum | Notes |
|---|---|---|
| Linux, x86-64 | Debian 13, Kali, Ubuntu 22.04+ or Fedora 43+ | A VM is fine. ARM (Apple Silicon) cannot build. Windows: use a Linux VM, see [Appendix A](#appendix-a--build-host-details). |
| Free disk | ~100 GB (tier 2: ~250 GB) | Put `work_dir` on a big disk if your home is small. |
| RAM / CPU | 8 GB / 2 cores | 16 GB and 4 cores make it noticeably faster. |
| Time | a few hours | It runs unattended after one passphrase. |
| A USB stick | 16 GB or more | Its contents will be erased. |
| A spare laptop to test on | VT-x, VT-d/IOMMU, 16 GB RAM (32 comfortable), 512 GB SSD | Check it against the Qubes Hardware Compatibility List. Never make the first install on a machine you intend to issue. |

### 1.2 Get the code

```bash
git clone <your-internal-url>/InQubestigationOS.git
cd InQubestigationOS
```

Clone **as your normal user**, into a directory you own, and never run the
scripts with `sudo`. The build writes `iso-build.json` next to `build_iso.py`,
and a clone made with `sudo` belongs to root.

### 1.3 Check the host, and let it fix itself

```bash
./build_iso.py doctor         # checks everything, changes nothing
./build_iso.py setup-host     # installs what is missing (shows the plan, asks once)
```

`doctor` prints one line per requirement and, for anything missing, the command
that fixes it. `setup-host` installs the packages, enables Docker, and adds you
to its group. It shows every command before running any.

If `work_dir` is on a disk that is too small, point it elsewhere:

```bash
./build_iso.py --set work_dir=/mnt/build/investigator-iso
```

Docker group membership does not reach a shell that is already open.
`setup-host` tells you how to continue without logging out
(`sg docker -c './build_iso.py all'`). `quickstart` handles this for you.

---

## 2. Build and sign the image

> **Where:** build host · **Time:** a few hours, unattended after one passphrase

### 2.1 The one command

```bash
./build_iso.py quickstart --usb
```

What it does, in order:

1. **Checks** the host and fixes what it can (`doctor`, then `setup-host`).
   Anything that can fail fast fails here, in seconds rather than hours in.
2. **Creates or reuses your signing key**, and asks for its passphrase. This is
   the only question it asks.
3. **Backs up the key** beside the build. Copy that backup to removable media
   before you ship anything signed with the key.
4. **Checks the supply chain** (`check-upstream`): the pinned Kali, Zeek and
   Wazuh keys and versions against upstream.
5. **Builds and signs the image.** This is the long part.
6. **Waits for a USB stick and writes it** (because of `--usb`). See Part 3.

If it stops, fix the cause and run it again: the steps that already succeeded
are skipped. The image build itself runs again every time, so if **only the USB
step** failed, run `./build_iso.py write-usb --wait` instead.

`--usb` is optional. Without it, `quickstart` builds and signs the image and
stops, and you write the stick later with `write-usb` (Part 3). With it, you
can plug the stick in at any time, even before the build starts. A stick that
is already there is used, as long as it is the only one.

| Add | Effect |
|---|---|
| `--yes` | Also skips the "write to /dev/sdX?" confirmation |
| `--no-passphrase` | A throwaway lab build that asks nothing, with an unprotected key |
| `--edition unwired` | The stick installs the unwired edition |

### 2.2 Choose before you build (optional)

Nothing has to be edited: the defaults build a working image. Settings are
changed by name. A typo is rejected, not ignored.

```bash
./build_iso.py --set work_dir=/srv/build   # change one
./build_iso.py --get tier                  # read one
./build_iso.py config                      # print them all
```

| Setting | Default | Change it when |
|---|---|---|
| `work_dir` | `~/investigator-iso` | your home disk has less than ~100 GB free |
| `edition` | `wired` | you want `unwired` sticks by default (you can also pick per stick) |
| `tier` | `1` | you want the templates inside the image (`2`, not yet built end to end) |
| `install.unattended` + `install.disk` | off | you want an install with no clicking, see [Part 4](#4-install-on-the-laptop) |
| `auto_provision` | `true` | you do not want first boot to configure the machine |
| `provisioner_config` | empty | you want to ship a reviewed, non-secret `golden-image.json` with the image |
| `iso_sign_key` | set by `gen-key` | never by hand |

### 2.3 What you get

In `<work_dir>/output/` (by default `~/investigator-iso/output/`):

| File | What it is |
|---|---|
| `InQubestigationOS.iso` | the image |
| `InQubestigationOS.iso.sha256`, `InQubestigationOS.iso.asc` | its checksum and signature |
| `oem/editions/wired/ks.cfg`, `oem/editions/unwired/ks.cfg` (each with `.asc`) | the signed installer answer file for each edition |
| `oem/ks.cfg` (+ `.asc`) | a copy of the configured default edition |
| `unit-signing-key.asc` | your public key, for colleagues |
| `verify-iso.sh`, `verify-iso.ps1` | one command for colleagues to verify the image (Linux, Windows) |
| `FINGERPRINT.txt` | your fingerprint, laid out to be read aloud |
| `BUILD-RECORD.txt` | date, tier, templates, hashes, and a staleness warning |

### 2.4 The same steps one at a time

`quickstart` chains these. Run them yourself when you want to see or repeat
one step:

```bash
./build_iso.py gen-key --uid "Kapo Cyber Image Signing <cyber@example.ch>"  # new key (rsa4096, 3 years)
./build_iso.py gen-key --use-key auto          # or adopt the one key already in your keyring
./build_iso.py backup-key --to /media/usb/keys # back the key up to removable media
./build_iso.py check-upstream                  # upstream keys and versions still match?
./build_iso.py --dry-run all                   # print the whole plan, change nothing
./build_iso.py templates                       # tier 2 only: build the templates
./build_iso.py iso                             # build, checksum and sign the image
```

> **Never put private key material in a config file or in this repository.**
> Only the fingerprint goes into `iso-build.json`. The build refuses to start if
> it finds a key block. Details: [SIGNING.md](SIGNING.md).

What `templates` and `iso` do internally is in
[Appendix B](#appendix-b--what-the-build-does-inside).

### 2.5 Production path: `bootstrap`

`quickstart` keeps the key backup on the build host, which is fine for testing.
For an image you will issue, use `bootstrap`. It **requires** a separate
backup medium and an export destination before it builds anything, and it
verifies the export by reading it back:

```bash
sudo mount LABEL=IMAGE-KEY-BACKUP /mnt/image-key-backup   # the backup medium, mounted
install -m 600 /dev/null /run/user/$UID/inqubestigation-gpg.pass
read -rsp 'Signing/backup passphrase: ' P; printf '%s' "$P" > /run/user/$UID/inqubestigation-gpg.pass; unset P; echo
sudo -v
./build_iso.py bootstrap --yes \
  --uid "Kapo Cyber Image Signing <cyber@example.ch>" --expire 3y \
  --passphrase-file /run/user/$UID/inqubestigation-gpg.pass \
  --to /mnt/image-key-backup/inqubestigation
```

The key **backup** is encrypted with a second, separate passphrase. On a
terminal, bootstrap asks for it. Unattended, supply it the same way as the first
one, in its own protected file, with `--backup-passphrase-file`.

For a repeat build, run the same command with the same medium mounted. It
reuses the key already pinned in `iso-build.json` and never creates a second
one. Delete the passphrase files afterwards. The full contract, including the
guided first run that needs none of the above typed by hand, is in
[BOOTSTRAP.md](BOOTSTRAP.md).

---

## 3. Put it on a USB stick

> **Where:** a Linux machine: the build host, or any Linux for a downloaded release · **Time:** 10–20 minutes

> **The fingerprint travels separately. Always.** A public key on the same stick
> or download as the image proves nothing: whoever can swap the image can swap
> the key. The fingerprint is published in
> [SIGNING-KEY.md](../SIGNING-KEY.md) in this repository's root, and every
> release points there. Name a second place on that page too (an intranet
> page, the phone). **The signing passphrase is never shared with anyone.**

### 3.1 From your own build

`quickstart --usb` already did this. To write another stick:

```bash
./build_iso.py write-usb --wait                      # uses the stick plugged in, or waits for one
./build_iso.py write-usb --device /dev/sdX --edition unwired
```

Before touching the stick, it checks the image's checksum and signature, and
the signature of the chosen edition's kickstart. It only writes to USB or
removable media (never an internal disk), and never to a mounted device. After writing, it **reads the stick back** and compares it.
It adds the `QUBES_OEM` partition with the kickstart. With one stick plugged
in, `--device` can be left out.

Colleagues verify an image with one command: `./verify-iso.sh <fingerprint>`.

### 3.2 Publish a download (GitHub Releases)

GitHub rejects files of 2 GiB or more. `package-release` re-verifies the build
and turns it into files GitHub accepts:

```bash
./build_iso.py package-release                  # into <work_dir>/release/InQubestigationOS-<YYYYMMDD>/
./build_iso.py package-release --to /mnt/big    # somewhere else
```

It writes:

| File | What it is |
|---|---|
| `InQubestigationOS.iso.part01`, `.part02`, … | the image, split into parts under 2 GiB |
| `InQubestigationOS-<YYYYMMDD>-kit.tar.gz` | `make-usb.sh`, the checksum and signature, both editions' signed kickstarts, the verification scripts |
| `unit-signing-key.asc` | your public key |
| `SHA256SUMS`, `SHA256SUMS.asc` | checksums of every file, signed |
| `README.txt` | the downloader's instructions: paste it as the release notes |

**The first time**, `package-release` also writes your fingerprint into
[SIGNING-KEY.md](../SIGNING-KEY.md) in the repository root. Commit and push
that file **before** you publish the release, because the release's README
tells downloaders to check against it:

```bash
git add SIGNING-KEY.md && git commit -m "Publish the image signing key fingerprint" && git push
```

From then on it refuses to package a release signed by any other key. A new
key is a deliberate edit of that file.

Also publish the key somewhere outside GitHub, so that one compromised account
cannot change every copy. keys.openpgp.org is free and takes one command. It
then emails the address in the key once to confirm it:

```bash
gpg --keyserver hkps://keys.openpgp.org --send-keys <your fingerprint>
```

Then list it under "Also published at" in `SIGNING-KEY.md`.

Create **one** release and upload every file in that folder as its assets.
Nothing secret is in it: the kit is built from an allowlist, so the key backup
and `iso-build.json` never go in. Signing `SHA256SUMS` asks for your passphrase
on *your* machine. Downloaders never need it.

### 3.3 From a downloaded release

On Linux, with `python3`, `gnupg`, `gdisk` and `dosfstools` installed. Take
the fingerprint from [SIGNING-KEY.md](../SIGNING-KEY.md) in the repository,
**not** from the download:

```bash
# all release files in one folder, then:
gpg --import unit-signing-key.asc
gpg --verify SHA256SUMS.asc SHA256SUMS      # "Good signature", with the fingerprint you were given
sha256sum -c SHA256SUMS                     # every line: OK
tar xzf InQubestigationOS-<YYYYMMDD>-kit.tar.gz
./make-usb.sh --fingerprint <that fingerprint> --edition wired    # or unwired
```

`make-usb.sh` joins the parts and then runs the same checks as `write-usb`
(3.1) against the fingerprint you gave it. Add `--device /dev/sdX` if more than
one stick is plugged in.

### 3.4 From Windows

Windows tools write a **plain Qubes installer**: the image boots, but nothing
configures the machine. Only `write-usb` and `make-usb.sh`, both on Linux, add the
`QUBES_OEM` partition. So use a Linux VM and pass the stick through to it. In
VirtualBox that means Settings → USB → **USB 3.0 (xHCI)**.

If you still want a plain stick from Windows:

1. **From a downloaded release only:** extract the kit archive (it contains
   `verify-iso.ps1`), then join the parts in order into one file, for example
   `cmd /c copy /b InQubestigationOS.iso.part01+InQubestigationOS.iso.part02 InQubestigationOS.iso`
   with every part listed. A build's own `output/` folder already has the
   whole image and the script.
2. Verify with `.\verify-iso.ps1 <fingerprint>` (needs Gpg4win).
3. Write it with Rufus in **DD Image mode**, because ISO mode breaks the boot.
   Choose "Install Qubes OS" at boot.

---

## 4. Install on the laptop

> **Where:** the laptop · **Time:** 20–40 minutes

**Normal install (the default):**

1. Boot the stick.
2. Install Qubes as usual and accept the defaults. **Enable disk encryption**
   with your unit's passphrase policy.
3. Reboot and complete Qubes' initial setup, which creates `sys-net`,
   `sys-firewall` and the rest. First boot (Part 5) waits for these to exist.

**Unattended install (optional, set before building):** the installer then
asks only for the disk-encryption passphrase, which stays human on purpose.
Find the laptop's disk identity **on the laptop**, then set both values in
**one** command:

```bash
# 1. On the laptop (from any live system): pick the internal disk
ls -l /dev/disk/by-id/ | grep -v part
```

```bash
# 2. On the build host, then build (Part 2) and write the stick (Part 3)
./build_iso.py --set install.unattended=true \
  --set install.disk=/dev/disk/by-id/nvme-SAMSUNG_MZVL2512HCJQ_S64ANS0T123456
```

- Only `/dev/disk/by-id/...` is accepted. `/dev/nvme0n1`-style names change
  between machines, and this setting erases the disk.
- At install time the stick checks that this identity matches exactly one whole
  disk, and stops before partitioning if it does not. There is no "pick any
  disk" fallback. Machines with different disks need different builds.
- Qubes' initial setup then runs by itself (`install.auto_initial_setup`, on by
  default).

---

## 5. First boot

> **Where:** the laptop · **Time:** tier 1: 1–3 hours, needs network (both editions)

Nothing to do: the machine configures itself, with nobody at the keyboard.
Watch it if you like:

```bash
journalctl -t golden-image -f
```

Each phase logs its progress, for example
`phase 4 (4/12, 25% done): install template payloads`. The run ends with
`provisioning run finished in … (wired edition)`.

| # | Phase | Unwired runs it |
|---|---|---|
| 1 | preflight checks | yes |
| 2 | credentials (four per-machine secrets) | — |
| 3 | clone templates | yes |
| 4 | install template payloads | yes |
| 5 | Wazuh agent in every template | yes |
| 6 | build inspection chain qubes | — |
| 7 | configure inspection chain (and its two in-qube timers) | — |
| 8 | Wazuh manager (the SIEM) | — |
| 9 | app qubes and netvm assignment | — |
| 10 | dom0 policy, segmentation, backup (and the dom0 timers) | — |
| 11 | agent enrollment | — |
| 12 | acceptance tests | — |

**One question comes up at the console:** the `investigator` login password.
It waits 90 seconds and then carries on without it, because provisioning never
depends on it. Unanswered, it is asked again at the next boot and every 30
minutes. `sudo golden-image-firstboot` asks it right away.

**If it stopped or was deferred**, resume by hand. Completed phases are
skipped:

```bash
sudo golden-image-provision              # run or resume
sudo golden-image-provision --dry-run    # show what it would do
sudo golden-image-provision --from-phase 7
```

**An unwired machine can be wired later**, at any time. From then on it counts
as wired. There is no way back short of reinstalling:

```bash
sudo golden-image-provision --edition wired
```

First boot runs the offline checks only. Checks that need the internet (DNS,
Tor exit) are recorded as `PENDING ONLINE`, never as passed. Run `--verify`
(Part 6) once the machine is on its network.

---

## 6. Verify and hand over

> **Where:** the laptop, in dom0 · **Time:** about 15 minutes

### 6.1 Verify

```bash
sudo golden-image-provision --verify
```

**Everything must pass before the laptop leaves your desk.** The command exits
non-zero on any failure, so a script can gate on it.

- **Wired:** fourteen groups of acceptance tests (0–13). Among them:
  - every hop of the chain points where it should;
  - no clearnet qube bypasses it;
  - `vault` and `dvm-offline` have no network;
  - every template carries the disabled Wazuh agent;
  - `8.8.8.8` is unreachable from `personal`, but DNS works;
  - Suricata, Zeek and Squid run;
  - the SIEM answers, and Tor really exits through Tor;
  - Wi-Fi firmware loaded.
- **Unwired:** the templates only. Each exists, carries its payload and the
  disabled agent, and the Kali keyring and Zeek are in place.

### 6.2 Hand over the credentials (wired only)

The wired edition generated four per-machine secrets into
`~/golden-image/credentials.json`: the dashboard, API and enrollment passwords,
and the backup passphrase. One command rotates them, copies them into the
offline `vault` qube (verified), and then destroys the dom0 copy and the build
log:

```bash
sudo golden-image-provision --handover
```

Or run the three steps separately, if your policy needs the values in the
unit's password process *before* the dom0 copy is destroyed:

```bash
sudo golden-image-provision --rotate-credentials
sudo golden-image-provision --escrow-credentials
sudo golden-image-provision --shred-credentials
```

**Copy the backup passphrase into your unit's password process as well.
Without it, no restore.** The unwired edition has no credentials, and these
commands say so.

### 6.3 Prepare the backup disk

Attach the disk to `sys-usb`, then:

```bash
sudo golden-image-provision --prepare-backup-media
```

It refuses non-removable disks, asks you to type `ERASE`, then formats and
labels it `GOLDEN-BACKUP`. From then on it mounts itself by that label, never
by device name.

### 6.4 Record the release

```bash
sudo golden-image-provision --issue --operator "Your Name"
```

It re-runs the tests, refuses if anything fails *or* if the credentials file is
still there, and writes a release record (`/var/lib/golden-image/issuance`):
version, host, results, and who released it.

### 6.5 Brief the investigator: three rules

- **Window colours mean trust.** Never move files from a redder window into a
  blacker one without a reason. [DESIGN.html](DESIGN.html) has the legend.
- **Evidence opens in a disposable.** Right-click, then open in `dvm-offline`:
  no network, destroyed on close.
- **Two Kali qubes, two exits.** `kali-clear` for scans and active work, which
  is inspected. `kali-tor` for OSINT where your IP must not appear. Tor carries
  TCP only, so SYN scans, UDP and ICMP do not work there.

The SIEM dashboard opens from the **SIEM dashboard** launcher in `work`.

---

## 7. Living with it: maintenance

> **Where:** the laptop runs itself · the build host decides when to rebuild

On the wired edition, routine upkeep is installed as timers. Nothing needs a
calendar entry. The unwired edition installs none.

| Timer | When | Does | Runs in |
|---|---|---|---|
| `golden-template-update` | weekly | updates templates; dom0 updates are *reported*, never applied unattended | dom0 |
| `golden-backup` | weekly | encrypted backup, then prunes old sets | dom0 |
| `golden-selfcheck` | weekly | the full acceptance suite again | dom0 |
| `golden-key-refresh` | weekly | renews a repository key near expiry, only if it matches the pinned fingerprint | dom0 |
| `golden-restore-test` | monthly | checks the newest backup archive's integrity (not a full restore) | dom0 |
| `golden-staleness` | daily | warns when the installed image is too old | dom0 |
| `golden-suricata-update` | weekly | refreshes IPS rules, reloads in place | `sys-ids` |
| `golden-key-expiry` | weekly | watches the Zeek, Kali and Wazuh key expiry | `sys-dpi` |

**Failures are not silent.** Every failure goes to the journal and shows as a
banner at the next login. One command answers "how is this machine?":

```bash
sudo golden-image-provision --status
```

**Occasional tasks, each one command:**

| When | Run |
|---|---|
| A case must not be linkable to other work at all | `sudo golden-image-provision --case-mode anonymous --case 2026-0417`, and `--case-mode normal` when it closes. It stops the Wazuh agent in the Tor qubes and logs both actions for the case file. |
| Upgrading Wazuh | `sudo golden-image-provision --upgrade-wazuh`. It upgrades the manager first, then the agents, and records the version. Commit that change to this repository too. |
| The expiry watch says a key is expiring | `sudo golden-image-provision --refresh-repo-keys` |
| Kali rotated its signing key | Confirm the new fingerprint at kali.org, set `"kali": {"key_fpr": "<new>"}` in `/usr/local/sbin/golden-image.json` on each laptop and run `--refresh-repo-keys`. On the build host, `./build_iso.py --set kali.key_fpr=<new fingerprint>`. |

**When to rebuild the image.** An image freezes dom0, Xen and the kernel at
build time. `./build_iso.py check-upstream` on the build host lists every
Qubes Security Bulletin since the last build and marks those that touch dom0,
Xen or the kernel. Those mean rebuild. CI runs it every Monday.

---

## 8. Command cheat sheet

**Build host: `./build_iso.py <command>`**

| Command | Does |
|---|---|
| `quickstart --usb` | everything: check, fix, key, build, sign, write the stick |
| `bootstrap` | the production path, with a separate key-backup medium and a verified export |
| `doctor` / `doctor --fix` | check the host; `--fix` also runs the fixes |
| `setup-host` | install what the host needs |
| `gen-key` / `backup-key` / `restore-key` | create, back up and restore the signing key |
| `config`, `--set K=V`, `--get K` | read and change settings |
| `check-upstream` | pinned keys and versions against upstream (`--update` accepts the changes) |
| `--dry-run all` | print the whole build plan, change nothing |
| `templates` / `iso` / `all` | build templates (tier 2) / the image / both |
| `sign` | sign an image on the machine that holds the key |
| `write-usb` | verify, then write, then read back a stick (`--wait`, `--device`, `--edition`) |
| `package-release` | turn a build into GitHub release files |
| `bootstrap-status` | show the state of a bootstrap run |
| `list-kickstarts` | show what the fetched Qubes sources offer |

**Laptop, in dom0: `sudo golden-image-provision <flag>`**

| Flag | Does |
|---|---|
| *(none)* | run or resume provisioning |
| `--dry-run`, `--from-phase N`, `--phase N`, `--list-phases` | preview, resume from, or run one phase; list them |
| `--status` | edition, phases, timers, last results |
| `--verify` | the acceptance tests |
| `--edition wired` | wire an unwired machine |
| `--handover` | rotate, escrow and shred the credentials |
| `--prepare-backup-media` | format the backup disk |
| `--issue --operator NAME` | record the release |
| `--case-mode anonymous\|normal --case ID` | cut or restore SIEM linkage for one case |
| `--upgrade-wazuh`, `--refresh-repo-keys` | maintenance |

`make` on its own lists shortcuts for the most common of these (`make
quickstart`, `make check`, `make verify`, …).

---

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| `Permission denied` writing `iso-build.json` | The clone belongs to root. `sudo chown -R "$USER": <the clone>`, or clone under your home. Never run the scripts with `sudo`. |
| `doctor`: "disk at … needed for tier 1" | `./build_iso.py --set work_dir=/mnt/build/investigator-iso` on a bigger disk, then run `quickstart` again. |
| The build disk is gone after a reboot | A disk mounted by hand does not come back. Add it to `/etc/fstab` by UUID (`sudo blkid`), with `nofail`, then `sudo mount -a`. |
| Docker needs `sudo` | `./build_iso.py setup-host`. It adds you to the group and tells you how to carry on without logging out. |
| `write-usb --wait` never sees the stick (VirtualBox) | Check that `lsblk` in the VM lists it. If not: power the VM off, set Settings → USB → **USB 3.0 (xHCI)**, attach the stick, then `./build_iso.py write-usb --wait`. Do not re-run `quickstart`, which would rebuild. |
| "more than one was already plugged in" | Several USB disks are attached. Name the one to write: `./build_iso.py write-usb --device /dev/sdX`. |
| "Running in dom0" | `build_iso.py` belongs on a separate build host. Only the provisioner runs in dom0. |
| Kali fingerprint mismatch stops the build | Either Kali rotated its key (confirm at kali.org, then `--set kali.key_fpr=…`) or the download was tampered with. Never bypass it. |
| A template fails to build (tier 2) | Fix the cause and run `./build_iso.py templates` again. Finished templates are skipped. |
| Provisioning was deferred at first boot | It waited 30 minutes for `sys-net` and `sys-firewall`. Complete Qubes' initial setup, then run `sudo golden-image-provision`. |
| An acceptance test fails | Do not issue. The log is `~/golden-image/build.log`. Fix, then `--verify` again. |
| The weekly self-check failed after issue | The login banner and `journalctl -t golden-image` name the group. The usual cause is a netvm changed by hand. |
| No network in a qube | Its netvm should be `sys-proxy`. The IPS is **fail-closed**, so check `systemctl status suricata-nfqueue` in `sys-ids`. |
| DNS goes to the wrong resolver | The `dnat-dns` rule did not survive. `--verify` group 13 names it. Background in [REVIEW.md](REVIEW.md), defect 3. |

---

## Appendix A — Build host details

### Which Linux

`doctor` names your distribution and what it does about it:

| Build host | Supported | What is different |
|---|---|---|
| **Debian 13** | reference host | nothing |
| **Kali rolling** | yes, and **the only host that has actually built an image** (VirtualBox, Docker, tier 1) | Debian underneath. The same two packages are missing as on Debian (below). |
| **Ubuntu 22.04 / 24.04** | yes | Older releases may lack `sq`/`sqv`. `setup-builder` names them and carries on. |
| **Fedora 43 / 44** | yes | upstream's own host, and the only one with `mock` |

Debian, Ubuntu and Fedora are covered by tests of host detection and package
resolution, but have not built an image yet.

**Two packages that every Debian-family host lacks, neither fatal:**

- **`mock`**: without it, the build container is created from the pinned
  Fedora image instead of a local chroot. This is chosen automatically.
- **`pykickstart`**: `setup-host` offers to install it into a virtualenv under
  `work_dir`. If you decline, the kickstart is checked from the finished image
  instead of before the build.

> **"Kali" means two different things here.** In this appendix it is a
> distribution you might build *on*. Everywhere else it is a template *inside*
> the image (`tpl-kali`). They are unrelated: the build host contributes only
> your signing key and the build record's hostname and timestamps. Every
> package is built inside containers from pinned sources.

### Running the build host in a VM

| | |
|---|---|
| Disk | 100 GB (tier 2: 250 GB), dynamically allocated. Make sure the physical disk has room to grow into. |
| RAM / CPU | 8 GB and 2 cores minimum, 16 GB and 4 cores better |
| A second virtual disk | the easiest way to give `work_dir` space. Mount it from `/etc/fstab` by UUID and `--set work_dir=` onto it. |
| USB passthrough | VirtualBox needs the **USB 3.0 (xHCI)** controller, or the stick never appears |
| Nested virtualisation | **not needed**. Docker containers are not VMs. |
| Guest additions | not needed |
| Architecture | must be x86-64. `doctor` refuses anything else. |

An existing Kali or Debian VM is fine. It does not need to be fresh:
`./build_iso.py --dry-run setup-host` shows everything it would change.

### Windows

The build needs Linux, so run a **Linux VM** (Hyper-V, VirtualBox or VMware)
and follow this guide inside it. **WSL2** may work, but it is unverified: the
image build's loop devices and chroots have not been confirmed under it.
`doctor` checks what it can. If it fails, use a VM.

Whatever you use, a discarded VM takes your signing key with it. Back it up
the moment you create it (`./build_iso.py backup-key --to <removable media>`).

---

## Appendix B — What the build does inside

### Templates: `investigator-*` and `tpl-*`

Two sets of names exist, and they are not a contradiction:

- **`tpl-*`**: the templates every installed machine uses (`tpl-sys`,
  `tpl-proxy`, `tpl-ids`, `tpl-kali`, `tpl-personal`, `tpl-wazuh`). First boot
  (phase 3) clones them from Debian 13 and installs their contents (phase 4).
- **`investigator-*`**: tier 2 only. The build host builds them into the image
  (`investigator-kali`, `investigator-office`, `investigator-ids`,
  `investigator-proxy`, `investigator-wazuh`). When they are present, phase 3
  clones `tpl-kali`, `tpl-personal`, `tpl-ids`, `tpl-proxy` and `tpl-wazuh`
  from them instead, and phase 4 skips what they already contain. That is what
  saves hours at first boot. The SIEM itself (indexer, manager, dashboard)
  then comes from the image, with no download.

Every template carries the Wazuh agent **installed but disabled**. A template
is shared: an enabled agent would report during updates, and every qube cloned
from it would share one identity. Phase 11 enables it per qube.

The one exception is the SIEM. Wazuh's packages do not allow the manager and
the agent on the same system, and the manager watches its own host. So
`investigator-wazuh`, and a tier 2 `tpl-wazuh` cloned from it, carry the
manager instead of the agent. At tier 1, `wazuh-srv` removes the agent it
inherited from `tpl-wazuh` before it installs the manager.

### `./build_iso.py templates` (tier 2)

1. **Preflight.** It refuses to run in dom0, checks disk, Docker and the key,
   and asks you to type `UNDERSTOOD` for three warnings (`--yes` records the
   acknowledgement).
2. **Fetches `qubes-builderv2`** and verifies its signed tag against the Qubes
   master key. Then it builds the container image.
3. **Fetches the Kali keyring** and checks it against the pinned fingerprint
   `827C8569F2518CC677FECA1AED65462EC8D5E4C5`. A mismatch **aborts**.
4. **Generates the template component** in
   `<work_dir>/qubes-template-investigator` and puts each flavor where the
   builder looks for it. Without that, a flavor would silently build as plain
   Debian.
5. **Builds the templates.** Each is a full debootstrap and takes hours.
   Finished ones are skipped. `--force templates` rebuilds them.

### `./build_iso.py iso`

1. Reads Qubes' own kickstart and `comps-dom0.xml`, and takes the stock template
   names from there rather than assuming them.
2. Writes `investigator.ks`, which decides what goes into the image. It also
   writes one install-time kickstart per edition, whose `%post` installs the
   provisioner, [WORKSTATION-GUIDE.md](WORKSTATION-GUIDE.md) and the
   first-boot service into dom0.
3. **Merges** its settings into `builder.yml`, rather than appending a
   duplicate block that would silently drop upstream's settings. The merge is
   then verified with `qb config get-var templates`. It sets
   `use-qubes-repo`, which the installer needs for `lorax-templates-qubes`, and
   `use-kernel-latest: false`, because Fedora 41's lorax crashes on the
   `--excludepkgs` that setting adds. The *installed* system still gets
   `kernel-latest`.
4. Runs `qb installer init-cache all`, then builds the installer.
5. Takes the **newest** image, refuses one older than this run, then checksums
   and signs it and every kickstart, and writes `BUILD-RECORD.txt`.

### What `write-usb` protects against

- **An image that changed since the build:** the checksum and signature are
  checked before writing.
- **An altered answer file:** the kickstart runs as root in the installer and
  the image signature does not cover it, so it is verified separately.
- **The wrong disk:** fixed and mounted disks are refused.
- **A stick that writes without error but reads back wrong:** it is read back
  and compared.

What nothing can check: the stick at boot time. Qubes' installer has no such
mechanism, so a written stick is protected by keeping it in your custody.
