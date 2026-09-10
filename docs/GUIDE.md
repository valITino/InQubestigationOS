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

**A build host.** Any Debian-family or Fedora-family Linux. This is *not* dom0
and not the laptop you are building — it is a separate machine or VM.

| Requirement | Why | Who satisfies it |
|---|---|---|
| A Debian-family or Fedora-family Linux | qubes-builderv2 ships dependency lists for both families. Debian, Kali and Ubuntu all qualify — see the next table | you |
| Docker, usable without `sudo` | Build cages. Podman cannot currently build DEB packages | `setup-host` |
| ~250 GB free disk | Five templates plus the ISO. Tier 1 needs ~100 GB | you |
| 8 GB RAM minimum | Builds are slow and can OOM below this | you |
| 4 CPU cores recommended | Nothing enforces it, but two cores roughly doubles an already long build | you |
| Several hours | The Kali *template* dominates — and see the warning below about the two different things called "Kali" here | you |

Everything in that table that a script can do, a script does. Ask first:

```bash
./build_iso.py doctor
```

It checks each requirement, changes nothing, and prints the command that fixes
whatever is missing. Every later step in this guide is also available as a
`make` target — run `make` on its own for the list.

### Which Linux, specifically

`doctor` reads `/etc/os-release` and prints the distribution by name, so you
never have to work out which of these you are on:

```
✓ supported build host  Kali GNU/Linux Rolling (debian-family) — detected via /etc/os-release
```

| Build host | Handled by the scripts | What is different about it |
|---|---|---|
| **Debian 13 (trixie)** | Preferred | Nothing. This is the reference host the rest of the guide assumes. |
| **Kali Linux (rolling)** | Yes | Debian testing underneath, and it declares `ID_LIKE=debian`, so every Debian instruction applies unchanged. Two packages Debian proper also lacks are missing here — see below. |
| **Ubuntu 22.04 / 24.04** | Yes | Same Debian-family path. Older Ubuntu may not carry the `sq`/`sqv` packages the builder wants; `setup-builder` — the step that installs upstream's own dependency list, not `setup-host` — names any it cannot find and carries on. |
| **Fedora 43 / 44** | Yes | Upstream's own build host, and the only family whose dependency list installs `mock`, so the build cage is seeded from a Mock chroot here and from the pinned Fedora container everywhere else. |

> **What "handled" means, and what it does not.** Every row above is what the
> code detects and adapts to, checked against each distribution's package
> archives. **None of it has been run end to end on a real build host of any
> distribution** — not Kali, not Debian, not Fedora. The regression suite
> exercises the host-detection and package-resolution logic, and the guide is
> honest about the difference: treat these as "the scripts know about this
> host", not "somebody has built an ISO on it".

**Two packages are missing on every Debian-family host, Kali included, and
neither is fatal:**

- **`mock`** was dropped from Debian in 2019 and is in no current Debian or
  Kali suite. Upstream's `tools/generate-container-image.sh` takes the Mock
  chroot as an *optional* argument; without it the build cage image is built
  from `dockerfiles/fedora.Dockerfile`, which pulls the pinned Fedora
  container and installs `mock`, `rpm-build` and `createrepo_c` *inside* it.
  The two images are not identical — one is seeded from a digest-pinned Fedora
  image, the other from a chroot built on your host — but both carry the
  `qubes-builder-fedora` tag, and that name is the only thing the builder ever
  looks for. `build_iso.py` picks the path automatically, based on whether
  `mock` is actually installed rather than on which distribution you are on.
- **`pykickstart`** was removed from Debian in August 2019 and has never been
  in Kali. It is only used to parse the generated kickstart *before* the
  build. `setup-host` offers to install it into a virtualenv under `work_dir`
  instead — the plan shows that step, and the PyPI download it involves,
  before you agree to it, and it pulls in `python3-venv` if that is missing;
  if that is not possible — no network, say — the build still runs and the
  same question is answered afterwards, by confirming the template RPMs are
  present in the finished ISO. `doctor` says which of the two is in effect.

> **"Kali" means two unrelated things in this repository.** Everywhere else in
> this guide, Kali is a **template inside the image you are building** — the
> `investigator-kali` qube, its apt repository and its signing key. Here, and
> only in this section, Kali is a **distribution you might be running the
> build on**. They are independent: you can build on Debian and get the Kali
> template, or build on Kali and produce an image with no Kali template at
> all. Which distribution you build on contributes nothing to the image's
> contents — every package is built inside a container, from the pinned
> sources in the configuration. What the build host does contribute is what
> you would expect it to: your signing key, and the hostname and timestamps
> the build record carries.

### Running the build host in a VM

A VM is a first-class build host — the ISO does not care what built it. Size
it as follows:

| | |
|---|---|
| **Virtual disk** | 250 GB for Tier 2, 100 GB for Tier 1. Prefer a dynamically-allocated disk so it only consumes what it uses, but **check the host has the space to grow into** — running the physical disk out mid-build is the most common way this fails. |
| **RAM** | 8 GB minimum, 12–16 GB if the physical machine allows. |
| **CPUs** | 4 cores recommended, 2 workable. |
| **Guest additions** | Not needed. Nothing here uses a GUI. |
| **Shared folder** | Optional, and the easiest way to get the finished ISO back to the host. A `vboxsf`/`hgfs` mount is fine as a *destination*; do not put `work_dir` on one. |

**You do not need nested virtualisation, and you should not turn it on for
this.** Docker containers are not virtual machines — they are processes
isolated by namespaces and cgroups on the VM's *own* kernel — so the build
cages need no VT-x inside the guest. Nested virtualisation only matters if you
intend to *boot* the finished ISO inside that same VM, which is a separate
activity from building it and is not what this guide asks for.

The one hardware requirement that is real: **the build host must be x86-64**,
because every package and the installer itself are built for that
architecture. An Apple Silicon Mac running an ARM Linux VM cannot build this
image — `./build_iso.py doctor` checks the architecture and fails on anything
that is not x86-64, so you find out in a second rather than in an hour.

**A target laptop** with VT-x and VT-d/IOMMU, 32 GB RAM comfortable (16 GB
workable), 512 GB SSD minimum. Check it against the Qubes Hardware
Compatibility List before committing.

### If your workstation is Windows

**The build host must be Linux.** This is not a limitation of these scripts —
`qubes-builderv2` builds every package inside a Linux container, using Mock
chroots for the RPMs and pbuilder for the DEBs, and its dependency lists are
Debian and Fedora packages. There is no Windows-native path, and the two
scripts here are POSIX throughout.

You have two options on a Windows machine, and they are not equally proven:

| | |
|---|---|
| **A Linux VM** — Hyper-V, VirtualBox or VMware; Debian 13, **Kali**, Ubuntu or Fedora; ~250 GB virtual disk, 8 GB RAM, 4 vCPU | **The path to use.** Inside the VM it is an ordinary Linux build host, so everything in this guide applies unchanged. |
| **WSL2** — Debian from the Microsoft Store, `systemd=true` in `/etc/wsl.conf`, Docker | **Not verified.** WSL2 is a real Linux kernel and the scripts run, but nobody — upstream or here — has confirmed that the Mock chroots and loop-device work that the ISO build depends on behave under it. `./build_iso.py doctor` detects WSL and checks the parts it can (kernel type, `/dev/loop-control`, systemd as PID 1). If it fails, use a VM rather than fighting it. |

**If you already have a Kali VM, use it.** A Kali VM installed for any other
reason is a perfectly good build host: it is Debian testing underneath, it
declares `ID_LIKE=debian`, and `setup-host` treats it exactly as it treats
Debian. See [Which Linux, specifically](#which-linux-specifically) above for
the two packages Kali does not carry and what the scripts do about them — and
for the warning that "Kali the build host" has nothing to do with "the Kali
template inside the image".

Two questions that come up at this point, both answered above but worth
repeating here because they decide whether you bother:

- **Does the VM need nested virtualisation enabled?** No. Docker containers
  are namespaced processes on the VM's own kernel, not virtual machines, so
  the build cages need no VT-x inside the guest. Leave it off.
- **Does it need to be a fresh VM?** No. The build touches `work_dir`,
  `/var/lib/docker`, and packages. `./build_iso.py --dry-run setup-host`
  prints exactly what that step would run, including the virtualenv and the
  PyPI download it uses for `pykickstart`, before you agree to any of it. Note
  that this is the *host* setup only: `setup-builder`, later in the run, also
  installs `qubes-builderv2`'s own dependency list, which is upstream's and
  not shown by that dry run.

Either way, remember that a WSL distro or a discarded VM takes your **signing
key** with it. Back it up the moment you create it:

```bash
./build_iso.py backup-key --to /mnt/c/Users/you/keys/investigator
```

**Writing the USB from Windows.** You can build in the VM, copy the ISO out to
Windows, and flash it with Rufus onto your 128 GB stick — but:

> **Rufus must be set to "Write in DD Image mode".** Select the ISO, press
> START, and choose DD Image mode when Rufus asks. This is the Qubes project's
> own instruction; ISO mode rewrites the boot structure and the installer will
> not work. One consequence they also note: a Rufus-written stick does not offer
> "Test this media and install Qubes OS" — choose "Install Qubes OS".

Rufus does not verify the image, so verify it on Windows first. The build writes
a PowerShell script beside the ISO for exactly this:

```powershell
.\verify-iso.ps1 <the fingerprint you were given out of band>
erify-iso.ps1 <the fingerprint you were given out of band>
```

# The administrator mounts the removable backup filesystem first. Merely
# creating /mnt/image-key-backup is deliberately not sufficient.
sudo mount LABEL=IMAGE-KEY-BACKUP /mnt/image-key-backup
install -m 600 /dev/null /run/user/$UID/inqubestigation-gpg.pass
# Write the passphrase into that runtime file without putting it in shell history.
read -rsp 'Signing/backup passphrase: ' P; printf '%s' "$P" > /run/user/$UID/inqubestigation-gpg.pass; unset P; echo
sudo -v
./build_iso.py bootstrap --yes \
  --uid "Kapo Cyber Image Signing <cyber@example.ch>" --expire 3y \
  --passphrase-file /run/user/$UID/inqubestigation-gpg.pass \
  --to /mnt/image-key-backup/inqubestigation
For every repeat build, mount the same backup medium and use the same runtime
secret file, then run the **same command**. The fingerprint already pinned in
`iso-build.json` wins: bootstrap verifies and reuses that key even though
`--uid` remains present, safely refreshes the encrypted backup, checks signing
with an empty agent cache, and resumes only marks whose configuration and Git
revision still match. `--yes` never creates a second identity. If the configured
key is missing or selection is ambiguous, the command stops and tells you to
restore it or pass its full fingerprint.

The runtime passphrase file must be owned by the build user and mode `0600` (a
protected FIFO or inherited `/proc/self/fd/N` is also accepted). Delete it after
the run. It is never copied into JSON, logs, artifacts, or the ISO. Run bootstrap
as the ordinary build user, not via `sudo`; after `setup-host`, orchestration
enters the new Docker group with `sg` while retaining that user's HOME and GPG
keyring. For `--yes`, authenticate with `sudo -v` first; the script verifies
non-interactive sudo readiness and does not edit sudo policy.

Gpg4win, and exits non-zero on any mismatch. Without a fingerprint argument it
prints the signer for you to compare by eye. If Gpg4win is not installed it says
so and exits 2 rather than implying the image is trustworthy.

`./build_iso.py write-usb` remains the better option when you can reach the
stick from Linux: it is the only path that also reads the stick back and
compares it byte for byte.

**A GPG key** for signing. Section 3 covers creating one — and backing it up,
which matters more than it sounds: lose the build host and every image you ever
signed becomes unverifiable.

**A spare machine to test on.** Do not let the first install be on hardware you
intend to issue.

---

## 2. Prepare the build host

**The short version.** Sections 2 to 6 are one command:

```bash
git clone <your-internal-url>/InQubestigationOS.git
cd InQubestigationOS
./build_iso.py bootstrap
```

It runs `setup-host`, `gen-key`, `backup-key`, `doctor`, `check-upstream`, the
dry-run plan and then the build, in that order, stopping at the first failure —
and every step is idempotent, so after fixing a cause you run `bootstrap` again
and the completed steps are skipped. It does not write the USB (you have to plug
it in) and it does not distribute the fingerprint (that has to travel
separately). Add `--yes` for an unattended run.

The rest of this section, and sections 3 to 6, explain what each of those steps
does and how to run them individually.

---

Clone the repository, then let it prepare the host:

```bash
git clone <your-internal-url>/InQubestigationOS.git
cd InQubestigationOS
./build_iso.py setup-host
```

It prints every command it intends to run and asks once before running any of
them. Rather than a fixed list of package names — which is how it used to
break, by naming one that a distribution had removed years earlier — it lists
what it needs by *capability* (a container engine, git, curl, gpg, rsync, YAML
for `builder.yml`, something that can read an ISO), asks your package manager
which name provides each, and installs those. Anything your distribution has
no package for at all is named and skipped rather than failing the rest.

It then enables the Docker service, adds you to its group, and — if the build
host is a Qubes app qube rather than a normal machine — writes the bind-dirs
entry that keeps `/var/lib/docker` across reboots, seeding the directory so the
first copy does not fail silently.

One step is listed conditionally: on Debian and Kali, which have not packaged
`pykickstart` since 2019, the plan offers to create a virtualenv under
`work_dir` and `pip install pykickstart` into it from PyPI. It is shown before
you agree, and it is optional — declining costs you the kickstart check that
runs *before* the build, and the same thing is confirmed afterwards from the
finished ISO instead.

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
| `provisioner_config` | Optional path to a reviewed, non-secret `golden-image.json` to embed beside the provisioner |
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
./build_iso.py --set install.unattended=true \
  --set install.disk=/dev/disk/by-id/wwn-0x5002538d00000000
```

`wwn-0x5002538d00000000` is an example only. Record the actual stable identifier
from the Qubes target machine and use that exact value for its image; never copy
the example or derive the value from the build host.

It is **off by default** on purpose. The disk value is a stable identity read
from the laptop being installed (use the exact `/dev/disk/by-id/` or
`/dev/disk/by-path/` link recorded for that machine), not `/dev/sda` or the
builder VM's disk. At install time, before emitting any `clearpart`, `%pre`
requires the identity to resolve uniquely to one whole disk and rejects missing,
ambiguous, partition, and installation-media matches. Blank can never mean
`clearpart --all`. A fleet whose disks have different identities needs a
per-machine ISO/configuration; there is deliberately no "pick the only fixed
disk" fallback.

To transport provisioner settings, create a reviewed JSON file containing only
non-secret overrides and set `provisioner_config=/path/to/golden-image.json`.
The build rejects secret-looking populated fields and version mismatches, embeds
the validated JSON beside `golden_image.py`, and the target loads that exact
neighbor. Per-machine credentials are still generated only after installation.
1. Boot the verified USB and deliberately select installation.
2. Confirm that the stable disk identity shown for this machine is the intended
   target; a mismatch stops before partitioning.
3. Enroll the machine's unique LUKS passphrase when Anaconda asks. No shared
   passphrase is embedded and encryption cannot be disabled in unattended mode.
4. The installer completes and reboots. `install.auto_initial_setup` (on by
   default) means the first-boot runner completes Qubes' own initial setup
   non-interactively, and retries
templates are already on disk, so installation and local provisioning do not
need a repository download. This is **not** a claim that online acceptance has
passed: first boot runs local/offline checks and records DNS resolution and Tor
exit confirmation as `PENDING ONLINE`, never PASS. Run the full `--verify` after
network enrollment; issuance remains blocked by real failures.

Attempts are serialized. The status log distinguishes `deferred` prerequisites,
`failed` provisioning/checks and `complete`; failures retain their exit code and
the inactive timer retries. The completion marker is created only after all
phases and the offline-capable acceptance gate return success.
> replace the image can replace the key beside it. Read the fingerprint out over
> the phone, or publish it somewhere colleagues already trust. `FINGERPRINT.txt`
> is formatted for exactly that, and `write-usb` reminds you to carry it
> separately. **This is the one step in the whole guide that must stay manual**:
> its entire value is that it does not travel with the image.

---

## 8. Install on a laptop

**Build the ISO so there is nothing to click.** Set this before section 6 and
the generated kickstart carries the language, keyboard, timezone and
partitioning answers, so Anaconda stops asking them:

```bash
./build_iso.py --set install.unattended=true --set install.disk=/dev/nvme0n1
```

It is **off by default** on purpose: it names a disk and erases it, which is not
a thing to turn on by accident. Turn it on once you have decided which disk, and
every laptop after that installs the same way.

The one answer it deliberately does **not** supply is the disk encryption
passphrase. `autopart --encrypted` makes Anaconda *require* one, so the decision
that has to stay human cannot be clicked past by someone in a hurry.

Then the install is:

1. Boot the USB.
2. Answer the passphrase prompt. That is the only prompt.
3. Reboot. `install.auto_initial_setup` (on by default) means the first-boot
   runner completes Qubes' own initial setup non-interactively, and retries
   every thirty minutes until the machine is provisioned — so a laptop left
   alone overnight finishes by itself.

**Without `install.unattended`** it is the ordinary Qubes install:

1. Boot the USB.
2. Install Qubes normally. Accept the defaults. **Enable full-disk encryption**
   with your unit's passphrase policy.
3. Reboot and complete Qubes initial setup — the step that creates `sys-net`,
   `sys-firewall`, `personal`, `work` and so on. The provisioner rewires these,
   so it waits for them to exist. (`sudo golden-image-provision --initial-setup`
   does the same thing without the wizard.)

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

Finally, prepare the backup disk. Attach it to `sys-usb`, then:

```bash
sudo golden-image-provision --prepare-backup-media
```

It lists what is attached, refuses anything that is not removable, makes you
type `ERASE`, then partitions, formats and labels it — and confirms
`/dev/disk/by-label/GOLDEN-BACKUP` actually appeared, because that is the path
the automount rule keys off.

A udev rule and a mount unit in `sys-usb` mount it at `/mnt/backup` whenever it
appears — by label, never by device node, because `/dev/sdb` is whatever was
plugged in last and a backup written to the wrong disk is worse than none.

When every check passes and the handover is done, record the release:

```bash
sudo golden-image-provision --issue --operator "Your Name"
```

It re-runs the acceptance tests, refuses if any fail *or* if `credentials.json`
is still on the machine, and only then writes `/var/lib/golden-image/issuance`
with the image version, the host, the counts and who released it. "All must pass
before the laptop leaves your desk" then survives the conversation it was said
in.

**Brief the investigator on three rules:**

- **Window colours mean trust.** Never move files from a redder window into a
  blacker one without a reason. `docs/DESIGN.html` has the legend.
- **Evidence opens in a disposable.** Right-click → open in `dvm-offline`. No
  network, destroyed on close, full office suite so anything renders.
- **Two Kali qubes, two exits.** `kali-clear` for scans and active work,
  inspected. `kali-tor` for OSINT where your IP must not appear — but Tor carries
  TCP only, so SYN scans, UDP scans and ICMP will not work there.

**For a case that demands zero linkage.** Tor-branch telemetry reaches the same
SIEM index as attributed telemetry. The correlation stays on this laptop, but if
a case cannot tolerate it at all:

```bash
sudo golden-image-provision --case-mode anonymous --case 2026-0417
# ...and when the case closes:
sudo golden-image-provision --case-mode normal --case 2026-0417
```

It stops and *masks* the agent in `kali-tor`, `sys-whonix` and `anon-whonix`, so
the per-boot start does not quietly undo it, and appends both actions to
`~/golden-image/case-mode.log` for the case file.

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
in sees it. One command answers "where is this machine":

```bash
sudo golden-image-provision --status
```

It prints which phases completed, whether the credentials are still on the
machine and whether they were escrowed, whether each timer is enabled and when it
next runs, and the last line of the self-check, restore-test and first-boot
records. The underlying detail is still there if you want it:

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
