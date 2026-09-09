# Changelog

## 2.2 — 2026-09-08

A second verification pass, and the automation of everything the first pass left
as a manual procedure. Full detail in [docs/REVIEW.md](docs/REVIEW.md).

**Fixed — would have failed in production**

- `wazuh-certs-tool.sh` was invoked with `-c /opt/wazuh-config.yml`. The tool has
  no `-c` flag; it hardcodes `config.yml` beside itself. It therefore generated
  no certificates, `|| true` hid that, and the indexer would not have started.
- The `qvm-backup` profile used a `passphrase_file:` key. `qubes-core-admin`
  accepts only `passphrase_text` or `passphrase_vm` — the weekly backup would
  have been rejected every Sunday.
- Phase 7 staged boot-time configuration into already-running qubes and never
  restarted them, so phase 12 tested, and passed, an unconfigured chain. The
  chain is now cycled before the tests run.
- `suricata-nfqueue.service` was written into `sys-ids`, an AppVM. It was
  discarded at the first shutdown, leaving a fail-closed queue rule with no
  listener — i.e. no traffic at all. It now lives in `tpl-ids`.
- DNS enforcement was applied only from `qubes-firewall.d`, which runs *before*
  `qubes-network.service` — the service that regenerates `dnat-dns`. It is now
  re-applied by `golden-dns.service`, ordered after it, and acceptance-test
  group 13 reads the chain back to prove it stuck.
- `nft add rule` in the firewall user scripts appended a fresh copy of every rule
  on every firewall reload. The chains are flushed first.
- Phases 3, 4 and 6 marked themselves complete after warning that a template or
  chain qube was missing, so the resume path skipped them forever and the machine
  stayed half-built. They now refuse to mark.
- `self.creds` was populated only by phase 2, so any resumed run set the
  dashboard admin password to the empty string and reported success. Credentials
  are loaded once at start-up and their absence is fatal where they are needed.
- `--from-phase N` left the completion marks in place, so it skipped every phase
  it was asked to redo.
- The Tor branch was given a qrexec pipe for the events port but not the
  enrollment port, so its agents could never register.
- `personal` and `work` were restricted to 80/443/DNS and then dropped
  everything, which blocked the SIEM traffic phase 11 configures.
- `zeek-8.0` in the OBS repository is frozen at 8.0.1-0. The 8.0 LTS line is
  published as `zeek-lts`, currently 8.0.10-0.
- ISO selection took the alphabetically first match under `artifacts/`, which
  accumulates across runs — a stale image could be signed and shipped as the new
  one. It now takes the newest and refuses anything older than the run.
- `builder.yml` was edited by appending duplicate top-level keys. YAML keeps only
  the last, so the upstream component list and the rpm/deb signing fingerprints
  were silently dropped. The script warned about this and told the operator to
  merge by hand; it now merges properly and verifies with `qb config get-var`.
- The generated Kali hook pointed `FLAVORS_DIR` at a directory that is never
  created, so it could not find the keyring the build had just verified.
- `investigator.ks` was written where its `%include conf/<base>` could not
  resolve.
- ISO signing, and the pre-write signature check, ran through a helper with a
  180-second timeout — too short to hash a tens-of-GB image. A timeout was
  reported as "signing failed" (build still exited 0) or as a forged signature.
- Phase 11 enabled the agent with `systemctl enable`, which writes into an
  AppVM's volatile `/etc`; every agent was disabled again at the next boot.
- Phase 11 enrolled `sys-ids`, `sys-dpi`, `sys-firewall`, `sys-net` and `sys-usb`
  over the network at the SIEM address. Those qubes are upstream of `sys-proxy`
  and the SIEM hangs off it — there is no route. They use qrexec now.
- Every `qubes.ConnectTCP` rule named `@default` as the destination while every
  caller named the qube explicitly, so all of them were denied.
- Acceptance group 7 scored total DNS failure as a warning, and warnings do not
  block, so a workstation that could resolve nothing still passed phase 12.
- Every acceptance group skips a qube that does not exist, and the gate counts
  failures, so a half-finished build passed. Group 0 asserts the estate first.
- The Zeek/OBS key had no fingerprint check at all, and the two Wazuh vendor
  scripts were run as root with nothing but TLS behind them. Both are pinned.
- `write-usb` and the generated `verify-iso.sh` reported a signature as
  verified against the unit key without ever checking which key signed it.
- `qwrite` appended a newline to every file it wrote, so nothing copied into a
  qube could be byte-identical to its original.
- An offline qube reports `netvm` as `none`; the code compared against `None`.
- `--shred-credentials` destroyed the build log and then re-created it by
  logging that it had done so.
- `./build_iso.py templates` died with a `KeyError` before building anything:
  the generated hook read `zeek.key_fpr`, which the builder's config lacked.
- The generated API password was stored, documented and rotated but never
  applied to the `wazuh-wui` user.
- `--dry-run` — the first command the guide tells you to run — could not
  complete on a host that had not already built.
- `prefer_debian: false` left `tpl-sys` with no agent while phase 12 asserted
  one, so that configuration could never pass its own tests.
- The wazuh-agent version pin fell back to an unpinned install in silence, and
  the hold then froze an unknown version.

**Fixed — security**

- Generated secrets were written verbatim into a world-readable `build.log`. The
  log is now mode 600 and every registered secret is redacted at the writer.
- The agent enrollment password was passed on a `qvm-run` command line, making it
  readable from `/proc` by any process inside the target qube. It goes over stdin.
- The Wazuh signing key was imported unverified over a `curl -s` that does not
  fail on HTTP errors. It is now pinned to
  `0DCFCA5547B19D2A6099506096B3EE5F29111145` and checked after import.
- The Kali fingerprint check flattened `gpg --fingerprint`'s human-readable output
  and looked for the fingerprint as a substring, so a key's own UID text could
  satisfy it. Both scripts now compare exact `--with-colons` `fpr` records.
- The Kali and Zeek keys were installed into `/etc/apt/trusted.gpg.d`, making them
  global trust anchors for every repository. Both are now in
  `/usr/share/keyrings/` and scoped with `signed-by=`.
- Nothing checked for root; a non-sudo run rewired the machine and only warned
  when it could not write the backup passphrase.
- `systemctl disable wazuh-agent` in templates was forced to succeed with
  `|| true`, defeating the identity-collision protection the code explains at
  length two screens earlier.
- `ips_failure_mode: closed` degraded to *no inspection at all* when the NFQUEUE
  hook could not be installed. It now installs a fallback drop.
- `golden-image.json` was written 0644 although it can carry four passwords.

**Automated — the requirements, not just the build**

- `setup-host`, `gen-key`, `doctor`, `config` and `check-upstream` replace the
  first four sections of the guide.
- `write-usb` verifies the signature, refuses non-removable targets, and reads
  the stick back; `verify-iso.sh` and `FINGERPRINT.txt` ship beside the image.
- Acceptance-test group 13 performs every check the guide used to list under
  "confirm by hand", including asking `check.torproject.org` whether the Tor
  branch really exits over Tor.
- `--rotate-credentials`, `--escrow-credentials` and `--shred-credentials` replace
  the handover checklist; shredding refuses without a verified escrow copy.
- Seven timers replace the maintenance table: template updates, weekly
  acceptance tests, backups with retention, monthly restore verification, IPS
  rule refresh, signing-key expiry, and a staleness banner.
- The backup disk mounts itself by filesystem label; the SIEM dashboard is a
  launcher in `work`.
- `--upgrade-wazuh` performs the manager-then-agents order and writes the
  version it reached into `golden-image.json`, so the config and the machine
  cannot drift apart.
- `--handover` runs rotate, escrow and shred in the only safe order.
- `--refresh-repo-keys` re-fetches and re-verifies the pinned Zeek, Kali and
  Wazuh keys, rolling back if a fetched key does not match its fingerprint.
- `check-upstream` performs the independent keyserver cross-check
  docs/VERIFICATION.md asks for, on every run rather than "on first build";
  the Monday CI job runs it with `--update` so the baseline moves with the
  world while the exit code still reflects the findings.
- `./build_iso.py sign` replaces the three commands SIGNING.md gave for a key
  on a smartcard or another machine, and regenerates the checksum, public key,
  fingerprint sheet and verify-iso.sh that those three left stale.
- `verify-iso.sh <fingerprint>` compares the signer against the fingerprint the
  colleague was given out of band, instead of asking them to do it by eye.
- `work_dir: auto` picks the largest writable filesystem with room for the
  build; `wazuh.mode: auto` decides local-or-central from the machine's RAM.
- Acceptance group 13 asserts the five dom0 maintenance timers are enabled. A
  laptop could otherwise be issued with no backups, no updates and no
  self-checks, and pass — phase 10 only warns when it cannot enable one.
- The key-expiry watch raises a login banner naming
  `--refresh-repo-keys`, rather than only writing to the journal.
- `CREDENTIALS-README.txt` described a four-part manual rotation that
  `--rotate-credentials` had replaced, and told the operator to hand-write the
  files the tooling now writes.
- `tests/` is the fake-dom0 harness and the static checks the previous release
  described but did not ship; CI runs them on every push and `check-upstream`
  every Monday.

**Fixed — a regression from this same pass**

- Making the dead `builder_branch` key live exposed that its value was wrong:
  qubes-builderv2 has exactly one branch, `main`. Passing `--branch release4.3`
  would have made the clone fail outright. Confirmed with `git ls-remote`.

**Automated — the last of it**

- `verify_builder` checks the builder's signed `mm_<sha>` tag against the Qubes
  trust chain: one pinned fingerprint (the Master Signing Key,
  `427F11FD0FAA4B080123F01CDDFA1A3E36879494`), developer keys trusted because it
  has signed them. This was the oldest `[VERIFY]` in the repository.
- `backup-key` / `restore-key`: the signing key existed in exactly one place and
  nothing kept a copy. Lose the build host and every image you ever signed
  becomes unverifiable.
- `--prepare-backup-media` partitions, formats and labels the backup disk, and
  confirms the by-label path the automount rule depends on actually appeared.
- `install.unattended` emits the Anaconda answers; `install.auto_initial_setup`
  completes Qubes' own initial setup non-interactively, and the first-boot
  service retries every 30 minutes instead of giving up after one attempt. The
  disk-encryption passphrase stays interactive on purpose.
- `component_remote` + `component_sign_key` push the generated template
  component to your git server as a signed tag and switch `verification-mode`
  off `insecure-skip-checking`.
- The generated kickstart is parsed with pykickstart and its package list read
  back; the finished ISO is opened (bsdtar, 7z, isoinfo, xorriso or a loop
  mount) and the template RPMs confirmed present. Two more `[VERIFY]`s gone.
- `write-usb --wait` waits for the stick; `verify-iso.ps1` gives colleagues on
  Windows the same one-command check, with the same fingerprint comparison.
- `doctor` detects WSL and checks what it can (kernel type, loop devices,
  systemd as PID 1) rather than letting a build fail obscurely later.
- Group 13 asserts the Wazuh certificate layout and reads the first-boot record.

**Automated — what the survey listed and this pass had left**

- `doctor --fix` runs the fixes it would otherwise only print.
- `templates`, `iso` and `all` run `check-upstream` themselves and refuse to
  start on a blocking finding. `--skip-upstream` opts out deliberately.
- An empty `iso_sign_key` is now fatal for a real build. Shipping an unsigned
  image was a warning you could walk past; `--allow-unsigned` is explicit.
- `use_fixed_defaults` FAILS the acceptance tests unless `credentials.lab_mode`
  says you meant it. `--verify` decides whether a machine is fit to issue, and
  warnings do not block.
- Phase 7 refuses to mark itself complete when a chain qube will not start;
  phase 10 refuses when a timer will not enable. Both used to warn and continue.
- Group 7 fails when `dig` is missing rather than warning (dnsutils is in the
  office template's package list now), and group 13 drives its own traffic
  before reading the Squid counters instead of asking the operator to browse.
- Phase 8 installs the SIEM stack itself on a Tier 1 build, and fetches the two
  vendor tools checksum-pinned when the template did not bake them in.
- The apt update-proxy CONNECT workaround is performed — netvm attached for that
  one install, and always restored — rather than described.
- `--status` replaces `journalctl -f`, `systemctl list-timers` and knowing which
  files to read.
- `--case-mode anonymous|normal --case <id>` stops and masks Tor-branch
  telemetry for a case that demands zero linkage, and writes the log entry the
  guide asked the operator to remember.
- `gen-key` adopts the only key in the keyring rather than asking; it takes
  `--passphrase-file` for a scripted key-management process.

- `bootstrap` runs the whole build side in order — setup-host, gen-key,
  backup-key, doctor, check-upstream, plan, build — stopping at the first
  failure and skipping what already succeeded.
- `preflight` runs `doctor` for the build actions and refuses on a blocking
  row, and re-checks the supply chain when the recorded baseline is older than
  `check_upstream_max_age_days`. An empty `iso_sign_key` fails there rather
  than four hours later beside the finished image.
- `--issue --operator "<name>"` re-runs the acceptance tests, refuses if any
  fail or if credentials.json is still on the machine, and writes the release
  record. `--status` answers "where is this machine" in one command.
- A `golden-key-refresh.timer` renews an expiring repository key by running
  `--refresh-repo-keys`, which verifies against the pinned fingerprint and
  rolls the old key back on mismatch. A genuinely *rotated* key therefore
  fails and stays a decision for a person, which is the correct outcome.
- The Wazuh passwords tool being absent is fatal rather than a warning: it
  would leave the SIEM admin password at a value nobody has.

**Deliberately still manual**, because automating them would be wrong: reading
the fingerprint out over an independent channel, choosing the disk-encryption
passphrase, accepting a rotated upstream signing key, applying dom0 updates that
may require a reboot, and deciding a machine is fit to issue.

**No unconditional `[VERIFY]` notes remain.** The two that can still print are
fallbacks for a missing tool or an upstream layout change.

**Verified 2026-09-09 against primary sources**

- Kali `827C…E4C5` current, expires 2028-04-17; legacy `44C6…0BF6` expires
  2027-02-04; published keyring SHA1 unchanged.
- Zeek OBS key `F9FA0223B56B116C363737EF5DA57BDD6DD785CA`, **expires 2026-12-02**.
- Wazuh 4.14.7 is current in the stable apt repository; signing key
  `0DCF…1145` expires 2027-05.
- Qubes 4.3 template names, dom0 Fedora 41, and the `custom-forward` /
  `custom-input` user hooks all confirmed; `custom-prerouting` still does not
  exist and qubes-issues #8629 is still open.
- Two of release 2.1's own records were wrong: `qvm-firewall <vm> reset` **is**
  documented on 4.3, and `qvm-backup --yes` **does** exist — it is on the
  top-level parser, not inside the mutually-exclusive "Profile setup" group.
  The weekly backup passes it now, because a timer that can be asked a
  y/N question is a timer that hangs forever.
- qubes-issues #9056 is Closed as not planned and labelled `R: declined`; it was
  cited as "the working pattern". Its value is the ordering fact, nothing more.

**Build hosts — Debian-family support, which had never actually worked**

The image version is unchanged: none of this alters what is built, only what can
build it. Verified 2026-09-09 against upstream `qubes-builderv2`,
packages.debian.org, pkg.kali.org and mdapi.fedoraproject.org.

- The container image build passed the Mock chroot to upstream's
  `tools/generate-container-image.sh` as a positional argument, and that
  argument selects a `sudo mock -r … --scrub=all` code path. `mock` was dropped
  from Debian in 2019 and is in no Debian or Kali suite; the script runs under
  `set -ex` and the call had the default `check=True`. **The build cage image
  therefore could not be built on any Debian-family host — including the
  Debian 13 host the guide recommends.** The argument is now passed only when
  `mock` is actually installed, so Fedora keeps upstream's preferred path and
  Debian-family hosts build from `dockerfiles/fedora.Dockerfile`, which needs
  nothing but the container engine. Both branches of that script tag the same
  `qubes-builder-fedora` tag. The two images are not identical — one is seeded
  from a digest-pinned Fedora image, the other from a chroot built on the host
  — but that tag is the only name anything in qubes-builderv2 looks for.
- `setup-host`'s Debian package list contained `python3-pykickstart`, which was
  removed from Debian in August 2019 and has never been in Kali. `apt-get
  install -y` fails the whole batch on one unknown name, so `setup-host` died
  on a fresh Debian-family host before installing anything.
- The package install was gated on five binaries. On a host that already had
  them, nothing was installed at all — so `python3-yaml` stayed missing and
  `doctor` blocked on it with the fix `./build_iso.py setup-host`, which had
  just decided there was nothing to do. The gate now covers Python modules and
  the ISO reader as well as binaries.
- `doctor --fix` built its argv without the script path, so every repair ran as
  `python3 setup-host` and failed with "can't open file". It could never fix
  anything, on any host.
- Package names are no longer hardcoded per distribution. Each requirement
  names several candidates and the package manager is asked which exist
  (`apt-cache policy`, `dnf list` plus a `repoquery --whatprovides` pass so a
  virtual provide is not mistaken for an absent package). Anything a
  distribution has no package for at all is reported and skipped instead of
  failing the batch. This is what fixed the class rather than the instances —
  the Fedora list had the same defect, asking for `docker`, which is not a
  Fedora binary package name.
- The build host is identified from `/etc/os-release` rather than guessed from
  which package manager is on `$PATH`. Three code paths guessed, two of them in
  opposite orders. Kali, Ubuntu and Mint are now recognised as Debian-family
  **and named**: `doctor` prints "Kali GNU/Linux Rolling (debian-family)".
- `pykickstart` is not packaged for Debian or Kali, so `setup-host` installs it
  into a virtualenv under `work_dir` — not with `--break-system-packages`,
  which would override PEP 668 on the operator's behalf. When that is not
  possible `doctor` says the kickstart is validated after the build instead,
  rather than repeating a fix that cannot work.
- `resolve_auto_values` raised `Fatal` for an underivable `mock_config` even on
  hosts where the value is then discarded unused.
- New `tests/host_checks.py` (135 checks), wired into the harness, the Makefile
  and CI. It pins each of the above against a dated ledger of packages verified
  absent from each distribution, probes this host's real package manager, and
  checks that `doctor --fix` invokes a script path that exists. Every fix was
  mutation-tested: re-introducing each bug fails the suite.

- `doctor` now checks the build host is x86-64. The docs called that the one
  real hardware requirement and nothing tested it, so an ARM VM would have got
  hours in before failing.

**Not verified on real hardware.** None of this has been run against a live
Kali VM or a real Qubes 4.3.1 build, on any distribution. The upstream facts
and package availability are checked against primary sources; the host
detection, package resolution and the pykickstart virtualenv are exercised
against a real apt archive on a Debian-family host; the ISO build itself
remains untested end to end.

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
