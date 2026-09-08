# Review and fixes

Two verification passes against primary sources, and what they found. Defects
are recorded here rather than quietly patched, so nobody reintroduces them.

- [Pass 2 — v2.2, 2026-09-08](#pass-2--v22-2026-09-08)
- [Pass 1 — v2.1, 2026-09-01](#pass-1--v21-2026-09-01)
- [What is actually tested](#what-is-actually-tested)
- [Still not verified](#still-not-verified--requires-real-hardware)

---

## Pass 2 — v2.2, 2026-09-08

Pass 1 fixed six defects and left a repository whose documentation described a
correct system. Pass 2 read the code against the upstream sources it depends on,
rather than against the design it was meant to implement. Four of the results
were things that could not have worked at all.

### Would not have worked

**1. The certificate tool was called with a flag it does not have.**
Phase 8 ran `./wazuh-certs-tool.sh -A -c /opt/wazuh-config.yml`. The tool
hardcodes `config_file="${base_path}/config.yml"` at line 13 and its `getHelp()`
lists no `-c` or `--config-file`. It therefore found no configuration, generated
no certificates, and `check=False` swallowed the failure. `wazuh-indexer` would
not have started, on every machine. The config is now written to `/opt/config.yml`
and the run is fatal if `root-ca.pem` does not appear afterwards.

**2. The backup profile used a key `qvm-backup` rejects.**
The profile carried `passphrase_file: /root/.backup-pass`.
`qubes-core-admin`'s `_load_backup_profile` accepts `passphrase_text` or
`passphrase_vm` and nothing else — the failure path is literally
`"specify passphrase_text or passphrase_vm"`. Every weekly backup would have been
rejected. Now `passphrase_text`, into a profile written 0600 before anything is
put in it.

**3. The acceptance tests passed an unconfigured chain.**
Phase 7 writes `rc.local`, the firewall user script, the nft drop-in and the
bind-dirs entries. All of those are read at qube *boot*. Phase 7 called
`ensure_running()` — `qvm-start --skip-if-running` — before writing them, so a
chain qube that was already up never re-read any of it, and phase 12 then
measured a system that had none of this configuration and reported it healthy.
Phase 7 now cycles the chain, downstream-first down and upstream-first up,
before the tests run.

**4. DNS enforcement lost a race it was documented as winning.**
The rules went into `/rw/config/qubes-firewall.d/`, on the reasoning that running
before the network comes up beats `qubes-setup-dnat-to-ns`. qubes-issues #9056
states the ordering the other way round: `qubes-firewall.service` starts *before*
`qubes-network.service`, which is what runs `qubes-setup-dnat-to-ns`. Running
first means being overwritten. A `golden-dns.service` in `tpl-sys`, ordered
`After=qubes-network.service`, now re-applies the chain afterwards, and
acceptance-test group 13 reads it back.

**5. The IPS unit did not survive a reboot.**
`suricata-nfqueue.service` was written into `/etc/systemd/system` of `sys-ids`,
which is an AppVM: anything under `/etc` outside a bind-dirs entry is discarded
at shutdown. After the first reboot the fail-closed queue rule had no listener —
and fail-closed with no listener is not "inspected traffic", it is *no traffic*,
on a machine that passed its tests the day before. The unit now lives in
`tpl-ids`.

**6. Firewall rules multiplied.**
`qubes-firewall` runs the user script on every firewall reload, not once per
boot, and `nft add rule` appends unconditionally. Every downstream firewall
change added another copy of every rule. The scripts now flush the chains they
own first.

**7. Half-built machines marked themselves finished.**
`_clone` and `_mk_netqube` warned and returned when a template was missing;
phases 3, 4 and 6 marked themselves complete regardless. The resume path then
skipped them forever. They now refuse to mark, and `--from-phase N` clears the
marks it supersedes — previously it was a no-op, because every phase it was
asked to redo was still recorded as done.

**8. Resumed runs set the dashboard password to the empty string.**
`self.creds` was populated only by phase 2. On any run where phase 2 was already
marked done — a resume, or `--phase 8` — it stayed `{}`, and
`wazuh-passwords-tool.sh -u admin -p ''` ran with `|| true` and `check=False`
behind an unconditional success message. Credentials are now loaded once at
start-up and their absence is fatal where they are needed.

**9. The Tor branch could never enrol.** Its qrexec pipe and policy carried the
events port (1514) but not the enrollment port (1515). The clearnet branch had
both. Agents register on 1515 before they ever send an event.

**10. The per-qube firewall blocked the SIEM.** Phase 9 restricted `personal`
and `work` to 80/443/DNS and then dropped everything, including the 1514/1515
traffic phase 11 configures. Qubes enforces per-VM rules in their own chain, so
the accept in `sys-proxy`'s `custom-forward` does not cover it.

**11. Zeek was pinned to a package frozen three years ago.**
`zeek-8.0` in the openSUSE Build Service Debian_13 repository is 8.0.1-0. The 8.0
LTS line is published as `zeek-lts`, currently 8.0.10-0. The image was pinned to
the frozen one, so the DPI recorder would never have received a fix.

**12. A stale ISO could be signed and shipped as the new one.**
`artifacts/` accumulates across runs and the code took `sorted(...)[0]` — the
alphabetically first image, not the one this run produced. It now takes the
newest and refuses anything older than the build's start time.

**13. builder.yml was edited by appending duplicate keys.**
A second `templates:`, `components:`, `sign-key:` and `cache:` were appended.
YAML keeps only the last occurrence, so the upstream component list collapsed to
one entry and the rpm and deb signing fingerprints silently vanished — packages
inside a signed ISO stopped being signed. The script *warned* about this and told
the operator to merge by hand. It now loads the YAML, merges into the existing
structures, keeps a timestamped backup, and verifies the result with
`qb config get-var templates`.

**14. Two path bugs in the ISO build.** `FLAVORS_DIR` was set to
`${BUILDER_DIR}/${SRC_DIR}/template-investigator`, a directory that is never
created, so the generated Kali hook could not find the keyring the build had just
verified. And `investigator.ks` was written to the builder root while its
`%include conf/<base>` only resolves from inside `qubes-release/conf/`.

**15. Signing was given 180 seconds to hash a tens-of-GB image.** It ran through
a helper with a fixed timeout; a timeout was swallowed into "signing failed", and
the build still exited 0. The same helper was verifying the signature before a
USB write, where a timeout would have been reported as a *forged* signature.

**16. Every agent came back disabled after a reboot.**
Phase 11 ran `systemctl enable --now wazuh-agent` inside the target qube.
`enable` writes a symlink under `/etc/systemd/system`, which in an AppVM is
volatile — so on every qube, at the next boot, the agent was off again. It is now
started from `/rw/config`, which persists; the unit itself comes from the
template.

**17. Half the estate was pointed at a SIEM address it cannot reach.**
`wazuh-srv` hangs off `sys-proxy`, i.e. at the *bottom* of the chain. Phase 11
enrolled `sys-ids`, `sys-dpi`, `sys-firewall`, `sys-net` and `sys-usb` — all
*upstream* of `sys-proxy` — over the network at `10.137.0.50`. Traffic from an
upstream qube goes outward; there is no route back down into a sibling of its own
client. Those five now use the qrexec transport the Tor branch already had.

**18. Every qrexec pipe was denied by the policy that was supposed to allow it.**
The rules named `@default` as the destination, but `qvm-connect-tcp
<local>:<vm>:<port>` issues the request with `<vm>` as the destination — and
every caller in the image names the qube explicitly. `@default` only matches the
form with an empty middle field. The policy now carries both, and group 13 opens
the dashboard over qrexec to prove it.

**19. Absent infrastructure produced no failing test.**
Every group starts `if not r.vm_exists(name): continue`, and the gate counts
failures — so a check that never runs cannot fail. A half-finished build, or
`--verify` run before phase 6, skipped most of the suite and was accepted. Group
0 now asserts the estate exists before anything else looks at it.

**20. A workstation that could resolve nothing still passed.**
Acceptance test group 7 scored total DNS failure as a WARN, and warnings never
block: phase 12 marks the build complete on `fail == 0`. It is a failure now.

### Security

| | |
|---|---|
| Secrets in a world-readable log | `qrun` logged every in-qube script verbatim, including the enrollment and dashboard passwords, into a 0644 `build.log` that the documented `shred` step never touched. The log is 0600 and secrets are redacted at the writer. |
| Secrets on a command line | The enrollment password was passed as a `qvm-run` argument, making it readable from `/proc/<pid>/cmdline` by any process inside the target qube. It goes over stdin. |
| Unverified signing keys | The Wazuh key was imported from whatever `curl -s` returned — `-s` alone exits 0 on a 404 — into a keyring `signed-by=` then trusted for the SIEM's packages. The Zeek/OBS key had no check at all. Both are now pinned (`0DCF…1145`, `F9FA…85CA`) and compared after import, in the provisioner and in the ISO build. |
| Unverified vendor scripts | `wazuh-certs-tool.sh` and `wazuh-passwords-tool.sh` were downloaded into the template and run as root against the SIEM with nothing but TLS behind them, in a file where every apt key is fingerprint-pinned. Both are now checksum-pinned, and `check-upstream` reports when either changes. |
| A signature check that checked nothing | `write-usb` printed "signature verifies against \<the unit key\>" after a bare `gpg --verify`, which exits 0 for a good signature from *any* key in the keyring. It reads `VALIDSIG` from `--status-fd` and compares. The generated `verify-iso.sh` had the same flaw, printing a fingerprint baked into a script that travels with the image. |
| A fingerprint check that a UID could satisfy | `gpg --fingerprint \| tr -d ' \n' \| grep -qi <fpr>` flattens uid text into the same blob as the fingerprints. Both scripts now compare exact `--with-colons` `fpr` records with `grep -qxF`. |
| Global apt trust anchors | The Kali and Zeek keys went into `/etc/apt/trusted.gpg.d`, where apt accepts *any* repository they sign — defeating the `signed-by=` on the same line, and the Zeek key belongs to a build service the code itself flags as outside upstream's control. Both are now in `/usr/share/keyrings/`. |
| No root check | `qvm-*` works as an unprivileged dom0 user, so a run without `sudo` re-templated the service qubes and rewired every netvm, then warned that it could not write the backup passphrase and carried on. |
| Fail-closed that failed open | With `ips_failure_mode: closed`, a failure to install the NFQUEUE rule was logged and swallowed; the qube then forwarded everything uninspected — the opposite of the configured mode. A fallback drop is installed. |
| `\|\| true` on the agent disable | Phase 5 spends six lines explaining that an enabled agent in a shared template gives every clone the same identity, then forces the disable to succeed. |
| `golden-image.json` at 0644 | It carries four passwords when `use_fixed_defaults` is on. |

### Documentation that had drifted

`image_version` said 2.0 while the CHANGELOG, README and DESIGN said 2.1.
`docs/SIGNING.md` — the document handed to colleagues so they can verify an image
— named a product and three filenames the build has never produced.
`docs/DESIGN.html` did not exist under that name. `docs/VERIFICATION.md` told the
reader to edit `KALI_KEY_FPR` in `golden-image.conf` (a bash-era variable in a
file that does not exist), named the pin setting as `WAZUH_PIN_AGENT=true`, and
still listed `custom-prerouting` as a chain to go and verify — after pass 1
established that it does not exist. The README described a `.gitignore` that was
not in the repository, and both the README and REVIEW.md published test results
from a harness that was not committed.

`docs/DESIGN.html` was the worst of it, and for a structural reason: it is the
only document that is not Markdown, so the first version of the checker never
opened it. Every `.md` file went green while the design specification carried on
publishing the previous release's version stamp, verification date and test
results — including a backup profile with the key `qvm-backup` rejects and an
"open verification" list of nine items that had all become tests. The checker
reads it now.

All of this is asserted by `tests/doc_checks.py`, which fails CI: every path a
doc references must exist, every flag and subcommand must be real, every config
key must resolve in the right `DEFAULT_CONFIG`, the version stamps must agree,
and the two scripts must pin the same fingerprints as each other and as the
verification record.

**21. `./build_iso.py templates` died before building anything.**
The generated Kali/Zeek hook reads `zeek.key_fpr`, which existed in the
provisioner's configuration but not in the builder's — a `KeyError` raised the
moment `gen_component()` evaluated its bodies. `tests/config_checks.py` now
proves statically that every config key the code reads exists, and that every key
the config defines is read; it reproduces this failure on the commit before the
fix.

**22. The API password was generated, stored, rotated and applied to nothing.**
Three of the four secrets reach something: the dashboard password through
`wazuh-passwords-tool.sh`, the enrollment password into `authd.pass`, the backup
passphrase into the profile. The fourth was documented in
`CREDENTIALS-README.txt` as a login credential and never set on the `wazuh-wui`
API user, whose password stayed whatever the installer generated.

**23. `--dry-run` could not run on a host that had not already built.**
The command docs/GUIDE.md tells you to run first, on the machine you have just
cloned onto, died at the first environment gate. Environment gates are warnings
in a dry run now, and the plan is printed against the recorded release4.3 names
when the sources are not fetched — so `--dry-run all` reaches phase 4 on a bare
host. The harness asserts that, and asserts that it wrote nothing.

**24. `prefer_debian: false` could never pass its own acceptance tests.**
In that configuration `tpl-sys` is cloned from Fedora, phase 5 installed an agent
into neither the apt list nor the dnf path for it, and phase 12 then failed
"`tpl-sys` carries the agent" every time.

### Settings that did nothing

Each of these was a documented knob the code never read — worse than an error,
because it looks configured:

| Key | Was | Now |
|---|---|---|
| `timeouts.short` | never read; everything got the 90-minute long timeout | short for dom0 calls and file writes, long only for in-qube installs and clones |
| `builder_branch` | never read; the builder was cloned from its default branch | passed to `git clone --branch`, with a warning if the checkout drifts |
| `wazuh.version` | printed as though it were installed; `apt` was given a bare package name | passed to `apt-get install wazuh-agent=<version>-1` before the hold is applied |
| `backup.keep_sets` | documented as retention, implemented nowhere | the weekly wrapper prunes to it |
| `use_fedora_template` | selected between two log lines | decides whether the Fedora template is in service at all: agent, and coverage by the tests |
| the generated API secret | stored, documented and rotated; applied to nothing | set on the `wazuh-wui` API user |
| `wazuh_version` (build_iso) | read from a key that does not exist in its `DEFAULT_CONFIG` | reads `wazuh.version`, which does |

### Corrections to pass 1

**`qvm-firewall <vm> reset` is documented.** Pass 1 recorded it as absent from
the manpage and built a rule-by-rule fallback for it. It is in the synopsis of
`doc/manpages/qvm-firewall.rst` in qubes-core-admin-client on `release4.3` and is
registered in `qubesadmin/tools/qvm_firewall.py`. The capability check is kept
because it costs one call, but `reset` is the expected path.

**qubes-issues #9056 says the opposite of what was quoted**, and it is Closed as
not planned, labelled `R: declined` — so it was never "the working pattern"
either. Its body is still the primary source for the *ordering*, which is what
matters here: `qubes-firewall.service` starts before `qubes-network.service`. See
"DNS enforcement lost a race it was documented as winning" above.

**`qvm-backup --yes` exists.** See pass 1 defect 4.

---

## Pass 1 — v2.1, 2026-09-01

Six defects, three of which would have failed silently.

### 1. `custom-prerouting` does not exist

The Squid intercept redirect was written into a chain named `custom-prerouting`.
Qubes has **no such chain**. The documented user hooks are `custom-forward` and
`custom-input` only; for NAT you must create your own. A request to add a
`custom-nat` chain is still open upstream (qubes-issues #8629). Re-confirmed
2026-09-08 against the current firewall documentation.

```sh
nft add chain ip qubes custom-dnat-squid \
    '{ type nat hook prerouting priority filter + 1 ; policy accept; }'
nft add rule ip qubes custom-dnat-squid iifname "vif*" tcp dport 80  redirect to :3128
nft add rule ip qubes custom-dnat-squid iifname "vif*" tcp dport 443 redirect to :3129
```

### 2. Missing `custom-input` accept

Redirected packets terminate **locally** on `sys-proxy`, so they hit the input
path, not forward. The old script only touched forward chains, so even with a
working redirect the traffic would have been dropped before reaching Squid.

### 3. DNS rules were written into a chain Qubes regenerates

`nft flush chain ip qubes dnat-dns` from `qubes-firewall-user-script`: modifying
Qubes-managed chains is unsupported, and `qubes-setup-dnat-to-ns` rewrites
`dnat-dns` when the network comes up. Replaced wholesale from
`/rw/config/qubes-firewall.d/` — and, as of pass 2, re-applied after
`qubes-network.service`, which is the part pass 1 got backwards.

### 4. `qvm-backup` has no `--yes` flag

**This was wrong too.** `--yes`/`-y` is registered on `qvm-backup`'s *top-level*
parser in qubes-core-admin-client, not inside the mutually-exclusive "Profile
setup" argument group, so it combines with `--profile` perfectly well. Pass 1
appears to have read the group and concluded the flag did not exist.

The conclusion — use profile mode — was still right, for a different reason: the
profile is how the passphrase reaches an unattended run. But the weekly script
now passes `--yes` as well, because a timer that can be asked a y/N question is a
timer that hangs forever, which is the failure pass 1 was trying to prevent.
(Pass 2 also found the profile used a key that does not exist — see above.)

### 5. `qvm-firewall reset`

Recorded as undocumented. **This was wrong** — see the corrections above.

### 6. bind-dirs would have lost the Wazuh agent identity

`/var/ossec` was declared in bind-dirs but `/rw/bind-dirs/var/ossec` was never
seeded, so the first-boot copy failed and the agent re-enrolled as a new agent on
every reboot.

---

## What is actually tested

`tests/run_tests.py` is the harness. It runs on every push, needs no Qubes
machine, and is what the numbers below come from — run `make check` and read them
yourself rather than trusting this table.

| Stage | What it proves |
|---|---|
| Compile | Both scripts parse under the dom0 Python |
| Dry run | All twelve phases plan; the plan is printed; **nothing is written to disk** |
| Real run | Twelve phases execute against stub `qvm-*` binaries and a synthetic dom0 root |
| Credentials | Four distinct secrets, mode 600, **and none of them anywhere in the build log** |
| Resume | A second run skips completed phases and does not crash |
| `--verify` | The acceptance tests run, and the exit code matches the summary — a machine that failed its tests must not look like one that passed |
| Static config | Every generated file: nftables brace balance, chain types and hooks against the valid sets, `redirect` only in a nat prerouting context, no `custom-prerouting`, nft set spacing, the add-then-delete idiom and `dstnat` priority in the DNS script, Squid peek-then-splice with no `bump`/`terminate` and `%>a` attribution, unbound DoT with no cleartext fallback and no open-resolver posture, Suricata `queue num` with no `bypass` in any executable line under fail-closed, the IPS unit in the template rather than the AppVM, and no unsubstituted placeholders anywhere |
| Documentation | Every path, flag, subcommand, config key, version stamp and fingerprint in the docs resolves against the code |

Three bugs were found *by* the harness rather than by reading: `/usr/local/bin`
and `/etc/systemd/system` were assumed to exist before being written into; a
`qvm-run --pass-io` with an inherited terminal blocked until its timeout (every
subprocess now runs with `stdin` closed); and phase 10 stopped marking itself
complete after a refactor, which the "phases recorded as complete" stage caught
immediately.

Adding the credential-lifecycle flow to the harness immediately found three
more: `qvm-prefs` reports an offline qube as `none` while the code compared
against `None`, so the escrow refused to write into `vault`; `qwrite` appended a
newline to *every* file it wrote, so a copy could never be byte-identical to its
original and the escrow's integrity check could never pass; and
`--shred-credentials` destroyed the build log and then re-created it with its own
success message.

`ensure_running` used to `sleep(5)` after starting a qube — simultaneously too
long on a fast machine and too short on a slow one. It now polls until qrexec
answers, which is the condition that actually matters, and gives up after
`timeouts.short` with a warning rather than continuing silently.

## Still not verified — requires real hardware

Everything that could become an automated check has: see acceptance-test group 13
and the table in [VERIFICATION.md](VERIFICATION.md). What is left needs a live
Qubes 4.3.1 install and a decision:

- an end-to-end run on real hardware — neither script has had one
- whether the Kali apt pin priorities suit your unit's tool set in practice
- whether `pykickstart` merges two `%packages` sections as expected (standard
  Anaconda behaviour, not confirmed against a Qubes-specific source; the build
  prints `[VERIFY]` at the moment it matters)
