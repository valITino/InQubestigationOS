# Hardware acceptance of a release candidate

ISO build/export do not imply installation, provisioning, online acceptance, or issuance. Those remain separate installed-laptop facts; see [BOOTSTRAP.md](BOOTSTRAP.md).

`acceptance_runner.py` knows where it is. `--collect` refuses to run unless
`/etc/qubes-release` and `qvm-ls` identify dom0. Build-host checks remain on the
build host; every command below that uses `golden-image-provision` runs only in
the authorized spare Qubes machine's dom0. The committed
`docs/acceptance-pending.json` is the honest result for this coding environment:
all hardware checks are pending and the candidate is not a verified release.

Copy the release candidate, its `BUILD-RECORD.txt`, and this runner to the spare.
Start a report, substituting the actual candidate revision and ISO path:

```bash
./acceptance_runner.py --report acceptance-report.json \
  --revision <40-character-candidate-commit> --image /path/InQubestigationOS.iso \
  --prepare-pending
```

## Authorized operator procedure

Record evidence immediately after each observation. Evidence must not contain
passwords, tokens, case data or client identifiers. The runner hashes the
hardware serial, redacts secret-shaped log text, and writes the report mode 600.

1. Boot the signed candidate on the spare, verify the expected fingerprint,
   select the intended stable disk identity, and enroll a **new per-machine**
   LUKS passphrase. Record installation only after reboot proves that passphrase
   unlocks the disk:

   ```bash
   ./acceptance_runner.py --report acceptance-report.json \
     --record 'installation_encryption=pass:LUKS prompt enrolled unique test-machine secret; cold unlock observed'
   ```

2. Complete initial setup. To test recovery, deliberately stop the first
   provisioning attempt on this spare (`sudo systemctl stop
   golden-image-firstboot.service`), preserve its failed/deferred status, then
   restart it and wait for completion. **Ask the operator and close all test
   case qubes before rebooting; this procedure never automates a dom0 reboot.**
   Reboot manually, unlock LUKS, and confirm state remains complete.

3. Collect safe machine facts, provisioner state, the full built-in acceptance
   suite, systemd results, and redacted log tails:

   ```bash
   sudo ./acceptance_runner.py --report acceptance-report.json --collect
   sudo golden-image-provision --status
   ```

4. Exercise the inspected chain from a disposable test qube. Confirm the
   configured netvm sequence, Squid attribution, Suricata NFQUEUE/drop behavior,
   Zeek events and Wazuh ingestion. On this spare only, stop Suricata, demonstrate
   that clearnet traffic stops, restart it, and demonstrate recovery. Do not call
   a Tor exit an anonymity guarantee: verify only that `kali-tor` routes solely
   through `sys-whonix`, the external endpoint reports a Tor exit at that moment,
   and `vault`/`dvm-offline` have no netvm. Record the observed evidence under
   `inspected_path_fail_closed`, `tor_and_offline_qubes`, and
   `services_and_agent_identity`; compare Wazuh agent IDs and require them to be
   distinct after a qube reboot.

5. Test failure gates: with backup media absent, start
   `golden-backup.service` and require a failed systemd result; alter a disposable
   copy of credentials after escrow and require shredding to refuse; use an
   intentionally mismatching repository key source in the spare's test config
   and require refresh rollback/nonzero status; perform an approved Wazuh test
   upgrade and use timestamps/package versions to prove manager-before-agents.
   Restore the production test configuration after each negative test. Record
   each named check, including `maintenance_failures`.

6. Rotate credentials, escrow to the offline vault, verify its recorded digest,
   then remove the dom0 copy through the supported handover commands. Do not put
   credential values in evidence.

7. Take a real encrypted backup. `golden-restore-test.service` is only an archive
   integrity check and is not sufficient evidence. For the newest test set,
   capture `qvm-ls --raw-list` before and after an actual
   `qvm-backup-restore --rename-conflicting -d sys-usb --passphrase-file
   /root/.backup-pass <set> vault`. Identify the newly restored qube, immediately
   confirm/set its netvm to `none` before starting it, inspect expected harmless
   test content, then remove that restored qube. Record
   `real_isolated_restore=pass` only after those observations. Never restore over
   the live vault and never substitute `--verify-only` for this step.

Each manual result uses:

```bash
sudo ./acceptance_runner.py --report acceptance-report.json \
  --record 'CHECK=pass:redacted observed evidence'
```

Use `fail` on a failed observation and leave unexecuted work `pending`. A passing
automated suite cannot erase another pending hardware check.

## Issuance

Only after every report check passes, the escrow record exists, and the dom0
credentials file is gone may the actual authorized operator run:

```bash
sudo ./acceptance_runner.py --report acceptance-report.json \
  --issue --operator 'Actual Authorized Operator Name'
```

There is deliberately no default or example operator identity. The runner
refuses issuance with any failure/pending item or incomplete handover, then calls
`golden-image-provision --issue --operator` as the final hardware gate. Until
that succeeds, keep the artifact labeled **release candidate**, not release.

Dom0 updates remain report-only by default. No unattended patching or reboot is
implemented. Any future opt-in must define an explicit maintenance window,
active-casework inhibition, update policy and separately approved reboot policy;
it must not change this default.
