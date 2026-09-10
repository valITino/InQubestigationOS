# Trusted Tier-2 release-candidate builds

The normal `checks` workflow is intentionally untrusted: it runs for pull
requests on GitHub-hosted runners and has no production signing key. It never
targets the `inqubestigation-trusted-build` label. A full build is opt-in through
**Actions → trusted Tier-2 release candidate → Run workflow** only.

## Repository-owner setup (once)

1. Provision a dedicated Debian 13 x86-64 machine with 4–8 vCPU, 16 GB RAM,
   at least 250 GiB free in `IQ_WORK_DIR`, and at least 100 GiB free on Docker's
   actual `DockerRootDir`. Register it as a self-hosted runner with the unique
   label `inqubestigation-trusted-build`. Do not attach that label to a general
   runner and do not let fork or pull-request workflows select it.
2. Create the protected GitHub environment `production-build`. Restrict it to
   the repository's protected default branch, require designated reviewers,
   prevent self-review, and allow only release custodians to dispatch workflows.
   The environment approval is the boundary preventing unreviewed code from
   reaching the runner or its key.
3. Configure these **environment variables**:
   `TRUSTED_BUILD_REF` (the reviewed full 40-character commit SHA),
   `IQ_RC_CONFIG` (absolute path to the reviewed non-secret `iso-build.json`),
   `IQ_WORK_DIR`, `IQ_BACKUP_DIR`, `IQ_CANDIDATE_DIR`, `IQ_SIGNING_FPR`, and
   `IQ_MAX_ARTIFACT_GB`. The config must set `tier` to `2`, the same work path,
   and the same signer. Both destination paths must be separately mounted.
4. Import the protected key into the runner account's GPG keyring. Configure
   `IQ_GPG_SESSION_SECRET` as an environment secret delivered only after
   approval. Keep the runner account unprivileged; authenticate its narrowly
   administered sudo session before dispatch. The automation will not alter
   sudo policy.
5. Install Docker, GPG, Git, Python 3 and the repository's host dependencies.
   Confirm `docker ps`, `sudo -n true`, `./build_iso.py doctor`, and
   `./build_iso.py check-upstream` as that runner account.
6. Set retention and access controls on `IQ_CANDIDATE_DIR` and
   `IQ_WORK_DIR/release-audit`. Check available GitHub Actions storage and
   retention for the repository's current plan before deciding to add any
   later upload step. This workflow deliberately performs no GitHub artifact
   upload because a Tier-2 Qubes ISO can exhaust hosted artifact quotas.

This repository was inspected from Linux: neither `packer` nor VMware `vmrun`
is installed here. Therefore no PowerShell/Packer VMware entry point is claimed
or added. If the actual workstation is Windows/VMware, create the Debian 13
**build VM** on that Windows host using its locally installed and licensed
interfaces, with configurable storage paths and the resources above. That VM
builds an ISO; it is not, and must not be described as, running Qubes in VMware.

## One build entry point

Review a commit, place its full SHA in `TRUSTED_BUILD_REF`, then dispatch using
that exact SHA and type `BUILD_TIER2_RELEASE_CANDIDATE`. The job-level condition
checks the manual trigger, default branch and confirmation without consulting an
environment-scoped variable. After `production-build` approval, the first step
requires both the input and environment `TRUSTED_BUILD_REF` to be non-empty full
40-hex SHAs and equal; it runs before checkout, secret materialization, or any
repository code. For an equivalent
owner-controlled invocation on the runner:

```bash
make release-candidate RC_ARGS='\
  --expected-ref 0123456789abcdef0123456789abcdef01234567 \
  --config /srv/inqubestigation/release/iso-build.json \
  --work-dir /srv/inqubestigation/work \
  --backup-dir /mnt/key-backup/inqubestigation \
  --candidate-dir /mnt/release-candidates/inqubestigation \
  --passphrase-file /run/user/$UID/iq-gpg-session \
  --signing-fingerprint A1B2C3D4E5F6071829394A5B6C7D8E9FA0B1C2D3'
```

The entry point checks the immutable ref, architecture, non-root identity,
sudo, Docker, physical storage locations, configuration, key and protected
secret session before calling the tested bootstrap. Upstream drift is checked
as a separate blocking command and never updated. Bootstrap reuses input-bound
template state where configuration and Git revision still match; existing RPM
checks prevent a marker from standing in for missing artifacts.

After building, it independently checks the ISO checksum and exact `VALIDSIG`
fingerprint. The ISO builder has already opened the ISO and required every Tier-2
template. `BUILD-RECORD.txt` records repository/builder commits, resolved
templates/component policy, configuration digest, versions, ISO digest and
signer. A mode-protected `release-audit/result.json` records per-file digests;
the build log remains beside it on the trusted runner.

Only these files are copied to a new internal `rc-<commit>` directory:

* `InQubestigationOS.iso` and `.sha256`/`.asc`
* `unit-signing-key.asc`, `FINGERPRINT.txt`
* `verify-iso.sh`, `verify-iso.ps1`
* `BUILD-RECORD.txt`

Unexpected output files fail the allowlist. Work trees, logs, passphrase files,
key backups and provisioning credentials are never recursively copied or
uploaded. The candidate is not a release: promotion/publication requires a
separate explicit owner process after hardware installation testing.

## Recovery

* **Download/upstream failure:** keep the baseline unchanged, restore network
  access, and rerun the same SHA. Do not use `--update` as a retry mechanism.
* **Expired secret session:** the signing readiness gate fails before expensive
  work where possible. Approve a new short-lived session file and rerun; the
  configured identity is reused.
* **Storage exhaustion:** expand or remount the work/Docker storage, remove only
  confirmed disposable caches, then rerun. Preflight blocks predictable
  shortages, while input-bound state avoids rebuilding valid template RPMs.
* **Stale state or changed configuration:** normal input hashing invalidates
  stale marks. If an artifact is damaged, remove that artifact and rerun. Use
  `--force` only for a reviewed intentional rebuild, never to bypass signing,
  doctor, upstream, or content verification.
* **Accepted upstream change:** independently verify the new fingerprint or
  version, run `./build_iso.py check-upstream --update` on a dedicated branch,
  inspect the `supply-chain.lock.json` diff, and merge it through review. The
  scheduled workflow only detects drift; an ephemeral artifact cannot accept it.
