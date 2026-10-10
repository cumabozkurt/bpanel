# Backup and restore (v0.4)

BPanel backs up hosting accounts with **restic 0.19.1** (BSD-2-Clause), run as an
external child process by the root agent (`exec.CommandContext`, argv only, no
shell). restic is not linked into the Go binary.

## Components

| Piece | Where |
|---|---|
| Target adapters, retention, manifest, restore verification | `internal/backup` (`target.go`, `engine.go`, `verify.go`) |
| Agent actions `backup.run` (now records a manifest), `backup.verify`, `backup.delete` | `internal/agent/misc.go`, `internal/agent/backup_verify.go` |
| RPC types | `internal/agentrpc/backup_verify.go` |
| API + weekly scheduler | `internal/api/backup_verify.go` |
| Results table | `internal/store/migrations/0009_backup.sql` (`backup_verifications`) |
| UI | user Backups page: "Restore test" row (keys `backup.verify_*`, EN+TR) |

## Targets

One restic repository per account: `<base>/<account>`.

| Kind | restic repository string | Credentials |
|---|---|---|
| `local` | `/var/backups/bpanel/alice` | none |
| `sftp` | `sftp:user@host:/srv/restic/alice`, or `sftp://user@host:2222//srv/restic/alice` for a non-standard port | root's SSH key/`~root/.ssh/config` (never in argv) |
| `s3` | `s3:https://s3.example.com/bucket/prefix/alice` (any S3-compatible endpoint) | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in the **environment** of the restic child only |

`Target.Validate` rejects relative paths, `..`, shell metacharacters, hosts
that start with `-`, endpoints carrying `user:pass@`, queries or paths, and
invalid bucket names. Errors from restic are scrubbed of all known credential
values before they are returned or logged (unit-tested).

The agent currently uses the `local` target (`Cfg.BackupRepo`). SFTP and S3
adapters are implemented and unit-tested (URL/env forms) but **not
exercised against a real SFTP/S3 server** in this environment.

## Retention

`Retention{Last, Daily, Weekly, Monthly, Yearly}` → `restic forget --prune
--group-by host,paths --keep-*`. Default 7 daily / 4 weekly / 6 monthly. A
policy that keeps nothing is refused (it would delete every snapshot).

**Scheduled backups + automatic retention (v0.4 part B).** Settings (admin page
*Backups* → "Schedule & retention", `GET/PUT /api/v1/admin/backups/policy`,
PUT needs `backups.delete` + recent auth because retention deletes snapshots):
`backup_auto` (default off), `backup_interval_hours` (24), `backup_auto_databases`
(on), `backup_keep_last/daily/weekly/monthly/yearly` (0/7/4/6/0). Housekeeping
(10 min tick) runs at most ONE due account per tick (oldest first). After a
**successful** scheduled backup the API calls agent action `backup.forget`
(`restic forget --prune --group-by host,paths --keep-* --json`, per-account
lock, 30 min timeout on both sides). A failed backup never prunes. Every run is
stored in `backup_runs` (migration `0009b_backup_runs.sql`: status, snapshot
ids, error code, `retention_status` ok/failed/skipped, `retention_error`,
`removed`); failures publish events `backup.failed` / `backup.retention_failed`
and are audited (`backup.run`, `backup.retention`). Manual user backups do not
prune.

## Restore verification

A successful backup does not prove the backup can be restored (§14). So:

1. **At backup time** BPanel hashes every regular file of the account with
   sha256 (no symlink following, `~/backups` excluded) *before* restic runs.
   After restic finishes, any file whose size/mtime changed in between is dropped
   from the manifest, so an active write does not show up later as a false
   mismatch. The manifest is stored root-only in
   `<BackupRepo>/.manifests/<account>/<snapshot>.json` (0600, directory 0700).
2. **`VerifyRestore(account)`** restores the latest `files` snapshot into a fresh
   0700 temp dir under `Cfg.RestoreDir` and compares sha256 against the manifest:
   every file when there are ≤500, otherwise an evenly spread sample of 300 that
   shifts each day. It then runs `restic check --read-data-subset=5%`. Status is
   `ok` only when both pass; otherwise `failed` (with up to 10 mismatching
   paths), `no_snapshot` or `no_manifest` (a snapshot made before v0.4).
3. Results go to `backup_verifications` (snapshot id, account, started,
   finished, files_checked, mismatches, check_ok, status, error, trigger).
4. **Weekly schedule**: on each 10-minute housekeeping tick, at most one active
   account whose last verification is older than 7 days is verified. Only one
   runs at a time panel-wide (a mutex; a manual request at the same time gets
   409 `server_busy`), with a 30-minute limit. It can be turned off with the
   setting `backup_verify_auto=0`.

### API

| Method | Path | Permission |
|---|---|---|
| GET | `/api/v1/admin/backups/verifications[?account=id]` | `backups.read` + account ownership |
| POST | `/api/v1/admin/accounts/{id}/backups/verify` | `backups.verify` (super/server/security admin) |
| DELETE | `/api/v1/admin/accounts/{id}/backups/{snap}` | `backups.delete` (super/server admin only) |
| GET | `/api/v1/user/backups/verification` | own account; agent error detail stripped |

Resellers and technical users have no `backups.verify`/`backups.delete`. Every
call is audit-logged (`backup.verify`, `backup.delete`).

## Separate credentials (compromised account cannot delete backups)

* The repository password (`/etc/bpanel/restic/<account>.pass`), target
  credentials and manifests are **root-owned 0600** files. `CheckSecretFile`
  refuses to run restic if a file has group/other bits set or is not owned by
  root. Hosting accounts never receive them, so a compromised account can
  neither read nor decrypt nor delete its repository.
* Repositories live outside account homes (`/var/backups/bpanel`, 0700 root).
* Deleting a snapshot is only possible through the agent action
  `backup.delete`, reachable only from the panel API route guarded by the
  `backups.delete` permission (admins only), and audited.
* `--no-lock` is refused by the runner.
* **For S3 we recommend** a bucket with *Object Lock* (compliance or governance
  mode) and/or credentials whose policy allows `PutObject`/`GetObject`/`ListBucket`
  but **not** `DeleteObject`, so that even a fully compromised server cannot
  erase old backups. Pruning then runs from a separate, trusted host with
  delete-capable keys. For SFTP, use a separate restricted user on the backup
  server (e.g. `rest-server --append-only` or an rrsync/chroot set-up). The
  `object_lock` flag on a target is informational only; enforcement is the
  provider's.
* Repository passwords and target credentials live in the secret store
  (`internal/secrets`, AES-256-GCM): records `backup/repo/<user>` and
  `backup/target` (JSON `s3_access_key`/`s3_secret_key`). Before every
  `backup.*` agent call (`agentCall`/`agentCallCtx` → `preBackupCall`) the panel
  pushes them with `backup.creds.load`; the agent keeps them **in memory only**
  and gives restic `RESTIC_PASSWORD` in the child environment (never a file,
  never argv, scrubbed from error text). `BackupCredsLoad/Export` implement
  `String()` as `[redacted]`; params are never logged by the agent.
* One-time migration (housekeeping start, and lazily on first use): for each
  account without a record, `backup.creds.export` reads the legacy
  `<restic_pass_dir>/<user>.pass` (0600/root check) and optional
  `backup_creds_file`; the value is stored unchanged (or a new 256-bit
  password is generated when no file exists), then `backup.creds.load
  {retire:true}` deletes the legacy file only if it equals the stored value.
  Idempotent: re-runs find the record and export nothing.
* Safety: if the agent has no password in memory, the legacy file is gone and
  the repository exists, the agent refuses with `backup_creds_missing` instead
  of generating a new password (which would make the repo unreadable). If the
  secret store is unavailable (master key unreadable) the panel skips the push
  and backups continue on the legacy file (logged, no values).
* Rotation: `POST /api/v1/admin/secrets/rotate` (permission `secrets.rotate`,
  held only by super_admin; recent auth required; API tokens refused) rotates
  the master key, re-encrypts every record and returns `{key_id,
  previous_key_id, reencrypted}`; audited as `secrets.rotate`. Repository
  passwords themselves are not changed by a master-key rotation.

## Admin UI (v0.4 part B)

Admin → *Backups* (`/backups`, tool "Backup Configuration"): per account the
last restore verification (status, time, files checked, mismatches) with a
"Verify now" button (`POST /admin/accounts/{id}/backups/verify`), last
scheduled backup and its retention outcome (`GET /admin/backups/overview`,
`backups.read`; resellers see only their own accounts), and the policy form.
Keys `backup.*` in EN + TR.

## Verified (real restic 0.19.1 linux/arm64, SHA256 checked against the release's SHA256SUMS)

`go test -tags restictest -run TestResticEndToEnd ./internal/backup` (output in
`work/v04/backup/e2e-output.txt`):

* backup of a temp account (4 files including a SQL dump, `backups/` excluded) → manifest 4 files
* retention `forget --prune` → 1 snapshot kept
* the live files are changed (index.php defaced, dump deleted) → single-file restore of `db/shop.sql`: sha256 matches, nothing else restored
* full-account restore: all 4 files identical, the excluded file is absent
* `VerifyRestore` (clean): `status=ok files_checked=4 mismatches=0 check_ok=true`
* after 64 bytes of each pack file are flipped: `status=failed check_ok=false`, the restore reports `ciphertext verification failed`
* part B (`TestResticEnvPasswordRetention`, output in `work/v04/backup/e2e-partb-output.txt`): password only via `RESTIC_PASSWORD` (no file), 3 backups, `forget --keep-last 1 --prune --json` → kept=1 removed=2, 1 snapshot left; a wrong password fails without echoing it
* unit/API (fakes): `TestBackupCredsLoadForgetRetire` (agent: fake restic sees `forget --prune … --json` with PWENV set and no password file; legacy file retired only on equal value; `backup_creds_missing` re-key guard), `TestBackupRetentionAfterScheduledBackup`, `TestBackupPasswordMigrationIdempotent` (value never in logs/audit/clear DB), `TestBackupCredsSecretStoreUnavailable`, `TestSecretsRotateAuth` (server_admin/security_admin/auditor 403, stale session `reauth_required`, super_admin 200 new key id, values still open, audited)

## Not verified here

* SFTP over a real **SSH** transport (host keys, `~/.ssh/config`): this sandbox has no `ssh`/`sshd`; see *Storage backends* for what was run instead.
* AWS S3 / Ceph RGW / Backblaze B2-S3 / Cloudflare R2 themselves (only the S3 protocol via `rclone serve s3`).
* The agent-level `backup.verify` running as root on a real host (the API is tested against a fake agent; the engine it calls is tested with real restic).
* MariaDB dump snapshots (`--stdin`) are not part of the restore verification yet (only the `files` snapshot is).

## Storage backends (v0.4 baox)

Repositories live in one of three free, open targets (`internal/backup/target.go`); restic (BSD-2-Clause) is invoked as a separate process, credentials reach it only through its environment and are scrubbed from its output.

| Target | Repository URL | Credentials | Real test (`-tags realstorage`) |
|---|---|---|---|
| `local` | `<path>/<account>` | none | `TestResticEndToEnd` (`-tags restictest`) |
| `sftp` | `sftp:user@host:/path/<account>` (port ≠ 22: `sftp://user@host:port//path/<account>`) | root's SSH key / `~/.ssh/config` (never in BPANEL) | `TestRealStorageSFTP` |
| `s3` | `s3:<scheme>://<endpoint>/<bucket>/<prefix>/<account>` | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env only | `TestRealStorageS3` |

Any S3-compatible service works (self-hosted Garage, SeaweedFS, Ceph RGW, `rclone serve s3`, or a provider's free tier). BPANEL does not require or recommend a paid service. Note: MinIO's community server binaries are no longer distributed (`dl.min.io` answers *410 Gone*, 2026-10-10), so MinIO was not used.

Running the real tests:

```
BPANEL_RESTIC=/path/restic BPANEL_RCLONE=/path/rclone \
  go test -tags "realstorage restictest" -count=1 -v ./internal/backup
```

Each test skips with a reason when a binary is missing.

Verified on 2026-10-10 (linux/arm64, restic 0.19.1 and rclone v1.75.2, both SHA-256 checked against their release `SHA256SUMS`):

* **S3**: `rclone serve s3` (real S3 HTTP API with SigV4 auth keys) on 127.0.0.1. The `Engine` ran 2 backups (deduplicated), `snapshots` = 2, full restore byte-identical, `check --read-data-subset 100%` ok, and the repo objects sat in `<bucket>/<prefix>/<account>/`. A wrong secret key was rejected and the error did not contain either key.
* **SFTP**: no `sshd` and no `ssh` client exist in the sandbox, and `pkg/sftp` is not a dependency (it was not added). Instead, restic's SFTP backend talked to a real SFTP server (`rclone serve sftp --stdio`) via `-o sftp.command=…` passed through `Engine.Run`: init, 2 backups, `snapshots` = 2, restore byte-identical, and `check --read-data` all passed, with the repo on the server under `/srv/restic/alice`. This covers the SFTP protocol and the Engine plumbing (password env, cache, scrubbing). It does **not** cover the SSH transport or host-key verification.
