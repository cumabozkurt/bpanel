# Account transfer & migration (v0.4, spec §10) — Transfer Tool

Admin page: **Transfer Tool** (`/transfer`, perms `xfer.read` / `xfer.write`, ServerAdmin role by default).
Steps: source → analyse/preview → conflicts → import job → report. Everything is free/open-source (stdlib Go,
OpenSSH `scp`, optional `sshpass` [GPL, external process only], MariaDB client tools).

## Sources
- **Archive on this server**: any `*.tar.gz|*.tgz|*.tar` in the agent's transfer directory `/var/lib/bpanel/xfer`
  (root, 0700). Names are basenames only (`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.(tar\.gz|tgz|tar)$`); symlinked archives are refused.
- **Remote pull** (`POST /admin/xfer/fetch`, job `xfer.fetch`): host/port/user/remote path + private key or password.
  The credential is written to the SecretStore (`xfer.fetch.<random>`) and deleted when the job ends (success or failure).
  The agent re-validates, resolves the host and refuses loopback, link-local (incl. 169.254.169.254), unspecified, multicast,
  0/8 and — unless "allow private" is ticked — RFC1918/ULA/CGNAT; it pins the checked IP and runs
  `scp -s -P <port> -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/var/lib/bpanel/xfer/.known_hosts -o ConnectTimeout=20 -o HostKeyAlias=<host> [-o BatchMode=yes -i <0600 keyfile>] -- user@IP:/path dest`
  (argv, SFTP mode so the remote side never shell-expands the path; password via `sshpass -e`, env only). Max 100 GiB, 2 h timeout.
- Browser upload: **not implemented** (large archives; use remote pull or place the file in the directory).

## Formats
- **BPanel archive** (export): tar.gz with `homedir/…`, `mysql/<db>.sql` (mariadb-dump without `--databases`, so no
  `CREATE DATABASE`/`USE`), `dnszones/<domain>.zone` (dnsx BIND export), `mail/mailboxes.json` (addresses/quotas; no hashes),
  and `manifest.json` last: `{format:"bpanel-xfer", version:1, account, domains, databases, zones, forwarders, certs, files:[{path,size,sha256}]}`.
  On analyse every member must be listed with matching size + SHA-256; missing or extra members → `xfer_checksum_mismatch`.
  Export skips `.ssh/`, symlinks that leave the home, special files, and (as root) files not owned by the account (hard-link guard).
- **cPanel** `cpmove-USER.tar.gz` / `backup-DATE_USER.tar.gz` (public layout): `cp/USER`, `userdata/main` + `userdata/<domain>`,
  `homedir/`, `mysql/*.sql`, `dnszones/*.db`, `va/<domain>` forwarders (pipes, files and `:fail:` targets dropped),
  `etc/<domain>/passwd|shadow|quota`. Listed as *not imported* with a reason: `mysql.sql` grants, SSL certs/keys (re-issue
  with Let's Encrypt), cron (never auto-imported), `vf/` filters, FTP, PostgreSQL, Mailman, DKIM keys, nested `homedir.tar`, team users, other cPanel internals.
- **HestiaCP**: recognised (`hestia/`, `pam/passwd`) → `xfer_format_unsupported`. Import is a follow-up (nested tar.zst payloads).

## Safety of archive handling (internal/xfer)
Parse only, never execute. Each entry name is canonicalised (no absolute paths, `..`, NUL, drive letters); hard links, devices,
FIFOs are refused; symlinks are accepted only when their target stays inside the archive root; limits on entry count, entry
size and total size (`xfer_archive_too_large`). Extraction goes through `os.Root` (no escape even via links created earlier),
never writes through an existing symlink, refuses symlinked parent dirs, strips setuid/setgid, chowns to the account.

## Import job (`POST /admin/xfer/import`, job `xfer.import`)
1. Agent `xfer.analyse` again; conflicts (username exists/reserved, domain exists, target DB exists) → `xfer_conflict`, nothing created.
2. `CreateAccount` (package: chosen, or same name as source plan, else `default`; random password → *action required*).
3. Domains via the account's own `createDomain` (addon, sub → sub of main, parked → alias), DNS via dnsx zone import (merge),
   home via agent `xfer.restore_home` (`.ssh/` never imported), databases via `newDatabase` + agent `xfer.restore_db`
   (mysql client runs **as the account's Unix user** with a temporary MariaDB login granted only on that database, `--local-infile=0`,
   `--binary-mode`, `--force`; login dropped afterwards), mailboxes via `createMailbox` (random password — hash import is a follow-up),
   forwarders via `createForwarder`. Every step goes into the report (`ok | failed | skipped | action_required`) stored in `xfer_runs.report`.

## Export (`POST /admin/accounts/{id}/export`, job `xfer.export`) → archive in the transfer directory.

## Verified / not verified
Verified by tests (synthetic fixtures built in-test, no customer data): cPanel parse, traversal/absolute/symlink/hardlink/device
rejection, oversize/entry-count limits, manifest checksum mismatch + extra member, Hestia recognition, SSRF guard + argv,
agent export→analyse→restore_home round trip (temp passwd/home), API analyse/conflicts/import job/export round trip with the fake agent, perms.
Not verified on a real host: scp/sshpass pull, mariadb-dump/mysql restore (no MariaDB in sandbox), chown as root.

## Follow-ups
HestiaCP import; mailbox password-hash import (agent action to set a crypt hash); DB users/grants from `mysql.sql`;
browser upload; installer: create `/var/lib/bpanel/xfer` 0700 root; cPanel SSL import; per-step resume of a failed import.
