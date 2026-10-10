# Usage & security extras (v0.4 usagex)

All components are free/open source (FREE-ONLY rule). fail2ban (GPL) and php-fpm are separate processes invoked with argv by the root agent; nothing GPL is linked.

## PHP INI editor (user, `/php-ini`)
- API: `GET/PUT /api/v1/user/php-ini` (own account only; version must be one the account's domains use).
- Allowlist: memory_limit (32M..package memory_mb, else 2048M), upload_max_filesize/post_max_size (≤2G, post ≥ upload), max_execution_time (1..3600), max_input_vars (100..100000), display_errors (On/Off), date.timezone (validated with the embedded Go tz database, `time/tzdata`).
- Stored in `php_ini_settings` (migration 0012). Rendered through the existing `php.pool.apply` agent action into the account's own FPM pool (`php_value[...]`); agent re-validates (iniKeyOK allowlist, now incl. post_max_size; iniValueOK), runs `php-fpm -t`, rolls back the file on failure and reloads. API restores the previous DB rows when the agent fails. Provisioning (`applyWebRec`) uses the same `phpPoolSpec`, so saved settings survive re-provisioning.
- Note: post_max_size is emitted after the template default line; FPM takes the later value.

## Resource usage (user, `/usage`)
Existing isolation sampler page/endpoint `/user/usage`; the tool now links there.

## Bandwidth (user `/bandwidth`, admin `/bandwidth`)
- Agent `usage.bandwidth.scan`: incremental read of `/var/log/bpanel/domlogs/<domain>.access.log` (domain validated, O_NOFOLLOW, regular files only), cursor = inode+offset (truncation/rotation restarts at 0), ≤32 MiB per domain per call (hard cap 256 MiB), complete lines only, lines >64 KiB skipped. Parses nginx combined `$body_bytes_sent`, aggregates per UTC day.
- API job every 15 min (`usagexLoop`, ≤4 bounded rounds), tables `bw_daily`, `bw_cursors`; housekeeping keeps 400 days and drops cursors of deleted domains. `POST /admin/bandwidth/collect` runs it now.
- Views: `GET /user/bandwidth?month=YYYY-MM` (own), `GET /admin/bandwidth` (admin all, reseller own accounts, technical granted accounts).
- Limits: aliases share the parent vhost log; static files with `access_log off` are not counted. Rotated-away data written between the last scan and rotation is lost (logrotate `delaycompress` keeps `.1`; not read).

## API tokens (user, `/api-tokens`)
UI over existing `/account/tokens` (create needs recent re-auth; modal calls `/account/reauth`). Perms offered: hosting.read / hosting.write.

## ModSecurity (user, `/modsecurity`)
- `GET /user/waf`, `PUT /user/waf/{domain}` — own non-alias domains only, reuses the netsec WAF apply path (CRS, configtest + rollback).
- `PUT /admin/accounts/{id}/waf/{domain}` (accounts.write + canManageAccount: admin, reseller for own accounts) sets the mode and optional `lock`; a locked domain returns `waf_locked` to the user. Table `waf_locks`.

## Brute-force protection (admin, `/brute-force`)
- `GET /admin/brute-force`: fail2ban jails (`fail2ban-client status [jail]`), netsec temporary blocks, allowlist. `not_installed` / `not_running` reported honestly.
- `POST /admin/brute-force/unban` (`fail2ban-client set <jail> unbanip <ip>`), allowlist CRUD (`bf_allowlist`) pushed as runtime `addignoreip/delignoreip` to every running jail. Temporary blocks are removed via the existing `/admin/firewall/blocks/{id}`.
- Limit: runtime ignoreip is not persisted into jail.local; after a fail2ban restart re-add or edit the allowlist (follow-up: write `/etc/fail2ban/jail.d/bpanel-allow.local`).

## Verified / not verified
Verified by unit/API tests with fakes (parser, rotation, symlink refusal, f2b parsers, not_installed path, ownership, lock, rollback). Not verified against a real nginx/php-fpm/fail2ban here (none installed in sandbox).
