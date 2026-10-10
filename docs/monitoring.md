# Monitoring, alerts, incidents, FIM and OS health (v0.4 obsx)

Spec §8 (monitoring, alerts, incident assignment and resolution history), §14 (notifications), §15 (OS health).
Everything here is free: stdlib Go, free software run as separate processes, and free incoming-webhook
services. No paid component, licence or API.

## Code map
| Part | Files |
|---|---|
| Core (no deps, unit-tested) | `internal/obsx/metrics.go` (text exposition writer + HTTP/agent recorder), `alerts.go` (rules, cooldown, dedup, incident state machine), `fim.go` (scan/diff), `health.go` (parsers) |
| Agent (root) | `internal/agent/obsx.go`: `obsx.fim.scan`, `obsx.os.health` (both `gateExempt`, read-only, no API parameters) |
| RPC types | `internal/agentrpc/obsx.go` |
| API | `internal/api/obsx.go` (`mountObsx`, `/metrics`, alert engine, incidents, channels, FIM, settings, retention prune) |
| Migration | `internal/store/migrations/0021_obsx.sql` (obsx_rules, obsx_channels, obsx_incidents, obsx_incident_history, obsx_fim_baseline) |
| UI | `web/src/lib/pages/admin/Monitoring.svelte` (`/monitoring`), `Alerts.svelte` (`/alerts`), keys `obsx.*` EN/TR |
| Mock agent | `internal/mockagent/obsx.go` (every health check reports `unsupported: simulated by the mock agent`) |
| Examples | `examples/prometheus/bpanel-scrape.yml`, `examples/grafana/bpanel-dashboard.json` |

## Prometheus `/metrics`
Served on the **admin realm only** (the user realm answers 404). Access: an admin session or admin API token
(bearer) whose staff role has `server.read`, or a loopback client (127.0.0.1/::1, no `X-Forwarded-For`)
while *Allow unauthenticated /metrics scrapes from localhost* is on (setting `obsx_metrics_localhost`, default on).
Format: Prometheus text exposition 0.0.4 written with the stdlib (no client library).

| Metric | Type | Labels | Source |
|---|---|---|---|
| `bpanel_http_requests_total` | counter | method, route (chi pattern, bounded), code (2xx…) | middleware `obsxHTTP` |
| `bpanel_http_request_duration_seconds` | histogram | method, route | middleware |
| `bpanel_agent_calls_total` | counter | method, result ok/error | `agentCall` / `agentCallCtx` |
| `bpanel_jobs` | gauge | status | `jobs` table |
| `bpanel_backup_last_success_timestamp_seconds` | gauge | account | `backup_runs` |
| `bpanel_shield_detections` | gauge | kind | `shield_detections` |
| `bpanel_cert_expiry_days` | gauge | domain | `domains.ssl_expires` (active certs) |
| `bpanel_disk_used_ratio`, `bpanel_inode_used_ratio` | gauge | mount (/, /home, /var; deduplicated) | agent `obsx.os.health` (cached 60 s) |
| `bpanel_account_cpu_usec`, `bpanel_account_memory_bytes` | gauge | account | newest `usage_samples` bucket (isolation sampler) |
| `bpanel_incidents` | gauge | severity | unresolved incidents |
| `bpanel_events_dropped_total` | counter | – | event bus |

Counters are in-process and reset on panel restart (Prometheus `rate()` handles resets).
Installing Prometheus/Grafana is **not** done by the installer; use the example scrape config and import the dashboard JSON.

## Alert engine
Rules (`GET/PUT /admin/obsx/rules[/{rule}]`): `backup_failed` (events backup.failed, backup.retention_failed),
`cert_expiring` (< threshold days, default 14), `disk_full` (> threshold %, disk or inodes, default 90),
`service_down` (agent `service.status`: failed, or enabled+inactive), `shield_detection` (shield.* events),
`failed_login_burst` (≥ threshold failures in 10 min, default 20), `job_failures` (failed jobs since last check),
`fim_change` (file integrity diff). Event rules run from an `events.Subscribe` hook; metric rules run every
`obsx_eval_interval_min` (default 5, 0 = off) or on `POST /admin/obsx/evaluate`.

**Dedup + cooldown:** each occurrence has a dedup key (`disk:/`, `cert:<domain>`, `backup_failed:<account id>` …).
A not-resolved incident with the same key is reused (count, last_at). Notifications go out for a new incident
and then at most once per rule cooldown. Metric conditions that clear auto-resolve their incident
(history `auto_resolved`). After resolve the next occurrence opens a new incident.

**Channels** (`/admin/obsx/channels`): email (net/smtp to 127.0.0.1:25, no auth; needs a local MTA),
Telegram bot (token + chat id), Slack incoming webhook (`https://hooks.slack.com/services/…`), Discord webhook
(`https://discord.com/api/webhooks/…`). Tokens / webhook URLs live in the SecretStore (`obsx/channel/<id>`),
are write-only, and HTTP goes through the SSRF-guarded webhook client. Each channel has a minimum severity;
last result is stored as a code only. **Webhooks are reused:** every notified alert publishes `alert.fired`
on the event bus, so an outbound webhook subscribed to `alert.*` receives it (signed, retried).

## Incidents
States `open → acknowledged → resolved`, `resolved → open` (reopen). `assign` (admin users only) and `note`
keep the state. Every action is written to `obsx_incident_history` (actor, time, note) and the audit log.
State changes are optimistic (`UPDATE … WHERE status=<read>`); a concurrent change answers 409.

## File integrity monitoring
The agent fingerprints a fixed allowlist (the API cannot pass paths): panel binaries
(`/usr/local/bin/bpanel*`, `/usr/bin/bpanel*`, `/opt/bpanel/bin`), `/etc/bpanel`, `/etc/ssh/sshd_config(.d)`,
`/etc/nginx`, `/etc/php` (php-fpm pool.d), `/etc/opt/remi`, `/etc/php-fpm.d` by SHA-256; `/etc/passwd`,
`/etc/shadow`, `/etc/group`, `/etc/sudoers` by metadata only (size, mtime, owner, mode — never read).
Max 5000 files, files > 256 MiB are metadata-only. `POST /admin/obsx/fim/baseline` stores the baseline;
checks run every `obsx_fim_interval_min` (default 360, 0 = off) or `POST /admin/obsx/fim/check`. Changes raise
`fim_change`, publish `obsx.fim_change` and write a system audit entry.

## OS health (`GET /admin/obsx/health`)
reboot-required (`/var/run/reboot-required`; unknown on non-Debian without needs-restarting), time sync
(`chronyc tracking`, else `timedatectl show`; unsupported when systemd is not PID 1), SMART (`smartctl -H`
per physical disk; not_installed without smartmontools), RAID (`/proc/mdstat`; unsupported without md),
log rotation (logrotate state file age > 48 h = warning), failed systemd units (`systemctl --failed`), disk/inode
usage. Each check returns ok / warning / failed / not_installed / unsupported / unknown with a reason.

## Log retention (`GET/PUT /admin/obsx/settings`)
`audit_days` (default 180, 7–3650; replaces the former hard-coded 180 days), `events_days`
(existing `events_retention_days`, default 90), `bandwidth_days` (`bw_daily`, default 400, 31–3650),
`incidents_days` (resolved incidents + history, default 365). Applied by the hourly housekeeping `prune`.

## Verified / not verified
Verified by tests: exposition format, auth of `/metrics`, dedup/cooldown (pure + DB), incident state machine
and history over HTTP, FIM detection on temp files (agent scan with a path prefix) and through the API,
disk rule + auto-resolve, retention prune, channel validation, secret non-disclosure, severity routing.
Not verified on a real host: actual SMTP delivery, Telegram/Slack/Discord delivery (HTTP stubbed in tests),
smartctl/chronyc/timedatectl output on real hardware (parsers tested on sample output), Prometheus/Grafana import.
