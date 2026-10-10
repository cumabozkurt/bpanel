# BPANEL operations runbook

## 1. Monitoring
- **Admin → Monitoring & Health** (`/monitoring`): OS health checks, disks/inodes, file integrity, settings and log retention.
- **Prometheus:** scrape `/metrics` on the admin port (see `examples/prometheus/bpanel-scrape.yml`). Local scrape needs no
  token while "allow localhost" is on; a remote Prometheus needs an admin API token with `server.read`.
  Import `examples/grafana/bpanel-dashboard.json` into Grafana (free OSS edition) and pick the Prometheus data source.
- Quick check from the host: `curl -sk https://127.0.0.1:<admin-port>/metrics | head`.

## 2. Alerts
- **Admin → Alerts & Incidents** (`/alerts`) → *Rules*: enable/disable, severity, threshold, cooldown.
- *Channels*: add email (needs a working local MTA on 127.0.0.1:25), Telegram (BotFather token + chat id),
  Slack or Discord incoming webhook. Press **Test** after adding. The last result column shows the error code.
- To fan alerts out to other systems, create a webhook (Admin → Webhooks) subscribed to `alert.*`.
- Alert checks run every 5 minutes (setting *Alert check interval*); *Run checks now* = `POST /api/v1/admin/obsx/evaluate`.

## 3. Incident handling
1. Open `/alerts`, filter *Active*. Click the incident to see detail and history.
2. **Acknowledge** to show you are on it; **Assign to me** (or assign another admin via API `assignee_id`).
3. Add notes while working (each note is kept in history with your name and time).
4. **Resolve** when fixed. Metric incidents (disk, certificate, service) resolve automatically when the condition clears.
5. A recurrence after resolve opens a new incident; while open, repeats only increase *Count* and notify once per cooldown.
6. Resolved incidents are pruned after *Resolved incidents* retention days (default 365).

## 4. Common failures and recovery
| Symptom | Likely cause | Recovery |
|---|---|---|
| `disk_full` incident | logs, backups or a tenant filling `/` or `/home` | `du -xh --max-depth=1 /var /home | sort -h`; rotate/compress logs; lower backup retention; check `bpanel_inode_used_ratio` for inode exhaustion (many small files, e.g. session dirs) |
| `cert_expiring` | AutoSSL failing (DNS not pointing, rate limit) | Domains → SSL → retry; check DNS A/AAAA; review agent log for `acme_*` errors |
| `service_down` | crashed or failed unit | Admin → Services → restart; `journalctl -u <unit> -n 100`; fix config (`nginx -t`, `php-fpm -t`) before restart |
| `backup_failed` | repository unreachable, wrong credentials, disk full | Backups → run verify; rotate credentials (Admin → Secrets); check free space on target |
| `failed_login_burst` | brute force | Brute-force page: confirm bans; consider firewall rate limits; check audit log for successful logins from the same IPs |
| `job_failures` | background job error | `GET /api/v1/jobs/{id}` for the error code; retry the action |
| `fim_change` | config edited or binary replaced | Compare with the change you made. Expected (upgrade, admin edit) → **Record new baseline**. Unexpected → treat as compromise: isolate host, compare package checksums (`debsums -c` / `rpm -Va`), rotate secrets |
| `shield_detection` | malware upload | Shield page → review quarantine; restore false positives; notify the account owner |
| Channel last result `obsx_smtp_unavailable` | no local MTA | install/start Postfix, or use Telegram/Slack/Discord |
| Channel last result `obsx_send_failed` | revoked webhook/token, network egress blocked | re-enter the secret (edit channel); check outbound HTTPS |
| Health `time_sync` warning | NTP not synchronised | `timedatectl set-ntp true` or `systemctl restart chronyd`; check UDP 123 egress |
| Health `raid` failed | degraded md array | `cat /proc/mdstat`, `mdadm --detail /dev/mdX`; replace disk, `mdadm --add` |
| Health `smart` failed | failing disk | back up immediately; schedule disk replacement |
| Health `log_rotation` warning | logrotate timer/cron not running | `systemctl status logrotate.timer`; run `logrotate -d /etc/logrotate.conf` to debug |
| `/metrics` 403 | no admin token, remote client, or "allow localhost" off | use a bearer admin token; or scrape from 127.0.0.1 |
| Agent errors in `bpanel_agent_calls_total{result="error"}` | agent down or timeouts | `systemctl status bpanel-agent`; restart; check socket permissions |

## 5. Retention
Monitoring → Settings → *Log retention*: audit log (default 180 d), events (90 d), bandwidth history (400 d),
resolved incidents (365 d). Pruning runs with hourly housekeeping.
