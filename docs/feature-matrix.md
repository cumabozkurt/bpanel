# Feature matrix: cPanel/WHM vs. BPANEL v1.0.0 (v0.4 feature set)

v1.0.0 did not add or remove features; the statuses below are those of v0.4.0.

Snapshot: 2026-10-10 (v0.4.0). Rows are taken from the code, not from plans: every BPANEL location
below is a tool id in `web/src/lib/tools.js` that routes to a page in `web/src/lib/App.svelte`
(checked by `work/v04/docsx/routecheck.py`: 96 tool links, 0 dead) backed by an API in `internal/api/*`
and, where privileged, an agent action in `internal/agent/*`. No tool carries a `soon` flag any more.

**Status labels**

- **working**: implemented and exercised end to end with the real root agent (v0.3 E2E audit,
  `audit/verification-v0.3.md`) in a container. Still **not run on a real Ubuntu 24.04 / AlmaLinux 9
  VM with systemd as PID 1** (nothing in BPANEL has been, see README "Known limitations").
- **working-unverified-on-real-host**: implemented in API + agent + UI (EN/TR) with unit / mock-agent /
  API tests passing (module `work/v04/<module>/REPORT.md`), but the external service it drives
  (Postfix, Dovecot, Rspamd, nftables, ModSecurity, pdnsutil, …) was not running in the sandbox, so the
  real-service path is untested. Without the service the API returns `not_installed`/`unsupported`.
- **partial**: implemented but narrower than the cPanel/WHM feature (gap in notes).
- **not planned**: not in BPANEL (v0.4); reason in notes. Free alternative named where one exists.

Every component in the "free component" column is free/open source (licences in
`third-party-licenses.md`); no row depends on a paid product (FREE-ONLY rule, `architecture.md` §3).

## A. cPanel (user) features

| Feature (cPanel) | BPANEL location | Status | Free component used | Notes |
|---|---|---|---|---|
| Email Accounts | user › Email › `email_accounts` `/email/accounts` | working | Postfix, Dovecot | quotas capped by package (R2-UX-15), SHA512-CRYPT |
| Forwarders | `forwarders` `/email/forwarders` | working | Postfix | |
| Default Address (catch-all) | `default_address` `/email/forwarders?catchall=1` | working | Postfix | |
| Webmail | `webmail` (action, SSO) | working | Roundcube 1.6 (GPL-3.0+) | |
| Email Deliverability (SPF/DKIM/DMARC) | `deliverability` `/email/deliverability` | working | Rspamd DKIM, PowerDNS | no MTA-STS/TLS-RPT/BIMI |
| Email Disk Usage | `email_disk_usage` | working | Dovecot quota | |
| Autoresponders | `autoresponders` `/email/autoresponders` | working-unverified-on-real-host | Dovecot Pigeonhole (Sieve vacation) | mailx |
| Email Filters (user) | `email_filters` `/email/filters` | working-unverified-on-real-host | Sieve | mailx; no separate "Global Email Filters" page |
| Spam Filters (SpamAssassin) | `spam_filters` `/email/spam` | working-unverified-on-real-host | Rspamd (Apache-2.0) | per-user threshold, allow/deny lists |
| Mailing Lists (Mailman) | `mailing_lists` `/email/lists` | working-unverified-on-real-host | mlmmj (MIT) | mlmmj instead of Mailman |
| Track Delivery | `track_delivery` `/email/track` | working-unverified-on-real-host | Postfix mail log | |
| Email Routing / BoxTrapper / Encryption (GnuPG) / Calendars & Contacts | — | not planned | (CalDAV: Radicale/SabreDAV could be added) | |
| File Manager | `file_manager` `/files` | working | agent fileops | upload goes through Shield scan when configured |
| Disk Usage | `disk_usage` `/disk` | working | quota | |
| Resource Usage (CloudLinux LVE) | `resource_usage` `/usage` | working-unverified-on-real-host | cgroup v2 | cgroup reads verified in a child cgroup on the sandbox kernel; not under systemd PID 1 |
| FTP Accounts | `ftp_accounts` `/ftp` | working | Pure-FTPd (ISC) | no "FTP Connections" page |
| Backup / Backup Wizard | `backups` `/backups` | working | restic 0.19 (BSD-2) | local repo E2E (v0.3); SFTP/S3 targets + verify are unverified on real host |
| File Restoration | `file_restore` `/backups` | working | restic | |
| Directory Privacy | `directory_privacy` `/web/privacy` | working-unverified-on-real-host | nginx/Apache basic auth | webx |
| Git Version Control | `git` `/git` | working-unverified-on-real-host | git (GPL-2.0, separate process) | devx |
| MySQL Databases / Wizard | `mysql_databases`, `db_wizard` `/databases` | working | MariaDB (GPL-2.0, external server) | |
| phpMyAdmin | `phpmyadmin` (SSO) | working | phpMyAdmin 5.2 (GPL-2.0+) | |
| Remote MySQL | `remote_mysql` `/databases/remote` | working-unverified-on-real-host | MariaDB | dbx |
| PostgreSQL Databases / phpPgAdmin | `postgresql` `/postgresql` | partial | PostgreSQL (PostgreSQL License) | DBs/users/grants; no phpPgAdmin web UI |
| Database processes (MySQL process list) | `db_processes` `/databases/processes` | working-unverified-on-real-host | MariaDB | |
| Domains / Addon / Subdomains / Aliases | `domains`, `subdomains`, `aliases` `/domains` | working | nginx, Apache | |
| Redirects | `redirects` `/domains?redirects=1` | working | nginx/Apache | |
| Zone Editor | `zone_editor` `/dns` | working | PowerDNS auth (GPL-2.0, HTTP API) | |
| DNSSEC / zone import-export / history | `dns_tools` `/dnsx` | working-unverified-on-real-host | pdnsutil | dnsx |
| Dynamic DNS | `dynamic_dns` `/ddns` | working-unverified-on-real-host | PowerDNS | devx |
| Errors / Raw Access | `errors`, `raw_access` `/logs/:kind` | working | web server logs | |
| Visitors / Awstats / Webalizer | `visitors` `/logs/access` | partial | access log | log viewer only, no Awstats-style statistics |
| Bandwidth | `bandwidth` `/bandwidth` | working-unverified-on-real-host | log accounting | usagex |
| SSL/TLS Status, AutoSSL | `ssl_status` `/ssl` | working | lego ACME (MIT), Let's Encrypt | AutoSSL against LE staging not run on a real VM |
| Two-Factor Authentication | `two_factor` `/security` | working | TOTP (stdlib) | recovery codes |
| SSH Access | `ssh_access` `/ftp` | partial | OpenSSH | SFTP/shell flag per account; no SSH key manager page |
| IP Blocker | `ip_blocker` `/web/ip-blocker` | working-unverified-on-real-host | nginx/Apache deny | webx |
| Hotlink Protection | `hotlink` `/web/hotlink` | working-unverified-on-real-host | nginx/Apache | webx |
| Leech Protection / Indexes | — | not planned | | Indexes partly via error pages / MIME; leech protection not built |
| Manage API Tokens | `api_tokens` `/api-tokens` | working-unverified-on-real-host | stdlib | usagex |
| ModSecurity (per domain) | `modsecurity` `/modsecurity` | working-unverified-on-real-host | ModSecurity (Apache-2.0) + OWASP CRS (Apache-2.0) | netsec WAF |
| Imunify360 / malware scan (user) | `malware_scans` `/malware-scans` | working-unverified-on-real-host | ClamAV (GPL-2.0), YARA (BSD-3), native heuristics | Shield replaces Imunify360 |
| MultiPHP Manager | `multiphp` `/php` | working | PHP-FPM, Remi (EL) | |
| MultiPHP INI Editor | `php_ini` `/php-ini` | working-unverified-on-real-host | PHP-FPM | usagex |
| WordPress Toolkit | `wordpress` `/wordpress` | working-unverified-on-real-host | WP-CLI (MIT), WordPress (GPL-2.0+) | appx |
| Softaculous (app installer) | `app_installer` `/installer` | working-unverified-on-real-host | pinned official tarballs (WordPress, Joomla, Drupal, Nextcloud) | free replacement for Softaculous; checksum-pinned catalogue |
| Application Manager (Node.js/Python) | `nodejs` `/apps` | working-unverified-on-real-host | Node.js, Python (admin-installed) | systemd `bpanel-app@` units; Ruby not supported |
| Cron Jobs | `cron_jobs` `/cron` | working | cron | |
| Terminal | `terminal` `/terminal` | working-unverified-on-real-host | stdlib PTY + WebSocket | runs in the account cage |
| Track DNS | `track_dns` `/track-dns` | working-unverified-on-real-host | miekg/dns (BSD-3), traceroute | |
| Error Pages | `error_pages` `/web/error-pages` | working-unverified-on-real-host | nginx/Apache | webx |
| MIME Types | `mime_types` `/web/mime` | working-unverified-on-real-host | nginx/Apache | webx |
| Apache Handlers / Site Publisher / Images / Cloudflare / Ruby Gems | — | not planned | | Cloudflare would be an external account; not required |
| Password & Security | `password_security` `/security` | working | argon2id | |
| Change Language / Theme | `change_language`, `theme` `/preferences` | working | — | EN + TR |
| Contact Information | `contact_info` `/contact-email` | working-unverified-on-real-host | — | adminx |
| User Manager (sub-users) | `user_manager` `/user-manager` | working-unverified-on-real-host | — | adminx |

## B. WHM (admin / reseller) features

| Feature (WHM) | BPANEL location | Status | Free component used | Notes |
|---|---|---|---|---|
| Basic WebHost Manager Setup / Nameservers | `basic_setup`, `nameservers` `/settings` | working | — | |
| Server Information | `server_info` `/server` | working | sysinfo | |
| Update Preferences | `update_prefs` `/update-prefs` | working-unverified-on-real-host | apt / dnf | adminx |
| Server status / health monitoring | `monitoring` `/monitoring` | working-unverified-on-real-host | smartctl, chronyc, `/metrics` for Prometheus | obsx |
| Notifications / contact manager | `alerts` `/alerts` | working-unverified-on-real-host | SMTP, Telegram/Slack/Discord webhooks (free) | obsx |
| Security Center: 2FA | `two_factor` `/security` | working | TOTP | |
| Security Advisor / audit trail | `audit_log` `/audit`, `sec_events` `/events` | working | SQLite FTS5 | events table + webhooks (`/webhooks`) |
| cPHulk Brute Force Protection | `brute_force` `/brute-force` | working-unverified-on-real-host | fail2ban (GPL-2.0, separate process), optional CrowdSec (MIT, CAPI off) | |
| Firewall (CSF equivalent) | `firewall` `/firewall` | working-unverified-on-real-host | nftables (`table inet bpanel` only) | lockout guard + confirm/rollback; nf_tables netlink missing in sandbox |
| ModSecurity Tools / Vendors | `firewall` `/firewall`, user `modsecurity` | working-unverified-on-real-host | ModSecurity + OWASP CRS | no paid rule vendors |
| List Accounts / Suspended | `list_accounts`, `list_suspended` `/accounts` | working | — | server-side paging |
| Create / Terminate / Suspend / Password | `create_account` `/accounts/new`, `/accounts?action=…` | working | system users | |
| Modify an Account / Change contact e-mail | `modify_account` `/modify-account` | working-unverified-on-real-host | — | adminx |
| Resellers: list / create / edit privileges | `list_resellers`, `create_reseller`, `edit_reseller` `/edit-reseller` | working-unverified-on-real-host | — | reseller ACL middleware (adminx) |
| Packages | `packages`, `add_package` `/packages` | working | — | |
| CloudLinux LVE limits / CageFS | `resource_limits` `/limits` | working-unverified-on-real-host | cgroup v2 slices, bubblewrap (LGPL-2.0+), systemd sandboxing | free replacement for CloudLinux; kernel test output in `work/v04/isolation/` (child cgroup), not under systemd PID 1 |
| MultiPHP Manager / PHP-FPM | `php_versions` `/php` | working | PHP-FPM | |
| EasyApache 4 (PHP extensions, modules) | `/php` | partial | distro packages | versions only; no per-module profile builder |
| Service Manager / Restart Services | `service_manager`, `restart_services` `/services` | working | systemd | critical units cannot be stopped |
| SQL Server settings / Remote MySQL | `db_settings` `/db-settings` | working-unverified-on-real-host | MariaDB, PostgreSQL | dbx |
| DNS Cluster | `dns_cluster` `/dns-cluster` | working-unverified-on-real-host | PowerDNS AXFR/NOTIFY | clusterx |
| Backup Configuration | `backup_config` `/backups` | partial | restic (local, SFTP, S3-compatible) | policy UI + verify; remote targets unverified; no full-server DR image |
| Transfer Tool (cPanel cpmove import) | `transfer_tool` `/transfer` | working-unverified-on-real-host | stdlib tar/gzip, SSH | xfer; imports cpmove archives without a cPanel licence |
| Bandwidth (all accounts) | `bandwidth` `/bandwidth` | working-unverified-on-real-host | log accounting | |
| Manage Plugins | `plugins` `/plugins` | working-unverified-on-real-host | ed25519-signed plugins (stdlib) | clusterx |
| Integrations (detect external engines) | `integrations` `/integrations` | working-unverified-on-real-host | provider registry | lists ClamAV/YARA/maldet/CrowdSec; commercial agents detect-only, never required |
| API documentation | `api_docs` `/openapi.json` | working | OpenAPI JSON | |
| Mail Queue Manager / Mail Troubleshooter | — | not planned | (postqueue could back it) | not built in v0.4 |
| IP Functions / Change Hostname / Tweak Settings | — | partial / not planned | | hostname set at install + `/settings`; no IP pool manager |
| WHMCS / billing hooks | — | not planned | | webhooks + API tokens are the integration point |

## C. Beyond cPanel/WHM (free, built in)

| Feature | BPANEL location | Status | Free component used | Notes |
|---|---|---|---|---|
| BPanel Shield (real-time scan, upload pipeline, quarantine, policies) | admin `bpanel_shield` `/shield`, user `/malware-scans` | working-unverified-on-real-host | ClamAV, YARA, native heuristics, fanotify/inotify | fail-closed policy; engines absent in sandbox → `not_installed`; AES-GCM quarantine |
| WAF with OWASP CRS per domain | `/modsecurity`, `/firewall` | working-unverified-on-real-host | ModSecurity v2/v3 + CRS | |
| Per-account isolation (cgroup v2 + bwrap cage + hardened FPM units) | `/limits`, `/usage` | working-unverified-on-real-host | Linux kernel, bubblewrap, systemd | |
| Multi-server (mTLS remote agents, per-node CA) | `servers` `/servers` | working-unverified-on-real-host | stdlib crypto/tls | `bpanel-agent join`; tested over loopback mTLS |
| Plugins (signed) | `/plugins` | working-unverified-on-real-host | ed25519 | example in `examples/plugins/` |
| Metrics / alerts / FIM | `/monitoring`, `/alerts` | working-unverified-on-real-host | Prometheus text format, Grafana example dashboard (optional, not bundled) | |
| Fine-grained RBAC + security events + webhooks | `/events`, `/webhooks` | working-unverified-on-real-host | stdlib HMAC | |
| Secrets at rest (AES-256-GCM envelope) | CLI `bpanel secrets` | partial | stdlib; OpenBao (MPL-2.0) optional | owned by the secrets worker; 2 error codes still lack EN/TR text at time of writing |

## Parity

Tally of tables A + B (computed by script from the rows above; a row with two labels counts under the first):

| Status | A (cPanel) | B (WHM) | Total rows |
|---|---|---|---|
| working | 23 | 10 | 33 |
| working-unverified-on-real-host | 28 | 15 | 43 |
| partial | 3 | 3 | 6 |
| not planned | 3 | 2 | 5 |
| **rows** | 57 | 30 | 87 |

The 5 "not planned" rows bundle 14 individual cPanel/WHM features (Email Routing, BoxTrapper, Email
Encryption, Calendars & Contacts; Leech Protection, Indexes; Apache Handlers, Site Publisher, Images,
Cloudflare, Ruby Gems; Mail Queue Manager, Mail Troubleshooter; WHMCS hooks). To avoid flattering the
score they are counted individually, giving a denominator of 87 − 5 + 14 = **96 features**.
Partial counts as half.

- **Feature parity (implemented):** (33 + 43 + 0.5 × 6) / 96 = 79 / 96 = **82.3 %**
  (per row, without un-bundling: 79 / 87 = 90.8 %).
- **Verified parity (working = container E2E with the real agent):** 33 / 96 = **34.4 %**.
- **Verified on a real Ubuntu 24.04 / AlmaLinux 9 host with systemd as PID 1: 0 %.**

Headline: about 82 % of the cPanel/WHM feature set is implemented with free software, about a third is
verified end to end in a container, and none has yet been run on a production-like host. The
"beyond cPanel" rows (table C: 7 working-unverified, 1 partial) are not counted in the parity score.
