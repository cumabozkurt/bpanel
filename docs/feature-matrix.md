# Feature matrix: cPanel/WHM vs. BPANEL v1.1.0

Generated from the container E2E results by `test/e2e/tools/matrix.py` (evidence:
[`docs/evidence/e2e-v1/SUMMARY.md`](evidence/e2e-v1/SUMMARY.md)). Every row below is implemented in API +
root agent + UI (EN/TR); the status says how it was **verified**.

**Status labels**

- **verified-e2e**: driven end to end over HTTPS (admin, reseller or user session) in an Ubuntu 24.04
  container with systemd as PID 1 and the real services (Postfix, Dovecot, Rspamd, PowerDNS, MariaDB,
  PostgreSQL, nginx + Apache, PHP-FPM, ModSecurity + CRS, ClamAV, YARA, nftables, fail2ban, Radicale,
  mlmmj, Pure-FTPd, restic, Pebble ACME), and the system effect was checked (mail in the Maildir, record
  answered by `dig`, rule in `nft`, process user, file owner, …). Every mapped check passed.
- **E2E failing**: at least one mapped E2E check failed (listed at the end).
- **implemented (no E2E)**: unit / API tests only.

Not yet done for any row: a run on a real VPS and on AlmaLinux 9 (the E2E container is Ubuntu 24.04).
Every component is free/open source (`third-party-licenses.md`); no row depends on a paid product.

## A. cPanel (user) features

| Feature | BPANEL location | Status | Free component | E2E checks (pass/total) | Notes |
|---|---|---|---|---|---|
| Email Accounts | `email_accounts` `/email/accounts` | **verified-e2e** | Postfix, Dovecot | 6/6 (email) | quotas capped by package, SHA512-CRYPT; IMAP/submission/DKIM checked |
| Forwarders | `forwarders` `/email/forwarders` | **verified-e2e** | Postfix | 2/2 (forwarders) |  |
| Default Address (catch-all) | `default_address` | **verified-e2e** | Postfix | 2/2 (catchall) |  |
| Webmail | `webmail` (SSO) | **verified-e2e** | Roundcube 1.6 | 2/2 (webmail) |  |
| Email Deliverability (SPF/DKIM/DMARC) | `deliverability` | **verified-e2e** | Rspamd DKIM, PowerDNS | 2/2 (deliverability) | no MTA-STS/TLS-RPT/BIMI |
| Email Disk Usage | `email_disk_usage` | **verified-e2e** | Dovecot quota | 1/1 (email-disk) |  |
| Autoresponders | `autoresponders` | **verified-e2e** | Dovecot Pigeonhole (Sieve vacation) | 4/4 (mail) |  |
| Email Filters | `email_filters` | **verified-e2e** | Sieve | 4/4 (mail) |  |
| Spam Filters (SpamAssassin) | `spam_filters` | **verified-e2e** | Rspamd | 4/4 (mail) | Rspamd instead of SpamAssassin |
| Mailing Lists (Mailman) | `mailing_lists` | **verified-e2e** | mlmmj (MIT) | 6/6 (lists) | mlmmj instead of Mailman |
| Track Delivery | `track_delivery` | **verified-e2e** | Postfix mail log | 3/3 (track) |  |
| Email Routing | `email_routing` `/email/routing` | **verified-e2e** | Postfix transport maps | 9/9 (routing) | new in v1.1 |
| BoxTrapper | `boxtrapper` `/email/boxtrapper` | **verified-e2e** | Sieve | 7/7 (boxtrapper) | new in v1.1 |
| Email Encryption (GnuPG) | `email_encryption` | **verified-e2e** | GnuPG (GPL-3.0) | 8/8 (gpg) | new in v1.1 |
| Calendars & Contacts (CalDAV/CardDAV) | `calendars` `/calendars` | **verified-e2e** | Radicale (GPL-3.0) | 9/9 (dav) | new in v1.1 |
| File Manager | `file_manager` `/files` | **verified-e2e** | agent fileops | 14/14 (files) | traversal and symlink escapes refused |
| Disk Usage | `disk_usage` `/disk` | **verified-e2e** | quota, du | 1/1 (disk) | disk quota enforcement needs a quota-capable filesystem (not overlayfs) |
| Resource Usage (CloudLinux LVE) | `resource_usage` `/usage` | **verified-e2e** | cgroup v2 | 3/3 (usage) |  |
| FTP Accounts | `ftp_accounts` `/ftp` | **verified-e2e** | Pure-FTPd (ISC) | 5/5 (ftp) | FTPS upload + chroot |
| Backup / Backup Wizard | `backups` `/backups` | **verified-e2e** | restic (BSD-2) | 2/2 (backups) | local repository in the E2E; SFTP/S3 targets not exercised |
| File Restoration | `file_restore` `/backups` | **verified-e2e** | restic | 2/2 (restore) |  |
| Directory Privacy | `directory_privacy` `/web/privacy` | **verified-e2e** | nginx/Apache basic auth | 3/3 (webx) |  |
| Git Version Control | `git` `/git` | **verified-e2e** | git | 6/6 (git) | push + deploy |
| MySQL Databases / Database Wizard | `mysql_databases`, `db_wizard` | **verified-e2e** | MariaDB | 6/6 (dbx, mysql) |  |
| phpMyAdmin | `phpmyadmin` (SSO) | **verified-e2e** | phpMyAdmin 5.2 | 2/2 (phpmyadmin) |  |
| Remote MySQL | `remote_mysql` | **verified-e2e** | MariaDB | 5/5 (dbx) |  |
| PostgreSQL Databases / phpPgAdmin | `postgresql`, `pg_browser` | **verified-e2e** | PostgreSQL | 11/11 (pg) | built-in browser instead of phpPgAdmin (v1.1) |
| MySQL process list | `db_processes` | **verified-e2e** | MariaDB | 4/4 (dbx) |  |
| Domains / Addon / Subdomains / Aliases | `domains` | **verified-e2e** | nginx, Apache, PowerDNS | 9/9 (domains) |  |
| Redirects | `redirects` | **verified-e2e** | nginx/Apache | 4/4 (redirects) |  |
| Zone Editor | `zone_editor` `/dns` | **verified-e2e** | PowerDNS | 8/8 (zone) |  |
| DNSSEC / zone import-export / history | `dns_tools` `/dnsx` | **verified-e2e** | pdnsutil | 12/12 (dnsx) |  |
| Dynamic DNS | `dynamic_dns` `/ddns` | **verified-e2e** | PowerDNS | 6/6 (ddns) |  |
| Errors / Raw Access | `errors`, `raw_access` | **verified-e2e** | web server logs | 3/3 (logs) |  |
| Visitors / Awstats / Webalizer | `visitors` `/stats/visitors` | **verified-e2e** | access log | 5/5 (visitors) | per-domain statistics (v1.1) |
| Bandwidth | `bandwidth` | **verified-e2e** | log accounting | 3/3 (bw) |  |
| SSL/TLS Status, AutoSSL | `ssl_status` `/ssl` | **verified-e2e** | lego ACME, Let's Encrypt | 6/6 (ssl) | real ACME HTTP-01 flow against a local Pebble CA; not against Let's Encrypt production |
| Two-Factor Authentication | `two_factor` | **verified-e2e** | TOTP | 5/5 (2fa) |  |
| SSH Access / Manage SSH Keys | `ssh_access`, `ssh_keys` | **verified-e2e** | OpenSSH | 11/11 (ssh) | real SSH/SFTP login with a generated key |
| IP Blocker | `ip_blocker` | **verified-e2e** | nginx/Apache deny | 3/3 (webx) |  |
| Hotlink Protection | `hotlink` | **verified-e2e** | nginx/Apache | 3/3 (webx) |  |
| Leech Protection | `leech_protection` `/web/leech` | **verified-e2e** | agent log scan + basic auth | 6/6 (webx) | new in v1.1 |
| Indexes | `directory_indexes` `/web/indexes` | **verified-e2e** | nginx autoindex / Apache Options | 3/3 (webx) | new in v1.1 |
| Apache Handlers | `apache_handlers` `/web/handlers` | **verified-e2e** | Apache/nginx types | 3/3 (webx) | new in v1.1 |
| Error Pages | `error_pages` | **verified-e2e** | nginx/Apache | 2/2 (webx) |  |
| MIME Types | `mime_types` | **verified-e2e** | nginx/Apache | 2/2 (webx) |  |
| Manage API Tokens | `api_tokens` | **verified-e2e** | stdlib | 6/6 (tokens) |  |
| ModSecurity (per domain) | `modsecurity` | **verified-e2e** | ModSecurity + OWASP CRS | 9/9 (waf) |  |
| Imunify360 / malware scan (user) | `malware_scans` | **verified-e2e** | ClamAV, YARA, heuristics | 8/8 (shield) | BPanel Shield replaces Imunify360 |
| MultiPHP Manager | `multiphp` `/php` | **verified-e2e** | PHP-FPM | 5/5 (php) |  |
| MultiPHP INI Editor | `php_ini` | **verified-e2e** | PHP-FPM | 4/4 (phpini) |  |
| WordPress Toolkit | `wordpress` | **verified-e2e** | WP-CLI, WordPress | 8/8 (inst) |  |
| Softaculous (App Installer) | `app_installer` | **verified-e2e** | 16 checksum-pinned official archives (tar/zip): WordPress, Joomla, Drupal, Nextcloud, Matomo, phpBB, MediaWiki, DokuWiki, Grav, Backdrop, WonderCMS, MyBB, OpenCart, Mautic, Omeka S, FOSSBilling | 3/3 (inst) + 81/81 (apps.sh, v1.2.0) | free replacement for Softaculous |
| Application Manager (Node.js / Python) | `nodejs` `/apps` | **verified-e2e** | Node.js, Python, systemd | 9/9 (apps) |  |
| Ruby on Rails / Ruby Gems (Ruby apps) | `nodejs` `/apps` (runtime ruby) | **verified-e2e** | Ruby, bundler (distro) | 9/9 (ruby) | Ruby/Rack apps as systemd `bpanel-app@` units with GEM_HOME and BUNDLE_PATH=vendor/bundle (v1.1); a `bundle install` of real gems was not exercised |
| Cron Jobs | `cron_jobs` | **verified-e2e** | cron | 5/5 (cron) |  |
| Terminal | `terminal` | **verified-e2e** | PTY + WebSocket | 4/4 (term) | runs as the account |
| Track DNS | `track_dns` | **verified-e2e** | miekg/dns, traceroute | 4/4 (tdns) |  |
| Site Publisher | `site_publisher` | **verified-e2e** | built-in templates | 7/7 (sitepub) | new in v1.1 |
| Images | `images` | **verified-e2e** | Go image libs | 7/7 (images) | new in v1.1 |
| Cloudflare | `cloudflare` | **verified-e2e** | Cloudflare API (user's own token) | 9/9 (cf) | new in v1.1; tested against a local Cloudflare API mock |
| Password & Security | `password_security` | **verified-e2e** | argon2id | 2/2 (password) |  |
| Change Language / Theme | `change_language`, `theme` | **verified-e2e** | - | 3/3 (prefs) | EN + TR |
| Contact Information | `contact_info` | **verified-e2e** | - | 2/2 (contact) |  |
| User Manager (sub-users) | `user_manager` | **verified-e2e** | - | 1/1 (umgr) |  |

## B. WHM (admin / reseller) features

| Feature | BPANEL location | Status | Free component | E2E checks (pass/total) | Notes |
|---|---|---|---|---|---|
| Basic WebHost Manager Setup / Nameservers | `basic_setup`, `nameservers` | **verified-e2e** | - | 3/3 (basic-setup) |  |
| Server Information | `server_info` | **verified-e2e** | sysinfo | 1/1 (server-info) |  |
| Update Preferences | `update_prefs` | **verified-e2e** | apt / dnf, unattended-upgrades | 5/5 (upd) |  |
| Server status / health monitoring | `monitoring` | **verified-e2e** | smartctl, chronyc, Prometheus text | 5/5 (mon) |  |
| Notifications / contact manager | `alerts` | **verified-e2e** | SMTP, Telegram/Slack/Discord webhooks | 7/7 (alerts) |  |
| Security Advisor / audit trail | `audit_log`, `sec_events` | **verified-e2e** | SQLite FTS5 | 3/3 (audit, events) |  |
| cPHulk Brute Force Protection | `brute_force` | **verified-e2e** | fail2ban | 5/5 (brute) |  |
| Firewall (CSF equivalent) | `firewall` | **verified-e2e** | nftables | 10/10 (fw) | lockout guard + confirm/rollback |
| ModSecurity Tools / Vendors | `firewall`, user `modsecurity` | **verified-e2e** | ModSecurity + OWASP CRS | 5/5 (waf) | no paid rule vendors |
| List Accounts / Suspended | `list_accounts` | **verified-e2e** | - | 10/10 (accounts, suspend) |  |
| Create / Terminate / Suspend / Password | `create_account` | **verified-e2e** | system users | 20/20 (accounts, suspend, terminate) | suspension also locks mail logins (v1.1 fix) |
| Modify an Account | `modify_account` | **verified-e2e** | - | 4/4 (modify) |  |
| Resellers (create / edit privileges / limits) | `list_resellers`, `edit_reseller` | **verified-e2e** | - | 8/8 (resl) |  |
| Packages | `packages` | **verified-e2e** | - | 3/3 (packages) |  |
| CloudLinux LVE limits / CageFS | `resource_limits` | **verified-e2e** | cgroup v2, bubblewrap, systemd | 5/5 (limits) | free replacement for CloudLinux |
| MultiPHP Manager / PHP-FPM | `php_versions` | **verified-e2e** | PHP-FPM | 5/5 (php) |  |
| EasyApache 4 (PHP extensions) | `php_extensions` | **verified-e2e** | distro packages | 6/6 (phpext) | per-version PHP extensions (v1.1); no Apache module profile builder |
| Service Manager / Restart Services | `service_manager` | **verified-e2e** | systemd | 4/4 (services) |  |
| SQL Server settings | `db_settings` | **verified-e2e** | MariaDB, PostgreSQL | 3/3 (dbset) |  |
| DNS Cluster | `dns_cluster` | **verified-e2e** | PowerDNS AXFR/NOTIFY | 5/5 (cluster) |  |
| Backup Configuration | `backup_config` | **verified-e2e** | restic (local, SFTP, S3-compatible) | 2/2 (backups) | local target verified; SFTP/S3 not exercised |
| Transfer Tool (cPanel cpmove import) | `transfer_tool` | **verified-e2e** | stdlib tar/gzip | 7/7 (xfer) |  |
| Bandwidth (all accounts) | `bandwidth` | **verified-e2e** | log accounting | 1/1 (bw) |  |
| Manage Plugins | `plugins` | **verified-e2e** | ed25519-signed plugins | 7/7 (plug) |  |
| Integrations | `integrations` | **verified-e2e** | provider registry | 3/3 (integ) |  |
| API documentation | `api_docs` | **verified-e2e** | OpenAPI 3.1 | 1/1 (api-docs) |  |
| Mail Queue Manager | `mail_queue` | **verified-e2e** | postqueue / postsuper | 12/12 (mailq) | new in v1.1 |
| Mail Troubleshooter | `mail_troubleshooter` | **verified-e2e** | postmap, DNS | 4/4 (trouble) | new in v1.1 |
| IP Functions | `ip_functions` | **verified-e2e** | iproute2, netplan/ifcfg | 12/12 (ips) | new in v1.1 |
| Change Hostname | `hostname` | **verified-e2e** | hostnamectl, Postfix | 6/6 (hostname) | new in v1.1 |
| Tweak Settings | `tweak_settings` | **verified-e2e** | - | 7/7 (tweak) | new in v1.1 |
| WHMCS / billing hooks | `billing` | **verified-e2e** | HMAC-signed webhooks, PHP reference module | 9/9 (billing, whmcs) | new in v1.1 |

## C. Beyond cPanel/WHM (free, built in; not counted in the parity score)

| Feature | BPANEL location | Status | Free component | E2E checks (pass/total) | Notes |
|---|---|---|---|---|---|
| BPanel Shield (real-time scan, quarantine) | `/shield`, `/malware-scans` | **verified-e2e** | ClamAV, YARA, heuristics | 9/9 (integ, shield) |  |
| WAF with OWASP CRS per domain | `/modsecurity` | **verified-e2e** | ModSecurity + CRS | 9/9 (waf) |  |
| Per-account isolation (cgroup v2 + cage) | `/limits`, `/usage` | **verified-e2e** | kernel, bubblewrap, systemd | 9/9 (limits, term) |  |
| Multi-server (mTLS remote agents) | `/servers` | **implemented (no E2E)** | stdlib crypto/tls | 0/0 (-) | unit/loopback mTLS tests only; needs two hosts |
| Signed plugins | `/plugins` | **verified-e2e** | ed25519 | 7/7 (plug) |  |
| Metrics / alerts / FIM | `/monitoring`, `/alerts` | **verified-e2e** | Prometheus text format | 12/12 (alerts, mon) |  |
| RBAC + security events + webhooks | `/events`, `/webhooks` | **verified-e2e** | stdlib HMAC | 9/9 (billing, events, tokens) |  |
| Secrets at rest (AES-256-GCM envelope) | CLI `bpanel secrets` | **verified-e2e** | stdlib | 4/4 (secrets) | key rotation verified |

## Parity

| | A (cPanel) | B (WHM) | Total |
|---|---|---|---|
| feature rows | 65 | 32 | 97 |
| implemented | 65 | 32 | 97 |
| verified-e2e | 65 | 32 | 97 |

- **Feature parity (implemented): 97 / 97 = 100 %.** v1.0.0 bundled 14 features into 5 "not planned"
  rows and had 6 "partial" rows; all of them are built in v1.1.0 and listed one per row above.
- **Verified end to end in a container: 97 / 97 = 100 %.**
- E2E checks: **520 passed, 0 failed, 1 skipped** (of 521).
- Verified on a real VPS / AlmaLinux 9: not yet.

Remaining gaps are named in the notes column (SFTP/S3 backup targets, Let's Encrypt production,
Cloudflare against the real API, multi-server across two hosts).

### Skipped checks

- `tdns` dns lookup NS of the own zone
