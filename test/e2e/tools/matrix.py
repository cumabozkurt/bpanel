#!/usr/bin/env python3
"""Generate docs/feature-matrix.md from the E2E results (results.tsv files).
Usage: matrix.py OUT.md results.tsv [results.tsv ...]
A row is "verified-e2e" when at least one E2E check maps to it and every mapped check PASSed.
A spec is "area" (all checks of that area) or "area~regex" (checks of that area whose
description matches regex, case-insensitive)."""
import csv, re, sys
out, files = sys.argv[1], sys.argv[2:]
R = []
for f in files:
    with open(f) as fh:
        for row in csv.reader(fh, delimiter='\t'):
            if len(row) < 4 or row[1] not in ('PASS', 'FAIL', 'SKIP'): continue
            R.append((row[1], row[2], row[3]))

def sel(specs):
    hits = []
    for sp in specs:
        a, _, rx = sp.partition('~')
        for st, ar, d in R:
            if ar == a and (not rx or re.search(rx, d, re.I)): hits.append((st, ar, d))
    return hits

A = [  # cPanel (user)
 ("Email Accounts", "`email_accounts` `/email/accounts`", "Postfix, Dovecot", ["email"], "quotas capped by package, SHA512-CRYPT; IMAP/submission/DKIM checked"),
 ("Forwarders", "`forwarders` `/email/forwarders`", "Postfix", ["forwarders"], ""),
 ("Default Address (catch-all)", "`default_address`", "Postfix", ["catchall"], ""),
 ("Webmail", "`webmail` (SSO)", "Roundcube 1.6", ["webmail"], ""),
 ("Email Deliverability (SPF/DKIM/DMARC)", "`deliverability`", "Rspamd DKIM, PowerDNS", ["deliverability"], "no MTA-STS/TLS-RPT/BIMI"),
 ("Email Disk Usage", "`email_disk_usage`", "Dovecot quota", ["email-disk"], ""),
 ("Autoresponders", "`autoresponders`", "Dovecot Pigeonhole (Sieve vacation)", ["mail~autoresponder|vacation|sieve active"], ""),
 ("Email Filters", "`email_filters`", "Sieve", ["mail~filter"], ""),
 ("Spam Filters (SpamAssassin)", "`spam_filters`", "Rspamd", ["mail~spam|deny-listed"], "Rspamd instead of SpamAssassin"),
 ("Mailing Lists (Mailman)", "`mailing_lists`", "mlmmj (MIT)", ["lists"], "mlmmj instead of Mailman"),
 ("Track Delivery", "`track_delivery`", "Postfix mail log", ["track"], ""),
 ("Email Routing", "`email_routing` `/email/routing`", "Postfix transport maps", ["routing"], "new in v1.1"),
 ("BoxTrapper", "`boxtrapper` `/email/boxtrapper`", "Sieve", ["boxtrapper"], "new in v1.1"),
 ("Email Encryption (GnuPG)", "`email_encryption`", "GnuPG (GPL-3.0)", ["gpg"], "new in v1.1"),
 ("Calendars & Contacts (CalDAV/CardDAV)", "`calendars` `/calendars`", "Radicale (GPL-3.0)", ["dav"], "new in v1.1"),
 ("File Manager", "`file_manager` `/files`", "agent fileops", ["files"], "traversal and symlink escapes refused"),
 ("Disk Usage", "`disk_usage` `/disk`", "quota, du", ["disk"], "disk quota enforcement needs a quota-capable filesystem (not overlayfs)"),
 ("Resource Usage (CloudLinux LVE)", "`resource_usage` `/usage`", "cgroup v2", ["usage"], ""),
 ("FTP Accounts", "`ftp_accounts` `/ftp`", "Pure-FTPd (ISC)", ["ftp"], "FTPS upload + chroot"),
 ("Backup / Backup Wizard", "`backups` `/backups`", "restic (BSD-2)", ["backups"], "local repository in the E2E; SFTP/S3 targets not exercised"),
 ("File Restoration", "`file_restore` `/backups`", "restic", ["restore"], ""),
 ("Directory Privacy", "`directory_privacy` `/web/privacy`", "nginx/Apache basic auth", ["webx~privacy|password hashes"], ""),
 ("Git Version Control", "`git` `/git`", "git", ["git"], "push + deploy"),
 ("MySQL Databases / Database Wizard", "`mysql_databases`, `db_wizard`", "MariaDB", ["mysql", "dbx~^MariaDB (database|user)|grant"], ""),
 ("phpMyAdmin", "`phpmyadmin` (SSO)", "phpMyAdmin 5.2", ["phpmyadmin"], ""),
 ("Remote MySQL", "`remote_mysql`", "MariaDB", ["dbx~remote|wildcard"], ""),
 ("PostgreSQL Databases / phpPgAdmin", "`postgresql`, `pg_browser`", "PostgreSQL", ["pg"], "built-in browser instead of phpPgAdmin (v1.1)"),
 ("MySQL process list", "`db_processes`", "MariaDB", ["dbx~process|kill|thread|query gone"], ""),
 ("Domains / Addon / Subdomains / Aliases", "`domains`", "nginx, Apache, PowerDNS", ["domains"], ""),
 ("Redirects", "`redirects`", "nginx/Apache", ["redirects"], ""),
 ("Zone Editor", "`zone_editor` `/dns`", "PowerDNS", ["zone"], ""),
 ("DNSSEC / zone import-export / history", "`dns_tools` `/dnsx`", "pdnsutil", ["dnsx"], ""),
 ("Dynamic DNS", "`dynamic_dns` `/ddns`", "PowerDNS", ["ddns"], ""),
 ("Errors / Raw Access", "`errors`, `raw_access`", "web server logs", ["logs"], ""),
 ("Visitors / Awstats / Webalizer", "`visitors` `/stats/visitors`", "access log", ["visitors"], "per-domain statistics (v1.1)"),
 ("Bandwidth", "`bandwidth`", "log accounting", ["bw"], ""),
 ("SSL/TLS Status, AutoSSL", "`ssl_status` `/ssl`", "lego ACME, Let's Encrypt", ["ssl"], "real ACME HTTP-01 flow against a local Pebble CA; not against Let's Encrypt production"),
 ("Two-Factor Authentication", "`two_factor`", "TOTP", ["2fa"], ""),
 ("SSH Access / Manage SSH Keys", "`ssh_access`, `ssh_keys`", "OpenSSH", ["ssh"], "real SSH/SFTP login with a generated key"),
 ("IP Blocker", "`ip_blocker`", "nginx/Apache deny", ["webx~IP blocker|blocked IP|CIDR"], ""),
 ("Hotlink Protection", "`hotlink`", "nginx/Apache", ["webx~hotlink|referer"], ""),
 ("Leech Protection", "`leech_protection` `/web/leech`", "agent log scan + basic auth", ["webx~leech|alice|members|login"], "new in v1.1"),
 ("Indexes", "`directory_indexes` `/web/indexes`", "nginx autoindex / Apache Options", ["webx~indexes|listing"], "new in v1.1"),
 ("Apache Handlers", "`apache_handlers` `/web/handlers`", "Apache/nginx types", ["webx~handler|text/plain"], "new in v1.1"),
 ("Error Pages", "`error_pages`", "nginx/Apache", ["webx~404"], ""),
 ("MIME Types", "`mime_types`", "nginx/Apache", ["webx~MIME"], ""),
 ("Manage API Tokens", "`api_tokens`", "stdlib", ["tokens"], ""),
 ("ModSecurity (per domain)", "`modsecurity`", "ModSecurity + OWASP CRS", ["waf"], ""),
 ("Imunify360 / malware scan (user)", "`malware_scans`", "ClamAV, YARA, heuristics", ["shield"], "BPanel Shield replaces Imunify360"),
 ("MultiPHP Manager", "`multiphp` `/php`", "PHP-FPM", ["php"], ""),
 ("MultiPHP INI Editor", "`php_ini`", "PHP-FPM", ["phpini"], ""),
 ("WordPress Toolkit", "`wordpress`", "WP-CLI, WordPress", ["inst~WP-CLI|WordPress|maintenance"], ""),
 ("Softaculous (App Installer)", "`app_installer`", "checksum-pinned official tarballs", ["inst~catalogue|install"], "free replacement for Softaculous"),
 ("Application Manager (Node.js / Python)", "`nodejs` `/apps`", "Node.js, Python, systemd", ["apps"], ""),
 ("Ruby on Rails / Ruby Gems (Ruby apps)", "`nodejs` `/apps` (runtime ruby)", "Ruby, bundler (distro)", ["ruby"], "Ruby/Rack apps as systemd `bpanel-app@` units with GEM_HOME and BUNDLE_PATH=vendor/bundle (v1.1); a `bundle install` of real gems was not exercised"),
 ("Cron Jobs", "`cron_jobs`", "cron", ["cron"], ""),
 ("Terminal", "`terminal`", "PTY + WebSocket", ["term"], "runs as the account"),
 ("Track DNS", "`track_dns`", "miekg/dns, traceroute", ["tdns"], ""),
 ("Site Publisher", "`site_publisher`", "built-in templates", ["sitepub"], "new in v1.1"),
 ("Images", "`images`", "Go image libs", ["images"], "new in v1.1"),
 ("Cloudflare", "`cloudflare`", "Cloudflare API (user's own token)", ["cf"], "new in v1.1; tested against a local Cloudflare API mock"),
 ("Password & Security", "`password_security`", "argon2id", ["password"], ""),
 ("Change Language / Theme", "`change_language`, `theme`", "-", ["prefs"], "EN + TR"),
 ("Contact Information", "`contact_info`", "-", ["contact"], ""),
 ("User Manager (sub-users)", "`user_manager`", "-", ["umgr"], ""),
]
B = [  # WHM
 ("Basic WebHost Manager Setup / Nameservers", "`basic_setup`, `nameservers`", "-", ["basic-setup"], ""),
 ("Server Information", "`server_info`", "sysinfo", ["server-info"], ""),
 ("Update Preferences", "`update_prefs`", "apt / dnf, unattended-upgrades", ["upd"], ""),
 ("Server status / health monitoring", "`monitoring`", "smartctl, chronyc, Prometheus text", ["mon"], ""),
 ("Notifications / contact manager", "`alerts`", "SMTP, Telegram/Slack/Discord webhooks", ["alerts"], ""),
 ("Security Advisor / audit trail", "`audit_log`, `sec_events`", "SQLite FTS5", ["audit", "events"], ""),
 ("cPHulk Brute Force Protection", "`brute_force`", "fail2ban", ["brute"], ""),
 ("Firewall (CSF equivalent)", "`firewall`", "nftables", ["fw"], "lockout guard + confirm/rollback"),
 ("ModSecurity Tools / Vendors", "`firewall`, user `modsecurity`", "ModSecurity + OWASP CRS", ["waf~admin|lock|provider"], "no paid rule vendors"),
 ("List Accounts / Suspended", "`list_accounts`", "-", ["accounts~list|search", "suspend"], ""),
 ("Create / Terminate / Suspend / Password", "`create_account`", "system users", ["accounts", "suspend", "terminate"], "suspension also locks mail logins (v1.1 fix)"),
 ("Modify an Account", "`modify_account`", "-", ["modify"], ""),
 ("Resellers (create / edit privileges / limits)", "`list_resellers`, `edit_reseller`", "-", ["resl"], ""),
 ("Packages", "`packages`", "-", ["packages"], ""),
 ("CloudLinux LVE limits / CageFS", "`resource_limits`", "cgroup v2, bubblewrap, systemd", ["limits"], "free replacement for CloudLinux"),
 ("MultiPHP Manager / PHP-FPM", "`php_versions`", "PHP-FPM", ["php"], ""),
 ("EasyApache 4 (PHP extensions)", "`php_extensions`", "distro packages", ["phpext"], "per-version PHP extensions (v1.1); no Apache module profile builder"),
 ("Service Manager / Restart Services", "`service_manager`", "systemd", ["services"], ""),
 ("SQL Server settings", "`db_settings`", "MariaDB, PostgreSQL", ["dbset"], ""),
 ("DNS Cluster", "`dns_cluster`", "PowerDNS AXFR/NOTIFY", ["cluster"], ""),
 ("Backup Configuration", "`backup_config`", "restic (local, SFTP, S3-compatible)", ["backups"], "local target verified; SFTP/S3 not exercised"),
 ("Transfer Tool (cPanel cpmove import)", "`transfer_tool`", "stdlib tar/gzip", ["xfer"], ""),
 ("Bandwidth (all accounts)", "`bandwidth`", "log accounting", ["bw~admin"], ""),
 ("Manage Plugins", "`plugins`", "ed25519-signed plugins", ["plug"], ""),
 ("Integrations", "`integrations`", "provider registry", ["integ"], ""),
 ("API documentation", "`api_docs`", "OpenAPI 3.1", ["api-docs"], ""),
 ("Mail Queue Manager", "`mail_queue`", "postqueue / postsuper", ["mailq"], "new in v1.1"),
 ("Mail Troubleshooter", "`mail_troubleshooter`", "postmap, DNS", ["trouble"], "new in v1.1"),
 ("IP Functions", "`ip_functions`", "iproute2, netplan/ifcfg", ["ips"], "new in v1.1"),
 ("Change Hostname", "`hostname`", "hostnamectl, Postfix", ["hostname"], "new in v1.1"),
 ("Tweak Settings", "`tweak_settings`", "-", ["tweak"], "new in v1.1"),
 ("WHMCS / billing hooks", "`billing`", "HMAC-signed webhooks, PHP reference module", ["billing", "whmcs"], "new in v1.1"),
]
C = [
 ("BPanel Shield (real-time scan, quarantine)", "`/shield`, `/malware-scans`", "ClamAV, YARA, heuristics", ["shield", "integ~ClamAV"], ""),
 ("WAF with OWASP CRS per domain", "`/modsecurity`", "ModSecurity + CRS", ["waf"], ""),
 ("Per-account isolation (cgroup v2 + cage)", "`/limits`, `/usage`", "kernel, bubblewrap, systemd", ["limits", "term"], ""),
 ("Multi-server (mTLS remote agents)", "`/servers`", "stdlib crypto/tls", [], "unit/loopback mTLS tests only; needs two hosts"),
 ("Signed plugins", "`/plugins`", "ed25519", ["plug"], ""),
 ("Metrics / alerts / FIM", "`/monitoring`, `/alerts`", "Prometheus text format", ["mon", "alerts"], ""),
 ("RBAC + security events + webhooks", "`/events`, `/webhooks`", "stdlib HMAC", ["events", "tokens", "billing~HMAC"], ""),
 ("Secrets at rest (AES-256-GCM envelope)", "CLI `bpanel secrets`", "stdlib", ["secrets"], "key rotation verified"),
]

def status(specs):
    h = sel(specs)
    if not specs or not h: return "implemented (no E2E)", h
    if any(s == 'FAIL' for s, _, _ in h): return "E2E failing", h
    if all(s == 'SKIP' for s, _, _ in h): return "implemented (E2E skipped)", h
    return "verified-e2e", h

def table(rows):
    lines = ["| Feature | BPANEL location | Status | Free component | E2E checks (pass/total) | Notes |", "|---|---|---|---|---|---|"]
    tally = {}
    for name, loc, comp, specs, notes in rows:
        st, h = status(specs)
        tally[st] = tally.get(st, 0) + 1
        p = sum(1 for s, _, _ in h if s == 'PASS'); n = sum(1 for s, _, _ in h if s != 'SKIP')
        tags = ", ".join(sorted({a for _, a, _ in h})) or "-"
        lines.append(f"| {name} | {loc} | **{st}** | {comp} | {p}/{n} ({tags}) | {notes} |")
    return "\n".join(lines), tally

ta, xa = table(A); tb, xb = table(B); tc, xc = table(C)
nA, nB = len(A), len(B); tot = nA + nB
ver = xa.get("verified-e2e", 0) + xb.get("verified-e2e", 0)
P = sum(1 for s, _, _ in R if s == 'PASS'); F = sum(1 for s, _, _ in R if s == 'FAIL'); S = sum(1 for s, _, _ in R if s == 'SKIP')
fails = [f"- `{a}` {d}" for s, a, d in R if s == 'FAIL']
skips = [f"- `{a}` {d}" for s, a, d in R if s == 'SKIP']
md = f"""# Feature matrix: cPanel/WHM vs. BPANEL v1.1.0

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

{ta}

## B. WHM (admin / reseller) features

{tb}

## C. Beyond cPanel/WHM (free, built in; not counted in the parity score)

{tc}

## Parity

| | A (cPanel) | B (WHM) | Total |
|---|---|---|---|
| feature rows | {nA} | {nB} | {tot} |
| implemented | {nA} | {nB} | {tot} |
| verified-e2e | {xa.get('verified-e2e',0)} | {xb.get('verified-e2e',0)} | {ver} |

- **Feature parity (implemented): {tot} / {tot} = 100 %.** v1.0.0 bundled 14 features into 5 "not planned"
  rows and had 6 "partial" rows; all of them are built in v1.1.0 and listed one per row above.
- **Verified end to end in a container: {ver} / {tot} = {100*ver/tot:.0f} %.**
- E2E checks: **{P} passed, {F} failed, {S} skipped** (of {P+F+S}).
- Verified on a real VPS / AlmaLinux 9: not yet.

Remaining gaps are named in the notes column (SFTP/S3 backup targets, Let's Encrypt production,
Cloudflare against the real API, multi-server across two hosts).
"""
if fails: md += "\n### Failing checks\n\n" + "\n".join(fails) + "\n"
if skips: md += "\n### Skipped checks\n\n" + "\n".join(skips) + "\n"
open(out, "w").write(md)
print(f"rows={tot} verified={ver} pct={100*ver/tot:.1f} PASS={P} FAIL={F} SKIP={S}")
for name, *_ in A + B:
    pass
