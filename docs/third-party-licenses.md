# Third-party licenses (BPANEL v0.4)

BPANEL itself is Apache-2.0 (`LICENSE`, `NOTICE`). This file lists every third-party component the
product links, bundles, installs, downloads, or may integrate with, and how it is shipped.

**Policy (master spec §24, BRIEF):** no GPL/AGPL code is linked into the Go binaries. GPL/AGPL programs
are only ever run as **separate processes** installed from the OS/vendor repository or downloaded at
install time, never redistributed inside the BPANEL release archive. Every optional integration must
report `not_installed`/`unsupported` when absent.

Legend — **Shipped:** `linked` = compiled into bpanel binaries · `bundled` = embedded in the web UI
bundle · `pkg` = installed by the installer from distro/vendor repos as a separate process ·
`download` = fetched at install time, pinned by SHA-256 · `candidate` = not installed by v0.3; optional
future integration. **Verified:** `yes` = licence text read from the module cache / node_modules / the
official repository on 2026-10-10; `no` = taken from metadata or not fetched.

## 1. Go modules linked into the binaries

Source: `bpanel/go.mod`; licence files read from `work/toolchain/gomod/<module>@<version>/LICENSE`.

| Component | Version | Use | License | Shipped | Notes | Verified |
|---|---|---|---|---|---|---|
| github.com/go-chi/chi/v5 | v5.3.2 | HTTP router | MIT | linked | — | yes |
| github.com/go-acme/lego/v5 | v5.5.2 | ACME / Let's Encrypt client | MIT | linked | Contacts the configured ACME CA only when issuing certs. Pulls many DNS-provider SDKs into the module graph; only packages actually imported are linked | yes |
| github.com/go-sql-driver/mysql | v1.10.1 | MariaDB/MySQL driver | MPL-2.0 | linked | File-level copyleft: unmodified, source link in NOTICE | yes |
| golang.org/x/crypto | v0.57.0 | bcrypt/argon2, ssh helpers | BSD-3-Clause | linked | — | yes |
| golang.org/x/net | v0.60.0 | idna, http helpers | BSD-3-Clause | linked | — | yes |
| golang.org/x/sys | v0.48.0 | unix syscalls (agent, isolation) | BSD-3-Clause | linked | indirect | yes |
| golang.org/x/text | v0.42.0 | unicode/idna tables | BSD-3-Clause | linked | indirect | yes |
| modernc.org/sqlite | v1.60.1 | pure-Go SQLite (panel store) | BSD-3-Clause | linked | Contains transpiled SQLite (public domain) | yes |
| modernc.org/libc | v1.77.1 | sqlite runtime | BSD-3-Clause | linked | indirect | yes |
| modernc.org/mathutil | v1.7.1 | sqlite dep | BSD-3-Clause | linked | indirect | yes |
| modernc.org/memory | v1.12.1 | sqlite dep | BSD-3-Clause | linked | indirect | yes |
| github.com/dustin/go-humanize | v1.0.1 | sqlite dep | MIT | linked | indirect | yes |
| github.com/google/uuid | v1.6.0 | sqlite/lego dep | BSD-3-Clause | linked | indirect | yes |
| github.com/ncruces/go-strftime | v1.0.0 | sqlite dep | MIT | linked | indirect; licence file not in local cache | no |
| github.com/mattn/go-isatty | v0.0.24 | libc dep | MIT | linked | indirect; licence file not in local cache | no |
| github.com/remyoudompheng/bigfft | v0.0.0-2023… | mathutil dep | BSD-3-Clause | linked | indirect | yes |
| github.com/go-jose/go-jose/v4 | v4.1.5 | JWS for ACME | Apache-2.0 | linked | indirect | yes |
| github.com/miekg/dns | v1.1.73 | DNS (lego DNS-01 checks) | BSD-3-Clause | linked | indirect | yes |
| github.com/cenkalti/backoff/v5 | v5.0.3 | lego retry | MIT | linked | indirect | yes |
| filippo.io/edwards25519 | v1.2.0 | mysql driver dep | BSD-3-Clause | linked | indirect | yes |
| software.sslmate.com/src/go-pkcs12 | v0.7.3 | lego PKCS#12 | BSD-3-Clause | linked | indirect | yes |
| Go standard library / runtime | 1.27.2 | — | BSD-3-Clause | linked | — | yes |

No GPL/AGPL module is present in the linked set.

## 2. Web UI (npm)

Runtime deps from `web/package.json`; licence from `node_modules/<pkg>/package.json`. Transitive deps of
`qrcode` (all MIT/ISC) are listed in `NOTICE` §2.

| Component | Version | Use | License | Shipped | Notes | Verified |
|---|---|---|---|---|---|---|
| @fontsource-variable/inter | 5.3.0 | UI font | OFL-1.1 | bundled | Font served locally, no Google Fonts call | yes (metadata) |
| @lucide/svelte | 1.53.0 | icons | ISC | bundled | — | yes (metadata) |
| qrcode | 1.5.4 | TOTP QR rendering | MIT | bundled | Client-side only | yes (metadata) |
| svelte | 5.57.2 | UI compiler/runtime | MIT | bundled (runtime helpers) | dev dep | yes (metadata) |
| @sveltejs/kit | 2.70.3 | app framework | MIT | build only | dev dep | yes (metadata) |
| vite | 7.3.7 | bundler | MIT | build only | dev dep | yes (metadata) |

## 3. Programs installed by the installer (separate processes)

Package names from `internal/installer/packages.go` (Debian/Ubuntu ↔ EL9). Installed from distro repos,
plus vendor repos for PowerDNS (`auth-50`), Rspamd (`rspamd-stable`), Remi (extra PHP on EL). Not
redistributed by BPANEL. Licences are the upstream project licences (not re-fetched this round).

| Component | Packages | Use | License | Shipped | Notes | Verified |
|---|---|---|---|---|---|---|
| nginx | nginx | front web server / reverse proxy | BSD-2-Clause | pkg | — | no |
| Apache httpd | apache2 / httpd | .htaccess backend (standard/full profile) | Apache-2.0 | pkg | — | no |
| PHP-FPM | php*-fpm, php-pdo, php-sqlite3 | PHP runtime | PHP-3.01 (Zend parts: Zend Engine License) | pkg | Remi repo on EL for extra versions | no |
| MariaDB | mariadb-server, mariadb(-client) | customer databases | GPL-2.0 | pkg | Talked to over socket via MPL driver — separate process | no |
| PowerDNS Authoritative | pdns-server/pdns + sqlite backend | DNS | GPL-2.0 | pkg | Controlled through its HTTP API | no |
| Postfix | postfix, postfix-lmdb | SMTP (full profile) | IPL-1.0 / EPL-2.0 (dual) | pkg | — | no |
| Dovecot | dovecot-imapd/pop3d/lmtpd/sieve/managesieved | IMAP/POP3/LMTP | MIT + LGPL-2.1 (Pigeonhole LGPL-2.1) | pkg | — | no |
| Rspamd | rspamd | spam filtering, DKIM | Apache-2.0 | pkg | Vendor repo; fuzzy/URL checks may query rspamd.com services by default | no |
| Redis | redis-server | Rspamd backend | RSALv2/SSPLv1/AGPL-3.0 (≥7.4/8.0); BSD-3 for ≤7.2 | pkg | Distro version decides licence; consider Valkey (BSD-3) | no |
| Pure-FTPd | pure-ftpd | FTP/FTPS | ISC-style (BSD) | pkg | — | no |
| fail2ban | fail2ban / fail2ban-server, fail2ban-systemd | brute-force bans | GPL-2.0 | pkg | separate process | no |
| nftables | nftables | firewall | GPL-2.0 | pkg | invoked via `nft` argv | no |
| OpenSSH, quota, acl, cron, logrotate, openssl, sqlite3, zip/unzip | various | base system | various OSS | pkg | — | no |

## 4. Pinned downloads (install time, SHA-256 checked, not in release archive)

| Component | Version | Use | License | Shipped | Notes | Verified |
|---|---|---|---|---|---|---|
| restic | 0.19.1 | backups | BSD-2-Clause | download (amd64/arm64 binaries) | https://github.com/restic/restic | yes |
| Roundcube | 1.6.19 | webmail | GPL-3.0-or-later w/ skins & plugins exception | download → PHP-FPM pool | https://github.com/roundcube/roundcubemail (README licence section) | yes |
| phpMyAdmin | 5.2.3 | DB admin UI | GPL-2.0-or-later | download → PHP-FPM pool | https://github.com/phpmyadmin/phpmyadmin; version check calls phpmyadmin.net unless `$cfg['VersionCheck']=false` | yes |

## 5. Candidate integrations (not installed by v0.3; v0.4+ optional, detect-and-report)

| Component | Use | License | Source | Shipped (planned) | Redistribution / telemetry notes | Verified |
|---|---|---|---|---|---|---|
| ClamAV (clamd, freshclam) | malware scan (Shield) | GPL-2.0 (+ libclamunrar under UnRAR licence) | https://github.com/Cisco-Talos/clamav | pkg, talk to clamd over unix socket | Signature DBs via freshclam/CVDUpdate only; manual CVD scraping discouraged, CDN rate-limits (403/429); use a private mirror for fleets (https://docs.clamav.net/faq/faq-cvd.html) | yes |
| YARA | rule-based scan | BSD-3-Clause | https://github.com/VirusTotal/yara | pkg, `yara` argv | Rule sets have their own licences (check each, many are DRL/GPL/commercial) | yes |
| YARA-X | YARA successor | BSD-3-Clause | https://github.com/VirusTotal/yara-x | download/pkg, separate process | same rule-licence caveat | yes |
| Linux Malware Detect (maldet) | PHP malware sigs | GPL-2.0 | https://github.com/rfxn/linux-malware-detect | separate process | Signature updates from rfxn.com | yes |
| bubblewrap | per-account sandbox (isolation) | LGPL-2.0-or-later (COPYING = LGPL 2.1 text) | https://github.com/containers/bubblewrap | pkg, `bwrap` argv | — | yes |
| Coraza | WAF engine | Apache-2.0 | https://github.com/corazawaf/coraza | could be linked (Go) or separate proxy | Linking allowed (Apache-2.0) — would be a new dep to justify | yes |
| OWASP CRS | WAF rules | Apache-2.0 | https://github.com/coreruleset/coreruleset | download | — | yes |
| CrowdSec | behaviour detection + bouncers | MIT (engine) | https://github.com/crowdsecurity/crowdsec | pkg, separate process | By default pushes signal meta-data (scenario, timestamp, machine_id, offending IP+geo) and component versions to Central API; opt-out documented. Console enrollment / CTI API / blocklists are SaaS under CrowdSec Terms (https://crowdsec.net/terms), CTI needs API key with quotas. BPANEL must default to **CAPI off** or ask the admin | yes (licence + CAPI doc) |
| Wazuh | HIDS/SIEM agent | GPL-2.0 | https://github.com/wazuh/wazuh | separate process / external manager | — | yes |
| Tetragon | eBPF runtime security | Apache-2.0 (BPF parts GPL-2.0) | https://github.com/cilium/tetragon | separate process | needs BTF kernel | yes |
| Falco | runtime threat detection | Apache-2.0 | https://github.com/falcosecurity/falco | separate process | rules Apache-2.0 | yes |
| Prometheus | metrics | Apache-2.0 | https://github.com/prometheus/prometheus | separate process | BPANEL may expose `/metrics` | yes |
| Grafana | dashboards | AGPL-3.0 | https://github.com/grafana/grafana | optional, **not bundled**, separate process | AGPL: never link/modify-and-serve inside BPANEL; Grafana has usage-reporting on by default (`reporting_enabled`) | yes |
| Loki | log store | AGPL-3.0 | https://github.com/grafana/loki | optional, not bundled | same AGPL rule | yes |
| OpenTelemetry Collector | telemetry pipeline | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-collector | separate process; Go SDK linkable | — | yes |
| OpenBao | secrets store | MPL-2.0 | https://github.com/openbao/openbao | separate process | Vault fork; HashiCorp Vault itself is BUSL-1.1 → avoid | yes |
| BorgBackup | backups (alt. to restic) | BSD-3-Clause | https://github.com/borgbackup/borg | pkg, separate process | — | yes |
| BIND 9 | DNS (alt. to PowerDNS) | MPL-2.0 | https://gitlab.isc.org/isc-projects/bind9 | pkg | — | yes |
| Imunify360 | commercial malware/WAF | Proprietary (paid licence) | https://www.imunify360.com | optional, admin-supplied licence | Never bundled; detect only | no |
| Monarx | commercial malware agent | Proprietary | https://www.monarx.com | optional | Never bundled; agent reports to vendor cloud | no |
| MaxMind GeoLite2 | GeoIP | CC BY-SA 4.0 data **plus** GeoLite2 EULA | https://www.maxmind.com/en/geolite2/eula | download by admin | Requires free MaxMind account + licence key; EULA terms (incl. updating/deleting old DBs). Cannot be redistributed in BPANEL release | no (EULA page not parsed) |
| DB-IP IP-to-Country Lite | GeoIP (default choice) | CC BY 4.0 | https://db-ip.com/db/download/ip-to-country-lite | download (monthly MMDB/CSV), no account | Attribution required: UI pages using it must link "IP Geolocation by DB-IP" to https://db-ip.com | yes |

## 6. Module additions (v0.4)

v0.4 module workers append their rows below, one heading per module (name, repo, licence, version,
maintenance, telemetry). As of this writing no new Go or npm dependency has been added by
rbac / isolation / shield / providers / events (they use stdlib + existing deps).

<!-- module rows below -->

### Shield (malware protection, v0.4)

No new Go or npm dependency. Scanners are optional external programs, detected at run time; when absent Shield reports them `not_installed` and the fail-closed policy applies. Nothing from them is linked into the BPanel binaries.

| Component | Version | Use | License | How BPanel uses it | Maintenance | Telemetry | Verified |
|---|---|---|---|---|---|---|---|
| ClamAV (clamd + freshclam) | distro package (1.0 LTS / 1.4 at time of writing) | signature scan of uploads, on-demand and real-time queue | GPL-2.0 (libclamunrar: UnRAR licence) | separate daemon; the agent speaks the clamd INSTREAM protocol over its unix socket (own client code in internal/shield/clamd.go, no ClamAV code copied or linked) | Cisco Talos, active | freshclam downloads signatures from the ClamAV CDN (database.clamav.net); no scan data is sent. Fleets should use a private mirror | protocol tested against a fake clamd only; real clamd not installed in the build sandbox |
| YARA (`yara` CLI) | distro package 4.x | rule scan with the embedded BPanel rules (internal/shield/rules/bpanel.yar, Apache-2.0, ours) | BSD-3-Clause | separate process, exec with argv and timeout | VirusTotal, maintenance mode (YARA-X is the successor) | none | rules compiled and matched with libyara 4.x via yara-python in a throwaway venv; `yara` CLI not installed here |

### appx — Application Manager, App Installer, WordPress Toolkit (v0.4)

No new Go or npm dependency (stdlib only: archive/tar, compress/gzip, compress/bzip2, crypto/sha1/sha256/sha512, os.Root). Everything below is downloaded at the tenant's/admin's request from the project's official URL, checked against a pinned or published checksum, and runs as a separate PHP/Node/Python process — nothing is linked into the BPanel binaries.

| Component | Version | Use | License | How BPanel uses it | Maintenance | Telemetry | Verified |
|---|---|---|---|---|---|---|---|
| WordPress | 7.1.3 (pinned) | App Installer / WordPress Toolkit | GPL-2.0-or-later | tarball from wordpress.org, sha1 (published) + sha256 pinned in internal/appx/catalog.go; extracted into the tenant's docroot as the tenant | WordPress.org, active | WordPress core contacts api.wordpress.org for updates (the site's own behaviour, not BPanel's) | checksum matched the real download 2026-10-10 |
| Joomla! | 6.1.4 (pinned) | App Installer | GPL-2.0-or-later | GitHub release tarball, sha256 from the release notes | Open Source Matters, active | Joomla's own update checks | checksum matched 2026-10-10 |
| Drupal | 11.4.9 (pinned) | App Installer | GPL-2.0-or-later | ftp.drupal.org tarball; md5 published in release-history XML matched, sha256 pinned | Drupal Association, active | Drupal's optional update module | md5 + sha256 matched 2026-10-10 |
| Nextcloud Server | 35.0.1 (pinned) | App Installer | AGPL-3.0-or-later | download.nextcloud.com tar.bz2, sha256 from the published .sha256 file | Nextcloud GmbH, active | Nextcloud's own update/app-store checks | published sha256 pinned; archive not downloaded in the sandbox (250 MB) |
| Matomo | — | catalogue entry, **disabled** | GPL-3.0-or-later | not installable until a release checksum is pinned | — | — | — |
| WP-CLI | latest official phar | WordPress core update | MIT | admin installs it via POST /admin/apps/wpcli: phar + published .sha512 from github.com/wp-cli/builds; run as the tenant with php | WP-CLI team, active | none | checksum logic unit-tested with a fake download |
| Node.js / Python | whatever the admin installed (detected) | Application Manager runtimes | MIT / PSF-2.0 | detected binaries only; BPanel never downloads runtimes | upstream | npm/pip contact their registries during `npm install` / `pip install` | detection unit-tested with a fake binary |

## v0.4 dnsx (DNSSEC, zone import/export, mailing lists)

No new Go dependency (stdlib only). External programs, invoked as separate processes with argv (never linked):

| Program | Repo | License | Version | Maintenance | Telemetry | Use |
|---|---|---|---|---|---|---|
| pdnsutil (PowerDNS Authoritative) | https://github.com/PowerDNS/pdns | GPL-2.0 | distro package (4.x) | active | none | `secure-zone`, `rectify-zone`, `disable-dnssec`, `increase-serial`, `show-zone` |
| mlmmj | https://codeberg.org/mlmmj/mlmmj | MIT | distro package (1.3+/1.4) | maintained (codeberg) | none | `mlmmj-receive` (Postfix pipe), `mlmmj-sub`, `mlmmj-unsub`, `mlmmj-list` |

mlmmj was chosen over Mailman 3 (GPL-3.0, Python/Django + PostgreSQL stack, far heavier); both are free. Both are optional: without them the API/UI return `dnssec_not_installed` / `mlist_not_installed`.

## v0.4 devx (Git Version Control, Terminal, Track DNS, Dynamic DNS)

No new module. Two packages of modules already in go.mod are now imported directly:

| Package | Module / version | License | Use | Telemetry |
|---|---|---|---|---|
| golang.org/x/net/websocket | golang.org/x/net v0.60.0 (already direct) | BSD-3-Clause | browser terminal WebSocket (RFC 6455 server) | none |
| github.com/miekg/dns | v1.1.73 (was indirect via lego; now imported by internal/api — `go mod tidy` will drop the `// indirect` marker) | BSD-3-Clause | CAA lookups for Track DNS (net.Resolver has no CAA) | none |

The PTY is allocated with stdlib syscalls (/dev/ptmx, TIOCSPTLCK/TIOCGPTN) — no creack/pty. External programs, separate processes, argv only, never linked:

| Program | License | Use |
|---|---|---|
| git | GPL-2.0 | clone/init/pull/for-each-ref/log/archive, run as the account uid in its cage |
| tar (GNU tar) | GPL-3.0 | unpacks `git archive` into the deploy path, as the account |
| traceroute / tracepath (iputils) | GPL-2.0 / BSD | Track DNS traceroute; `not_installed` when neither exists |

## v0.4 dbx (databases)

| Name | Repo | License | Version | Maintenance | Telemetry | How used |
|---|---|---|---|---|---|---|
| PostgreSQL (server, psql, pg_dump, pg_restore) | https://git.postgresql.org/gitweb/?p=postgresql.git | PostgreSQL License (permissive, free) | distribution package (13+) | active, PGDG | none | optional, installed with `--with-postgresql`; external processes only |
| MariaDB (existing) | https://github.com/MariaDB/server | GPL-2.0 | distribution package | active | none | external server; no new Go dependency (driver go-sql-driver/mysql MPL-2.0 already present) |

No new Go modules were added (SCRAM uses stdlib `crypto/pbkdf2`, `crypto/hmac`, `crypto/sha256`).

## obsx (monitoring, alerts, FIM, OS health) — v0.4
No new Go dependencies (metrics writer, SMTP client and webhooks use the Go standard library).
External programs probed as separate processes when installed (never linked): smartmontools `smartctl`
(GPL-2.0), chrony `chronyc` (GPL-2.0), systemd `timedatectl`/`systemctl` (LGPL-2.1+), logrotate (GPL-2.0).
Optional, not installed by BPANEL: Prometheus (Apache-2.0), Grafana OSS (AGPL-3.0, separate service).
Notification services used only if the admin configures them, all free: Telegram Bot API, Slack incoming
webhooks, Discord webhooks. No telemetry.

## v0.4 docsx — completeness pass (FREE-ONLY rule, 2026-10-10)

Rows for components that v0.4 modules install or drive but that no module section above listed. All are
free/open source and run as **separate processes** (nothing here is linked into the Go binaries).
"Verified" = licence checked against the upstream repository this round (`yes`) or taken from the
project's well-known licence without re-reading the file (`known`).

| Component | Module | Use | License | Installed how | Telemetry | Verified |
|---|---|---|---|---|---|---|
| ModSecurity v2 (`mod_security2`) | netsec WAF | Apache WAF engine | Apache-2.0 | distro pkg, admin opt-in | none | known |
| libmodsecurity v3 + ModSecurity-nginx connector | netsec WAF | nginx WAF engine | Apache-2.0 | distro pkg (`libnginx-mod-http-modsecurity`) | none | known |
| OWASP CoreRuleSet | netsec WAF | WAF rules | Apache-2.0 | distro pkg (`modsecurity-crs`) | none | yes (§5) |
| CrowdSec engine + `crowdsec-firewall-bouncer` | netsec / installer `--with-crowdsec` | behaviour bans | MIT / MIT | distro/vendor pkg, opt-in (Debian family) | Central API signal sharing: BPANEL leaves CAPI enrolment to the admin; no paid console, blocklist subscription or CTI key is used | yes (§5) |
| Dovecot Pigeonhole (Sieve, ManageSieve) | mailx | autoresponders, filters | LGPL-2.1 | distro pkg | none | known |
| Rspamd | mailx | spam filters | Apache-2.0 | vendor pkg | see §3 (fuzzy/URL checks to rspamd.com can be disabled) | known |
| bubblewrap (`bwrap`) | isolation | per-account cage | LGPL-2.0-or-later | distro pkg | none | yes (§5) |
| systemd (slices, sandboxing directives) | isolation, appx | cgroup v2 limits, hardened FPM/app units | LGPL-2.1-or-later | base OS | none | known |
| chrony, traceroute, git | installer v0.4 base packages | time sync, Track DNS, Git | GPL-2.0 / GPL-2.0 / GPL-2.0 | distro pkg | none | known |
| smartmontools | installer `--with-smart`, obsx | disk health | GPL-2.0 | distro pkg, opt-in | none | known |
| mlmmj | dnsx, installer full profile | mailing lists | MIT | distro pkg / EPEL | none | known |
| OpenSSH (`ssh`, `sftp`) | xfer, backup SFTP target | remote transfer | BSD-style (OpenSSH licence) | base OS | none | known |
| S3-compatible storage (any: MinIO, Garage, Ceph RGW, a provider) | backup | optional remote restic target | n/a (protocol) | admin-supplied endpoint; no specific paid provider required | provider's own | — |
| Redis note | mail (Rspamd) | Rspamd cache | BSD-3 (≤7.2) / RSALv2+SSPLv1+AGPL-3.0 (7.4 → 8.x) | distro pkg | none | known |

**Redis:** the distribution decides the version. Redis ≤ 7.2 is BSD-3; Redis 8.x can be used under
AGPL-3.0 (OSI). If a distribution ships the 7.4 line (RSALv2/SSPL only, not OSI), install **Valkey**
(BSD-3-Clause, https://github.com/valkey-io/valkey) instead; Rspamd works with either.

**Commercial products:** Imunify360 and Monarx appear only in the provider registry as
`commercial_optional`, **detect-only** entries (`internal/providers/builtin.go`, `internal/agent/providers.go`):
if an admin already runs one, the Integrations page shows it as present. BPANEL never installs,
configures, requires or calls them, and every feature they would cover has a free built-in path
(Shield + ClamAV/YARA). No CloudLinux, LiteSpeed Enterprise, Softaculous, KernelCare, JetBackup, cPanel
licence, paid DNS/registrar API or paid threat feed is referenced by the code (grep, 2026-10-10).

### Secret providers and storage tests (v0.4 baox)

| Component | Repo | License | Version tested | Use | Telemetry |
|---|---|---|---|---|---|
| OpenBao | github.com/openbao/openbao | MPL-2.0 | v2.7.1 | optional external secret server (HTTP API only; no Go SDK linked) | none |
| rclone | github.com/rclone/rclone | MIT | v1.75.2 | test-only S3/SFTP server for `-tags realstorage` (separate process) | none |
| restic | github.com/restic/restic | BSD-2-Clause | 0.19.1 | backup engine (separate process, already used) | none |

No new Go module dependencies were added.
