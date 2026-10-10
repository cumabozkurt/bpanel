# Changelog

All notable changes to BOZKURT PANEL (BPANEL). Dates are Europe/Istanbul.

## v1.1.0 — 2026-10-11 (cPanel/WHM parity + container E2E)

v1.1.0 closes the cPanel/WHM rows that v1.0.0 listed as **not planned** or **partial**, and runs
every feature row end to end in an Ubuntu 24.04 container with systemd as PID 1 and the real
services (Postfix, Dovecot, Rspamd, PowerDNS, MariaDB, PostgreSQL, nginx + Apache, ModSecurity +
CRS, ClamAV, YARA, nftables, fail2ban, Radicale, mlmmj). The E2E found real bugs, fixed below.
Evidence: `docs/evidence/e2e-v1/SUMMARY.md`. Archives are still **unsigned** (no release key).

### Added (user panel)
- **Email Routing** (local / backup MX / remote, Postfix transport maps), **BoxTrapper**
  (Sieve-based challenge/allow-list), **Email Encryption** (per-account GnuPG keyring: import,
  generate, export public keys, delete).
- **Calendars & Contacts**: CalDAV/CardDAV with Radicale (bcrypt logins, per-account collections).
- **SSH Access › Manage SSH Keys** (import, generate, authorise, delete).
- **Visitors** (per-domain access-log viewer with filters), **Leech Protection** (per-user login
  limits for protected directories), **Indexes** (per-directory listing mode), **Apache Handlers**.
- **Site Publisher** (templates written into a docroot), **Images** (thumbnailer, scaler,
  converter), **PostgreSQL** read-only table browser, **Cloudflare** DNS sync (API token
  in the secret store; dry-run diff before apply).
### Added (admin panel)
- **Mail Queue Manager** (list, inspect, queue actions), **Mail Troubleshooter** (route
  trace + MX/SPF lookups), **IP Functions** (add/remove IPs, assign to accounts), **Change
  Hostname**, **Tweak Settings**, **PHP extensions** per version (distribution packages),
  **billing events + WHMCS-style hooks** (signed `account.*` webhooks and a reference PHP module).
- Migration `0022_v11.sql` (mail routing, BoxTrapper, DAV logins, account IPs, Cloudflare links).
- Installer (profile `full`): optional packages gnupg, radicale, python3-bcrypt, ruby, bundler,
  postgresql client (EL: gnupg2, ruby, rubygem-bundler, postgresql).
- UI: 376 new strings, EN = TR (3 015 keys); every page reachable from `tools.js`.

### Fixed (found by the container E2E)
- **Secret store unusable since v0.4**: the API (read-only `/etc` under `ProtectSystem=strict`)
  could not create `/etc/bpanel/secret.key`, so webhooks, Cloudflare and the Transfer Tool failed
  with `secrets_unavailable`. The key now lives in `/var/lib/bpanel/keys/secret.key` (0600,
  bpanel); upgrade copies an existing legacy key.
- **Mail**: the Sieve activation link `~/.dovecot.sieve` and Dovecot's duplicate database
  `~/.dovecot.lda-dupes` sat in the Maildir++ root, which listed them as folders and made
  `fileinto` into a new folder fail after any vacation reply. The link is now `~/dovecot.sieve` and
  Dovecot's home is `<mailbox>/bpanel-home` (2.3 `override_fields`, 2.4 `fields`, both tested);
  upgrade migrates existing mailboxes.
- **Rspamd allow/deny lists** written as `*@domain` never matched; entries are normalised to
  `@domain` (deny-listed senders are now rejected with 554).
- **Email routing / mailing lists**: Postfix `transport_maps` pointed at
  `/etc/postfix/bpanel_mlmmj_transport` while the agent wrote `/etc/postfix/bpanel/…`; mlmmj
  tools were run by bare name and refused ("must be invoked with full path").
- **DNSSEC** could not be enabled: PowerDNS needs `gsqlite3-dnssec=yes`; disabling DNSSEC on an
  unsigned zone is now a no-op instead of an error.
- **Hotlink protection** could never be enabled on nginx ("conflicting parameter"): the own
  domain was rendered after `server_names`, which already contains it; server names and
  duplicate allowed domains are no longer repeated.
- **Mailing lists** never received mail: Postfix rejected the list address ("User unknown in
  virtual mailbox table") before reading the transport map; the list address is now an identity
  alias (removed with the list).
- **DNSSEC**: signed answers appeared only after the PowerDNS cache expired; the zone is now
  purged from the cache (`pdns_control purge`) on enable/disable.
- **Git Version Control**: pushing to a panel-created repository was refused (checked-out branch
  of a non-bare repository); new repositories set `receive.denyCurrentBranch=updateInstead`.
- **WAF on Debian/Ubuntu Apache** had no audit log and no request-body inspection, because only
  `modsecurity.conf-recommended` exists; the first WAF apply installs it as `modsecurity.conf`
  with the engine Off globally (each domain's include switches it on) and
  `SecRequestBodyLimitAction ProcessPartial`. An existing `modsecurity.conf` is never touched.
- **Brute-force allowlist** entries were lost whenever fail2ban restarted (runtime `ignoreip`
  only); the API re-pushes the allowlist to every jail every 5 minutes.
- **Directory privacy / error pages** returned 500: `/var/lib/bpanel/webx` was 0700, nginx could
  not read the htpasswd files (now 0711).
- **BPanel Shield** quarantined 19 WordPress core files (`php_backtick_input` matched Markdown
  backticks in docblocks); the rule now only fires on code lines. Regression test runs every
  heuristic over the WordPress tree (1 512 PHP files, 0 hits).
- **E-mail alerts** always failed (`obsx_smtp_unavailable`): Go's `smtp.SendMail` upgraded to
  STARTTLS and rejected the host certificate for `127.0.0.1`; loopback delivery is now plaintext.
- **Transfer Tool**: imported zone files were applied empty (zone text dropped over RPC), and
  mailbox passwords were reset; cPanel crypt hashes (`$6$`, `$5$`, `$2y$`, `$1$`) are now kept.
- **Radicale** storage was root-owned (permission denied); **hostname** change failed in
  containers (`/etc/hostname` bind mount: EBUSY); agent validation errors answered 502 instead of
  409/422.

### Changed
- Version **1.1.0** everywhere (`internal/version`, `Makefile`, `install.sh`, `web/package.json`,
  `docs/openapi.json`).
- `docs/feature-matrix.md` rewritten from the E2E evidence; "not planned" removed.
- GitHub Pages site fully bilingual (EN/TR) with automatic language detection and a persistent
  switcher.

## v1.0.0 — 2026-10-10 (first public open-source release)

v1.0.0 is the first public release of BOZKURT PANEL on GitHub
(<https://github.com/cumabozkurt/bpanel>), with a project site on GitHub Pages
(<https://cumabozkurt.github.io/bpanel/>). It is the v0.4 feature set (≈82 % of the cPanel/WHM
feature list, see `docs/feature-matrix.md`) after a full release audit: every automated test was
re-run, the failures it found were fixed and the version strings were brought into line. **No
feature was added or removed** and the database schema is unchanged (no new migration), so an
upgrade from v0.4.0 only replaces binaries and re-applies the configuration.

**Honest status:** the code, its unit/race/fuzz/regression tests and the installer's signature
checks pass, but BPANEL has **still not been run on a real Ubuntu 24.04 or AlmaLinux 9 server with
systemd as PID 1** (see "Known limitations" in `README.md`). Use a disposable VPS first.

### Fixed
- **Archive path canonicalisation (`internal/xfer`, Transfer Tool).** `CleanName` accepted entry
  names such as `./\x` or `./C:x` that only look absolute after `path.Clean` removes the `./`
  prefix, so the canonical name was not stable (a second call rejected it). The cleaned name is now
  checked again and refused as `xfer_archive_unsafe`. Found by the existing `FuzzCleanName` target;
  the crashing input is kept as a regression corpus (`internal/xfer/testdata/fuzz/FuzzCleanName/`).
- **Data races in API tests.** `TestObsxAlertDedupCooldownAndIncidents` and the webhook retry test
  changed a captured `now` variable while event deliveries read `Server.Now` on background
  goroutines; `go test -race ./...` failed. A goroutine-safe fake clock (`internal/api/testclock_test.go`)
  replaces it. Production code was not affected (`Server.Now` is `time.Now` outside tests).
- **`installer/test/test-install-sh.sh` (root mode).** The end-to-end check still expected the
  installer to run from the unpacked archive; since R2-SYS-17 `install.sh` copies the verified
  binaries to `/usr/local/lib/bpanel` and runs them from there. The expectation was updated and a
  check that the binaries are really copied was added.
- **Node join instructions pointed at port 8443.** The end of a `--node` install, the agent's
  `join` help comment and `docs/installation.md` told the admin to run
  `bpanel-agent join --panel https://<main-panel>:8443`, but BPANEL never listens on 8443: the
  one-time join endpoint `/msrv/join` is served on the user-panel port **2083**. All three now say 2083.
- **`bpanel-installer render --out DIR`** failed with "no such file or directory" (profile `full`)
  unless `DIR` already existed, although the README shows it with a fresh `/tmp/cfg`. The output
  directory is now created first. Verified for `--distro ubuntu` and `--distro almalinux`.
- **Dev mode (`make dev`).** The secret store tried to create `/etc/bpanel/secret.key` and failed
  for the non-root developer ("secret store unavailable"). Dev runs now keep the key in `--dev-dir`.
- **`.gitignore`.** `dist/` also matched `internal/webui/dist`, so a fresh clone had no embedded web
  UI and `go build` failed (`pattern all:dist: no matching files`). Patterns are now anchored
  (`/dist/`, `/bin/`) and the built SPA is committed.

### Changed
- Version **1.0.0** everywhere: `internal/version`, the agent's default, `Makefile` `VERSION`,
  `installer/install.sh` `BPANEL_DEFAULT_VERSION` (was still `0.3.0`, which made `make release-check`
  fail), `web/package.json`, `docs/openapi.json` (regenerated; was stamped `0.3.0`) and the docs.
- `gofmt` applied to the 19 Go files that were not formatted (whitespace only).
- Web UI rebuilt and re-embedded (`make web embed`).

### Added
- GitHub Pages project site in `docs/` (`docs/index.html`, static, no build step) with features,
  ports, install steps, screenshots and links.
- New v1.0 screenshots in `docs/screenshots/v1-*.png` (Shield, Firewall, Monitoring, Servers,
  Transfer Tool, App Installer, Resource Usage, …) captured from `make dev`.
- `CONTRIBUTING.md`, `SECURITY.md`, a GitHub Actions CI workflow (`.github/workflows/ci.yml`: vet,
  tests, i18n check, web build, install.sh signature tests) and issue templates.
- Release notes: `docs/release-notes/v1.0.0.md`.

### Verification (2026-10-10, Go 1.27.2, Node 20, pnpm 10, Debian 13 amd64 build host)
| Check | Result |
|---|---|
| `go build ./...`, `go build -tags dev ./...`, `go vet ./...` | pass |
| `go test ./...` | 28 packages ok, 9 without tests, 0 failures |
| `go test -race ./...` | 0 races, 0 failures (after the test-clock fix) |
| 16 fuzz targets × 15 s (+ `FuzzCleanName` 45 s after the fix) | 1 finding (fixed above), then all pass |
| `govulncheck ./...` | 0 vulnerabilities reached by the code (1 in a required module, not called) |
| `pnpm audit --prod` | no known vulnerabilities |
| `pnpm run i18n:check` | 2639 keys, EN = TR |
| `svelte-check` | 0 errors (2 a11y warnings) |
| `pnpm run build` | pass |
| `installer/test/test-install-sh.sh` (minisign + OpenSSL, as root in a private mount namespace) | all checks pass |
| `make dev` smoke test + headless Chrome screenshots of 11 pages | pass |
| `make validate-configs`, real Ubuntu 24.04 / AlmaLinux 9 install | **not run** for this release (no scratch VM/container available) |

### Upgrade
`sudo bpanel-installer upgrade` with the v1.0.0 binaries (see `docs/upgrade.md`). No database
migration; the pre-upgrade backup in `/var/backups/bpanel/upgrade-0.4.0-to-1.0.0-*` is still taken.

## v0.4.0 — 2026-10-10 (preview, cPanel/WHM parity + security platform)

v0.4 extends v0.3 (nothing rewritten) with the security platform from the master spec and the
remaining cPanel/WHM tools. Every tool that was marked "Soon" now opens a real page; anything that
needs a program the server lacks answers `not_installed` / `unsupported` with a reason instead of a
fake success. **Everything is free software** (FREE-ONLY rule): no paid component, licence or API is
used or required (`docs/architecture.md` §3). Per-module detail: `docs/*.md`; evidence:
`work/v04/<module>/REPORT.md`. **Still not run on a real Ubuntu 24.04 / AlmaLinux 9 VM with systemd
as PID 1.** Parity: ≈82 % of the cPanel/WHM feature set implemented, ≈34 % verified end to end in a
container (`docs/feature-matrix.md`).

### Security foundation (waves 1–2)
- Fine-grained RBAC (`internal/rbac`, permission guard on every route), step-up re-authentication,
  idempotency keys, jobs queue, central security events with HMAC-signed admin webhooks
  (`/events`, `/webhooks`), log redaction, encrypted secrets at rest (AES-256-GCM envelope, optional
  OpenBao). Migrations 0005–0008.

### Isolation (CloudLinux-style, free)
- Per-account cgroup v2 slices (CPU, memory, IO, tasks), bubblewrap cage for shell/cron, hardened
  per-user PHP-FPM units, limit profiles on packages (`/limits`) and per-account usage (`/usage`).
  Kernel tests ran in a disposable child cgroup (OOM kill, pids.max); not under systemd PID 1.

### BPanel Shield (malware protection)
- Real-time watcher → scan queue → ClamAV / YARA (embedded rules) / native heuristics → fail-closed
  policy → AES-GCM quarantine and restore; safe upload pipeline; admin `/shield`, user `/malware-scans`.
  Engines were not installed in the sandbox: they report `not_installed`.

### Network security
- nftables firewall confined to `table inet bpanel` with lockout guard and confirm-or-rollback
  (`/firewall`), fail2ban brute-force management with allowlists (`/brute-force`), optional CrowdSec
  (CAPI off), per-domain ModSecurity + OWASP CRS (`/modsecurity`).

### cPanel tools (waves 3–7)
- Mail: autoresponders, filters (Sieve), spam filters (Rspamd), delivery tracking, mailing lists (mlmmj).
- Web: directory privacy, hotlink protection, error pages, MIME types, IP blocker.
- Usage: bandwidth accounting, MultiPHP INI editor, API tokens.
- Databases: remote MySQL hosts, PostgreSQL databases/users, process list, admin SQL settings.
- DNS: DNSSEC, BIND zone import/export, zone history and revert, Dynamic DNS.
- Developer: Git version control with deploy, browser terminal (in the account cage), Track DNS.
- Applications: checksum-pinned App Installer (WordPress, Joomla, Drupal, Nextcloud), WordPress
  Toolkit (WP-CLI), Node.js/Python Application Manager (`bpanel-app@` units).
- Admin: modify account, edit reseller privileges (reseller ACL), update preferences, contact e-mail,
  user manager.

### WHM / platform (waves 7–9)
- Backups: SFTP and S3-compatible restic targets, retention, restore verification (real restic e2e).
- Transfer Tool: import cPanel `cpmove` archives and BPANEL/remote transfers with unsafe-archive checks.
- Multi-server: panel CA, per-node mTLS certificates, `bpanel-agent join`, `/servers`.
- DNS cluster (PowerDNS AXFR/NOTIFY) and ed25519-signed plugins (`/plugins`).
- Monitoring: OS health, SMART, time sync, `/metrics` (Prometheus format), alerts to e-mail /
  Telegram / Slack / Discord, file-integrity monitoring; Grafana/Prometheus examples in `examples/`.
- Installer: v0.4 packages and directories, `--with-crowdsec`, `--with-smart`, v0.3 → v0.4 upgrade
  (`docs/installation.md`, `docs/upgrade.md`).
- QA: fuzz tests for parsers (dnsx, mailx, webx, xfer, clusterx), race runs, govulncheck.

### Docs
- `docs/index.md`, cPanel/WHM feature matrix with honest parity, "Free software only" section,
  licence table completed for every v0.4 component.

### Known gaps
- Not planned in v0.4: Email Routing, BoxTrapper, Email Encryption, Calendars & Contacts, Leech
  Protection, Indexes, Site Publisher, Mail Queue Manager, WHMCS hooks (see feature matrix).
- Services the sandbox could not run (Postfix/Dovecot/Rspamd live, nf_tables, ModSecurity, ClamAV,
  pdnsutil, systemd PID 1) leave most v0.4 features "working-unverified-on-real-host".

## v0.3.0 — 2026-10-09 (preview, round-2 audit fixes)

v0.3 closes the round-2 audit (`audit/round2/`: UX, functional E2E with the real agent,
performance/chaos, distro installs, white-box). Per-area detail: `audit/round2/fixlog-backend.md`,
`audit/round2/fixlog-installer.md`, `audit/round2/fixlog-ui.md`; evidence:
`audit/verification-v0.3.md`. **Still not run on a real Ubuntu 24.04 / AlmaLinux 9 VM with
systemd as PID 1**, and `curl | bash` stays blocked until a release key exists. Use a disposable server.

### Security (white-box, R2-WB)
- **R2-WB-1 (critical):** every tenant action of the root agent now requires a panel-managed account (ownership marker or `bpanel-users`); a central gate in `Dispatch` checks the account named by each of the 42 tenant methods before the handler runs, and every method must be classified (tenant or exempt) or the build's tests fail. Unmanaged accounts such as the cloud image's uid-1000 user get `not_managed`.
- **R2-WB-2:** `ssl.selfsigned` checks domain ownership. **R2-WB-3:** `mail.usage` no longer follows symlinks in `~/mail`. **R2-WB-4:** public suffixes (`com.tr`, …) cannot be claimed. **R2-WB-5:** a tenant owning the parent domain no longer blocks the panel hostname certificate.
- **R2-WB-6:** agent request memory is bounded (64 connections, 1 MiB lines free, 2 slots for large lines). **R2-WB-7:** strict request decoding (unknown fields, trailing data refused).
- **R2-WB-8:** database restore runs as a temporary MariaDB user limited to the one database. **R2-WB-12:** PHP INI values cannot contain separators/newlines. **R2-WB-13:** mailbox passwords use SHA512-CRYPT. **R2-WB-14:** critical units can be restarted but never stopped from the panel.
- **R2-WB-15:** installer validates hostname and e-mail. **R2-WB-16:** third-party repository keys are pinned by fingerprint. **R2-WB-18:** reproducible archives and `make release-check` (version strings, embedded UI, clean tree). **R2-WB-20:** fail2ban filters anchored.

### Functional fixes found with the real agent (R2-E2E)
- **R2-E2E-1 / R2-SYS-6:** restic lives in `/usr/local/lib/bpanel/bin/restic`, the cache in its own directory: backups work on a fresh install.
- **R2-E2E-2:** `default_php` is seeded from the detected distribution PHP (8.4 on Debian 13).
- **R2-E2E-3:** Dovecot 2.4 configuration syntax; **v0.3:** the agent writes `userdb_quota_storage_size` on Dovecot 2.4 (`dovecot_syntax` from `agent.json`, `capabilities.json` or `dovecot --version`) and keeps `userdb_quota_rule` on 2.3.
- **R2-E2E-4 / R2-SYS-2:** `openssh-server` is installed. **R2-E2E-5 / R2-SYS-12:** Postfix `myhostname` before `postmap`; Roundcube schema step idempotent.
- **R2-E2E-6:** zone reset keeps subdomain and addon records. **R2-E2E-7:** a mailbox quota change no longer corrupts the passwd-file extra field. **R2-E2E-8:** phpMyAdmin sign-on uses the configured port. **R2-E2E-9:** in-place mailbox restore is an atomic swap; a DB restore from a files snapshot is a 422 `snapshot_kind_mismatch`.
- **R2-E2E-10:** homes are `user:<web group> 0710`, skeleton files 0600 (no cross-tenant reads).

### Installer / system (R2-SYS)
- **R2-SYS-1** EL9 `curl-minimal` conflict; **R2-SYS-3/4/7/9** SSH host keys, `/run/sshd`, socket-activated `ssh` on Ubuntu, sshd enabled; **R2-SYS-5** selftest site check fixed so installs complete; **R2-SYS-8** cron started; **R2-SYS-10** `bpanel-installer upgrade` path from v0.1/v0.2; **R2-SYS-13** rspamd on `127.0.0.1`; **R2-SYS-14** `uninstall --purge` removes secrets/debris; **R2-SYS-17** installer copy kept on the system; **R2-SYS-18** disk-space message.
- **R2-SYS-15 (v0.3):** database users are mirrored to `'user'@'127.0.0.1'` and `'user'@'::1'` (same password and grants, every change applied to all), and MariaDB runs without `skip-name-resolve`; apps configured with DB host `127.0.0.1` work.
- **R2-SYS-16 (v0.3):** the API gates DNS, FTP (write), mail and webmail endpoints on the install-profile flags (`409 feature_disabled`, `field` = the feature), refuses an explicit Apache web mode when Apache is not installed, and reports `apache/dns/ftp/mail/webmail` in `/auth/me`; the UI hides those tools (dashboard, sidebar, palette, search). See `docs/capabilities.md`.

### Performance and resilience (R2-PERF)
- **R2-PERF-1** argon2 concurrency cap (503 when full); **R2-PERF-2** read-only SQLite pool, FTS5 audit search, cached counts; **R2-PERF-3** upload buffers; **R2-PERF-4** `BEGIN IMMEDIATE`, busy/disk-full → 503; **R2-PERF-5** stale provisioning rows rolled back at start; **R2-PERF-6** agent circuit breaker; **R2-PERF-7** compression + code splitting; **R2-PERF-8** server-side paging for accounts, audit and (v0.3, now also in the UI) DNS zones; **R2-PERF-9** quota batch; **R2-PERF-10** indexes; **R2-PERF-11** sampled 429 logging; **R2-PERF-12** `quick_check`, missing-DB and downgrade guards; **R2-PERF-13** `disk_full`; **R2-PERF-14** restic unlock; **R2-PERF-15** adoption of own interrupted accounts (also R2-SYS-11) and optimistic locking (ETag / `version`); **R2-PERF-16** cached sysinfo.

### UI (R2-UX)
- Roles: **R2-UX-01…05** reseller sees no admin-only tools, scoped packages, prefixed package names; **R2-UX-06** wrong-panel link.
- Forms: **R2-UX-10…23, 39, 40** no silent truncation, IDN/emoji domain rules, docroot/FTP dir rules, cron textarea, file-name rules, DB-wizard confirmation, DNS FQDN semantics and per-type validation, path bar, `wrong_current_password` (now also returned by `/account/password`), TOTP paste.
- **R2-UX-15 (v0.3):** a mailbox quota is pre-filled with, and capped at, the package mailbox quota (`package_quota_mb` in `GET /user/email/accounts`; the API refuses larger or unlimited quotas when the package sets one).
- Accessibility and visuals: **R2-UX-07, 08, 09, 24–32, 41** focus management, label-in-name, table headers, contrast, page titles, forced colours, print, plurals.
- Discoverability: **R2-UX-33…37** planned tools collapsed, deep links with intent, `.bpanel` hidden, system theme follow, notifications.
- `GET /admin/packages` is scoped for resellers server-side (R2-UX-03).

### Tests
- `TestR2AuditSearch` fixed (the audit row is written by the HTTP handler, so the test now creates the account through the API).
- New: `TestR3FeatureGates`, `TestR3ApacheGate`, `TestR3MailboxQuotaCap`, `TestR3DovecotQuotaSyntax`, `TestR3DBHosts`; UI checks in `work/r3-integrate/r3ui-tests.mjs`.

### Known limitations
See `audit/SUMMARY.md` → "Open items". In short: no real systemd VM run yet; no release key
(`make release-keygen`); DB users created before v0.3 get their `127.0.0.1`/`::1` twins on the
next password change; R2-WB-9/10/11/17/19/21/22 (low/info) are documented but not all fixed;
parity with cPanel/WHM is still partial.

## v0.2.0 — 2026-10-09 (preview, security/code/system/UX hardening)

v0.2 is a hardening release on top of the v0.1 preview. It closes the audit findings
listed in `audit/SUMMARY.md`; per-area detail is in `audit/fixlog-backend.md`,
`audit/fixlog-installer.md` and `audit/fixlog-ui.md`, and the verification evidence is in
`audit/verification-v0.2.md`. **It has still not been run on a real Ubuntu 24.04 or
AlmaLinux 9 server with systemd as PID 1.** Use a disposable VPS.

### Security
- **SEC-1 / SEC-9:** docroot, FTP dir and redirect values can no longer inject nginx/Apache/Pure-FTPd configuration (strict `RelPath`/`DocRoot`, agent re-validation, quoted templates that refuse unsafe values).
- **SEC-2 / SEC-3:** the root agent no longer follows tenant symlinks (`os.Root` + `O_NOFOLLOW` everywhere it touches a home); backup restores are staged in a root-only directory and copied in as the account.
- **SEC-4:** nginx `disable_symlinks if_not_owner`, Apache `SymLinksIfOwnerMatch`, no `AllowOverride All`.
- **SEC-5:** account creation refuses existing system users and homes; root-owned ownership markers in `/etc/bpanel/accounts`; cloud-image usernames reserved.
- **SEC-6 / SEC-7:** cross-account domain takeover and claiming the panel hostname/nameservers are refused (API, in the insert transaction) and mirrored by a new **agent-side ownership registry** (`internal/agent/owners.go`, CODE-27) for vhosts, zones and mail domains.
- **SEC-8:** the phpMyAdmin SSO password is sealed at rest; the token is single use and loopback only.
- **SEC-10:** `install.sh` verifies a minisign signature (with an OpenSSL fallback) from a second origin and fails closed while no release key is embedded.
- **SEC-12:** forwarders are removed with their domain; `:fail:` forwarders go to a Postfix `vreject` map (`check_recipient_access hash:/etc/postfix/bpanel/vreject`).
- **SEC-17 / SEC-18:** TOTP codes are single use; login lockout is per IP and per account+IP (no username lockout DoS).
- Login CSRF protection (JSON-only unauthenticated POSTs, `Sec-Fetch-Site`/`Origin` checks); right-most-untrusted `X-Forwarded-For`; no open redirect; real-byte zip-bomb budget.

### Backend
- Provisioning is a saga with recorded steps and compensation; termination is idempotent and retried.
- Real HTTP status codes, request IDs, no internal error text in 5xx; panic recoverer.
- Streaming upload/download (256 MiB per file, 1 GiB per request).
- AutoSSL renewal in the API housekeeping loop.
- Transactional quota checks; reseller limits and disk pool.
- New endpoints: atomic **Database Wizard** (`POST /user/db-wizard`), **activity feed** (`GET /account/activity`), **server-side dashboard favorites** (`PUT /account/preferences`), `limits` in `/meta`; generated error-code catalogue (`internal/api/errcodes.go`).
- Dev mode (mock agent + demo data) is compiled only with `-tags dev`; production binaries refuse `--dev`.
- Migrations are checksummed; `0002_hardening.sql`.

### Installer / system
- nginx base config generated from the stock config (no duplicate `gzip`), systemd-resolved stub handling, minimal profile is nginx-only.
- `/var/lib/bpanel` `root:bpanel 0751`; DB in `/var/lib/bpanel/db`; **`/home` is set to `root:root 0711`** so tenants cannot list other homes (the SFTP chroot stays `ChrootDirectory /home`).
- `pam_systemd` added to the cron PAM stack so cron jobs land in `user-<uid>.slice`; PHP-FPM runs in a new **`bpanel-php.slice`** (CPU/IO weight, `MemoryHigh`/`MemoryMax`, `TasksMax`) with `PrivateTmp=yes`.
- fail2ban jails (`sshd`, `bpanel`, and on full `roundcube-auth`, `dovecot`, `postfix-sasl`), logrotate fix, Postfix root alias, SELinux setup for AlmaLinux (not yet run on a real host), Ubuntu `ssh.socket` handling, apt lock waiting and resumable package stage.
- Uninstall leaves a working server (configs kept, firewall never left open).
- Agent unit exposure 9.0 → 5.4, API unit 4.3 → 1.2 (`systemd-analyze security`).
- Release signing: `make release-keygen`, `make release`, `make verify-release`.

### UI
- 25 UX fixes: mobile layout at 390 px, drawer, table overflow, sorting and paging, focus traps, skip link, contrast ≥ 4.5:1, File Manager keyboard support, unsaved-changes guard, cron validation, Turkish-insensitive search, IDN/punycode, translated errors.
- i18n: 997 keys, EN/TR parity enforced by `make web` (also every backend error code and audit action).

### Known limitations
See README → "Known limitations" and `audit/SUMMARY.md`. In short: no real Ubuntu 24.04 /
AlmaLinux 9 systemd VM run yet; `curl | bash` install is blocked until a release key is
generated (`make release-keygen`); CODE-21, 23, 25 and 26 remainders are deferred; the agent
ownership registry cannot stop a fully compromised API from naming the right owner; feature
parity with cPanel/WHM is about 13% end-to-end.

## v0.1.0 — 2026-10-09 (preview)
First preview: Go API + typed-action root agent + staged installer + SvelteKit UI (EN/TR).
