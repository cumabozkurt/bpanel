# BPANEL v1.1.0 — container end-to-end verification (E2E)

**Result: every cPanel/WHM feature row of [`docs/feature-matrix.md`](../../feature-matrix.md) (97 / 97)
was driven end to end and passed. 520 checks passed, 0 failed, 1 skipped (environment; the same
lookup passed in the supplementary suite).** Build under test: `bpanel 1.1.0 12857cd`, the same
binaries as in the `linux-amd64` archive of the v1.1.0 release (`bpanel-api` SHA-256
`a5e6d0795331ac12f8be9884c5fa03ff55cfd1358f46c6a4a78e97c00d601e53`), installed as an upgrade over
the earlier 1.1.0 test builds.

## Environment

| | |
|---|---|
| Host image | `docker.io/library/ubuntu:24.04` + systemd ([`test/e2e/Containerfile.ubuntu`](../../../test/e2e/Containerfile.ubuntu)), rootful podman, **systemd as PID 1** |
| Install | `install.sh --profile full` (fresh v1.0.0 install, then in-place upgrades to v1.1.0; last upgrade log: [`logs/upgrade-1.1.0-12857cd.log`](logs/upgrade-1.1.0-12857cd.log)) |
| Real services | nginx + Apache, PHP-FPM 8.3, MariaDB, PostgreSQL 16, PowerDNS (gsqlite3, DNSSEC), Postfix, Dovecot + Pigeonhole, Rspamd, Roundcube, phpMyAdmin, Pure-FTPd, mlmmj, Radicale, GnuPG, ModSecurity + OWASP CRS, ClamAV, YARA, nftables, fail2ban, restic, Node.js, Python, Ruby |
| Test doubles | Pebble (local ACME CA, real lego HTTP-01 flow), `cfmock.py` (local Cloudflare API), `hook.py` (webhook receiver) |
| Not covered | real VPS, AlmaLinux 9, Let's Encrypt production, the real Cloudflare API, SFTP/S3 backup targets, multi-server across two hosts |

## How the suites work

The suites ([`test/e2e/`](../../../test/e2e/)) run **inside** the server as root. Each check calls the
panel API over HTTPS on 2083/2087 with a real session (admin, reseller or user, CSRF + step-up
re-auth like the UI) and then checks the **system effect** with the real tool: mail found in the
Maildir, `dig` answer from PowerDNS, rule in `nft list`, `ps` shows the account user, file owner and
mode, `openssl s_client` certificate, IMAP/SMTP/SSH/FTPS logins, `psql`/`mysql` queries, and so on.
Negative checks (traversal, foreign domains, wrong passwords, refused values, locked modes) are
part of every section.

| Suite | Scope | Checks | Result |
|---|---|---|---|
| `v11.sh` | v1.1 parity features (Email Routing, BoxTrapper, GnuPG, CalDAV/CardDAV, SSH keys, Visitors, Site Publisher, Images, PostgreSQL browser, Cloudflare, Indexes/Handlers/Leech, Mail Queue, Mail Troubleshooter, IP Functions, Hostname, Tweak Settings, PHP extensions, billing/WHMCS) | 159 | **159 PASS** |
| `v10.sh` | rows that v1.0.0 marked "unverified" (mail filters/spam/lists, webx, Git, remote MySQL, DNSSEC, DDNS, tokens, WAF, Shield, apps, installer, resellers, updates, monitoring, alerts, brute force, firewall, limits, DNS cluster, Transfer Tool, plugins, secrets, …) | 219 | **217 PASS, 1 FAIL → PASS on re-run, 1 SKIP** |
| `core.sh` | v0.1–v0.3 core (accounts, packages, domains, files, DNS, mail, FTP, databases, phpMyAdmin, backups/restore, AutoSSL, logs, PHP, cron, password/2FA/sessions, preferences, services, suspend/terminate) | 129 | **129 PASS** |
| `extra.sh` | Ruby apps (Application Manager), Track DNS NS lookup | 14 | **14 PASS** |
| **Total** | | **521** | **520 PASS, 0 FAIL, 1 SKIP** |

Per-area tallies (pass/total):

- **v11:** setup 8/8, visitors 5/5, routing 9/9, boxtrapper 7/7, gpg 8/8, dav 9/9, ssh 11/11, sitepub 7/7, images 7/7, pg 11/11, cf 9/9, webx 12/12, mailq 12/12, trouble 4/4, ips 12/12, hostname 6/6, tweak 7/7, phpext 6/6, billing 7/7, whmcs 2/2
- **v10:** setup 4/4, mail 12/12 (after re-run), lists 6/6, track 3/3, webx 13/13, git 6/6, dbx 14/14, dnsx 12/12, ddns 6/6, bw 3/3, tokens 6/6, waf 9/9, shield 8/8, phpini 4/4, apps 9/9, inst 10/10, tdns 3/3 (+1 skip), contact 2/2, umgr 1/1, usage 3/3, term 4/4, modify 4/4, resl 8/8, upd 5/5, mon 5/5, alerts 7/7, brute 5/5, fw 10/10, limits 5/5, dbset 3/3, cluster 5/5, xfer 7/7, plug 7/7, integ 3/3, events 2/2, secrets 4/4
- **core:** c-setup 2/2, packages 3/3, accounts 9/9, domains 9/9, redirects 4/4, files 14/14, disk 1/1, zone 8/8, email 6/6, forwarders 2/2, catchall 2/2, deliverability 2/2, email-disk 1/1, webmail 2/2, ftp 5/5, mysql 2/2, phpmyadmin 2/2, backups 2/2, restore 2/2, ssl 6/6, logs 3/3, php 5/5, cron 5/5, password 2/2, 2fa 5/5, sessions 1/1, prefs 3/3, server-info 1/1, basic-setup 3/3, audit 1/1, services 4/4, suspend 9/9, terminate 2/2, api-docs 1/1
- **extra:** x-setup 4/4, ruby 9/9, tdns 1/1

API coverage: the suites called **235 distinct method + route pairs** (526 calls; [`results/coverage.tsv`](results/coverage.tsv)).
UI: **174 / 174** page loads (every v1.1 page, user and admin, EN and TR) rendered without JS errors,
API 5xx or untranslated keys ([`ui/ui-smoke.json`](ui/ui-smoke.json), screenshots in
[`docs/screenshots/v11/`](../../screenshots/v11/)).

## Non-PASS results, explained

| Check | What happened | Resolution |
|---|---|---|
| `v10 T016 [mail] deny-listed sender rejected/not in INBOX` | Rspamd reloads asynchronously after the settings change; the test mail was scanned in the same second as the reload, before the new per-account rule was active. | Harness now waits until `rspamc stat` answers after the reload. Re-run of `v11.sh setup` + `v10.sh setup mail` on the same build: 24/24 PASS ([`results/run7-mail-rerun.tsv`](results/run7-mail-rerun.tsv)). Product behaviour (rule active a few seconds after saving) is unchanged and documented. |
| `v10 T127 [tdns] dns lookup NS of the own zone` (SKIP) | Track DNS uses the system resolver like cPanel; the container's upstream resolver answers no NS queries at all. | `extra.sh nsdns` points the resolver at the server's own PowerDNS for the duration of the check: PASS. |

### Product bugs the E2E found in this round (fixed in v1.1.0)

All of these were fixed in the code before the final run; see `CHANGELOG.md` for details.

- Preferences accepted any well-formed language tag (`"xx"`); now only shipped UI languages (`en`, `tr`).
- Earlier rounds (before run 7): secret store path under `ProtectSystem=strict`, Sieve link / Dovecot
  home inside the Maildir root, Rspamd `*@domain` lists, Postfix transport map path, mlmmj full paths and
  list address alias, DNSSEC (`gsqlite3-dnssec`, cache purge), hotlink `server_names`, Git push to
  non-bare repos, Debian ModSecurity base config, fail2ban allowlist resync, suspended accounts' mail
  logins, login shell for shell users, quota on overlay filesystems, webx dir mode, Shield false
  positives on WordPress docblocks, loopback SMTP alerts, Transfer Tool zones and password hashes,
  Radicale storage owner, hostname change in containers, agent 4xx codes.

### Harness bugs fixed in this round

- `core.sh` restore picked the newest snapshot, which is the database dump (`tags: db`) since the suite
  also creates a database; it now picks the `files` snapshot.
- After AutoSSL issues a certificate the vhost redirects HTTP to HTTPS; site checks now follow redirects.
- Random test passwords could be shorter than the 10-character minimum (`DbW${RANDOM}x7k`).
- A shared `/tmp/pma.jar` cookie jar between concurrent runs.

## Run history (this release)

| Run | Build | Notes |
|---|---|---|
| run 3–5 | earlier 1.1.0 test builds | many FAILs; drove the product fixes above |
| run 6 | `2ed9870` | v11 + v10: 377 PASS, 0 FAIL, 1 SKIP; core: 7 FAIL (6 harness, see above, + the preference-language bug) |
| **run 7** | **`12857cd` (release build)** | v11 159/159, v10 217 + 1 re-run PASS + 1 SKIP, core 129/129, extra 14/14 |
| run 7 (parallel) | `12857cd` | a second core run accidentally ran concurrently ([`results/run7-core-interrupted.tsv`](results/run7-core-interrupted.tsv)): 126 PASS, 3 FAIL, all from the short random DB-wizard password and the shared cookie jar (harness) |
| run 8 | `12857cd` | core again, alone, with the fixed harness: **129 / 129 PASS** ([`results/run8-core.tsv`](results/run8-core.tsv)) |

## Files

- `results/run7-*.tsv` — one row per check (`id, status, area, check, detail`)
- `results/coverage.tsv` — every API call (method, route template, role, HTTP code)
- `logs/` — console output of each run and the upgrade log (one-time login token redacted)
- `ui/` — UI smoke run (EN + TR)
- The suites themselves: [`test/e2e/`](../../../test/e2e/) (`README.md` explains how to run them)

The feature matrix is generated from these files:

```sh
python3 test/e2e/tools/matrix.py docs/feature-matrix.md \
  docs/evidence/e2e-v1/results/run7-v11.tsv <run7-v10 without the superseded T016 row> \
  <T016 row of run7-mail-rerun.tsv> docs/evidence/e2e-v1/results/run7-core.tsv \
  docs/evidence/e2e-v1/results/run7-extra.tsv
```

**Honest limits:** this is a container on one host, not a production VPS; AlmaLinux 9 was not run; the
release archives are unsigned. See the README "Known limitations".
