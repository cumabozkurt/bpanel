<p align="center">
  <img src="docs/assets/logo.svg" width="88" alt="BOZKURT PANEL logo">
</p>

<h1 align="center">BOZKURT PANEL (BPANEL) v1.0.0</h1>

<p align="center">
  <b>Free, open-source web hosting control panel with a cPanel/WHM-style layout and the same ports,<br>
  for Ubuntu 24.04 LTS and AlmaLinux 9.</b>
</p>

<p align="center">
  <a href="https://github.com/cumabozkurt/bpanel/releases/tag/v1.0.0"><img alt="Release" src="https://img.shields.io/github/v/release/cumabozkurt/bpanel?label=release&color=14b8a6"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <a href="https://github.com/cumabozkurt/bpanel/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/cumabozkurt/bpanel/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Go 1.27" src="https://img.shields.io/badge/Go-1.27-00ADD8">
  <img alt="Svelte 5" src="https://img.shields.io/badge/SvelteKit-Svelte%205-ff3e00">
  <img alt="Languages" src="https://img.shields.io/badge/i18n-EN%20%7C%20TR-informational">
</p>

<p align="center">
  <a href="https://cumabozkurt.github.io/bpanel/"><b>Website</b></a> ·
  <a href="docs/index.md">Documentation</a> ·
  <a href="docs/installation.md">Installation</a> ·
  <a href="docs/feature-matrix.md">Feature matrix</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="docs/release-notes/v1.0.0.md">Release notes</a> ·
  <a href="#türkçe">Türkçe</a>
</p>

> **Status: v1.0.0, first public open-source release** (the v0.4 cPanel/WHM parity + security
> platform after a full release audit, see [`CHANGELOG.md`](CHANGELOG.md)). **100 % free software**:
> no paid component, licence or API (`docs/architecture.md` §3). It builds; its unit, race, fuzz
> and security regression tests pass; the generated configs passed the real `nginx -t` /
> `apache2ctl` / `php-fpm -t` / `postfix check` tools; and a `minimal` install/uninstall was run as
> root in a Debian 13 container. It has **not yet been run on a real Ubuntu 24.04 or AlmaLinux 9
> server with systemd as PID 1**. Try it on a disposable VPS before production. See
> [Known limitations](#known-limitations).

![User dashboard](docs/screenshots/02-user-dashboard-en.png)

## Table of contents

[Ports](#ports-same-as-cpanelwhm) · [Install](#install) · [Upgrade](#upgrade) · [Uninstall](#uninstall) ·
[Features](#features-v100) · [Screenshots](#screenshots) · [Architecture](#architecture) ·
[Security](#security-model) · [Languages](#languages) · [Build from source](#build-from-source) ·
[Testing](#testing) · [Known limitations](#known-limitations) · [Contributing](#contributing) · [Licence](#licence)

## Ports (same as cPanel/WHM)

| Interface | HTTPS | HTTP (redirects to HTTPS) |
|---|---|---|
| User panel (cPanel equivalent) | **2083** | 2082 |
| Admin panel (WHM equivalent) | **2087** | 2086 |
| Webmail (Roundcube) | **2096** | 2095 |

All three sit at the root path (`https://server:2087/`). There is no `/yonetim` path and no port 8443.

## Install

On a **fresh** Ubuntu 24.04 or AlmaLinux 9 server, as root:

```bash
curl -fsSL https://get.bozkurtpanel.com | sudo bash
# non-interactive:
curl -fsSL https://get.bozkurtpanel.com | sudo bash -s -- \
  --hostname panel.example.com --email admin@example.com --profile full --lang en --yes
```

`install.sh` (in `installer/`) checks the OS and CPU, downloads
`bpanel-<version>-linux-<arch>.tar.gz` and its detached **minisign signature**,
verifies the signature against the release public key embedded in the script,
checks the binaries' SHA-256 sums and runs `bpanel-installer install`. The script
is served from `get.bozkurtpanel.com` (and the git repository) while the archives
come from GitHub Releases, so a compromised download host cannot slip in a
modified or older release: the signature's trusted comment names the file and the
version. `minisign` is used when installed, otherwise OpenSSL 3 (present on both
supported systems). A script without a release key refuses to install.

From an unpacked release archive you can run `sudo ./install.sh`; nothing is
downloaded, and `SHA256SUMS` is checked against `SHA256SUMS.minisig` first.
`BPANEL_ALLOW_UNSIGNED=1` runs an unsigned build you made yourself (development only).

The installer is staged and resumable (state in `/var/lib/bpanel/install-state.json`,
log in `/var/log/bpanel/install.log`). If a run stops, including in the middle of
package installation, run it again and it continues where it left off (an
interrupted dpkg run is completed first). On a fresh VM it waits for cloud-init
and unattended-upgrades to release the apt lock instead of failing.

> **v1.0.0 is not signed yet.** `get.bozkurtpanel.com` is not online and the release signing
> key has not been generated (`make release-keygen`), so the `curl | bash` one-liner above
> **fails closed** on purpose. Until signed releases exist you have two options:
>
> 1. **Use the v1.0.0 archive from GitHub Releases** (unsigned, SHA-256 checksums published):
>
>    ```bash
>    V=1.0.0; A=amd64   # or arm64
>    curl -fLO https://github.com/cumabozkurt/bpanel/releases/download/v$V/bpanel-$V-linux-$A.tar.gz
>    curl -fLO https://github.com/cumabozkurt/bpanel/releases/download/v$V/bpanel-$V-linux-$A.tar.gz.sha256
>    sha256sum -c bpanel-$V-linux-$A.tar.gz.sha256
>    tar -xzf bpanel-$V-linux-$A.tar.gz && cd bpanel-$V-linux-$A
>    sudo BPANEL_ALLOW_UNSIGNED=1 ./install.sh --hostname panel.example.com --email admin@example.com --profile full --yes
>    ```
>
> 2. **Build and sign it yourself**: `make release-keygen && make release` creates
>    `dist/bpanel-1.0.0-linux-amd64.tar.gz` signed with *your* key; copy it to the server,
>    unpack it and run `sudo ./install.sh`.
>
> `BPANEL_BASE_URL` points the script at another download location and `BPANEL_PUBKEY` at your
> own signing key. `BPANEL_ALLOW_UNSIGNED=1` only affects an unpacked local archive; the
> network install path always requires a valid signature.

Profiles: `minimal` (Nginx + PHP-FPM + MariaDB; every site is nginx-only, no Apache), `web` (+ Apache for `.htaccess`, PowerDNS, Pure-FTPd), `full` (+ Postfix/Dovecot mail, Rspamd, Roundcube webmail).
Flags: `--hostname --email --profile --lang en|tr --admin --php 8.2,8.4 --yes --force --allow-unsupported --skip-repos`.

What the installer changes on the system, besides installing packages:

- **Port 53 (web/full):** on Ubuntu, systemd-resolved's stub listener (127.0.0.53) is turned off
  (`/etc/systemd/resolved.conf.d/bpanel.conf`) so PowerDNS can answer on port 53, and
  `/etc/resolv.conf` points at resolved's upstream servers.
- **Firewall:** an nftables table `inet bpanel` (`bpanel-firewall.service`) replaces firewalld/ufw.
  SSH ports are read from `sshd -T` and, on Ubuntu 24.04, from `ssh.socket`.
- **fail2ban:** jails for SSH and the panel logins (and, with `full`, webmail, IMAP/POP3 and SMTP AUTH), banning through nftables.
- **SELinux (AlmaLinux):** file contexts for `/var/lib/bpanel`, `/usr/share/bpanel`, `/etc/bpanel/ssl`,
  `~/public_html`, `~/tmp`, `~/mail`, the needed `httpd_*`/`ftpd_full_access` booleans and ports 2090/2095/2096/8080.
- **Mail (full):** mail for `root` goes to `--email` (`/etc/aliases`).
- **Directories:** `/var/lib/bpanel` is `root:bpanel 0751`; the panel database lives in
  `/var/lib/bpanel/db` (API user only), ACME challenges in `/var/lib/bpanel/acme`
  (world-readable), webmail/phpMyAdmin state in `/var/lib/bpanel/apps` (`bpanel-apps`).
- **Logs:** `/etc/logrotate.d/bpanel` rotates domain logs daily (14 days) and the install log.
- Each PHP-FPM service gets a private `/tmp`; accounts use `~/tmp` through their pool.

`sudo bpanel-installer render --profile full --out /tmp/cfg` writes every generated
configuration file for review; `make validate-configs` checks them with `nginx -t`,
`apache2ctl configtest`, `php-fpm -t`, `postfix check`, `sshd -t`, fail2ban and
`systemd-analyze` on a scratch machine.

At the end the installer prints the panel URLs and a one-time admin login link (`bpanel login-link` makes a new one).

## Upgrade

```bash
curl -fsSL https://get.bozkurtpanel.com | sudo bash -s -- upgrade   # or, on the server:
sudo bpanel-installer upgrade
```

Running the installer on a server with an older version upgrades it automatically.
The upgrade installs packages a newer release needs, re-applies the system hardening
and service configuration of the new release, replaces the binaries and units,
migrates the panel database and files (for example the restic binary moved to
`/usr/local/lib/bpanel/bin/restic`), restarts the panel and runs the self-test.
Websites, mail and data stay online. It can be interrupted and run again; on an
up-to-date server it re-applies the configuration (`--force` repeats every step).
The installer keeps a copy of itself in `/usr/local/lib/bpanel`
(`/usr/local/sbin/bpanel-installer`), so neither upgrade nor uninstall needs the
original archive.

## Uninstall

```bash
sudo bpanel-installer uninstall          # remove the panel; sites, mail, DNS and DBs keep running
sudo bpanel-installer uninstall --purge  # also delete the panel database, configuration and secrets
```

The uninstaller removes the panel itself (`bpanel-api`, `bpanel-agent`, the binaries,
phpMyAdmin and the panel's fail2ban jail) and leaves the server **working**:

- nginx, Apache, PHP-FPM, PowerDNS, Postfix, Dovecot, Rspamd and Pure-FTPd keep the
  configuration the panel gave them. Stock files are not copied back over it (Apache's
  stock `ports.conf` would take port 80 from nginx, the stock `pdns.conf` would drop the
  zone database); the originals stay next to them as `*.bpanel-orig`.
- **Firewall:** firewalld or ufw, if one was active before the install, is turned back on
  with the site ports opened. Otherwise `bpanel-firewall.service` stays active without the
  panel ports. The server is never left without a firewall.
- systemd-resolved's stub listener stays off while PowerDNS is installed (both cannot own port 53);
  otherwise `/etc/resolv.conf` is restored.
- The SFTP jail (`/etc/ssh/sshd_config.d/50-bpanel.conf`) stays while hosting accounts exist.
- SELinux contexts and booleans stay (the sites still need them); the uninstaller prints the values from before the install.

`--purge` also deletes `/etc/bpanel/{api.json,agent.json,secrets,acme,restic,accounts,owners}`,
the panel database, the download cache and restic. Without `--purge`, restic and the backup
repository passwords stay so the backups in `/var/backups/bpanel` can still be restored. It keeps what running services still use and says so:
`/etc/bpanel/ssl` (the certificate of nginx, Postfix, Dovecot and Pure-FTPd),
`/var/lib/bpanel/acme` and the Roundcube webmail. Distribution packages are never
removed; use apt/dnf if you want them gone.

## Features (v1.0.0)

Full table with status per feature: [`docs/feature-matrix.md`](docs/feature-matrix.md). About **82 %** of the
cPanel/WHM feature set is implemented (96 tools wired, none left as "Soon"), about **34 %** verified end
to end in a container; none yet on a real VM.
Docs index: [`docs/index.md`](docs/index.md).

- **Email:** accounts, forwarders, catch-all, Roundcube webmail, SPF/DKIM/DMARC, autoresponders, Sieve filters, Rspamd spam filters, delivery tracking, mailing lists (mlmmj).
- **Files & web:** file manager, disk usage, FTP/SFTP, restic backups and restore, directory privacy, hotlink protection, error pages, MIME types, IP blocker, Git version control.
- **Databases:** MariaDB + wizard, phpMyAdmin SSO, remote MySQL, PostgreSQL, process list.
- **Domains & DNS:** addon/sub/alias domains, redirects, PowerDNS zone editor, DNSSEC, zone import/export and history, Dynamic DNS, DNS cluster.
- **Software:** MultiPHP + INI editor, App Installer (WordPress, Joomla, Drupal, Nextcloud), WordPress Toolkit, Node.js/Python Application Manager, cron, browser terminal, Track DNS.
- **WHM:** accounts, packages, resellers with privileges, modify account, services, update preferences, SQL settings, bandwidth, Transfer Tool (cPanel `cpmove` import), backup configuration, plugins, API tokens, OpenAPI.
- **Beyond cPanel:** BPanel Shield (ClamAV/YARA/heuristics, quarantine), nftables firewall with rollback, fail2ban/CrowdSec, ModSecurity + OWASP CRS, per-account cgroup v2 isolation and bwrap cage, multi-server over mTLS, monitoring/alerts/FIM with Prometheus metrics, RBAC, security events and webhooks, encrypted secrets.

## Screenshots

Captures live in [`docs/screenshots/`](docs/screenshots/) (EN/TR, light/dark, user and admin). The
`v1-*.png` files were captured from the v1.0.0 build in dev mode (mock agent, demo data); the numbered
files are the earlier v0.3 set with the same layout.

| | |
|---|---|
| ![Admin dashboard](docs/screenshots/v1-admin-dashboard.png) | ![BPanel Shield](docs/screenshots/v1-shield.png) |
| WHM-style admin dashboard (port 2087) | BPanel Shield malware protection |
| ![Firewall](docs/screenshots/v1-firewall.png) | ![Monitoring](docs/screenshots/v1-monitoring.png) |
| nftables firewall with confirm-or-rollback | Monitoring, alerts and incidents |
| ![User tools](docs/screenshots/v1-user-dashboard.png) | ![App Installer](docs/screenshots/v1-app-installer.png) |
| cPanel-style user tools (port 2083) | App Installer (WordPress, Joomla, Drupal, Nextcloud) |

## Architecture

| Part | What it does |
|---|---|
| `bpanel-api` (`cmd/bpanel-api`) | Go HTTP API + embedded SvelteKit SPA. Runs as the unprivileged `bpanel` user under systemd hardening and serves 2083/2082 and 2087/2086. SQLite state. |
| `bpanel-agent` (`cmd/bpanel-agent`) | Root helper on a unix socket (`/run/bpanel/agent.sock`), accepting only the API's uid (SO_PEERCRED). It runs a **fixed set of typed actions** (`account.create`, `web.vhost.apply`, `dns.rrset.replace`, …). Parameters are strictly decoded JSON (unknown fields rejected) and validated. External programs run as argv, **never through a shell**, and there is no "run command" action. |
| `bpanel` (`cmd/bpanel`) | Admin CLI: `version`, `login-link`, `admin`, `selftest`, `openapi`. |
| `bpanel-installer` | Staged installer / uninstaller. |
| `web/` | SvelteKit (Svelte 5) SPA, built into `internal/webui/dist` and embedded in `bpanel-api`. |

Stack it configures: Nginx (+ optional Apache behind it for `.htaccess`), PHP-FPM
(one pool per user, MultiPHP 8.1–8.5), MariaDB, PowerDNS, Postfix + Dovecot + Rspamd,
Roundcube, phpMyAdmin, Pure-FTPd, Let's Encrypt via lego, restic backups and nftables.

API reference: `docs/openapi.json` (OpenAPI 3.1), also served by the panel at `/openapi.json`.

## Security model

Summarised from [`docs/security.md`](docs/security.md), [`docs/isolation.md`](docs/isolation.md) and
[`docs/architecture.md`](docs/architecture.md); report vulnerabilities privately as described in
[`SECURITY.md`](SECURITY.md).

- **Privilege split:** the web-facing API runs as the unprivileged `bpanel` user under systemd hardening;
  only the root agent changes the system, over a unix socket restricted to the API's uid (SO_PEERCRED).
- **No shell, no "run command":** the agent exposes a fixed list of typed actions; parameters are
  strictly decoded, validated again by the agent and passed as argv. Paths go through `safefs`
  (canonical, under allowed roots, no symlink following).
- **Tenant gate:** every tenant action requires a panel-managed account, and the agent's ownership
  registry refuses cross-account actions on vhosts, zones and mail domains.
- **Accounts and sessions:** argon2id password hashing (OWASP baseline parameters), login rate limiting, TOTP 2FA with recovery codes,
  step-up re-authentication for sensitive actions, CSRF protection, fine-grained RBAC on every admin
  route, scoped API tokens, audit log and security events with HMAC-signed webhooks.
- **Secrets at rest:** AES-256-GCM envelope encryption (optional OpenBao provider); logs pass through a
  redaction handler.
- **Network:** nftables table `inet bpanel` with lockout guard and confirm-or-rollback, fail2ban
  (optional CrowdSec), per-domain ModSecurity + OWASP CRS, per-account cgroup v2 limits and a bubblewrap
  cage for shell, cron and the browser terminal.
- **Supply chain:** releases are designed to be minisign-signed, and `install.sh` fails closed without a
  release key; App Installer packages are version- and checksum-pinned.

## Languages

English is the default and Turkish is fully translated (2639 keys each in v1.0.0,
checked by `make i18n`). Every page has a language switcher. Each user's choice is stored
on their account (`PUT /api/v1/account/preferences`). Administrators set the
server default in **Settings**. To add a language, copy
`web/src/lib/i18n/locales/en.json` to `xx.json`, translate it and rebuild.

## Build from source

Needs Go 1.27+ (`go.mod` pins 1.27.2; with `GOTOOLCHAIN=auto` an older `go` downloads it), Node 20+ and pnpm 10.

```bash
git clone https://github.com/cumabozkurt/bpanel.git && cd bpanel
```

The built web UI is committed in `internal/webui/dist`, so `go build ./...` works on a fresh clone;
run `make web embed` after changing anything under `web/`.

```bash
make web embed     # build the SPA and copy it into internal/webui/dist
make vet test      # go vet + go test
make build         # host binaries in bin/
make release       # static linux-amd64 + linux-arm64 tarballs, SHA-256 sums and minisign signatures in dist/
make release-keygen   # one-time: create the release signing key, embed its public half in install.sh
make test-installer   # installer tests + install.sh signature tests
make validate-configs # generated configs through nginx -t, apache2ctl, php-fpm -t, postfix check, sshd -t (root, scratch box)
make dev           # run the API with the in-process mock agent on :2083 / :2087 (no root)
make openapi       # regenerate docs/openapi.json
```

Dev mode logins: admin `bpadmin` / `Demo-Pass-2026` (port 2087), user `demo` / `Demo-User-2026` (port 2083).

`packaging/` holds copies of the files the installer writes: systemd units
(`bpanel-api.service`, `bpanel-agent.service`, `bpanel-firewall.service`, PHP-FPM and
resolved drop-ins), logrotate, fail2ban, Apache base config, the SSH SFTP jail and tmpfiles.
A test keeps them identical to what the installer generates. The nginx base config is
generated per server (it only adds directives the distribution file does not set);
see `bpanel-installer render`.

## Testing

```bash
make vet test                     # go vet + go test ./...
go test -race ./...               # race detector (needs cgo / a C compiler)
make test-installer               # installer tests + install.sh signature tests (needs minisign + openssl)
make i18n                         # EN/TR key parity, tool and error-code coverage
cd web && pnpm install && pnpm run build
go test ./internal/xfer -run '^$' -fuzz FuzzCleanName -fuzztime 30s   # any of the 16 fuzz targets
```

Results for v1.0.0 are in [`CHANGELOG.md`](CHANGELOG.md#v100--2026-10-10-first-public-open-source-release)
and [`docs/release-notes/v1.0.0.md`](docs/release-notes/v1.0.0.md). CI runs vet, tests, the i18n
check, the web build and the install.sh signature tests on every push.

## Known limitations

- **No real-server run yet (also true for v1.0.0).** v0.3 was verified in a Debian 13 arm64 container without
  systemd as PID 1 and without nf_tables. A full run on Ubuntu 24.04 and AlmaLinux 9 VMs
  (systemd, SELinux, `ssh.socket`, systemd-resolved, nftables, AutoSSL against Let's Encrypt
  staging, `php.install` under the agent sandbox) is still required.
- **v1.0.0 archives are unsigned; `curl | bash` install is blocked until a release key exists.** `install.sh` fails closed
  while `BPANEL_RELEASE_PUBKEY` is `UNSET`. The maintainer must run `make release-keygen`
  (offline) and publish signed releases with `make release`.
- **Feature parity (v1.0.0 = v0.4 feature set):** about 82% of the cPanel/WHM feature list is implemented and about 34%
  is verified end to end in a container; most v0.4 tools are "working-unverified-on-real-host"
  (see `docs/feature-matrix.md`). No tool is marked "Soon" any more.
- **`/home` is set to `root:root 0711`** at install so tenants cannot list other homes (the
  SFTP chroot is `ChrootDirectory /home`). Uninstall does not change it back.
- **Agent ownership registry limit:** the root agent records which account owns each vhost,
  zone and mail domain and refuses cross-account actions, but a fully compromised API can
  still name the right owner for a victim's domain (the API is the identity provider).
- **Deferred code items:** CODE-21 (changing the server IP, nameservers or default PHP does not
  re-render existing zones/vhosts; the admin gets a warning), CODE-23 (no pagination on
  user-side lists), CODE-25 (bandwidth stat is 0, inode limit unused, "SSH Access" links to
  FTP), CODE-26 (`users.owner_id` has no `ON DELETE` rule; single SQLite connection).
- PHP-FPM pools share one `bpanel-php.slice`; true per-tenant FPM cgroups would need one FPM
  master per account. Cron jobs reach `user-<uid>.slice` through `pam_systemd`.
- After a hostname certificate renewal, Postfix/Dovecot/Pure-FTPd are not reloaded
  automatically yet.

## Contributing

Issues and pull requests are welcome; see [`CONTRIBUTING.md`](CONTRIBUTING.md). Please report
security problems privately ([`SECURITY.md`](SECURITY.md)), not in public issues.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE); third-party components and their
licences are listed in [`docs/third-party-licenses.md`](docs/third-party-licenses.md).

---

## Türkçe

**BOZKURT PANEL (BPANEL)**, cPanel/WHM düzenini ve portlarını kullanan, açık kaynaklı
(Apache-2.0) bir web hosting kontrol panelidir. **Ubuntu 24.04 LTS** ve **AlmaLinux 9** içindir.

> **Durum: v1.0.0, ilk açık kaynak sürüm** (v0.4 cPanel/WHM eşdeğerliği + güvenlik platformu, kapsamlı sürüm denetiminden geçmiş hâliyle; bkz. `CHANGELOG.md`). Proje sitesi: <https://cumabozkurt.github.io/bpanel/>. **Tamamen ücretsiz yazılım**: ücretli bileşen, lisans veya API yok. Özellik tablosu: `docs/feature-matrix.md` (yaklaşık %82 uygulanmış, %34 konteynerde uçtan uca doğrulanmış). Derleniyor; birim, race ve güvenlik regresyon testleri geçiyor,
> üretilen yapılandırmalar gerçek `nginx -t` / `apache2ctl` / `php-fpm -t` / `postfix check`
> araçlarından geçiyor, fuzz testleri temiz ve `minimal` kurulum/kaldırma bir Debian 13 konteynerinde root olarak
> denendi. **Henüz systemd çalışan gerçek bir Ubuntu 24.04 / AlmaLinux 9 sunucuda
> çalıştırılmadı.** Canlı sistem yerine silinebilir bir VPS kullanın.
> Bkz. [Bilinen sınırlamalar](#bilinen-sınırlamalar).

![Kullanıcı paneli](docs/screenshots/20-user-dashboard-tr.png)

### Portlar (cPanel/WHM ile aynı)

| Arayüz | HTTPS | HTTP (HTTPS'e yönlendirir) |
|---|---|---|
| Kullanıcı paneli (cPanel karşılığı) | **2083** | 2082 |
| Yönetici paneli (WHM karşılığı) | **2087** | 2086 |
| Web posta (Roundcube) | **2096** | 2095 |

Üçü de kök yolda açılır (`https://sunucu:2087/`). `/yonetim` yolu ve 8443 portu yoktur.

### Kurulum

**Temiz** bir Ubuntu 24.04 veya AlmaLinux 9 sunucuda, root olarak:

```bash
curl -fsSL https://get.bozkurtpanel.com | sudo bash
# etkileşimsiz:
curl -fsSL https://get.bozkurtpanel.com | sudo bash -s -- \
  --hostname panel.ornek.com.tr --email admin@ornek.com.tr --profile full --lang tr --yes
```

`install.sh` işletim sistemini ve mimariyi denetler, sürüm arşivini ve ayrık
**minisign imzasını** indirir, imzayı betiğin içine gömülü sürüm açık anahtarıyla
doğrular, ikili dosyaların SHA-256 sağlamalarını denetler ve `bpanel-installer install`
komutunu çalıştırır. Betik `get.bozkurtpanel.com` adresinden, arşivler GitHub
Releases'tan gelir: indirme sunucusu ele geçirilse bile değiştirilmiş ya da eski bir
sürüm kabul edilmez. Anahtarı olmayan bir betik kurulum yapmaz. Kurulum aşamalıdır;
yarıda kalırsa (paket kurulumunun ortası dahil) komutu yeniden çalıştırın, kaldığı yerden
devam eder. Yeni bir sunucuda apt kilidinin açılmasını bekler.

> **v1.0.0 henüz imzalı değil.** `get.bozkurtpanel.com` yayında değil ve sürüm imzalama
> anahtarı üretilmedi (`make release-keygen`); bu yüzden yukarıdaki `curl | bash` komutu
> bilerek kurulumu reddeder. İmzalı sürümler çıkana kadar:
>
> 1. **GitHub Releases'taki v1.0.0 arşivini kullanın** (imzasız, SHA-256 sağlamaları yayında):
>
>    ```bash
>    V=1.0.0; A=amd64   # ya da arm64
>    curl -fLO https://github.com/cumabozkurt/bpanel/releases/download/v$V/bpanel-$V-linux-$A.tar.gz
>    curl -fLO https://github.com/cumabozkurt/bpanel/releases/download/v$V/bpanel-$V-linux-$A.tar.gz.sha256
>    sha256sum -c bpanel-$V-linux-$A.tar.gz.sha256
>    tar -xzf bpanel-$V-linux-$A.tar.gz && cd bpanel-$V-linux-$A
>    sudo BPANEL_ALLOW_UNSIGNED=1 ./install.sh --hostname panel.ornek.com.tr --email admin@ornek.com.tr --profile full --lang tr --yes
>    ```
>
> 2. **Kendiniz derleyip imzalayın:** `make release-keygen && make release`, kendi anahtarınızla
>    imzalı `dist/bpanel-1.0.0-linux-amd64.tar.gz` üretir; sunucuya kopyalayıp açın ve
>    `sudo ./install.sh` çalıştırın.

Profiller: `minimal` (Nginx + PHP-FPM + MariaDB; Apache yok, siteler yalnızca Nginx ile), `web` (+ `.htaccess` için Apache, PowerDNS, Pure-FTPd), `full` (+ Postfix/Dovecot e-posta, Rspamd, Roundcube web posta).

Kurucu ayrıca: PowerDNS için systemd-resolved'ın 127.0.0.53 dinleyicisini kapatır,
firewalld/ufw yerine nftables tablosu kurar, SSH ve panel girişleri için fail2ban
kuralları ekler, AlmaLinux'ta SELinux etiketlerini ve booleanlarını ayarlar, `root`
postasını `--email` adresine yönlendirir ve günlük döndürmeyi (logrotate) yapılandırır.

### Yükseltme

```bash
curl -fsSL https://get.bozkurtpanel.com | sudo bash -s -- upgrade   # ya da sunucuda:
sudo bpanel-installer upgrade
```

Eski bir sürümün kurulu olduğu sunucuda kurucu otomatik olarak yükseltme yapar: yeni
sürümün gerektirdiği paketleri kurar, sıkılaştırmayı ve servis ayarlarını yeniden
uygular, ikili dosyaları ve servis birimlerini değiştirir, veritabanını ve dosyaları
taşır, paneli yeniden başlatır ve kendi kendine testi çalıştırır. Siteler, e-posta ve
veriler çalışmaya devam eder; yarıda kalırsa yeniden çalıştırılabilir. Kurucunun bir
kopyası `/usr/local/lib/bpanel` içinde kalır.

### Kaldırma

```bash
sudo bpanel-installer uninstall          # paneli kaldırır; siteler, e-posta, DNS ve veritabanları çalışmaya devam eder
sudo bpanel-installer uninstall --purge  # panel veritabanını, ayarlarını ve gizli anahtarlarını da siler
```

Kaldırıcı yalnızca paneli (servisler, ikili dosyalar, phpMyAdmin, panelin fail2ban
kuralı) siler ve sunucuyu **çalışır durumda** bırakır: Nginx, Apache, PHP-FPM, PowerDNS
ve posta servisleri panelin verdiği ayarlarla çalışmaya devam eder (özgün dosyalar
`*.bpanel-orig` olarak yanlarında durur). Kurulumdan önce firewalld veya ufw açıksa
site portları açılarak geri getirilir; değilse `bpanel-firewall` panel portları
olmadan çalışmaya devam eder, sunucu hiçbir zaman güvenlik duvarsız kalmaz. PowerDNS
kuruluysa systemd-resolved dinleyicisi kapalı kalır. `--purge`, servislerin hâlâ
kullandığı dosyaları (`/etc/bpanel/ssl`, `/var/lib/bpanel/acme`, web posta) silmez ve
bunları listeler. Dağıtım paketleri hiçbir zaman silinmez.

### Mimari ve güvenlik

`bpanel-api`, yetkisiz `bpanel` kullanıcısıyla çalışır. Root yetkisi gereken her iş
unix soketi üzerinden `bpanel-agent`'a gider. Ajan yalnızca **tanımlı, tipli
eylemleri** çalıştırır: parametreler katı biçimde çözülür ve doğrulanır, programlar argv ile
çağrılır, **hiçbir zaman kabuk (shell) kullanılmaz** ve "komut çalıştır" diye bir eylem yoktur.

### Diller

Varsayılan dil İngilizcedir, Türkçe çevirisi tamdır. Her sayfada dil seçici vardır.
Her kullanıcının seçimi kendi hesabında saklanır. Sunucu varsayılanını yönetici
**Ayarlar** sayfasından belirler.

### Kaynaktan derleme

Go 1.27+, Node 20+ ve pnpm gerekir: `git clone https://github.com/cumabozkurt/bpanel.git`, ardından
`make web embed vet test release`. Derlenmiş web arayüzü `internal/webui/dist` içinde depoya dahildir;
temiz bir klonda `go build ./...` doğrudan çalışır. Sahte ajanla
geliştirme sunucusu için `make dev` kullanın (yönetici `bpadmin` / `Demo-Pass-2026`, kullanıcı
`demo` / `Demo-User-2026`).

### Bilinen sınırlamalar

- **Henüz gerçek sunucuda denenmedi (v1.0.0 için de geçerli).** v0.3, systemd'nin PID 1 olmadığı ve nf_tables
  bulunmayan bir Debian 13 arm64 konteynerinde doğrulandı. Ubuntu 24.04 ve AlmaLinux 9
  sanal makinelerinde tam bir çalıştırma (systemd, SELinux, `ssh.socket`, systemd-resolved,
  nftables, Let's Encrypt staging ile AutoSSL, ajan sandbox'ında `php.install`) hâlâ gerekli.
- **v1.0.0 arşivleri imzasız; sürüm anahtarı üretilene kadar `curl | bash` kurulumu kapalı.** `BPANEL_RELEASE_PUBKEY`
  `UNSET` iken `install.sh` kurulumu reddeder. Bakımcının `make release-keygen` (çevrimdışı)
  çalıştırıp imzalı sürümleri `make release` ile yayınlaması gerekir.
- **Özellik kapsamı (v1.0.0 = v0.4 özellik seti):** cPanel/WHM özellik listesinin yaklaşık %82'si
  uygulanmış, yaklaşık %34'ü bir konteynerde uçtan uca doğrulanmış; çoğu v0.4 aracı
  "gerçek sunucuda doğrulanmamış" durumda (`docs/feature-matrix.md`). "Yakında" olarak işaretli araç kalmadı.
- **`/home` kurulumda `root:root 0711` yapılır**; böylece hesaplar birbirlerinin dizinlerini
  listeleyemez (SFTP chroot `ChrootDirectory /home`). Kaldırma işlemi bunu geri almaz.
- **Ajan sahiplik kaydı sınırı:** root ajan her vhost, DNS bölgesi ve e-posta alan adının hangi
  hesaba ait olduğunu kaydeder ve hesaplar arası işlemleri reddeder; ancak tamamen ele
  geçirilmiş bir API, kurbanın alan adı için doğru sahibi yine de bildirebilir (kimliği API belirler).
- **Ertelenen kod maddeleri:** CODE-21 (sunucu IP'si, ad sunucuları veya varsayılan PHP
  değişince mevcut bölgeler/vhost'lar yeniden üretilmez; yöneticiye uyarı gösterilir), CODE-23
  (kullanıcı tarafı listelerde sayfalama yok), CODE-25 (bant genişliği 0 gösterilir, inode
  sınırı kullanılmıyor, "SSH Erişimi" FTP'ye gidiyor), CODE-26 (`users.owner_id` için
  `ON DELETE` kuralı yok; tek SQLite bağlantısı).
- PHP-FPM havuzları ortak bir `bpanel-php.slice` içinde çalışır; hesap başına gerçek cgroup
  için hesap başına ayrı FPM ana süreci gerekir. Cron işleri `pam_systemd` ile
  `user-<uid>.slice` içine düşer.
- Ana makine sertifikası yenilendiğinde Postfix/Dovecot/Pure-FTPd henüz otomatik yeniden yüklenmiyor.

### Katkı

Hata kayıtları ve çekme istekleri memnuniyetle karşılanır; bkz. [`CONTRIBUTING.md`](CONTRIBUTING.md).
Güvenlik açıklarını herkese açık kayıt yerine [`SECURITY.md`](SECURITY.md) içindeki yolla bildirin.

### Lisans

Apache Lisansı 2.0. Ayrıntılar için [LICENSE](LICENSE) dosyasına bakın.
