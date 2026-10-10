# Installation (v1.1.0)

> v1.1.0 archives on GitHub Releases are **not signed yet** (no release key). The one-command
> install below fails closed until signed releases exist; install from the unpacked archive with
> `BPANEL_ALLOW_UNSIGNED=1` after checking the published SHA-256, or build and sign your own
> release. Both paths are described in the [README](../README.md#install).

BOZKURT PANEL is free software end to end: every package the installer adds comes from the distribution repositories
(Ubuntu 24.04 main/universe, AlmaLinux 9 BaseOS/AppStream/EPEL) or from free official upstream repositories
(PowerDNS, rspamd). No licence key, paid repository or paid API is used or required.

## Requirements

| | |
|---|---|
| OS | Ubuntu 24.04 LTS or AlmaLinux 9 / Rocky 9 (x86_64 or aarch64), fresh server |
| CPU / RAM | 1 vCPU / 2 GB (minimal, web); 2 vCPU / 4 GB recommended for `full` (mail + rspamd) |
| Disk | 20 GB+ (more for mail and backups) |
| Network | public IPv4 (IPv6 optional), FQDN hostname resolving to the server, outbound 80/443 for packages and Let's Encrypt |
| Access | root (or sudo) shell |

## One-command install

```sh
curl -fsSL https://get.bozkurtpanel.com | sudo bash -s -- \
  --hostname panel.example.com --email admin@example.com --profile full --lang en --yes
```

`install.sh` only downloads and verifies the static `bpanel-installer` and execs it with the same arguments. The
installer is staged and resumable: re-running it after an interruption continues where it stopped (state in
`/var/lib/bpanel/install-state.json`, log in `/var/log/bpanel/install.log`).

## Profiles and flags

| Profile | Installs |
|---|---|
| `minimal` | nginx, PHP-FPM, MariaDB, nftables firewall, fail2ban, SFTP, restic, chrony, git, traceroute |
| `web` | minimal + Apache, PowerDNS (SQLite backend), Pure-FTPd |
| `full` (default) | web + Postfix, Dovecot (IMAP/POP3/LMTP, Sieve + ManageSieve = Pigeonhole), rspamd + Redis, Roundcube, mlmmj mailing lists |

| Flag | Effect |
|---|---|
| `--with-postgresql` | also install PostgreSQL as a second database engine |
| `--with-crowdsec` | CrowdSec engine + nftables bouncer (MIT; free community blocklists only). Ubuntu: `crowdsec`, `crowdsec-firewall-bouncer` from universe. AlmaLinux 9: not in base/EPEL – the installer warns and you add the free official CrowdSec repository yourself |
| `--with-smart` | smartmontools (disk health in Monitoring) |
| `--node` | multi-server **node**: the agent only, with an mTLS remote listener (`--remote-listen`, default `:8445`); the panel API is disabled and join instructions are printed |
| `--php 8.2,8.4` | extra PHP versions (ondrej/php on Ubuntu, Remi on AlmaLinux) |
| `--skip-repos`, `--no-systemd`, `--stages` | development / test helpers |

Distribution package names used for v0.4 features:

| Feature | Ubuntu 24.04 | AlmaLinux 9 |
|---|---|---|
| Sieve / ManageSieve | `dovecot-sieve`, `dovecot-managesieved` | `dovecot-pigeonhole` |
| rspamd | `rspamd` (official free rspamd.com apt repo when repos are enabled) | `rspamd` (official free rspamd.com rpm repo) |
| Mailing lists | `mlmmj` (universe) | `mlmmj` (EPEL, optional – lists report `not_installed` if absent) |
| Brute force | `fail2ban`, `python3-systemd` | `fail2ban-server`, `fail2ban-systemd` |
| Time | `chrony` (unit `chrony`) | `chrony` (unit `chronyd`) |
| Tools | `traceroute`, `git`, optional `smartmontools` | same |
| Backups | restic (pinned upstream binary, SHA-256 verified) | same |

Optional packages (mlmmj, smartmontools, CrowdSec) are installed one by one; a failure is a warning, never an abort,
and the feature that needs the package reports `not_installed` in the API and UI.

## What the installer configures for the v0.4 modules

- Directories (root-owned, only the root agent writes them): `/var/lib/bpanel/{xfer,webx,fim}` 0700,
  `/var/lib/bpanel/{appx,plugins}` 0750, `/usr/local/bpanel/plugins` 0755.
- `/etc/systemd/system/bpanel-app@.service`: the hardened appx template unit (same content the agent writes).
- Postfix (full): master.cf `mlmmj unix - n n - - pipe flags=ORhu user=mlmmj argv=/usr/bin/mlmmj-receive -F -L /var/spool/mlmmj/$nexthop`,
  `transport_maps = hash:/etc/postfix/bpanel_mlmmj_transport` (`lmdb:` on AlmaLinux), `recipient_delimiter = +`,
  `mlmmj_destination_recipient_limit = 1`; the `mlmmj` system user and `/var/spool/mlmmj` (0700). An existing
  transport map written by the agent is never overwritten.
- fail2ban jails (nftables actions): `sshd`, `bpanel` (panel login, journal filter), and on `full` `dovecot`,
  `postfix-sasl`, `roundcube-auth`.
- chrony enabled; CrowdSec + bouncer enabled when `--with-crowdsec`.

## Ports

| Port | Service | Profile |
|---|---|---|
| 22 (your SSH ports) | SSH/SFTP | all |
| 80, 443 | websites, ACME | all |
| 2082/2083 | user panel (HTTP→HTTPS / HTTPS) | all |
| 2086/2087 | admin panel (HTTP→HTTPS / HTTPS) | all |
| 21 + passive range, 53 tcp/udp | FTP, DNS | web, full |
| 25, 465, 587, 110, 995, 143, 993, 4190 | SMTP, submission, POP3, IMAP, ManageSieve | full |
| 2095/2096 | webmail | full |
| 8445 | agent mTLS listener | `--node` only, open it to the main panel's IP only |

3306 and the PostgreSQL port listen on localhost only.

## Post-install

1. Open the admin panel URL printed in the summary and sign in with the generated admin password (shown once; also in
   `/root/bpanel-credentials` if the summary says so). Change it and enable 2FA.
2. Set DNS: A/AAAA for the hostname, MX/SPF/DKIM/DMARC for mail domains (the panel shows the records).
3. Run `bpanel selftest` (agent, DB, listeners + v0.4 services) and `bpanel doctor` (v0.4 services only).
4. Node servers: on the main panel open Servers → Add server, copy the token, then on the node
   `bpanel-agent join --panel https://<main-panel>:2083 --token bpj_...` (the join endpoint `/msrv/join` is served on the user-panel port 2083) and `systemctl restart bpanel-agent`.

## `bpanel doctor`

Prints `ok`, `missing` or `inactive` for fail2ban, chrony, PowerDNS, rspamd, mlmmj, restic, Sieve (Pigeonhole) and the
`bpanel-app@` template. A component the installed profile needs (e.g. rspamd on `full`) counts as a failure (exit 1);
optional ones are shown with `·` and do not fail.

## Troubleshooting

| Symptom | Fix |
|---|---|
| install stopped half-way | re-run the same command; finished stages are skipped. See `/var/log/bpanel/install.log` |
| apt lock held | the installer waits up to 15 min for unattended-upgrades; otherwise stop it and re-run |
| "optional package mlmmj could not be installed" (AlmaLinux) | `dnf install epel-release && dnf install mlmmj`, then `bpanel-installer upgrade --force` |
| port 53 busy | systemd-resolved's stub listener is turned off automatically; another DNS server must be removed |
| `bpanel doctor` says rspamd missing | check repo access to rspamd.com, `apt install rspamd` / `dnf install rspamd`, re-run upgrade |
| node not reachable | the managed nftables table does not open 8445; add a rule for the main panel IP (re-applied rules are rewritten on upgrade – re-add it, see multi-server.md) |
| SELinux denials (AlmaLinux) | `ausearch -m avc -ts recent`; the installer sets the booleans it needs |
