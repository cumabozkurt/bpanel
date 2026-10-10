# BPANEL architecture

Snapshot: 2026-10-10. The current state is v1.0.0 (the v0.4.0 feature set — v0.3.0 base plus the v0.4 modules — after the v1.0.0 release audit; no architectural change). The target is the master spec §16–§19 design.

## 1. Current (v0.3 base)

```
 Browser (SvelteKit SPA, EN/TR)
   │ HTTPS  :2083 user realm   :2087 admin realm   :2096 webmail
   ▼
┌──────────────────────────── bpanel-api (user "bpanel", unprivileged) ─────────────────────────┐
│ chi router per realm: requestIDs → compress → realm → securityHeaders → loadSession → csrf    │
│   /api/v1/auth/*, /account/*         requireAuth                                              │
│   /api/v1/user/*   (user realm)      ownership checks in handlers                             │
│   /api/v1/admin/*  (admin realm)     requireRole(admin,reseller) + permGuard (v0.4 RBAC)      │
│   /3rdparty/phpMyAdmin/* → reverse proxy 127.0.0.1:2090 (one-time pma tokens)                 │
│ store: SQLite (modernc, pure Go) /var/lib/bpanel/db/bpanel.db, migrations 0001–0005           │
│ loops: housekeeping (10 min: provisioning rollback, PMA user prune, AutoSSL, hostname cert)   │
│        probeAgent (5 s: circuit breaker → 503 agent_unreachable)                              │
└───────────────┬──────────────────────────────────────────────────────────────────────────────┘
                │ unix socket /run/bpanel/agent.sock  (typed JSON RPC, internal/agentrpc)
                ▼
┌──────────────────────────── bpanel-agent (root) ─────────────────────────────────────────────┐
│ allowlisted typed methods only (server.go dispatch)                                            │
│ gate.go / owners.go: every tenant method requires a panel-managed account (R2-WB-1)            │
│ safefs.go: canonical paths under allowed roots, no symlink following                           │
│ exec.CommandContext(argv), timeouts, audit                                                     │
└──────┬────────┬────────┬────────┬────────┬────────┬────────┬─────────┬─────────────────────────┘
       ▼        ▼        ▼        ▼        ▼        ▼        ▼         ▼
     nginx   Apache   PHP-FPM  MariaDB  PowerDNS Postfix/  Pure-FTPd  restic, nftables,
             (opt.)   pools             (HTTP    Dovecot/            fail2ban, cron,
                      per acct          API)     Rspamd              quota/acl
```

### Binaries (`cmd/`)

| Binary | Runs as | Role |
|---|---|---|
| `bpanel-api` | `bpanel` | HTTP API and embedded UI (`internal/webui/dist`), both realms, background loops. `--dev` is only available in dev builds |
| `bpanel-agent` | root | Privileged executor on a unix socket; the only component that changes the system |
| `bpanel` | root | Admin CLI on the server |
| `bpanel-installer` | root | Installs and upgrades profiles (minimal/web/full); writes `capabilities.json` and `feature_*` settings |

### Packages (`internal/`)

| Package | Purpose |
|---|---|
| api | handlers, middleware, realms, errcodes (EN/TR), features gate, maintenance loops, openapi |
| agent / agentrpc | root agent methods, tenant gate, safe FS / typed RPC client and circuit breaker |
| auth | password hashing, TOTP, sessions |
| store (+migrations) | SQLite schema: users, packages, domains, DBs, mail, FTP, cron, sessions, audit_log, api_tokens, tech_grants, recovery_codes; 0005 adds secrets, webhooks, jobs, idempotency_keys, events |
| installer, distro | OS detection (Debian/Ubuntu, EL9), packages, configs, units, upgrade/uninstall |
| fileops, validate, sysinfo, openapi, version, webui, mockagent | helpers, input validation, server info, spec, embedded UI, test agent |
| events, rbac, redact (v0.4 wave 1) | event bus `events.Publish`; role/permission catalogue; secret redaction for logs |
| providers, shield, isolation (v0.4) | provider registry; malware scanning; per-account cgroups/sandbox |

### Realms and trust boundaries
- **User realm** (:2083) and **admin realm** (:2087) are separate listeners on the same router code. Admin routes are mounted only on the admin realm.
- API ↔ agent: local unix socket, owned by the `bpanel` group. The agent re-validates every argument and checks account ownership itself, so it does not trust the API.
- Settings and feature flags come from SQLite `settings`. Missing features return `409 feature_not_installed`.

## 2. Target (v0.4 → v1.0)

```
                         ┌───────────────── Control plane (bpanel-api) ─────────────────┐
 UI / API clients ──────▶│ RBAC (perm per route + object-level canManageAccount)        │
 (tokens, webhooks)      │ step-up reauth · idempotency keys · OpenAPI                  │
                         │                                                              │
                         │  ┌──────────┐   ┌────────────┐   ┌───────────────────────┐   │
                         │  │ Providers│   │ Jobs queue │   │ Events bus            │   │
                         │  │ registry │   │ (SQLite,   │──▶│ events table, webhooks│   │
                         │  │ detect → │   │ retries,   │   │ alerts, SIEM export   │   │
                         │  │ status   │   │ fair RR)   │   └───────────────────────┘   │
                         │  └──────────┘   └─────┬──────┘                               │
                         │  Secrets: AES-256-GCM envelope (local KEK) | OpenBao provider │
                         └────────────────────────┼───────────────────────────────────────┘
                                 local unix socket │  mTLS (per-node cert, pinned CA)
                       ┌───────────────────────────┴───────────────┬────────────────────┐
                       ▼                                           ▼                    ▼
               ┌──────────────── node agent (root) ────────────┐  node 2 agent ...  node N
               │ typed allowlisted actions + tenant gate       │
               │ Isolation: cgroup v2 slice per account,       │
               │   bwrap/namespace cage, FPM per UID           │
               │ Shield: fanotify/inotify watcher → scan queue │
               │   → native/ClamAV/YARA/LMD providers →        │
               │   quarantine (AES-GCM) → events               │
               │ Netsec: nftables sets, fail2ban/CrowdSec,     │
               │   WAF (Coraza/ModSecurity + OWASP CRS)        │
               │ Backups: restic/Borg, restore tests           │
               │ Metrics: /metrics (Prometheus), health        │
               └───────────────────────────────────────────────┘
```

| Target component | Design | Status |
|---|---|---|
| Providers | Each external engine (scanner, WAF, DNS, backup, secrets) implements one interface and reports `installed / not_installed / unsupported` with a reason. It never returns a fake success | implemented v0.4 (`internal/providers`), tests pass |
| Events | `events.Publish` never blocks. Events are persisted to `events` and fanned out to admin webhooks with delivery records | available |
| Jobs | `jobs` table, `Register(kind)` / `Enqueue(spec)`, retries, per-account fairness, idempotency keys | schema in 0005; package pending |
| Isolation | cgroup v2 per-account slice (cpu/io/memory/pids), bwrap cage for shell/cron/PHP, limits from packages (0006) | implemented v0.4; kernel-tested in a child cgroup, not under systemd PID 1 |
| Shield | Watcher → debounce → queue → providers → policy → quarantine/restore, plus a staged upload scan (0007) | implemented v0.4; engines not installed in sandbox |
| Netsec | Firewall rules, IP bans and allowlists, SSH protection, WAF with CRS, central security events (0008) | implemented v0.4 (nftables, fail2ban, ModSecurity+CRS); real nf_tables untested |
| Multi-server | Every node runs the same agent. The remote transport is mTLS with per-node certs issued by the panel CA, plus enrollment tokens, health checks and config push through jobs. Local nodes keep the unix socket | implemented v0.4 (`internal/msrv`), loopback mTLS tests |
| Secrets | `secrets.Provider` with Seal/Open: a local AES-256-GCM envelope and an OpenBao backend. Only sealed strings are stored in SQLite | in progress (secfound) |

Rules that stay fixed: the API never runs privileged commands. Every agent action is typed, allowlisted, ownership-checked, audited and bounded by a timeout. No GPL/AGPL code is linked into these binaries (see `third-party-licenses.md`).

## 3. Free software only

BPANEL is completely free: no paid component, licence, API, tier or "pro" feature (user rule,
2026-10-10). Every feature is built on free/open-source software or free public services that need no
payment. Commercial hosting add-ons are replaced as follows:

| Commercial product (cPanel ecosystem) | BPANEL free alternative | Where |
|---|---|---|
| cPanel/WHM licence | BPANEL itself (Apache-2.0) | whole repo |
| CloudLinux LVE / CageFS | cgroup v2 slice per account + bubblewrap cage + hardened systemd FPM units | `internal/isolation`, `/limits`, `/usage` |
| Imunify360 / Monarx / ImunifyAV+ | BPanel Shield: ClamAV, YARA, native heuristics, fanotify/inotify watcher, quarantine | `internal/shield`, `/shield`, `/malware-scans` |
| Imunify WAF / commercial ModSecurity vendors | ModSecurity (v2 / libmodsecurity v3) + OWASP CRS | `internal/netsec`, `/modsecurity`, `/firewall` |
| CSF/LFD (free but unmaintained) / cPHulk | nftables `table inet bpanel` + fail2ban, optional CrowdSec (community, CAPI off by default) | `/firewall`, `/brute-force` |
| LiteSpeed Enterprise | nginx front + Apache httpd backend, PHP-FPM | installer |
| Softaculous | checksum-pinned App Installer (WordPress, Joomla, Drupal, Nextcloud) + WP-CLI toolkit | `internal/appx` |
| JetBackup / Acronis | restic (local, SFTP, S3-compatible) with restore verification | `internal/backup` |
| KernelCare (live patching) | none bundled: distro security updates via Update Preferences (`/update-prefs`); Ubuntu Livepatch / kpatch are optional OS features outside BPANEL | adminx |
| Paid DNS / registrar APIs | PowerDNS authoritative + DNS cluster (AXFR/NOTIFY), Dynamic DNS | `internal/dnsx`, `internal/clusterx` |
| Paid GeoIP / threat feeds | DB-IP Lite (CC BY 4.0) when GeoIP is needed; no paid feed | third-party-licenses §5 |
| Paid monitoring (e.g. hosted APM) | built-in health + `/metrics` (Prometheus format), optional self-hosted Prometheus/Grafana OSS | `internal/obsx` |

Rules: an integration that needs payment to function is never added. Commercial agents may at most be
*detected* (Integrations page) when an admin already runs them; nothing depends on them. All bundled or
installed components and their licences are listed in `third-party-licenses.md`.
