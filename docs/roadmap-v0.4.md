# Roadmap: v0.4 and beyond (master spec §26 phases)

Snapshot: 2026-10-10. Effort is given in focused engineer-days (d) and is a rough figure. "Done" means the work has tests and evidence, not just written code. Status per area is in `feature-matrix.md`.

| Phase | Goal | Done / in tree | Remaining items | Effort |
|---|---|---|---|---|
| 0. Repository review | Inventory and risk list | v0.3 audits (`audit/verification-v0.3.md`, round2), `docs/feature-matrix.md` | Keep the matrix current per module report | 0.5 d |
| 1. Security foundation | Authentication, RBAC, audit, agent, secrets, errors | `internal/rbac`, `api/perm.go` permGuard, `internal/events`, `internal/redact`, migration 0005 (secrets, webhooks, jobs, idempotency, events) | `opPerm`/`requirePerm`/`requireRecentAuth` + reauth endpoint; route-table test so no mutating admin route is unguarded; `internal/secrets` (AES-GCM envelope, OpenBao stub) and migrating installer secrets; `internal/jobs`; webhook worker; fix the redact `bpt_` test; staff-role UI EN/TR | 6–8 d |
| 2. User isolation | UID/GID, FPM, cgroups v2, FS limits | per-account UID and FPM pools (v0.3); `internal/isolation` + agent/rpc (in progress) | cgroup slice create/limit/stats via agent; package limits + migration 0006; bwrap cage for cron/SSH/PHP; limit-hit events; UI; real-kernel test on a VM (sandbox: disposable child cgroup only) | 6–9 d |
| 3. BPanel Shield | Scanner providers, watch, upload scan, quarantine, YARA, signatures | `internal/shield` core (types, clamd, yara, heuristic, policy, cache, archive, scanner, tests) | fanotify watcher with inotify fallback; fair queue with dedupe and debounce; AES-GCM quarantine with restore and FP handling; staged upload pipeline in front of `/user/files/upload`; migration 0007; API, UI and events; freshclam/rule updates; ClamAV/YARA/LMD return `not_installed` when absent | 8–12 d |
| 4. Network and web security | WAF, CRS, firewall, bans, SSH, central events | nftables and fail2ban installed by the installer | netsec agent actions (nft sets, allow/deny, rate limits); fail2ban jail management; Coraza or ModSecurity with OWASP CRS per vhost and exclusions; optional CrowdSec with CAPI off by default; migration 0008; UI | 8–10 d |
| 5. Hosting infrastructure | Close gaps in DNS, SSL, PHP, web, DB, mail | v0.3 hosting features verified in the sandbox | DNSSEC, CAA, secondary DNS; outbound mail rate limits, MTA-STS/TLS-RPT; PostgreSQL; app runtimes (Node/Python); fix the axe `/dns` label; real-VM AutoSSL staging | 10–15 d |
| 6. Backup and observability | restic/Borg, restore tests, Prometheus, logs, alerts | restic local backup and restore | remote targets (S3/SFTP) with sealed credentials; schedules and retention; automated restore verification; Borg provider; `/metrics`; log shipping (OTel); alert rules on events | 7–10 d |
| 7. Multi-server | Central management, agents, job queue, health, config push | none | node enrollment and panel CA; agent over mTLS (cert pinning, replay protection); routing jobs per node; health and heartbeat; config distribution; per-node feature capabilities; failover rules | 12–18 d |
| 8. Quality and production readiness | Performance, security tests, install, migration, docs, packaging | V3: race, govulncheck, PoCs, i18n parity, UI tests | release signing key and signed artifacts; real Ubuntu 24.04 / Alma 9 VM runs (systemd as PID 1, SELinux, nft); v0.3→v0.4 upgrade test; load test; fuzzing (agent RPC, validators); EICAR/attack simulation; finish third-party-licenses rows for each module | 6–9 d |

**Total remaining (rough):** about 63–92 engineer-days. Phases 1–3 are the v0.4 scope. Phases 4–8 are v0.5 and later.

## Order and dependencies
1. Phase 1 contracts (perm, jobs, secrets, events) come first. Phases 2–4 build on them.
2. Phases 2 and 3 can run in parallel. Shield's upload pipeline depends on the jobs queue.
3. Phase 7 (mTLS agent) needs the provider and job abstractions to be stable.
4. Phase 8 work on signing and real-VM testing should start early, because it blocks any production release.

## Exit criteria for v0.4
- Every mutating admin route has a permission check, and a test enforces it.
- Isolation and Shield either work on a real kernel or report `unsupported` honestly, with tests passing on fakes.
- EN/TR key parity holds. `go test` passes for every package. The web build passes.
- Each module has a `REPORT.md` with real test counts. `third-party-licenses.md` §6 is updated.
