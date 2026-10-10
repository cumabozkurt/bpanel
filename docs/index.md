# BPANEL documentation (v1.1.0)

Project website: <https://cumabozkurt.github.io/bpanel/> · Release notes: [v1.1.0](release-notes/v1.1.0.md) · [v1.0.0](release-notes/v1.0.0.md)

Start with the repository [README](../README.md) and the [CHANGELOG](../CHANGELOG.md).

## Overview
- [Architecture](architecture.md): API, root agent, trust boundaries, v0.4 components, **free software only** (§3)
- [Feature matrix](feature-matrix.md): every cPanel/WHM feature vs. BPANEL, status and parity %
- [Capabilities](capabilities.md): install profiles and feature flags (`capabilities.json`, `/auth/me`)
- [Security model](security.md)
- [Third-party licenses](third-party-licenses.md): every bundled, installed or optional component and its free licence
- [Roadmap v0.4](roadmap-v0.4.md) (planning document, kept for history)

## Install and operate
- [Installation](installation.md)
- [Upgrade v0.4 → v1.0.0 (and v0.3 → v0.4)](upgrade.md)
- [Operations runbook](operations-runbook.md)
- [Backup and restore](backup-and-restore.md)
- [Migration / Transfer Tool](migration.md): cPanel `cpmove`, BPANEL and remote transfers
- [Multi-server](multi-server.md): mTLS remote agents, `bpanel-agent join`
- [Monitoring and alerts](monitoring.md): health, `/metrics`, alerts, FIM

## Security modules
- [Isolation](isolation.md): cgroup v2 limits, bwrap cage, hardened PHP-FPM units
- [Malware protection (BPanel Shield)](malware-protection.md): ClamAV, YARA, heuristics, quarantine
- Firewall, brute force and WAF: see [security.md](security.md) and [usage-extras.md](usage-extras.md)

## Hosting features
- [Mail tools](mail-tools.md): autoresponders, filters, spam, delivery tracking
- [DNS](dns.md): DNSSEC, zone import/export, history, mailing lists
- [Databases](databases.md): MariaDB, remote MySQL, PostgreSQL, process list
- [Web extras](web-extras.md): directory privacy, hotlink, error pages, MIME types, IP blocker
- [Usage extras](usage-extras.md): bandwidth, PHP INI, API tokens, ModSecurity, brute force
- [Applications](applications.md): App Installer, WordPress Toolkit, Node.js/Python apps
- [Developer tools](dev-tools.md): Git, Terminal, Track DNS, Dynamic DNS
- [Admin extras](admin-extras.md): modify account, reseller privileges, update preferences, user manager
- [Plugins](plugins.md): signed plugins and the DNS cluster

## API
- [OpenAPI 3.1 specification](openapi.json) (also served at `/openapi.json`)

## Screenshots
- [screenshots/](screenshots/): UI captures (`v11/*.jpg` from the v1.1.0 E2E server in EN and TR, `v1-*.png` from the v1.0.0 build in dev mode; numbered files are the v0.3 set)

## Project
- [Release notes v1.1.0](release-notes/v1.1.0.md) · [v1.0.0](release-notes/v1.0.0.md)
- [Feature matrix](feature-matrix.md) · [E2E evidence](evidence/e2e-v1/SUMMARY.md) · [E2E suites](../test/e2e/)
- [Contributing](../CONTRIBUTING.md) · [Security policy](../SECURITY.md)
- The project website is the static `index.html` in this directory (GitHub Pages, `/docs` on `main`); it is bilingual (EN/TR), follows the browser language and remembers the choice made with the EN | TR switch (`localStorage` key `bpanel-lang`, or `?lang=tr` / `?lang=en`).
