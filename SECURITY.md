# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | yes |
| < 1.0 (previews) | no — upgrade to 1.0.x |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's private vulnerability reporting:
<https://github.com/cumabozkurt/bpanel/security/advisories/new>
(repository → *Security* → *Report a vulnerability*).

Include the affected version/commit, the component (`bpanel-api`, `bpanel-agent`, installer, web UI),
the impact, and the steps to reproduce on a test system. You will get an acknowledgement as soon as
possible; fixes are released as patch versions with a CHANGELOG entry and a GitHub security advisory.
Please give us a reasonable time to fix the issue before public disclosure.

## Scope and design notes

The security model (privilege split between the unprivileged API and the root agent, typed agent
actions without a shell, tenant ownership checks, RBAC, encrypted secrets, firewall, isolation) is
described in [`docs/security.md`](docs/security.md), [`docs/isolation.md`](docs/isolation.md) and
[`docs/architecture.md`](docs/architecture.md). Known limitations are listed in the README.

Release archives are designed to be minisign-signed and `install.sh` refuses unsigned network
installs. **v1.0.0 archives are not signed yet**; verify their SHA-256 against the release page.
