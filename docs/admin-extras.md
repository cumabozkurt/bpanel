# Admin extras (v0.4 adminx)

Modify Account, Change Contact Email, Edit Reseller, Update Preferences, User Manager. All free; no new dependencies.

## API
| Route | Perm / scope |
|---|---|
| GET/PUT `/admin/accounts/{id}/modify` | accounts.read / accounts.write; admin or owning reseller (visibleAccount/manageableAccount); owner change admin-only |
| GET/PUT `/admin/resellers/{id}/limits` | accounts.read/write + base role admin |
| GET/PUT `/admin/updates/prefs`, GET `/admin/updates/status`, POST `/admin/updates/apply` | server.read/write + base role admin |
| GET/PUT `/user/contact-email`, GET `/user/user-manager` | own hosting account only |

## Design
- **Overrides** (`account_overrides`, migration 0013): shell_access, max addon/sub domains (NULL = package). `packageOf` applies them, so every existing limit check sees them.
- **Shell access**: toggling re-renders the sshd jail via the existing agent action `isolation.ssh.apply` with every hosting account that has no shell access (mode from setting `ssh_jail_mode`, default `sftp`). Failure → warning `ssh_jail_not_applied`, setting stays saved.
- **Change primary domain** (v1.2): pick an addon domain of the account; it becomes the primary domain and the old primary becomes an addon domain (one transaction on `domains.kind` + `users.primary_domain`; vhosts, DNS zones, mail domains, SSL and document roots of both stay untouched). Any other name answers 422 `primary_domain_not_addon` — add it as an addon domain first. Audited as `account.primary_domain`, published as the webhook event `account.primary_domain_changed`.
- **Contact email**: validated (validate.Email, ≤254). BPanel has no outbound mail path, so the old address is **not notified**; the change is audited (old address masked).
- **Edit Reseller** (`reseller_limits`): max accounts + disk pool (existing users columns), bandwidth pool, allowed packages, ACL (subset of the rbac `reseller` role). Enforced in CreateAccount and package changes (`checkResellerLimits`: 403 package_not_allowed, 409 limit_reached/reseller_bandwidth) and on every admin-realm request (`resellerACL` middleware after permGuard; admin.read always kept).
- **Update Preferences**: settings `update_policy` (security|all|manual), `update_auto_reboot` (never|when_required). Agent `system.updates.status` runs `apt list --upgradable` or `dnf check-update [--security]` (90 s timeout), reboot from `/var/run/reboot-required` or `needs-restarting -r`. `system.updates.apply` runs only on POST, as job `system.updates.apply` (apt-get upgrade / unattended-upgrade for security-only / dnf upgrade [--security]; reboot via `shutdown -r +2` only when required and policy allows). No package manager → `not_installed`; apt security-only without unattended-upgrades → `unsupported`. The policy is NOT applied on a timer: "security/all" choose what the button installs.
- **User Manager**: read-only unified list of the account's mailboxes + FTP accounts with links to their pages; Web Disk reported `not_installed`. No new auth system.

## Verified / not verified
- Verified (unit/integration with fake agent): ownership (foreign 404, reseller owner change 403), rename 422, overrides in packageOf, ssh jail list excludes shell accounts, reseller limits on create (403/409), ACL denial, reseller blocked from edit-reseller and update endpoints, update job passes stored policy to agent, apt output parsing, not_installed path, fake-apt status + reboot flag.
- Not verified: real apt/dnf upgrade and reboot (never run in this sandbox), real sshd reload.
