// Package rbac is BPANEL's role and permission catalogue (v0.4 security
// foundation, master spec §9).
//
// The database keeps the legacy base role in users.role (admin | reseller |
// user; a CHECK constraint and much existing code rely on it). Staff roles
// live in users.sec_role and only apply to base role "admin":
//
//	role=admin  sec_role=""               -> super_admin (every v0.3 admin)
//	role=admin  sec_role=server_admin     -> server_admin
//	role=admin  sec_role=security_admin   -> security_admin
//	role=admin  sec_role=auditor          -> auditor (read-only)
//	role=admin  sec_role=technical        -> technical (scoped to granted accounts)
//	role=reseller                         -> reseller
//	role=user                             -> user (hosting customer)
package rbac

import (
	"sort"
	"strings"
)

// Roles.
const (
	SuperAdmin    = "super_admin"
	ServerAdmin   = "server_admin"
	SecurityAdmin = "security_admin"
	Reseller      = "reseller"
	User          = "user"
	Technical     = "technical"
	Auditor       = "auditor"
)

// Roles lists every role in display order.
var Roles = []string{SuperAdmin, ServerAdmin, SecurityAdmin, Reseller, User, Technical, Auditor}

// StaffRoles are the roles stored in users.sec_role (base role admin).
var StaffRoles = []string{SuperAdmin, ServerAdmin, SecurityAdmin, Technical, Auditor}

// Permissions. A ".read" permission only ever guards GET/HEAD routes.
const (
	AdminRead         = "admin.read" // dashboards / summary of the admin realm
	AccountsRead      = "accounts.read"
	AccountsCreate    = "accounts.create"
	AccountsWrite     = "accounts.write" // suspend, unsuspend, change package
	AccountsPassword  = "accounts.password"
	AccountsLoginAs   = "accounts.login_as"
	AccountsTerminate = "accounts.terminate"
	PackagesRead      = "packages.read"
	PackagesWrite     = "packages.write"
	ServerRead        = "server.read"
	ServerWrite       = "server.write" // services, PHP versions, settings
	AuditRead         = "audit.read"
	RolesRead         = "roles.read"
	RolesWrite        = "roles.write" // staff users, role assignment, technical grants
	SecurityRead      = "security.read"
	SecurityWrite     = "security.write" // access policy, MFA/password/re-auth policy
	SessionsRevoke    = "sessions.revoke"
	WebhooksRead      = "webhooks.read"
	WebhooksWrite     = "webhooks.write"
	JobsRead          = "jobs.read"
	EventsRead        = "events.read"
	SecretsRead       = "secrets.read" // status only, never values
	SecretsWrite      = "secrets.write"
	FirewallRead      = "firewall.read"
	FirewallWrite     = "firewall.write"
	WAFRead           = "waf.read"
	WAFWrite          = "waf.write"
	ShieldRead        = "shield.read"
	ShieldWrite       = "shield.write"
	IsolationRead     = "isolation.read"
	IsolationWrite    = "isolation.write"
	HostingRead       = "hosting.read"   // user realm: own hosting account
	HostingWrite      = "hosting.write"  // user realm: own hosting account
	TokensSelf        = "tokens.self"    // manage own API tokens
	BackupsRead       = "backups.read"   // v0.4 backup: verification results
	BackupsVerify     = "backups.verify" // run a restore verification now
	BackupsDelete     = "backups.delete" // forget/prune a snapshot (admin only)
	XferRead          = "xfer.read"      // v0.4 xfer: Transfer Tool archives, analysis, history
	XferWrite         = "xfer.write"     // v0.4 xfer: remote pull, import, export
	SecretsRotate     = "secrets.rotate" // v0.4: rotate the secret-store master key (super_admin only: in no role set)
)

// Catalogue is every permission with a short English description.
var Catalogue = map[string]string{
	AdminRead:         "View the admin dashboard",
	AccountsRead:      "View hosting accounts",
	AccountsCreate:    "Create hosting accounts",
	AccountsWrite:     "Suspend, unsuspend and change packages of accounts",
	AccountsPassword:  "Set account passwords",
	AccountsLoginAs:   "Log in as an account",
	AccountsTerminate: "Terminate accounts",
	PackagesRead:      "View packages",
	PackagesWrite:     "Create, edit and delete packages",
	ServerRead:        "View server status, services, PHP and settings",
	ServerWrite:       "Manage services, PHP versions and server settings",
	AuditRead:         "Read the audit log",
	RolesRead:         "View staff users and roles",
	RolesWrite:        "Create staff users and assign roles",
	SecurityRead:      "View security policies",
	SecurityWrite:     "Change security policies (admin IP access, MFA, passwords)",
	SessionsRevoke:    "End other users' sessions",
	WebhooksRead:      "View webhooks and deliveries",
	WebhooksWrite:     "Manage webhooks",
	JobsRead:          "View background jobs",
	EventsRead:        "View security events",
	SecretsRead:       "View secret store status",
	SecretsWrite:      "Rotate the secret store key",
	FirewallRead:      "View firewall",
	FirewallWrite:     "Change firewall rules",
	WAFRead:           "View WAF",
	WAFWrite:          "Change WAF rules",
	ShieldRead:        "View malware protection",
	ShieldWrite:       "Manage malware protection",
	IsolationRead:     "View account isolation and limits",
	IsolationWrite:    "Change account isolation and limits",
	HostingRead:       "Read own hosting account",
	HostingWrite:      "Change own hosting account",
	TokensSelf:        "Manage own API tokens",
	BackupsRead:       "View backup verification results",
	BackupsVerify:     "Run a backup restore verification",
	BackupsDelete:     "Delete backup snapshots",
	XferRead:          "View Transfer Tool archives and reports",
	XferWrite:         "Import, export and pull accounts (Transfer Tool)",
	SecretsRotate:     "Rotate the secret store master key",
}

// AccountScoped are permissions that can be granted to a technical user per
// account (technical_grants.perms).
var AccountScoped = []string{AccountsRead, AccountsWrite, AccountsPassword, AccountsLoginAs, IsolationRead, IsolationWrite, ShieldRead, ShieldWrite}

func set(ps ...string) map[string]bool {
	m := map[string]bool{}
	for _, p := range ps {
		m[p] = true
	}
	return m
}

func reads() []string {
	var out []string
	for p := range Catalogue {
		if strings.HasSuffix(p, ".read") {
			out = append(out, p)
		}
	}
	return out
}

var rolePerms = map[string]map[string]bool{
	ServerAdmin: set(AdminRead, AccountsRead, AccountsCreate, AccountsWrite, AccountsPassword, AccountsLoginAs, AccountsTerminate,
		PackagesRead, PackagesWrite, ServerRead, ServerWrite, AuditRead, RolesRead, SecurityRead, SessionsRevoke, WebhooksRead,
		JobsRead, EventsRead, SecretsRead, FirewallRead, WAFRead, ShieldRead, IsolationRead, IsolationWrite, TokensSelf,
		BackupsRead, BackupsVerify, BackupsDelete, XferRead, XferWrite),
	SecurityAdmin: set(AdminRead, AccountsRead, PackagesRead, ServerRead, AuditRead, RolesRead, SecurityRead, SecurityWrite,
		SessionsRevoke, WebhooksRead, WebhooksWrite, JobsRead, EventsRead, SecretsRead, SecretsWrite, FirewallRead, FirewallWrite,
		WAFRead, WAFWrite, ShieldRead, ShieldWrite, IsolationRead, TokensSelf, BackupsRead, BackupsVerify),
	Auditor: set(append(reads(), TokensSelf)...),
	Reseller: set(AdminRead, AccountsRead, AccountsCreate, AccountsWrite, AccountsPassword, AccountsLoginAs, AccountsTerminate,
		PackagesRead, PackagesWrite, SessionsRevoke, JobsRead, EventsRead, HostingRead, HostingWrite, IsolationRead, IsolationWrite, TokensSelf,
		ShieldRead, ShieldWrite), // v0.4 shield: own accounts only (owner_id scope in api/shield.go)
	Technical: set(AdminRead, AccountsRead, AccountsWrite, AccountsPassword, AccountsLoginAs, JobsRead, IsolationRead, IsolationWrite,
		ShieldRead, ShieldWrite, TokensSelf),
	User: set(HostingRead, HostingWrite, TokensSelf),
}

// Effective maps the stored (role, sec_role) pair to an RBAC role.
func Effective(baseRole, secRole string) string {
	switch baseRole {
	case "admin":
		switch secRole {
		case "", SuperAdmin:
			return SuperAdmin
		case ServerAdmin, SecurityAdmin, Technical, Auditor:
			return secRole
		}
		return Auditor // unknown value: fail to the least privileged staff role
	case "reseller":
		return Reseller
	case "user":
		return User
	}
	return ""
}

// Has reports whether role holds perm.
func Has(role, perm string) bool {
	if role == SuperAdmin {
		_, known := Catalogue[perm]
		return known
	}
	return rolePerms[role][perm]
}

// Perms returns the sorted permissions of role.
func Perms(role string) []string {
	var out []string
	for p := range Catalogue {
		if Has(role, p) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// Known reports whether p is a catalogued permission.
func Known(p string) bool { _, ok := Catalogue[p]; return ok }

// ValidRole reports whether r is a role name.
func ValidRole(r string) bool {
	for _, x := range Roles {
		if x == r {
			return true
		}
	}
	return false
}

// IsStaff reports whether r is stored as sec_role on a base admin.
func IsStaff(r string) bool {
	for _, x := range StaffRoles {
		if x == r {
			return true
		}
	}
	return false
}

// AdminRealm reports whether role may log in to the admin realm.
func AdminRealm(role string) bool { return role != User && role != "" }

// IsReadOnly reports whether a role can never change anything.
func IsReadOnly(role string) bool { return role == Auditor }
