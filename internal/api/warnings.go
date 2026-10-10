package api

// Warning is a non-blocking notice returned next to a successful result
// (handoff-ui H-6). Code is a stable, translatable identifier; Area names
// the subsystem; Detail carries the agent error code or the affected name
// and is shown as technical detail only.
type Warning struct {
	Code   string `json:"code"`
	Area   string `json:"area"`
	Detail string `json:"detail,omitempty"`
}

// Warning codes (every one has an EN+TR translation under warnings.<code>).
const (
	WarnMailSetupFailed       = "mail_setup_failed"
	WarnDNSSetupFailed        = "dns_setup_failed"
	WarnCleanupFailed         = "cleanup_failed"
	WarnQuotaUpdateFailed     = "quota_update_failed"
	WarnExistingNotUpdated    = "existing_accounts_not_updated"
	WarnRootAliasUpdateFailed = "root_alias_update_failed"
)

// WarningCodes lists every warning code (i18n check, OpenAPI).
var WarningCodes = []string{WarnMailSetupFailed, WarnDNSSetupFailed, WarnCleanupFailed, WarnQuotaUpdateFailed,
	WarnExistingNotUpdated, WarnRootAliasUpdateFailed, WarnSSHJailNotApplied /* adminx.go */}

func warn(code, area, detail string) Warning { return Warning{Code: code, Area: area, Detail: detail} }

// AuditRealms is the set of values written to audit_log.realm: the panel
// realms, the webmail login realm and "system" for housekeeping jobs.
var AuditRealms = []string{RealmUser, RealmAdmin, "webmail", "system"}
