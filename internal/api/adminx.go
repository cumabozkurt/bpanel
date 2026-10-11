// SPDX-License-Identifier: Apache-2.0

package api

// v0.4 adminx: Modify Account, Change Contact Email, Edit Reseller,
// Update Preferences and the user-realm User Manager.
//
//   - Modify Account (admin / owning reseller): package, owner reseller (admin
//     only), shell access (re-renders the sshd jail via isolation.ssh.apply),
//     max addon/sub domain overrides (applied in packageOf), contact email.
//     Change primary domain (v1.2): an addon domain of the account becomes the
//     primary domain and the old primary domain becomes an addon domain. Both
//     already have their vhost, DNS zone, mail domain, SSL certificate and
//     document root, which stay as they are: the swap is one transaction on
//     domains.kind + users.primary_domain, nothing is moved on disk and the
//     agent keeps no main/addon distinction. A name that is not an addon
//     domain of the account answers 422 primary_domain_not_addon (add it as
//     an addon domain first).
//   - Change Contact Email (user realm): own address, validated, audited. The
//     panel has no outbound mail path, so the old address is NOT notified; the
//     change is recorded in the audit log only.
//   - Edit Reseller (admin): max accounts, disk/bandwidth pools, allowed
//     packages, ACL = subset of the reseller RBAC role. Enforced on account
//     create (CreateAccount → checkResellerLimits), package changes and on
//     every admin-realm request of the reseller (resellerACL middleware).
//   - Update Preferences (admin): policy security|all|manual + auto-reboot in
//     settings; status from the agent (system.updates.status); apply only on
//     an explicit POST, as a job (system.updates.apply).
//   - User Manager (user realm): read-only unified list of the account's
//     mailboxes and FTP accounts with links to their pages. No new auth system.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/jobs"
	"github.com/cumabozkurt/bpanel/internal/rbac"
	"github.com/cumabozkurt/bpanel/internal/store"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// WarnSSHJailNotApplied: shell access was saved but the sshd jail could not be re-rendered.
const WarnSSHJailNotApplied = "ssh_jail_not_applied"

const (
	updatesStatusTimeout = 3 * time.Minute
	updatesApplyTimeout  = 50 * time.Minute
	jobUpdatesApply      = "system.updates.apply"
)

// ---- routes -----------------------------------------------------------------

func (s *Server) mountAdminx(r chi.Router) {
	s.opPerm(r, rbac.AccountsRead, "GET", "/admin/accounts/{id}/modify", "accounts", "Modify Account: current package, owner, shell access, overrides, contact email", nil, s.h(s.getModifyAccount))
	s.opPerm(r, rbac.AccountsWrite, "PUT", "/admin/accounts/{id}/modify", "accounts", "Modify Account (package, owner [admin], shell access, domain overrides, contact email)", ModifyAccountReq{}, s.h(s.putModifyAccount))
	s.opPerm(r, rbac.AccountsRead, "GET", "/admin/resellers/{id}/limits", "accounts", "Edit Reseller: limits, allowed packages, ACL", nil, s.h(s.getResellerLimits))
	s.opPerm(r, rbac.AccountsWrite, "PUT", "/admin/resellers/{id}/limits", "accounts", "Edit Reseller (admin only)", ResellerLimitsReq{}, s.h(s.putResellerLimits))
	s.opPerm(r, rbac.ServerRead, "GET", "/admin/updates/prefs", "server", "Update preferences", nil, s.h(s.getUpdatePrefs))
	s.opPerm(r, rbac.ServerWrite, "PUT", "/admin/updates/prefs", "server", "Set update preferences", UpdatePrefs{}, s.h(s.putUpdatePrefs))
	s.opPerm(r, rbac.ServerRead, "GET", "/admin/updates/status", "server", "Pending package updates and reboot-required (agent probe)", nil, s.h(s.getUpdatesStatus))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/updates/apply", "server", "Apply package updates now (job)", nil, s.h(s.postUpdatesApply))
	s.Jobs().Register(jobUpdatesApply, s.runUpdatesApply)
}

func (s *Server) mountAdminxUser(r chi.Router) {
	s.op(r, "GET", "/user/contact-email", "account", "Own contact email", nil, s.h(s.getContactEmail))
	s.op(r, "PUT", "/user/contact-email", "account", "Change own contact email", ContactEmailReq{}, s.h(s.putContactEmail))
	s.op(r, "GET", "/user/user-manager", "account", "User Manager: mailboxes and FTP accounts of this account", nil, s.h(s.userManager))
}

func adminOnly(r *http.Request) error {
	if u := userOf(r); u == nil || u.Role != "admin" {
		return &apiError{Status: 403, Code: "permission_denied"}
	}
	return nil
}

// ---- account overrides --------------------------------------------------------

type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type accountOverrides struct {
	ShellAccess     bool   `json:"shell_access"`
	MaxAddonDomains *int64 `json:"max_addon_domains"` // nil = package value
	MaxSubdomains   *int64 `json:"max_subdomains"`
}

func (s *Server) overridesOf(ctx context.Context, q rowQuerier, uid int64) accountOverrides {
	var o accountOverrides
	var sh int
	var ad, sd sql.NullInt64
	if err := q.QueryRowContext(ctx, `SELECT shell_access, max_addon_domains, max_subdomains FROM account_overrides WHERE user_id=?`, uid).Scan(&sh, &ad, &sd); err != nil {
		return o
	}
	o.ShellAccess = sh == 1
	if ad.Valid {
		o.MaxAddonDomains = &ad.Int64
	}
	if sd.Valid {
		o.MaxSubdomains = &sd.Int64
	}
	return o
}

// applyAccountOverrides is called by packageOf so every limit check (domain
// create, stats) sees the Modify Account overrides.
func (s *Server) applyAccountOverrides(ctx context.Context, u *store.User, p *store.Package) {
	if u == nil || u.ID == 0 {
		return
	}
	o := s.overridesOf(ctx, s.Store.R, u.ID)
	if o.MaxAddonDomains != nil {
		p.MaxDomains = *o.MaxAddonDomains
	}
	if o.MaxSubdomains != nil {
		p.MaxSubdomains = *o.MaxSubdomains
	}
}

// ---- Modify Account -------------------------------------------------------------

type ModifyAccountReq struct {
	PackageID       *int64  `json:"package_id,omitempty"`
	OwnerID         *int64  `json:"owner_id,omitempty"` // admin only
	ShellAccess     *bool   `json:"shell_access,omitempty"`
	MaxAddonDomains *int64  `json:"max_addon_domains,omitempty"` // -1 unlimited, >=0 limit
	MaxSubdomains   *int64  `json:"max_subdomains,omitempty"`
	ResetOverrides  bool    `json:"reset_overrides,omitempty"` // back to the package values
	Email           *string `json:"email,omitempty"`
	PrimaryDomain   *string `json:"primary_domain,omitempty"` // an addon domain of the account to promote (see file comment)
	Version         *int64  `json:"version,omitempty"`
}

func (s *Server) getModifyAccount(w http.ResponseWriter, r *http.Request) (any, error) {
	u, err := s.visibleAccount(r)
	if err != nil {
		return nil, err
	}
	o := s.overridesOf(r.Context(), s.Store.R, u.ID)
	pkg := s.packageOf(r.Context(), &u)
	return map[string]any{"id": u.ID, "username": u.Username, "role": u.Role, "package_id": u.PackageID, "owner_id": u.OwnerID,
		"email": u.Email, "primary_domain": u.PrimaryDomain, "version": u.Version, "overrides": o,
		"effective":        map[string]int64{"max_addon_domains": pkg.MaxDomains, "max_subdomains": pkg.MaxSubdomains},
		"rename_supported": true, "addon_domains": s.addonDomainNames(r.Context(), u.ID)}, nil
}

// addonDomainNames lists the addon domains that can become the primary domain.
func (s *Server) addonDomainNames(ctx context.Context, uid int64) []string {
	out := []string{}
	rows, err := s.Store.R.QueryContext(ctx, `SELECT name FROM domains WHERE user_id=? AND kind='addon' ORDER BY name`, uid)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			out = append(out, n)
		}
	}
	return out
}

func validOverride(v *int64, field string) error {
	if v != nil && (*v < -1 || *v > 100000) {
		return &apiError{Status: 400, Code: "invalid_limit", Field: field, Max: 100000}
	}
	return nil
}

func validContactEmail(e string) error {
	if len(e) > 254 {
		return tooLong("email", 254)
	}
	if e != "" && validate.Email(e) != nil {
		return badField("invalid_email", "email")
	}
	return nil
}

func (s *Server) putModifyAccount(w http.ResponseWriter, r *http.Request) (any, error) {
	var in ModifyAccountReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	me := userOf(r)
	u, err := s.manageableAccount(r)
	if err != nil {
		return nil, err
	}
	if err := checkVersion(w, r, in.Version, u.Version); err != nil {
		return nil, err
	}
	var newPrimaryID int64
	var newPrimary string
	if in.PrimaryDomain != nil && !strings.EqualFold(strings.TrimSpace(*in.PrimaryDomain), u.PrimaryDomain) {
		newPrimary = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(*in.PrimaryDomain), "."))
		var kind string
		err := s.Store.DB.QueryRowContext(r.Context(), `SELECT id, kind FROM domains WHERE user_id=? AND name=?`, u.ID, newPrimary).Scan(&newPrimaryID, &kind)
		if err != nil || kind != "addon" {
			return nil, &apiError{Status: 422, Code: "primary_domain_not_addon", Field: "primary_domain"}
		}
	}
	if in.OwnerID != nil && me.Role != "admin" {
		return nil, &apiError{Status: 403, Code: "permission_denied", Field: "owner_id"}
	}
	if err := validOverride(in.MaxAddonDomains, "max_addon_domains"); err != nil {
		return nil, err
	}
	if err := validOverride(in.MaxSubdomains, "max_subdomains"); err != nil {
		return nil, err
	}
	var email string
	if in.Email != nil {
		email = strings.TrimSpace(*in.Email)
		if err := validContactEmail(email); err != nil {
			return nil, err
		}
	}
	ctx := r.Context()
	// target package and owner
	pkgID := u.PackageID
	var pkg store.Package
	if in.PackageID != nil {
		pkgID = in.PackageID
	}
	if pkgID != nil {
		p, err := store.One[store.Package](ctx, s.Store.DB, `SELECT *, 0 AS accounts FROM packages WHERE id=?`, *pkgID)
		if err != nil {
			return nil, badField("invalid_package", "package_id")
		}
		pkg = p
	} else {
		pkg = unlimitedPackage()
	}
	ownerID := u.OwnerID
	var newOwner *store.User
	if in.OwnerID != nil && (u.OwnerID == nil || *u.OwnerID != *in.OwnerID) {
		if u.Role != "user" {
			return nil, &apiError{Status: 409, Code: "owner_change_not_allowed", Field: "owner_id"}
		}
		o, err := s.userByID(ctx, *in.OwnerID)
		if err != nil || (o.Role != "reseller" && o.Role != "admin") || o.Status == "terminating" {
			return nil, badField("invalid_owner", "owner_id")
		}
		newOwner, ownerID = &o, in.OwnerID
	}
	// the reseller that will own the account after the change (if any)
	var reseller *store.User
	switch {
	case newOwner != nil && newOwner.Role == "reseller":
		reseller = newOwner
	case newOwner == nil && me.Role == "reseller":
		reseller = me
	}
	pkgChanged := in.PackageID != nil && (u.PackageID == nil || *u.PackageID != *in.PackageID)
	if reseller != nil && (pkgChanged || newOwner != nil) {
		if pkg.OwnerID == nil || *pkg.OwnerID != reseller.ID {
			return nil, &apiError{Status: 403, Code: "package_not_owned", Field: "package_id"}
		}
		if err := s.checkResellerLimits(ctx, reseller, pkg, u.ID); err != nil {
			return nil, err
		}
	}
	var shellChanged bool
	old := s.overridesOf(ctx, s.Store.DB, u.ID)
	if err := s.Store.Tx(ctx, func(tx *sql.Tx) error {
		if reseller != nil && (pkgChanged || newOwner != nil) {
			if err := checkResellerAllocation(ctx, tx, reseller, pkg, u.ID, newOwner != nil); err != nil {
				return err
			}
		}
		guard, gargs := versionGuard(r, in.Version)
		res, err := tx.ExecContext(ctx, `UPDATE users SET package_id=?, owner_id=?, email=CASE WHEN ? THEN ? ELSE email END, version=version+1 WHERE id=?`+guard,
			append([]any{pkgID, ownerID, in.Email != nil, email, u.ID}, gargs...)...)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err == nil && n == 0 {
			return &apiError{Status: http.StatusPreconditionFailed, Code: "version_conflict"}
		}
		if newPrimaryID != 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE domains SET kind='addon' WHERE user_id=? AND kind='main'`, u.ID); err != nil {
				return err
			}
			if res, err := tx.ExecContext(ctx, `UPDATE domains SET kind='main' WHERE id=? AND user_id=? AND kind='addon'`, newPrimaryID, u.ID); err != nil {
				return err
			} else if n, _ := res.RowsAffected(); n != 1 {
				return &apiError{Status: 409, Code: "version_conflict"}
			}
			if _, err := tx.ExecContext(ctx, `UPDATE users SET primary_domain=? WHERE id=?`, newPrimary, u.ID); err != nil {
				return err
			}
		}
		o := old
		if in.ResetOverrides {
			o.MaxAddonDomains, o.MaxSubdomains = nil, nil
		}
		if in.MaxAddonDomains != nil {
			o.MaxAddonDomains = in.MaxAddonDomains
		}
		if in.MaxSubdomains != nil {
			o.MaxSubdomains = in.MaxSubdomains
		}
		if in.ShellAccess != nil {
			shellChanged = *in.ShellAccess != old.ShellAccess
			o.ShellAccess = *in.ShellAccess
		}
		sh := 0
		if o.ShellAccess {
			sh = 1
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO account_overrides(user_id,shell_access,max_addon_domains,max_subdomains,updated_at) VALUES(?,?,?,?,?)
			ON CONFLICT(user_id) DO UPDATE SET shell_access=excluded.shell_access, max_addon_domains=excluded.max_addon_domains,
			max_subdomains=excluded.max_subdomains, updated_at=excluded.updated_at`, u.ID, sh, o.MaxAddonDomains, o.MaxSubdomains, s.Now().Unix())
		return err
	}); err != nil {
		return nil, err
	}
	warnings := []Warning{}
	if pkgChanged && u.SystemUser {
		if err := s.agentCall(r, rpc.MAccountQuota, rpc.AccountQuota{User: u.Username, QuotaMB: agentLimit(pkg.DiskMB), CPUQuota: int(agentLimit(pkg.CPUPercent)), MemoryMB: agentLimit(pkg.MemoryMB), MaxTasks: int(agentLimit(pkg.MaxTasks))}, nil); err != nil {
			warnings = append(warnings, warn(WarnQuotaUpdateFailed, "quota", ""))
		}
	}
	shellStatus := ""
	if shellChanged {
		shellStatus = s.applySSHJail(r)
		if shellStatus != "applied" {
			warnings = append(warnings, warn(WarnSSHJailNotApplied, "ssh", shellStatus))
		}
	}
	var parts []string
	if pkgChanged {
		parts = append(parts, "package="+pkg.Name)
	}
	if newOwner != nil {
		parts = append(parts, "owner="+newOwner.Username)
	}
	if in.ShellAccess != nil {
		parts = append(parts, "shell="+strconv.FormatBool(*in.ShellAccess))
	}
	if in.MaxAddonDomains != nil || in.MaxSubdomains != nil || in.ResetOverrides {
		parts = append(parts, "domain_overrides")
	}
	if in.Email != nil {
		parts = append(parts, "contact_email")
	}
	if newPrimaryID != 0 {
		parts = append(parts, "primary_domain="+newPrimary)
		s.audit(r, "account.primary_domain", u.Username, u.PrimaryDomain+" -> "+newPrimary, true)
		s.billingEvent(r, "account.primary_domain_changed", u.ID, u.Username, map[string]any{"old": u.PrimaryDomain, "domain": newPrimary})
	}
	s.audit(r, "account.modify", u.Username, strings.Join(parts, " "), true)
	return map[string]any{"ok": true, "warnings": warnings, "ssh": shellStatus}, nil
}

// applySSHJail re-renders the sshd jail file: every hosting account WITHOUT
// shell access is jailed (mode from setting ssh_jail_mode, default sftp).
// Returns the agent status or a reason when it could not be applied.
func (s *Server) applySSHJail(r *http.Request) string {
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT u.username FROM users u LEFT JOIN account_overrides o ON o.user_id=u.id
		WHERE u.system_user=1 AND u.role IN ('user','reseller') AND u.status NOT IN ('provisioning','terminating') AND COALESCE(o.shell_access,0)=0 ORDER BY u.username`)
	if err != nil {
		return "db_error"
	}
	var users []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			users = append(users, n)
		}
	}
	rows.Close()
	if users == nil {
		users = []string{}
	}
	mode := s.Store.Get("ssh_jail_mode", "sftp")
	if mode != "cage" {
		mode = "sftp"
	}
	shell := []string{}
	if rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT u.username FROM users u JOIN account_overrides o ON o.user_id=u.id
		WHERE u.system_user=1 AND u.role IN ('user','reseller') AND u.status NOT IN ('provisioning','terminating') AND o.shell_access=1 ORDER BY u.username`); err == nil {
		for rows.Next() {
			var n string
			if rows.Scan(&n) == nil {
				shell = append(shell, n)
			}
		}
		rows.Close()
	}
	var res rpc.IsolationSSHResult
	if err := s.agentCall(r, rpc.MIsolationSSHApply, rpc.IsolationSSHApply{Users: users, Mode: mode, Shell: shell}, &res); err != nil {
		var re *rpc.Error
		if errors.As(err, &re) {
			s.audit(r, "isolation.ssh.apply", "", re.Code, false)
			return re.Code
		}
		return "agent_error"
	}
	s.audit(r, "isolation.ssh.apply", "", res.Status, true)
	if res.Status == "" {
		return "applied"
	}
	return res.Status
}

// ---- Change Contact Email (user realm) ------------------------------------------

type ContactEmailReq struct {
	Email string `json:"email"`
}

func (s *Server) getContactEmail(w http.ResponseWriter, r *http.Request) (any, error) {
	return map[string]any{"email": userOf(r).Email, "notify_old": false}, nil
}

func (s *Server) putContactEmail(w http.ResponseWriter, r *http.Request) (any, error) {
	var in ContactEmailReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	e := strings.TrimSpace(in.Email)
	if e == "" {
		return nil, badField("invalid_email", "email")
	}
	if err := validContactEmail(e); err != nil {
		return nil, err
	}
	u := userOf(r)
	if _, err := s.Store.DB.ExecContext(r.Context(), `UPDATE users SET email=?, version=version+1 WHERE id=?`, e, u.ID); err != nil {
		return nil, err
	}
	// no outbound mail path in the panel: the old address is not notified,
	// the change is audited (old address masked).
	s.audit(r, "account.contact_email", u.Username, "from "+maskEmail(u.Email), true)
	return map[string]any{"ok": true, "email": e, "old_notified": false}, nil
}

func maskEmail(e string) string {
	l, d, ok := strings.Cut(e, "@")
	if !ok || l == "" {
		return "(none)"
	}
	return l[:1] + "***@" + d
}

// ---- Edit Reseller ----------------------------------------------------------------

type ResellerLimitsReq struct {
	MaxAccounts     *int64    `json:"max_accounts,omitempty"`     // -1 unlimited
	DiskMB          *int64    `json:"disk_mb,omitempty"`          // -1 no pool limit
	BandwidthMB     *int64    `json:"bandwidth_mb,omitempty"`     // -1 no pool limit
	AllowedPackages *[]int64  `json:"allowed_packages,omitempty"` // [] = all own packages
	ACL             *[]string `json:"acl,omitempty"`              // [] = full reseller role
}

type resellerLimits struct {
	MaxAccounts     int64    `json:"max_accounts"`
	DiskMB          int64    `json:"disk_mb"`
	BandwidthMB     int64    `json:"bandwidth_mb"`
	AllowedPackages []int64  `json:"allowed_packages"`
	ACL             []string `json:"acl"`
}

func (s *Server) resellerLimitsOf(ctx context.Context, q rowQuerier, u *store.User) resellerLimits {
	l := resellerLimits{MaxAccounts: u.MaxAccounts, DiskMB: u.ResellerDiskMB, BandwidthMB: Unlimited, AllowedPackages: []int64{}, ACL: []string{}}
	var ap, acl string
	if err := q.QueryRowContext(ctx, `SELECT bandwidth_mb, allowed_packages, acl FROM reseller_limits WHERE user_id=?`, u.ID).Scan(&l.BandwidthMB, &ap, &acl); err == nil {
		_ = json.Unmarshal([]byte(ap), &l.AllowedPackages)
		_ = json.Unmarshal([]byte(acl), &l.ACL)
	}
	return l
}

func (s *Server) resellerByParam(r *http.Request) (store.User, error) {
	u, err := s.userByID(r.Context(), idParam(r, "id"))
	if err != nil || u.Role != "reseller" {
		return u, notFound()
	}
	return u, nil
}

func (s *Server) getResellerLimits(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := adminOnly(r); err != nil {
		return nil, err
	}
	u, err := s.resellerByParam(r)
	if err != nil {
		return nil, err
	}
	l := s.resellerLimitsOf(r.Context(), s.Store.R, &u)
	var used struct{ accounts, disk, bw int64 }
	_ = s.Store.R.QueryRowContext(r.Context(), `SELECT COUNT(*), COALESCE(SUM(MAX(p.disk_mb,0)),0), COALESCE(SUM(MAX(p.bandwidth_mb,0)),0)
		FROM users c LEFT JOIN packages p ON p.id=c.package_id WHERE c.owner_id=?`, u.ID).Scan(&used.accounts, &used.disk, &used.bw)
	pkgs, err := store.Select[store.Package](r.Context(), s.Store.R, `SELECT *, 0 AS accounts FROM packages WHERE owner_id=? ORDER BY name`, u.ID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": u.ID, "username": u.Username, "limits": l, "acl_choices": rbac.Perms(rbac.Reseller), "packages": pkgs,
		"used": map[string]int64{"accounts": used.accounts, "disk_mb": used.disk, "bandwidth_mb": used.bw}}, nil
}

func (s *Server) putResellerLimits(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := adminOnly(r); err != nil {
		return nil, err
	}
	var in ResellerLimitsReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u, err := s.resellerByParam(r)
	if err != nil {
		return nil, err
	}
	l := s.resellerLimitsOf(r.Context(), s.Store.DB, &u)
	chk := func(v *int64, field string, dst *int64) error {
		if v == nil {
			return nil
		}
		if *v < -1 || *v == 0 && field != "max_accounts" || *v > maxSizeMB {
			return &apiError{Status: 400, Code: "invalid_limit", Field: field, Max: maxSizeMB}
		}
		*dst = *v
		return nil
	}
	if err := chk(in.MaxAccounts, "max_accounts", &l.MaxAccounts); err != nil {
		return nil, err
	}
	if err := chk(in.DiskMB, "disk_mb", &l.DiskMB); err != nil {
		return nil, err
	}
	if err := chk(in.BandwidthMB, "bandwidth_mb", &l.BandwidthMB); err != nil {
		return nil, err
	}
	if in.AllowedPackages != nil {
		seen := map[int64]bool{}
		l.AllowedPackages = []int64{}
		for _, id := range *in.AllowedPackages {
			var n int
			if err := s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM packages WHERE id=? AND owner_id=?`, id, u.ID).Scan(&n); err != nil {
				return nil, err
			}
			if n == 0 {
				return nil, badField("invalid_package", "allowed_packages")
			}
			if !seen[id] {
				seen[id] = true
				l.AllowedPackages = append(l.AllowedPackages, id)
			}
		}
		sort.Slice(l.AllowedPackages, func(i, j int) bool { return l.AllowedPackages[i] < l.AllowedPackages[j] })
	}
	if in.ACL != nil {
		l.ACL = []string{}
		seen := map[string]bool{}
		for _, p := range *in.ACL {
			if !rbac.Has(rbac.Reseller, p) {
				return nil, &apiError{Status: 400, Code: "invalid_acl", Field: "acl", Message: p}
			}
			if !seen[p] {
				seen[p] = true
				l.ACL = append(l.ACL, p)
			}
		}
		sort.Strings(l.ACL)
	}
	ap, _ := json.Marshal(l.AllowedPackages)
	acl, _ := json.Marshal(l.ACL)
	if err := s.Store.Tx(r.Context(), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(r.Context(), `UPDATE users SET max_accounts=?, reseller_disk_mb=?, version=version+1 WHERE id=?`, l.MaxAccounts, l.DiskMB, u.ID); err != nil {
			return err
		}
		_, err := tx.ExecContext(r.Context(), `INSERT INTO reseller_limits(user_id,bandwidth_mb,allowed_packages,acl,updated_at) VALUES(?,?,?,?,?)
			ON CONFLICT(user_id) DO UPDATE SET bandwidth_mb=excluded.bandwidth_mb, allowed_packages=excluded.allowed_packages, acl=excluded.acl, updated_at=excluded.updated_at`,
			u.ID, l.BandwidthMB, string(ap), string(acl), s.Now().Unix())
		return err
	}); err != nil {
		return nil, err
	}
	s.audit(r, "reseller.limits", u.Username, "accounts="+strconv.FormatInt(l.MaxAccounts, 10)+" disk="+strconv.FormatInt(l.DiskMB, 10)+
		" bw="+strconv.FormatInt(l.BandwidthMB, 10)+" packages="+string(ap)+" acl="+string(acl), true)
	return map[string]any{"ok": true, "limits": l}, nil
}

// checkResellerLimits enforces the Edit Reseller limits that are not already
// covered by checkResellerAllocation (max accounts / disk pool): allowed
// packages and the bandwidth pool. excludeUser is the account being changed.
func (s *Server) checkResellerLimits(ctx context.Context, reseller *store.User, pkg store.Package, excludeUser int64) error {
	if reseller == nil || reseller.Role != "reseller" {
		return nil
	}
	l := s.resellerLimitsOf(ctx, s.Store.DB, reseller)
	if len(l.AllowedPackages) > 0 {
		ok := false
		for _, id := range l.AllowedPackages {
			ok = ok || id == pkg.ID
		}
		if !ok {
			return &apiError{Status: 403, Code: "package_not_allowed", Field: "package_id"}
		}
	}
	if limited(l.BandwidthMB) {
		if !limited(pkg.BandwidthMB) {
			return &apiError{Status: 403, Code: "reseller_unlimited_not_allowed", Field: "bandwidth_mb", Message: "bandwidth_mb"}
		}
		var used int64
		if err := s.Store.DB.QueryRowContext(ctx, `SELECT COALESCE(SUM(MAX(p.bandwidth_mb,0)),0) FROM users u JOIN packages p ON p.id=u.package_id
			WHERE u.owner_id=? AND u.id<>?`, reseller.ID, excludeUser).Scan(&used); err != nil {
			return err
		}
		if used+pkg.BandwidthMB > l.BandwidthMB {
			return &apiError{Status: 409, Code: "limit_reached", Message: "reseller_bandwidth", Field: "bandwidth_mb", Max: l.BandwidthMB}
		}
	}
	return nil
}

// resellerACL narrows a reseller's admin-realm permissions to its ACL (set
// by Edit Reseller). Empty ACL = the full reseller role. admin.read always
// stays so the dashboard loads. Installed after permGuard on the admin group.
func (s *Server) resellerACL(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := userOf(r)
		if u == nil || u.Role != "reseller" {
			next.ServeHTTP(w, r)
			return
		}
		var acl string
		if err := s.Store.R.QueryRowContext(r.Context(), `SELECT acl FROM reseller_limits WHERE user_id=?`, u.ID).Scan(&acl); err != nil {
			next.ServeHTTP(w, r)
			return
		}
		var list []string
		if json.Unmarshal([]byte(acl), &list) != nil || len(list) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		perm := rbac.AdminRead
		if p, ok := lookupRoutePerm(r.Method, routePath(r)); ok {
			perm = p.Perm
		}
		if perm != rbac.AdminRead {
			allowed := false
			for _, p := range list {
				allowed = allowed || p == perm
			}
			if !allowed {
				permDenied(w)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ---- Update Preferences -----------------------------------------------------------

type UpdatePrefs struct {
	Policy     string `json:"policy"`      // security | all | manual
	AutoReboot string `json:"auto_reboot"` // never | when_required
}

func (s *Server) updatePrefs() UpdatePrefs {
	return UpdatePrefs{Policy: s.Store.Get("update_policy", "manual"), AutoReboot: s.Store.Get("update_auto_reboot", "never")}
}

func (s *Server) getUpdatePrefs(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := adminOnly(r); err != nil {
		return nil, err
	}
	return map[string]any{"prefs": s.updatePrefs(), "last_job": s.Store.Get("update_last_job", "")}, nil
}

func (s *Server) putUpdatePrefs(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := adminOnly(r); err != nil {
		return nil, err
	}
	var in UpdatePrefs
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	switch in.Policy {
	case "security", "all", "manual":
	default:
		return nil, badField("invalid_update_policy", "policy")
	}
	switch in.AutoReboot {
	case "never", "when_required":
	default:
		return nil, badField("invalid_update_policy", "auto_reboot")
	}
	if err := s.Store.Set("update_policy", in.Policy); err != nil {
		return nil, err
	}
	if err := s.Store.Set("update_auto_reboot", in.AutoReboot); err != nil {
		return nil, err
	}
	s.audit(r, "server.update_prefs", "", in.Policy+" reboot="+in.AutoReboot, true)
	return map[string]any{"ok": true, "prefs": in}, nil
}

func (s *Server) getUpdatesStatus(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := adminOnly(r); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(r.Context(), updatesStatusTimeout)
	defer cancel()
	var st rpc.UpdatesStatus
	if err := s.Agent.Call(ctx, rpc.MUpdatesStatus, rpc.UpdatesStatusReq{SecurityOnly: s.updatePrefs().Policy == "security"}, &st); err != nil {
		var re *rpc.Error
		if errors.As(err, &re) && re.Code == "unknown_method" {
			return rpc.UpdatesStatus{Status: "unsupported", Reason: "agent does not support update status (upgrade bpanel-agent)"}, nil
		}
		return nil, err
	}
	if st.Status == "" {
		st.Status = "unsupported"
		st.Reason = "agent returned no status"
	}
	return st, nil
}

type updatesApplyPayload struct {
	SecurityOnly bool  `json:"security_only"`
	AutoReboot   bool  `json:"auto_reboot"`
	ActorID      int64 `json:"actor_id"`
}

func (s *Server) postUpdatesApply(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := adminOnly(r); err != nil {
		return nil, err
	}
	p := s.updatePrefs()
	pl := updatesApplyPayload{SecurityOnly: p.Policy == "security", AutoReboot: p.AutoReboot == "when_required", ActorID: userOf(r).ID}
	id, err := s.Jobs().Enqueue(r.Context(), jobs.Spec{Kind: jobUpdatesApply, ActorID: userOf(r).ID, Payload: pl})
	if err != nil {
		return nil, err
	}
	_ = s.Store.Set("update_last_job", id)
	s.audit(r, "server.updates_apply", id, "security_only="+strconv.FormatBool(pl.SecurityOnly)+" auto_reboot="+strconv.FormatBool(pl.AutoReboot), true)
	return map[string]any{"job_id": id}, nil
}

func (s *Server) runUpdatesApply(ctx context.Context, j *jobs.Job) (any, error) {
	var pl updatesApplyPayload
	if err := json.Unmarshal(j.Payload, &pl); err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, updatesApplyTimeout)
	defer cancel()
	var res rpc.UpdatesApplyResult
	err := s.Agent.Call(cctx, rpc.MUpdatesApply, rpc.UpdatesApply{SecurityOnly: pl.SecurityOnly, AutoReboot: pl.AutoReboot}, &res)
	ok := err == nil && res.Status == "applied"
	detail := res.Status
	if err != nil {
		var re *rpc.Error
		if errors.As(err, &re) {
			detail = re.Code
		} else {
			detail = "agent_error"
		}
	}
	s.auditSystem("server.updates_applied", j.ID, detail, ok)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// ---- User Manager (user realm) ------------------------------------------------------

type subUser struct {
	Kind      string   `json:"kind"` // email | ftp
	ID        int64    `json:"id"`
	Login     string   `json:"login"`
	Services  []string `json:"services"`
	QuotaMB   int64    `json:"quota_mb"`
	Detail    string   `json:"detail,omitempty"`
	CreatedAt int64    `json:"created_at"`
	Manage    string   `json:"manage"` // UI path
}

func (s *Server) userManager(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	ctx := r.Context()
	mb, err := store.Select[store.Mailbox](ctx, s.Store.R, `SELECT id,user_id,domain_id,email,quota_mb,created_at FROM mailboxes WHERE user_id=? ORDER BY email`, u.ID)
	if err != nil {
		return nil, err
	}
	ftp, err := store.Select[store.FTPAccount](ctx, s.Store.R, `SELECT id,user_id,login,dir,quota_mb,created_at FROM ftp_accounts WHERE user_id=? ORDER BY login`, u.ID)
	if err != nil {
		return nil, err
	}
	out := []subUser{}
	for _, m := range mb {
		out = append(out, subUser{Kind: "email", ID: m.ID, Login: m.Email, Services: []string{"email"}, QuotaMB: m.QuotaMB, CreatedAt: m.CreatedAt, Manage: "/email/accounts"})
	}
	for _, f := range ftp {
		out = append(out, subUser{Kind: "ftp", ID: f.ID, Login: f.Login, Services: []string{"ftp"}, QuotaMB: f.QuotaMB, Detail: f.Dir, CreatedAt: f.CreatedAt, Manage: "/ftp"})
	}
	pkg := s.packageOf(ctx, u)
	return map[string]any{"account": u.Username, "users": out,
		"counts":  map[string]int{"email": len(mb), "ftp": len(ftp)},
		"limits":  map[string]int64{"email": pkg.MaxEmail, "ftp": pkg.MaxFTP},
		"create":  map[string]string{"email": "/email/accounts?new=1", "ftp": "/ftp?new=1"},
		"webdisk": "not_installed"}, nil
}
