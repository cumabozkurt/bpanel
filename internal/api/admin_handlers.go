package api

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/store"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// PackageReq creates or edits a package. Every limit follows G1 (see
// limits.go): -1 or null = unlimited, 0 = none (counts only), absent =
// unlimited. Version (or an If-Match header) makes an edit conditional.
type PackageReq struct {
	Name          string `json:"name"`
	DiskMB        Limit  `json:"disk_mb"`
	BandwidthMB   Limit  `json:"bandwidth_mb"`
	MaxDomains    Limit  `json:"max_domains"`
	MaxSubdomains Limit  `json:"max_subdomains"`
	MaxAliases    Limit  `json:"max_aliases"`
	MaxEmail      Limit  `json:"max_email"`
	MaxDB         Limit  `json:"max_db"`
	MaxFTP        Limit  `json:"max_ftp"`
	MailQuotaMB   Limit  `json:"mail_quota_mb"`
	CPUPercent    Limit  `json:"cpu_percent"`
	MemoryMB      Limit  `json:"memory_mb"`
	MaxTasks      Limit  `json:"max_tasks"`
	PHPVersion    string `json:"php_version"`
	Version       *int64 `json:"version,omitempty"`
}

type SuspendReq struct {
	Reason  string `json:"reason"`
	Version *int64 `json:"version,omitempty"`
}

type ChangePackageReq struct {
	PackageID int64  `json:"package_id"`
	Version   *int64 `json:"version,omitempty"`
}

type SettingsReq struct {
	DefaultLang  *string `json:"default_lang,omitempty"`
	DefaultPHP   *string `json:"default_php,omitempty"`
	Nameservers  *string `json:"nameservers,omitempty"`
	ServerIP     *string `json:"server_ip,omitempty"`
	ACMEEmail    *string `json:"acme_email,omitempty"`
	ContactEmail *string `json:"contact_email,omitempty"`
}

func (s *Server) adminRoutes(r chi.Router) {
	s.op(r, "GET", "/admin/summary", "admin", "Server meta strip, statistics and next steps", nil, s.h(s.adminSummary))
	s.op(r, "GET", "/admin/packages", "packages", "List hosting packages", nil, s.h(s.listPackages))
	s.op(r, "POST", "/admin/packages", "packages", "Create a package", PackageReq{}, s.h(s.createPackage))
	s.op(r, "PUT", "/admin/packages/{id}", "packages", "Edit a package (re-applies limits to its accounts)", PackageReq{}, s.h(s.updatePackage))
	s.op(r, "DELETE", "/admin/packages/{id}", "packages", "Delete an unused package", nil, s.h(s.deletePackage))
	s.op(r, "GET", "/admin/accounts", "accounts", "List accounts visible to the caller (?limit=&offset=&q=&role=&status=)", nil, s.h(s.listAccounts))
	s.op(r, "POST", "/admin/accounts", "accounts", "Create a hosting account (or reseller)", CreateAccountReq{}, s.idempotent(s.h(s.createAccount)))
	s.op(r, "POST", "/admin/accounts/{id}/suspend", "accounts", "Suspend an account", SuspendReq{}, s.h(s.suspendAccount))
	s.op(r, "POST", "/admin/accounts/{id}/unsuspend", "accounts", "Unsuspend an account", nil, s.h(s.unsuspendAccount))
	s.op(r, "PUT", "/admin/accounts/{id}/package", "accounts", "Change an account's package", ChangePackageReq{}, s.h(s.changeAccountPackage))
	s.op(r, "POST", "/admin/accounts/{id}/password", "accounts", "Set an account's password", PasswordReq{}, s.h(s.setAccountPassword))
	s.op(r, "POST", "/admin/accounts/{id}/login", "accounts", "One-time link to the user panel as this account", nil, s.h(s.loginAs))
	s.op(r, "DELETE", "/admin/accounts/{id}", "accounts", "Terminate an account (removes all data)", nil, s.h(s.terminateAccount))
	s.mountIsolation(r)
	s.mountShield(r)   // v0.4 shield.go
	s.mountV11Admin(r) // v1.1 parity: mail queue, IPs, hostname, tweak settings, PHP extensions, billing
	r.Group(func(r chi.Router) {
		r.Use(s.requireRole("admin"))
		s.op(r, "GET", "/admin/services", "server", "Service status", nil, s.h(s.listServices))
		s.op(r, "POST", "/admin/services/{unit}/{action}", "server", "Start, stop, restart or reload a service", nil, s.h(s.serviceAction))
		s.op(r, "GET", "/admin/php", "server", "PHP versions (MultiPHP manager)", nil, s.h(s.adminPHP))
		s.op(r, "POST", "/admin/php/{version}/{action}", "server", "Install or remove a PHP version", nil, s.h(s.adminPHPAction))
		s.op(r, "GET", "/admin/server", "server", "Server information", nil, s.h(s.serverInfo))
		s.op(r, "GET", "/admin/audit", "server", "Audit log (?limit=&q=)", nil, s.h(s.auditLog))
		s.op(r, "GET", "/admin/settings", "server", "Server settings", nil, s.h(s.getSettings))
		s.op(r, "PUT", "/admin/settings", "server", "Update server settings", SettingsReq{}, s.h(s.putSettings))
		s.mountProviders(r)
	})
}

// visibleAccount returns an account the caller may manage.
func (s *Server) visibleAccount(r *http.Request) (store.User, error) {
	me := userOf(r)
	u, err := s.userByID(r.Context(), idParam(r, "id"))
	if err != nil {
		return u, notFound()
	}
	if u.Role == "admin" || u.ID == me.ID {
		return u, forbidden()
	}
	if me.Role == "reseller" && (u.OwnerID == nil || *u.OwnerID != me.ID) {
		return u, notFound()
	}
	if u.Status == "provisioning" {
		return u, conflict("account_busy")
	}
	return u, nil
}

// manageableAccount is visibleAccount for every action except terminate: an
// account being terminated can only be terminated (again).
func (s *Server) manageableAccount(r *http.Request) (store.User, error) {
	u, err := s.visibleAccount(r)
	if err == nil && u.Status == "terminating" {
		return u, conflict("account_busy")
	}
	return u, err
}

func (s *Server) adminSummary(w http.ResponseWriter, r *http.Request) (any, error) {
	me := userOf(r)
	var si rpc.SysInfo
	if me.Role == "admin" {
		var err error
		if si, err = s.sysInfo(r); err != nil {
			s.Log.Info("summary: sysinfo", "err", err) // the summary renders without it
		}
	}
	where, args := " WHERE role<>'admin'", []any{}
	if me.Role == "reseller" {
		where, args = " WHERE owner_id=?", []any{me.ID}
	}
	cnt := func(extra string) int64 {
		q := `SELECT COUNT(*) FROM users` + where
		if extra != "" {
			if where == "" {
				q += " WHERE " + extra
			} else {
				q += " AND " + extra
			}
		}
		return s.count(q, args...)
	}
	pkgCount := s.count(`SELECT COUNT(*) FROM packages`)
	if me.Role == "reseller" {
		pkgCount = s.count(`SELECT COUNT(*) FROM packages WHERE owner_id=?`, me.ID) // R2-UX-03
	}
	steps := []map[string]string{}
	if me.Role == "admin" {
		if s.Store.Get("nameservers", "") == "" {
			steps = append(steps, map[string]string{"key": "nameservers", "tool": "settings"})
		}
		if s.Store.Get("contact_email", "") == "" {
			steps = append(steps, map[string]string{"key": "contact", "tool": "settings"})
		}
		if !me.TOTPEnabled {
			steps = append(steps, map[string]string{"key": "totp", "tool": "security"})
		}
		if s.count(`SELECT COUNT(*) FROM packages`) == 0 {
			steps = append(steps, map[string]string{"key": "package", "tool": "packages"})
		}
	}
	out := map[string]any{
		"username": me.Username, "role": me.Role, "hostname": s.Cfg.Hostname, "version": s.Version, "sys": si,
		"accounts": cnt(""), "suspended": cnt("status='suspended'"),
		"packages": pkgCount, "next_steps": steps,
	}
	if me.Role == "admin" {
		out["resellers"] = cnt("role='reseller'") // resellers do not manage resellers (R2-UX-02)
	}
	return out, nil
}

// ---- packages ----------------------------------------------------------------

func (s *Server) listPackages(w http.ResponseWriter, r *http.Request) (any, error) {
	me := userOf(r)
	q := `SELECT p.*, (SELECT COUNT(*) FROM users u WHERE u.package_id=p.id) AS accounts FROM packages p`
	if me.Role == "reseller" {
		// R2-UX-03: only the reseller's own packages (the admin's are neither
		// usable by it nor its business)
		return store.Select[store.Package](r.Context(), s.Store.R, q+` WHERE p.owner_id=? ORDER BY p.name`, me.ID)
	}
	return store.Select[store.Package](r.Context(), s.Store.R, q+` ORDER BY p.name`)
}

// asPackage resolves absent limits to unlimited (G1).
func (in *PackageReq) asPackage() store.Package {
	u := Unlimited
	return store.Package{Name: in.Name, DiskMB: in.DiskMB.or(u), BandwidthMB: in.BandwidthMB.or(u), MaxDomains: in.MaxDomains.or(u),
		MaxSubdomains: in.MaxSubdomains.or(u), MaxAliases: in.MaxAliases.or(u), MaxEmail: in.MaxEmail.or(u), MaxDB: in.MaxDB.or(u),
		MaxFTP: in.MaxFTP.or(u), MailQuotaMB: in.MailQuotaMB.or(u), CPUPercent: in.CPUPercent.or(u), MemoryMB: in.MemoryMB.or(u),
		MaxTasks: in.MaxTasks.or(u), PHPVersion: in.PHPVersion}
}

// validate checks the name (UX-40: a real pattern, trimmed, never cut) and
// every limit (G1 rules and sane upper bounds), naming the field.
func (in *PackageReq) validate() error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return badField("invalid_name", "name")
	}
	if err := validate.PackageName(in.Name); err != nil {
		return fieldErr(err, "name", 64)
	}
	p := in.asPackage()
	for _, c := range []struct {
		k string
		v int64
	}{{"max_domains", p.MaxDomains}, {"max_subdomains", p.MaxSubdomains}, {"max_aliases", p.MaxAliases},
		{"max_email", p.MaxEmail}, {"max_db", p.MaxDB}, {"max_ftp", p.MaxFTP}} {
		if err := checkCount(c.k, c.v); err != nil {
			return err
		}
	}
	for _, c := range []struct {
		k   string
		v   int64
		max int64
	}{{"disk_mb", p.DiskMB, maxSizeMB}, {"bandwidth_mb", p.BandwidthMB, maxSizeMB}, {"mail_quota_mb", p.MailQuotaMB, maxSizeMB},
		{"cpu_percent", p.CPUPercent, maxCPUPercent}, {"memory_mb", p.MemoryMB, maxSizeMB}, {"max_tasks", p.MaxTasks, maxTasksLimit}} {
		if err := checkSize(c.k, c.v, c.max); err != nil {
			return err
		}
	}
	if in.PHPVersion != "" && validate.PHPVersion(in.PHPVersion) != nil {
		return badField("invalid_php_version", "php_version")
	}
	return nil
}

// ---- optimistic locking (R2-PERF-15) ----------------------------------------

// wantVersion returns the version the client edited: the body's "version"
// or an If-Match header ("3", "\"3\"" or W/"3"). Neither = unconditional
// (last writer wins, as before).
func wantVersion(r *http.Request, body *int64) (int64, bool, error) {
	if body != nil {
		return *body, true, nil
	}
	h := strings.TrimSpace(r.Header.Get("If-Match"))
	if h == "" || h == "*" {
		return 0, false, nil
	}
	h = strings.Trim(strings.TrimPrefix(h, "W/"), `"`)
	v, err := strconv.ParseInt(h, 10, 64)
	if err != nil {
		return 0, false, &apiError{Status: 400, Code: "invalid_version", Field: "If-Match"}
	}
	return v, true, nil
}

// checkVersion answers 412 version_conflict when the row changed since the
// client read it. The current version is sent as ETag.
func checkVersion(w http.ResponseWriter, r *http.Request, body *int64, current int64) error {
	want, ok, err := wantVersion(r, body)
	if err != nil || !ok {
		return err
	}
	if want != current {
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, current))
		return &apiError{Status: http.StatusPreconditionFailed, Code: "version_conflict", Message: fmt.Sprintf("current version %d", current)}
	}
	return nil
}

// bumpVersion runs an UPDATE ... SET version=version+1 guarded by the
// expected version, so two concurrent edits cannot both win.
func versionGuard(r *http.Request, body *int64) (string, []any) {
	if want, ok, _ := wantVersion(r, body); ok {
		return ` AND version=?`, []any{want}
	}
	return "", nil
}

func (s *Server) createPackage(w http.ResponseWriter, r *http.Request) (any, error) {
	var in PackageReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	me := userOf(r)
	var owner any
	name := in.Name
	p := in.asPackage()
	if me.Role == "reseller" {
		owner = me.ID
		if !strings.HasPrefix(name, me.Username+"_") {
			name = me.Username + "_" + name
		}
		// resellers cannot define unlimited packages or exceed their disk pool (CODE-9)
		if err := resellerPackageOK(p, me); err != nil {
			return nil, err
		}
	}
	res, err := s.Store.DB.Exec(`INSERT INTO packages(name,owner_id,disk_mb,bandwidth_mb,max_domains,max_subdomains,max_aliases,max_email,max_db,max_ftp,mail_quota_mb,cpu_percent,memory_mb,max_tasks,php_version,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, name, owner, p.DiskMB, p.BandwidthMB, p.MaxDomains, p.MaxSubdomains, p.MaxAliases,
		p.MaxEmail, p.MaxDB, p.MaxFTP, p.MailQuotaMB, p.CPUPercent, p.MemoryMB, p.MaxTasks, p.PHPVersion, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	s.audit(r, "package.create", name, "", true)
	return map[string]any{"id": id, "name": name, "version": 1, "prefixed": name != in.Name}, nil
}

func (s *Server) ownPackage(r *http.Request) (store.Package, error) {
	p, err := store.One[store.Package](r.Context(), s.Store.DB, `SELECT *, 0 AS accounts FROM packages WHERE id=?`, idParam(r, "id"))
	if err != nil {
		return p, notFound()
	}
	me := userOf(r)
	if me.Role == "reseller" && (p.OwnerID == nil || *p.OwnerID != me.ID) {
		return p, forbidden()
	}
	return p, nil
}

func (s *Server) updatePackage(w http.ResponseWriter, r *http.Request) (any, error) {
	var in PackageReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	p, err := s.ownPackage(r)
	if err != nil {
		return nil, err
	}
	if err := checkVersion(w, r, in.Version, p.Version); err != nil {
		return nil, err
	}
	np := in.asPackage()
	me := userOf(r)
	if me.Role == "reseller" {
		if err := resellerPackageOK(np, me); err != nil {
			return nil, err
		}
		if limited(me.ResellerDiskMB) {
			// growing a package grows every account on it: re-check the pool
			var used int64
			if err := s.Store.DB.QueryRowContext(r.Context(), `SELECT COALESCE(SUM(p.disk_mb),0) FROM users u JOIN packages p ON p.id=u.package_id
				WHERE u.owner_id=? AND u.package_id<>?`, me.ID, p.ID).Scan(&used); err != nil {
				return nil, err
			}
			n := s.count(`SELECT COUNT(*) FROM users WHERE package_id=? AND owner_id=?`, p.ID, me.ID)
			if used+n*np.DiskMB > me.ResellerDiskMB {
				return nil, &apiError{Status: 409, Code: "limit_reached", Message: "reseller_disk", Field: "disk_mb"}
			}
		}
	}
	guard, gargs := versionGuard(r, in.Version)
	res, err := s.Store.DB.Exec(`UPDATE packages SET disk_mb=?,bandwidth_mb=?,max_domains=?,max_subdomains=?,max_aliases=?,max_email=?,max_db=?,max_ftp=?,mail_quota_mb=?,cpu_percent=?,memory_mb=?,max_tasks=?,php_version=?,version=version+1 WHERE id=?`+guard,
		append([]any{np.DiskMB, np.BandwidthMB, np.MaxDomains, np.MaxSubdomains, np.MaxAliases, np.MaxEmail, np.MaxDB, np.MaxFTP, np.MailQuotaMB, np.CPUPercent, np.MemoryMB, np.MaxTasks, np.PHPVersion, p.ID}, gargs...)...)
	if err != nil {
		return nil, err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return nil, &apiError{Status: http.StatusPreconditionFailed, Code: "version_conflict"}
	}
	users, err := store.Select[store.User](r.Context(), s.Store.R, userSelect+` WHERE u.package_id=? AND u.system_user=1`, p.ID)
	if err != nil {
		return nil, err
	}
	warnings := s.applyQuotas(r, users, np)
	s.audit(r, "package.update", p.Name, "", true)
	w.Header().Set("ETag", fmt.Sprintf(`"%d"`, p.Version+1))
	return map[string]any{"ok": true, "warnings": warnings, "version": p.Version + 1}, nil
}

// applyQuotas re-applies a package's limits to its accounts with ONE agent
// call (one systemd daemon-reload) instead of one call per account
// (R2-PERF-9). An older agent without the batch method gets the per-account
// calls as before.
func (s *Server) applyQuotas(r *http.Request, users []store.User, p store.Package) []Warning {
	warnings := []Warning{}
	if len(users) == 0 {
		return warnings
	}
	q := func(u string) rpc.AccountQuota {
		return rpc.AccountQuota{User: u, QuotaMB: agentLimit(p.DiskMB), CPUQuota: int(agentLimit(p.CPUPercent)),
			MemoryMB: agentLimit(p.MemoryMB), MaxTasks: int(agentLimit(p.MaxTasks))}
	}
	batch := rpc.AccountQuotaBatch{}
	for _, u := range users {
		batch.Items = append(batch.Items, q(u.Username))
	}
	var res rpc.AccountQuotaBatchResult
	err := s.agentCall(r, rpc.MAccountQuotaBatch, batch, &res)
	if agentCode(err) == "unknown_method" {
		for _, u := range users {
			if err := s.agentCall(r, rpc.MAccountQuota, q(u.Username), nil); err != nil {
				warnings = append(warnings, warn(WarnQuotaUpdateFailed, "quota", u.Username+": "+agentCode(err)))
			}
		}
		return warnings
	}
	if err != nil {
		return append(warnings, warn(WarnQuotaUpdateFailed, "quota", agentCode(err)))
	}
	names := make([]string, 0, len(res.Failed))
	for u := range res.Failed {
		names = append(names, u)
	}
	sort.Strings(names)
	for _, u := range names {
		warnings = append(warnings, warn(WarnQuotaUpdateFailed, "quota", u+": "+res.Failed[u]))
	}
	return warnings
}

func (s *Server) deletePackage(w http.ResponseWriter, r *http.Request) (any, error) {
	p, err := s.ownPackage(r)
	if err != nil {
		return nil, err
	}
	if s.count(`SELECT COUNT(*) FROM users WHERE package_id=?`, p.ID) > 0 {
		return nil, conflict("package_in_use")
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM packages WHERE id=?`, p.ID); err != nil {
		return nil, err
	}
	s.audit(r, "package.delete", p.Name, "", true)
	return nil, nil
}

// ---- accounts ------------------------------------------------------------------

// pageParams reads ?limit=&offset= (CODE-23). Without limit the full list
// is returned, as before; X-Total-Count always carries the total.
func pageParams(r *http.Request) (limit, offset int) {
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit <= 0 || limit > 1000 {
		limit = -1
	}
	offset, err = strconv.Atoi(r.URL.Query().Get("offset"))
	if err != nil || offset < 0 {
		offset = 0
	}
	return limit, offset
}

// listAccounts pages on the server (R2-PERF-8): ?limit=1..1000&offset=&q=
// (substring of username, primary domain or email) &role=user|reseller
// &status=active|suspended|provisioning|terminating. The body is the same
// JSON array as before; X-Total-Count carries the number of matching rows
// (all of them, not just the page). Without limit every row is returned.
func (s *Server) listAccounts(w http.ResponseWriter, r *http.Request) (any, error) {
	me := userOf(r)
	limit, offset := pageParams(r)
	where, args := ` WHERE u.role<>'admin'`, []any{}
	if me.Role == "reseller" {
		where, args = ` WHERE u.owner_id=?`, []any{me.ID}
	}
	qv := r.URL.Query()
	if q := strings.TrimSpace(qv.Get("q")); q != "" {
		if len(q) > 253 {
			return nil, tooLong("q", 253)
		}
		where += ` AND (u.username LIKE ? ESCAPE '\' OR u.primary_domain LIKE ? ESCAPE '\' OR u.email LIKE ? ESCAPE '\')`
		like := "%" + likeEscape(strings.ToLower(q)) + "%"
		args = append(args, like, like, like)
	}
	if role := qv.Get("role"); role == "user" || role == "reseller" {
		where += ` AND u.role=?`
		args = append(args, role)
	}
	if st := qv.Get("status"); st == "active" || st == "suspended" || st == "provisioning" || st == "terminating" {
		where += ` AND u.status=?`
		args = append(args, st)
	}
	var total int64
	if err := s.Store.R.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM users u`+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	w.Header().Set("X-Total-Count", strconv.FormatInt(total, 10))
	w.Header().Set("Access-Control-Expose-Headers", "X-Total-Count")
	return store.Select[store.User](r.Context(), s.Store.R, userSelect+where+` ORDER BY u.username LIMIT ? OFFSET ?`, append(args, limit, offset)...)
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) (any, error) {
	var in CreateAccountReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute) // finish even if the browser goes away
	defer cancel()
	u, warnings, err := s.CreateAccount(ctx, userOf(r), in)
	if err != nil {
		s.audit(r, "account.create", in.Username, err.Error(), false)
		return nil, err
	}
	s.audit(r, "account.create", u.Username, u.PrimaryDomain, true)
	s.billingEvent(r, "account.created", u.ID, u.Username, map[string]any{"domain": u.PrimaryDomain})
	if warnings == nil {
		warnings = []Warning{}
	}
	return map[string]any{"account": u, "warnings": warnings}, nil
}

func (s *Server) suspendAccount(w http.ResponseWriter, r *http.Request) (any, error) {
	var in SuspendReq
	if r.ContentLength != 0 {
		if err := decode(r, &in); err != nil {
			return nil, err
		}
	}
	if len(in.Reason) > 500 {
		return nil, tooLong("reason", 500) // never cut (R2-UX-10 / UX-40)
	}
	if strings.ContainsAny(in.Reason, "\x00\r\n") {
		return nil, badField("invalid_reason", "reason")
	}
	u, err := s.manageableAccount(r)
	if err != nil {
		return nil, err
	}
	if err := checkVersion(w, r, in.Version, u.Version); err != nil {
		return nil, err
	}
	if err := s.SetSuspended(r.Context(), &u, true, strings.TrimSpace(in.Reason)); err != nil {
		return nil, err
	}
	s.audit(r, "account.suspend", u.Username, in.Reason, true)
	s.billingEvent(r, "account.suspended", u.ID, u.Username, map[string]any{"reason": in.Reason})
	return nil, nil
}

func (s *Server) unsuspendAccount(w http.ResponseWriter, r *http.Request) (any, error) {
	u, err := s.manageableAccount(r)
	if err != nil {
		return nil, err
	}
	if err := checkVersion(w, r, nil, u.Version); err != nil {
		return nil, err
	}
	if err := s.SetSuspended(r.Context(), &u, false, ""); err != nil {
		return nil, err
	}
	s.audit(r, "account.unsuspend", u.Username, "", true)
	s.billingEvent(r, "account.unsuspended", u.ID, u.Username, map[string]any{})
	return nil, nil
}

func (s *Server) changeAccountPackage(w http.ResponseWriter, r *http.Request) (any, error) {
	var in ChangePackageReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u, err := s.manageableAccount(r)
	if err != nil {
		return nil, err
	}
	if err := checkVersion(w, r, in.Version, u.Version); err != nil {
		return nil, err
	}
	p, err := store.One[store.Package](r.Context(), s.Store.DB, `SELECT *, 0 AS accounts FROM packages WHERE id=?`, in.PackageID)
	if err != nil {
		return nil, badField("invalid_package", "package_id")
	}
	me := userOf(r)
	if me.Role == "reseller" && (p.OwnerID == nil || *p.OwnerID != me.ID) {
		return nil, &apiError{Status: 403, Code: "package_not_owned", Field: "package_id"} // R2-UX-03
	}
	if err := s.checkResellerLimits(r.Context(), me, p, u.ID); err != nil { // v0.4 adminx.go (Edit Reseller)
		return nil, err
	}
	// reseller ceilings and disk pool, checked and applied atomically (CODE-9)
	if err := s.Store.Tx(r.Context(), func(tx *sql.Tx) error {
		if me.Role == "reseller" {
			if err := checkResellerAllocation(r.Context(), tx, me, p, u.ID, false); err != nil {
				return err
			}
		}
		guard, gargs := versionGuard(r, in.Version)
		res, err := tx.ExecContext(r.Context(), `UPDATE users SET package_id=?, version=version+1 WHERE id=?`+guard, append([]any{p.ID, u.ID}, gargs...)...)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err == nil && n == 0 {
			return &apiError{Status: http.StatusPreconditionFailed, Code: "version_conflict"}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if u.SystemUser {
		if err := s.agentCall(r, rpc.MAccountQuota, rpc.AccountQuota{User: u.Username, QuotaMB: agentLimit(p.DiskMB), CPUQuota: int(agentLimit(p.CPUPercent)), MemoryMB: agentLimit(p.MemoryMB), MaxTasks: int(agentLimit(p.MaxTasks))}, nil); err != nil {
			uctx, cancel := undoCtx(r.Context())
			defer cancel()
			if _, uerr := s.Store.DB.ExecContext(uctx, `UPDATE users SET package_id=? WHERE id=?`, u.PackageID, u.ID); uerr != nil {
				s.Log.Error("package change undo", "err", uerr)
			}
			return nil, err
		}
	}
	s.audit(r, "account.package", u.Username, p.Name, true)
	s.billingEvent(r, "account.package_changed", u.ID, u.Username, map[string]any{"package": p.Name})
	return nil, nil
}

func (s *Server) setAccountPassword(w http.ResponseWriter, r *http.Request) (any, error) {
	var in PasswordReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u, err := s.manageableAccount(r)
	if err != nil {
		return nil, err
	}
	if err := passwordErr(in.Password, "password"); err != nil {
		return nil, err
	}
	h, err := s.hashPassword(r.Context(), in.Password)
	if err != nil {
		return nil, err
	}
	if u.SystemUser {
		if err := s.agentCall(r, rpc.MAccountPassword, rpc.AccountPassword{User: u.Username, Password: in.Password}, nil); err != nil {
			return nil, err
		}
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `UPDATE users SET password_hash=?, version=version+1 WHERE id=?`, h, u.ID); err != nil {
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM sessions WHERE user_id=?`, u.ID); err != nil {
		return nil, err
	}
	s.audit(r, "account.password", u.Username, "", true)
	s.billingEvent(r, "account.password_changed", u.ID, u.Username, map[string]any{})
	return nil, nil
}

func (s *Server) loginAs(w http.ResponseWriter, r *http.Request) (any, error) {
	u, err := s.manageableAccount(r)
	if err != nil {
		return nil, err
	}
	if !u.SystemUser {
		return nil, bad("no_hosting_account")
	}
	tok, err := CreateOnceToken(s.Store, u.ID, RealmUser, userOf(r).ID, 60*time.Second)
	if err != nil {
		return nil, err
	}
	// built from the configured hostname, never from the request Host header (CODE-28)
	host := s.Cfg.Hostname
	if host == "" {
		host = strings.Split(r.Host, ":")[0]
		if validate.Domain(host) != nil && net.ParseIP(host) == nil {
			return nil, bad("hostname_not_configured")
		}
	}
	s.audit(r, "account.login_as", u.Username, "", true)
	return map[string]string{"url": fmt.Sprintf("%s://%s:%d/login/once/%s", map[bool]string{true: "http", false: "https"}[s.Cfg.PlainHTTP], host, s.Cfg.UserPort, tok)}, nil
}

func (s *Server) terminateAccount(w http.ResponseWriter, r *http.Request) (any, error) {
	u, err := s.visibleAccount(r)
	if err != nil {
		return nil, err
	}
	if u.Role == "reseller" && s.count(`SELECT COUNT(*) FROM users WHERE owner_id=?`, u.ID) > 0 {
		return nil, conflict("reseller_has_accounts")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := s.TerminateAccount(ctx, &u); err != nil {
		s.audit(r, "account.terminate", u.Username, err.Error(), false)
		return nil, err
	}
	if u.Role == "reseller" {
		// packages owned by a removed reseller would otherwise have a dangling owner
		if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM packages WHERE owner_id=? AND id NOT IN (SELECT package_id FROM users WHERE package_id IS NOT NULL)`, u.ID); err != nil {
			s.Log.Warn("reseller package cleanup", "err", err)
		}
	}
	s.audit(r, "account.terminate", u.Username, u.PrimaryDomain, true)
	s.billingEvent(r, "account.terminated", u.ID, u.Username, map[string]any{"domain": u.PrimaryDomain})
	return nil, nil
}

// ---- server -----------------------------------------------------------------------

func (s *Server) listServices(w http.ResponseWriter, r *http.Request) (any, error) {
	var out rpc.ServiceStatus
	if err := s.agentCall(r, rpc.MServiceStatus, rpc.ServiceStatusReq{}, &out); err != nil {
		return nil, err
	}
	return out.Services, nil
}

func (s *Server) serviceAction(w http.ResponseWriter, r *http.Request) (any, error) {
	unit, action := chi.URLParam(r, "unit"), chi.URLParam(r, "action")
	if err := validate.Unit(unit); err != nil {
		return nil, bad("invalid_unit")
	}
	err := s.agentCall(r, rpc.MServiceAction, rpc.ServiceAction{Unit: unit, Action: action}, nil)
	s.audit(r, "service."+action, unit, "", err == nil)
	return nil, err
}

func (s *Server) adminPHP(w http.ResponseWriter, r *http.Request) (any, error) {
	var v rpc.PHPVersionsResult
	if err := s.agentCall(r, rpc.MPHPVersions, rpc.Empty{}, &v); err != nil {
		return nil, err
	}
	usage, err := s.phpUsage(r.Context())
	if err != nil {
		return nil, err
	}
	return map[string]any{"versions": v.Versions, "usage": usage, "default": s.Store.Get("default_php", "8.3")}, nil
}

func (s *Server) adminPHPAction(w http.ResponseWriter, r *http.Request) (any, error) {
	v, action := chi.URLParam(r, "version"), chi.URLParam(r, "action")
	if err := validate.PHPVersion(v); err != nil {
		return nil, bad("invalid_php_version")
	}
	switch action {
	case "install":
	case "remove":
		// in use = effective version of any site, or set on an account or package (CODE-21)
		usage, err := s.phpUsage(r.Context())
		if err != nil {
			return nil, err
		}
		if usage[v] > 0 || s.Store.Get("default_php", "8.3") == v ||
			s.count(`SELECT COUNT(*) FROM users WHERE php_version=?`, v) > 0 ||
			s.count(`SELECT COUNT(*) FROM packages WHERE php_version=?`, v) > 0 {
			return nil, conflict("php_version_in_use")
		}
	default:
		return nil, bad("invalid_action")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	err := s.Agent.Call(ctx, rpc.MPHPInstall, rpc.PHPInstall{Version: v, Remove: action == "remove"}, nil)
	s.audit(r, "php."+action, v, "", err == nil)
	return nil, err
}

// phpUsage counts sites per effective PHP version.
func (s *Server) phpUsage(ctx context.Context) (map[string]int64, error) {
	usage := map[string]int64{}
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT COALESCE(NULLIF(d.php_version,''), NULLIF(u.php_version,''), ?) AS v, COUNT(*) FROM domains d JOIN users u ON u.id=d.user_id WHERE d.kind<>'alias' GROUP BY v`, s.Store.Get("default_php", "8.3"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ver string
		var n int64
		if err := rows.Scan(&ver, &n); err != nil {
			return nil, err
		}
		usage[ver] = n
	}
	return usage, rows.Err()
}

func (s *Server) serverInfo(w http.ResponseWriter, r *http.Request) (any, error) {
	si, err := s.sysInfo(r)
	if err != nil {
		return nil, err
	}
	var ping rpc.PingResult
	if err := s.agentCall(r, rpc.MPing, rpc.Empty{}, &ping); err != nil {
		return nil, err
	}
	return map[string]any{"sys": si, "agent": ping, "panel_version": s.Version}, nil
}

// auditLog searches the audit log (R2-PERF-2): no WHERE at all without q,
// the trigram FTS index for q of 3+ characters (same case-insensitive
// substring semantics as before) and LIKE only for 1-2 characters. Runs on
// the read pool; the total (X-Total-Count) is cached for 10 s per query.
func (s *Server) auditLog(w http.ResponseWriter, r *http.Request) (any, error) {
	limit, offset := pageParams(r)
	if limit < 0 {
		limit = 200
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > 200 {
		return nil, tooLong("q", 200)
	}
	where, args := "", []any{}
	switch {
	case q == "":
	case len([]rune(q)) >= 3:
		where = ` WHERE id IN (SELECT rowid FROM audit_fts WHERE audit_fts MATCH ?)`
		args = append(args, `"`+strings.ReplaceAll(q, `"`, `""`)+`"`)
	default:
		like := "%" + likeEscape(q) + "%"
		where = ` WHERE actor LIKE ? ESCAPE '\' OR action LIKE ? ESCAPE '\' OR target LIKE ? ESCAPE '\'`
		args = append(args, like, like, like)
	}
	total := s.auditCount.get(q, s.Now(), func() int64 {
		var n int64
		if err := s.Store.R.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM audit_log`+where, args...).Scan(&n); err != nil {
			s.Log.Warn("audit count", "err", err)
		}
		return n
	})
	w.Header().Set("X-Total-Count", strconv.FormatInt(total, 10))
	return store.Select[store.Audit](r.Context(), s.Store.R, `SELECT * FROM audit_log`+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
}

var settingKeys = []string{"default_lang", "default_php", "nameservers", "server_ip", "acme_email", "contact_email"}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) (any, error) {
	out := map[string]string{}
	for _, k := range settingKeys {
		out[k] = s.Store.Get(k, "")
	}
	if out["default_lang"] == "" {
		out["default_lang"] = "en"
	}
	if out["default_php"] == "" {
		out["default_php"] = "8.3"
	}
	if out["server_ip"] == "" {
		out["server_ip"] = s.serverIP()
	}
	if out["nameservers"] == "" {
		out["nameservers_suggested"] = strings.Join(s.nameservers(), " ")
	}
	return out, nil
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) (any, error) {
	var in SettingsReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	set := func(k string, v *string, check func(string) error) error {
		if v == nil {
			return nil
		}
		val := strings.TrimSpace(*v)
		if val != "" && check != nil {
			if err := check(val); err != nil {
				return bad("invalid_" + k)
			}
		}
		return s.Store.Set(k, val)
	}
	checkNS := func(v string) error {
		for _, n := range strings.Fields(v) {
			if err := validate.Domain(n); err != nil {
				return err
			}
		}
		return nil
	}
	checkIP := func(v string) error { return validate.RecordContent("A", v) }
	for _, e := range []error{
		set("default_lang", in.DefaultLang, validate.Lang),
		set("default_php", in.DefaultPHP, validate.PHPVersion),
		set("nameservers", in.Nameservers, checkNS),
		set("server_ip", in.ServerIP, checkIP),
		set("acme_email", in.ACMEEmail, validate.Email),
		set("contact_email", in.ContactEmail, validate.Email),
	} {
		if e != nil {
			return nil, e
		}
	}
	s.audit(r, "settings.update", "", "", true)
	warnings := []Warning{}
	if in.ContactEmail != nil && *in.ContactEmail != "" && s.Store.Get("feature_mail", "1") == "1" {
		// root's mail (cron, fail2ban) follows the contact email (handoff-installer H-10)
		if err := s.agentCall(r, rpc.MMailRootAlias, rpc.RootAlias{Email: *in.ContactEmail}, nil); err != nil {
			warnings = append(warnings, warn(WarnRootAliasUpdateFailed, "mail", agentCode(err)))
		}
	}
	if in.ServerIP != nil || in.Nameservers != nil || in.DefaultPHP != nil {
		// CODE-21 (deferred): existing zones/vhosts are not re-rendered automatically
		warnings = append(warnings, warn(WarnExistingNotUpdated, "settings", ""))
	}
	return map[string]any{"ok": true, "warnings": warnings}, nil
}
