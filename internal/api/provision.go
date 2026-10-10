package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/distro"
	"github.com/cumabozkurt/bpanel/internal/store"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

func (s *Server) agentCall(r *http.Request, method string, params any, out any) error {
	ctx := context.Background()
	if r != nil {
		ctx = r.Context()
	}
	if err := s.preBackupCall(ctx, method, params); err != nil { // v0.4 backup_secrets.go
		return err
	}
	err := s.Agent.Call(ctx, method, params, out)
	s.obsxAgent(method, err) // v0.4 obsx.go metrics
	if err == nil && method == rpc.MDBUserPassword {
		s.dbxAfterDBChange(r, method) // v0.4 dbx.go: re-copy the hash to remote mirrors
	}
	return err
}

// undoCtx gives a compensation its own bounded context that survives the
// cancellation of the request that triggered it (CODE-14).
func undoCtx(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), 2*time.Minute)
}

func (s *Server) nameservers() []string {
	ns := strings.Fields(s.Store.Get("nameservers", ""))
	if len(ns) == 0 {
		h := s.Cfg.Hostname
		if h == "" {
			h = "server.example.com"
		}
		parent := h
		if i := strings.Index(h, "."); i > 0 && strings.Count(h, ".") >= 2 {
			parent = h[i+1:]
		}
		ns = []string{"ns1." + parent, "ns2." + parent}
	}
	return ns
}

func (s *Server) serverIP() string {
	if ip := s.Store.Get("server_ip", ""); ip != "" {
		return ip
	}
	if s.Cfg.ServerIP != "" {
		return s.Cfg.ServerIP
	}
	return "127.0.0.1"
}

// zoneTemplate returns the default records for a new zone (main/addon/alias domains).
func (s *Server) zoneTemplate(domain, dkim string) []rpc.DNSRecord {
	ip := s.serverIP()
	recs := []rpc.DNSRecord{}
	for _, ns := range s.nameservers() {
		recs = append(recs, rpc.DNSRecord{Name: domain, Type: "NS", TTL: 86400, Content: ns})
	}
	recs = append(recs,
		rpc.DNSRecord{Name: domain, Type: "A", TTL: 3600, Content: ip},
		rpc.DNSRecord{Name: "www." + domain, Type: "CNAME", TTL: 3600, Content: domain},
		rpc.DNSRecord{Name: "mail." + domain, Type: "A", TTL: 3600, Content: ip},
		rpc.DNSRecord{Name: "ftp." + domain, Type: "A", TTL: 3600, Content: ip},
		rpc.DNSRecord{Name: domain, Type: "MX", TTL: 3600, Content: "10 mail." + domain},
		rpc.DNSRecord{Name: domain, Type: "TXT", TTL: 3600, Content: "v=spf1 +a +mx +ip4:" + ip + " ~all"},
		rpc.DNSRecord{Name: "_dmarc." + domain, Type: "TXT", TTL: 3600, Content: "v=DMARC1; p=none; rua=mailto:postmaster@" + domain},
	)
	if dkim != "" {
		recs = append(recs, rpc.DNSRecord{Name: "bpanel._domainkey." + domain, Type: "TXT", TTL: 3600, Content: dkim})
	}
	return recs
}

// unlimitedPackage is what an account without a package may use (G1: the
// zero Package would now mean "none" for every count limit).
func unlimitedPackage() store.Package {
	return store.Package{DiskMB: Unlimited, BandwidthMB: Unlimited, MaxDomains: Unlimited, MaxSubdomains: Unlimited,
		MaxAliases: Unlimited, MaxEmail: Unlimited, MaxDB: Unlimited, MaxFTP: Unlimited, MailQuotaMB: Unlimited,
		CPUPercent: Unlimited, MemoryMB: Unlimited, MaxTasks: Unlimited}
}

func (s *Server) packageOf(ctx context.Context, u *store.User) store.Package {
	p := unlimitedPackage()
	if u.PackageID != nil {
		got, err := store.One[store.Package](ctx, s.Store.R, `SELECT * FROM packages WHERE id=?`, *u.PackageID)
		switch {
		case err == nil:
			p = got
		case !errors.Is(err, sql.ErrNoRows):
			s.Log.Warn("package lookup", "user", u.Username, "err", err)
		}
	}
	s.applyAccountOverrides(ctx, u, &p) // v0.4 adminx.go (Modify Account overrides)
	return p
}

func (s *Server) domainsOf(ctx context.Context, uid int64) ([]store.Domain, error) {
	return store.Select[store.Domain](ctx, s.Store.DB, `SELECT d.*, COALESCE(p.name,'') AS parent_name FROM domains d
		LEFT JOIN domains p ON p.id=d.parent_id WHERE d.user_id=? ORDER BY CASE d.kind WHEN 'main' THEN 0 WHEN 'addon' THEN 1 WHEN 'sub' THEN 2 ELSE 3 END, d.name`, uid)
}

func (s *Server) phpFor(u *store.User, d store.Domain) string {
	if d.PHPVersion != "" {
		return d.PHPVersion
	}
	if u.PHPVersion != "" {
		return u.PHPVersion
	}
	return s.Store.Get("default_php", "8.3")
}

// stepFunc records a completed (or possibly completed) provisioning step.
type stepFunc func(step, arg string, call func() error) error

func noRecord(_, _ string, call func() error) error { return call() }

// applyWeb regenerates PHP pools and vhosts for every site of an account.
func (s *Server) applyWeb(ctx context.Context, u *store.User) error {
	return s.applyWebRec(ctx, u, noRecord)
}

func (s *Server) applyWebRec(ctx context.Context, u *store.User, rec stepFunc) error {
	doms, err := s.domainsOf(ctx, u.ID)
	if err != nil {
		return err
	}
	pkg := s.packageOf(ctx, u)
	versions := map[string]bool{}
	aliases := map[int64][]string{}
	for _, d := range doms {
		if d.Kind == "alias" && d.ParentID != nil {
			aliases[*d.ParentID] = append(aliases[*d.ParentID], d.Name, "www."+d.Name)
		}
	}
	for _, d := range doms {
		if d.Kind != "alias" {
			versions[s.phpFor(u, d)] = true
		}
	}
	mem := "256M"
	maxChildren := 10
	if pkg.MemoryMB > 0 && pkg.MemoryMB < 512 {
		mem = "128M"
		maxChildren = 5
	}
	for v := range versions {
		if err := rec("pool", v, func() error {
			_, _ = mem, maxChildren // v0.4 usagex: defaults now live in phpPoolSpec (+ saved php_ini settings)
			return s.Agent.Call(ctx, rpc.MPHPPoolApply, s.phpPoolSpec(ctx, u, v, pkg), nil)
		}); err != nil {
			return err
		}
	}
	for _, d := range doms {
		if d.Kind == "alias" {
			continue
		}
		al := aliases[d.ID]
		if d.Kind != "sub" {
			al = append([]string{"www." + d.Name}, al...)
		}
		v := rpc.Vhost{User: u.Username, Domain: d.Name, Aliases: al, DocRoot: d.DocRoot, PHPVersion: s.phpFor(u, d),
			Mode: u.WebMode, SSL: d.SSLStatus == "active", Suspended: u.Status == "suspended", Redirect: d.Redirect}
		if err := rec("vhost", d.Name, func() error { return s.Agent.Call(ctx, rpc.MVhostApply, v, nil) }); err != nil {
			return err
		}
	}
	// Drop pools for versions no longer used, so php-fpm never keeps a pool
	// for a version the account left (SYS-9).
	for _, v := range distro.KnownPHP {
		if !versions[v] {
			if err := s.Agent.Call(ctx, rpc.MPHPPoolRemove, rpc.PHPPoolRef{User: u.Username, Version: v}, nil); err != nil {
				s.Log.Warn("php pool cleanup", "user", u.Username, "version", v, "err", err)
			}
		}
	}
	return nil
}

type CreateAccountReq struct {
	Username  string `json:"username"`
	Domain    string `json:"domain"`
	Password  string `json:"password"`
	Email     string `json:"email"`
	PackageID int64  `json:"package_id"`
	Role      string `json:"role,omitempty"` // user (default) or reseller
	// reseller only (G1): -1/null/absent = unlimited, 0 = none
	MaxAccounts Limit `json:"max_accounts,omitempty"`
	// reseller only: total disk (MB) it may allocate; -1/null/absent = no pool limit; 0 is invalid
	ResellerDiskMB Limit  `json:"reseller_disk_mb,omitempty"`
	Lang           string `json:"lang,omitempty"`
	WebMode        string `json:"web_mode,omitempty"`
}

// ---- provisioning steps (saga) ----------------------------------------------

// definitive reports whether an agent error proves the action did not happen
// (validation/refusal, or the agent was never reached). Timeouts and broken
// connections leave the outcome unknown.
func definitive(err error) bool {
	var re *rpc.Error
	if !errors.As(err, &re) {
		return true
	}
	switch re.Code {
	case "agent_io", "agent_timeout", "agent_response_too_large":
		return false
	}
	return true
}

// recorder returns a stepFunc that writes each step to provision_steps
// before running it (intent), and drops the record when the agent
// definitively did not perform it. A crash between the agent call and the
// bookkeeping therefore never leaks an object: reconciliation compensates
// every recorded step, and every compensation is idempotent.
func (s *Server) recorder(ctx context.Context, userID int64) stepFunc {
	return func(step, arg string, call func() error) error {
		var seq int64
		if err := s.Store.DB.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq),0)+1 FROM provision_steps WHERE user_id=?`, userID).Scan(&seq); err != nil {
			return err
		}
		if _, err := s.Store.DB.ExecContext(ctx, `INSERT INTO provision_steps(user_id,seq,step,arg,done_at) VALUES(?,?,?,?,?)`,
			userID, seq, step, arg, s.Now().Unix()); err != nil {
			return err
		}
		err := call()
		if err != nil && definitive(err) {
			if _, derr := s.Store.DB.ExecContext(context.WithoutCancel(ctx), `DELETE FROM provision_steps WHERE user_id=? AND seq=?`, userID, seq); derr != nil {
				s.Log.Warn("provision step bookkeeping", "err", derr)
			}
		}
		return err
	}
}

type provStep struct {
	Seq  int64  `db:"seq"`
	Step string `db:"step"`
	Arg  string `db:"arg"`
}

// compensate undoes the recorded steps of an account in reverse order, each
// with its own bounded context, and returns the failures.
func (s *Server) compensate(parent context.Context, userID int64, username string) []string {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 10*time.Minute)
	defer cancel()
	steps, err := store.Select[provStep](ctx, s.Store.DB, `SELECT seq, step, arg FROM provision_steps WHERE user_id=? ORDER BY seq DESC`, userID)
	if err != nil {
		return []string{err.Error()}
	}
	var errs []string
	for _, st := range steps {
		sctx, scancel := undoCtx(ctx)
		var err error
		switch st.Step {
		case "zone":
			err = s.Agent.Call(sctx, rpc.MDNSZoneDelete, rpc.ZoneRef{Owner: username, Zone: st.Arg}, nil)
		case "mail":
			err = s.Agent.Call(sctx, rpc.MMailDomainOff, rpc.MailDomain{User: username, Domain: st.Arg}, nil)
		case "vhost":
			err = s.Agent.Call(sctx, rpc.MVhostRemove, rpc.DomainRef{Owner: username, Domain: st.Arg}, nil)
		case "pool":
			err = s.Agent.Call(sctx, rpc.MPHPPoolRemove, rpc.PHPPoolRef{User: username, Version: st.Arg}, nil)
		case "account":
			// the agent refuses accounts it did not create (ownership marker)
			err = s.Agent.Call(sctx, rpc.MAccountTerminate, rpc.AccountRef{User: username}, nil)
		}
		scancel()
		if err != nil {
			errs = append(errs, st.Step+" "+st.Arg+": "+err.Error())
			continue
		}
		if _, err := s.Store.DB.ExecContext(ctx, `DELETE FROM provision_steps WHERE user_id=? AND seq=?`, userID, st.Seq); err != nil {
			errs = append(errs, err.Error())
		}
	}
	return errs
}

// rollbackAccount compensates a failed CreateAccount and removes its rows
// once every step is undone.
func (s *Server) rollbackAccount(ctx context.Context, userID int64, username string) {
	errs := s.compensate(ctx, userID, username)
	if len(errs) > 0 {
		s.Log.Error("account rollback incomplete; will retry", "user", username, "errors", strings.Join(errs, "; "))
		return // the row stays in 'provisioning'; reconcileProvisioning retries
	}
	dctx, cancel := undoCtx(ctx)
	defer cancel()
	if _, err := s.Store.DB.ExecContext(dctx, `DELETE FROM users WHERE id=?`, userID); err != nil {
		s.Log.Error("account rollback: delete row", "user", username, "err", err)
	}
}

// reconcileStartup rolls back every account left in 'provisioning' by an
// earlier process (killed mid-create) and resumes interrupted terminations
// right at start instead of after the 30-minute grace period: re-creating
// the same account used to fail with 409 for half an hour (R2-PERF-5).
// Rows created by this process are never touched.
func (s *Server) reconcileStartup(ctx context.Context) {
	s.reconcileBefore(ctx, s.startedAt.Unix())
}

// reconcileProvisioning finishes work interrupted by a crash: accounts stuck
// in 'provisioning' are rolled back, accounts in 'terminating' are terminated.
func (s *Server) reconcileProvisioning(ctx context.Context, olderThan time.Duration) {
	s.reconcileBefore(ctx, s.Now().Add(-olderThan).Unix())
}

func (s *Server) reconcileBefore(ctx context.Context, cut int64) {
	users, err := store.Select[store.User](ctx, s.Store.DB, userSelect+` WHERE (u.status='provisioning' AND u.created_at<?) OR u.status='terminating'`, cut)
	if err != nil {
		s.Log.Warn("reconcile", "err", err)
		return
	}
	for _, u := range users {
		if ctx.Err() != nil {
			return
		}
		if u.Status == "provisioning" {
			s.Log.Warn("rolling back interrupted account creation", "user", u.Username)
			s.rollbackAccount(ctx, u.ID, u.Username)
			continue
		}
		s.Log.Warn("resuming interrupted account termination", "user", u.Username)
		if err := s.TerminateAccount(ctx, &u); err != nil {
			s.Log.Warn("terminate retry", "user", u.Username, "err", err)
		}
	}
}

// ---- domain ownership --------------------------------------------------------

// reservedNames are the server's own hostnames (panel hostname, nameservers).
func (s *Server) reservedNames() []string {
	reserved := []string{}
	if h := strings.ToLower(strings.TrimSuffix(s.Cfg.Hostname, ".")); h != "" {
		reserved = append(reserved, h)
	}
	for _, ns := range s.nameservers() {
		reserved = append(reserved, strings.ToLower(strings.TrimSuffix(ns, ".")))
	}
	return reserved
}

func isSubdomainOf(name, parent string) bool {
	return parent != "" && strings.HasSuffix(name, "."+parent)
}

// checkDomainClaim refuses names a tenant must not own (SEC-6 / CODE-4):
//   - the panel hostname, the nameserver hosts and anything below them;
//   - a parent of those names (that zone would be authoritative for them),
//     unless an administrator creates it (the operator's own domain);
//   - any name below, or above, a domain owned by another account.
//
// reserved comes from reservedNames(), computed before any transaction
// (the store has a single connection: no s.Store.DB use inside a Tx).
func (s *Server) checkDomainClaim(ctx context.Context, q store.Querier, reserved []string, ownerID int64, name string, isAdmin bool) error {
	for _, r := range reserved {
		if name == r || isSubdomainOf(name, r) {
			return &apiError{Status: 403, Code: "domain_reserved", Message: "this name belongs to the server itself"}
		}
		if isSubdomainOf(r, name) && !isAdmin {
			return &apiError{Status: 403, Code: "domain_reserved", Message: "this domain contains the server's own hostnames"}
		}
	}
	var parents []any
	labels := strings.Split(name, ".")
	for i := 1; i < len(labels)-1; i++ {
		parents = append(parents, strings.Join(labels[i:], "."))
	}
	query := `SELECT COUNT(*) FROM domains WHERE user_id<>? AND (name LIKE ?`
	args := []any{ownerID, "%." + name}
	if len(parents) > 0 {
		query += ` OR name IN (?` + strings.Repeat(",?", len(parents)-1) + `)`
		args = append(args, parents...)
	}
	query += `)`
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	var n int64
	if rows.Next() {
		if err := rows.Scan(&n); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if n > 0 {
		return conflict("domain_owned_by_another_account")
	}
	return nil
}

// ---- reseller limits (CODE-9) ------------------------------------------------

// resellerPackageOK checks that a package may be used or defined by a
// reseller: no unlimited (-1) resource limits, and disk within the pool.
// The offending JSON key is in "field" (and, as before, "message").
func resellerPackageOK(p store.Package, reseller *store.User) error {
	limits := []struct {
		k string
		v int64
	}{{"disk_mb", p.DiskMB}, {"max_domains", p.MaxDomains}, {"max_subdomains", p.MaxSubdomains},
		{"max_aliases", p.MaxAliases}, {"max_email", p.MaxEmail}, {"max_db", p.MaxDB}, {"max_ftp", p.MaxFTP},
		{"cpu_percent", p.CPUPercent}, {"memory_mb", p.MemoryMB}, {"max_tasks", p.MaxTasks}}
	for _, l := range limits {
		if !limited(l.v) {
			return &apiError{Status: 403, Code: "reseller_unlimited_not_allowed", Message: l.k, Field: l.k}
		}
	}
	if limited(reseller.ResellerDiskMB) && p.DiskMB > reseller.ResellerDiskMB {
		return &apiError{Status: 409, Code: "limit_reached", Message: "reseller_disk", Field: "disk_mb", Max: reseller.ResellerDiskMB}
	}
	return nil
}

// resellerDiskUsed sums the disk allocations of a reseller's accounts.
func resellerDiskUsed(ctx context.Context, tx *sql.Tx, resellerID, excludeUser int64) (int64, error) {
	var n int64
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(p.disk_mb),0) FROM users u JOIN packages p ON p.id=u.package_id
		WHERE u.owner_id=? AND u.id<>?`, resellerID, excludeUser).Scan(&n)
	return n, err
}

// checkResellerAllocation enforces MaxAccounts (when adding) and the disk
// pool inside the caller's transaction.
func checkResellerAllocation(ctx context.Context, tx *sql.Tx, reseller *store.User, pkg store.Package, excludeUser int64, adding bool) error {
	if err := resellerPackageOK(pkg, reseller); err != nil {
		return err
	}
	if adding && limited(reseller.MaxAccounts) {
		var n int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE owner_id=?`, reseller.ID).Scan(&n); err != nil {
			return err
		}
		if n >= reseller.MaxAccounts {
			return limitReached("accounts")
		}
	}
	if limited(reseller.ResellerDiskMB) {
		used, err := resellerDiskUsed(ctx, tx, reseller.ID, excludeUser)
		if err != nil {
			return err
		}
		if used+pkg.DiskMB > reseller.ResellerDiskMB {
			return limitReached("reseller_disk")
		}
	}
	return nil
}

// ---- create ------------------------------------------------------------------

// CreateAccount provisions a full hosting account. owner is the creating
// admin/reseller. It runs as a saga (CODE-5): the user and main domain rows
// are inserted in one transaction with status 'provisioning', every agent
// side effect is recorded in provision_steps, and on any failure the
// recorded steps are compensated in reverse order before the rows go.
func (s *Server) CreateAccount(ctx context.Context, owner *store.User, in CreateAccountReq) (*store.User, []Warning, error) {
	in.Username = strings.ToLower(strings.TrimSpace(in.Username))
	if err := maxLen("username", in.Username, 16); err != nil {
		return nil, nil, err
	}
	if err := validate.Username(in.Username); err != nil {
		return nil, nil, badField(err.Error(), "username")
	}
	dom, err := validate.NormalizeDomain(in.Domain)
	if err != nil {
		return nil, nil, fieldErr(err, "domain", validate.MaxDomain)
	}
	in.Domain = dom
	if err := passwordErr(in.Password, "password"); err != nil {
		return nil, nil, err
	}
	if err := maxLen("email", in.Email, 254); err != nil {
		return nil, nil, err
	}
	if in.Email != "" && validate.Email(in.Email) != nil {
		return nil, nil, badField("invalid_email", "email")
	}
	if in.Lang != "" && validate.Lang(in.Lang) != nil {
		return nil, nil, badField("invalid_language", "lang")
	}
	maxAccounts, resellerDisk := in.MaxAccounts.or(Unlimited), in.ResellerDiskMB.or(Unlimited)
	if err := checkCount("max_accounts", maxAccounts); err != nil {
		return nil, nil, err
	}
	if err := checkSize("reseller_disk_mb", resellerDisk, maxSizeMB); err != nil {
		return nil, nil, err
	}
	role := "user"
	switch in.Role {
	case "reseller":
		if owner.Role != "admin" {
			// R2-UX-02: a clear code instead of the generic forbidden
			return nil, nil, &apiError{Status: 403, Code: "reseller_cannot_create_reseller", Field: "role"}
		}
		role = "reseller"
	case "", "user":
		maxAccounts, resellerDisk = Unlimited, Unlimited
	default:
		return nil, nil, badField("invalid_role", "role")
	}
	explicitMode := in.WebMode
	if in.WebMode == "" {
		in.WebMode = s.Store.Get("web_mode", "nginx-apache")
	}
	if explicitMode == "nginx-apache" && !s.featureOn("apache") {
		// asked for explicitly on a server without Apache (R2-SYS-16)
		return nil, nil, &apiError{Status: 409, Code: "feature_disabled", Field: "apache", Message: "apache is not installed on this server (install profile)"}
	}
	if in.WebMode != "nginx" || !s.featureOn("apache") {
		if !s.featureOn("apache") {
			in.WebMode = "nginx" // minimal profile (SYS-5 / H-2)
		} else {
			in.WebMode = "nginx-apache"
		}
	}
	pkg, err := store.One[store.Package](ctx, s.Store.DB, `SELECT * FROM packages WHERE id=?`, in.PackageID)
	if err != nil {
		return nil, nil, badField("invalid_package", "package_id")
	}
	// R2-UX-03: a reseller assigns only its own packages
	if owner.Role == "reseller" && (pkg.OwnerID == nil || *pkg.OwnerID != owner.ID) {
		return nil, nil, &apiError{Status: 403, Code: "package_not_owned", Field: "package_id"}
	}
	if err := s.checkResellerLimits(ctx, owner, pkg, 0); err != nil { // v0.4 adminx.go (Edit Reseller)
		return nil, nil, err
	}
	// never adopt an existing Linux account (SEC-5): ask the agent first
	var ex rpc.AccountExistsResult
	if err := s.Agent.Call(ctx, rpc.MAccountExists, rpc.AccountRef{User: in.Username}, &ex); err != nil {
		return nil, nil, err
	}
	// An account the panel itself created (ownership marker) whose panel row
	// is gone - the API or agent was killed mid-create - is adopted by the
	// agent instead of blocking the name forever (R2-PERF-15). The username
	// check in the transaction below still refuses a name a panel row uses.
	if ex.Exists && !ex.Managed {
		return nil, nil, conflict("username_taken_on_server")
	}
	hash, err := s.hashPassword(ctx, in.Password)
	if err != nil {
		return nil, nil, err
	}
	now := s.Now().Unix()
	reserved := s.reservedNames()
	var uid int64
	err = s.Store.Tx(ctx, func(tx *sql.Tx) error {
		if owner.Role == "reseller" {
			if err := checkResellerAllocation(ctx, tx, owner, pkg, 0, true); err != nil {
				return err
			}
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE username=?`, in.Username).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return conflict("username_taken")
		}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM domains WHERE name=?`, in.Domain).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return conflict("domain_taken")
		}
		if err := s.checkDomainClaim(ctx, tx, reserved, 0, in.Domain, owner.Role == "admin"); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO users(username,role,owner_id,package_id,email,password_hash,lang,status,system_user,home,primary_domain,php_version,web_mode,max_accounts,reseller_disk_mb,created_at)
			VALUES(?,?,?,?,?,?,?,'provisioning',1,?,?,?,?,?,?,?)`, in.Username, role, owner.ID, pkg.ID, in.Email, hash, in.Lang,
			"/home/"+in.Username, in.Domain, pkg.PHPVersion, in.WebMode, maxAccounts, resellerDisk, now)
		if err != nil {
			return err
		}
		if uid, err = res.LastInsertId(); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO domains(user_id,name,kind,docroot,created_at) VALUES(?,?,'main','public_html',?)`, uid, in.Domain, now)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	rec := s.recorder(ctx, uid)
	fail := func(err error) (*store.User, []Warning, error) {
		s.rollbackAccount(ctx, uid, in.Username)
		return nil, nil, err
	}
	var cr rpc.AccountCreateResult
	if err := rec("account", in.Username, func() error {
		return s.Agent.Call(ctx, rpc.MAccountCreate, rpc.AccountCreate{User: in.Username, Password: in.Password, QuotaMB: agentLimit(pkg.DiskMB),
			CPUQuota: int(agentLimit(pkg.CPUPercent)), MemoryMB: agentLimit(pkg.MemoryMB), MaxTasks: int(agentLimit(pkg.MaxTasks)), ShellSFTP: true, Adopt: ex.Managed}, &cr)
	}); err != nil {
		return fail(err)
	}
	home := cr.Home
	if home == "" {
		home = "/home/" + in.Username
	}
	if _, err := s.Store.DB.ExecContext(ctx, `UPDATE users SET uid=?, home=? WHERE id=?`, cr.UID, home, uid); err != nil {
		return fail(err)
	}
	u, err := s.userByID(ctx, uid)
	if err != nil {
		return fail(err)
	}
	if err := s.applyWebRec(ctx, &u, rec); err != nil {
		return fail(err)
	}
	dkim := ""
	if s.Store.Get("feature_mail", "1") == "1" {
		var md rpc.MailDomainResult
		if err := rec("mail", in.Domain, func() error {
			return s.Agent.Call(ctx, rpc.MMailDomainOn, rpc.MailDomain{User: u.Username, Domain: in.Domain}, &md)
		}); err != nil {
			return fail(err)
		}
		dkim = md.DKIMRecord
	}
	if s.Store.Get("feature_dns", "1") == "1" {
		if err := rec("zone", in.Domain, func() error {
			return s.Agent.Call(ctx, rpc.MDNSZoneCreate, rpc.DNSZone{Owner: u.Username, Zone: in.Domain, Records: s.zoneTemplate(in.Domain, dkim)}, nil)
		}); err != nil {
			return fail(err)
		}
	}
	if err := s.Store.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET status='active' WHERE id=?`, uid); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM provision_steps WHERE user_id=?`, uid)
		return err
	}); err != nil {
		return fail(err)
	}
	u.Status = "active"
	return &u, nil, nil
}

// ---- terminate ---------------------------------------------------------------

// TerminateAccount removes everything an account owns, then the account
// (CODE-16). The row is marked 'terminating' first; every step is idempotent;
// if any step fails the row stays (and the error is returned), so a retry
// (admin or reconcileProvisioning) finishes the job instead of orphaning
// resources.
func (s *Server) TerminateAccount(ctx context.Context, u *store.User) error {
	if _, err := s.Store.DB.ExecContext(ctx, `UPDATE users SET status='terminating' WHERE id=?`, u.ID); err != nil {
		return err
	}
	if _, err := s.Store.DB.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, u.ID); err != nil {
		return err
	}
	doms, err := s.domainsOf(ctx, u.ID)
	if err != nil {
		return err
	}
	dbs, err := store.Select[store.Database](ctx, s.Store.DB, `SELECT *, '' AS users FROM databases WHERE user_id=?`, u.ID)
	if err != nil {
		return err
	}
	dbu, err := store.Select[store.DBUser](ctx, s.Store.DB, `SELECT *, '' AS dbs FROM db_users WHERE user_id=?`, u.ID)
	if err != nil {
		return err
	}
	ftps, err := store.Select[store.FTPAccount](ctx, s.Store.DB, `SELECT * FROM ftp_accounts WHERE user_id=?`, u.ID)
	if err != nil {
		return err
	}
	fwds, err := store.Select[store.Forwarder](ctx, s.Store.DB, `SELECT * FROM forwarders WHERE user_id=?`, u.ID)
	if err != nil {
		return err
	}
	var errs []string
	call := func(method string, params any) {
		if err := s.Agent.Call(ctx, method, params, nil); err != nil {
			if agentCode(err) == "no_such_user" {
				return // the Linux account is already gone (retry after a crash): nothing left to remove
			}
			errs = append(errs, method+": "+err.Error())
		}
	}
	for _, f := range ftps {
		call(rpc.MFTPDelete, rpc.FTPRef{Owner: u.Username, Login: f.Login})
	}
	for _, d := range dbs {
		call(rpc.MDBDrop, rpc.DBRef{Owner: u.Username, Name: d.Name})
	}
	for _, d := range dbu {
		call(rpc.MDBUserDrop, rpc.DBUserRef{Owner: u.Username, User: d.Name})
	}
	// phpMyAdmin SSO user (never in db_users) keeps grants otherwise
	call(rpc.MDBUserDrop, rpc.DBUserRef{Owner: u.Username, User: pmaUserName(u.Username)})
	seen := map[string]bool{}
	for _, f := range fwds {
		if !seen[f.Source] {
			seen[f.Source] = true
			call(rpc.MMailForwardDel, rpc.MailForwardRef{Owner: u.Username, Source: f.Source})
		}
	}
	for _, d := range doms {
		if d.Kind != "alias" {
			call(rpc.MVhostRemove, rpc.DomainRef{Owner: u.Username, Domain: d.Name})
		}
		if d.Kind != "sub" {
			call(rpc.MMailDomainOff, rpc.MailDomain{User: u.Username, Domain: d.Name})
			call(rpc.MDNSZoneDelete, rpc.ZoneRef{Owner: u.Username, Zone: d.Name})
		}
	}
	for _, v := range distro.KnownPHP {
		call(rpc.MPHPPoolRemove, rpc.PHPPoolRef{User: u.Username, Version: v})
	}
	if len(errs) > 0 {
		return fmt.Errorf("terminate %s incomplete (will be retried): %s", u.Username, strings.Join(errs, "; "))
	}
	if u.SystemUser {
		if err := s.Agent.Call(ctx, rpc.MAccountTerminate, rpc.AccountRef{User: u.Username}, nil); err != nil {
			return err
		}
	}
	return s.Store.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM pma_users WHERE owner_id=?`, u.ID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM provision_steps WHERE user_id=?`, u.ID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id=?`, u.ID)
		return err
	})
}

// SetSuspended suspends or unsuspends an account (system login + all vhosts).
func (s *Server) SetSuspended(ctx context.Context, u *store.User, suspend bool, reason string) error {
	if u.SystemUser {
		if err := s.Agent.Call(ctx, rpc.MAccountSuspend, rpc.AccountSuspend{User: u.Username, Suspend: suspend}, nil); err != nil {
			return err
		}
	}
	status := "active"
	if suspend {
		status = "suspended"
	} else {
		reason = ""
	}
	if _, err := s.Store.DB.ExecContext(ctx, `UPDATE users SET status=?, suspend_reason=?, version=version+1 WHERE id=?`, status, reason, u.ID); err != nil {
		// keep OS state and panel state in agreement (CODE-15)
		uctx, cancel := undoCtx(ctx)
		defer cancel()
		if u.SystemUser {
			if rerr := s.Agent.Call(uctx, rpc.MAccountSuspend, rpc.AccountSuspend{User: u.Username, Suspend: !suspend}, nil); rerr != nil {
				s.Log.Error("suspend: could not revert system state", "user", u.Username, "err", rerr)
			}
		}
		return err
	}
	u.Status = status
	if suspend {
		if _, err := s.Store.DB.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, u.ID); err != nil {
			return err
		}
	}
	if !u.SystemUser {
		return nil
	}
	return s.applyWeb(ctx, u)
}
