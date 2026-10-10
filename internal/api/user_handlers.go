package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/auth"
	"github.com/cumabozkurt/bpanel/internal/fileops"
	"github.com/cumabozkurt/bpanel/internal/store"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

type DomainReq struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`                // addon | sub | alias
	ParentID   int64  `json:"parent_id,omitempty"` // sub: parent domain; alias: target site
	DocRoot    string `json:"docroot,omitempty"`
	PHPVersion string `json:"php_version,omitempty"`
}

type DomainUpdateReq struct {
	DocRoot    *string `json:"docroot,omitempty"`
	PHPVersion *string `json:"php_version,omitempty"`
	Redirect   *string `json:"redirect,omitempty"`
}

type RRSetReq struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Records []string `json:"records"`
}

// MailboxReq: quota_mb absent = the package's mail_quota_mb, -1/null =
// unlimited, n > 0 = n MB; 0 is invalid (G1).
type MailboxReq struct {
	Local    string `json:"local"`
	Domain   string `json:"domain"`
	Password string `json:"password"`
	QuotaMB  Limit  `json:"quota_mb"`
}

type PasswordReq struct {
	Password string `json:"password"`
}

// QuotaReq: -1/null = unlimited, n > 0 = n MB; 0 is invalid (G1).
type QuotaReq struct {
	QuotaMB Limit `json:"quota_mb"`
}

type ForwarderReq struct {
	Source      string `json:"source"` // local part, "*" for catch-all
	Domain      string `json:"domain"`
	Destination string `json:"destination"`
}

type NameReq struct {
	Name string `json:"name"`
}

type DBUserReq struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type GrantReq struct {
	DBID       int64    `json:"db_id"`
	UserID     int64    `json:"user_id"`
	Privileges []string `json:"privileges"` // ["ALL"] for all privileges; [] is rejected
	All        bool     `json:"all,omitempty"`
}

// DBWizardReq creates a database, a user and the grant in one call (handoff-ui H-2).
type DBWizardReq struct {
	Name       string   `json:"name"`
	User       string   `json:"user"`
	Password   string   `json:"password"`
	Privileges []string `json:"privileges"`
	All        bool     `json:"all,omitempty"`
}

// FTPReq: quota_mb absent/-1/null = unlimited, n > 0 = n MB; 0 is invalid
// (G1). dir must not be a private directory (etc, mail, logs, tmp, backups, ssl).
type FTPReq struct {
	Login    string `json:"login"`
	Domain   string `json:"domain"`
	Password string `json:"password"`
	Dir      string `json:"dir"`
	QuotaMB  Limit  `json:"quota_mb"`
}

type CronReq struct {
	Minute  string `json:"minute"`
	Hour    string `json:"hour"`
	Dom     string `json:"dom"`
	Month   string `json:"month"`
	Dow     string `json:"dow"`
	Command string `json:"command"`
}

type CronEmailReq struct {
	Email string `json:"email"`
}

type SSLReq struct {
	DomainID int64 `json:"domain_id"`
}

type RestoreReq struct {
	Snapshot string `json:"snapshot"`
	Path     string `json:"path"`
	InPlace  bool   `json:"in_place"`
}

type BackupReq struct {
	Databases bool `json:"databases"`
}

func (s *Server) userRoutes(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if u := userOf(r); u == nil || !u.SystemUser {
					writeJSON(w, 403, apiError{Code: "no_hosting_account"})
					return
				}
				next.ServeHTTP(w, r)
			})
		})
		s.mountIsolationUser(r)
		s.mountShieldUser(r) // v0.4 shield.go
		s.mountMailx(r)      // v0.4 mailx.go
		s.mountWebx(r)       // v0.4 webx.go (web extras)
		s.mountDnsx(r)       // v0.4 dnsx.go (DNSSEC, import/export, history, lists)
		s.mountAppx(r)       // v0.4 appx.go (restored by dnsx after an EIO on this file)
		s.mountDevx(r)       // v0.4 devx.go (restored by dnsx after an EIO on this file)
		s.mountUsagexUser(r) // v0.4 usagex.go
		s.mountAdminxUser(r) // v0.4 adminx.go
		s.mountDbx(r)        // v0.4 dbx.go (remote MySQL, PostgreSQL, process list)
		s.mountV11User(r)    // v1.1 parity (v11_user.go, v11_tools.go)
		s.mountV11Tools(r)
		s.op(r, "GET", "/user/summary", "user", "General information and statistics sidebar", nil, s.h(s.userSummary))
		s.op(r, "GET", "/user/domains", "domains", "List domains, subdomains and aliases", nil, s.h(s.listDomains))
		s.op(r, "POST", "/user/domains", "domains", "Create an addon domain, subdomain or alias", DomainReq{}, s.idempotent(s.h(s.createDomain)))
		s.op(r, "PUT", "/user/domains/{id}", "domains", "Change document root, PHP version or redirect", DomainUpdateReq{}, s.h(s.updateDomain))
		s.op(r, "DELETE", "/user/domains/{id}", "domains", "Delete a domain", nil, s.h(s.deleteDomain))
		s.op(r, "GET", "/user/dns/{domain}", "dns", "Get a DNS zone (?limit=&offset=&q=&type= page the records)", nil, s.h(s.getZone))
		s.op(r, "PUT", "/user/dns/{domain}/rrset", "dns", "Replace one record set (name+type)", RRSetReq{}, s.h(s.putRRSet))
		s.op(r, "DELETE", "/user/dns/{domain}/rrset/{name}/{type}", "dns", "Delete one record set", nil, s.h(s.deleteRRSet))
		s.op(r, "POST", "/user/dns/{domain}/reset", "dns", "Reset a zone to the default template", nil, s.h(s.resetZone))
		s.op(r, "GET", "/user/email/accounts", "email", "List email accounts", nil, s.h(s.listMailboxes))
		s.op(r, "POST", "/user/email/accounts", "email", "Create an email account", MailboxReq{}, s.h(s.createMailbox))
		s.op(r, "PUT", "/user/email/accounts/{id}/password", "email", "Change an email account password", PasswordReq{}, s.h(s.mailboxPassword))
		s.op(r, "PUT", "/user/email/accounts/{id}/quota", "email", "Change an email account quota", QuotaReq{}, s.h(s.mailboxQuota))
		s.op(r, "DELETE", "/user/email/accounts/{id}", "email", "Delete an email account", nil, s.h(s.deleteMailbox))
		s.op(r, "GET", "/user/email/forwarders", "email", "List forwarders and catch-alls", nil, s.h(s.listForwarders))
		s.op(r, "POST", "/user/email/forwarders", "email", "Add a forwarder (source * = default address/catch-all)", ForwarderReq{}, s.h(s.createForwarder))
		s.op(r, "DELETE", "/user/email/forwarders/{id}", "email", "Delete a forwarder", nil, s.h(s.deleteForwarder))
		s.op(r, "GET", "/user/email/deliverability", "email", "SPF/DKIM/DMARC status per domain", nil, s.h(s.deliverability))
		s.op(r, "GET", "/user/databases", "databases", "List databases, users and grants", nil, s.h(s.listDatabases))
		s.op(r, "POST", "/user/databases", "databases", "Create a database (name is prefixed with the username)", NameReq{}, s.h(s.createDatabase))
		s.op(r, "DELETE", "/user/databases/{id}", "databases", "Delete a database", nil, s.h(s.deleteDatabase))
		s.op(r, "POST", "/user/db-users", "databases", "Create a database user", DBUserReq{}, s.h(s.createDBUser))
		s.op(r, "PUT", "/user/db-users/{id}/password", "databases", "Change a database user's password", PasswordReq{}, s.h(s.dbUserPassword))
		s.op(r, "DELETE", "/user/db-users/{id}", "databases", "Delete a database user", nil, s.h(s.deleteDBUser))
		s.op(r, "POST", "/user/db-wizard", "databases", "Create a database, a user and the grant in one step (rolled back on failure)", DBWizardReq{}, s.h(s.dbWizard))
		s.op(r, "POST", "/user/db-grants", "databases", "Grant a user privileges on a database", GrantReq{}, s.h(s.grantDB))
		s.op(r, "DELETE", "/user/db-grants/{db}/{user}", "databases", "Revoke a user's privileges on a database", nil, s.h(s.revokeDB))
		s.op(r, "POST", "/user/phpmyadmin", "databases", "Get a single-sign-on phpMyAdmin URL", nil, s.h(s.phpMyAdminSSO))
		s.op(r, "POST", "/user/files", "files", "File Manager operation (list, read, write, mkdir, touch, delete, rename, copy, chmod, zip, unzip)", rpc.FileOp{}, s.h(s.fileOp))
		s.op(r, "POST", "/user/files/upload", "files", "Upload files (multipart/form-data: path, file[])", nil, s.h(s.fileUpload))
		s.op(r, "GET", "/user/files/download", "files", "Download a file (?path=)", nil, s.fileDownload)
		s.op(r, "GET", "/user/ftp", "ftp", "List FTP accounts and connection details", nil, s.h(s.listFTP))
		s.op(r, "POST", "/user/ftp", "ftp", "Create an FTP account", FTPReq{}, s.h(s.createFTP))
		s.op(r, "PUT", "/user/ftp/{id}/password", "ftp", "Change an FTP password", PasswordReq{}, s.h(s.ftpPassword))
		s.op(r, "DELETE", "/user/ftp/{id}", "ftp", "Delete an FTP account", nil, s.h(s.deleteFTP))
		s.op(r, "GET", "/user/cron", "cron", "List cron jobs", nil, s.h(s.listCron))
		s.op(r, "POST", "/user/cron", "cron", "Add a cron job", CronReq{}, s.h(s.createCron))
		s.op(r, "DELETE", "/user/cron/{id}", "cron", "Delete a cron job", nil, s.h(s.deleteCron))
		s.op(r, "PUT", "/user/cron/email", "cron", "Set the cron notification email", CronEmailReq{}, s.h(s.cronEmail))
		s.op(r, "GET", "/user/ssl", "ssl", "SSL/TLS status of every domain", nil, s.h(s.sslStatus))
		s.op(r, "POST", "/user/ssl/autossl", "ssl", "Run AutoSSL (Let's Encrypt) for one domain", SSLReq{}, s.h(s.runAutoSSL))
		s.op(r, "GET", "/user/php", "php", "Installed PHP versions and per-domain selection", nil, s.h(s.userPHP))
		s.op(r, "GET", "/user/disk", "metrics", "Disk usage by directory, databases and mail", nil, s.h(s.diskUsage))
		s.op(r, "GET", "/user/logs", "metrics", "Access or error log tail (?domain=&kind=access|error)", nil, s.h(s.logs))
		s.op(r, "GET", "/user/backups", "backup", "List restic snapshots", nil, s.h(s.listBackups))
		s.op(r, "POST", "/user/backups", "backup", "Run a backup now", BackupReq{}, s.h(s.runBackup))
		s.op(r, "POST", "/user/backups/restore", "backup", "Restore files, a directory or a database from a snapshot", RestoreReq{}, s.h(s.restoreBackup))
		s.mountBackupVerifyUser(r) // v0.4 backup_verify.go
		s.op(r, "GET", "/user/webmail", "email", "Webmail URL", nil, s.h(s.webmailURL))
	})
}

// ---- helpers ----------------------------------------------------------------------

// count runs a COUNT query; a database error is logged and counts as 0
// only for display purposes. Limit checks use txCount inside a transaction.
func (s *Server) count(q string, args ...any) int64 {
	var n int64
	if err := s.Store.DB.QueryRow(q, args...).Scan(&n); err != nil {
		s.Log.Warn("count query", "err", err)
	}
	return n
}

func txCount(ctx context.Context, tx *sql.Tx, q string, args ...any) (int64, error) {
	var n int64
	err := tx.QueryRowContext(ctx, q, args...).Scan(&n)
	return n, err
}

// insertLimited atomically checks a package limit and a uniqueness rule and
// inserts the row (CODE-13): the transaction holds the store's only
// connection, so two parallel requests cannot both pass the check.
func (s *Server) insertLimited(ctx context.Context, limit int64, what, countQ string, countArgs []any,
	existsQ string, existsArgs []any, insertQ string, insertArgs ...any) (int64, error) {
	var id int64
	err := s.Store.Tx(ctx, func(tx *sql.Tx) error {
		if countQ != "" && limited(limit) { // G1: -1 unlimited, 0 none
			n, err := txCount(ctx, tx, countQ, countArgs...)
			if err != nil {
				return err
			}
			if n >= limit {
				return limitReached(what)
			}
		}
		if existsQ != "" {
			n, err := txCount(ctx, tx, existsQ, existsArgs...)
			if err != nil {
				return err
			}
			if n > 0 {
				return conflict("already_exists")
			}
		}
		res, err := tx.ExecContext(ctx, insertQ, insertArgs...)
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return id, err
}

// deleteRow removes a row created by insertLimited when the agent action
// that should follow it failed.
func (s *Server) deleteRow(ctx context.Context, table string, id int64) {
	dctx, cancel := undoCtx(ctx)
	defer cancel()
	if _, err := s.Store.DB.ExecContext(dctx, `DELETE FROM `+table+` WHERE id=?`, id); err != nil {
		s.Log.Error("undo insert", "table", table, "id", id, "err", err)
	}
}

func (s *Server) ownDomain(r *http.Request, id int64) (store.Domain, error) {
	d, err := store.One[store.Domain](r.Context(), s.Store.DB, `SELECT d.*, '' AS parent_name FROM domains d WHERE d.id=? AND d.user_id=?`, id, userOf(r).ID)
	if err != nil {
		return d, notFound()
	}
	return d, nil
}

func (s *Server) ownDomainByName(r *http.Request, name string) (store.Domain, error) {
	d, err := store.One[store.Domain](r.Context(), s.Store.DB, `SELECT d.*, '' AS parent_name FROM domains d WHERE d.name=? AND d.user_id=?`, strings.ToLower(name), userOf(r).ID)
	if err != nil {
		return d, notFound()
	}
	return d, nil
}

// ---- summary ------------------------------------------------------------------------

func (s *Server) userSummary(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	pkg := s.packageOf(r.Context(), u)
	var du rpc.DiskUsage
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	// best effort: the summary still renders when usage cannot be measured in time
	if err := s.Agent.Call(ctx, rpc.MDiskUsage, rpc.DiskUsageReq{User: u.Username}, &du); err != nil {
		s.Log.Info("summary: disk usage", "err", err)
	}
	var dbSizes rpc.DBSizes
	if err := s.Agent.Call(ctx, rpc.MDBSizes, rpc.DBSizesReq{Prefix: u.Username}, &dbSizes); err != nil {
		s.Log.Info("summary: db sizes", "err", err)
	}
	var dbBytes int64
	for _, v := range dbSizes.Sizes {
		dbBytes += v
	}
	stat := func(key string, used, limit int64) map[string]any {
		return map[string]any{"key": key, "used": used, "limit": limit}
	}
	ssl := "none"
	if err := s.Store.R.QueryRow(`SELECT ssl_status FROM domains WHERE user_id=? AND kind='main'`, u.ID).Scan(&ssl); err != nil {
		ssl = "none"
	}
	// one round trip for every count (read pool, never queued behind writes)
	var nAddon, nSub, nAlias, nMail, nFwd, nDB, nFTP, nCron int64
	if err := s.Store.R.QueryRowContext(r.Context(), `SELECT
		(SELECT COUNT(*) FROM domains WHERE user_id=?1 AND kind='addon'),
		(SELECT COUNT(*) FROM domains WHERE user_id=?1 AND kind='sub'),
		(SELECT COUNT(*) FROM domains WHERE user_id=?1 AND kind='alias'),
		(SELECT COUNT(*) FROM mailboxes WHERE user_id=?1),
		(SELECT COUNT(*) FROM forwarders WHERE user_id=?1),
		(SELECT COUNT(*) FROM databases WHERE user_id=?1),
		(SELECT COUNT(*) FROM ftp_accounts WHERE user_id=?1),
		(SELECT COUNT(*) FROM cron_jobs WHERE user_id=?1)`, u.ID).Scan(&nAddon, &nSub, &nAlias, &nMail, &nFwd, &nDB, &nFTP, &nCron); err != nil {
		return nil, err
	}
	// G1: limit -1 = unlimited, 0 = none
	stats := []any{
		stat("disk", du.TotalBytes, bytesLimit(pkg.DiskMB)),
		stat("db_disk", dbBytes, Unlimited),
		stat("inodes", du.Inodes, Unlimited),
		stat("bandwidth", 0, bytesLimit(pkg.BandwidthMB)),
		stat("addon_domains", nAddon, pkg.MaxDomains),
		stat("subdomains", nSub, pkg.MaxSubdomains),
		stat("aliases", nAlias, pkg.MaxAliases),
		stat("email_accounts", nMail, pkg.MaxEmail),
		stat("forwarders", nFwd, 500),
		stat("databases", nDB, pkg.MaxDB),
		stat("ftp_accounts", nFTP, pkg.MaxFTP),
		stat("cron_jobs", nCron, 100),
	}
	return map[string]any{
		"username": u.Username, "primary_domain": u.PrimaryDomain, "home": u.Home, "shared_ip": s.serverIP(),
		"last_login_ip": u.LastLoginIP, "last_login_at": u.LastLoginAt, "package": pkg.Name, "ssl_status": ssl,
		"hostname": s.Cfg.Hostname, "php_version": s.phpFor(u, store.Domain{}), "stats": stats,
	}, nil
}

// ---- domains ------------------------------------------------------------------------

func (s *Server) listDomains(w http.ResponseWriter, r *http.Request) (any, error) {
	return s.domainsOf(r.Context(), userOf(r).ID)
}

func (s *Server) createDomain(w http.ResponseWriter, r *http.Request) (any, error) {
	var in DomainReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	ctx := r.Context()
	u := userOf(r)
	pkg := s.packageOf(ctx, u)
	var parent store.Domain
	var limit int64
	switch in.Kind {
	case "addon", "alias":
		// trailing dot, upper case and IDN are normalised; schemes, paths,
		// emoji/symbols and public suffixes are refused (R2-UX-11, R2-WB-4)
		d, err := validate.NormalizeDomain(in.Name)
		if err != nil {
			return nil, fieldErr(err, "name", validate.MaxDomain)
		}
		in.Name = d
	}
	switch in.Kind {
	case "addon":
		limit = pkg.MaxDomains
	case "sub":
		p, err := s.ownDomain(r, in.ParentID)
		if err != nil || p.Kind == "alias" || p.Kind == "sub" {
			return nil, badField("invalid_parent", "parent_id")
		}
		if err := maxLen("name", strings.TrimSpace(in.Name), 63); err != nil {
			return nil, err
		}
		label, err := validate.NormalizeLabel(in.Name)
		if err != nil {
			return nil, badField(err.Error(), "name")
		}
		limit = pkg.MaxSubdomains
		parent = p
		in.Name = label + "." + p.Name
		if len(in.Name) > validate.MaxDomain {
			return nil, tooLong("name", validate.MaxDomain-len(p.Name)-1)
		}
	case "alias":
		p, err := s.ownDomain(r, in.ParentID)
		if err != nil || p.Kind == "alias" {
			return nil, badField("invalid_parent", "parent_id")
		}
		limit = pkg.MaxAliases
		parent = p
	default:
		return nil, badField("invalid_kind", "kind")
	}
	if err := validate.Domain(in.Name); err != nil {
		return nil, badField("invalid_domain", "name")
	}
	docroot := in.DocRoot
	if docroot == "" {
		// a 253-character domain gets a shortened docroot instead of
		// failing with invalid_docroot (R2-UX-12)
		docroot = validate.DefaultDocRoot(in.Name)
		if in.Kind == "alias" {
			docroot = parent.DocRoot
		}
	}
	// strict grammar + no private dirs: the value ends up in nginx/Apache configs (SEC-1)
	rel, err := validate.DocRoot(docroot)
	if err != nil {
		return nil, fieldErr(err, "docroot", 255)
	}
	if in.PHPVersion != "" && validate.PHPVersion(in.PHPVersion) != nil {
		return nil, badField("invalid_php_version", "php_version")
	}
	var parentID any
	if parent.ID != 0 {
		parentID = parent.ID
	}
	reserved := s.reservedNames()
	var id int64
	err = s.Store.Tx(ctx, func(tx *sql.Tx) error {
		if limited(limit) { // G1: -1 unlimited, 0 none
			n, err := txCount(ctx, tx, `SELECT COUNT(*) FROM domains WHERE user_id=? AND kind=?`, u.ID, in.Kind)
			if err != nil {
				return err
			}
			if n >= limit {
				return limitReached(map[string]string{"addon": "addon_domains", "sub": "subdomains", "alias": "aliases"}[in.Kind])
			}
		}
		n, err := txCount(ctx, tx, `SELECT COUNT(*) FROM domains WHERE name=?`, in.Name)
		if err != nil {
			return err
		}
		if n > 0 {
			return conflict("domain_taken")
		}
		// cross-account and server-name ownership rules (SEC-6 / CODE-4)
		if err := s.checkDomainClaim(ctx, tx, reserved, u.ID, in.Name, false); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO domains(user_id,name,kind,parent_id,docroot,php_version,created_at) VALUES(?,?,?,?,?,?,?)`,
			u.ID, in.Name, in.Kind, parentID, rel, in.PHPVersion, s.Now().Unix())
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	if err != nil {
		return nil, err
	}
	undo := func(cause error) error {
		s.deleteRow(ctx, "domains", id)
		uctx, cancel := undoCtx(ctx)
		defer cancel()
		if err := s.applyWeb(uctx, u); err != nil {
			s.Log.Error("domain.create undo: re-apply web", "err", err)
		}
		s.audit(r, "domain.create", in.Name, cause.Error(), false)
		return cause
	}
	if err := s.applyWeb(ctx, u); err != nil {
		return nil, undo(err)
	}
	warnings := []Warning{}
	switch in.Kind {
	case "addon", "alias":
		dkim := ""
		if in.Kind == "addon" {
			var md rpc.MailDomainResult
			if err := s.Agent.Call(ctx, rpc.MMailDomainOn, rpc.MailDomain{User: u.Username, Domain: in.Name}, &md); err == nil {
				dkim = md.DKIMRecord
			} else {
				warnings = append(warnings, warn(WarnMailSetupFailed, "mail", agentCode(err)))
			}
		}
		if err := s.Agent.Call(ctx, rpc.MDNSZoneCreate, rpc.DNSZone{Owner: u.Username, Zone: in.Name, Records: s.zoneTemplate(in.Name, dkim)}, nil); err != nil {
			warnings = append(warnings, warn(WarnDNSSetupFailed, "dns", agentCode(err)))
		}
	case "sub":
		if err := s.Agent.Call(ctx, rpc.MDNSRRSetReplace, rpc.RRSet{Owner: u.Username, Zone: parent.Name, Name: in.Name, Type: "A", TTL: 3600, Records: []string{s.serverIP()}}, nil); err != nil {
			warnings = append(warnings, warn(WarnDNSSetupFailed, "dns", agentCode(err)))
		}
	}
	s.audit(r, "domain.create", in.Name, in.Kind, true)
	return map[string]any{"id": id, "name": in.Name, "docroot": rel, "warnings": warnings}, nil
}

// agentCode returns the error code of an agent error (no internal detail).
// warnArea maps an agent method ("mail.forward.delete") to its area ("mail").
func warnArea(method string) string {
	a, _, _ := strings.Cut(method, ".")
	if a == "web" || a == "php" {
		return "web"
	}
	return a
}

func agentCode(err error) string {
	var re *rpc.Error
	if errors.As(err, &re) {
		return re.Code
	}
	return "internal_error"
}

func (s *Server) updateDomain(w http.ResponseWriter, r *http.Request) (any, error) {
	var in DomainUpdateReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	d, err := s.ownDomain(r, idParam(r, "id"))
	if err != nil {
		return nil, err
	}
	if in.DocRoot != nil {
		rel, err := validate.DocRoot(*in.DocRoot)
		if err != nil {
			return nil, fieldErr(err, "docroot", 255)
		}
		d.DocRoot = rel
	}
	if in.PHPVersion != nil {
		if *in.PHPVersion != "" && validate.PHPVersion(*in.PHPVersion) != nil {
			return nil, bad("invalid_php_version")
		}
		d.PHPVersion = *in.PHPVersion
	}
	if in.Redirect != nil {
		red := strings.TrimSpace(*in.Redirect)
		if len(red) > 2000 {
			return nil, tooLong("redirect", 2000)
		}
		if red != "" && (!strings.HasPrefix(red, "http://") && !strings.HasPrefix(red, "https://") || !validate.ConfigSafe(red)) {
			return nil, badField("invalid_redirect", "redirect")
		}
		d.Redirect = strings.TrimRight(red, "/")
	}
	old, err := s.ownDomain(r, d.ID)
	if err != nil {
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `UPDATE domains SET docroot=?, php_version=?, redirect=? WHERE id=?`, d.DocRoot, d.PHPVersion, d.Redirect, d.ID); err != nil {
		return nil, err
	}
	if err := s.applyWeb(r.Context(), userOf(r)); err != nil {
		uctx, cancel := undoCtx(r.Context())
		defer cancel()
		if _, uerr := s.Store.DB.ExecContext(uctx, `UPDATE domains SET docroot=?, php_version=?, redirect=? WHERE id=?`, old.DocRoot, old.PHPVersion, old.Redirect, d.ID); uerr != nil {
			s.Log.Error("domain.update undo", "err", uerr)
		}
		if uerr := s.applyWeb(uctx, userOf(r)); uerr != nil {
			s.Log.Error("domain.update undo: re-apply web", "err", uerr)
		}
		return nil, err
	}
	s.audit(r, "domain.update", d.Name, fmt.Sprintf("docroot=%s php=%s redirect=%s", d.DocRoot, d.PHPVersion, d.Redirect), true)
	return nil, nil
}

func (s *Server) deleteDomain(w http.ResponseWriter, r *http.Request) (any, error) {
	d, err := s.ownDomain(r, idParam(r, "id"))
	if err != nil {
		return nil, err
	}
	if d.Kind == "main" {
		return nil, unprocessable("cannot_delete_main_domain")
	}
	ctx := r.Context()
	u := userOf(r)
	if s.count(`SELECT COUNT(*) FROM mailboxes WHERE domain_id=?`, d.ID) > 0 {
		return nil, conflict("domain_has_mailboxes")
	}
	children, err := store.Select[store.Domain](ctx, s.Store.DB, `SELECT *, '' AS parent_name FROM domains WHERE parent_id=?`, d.ID)
	if err != nil {
		return nil, err
	}
	for _, c := range children {
		if s.count(`SELECT COUNT(*) FROM mailboxes WHERE domain_id=?`, c.ID) > 0 {
			return nil, conflict("domain_has_mailboxes")
		}
	}
	// Forwarders of the removed domains go too, otherwise the next owner of
	// the name inherits them (SEC-12).
	removed := append([]store.Domain{d}, children...)
	var sources []string
	if err := s.Store.Tx(ctx, func(tx *sql.Tx) error {
		for _, x := range removed {
			if x.Kind == "sub" {
				continue
			}
			fw, err := store.Select[store.Forwarder](ctx, tx, `SELECT * FROM forwarders WHERE user_id=? AND (source=? OR source LIKE ?)`, u.ID, "@"+x.Name, "%@"+x.Name)
			if err != nil {
				return err
			}
			for _, f := range fw {
				sources = append(sources, f.Source)
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM forwarders WHERE user_id=? AND (source=? OR source LIKE ?)`, u.ID, "@"+x.Name, "%@"+x.Name); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM domains WHERE id=?`, d.ID)
		return err
	}); err != nil {
		return nil, err
	}
	warnings := []Warning{}
	call := func(method string, params any) {
		if err := s.Agent.Call(ctx, method, params, nil); err != nil {
			s.Log.Warn("domain.delete cleanup", "method", method, "err", err)
			warnings = append(warnings, warn(WarnCleanupFailed, warnArea(method), agentCode(err)))
		}
	}
	seen := map[string]bool{}
	for _, src := range sources {
		if !seen[src] {
			seen[src] = true
			call(rpc.MMailForwardDel, rpc.MailForwardRef{Owner: u.Username, Source: src})
		}
	}
	if d.Kind != "alias" {
		call(rpc.MVhostRemove, rpc.DomainRef{Owner: u.Username, Domain: d.Name})
	}
	for _, c := range children {
		if c.Kind != "alias" {
			call(rpc.MVhostRemove, rpc.DomainRef{Owner: u.Username, Domain: c.Name})
		} else {
			call(rpc.MMailDomainOff, rpc.MailDomain{User: u.Username, Domain: c.Name})
			call(rpc.MDNSZoneDelete, rpc.ZoneRef{Owner: u.Username, Zone: c.Name})
		}
	}
	switch d.Kind {
	case "addon", "alias":
		call(rpc.MMailDomainOff, rpc.MailDomain{User: u.Username, Domain: d.Name})
		call(rpc.MDNSZoneDelete, rpc.ZoneRef{Owner: u.Username, Zone: d.Name})
	case "sub":
		zone := d.ParentName
		if zone == "" && d.ParentID != nil {
			if err := s.Store.DB.QueryRowContext(ctx, `SELECT name FROM domains WHERE id=?`, *d.ParentID).Scan(&zone); err != nil {
				zone = ""
			}
		}
		if zone != "" {
			call(rpc.MDNSRRSetDelete, rpc.RRSetRef{Owner: u.Username, Zone: zone, Name: d.Name, Type: "A"})
		}
	}
	if err := s.applyWeb(ctx, u); err != nil {
		return nil, err
	}
	s.audit(r, "domain.delete", d.Name, d.Kind, true)
	return map[string]any{"ok": true, "warnings": warnings}, nil
}

// ---- DNS ----------------------------------------------------------------------------

func (s *Server) zoneDomain(r *http.Request) (store.Domain, error) {
	d, err := s.ownDomainByName(r, chi.URLParam(r, "domain"))
	if err != nil {
		return d, err
	}
	if d.Kind == "sub" {
		return d, bad("subdomain_has_no_zone")
	}
	return d, nil
}

// zonePage is the zone with its records paged on the server (R2-PERF-8).
// Without limit every record is returned, as before; total is always the
// number of records matching q/type.
type zonePage struct {
	rpc.DNSZone
	Total  int `json:"total"`
	Offset int `json:"offset"`
	Limit  int `json:"limit"` // -1 = all
}

// getZone returns a zone. Paging: ?limit=1..1000&offset=&q= (substring of
// name or content, case-insensitive) &type=A|AAAA|... Records keep the
// agent's order (name, type). X-Total-Count = total.
func (s *Server) getZone(w http.ResponseWriter, r *http.Request) (any, error) {
	d, err := s.zoneDomain(r)
	if err != nil {
		return nil, err
	}
	var z rpc.DNSZone
	if err := s.agentCall(r, rpc.MDNSZoneGet, rpc.ZoneRef{Owner: userOf(r).Username, Zone: d.Name}, &z); err != nil {
		return nil, err
	}
	limit, offset := pageParams(r)
	qv := r.URL.Query()
	q := strings.ToLower(strings.TrimSpace(qv.Get("q")))
	typ := strings.ToUpper(strings.TrimSpace(qv.Get("type")))
	recs := z.Records
	if q != "" || typ != "" {
		recs = recs[:0:0]
		for _, rec := range z.Records {
			if typ != "" && rec.Type != typ {
				continue
			}
			if q != "" && !strings.Contains(strings.ToLower(rec.Name), q) && !strings.Contains(strings.ToLower(rec.Content), q) {
				continue
			}
			recs = append(recs, rec)
		}
	}
	total := len(recs)
	if offset > total {
		offset = total
	}
	recs = recs[offset:]
	if limit >= 0 && limit < len(recs) {
		recs = recs[:limit]
	}
	if recs == nil {
		recs = []rpc.DNSRecord{}
	}
	z.Records = recs
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	return zonePage{DNSZone: z, Total: total, Offset: offset, Limit: limit}, nil
}

// recordName turns a user-facing name into the FQDN inside zone. PUT and
// DELETE use the same rule:
//
//	"", "@"                 -> the zone apex
//	"www", "çiçek"          -> relative: www.<zone>, xn--iek-...<zone>
//	"www.example.com"       -> already ends in the zone: kept
//	"evil.example.org."     -> trailing dot = absolute (FQDN, as in every
//	                           zone editor): kept as is, so a name outside the
//	                           zone fails with record_outside_zone instead of
//	                           becoming evil.example.org.<zone> (R2-UX-18)
func recordName(zone, in string) string {
	name := strings.ToLower(strings.TrimSpace(in))
	if name == "" || name == "@" || name == zone+"." {
		return zone
	}
	abs := strings.HasSuffix(name, ".")
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	for i, l := range labels {
		if l == "*" || strings.HasPrefix(l, "_") || l == "" {
			continue
		}
		if a, err := validate.NormalizeLabel(l); err == nil {
			labels[i] = a
		}
	}
	name = strings.Join(labels, ".")
	if abs || name == zone || strings.HasSuffix(name, "."+zone) {
		return name
	}
	return name + "." + zone
}

func (s *Server) putRRSet(w http.ResponseWriter, r *http.Request) (any, error) {
	var in RRSetReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	d, err := s.zoneDomain(r)
	if err != nil {
		return nil, err
	}
	in.Type = strings.ToUpper(in.Type)
	if err := maxLen("name", in.Name, validate.MaxDomain+1); err != nil {
		return nil, err
	}
	name := recordName(d.Name, in.Name)
	if !validate.DNSTypes[in.Type] {
		return nil, badField("invalid_record_type", "type")
	}
	if err := validate.RecordName(d.Name, name); err != nil {
		return nil, badField(err.Error(), "name")
	}
	if len(in.Records) > 100 {
		return nil, badField("invalid_record_content", "records")
	}
	for _, c := range in.Records {
		if len(c) > 4000 {
			return nil, tooLong("records", 4000)
		}
		if err := validate.RecordContent(in.Type, c); err != nil {
			return nil, badField(err.Error(), "records")
		}
	}
	if in.TTL == 0 {
		in.TTL = 3600
	}
	if in.TTL < 60 || in.TTL > 604800 {
		return nil, bad("invalid_ttl")
	}
	before := s.dnsxBefore(r, d.Name, name, in.Type) // v0.4 dnsx history
	if err := s.agentCall(r, rpc.MDNSRRSetReplace, rpc.RRSet{Owner: userOf(r).Username, Zone: d.Name, Name: name, Type: in.Type, TTL: in.TTL, Records: in.Records}, nil); err != nil {
		return nil, err
	}
	s.dnsxRecord(r, d.Name, name, in.Type, "replace", before, normSet(name, in.Type, in.TTL, in.Records), 0)
	s.audit(r, "dns.rrset", d.Name, name+" "+in.Type, true)
	return nil, nil
}

func (s *Server) deleteRRSet(w http.ResponseWriter, r *http.Request) (any, error) {
	d, err := s.zoneDomain(r)
	if err != nil {
		return nil, err
	}
	name, typ := recordName(d.Name, chi.URLParam(r, "name")), strings.ToUpper(chi.URLParam(r, "type"))
	if !validate.DNSTypes[typ] {
		return nil, bad("invalid_record_type")
	}
	if err := validate.RecordName(d.Name, name); err != nil {
		return nil, bad(err.Error())
	}
	before := s.dnsxBefore(r, d.Name, name, typ) // v0.4 dnsx history
	if err := s.agentCall(r, rpc.MDNSRRSetDelete, rpc.RRSetRef{Owner: userOf(r).Username, Zone: d.Name, Name: name, Type: typ}, nil); err != nil {
		return nil, err
	}
	if before != nil {
		s.dnsxRecord(r, d.Name, name, typ, "delete", before, nil, 0)
	}
	s.audit(r, "dns.delete", d.Name, name+" "+typ, true)
	return nil, nil
}

func (s *Server) resetZone(w http.ResponseWriter, r *http.Request) (any, error) {
	d, err := s.zoneDomain(r)
	if err != nil {
		return nil, err
	}
	var md rpc.MailDomainResult
	dkim := ""
	if d.Kind != "alias" && s.agentCall(r, rpc.MMailDomainOn, rpc.MailDomain{User: userOf(r).Username, Domain: d.Name}, &md) == nil {
		dkim = md.DKIMRecord
	}
	recs, err := s.resetRecords(r.Context(), userOf(r).ID, d.Name, dkim)
	if err != nil {
		return nil, err
	}
	beforeSets, _, berr := s.zoneSets(r, d.Name) // v0.4 dnsx history
	// reset in place (PATCH), never delete + re-create the zone
	if err := s.agentCall(r, rpc.MDNSZoneCreate, rpc.DNSZone{Owner: userOf(r).Username, Zone: d.Name, Records: recs, Replace: true}, nil); err != nil {
		return nil, err
	}
	if afterSets, _, aerr := s.zoneSets(r, d.Name); berr == nil && aerr == nil {
		s.dnsxRecordDiff(r, d.Name, "reset", beforeSets, afterSets)
	}
	s.audit(r, "dns.reset", d.Name, "", true)
	return nil, nil
}

// resetRecords is the default template plus the records the panel itself
// keeps for the account's registered names inside the zone: the A record
// of every subdomain (created with the subdomain) and, for an addon or
// alias domain the account placed below this zone, its own A/www records.
// A reset used to drop them and take subdomain sites offline (R2-E2E-6).
func (s *Server) resetRecords(ctx context.Context, uid int64, zone, dkim string) ([]rpc.DNSRecord, error) {
	recs := s.zoneTemplate(zone, dkim)
	have := map[string]bool{}
	for _, rc := range recs {
		have[rc.Name+"/"+rc.Type] = true
	}
	doms, err := store.Select[store.Domain](ctx, s.Store.R, `SELECT d.*, '' AS parent_name FROM domains d WHERE d.user_id=? AND d.name LIKE ? ESCAPE '\' ORDER BY d.name`,
		uid, "%."+likeEscape(zone))
	if err != nil {
		return nil, err
	}
	ip := s.serverIP()
	for _, d := range doms {
		if !strings.HasSuffix(d.Name, "."+zone) || have[d.Name+"/A"] || have[d.Name+"/CNAME"] {
			continue
		}
		recs = append(recs, rpc.DNSRecord{Name: d.Name, Type: "A", TTL: 3600, Content: ip})
		have[d.Name+"/A"] = true
		if d.Kind == "addon" || d.Kind == "alias" {
			if w := "www." + d.Name; !have[w+"/CNAME"] && !have[w+"/A"] {
				recs = append(recs, rpc.DNSRecord{Name: w, Type: "CNAME", TTL: 3600, Content: d.Name})
				have[w+"/CNAME"] = true
			}
		}
	}
	return recs, nil
}

// ---- email ---------------------------------------------------------------------------

func (s *Server) listMailboxes(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	boxes, err := store.Select[store.Mailbox](r.Context(), s.Store.DB, `SELECT * FROM mailboxes WHERE user_id=? ORDER BY email`, u.ID)
	if err != nil {
		return nil, err
	}
	doms, _ := s.domainsOf(r.Context(), u.ID)
	var names []string
	for _, d := range doms {
		if d.Kind != "sub" {
			names = append(names, d.Name)
		}
	}
	var usage rpc.MailUsage
	if err := s.agentCall(r, rpc.MMailUsage, rpc.MailUsageReq{User: u.Username, Domains: names}, &usage); err != nil {
		s.Log.Info("mail usage", "err", err) // the list still renders without usage
	}
	for i := range boxes {
		boxes[i].UsedBytes = usage.Bytes[boxes[i].Email]
	}
	// package_quota_mb: the default quota of a new mailbox (the package's
	// mailbox quota; -1 = unlimited), so the UI can pre-fill it
	return map[string]any{"accounts": boxes, "domains": names, "package_quota_mb": s.packageOf(r.Context(), u).MailQuotaMB}, nil
}

func (s *Server) createMailbox(w http.ResponseWriter, r *http.Request) (any, error) {
	var in MailboxReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	pkg := s.packageOf(r.Context(), u)
	in.Local = strings.ToLower(strings.TrimSpace(in.Local))
	if err := maxLen("local", in.Local, 63); err != nil {
		return nil, err
	}
	if err := validate.EmailLocal(in.Local); err != nil {
		return nil, badField("invalid_email_local", "local")
	}
	d, err := s.ownDomainByName(r, in.Domain)
	if err != nil || d.Kind == "sub" {
		return nil, badField("invalid_domain", "domain")
	}
	if err := passwordErr(in.Password, "password"); err != nil {
		return nil, err
	}
	quota, err := s.mailQuota(pkg, in.QuotaMB.or(pkg.MailQuotaMB))
	if err != nil {
		return nil, err
	}
	email := in.Local + "@" + d.Name
	// record first (limit + uniqueness atomically), then the agent (CODE-13)
	id, err := s.insertLimited(r.Context(), pkg.MaxEmail, "email_accounts", `SELECT COUNT(*) FROM mailboxes WHERE user_id=?`, []any{u.ID},
		`SELECT COUNT(*) FROM mailboxes WHERE email=?`, []any{email},
		`INSERT INTO mailboxes(user_id,domain_id,email,quota_mb,created_at) VALUES(?,?,?,?,?)`, u.ID, d.ID, email, quota, s.Now().Unix())
	if err != nil {
		return nil, err
	}
	if d.Kind == "alias" {
		// make sure Postfix knows the alias domain
		if err := s.agentCall(r, rpc.MMailDomainOn, rpc.MailDomain{User: u.Username, Domain: d.Name}, nil); err != nil {
			s.deleteRow(r.Context(), "mailboxes", id)
			return nil, err
		}
	}
	if err := s.agentCall(r, rpc.MMailboxCreate, rpc.Mailbox{User: u.Username, Email: email, Password: in.Password, QuotaMB: agentLimit(quota)}, nil); err != nil {
		s.deleteRow(r.Context(), "mailboxes", id)
		return nil, err
	}
	// a forwarder created before the mailbox must now keep a local copy
	if s.count(`SELECT COUNT(*) FROM forwarders WHERE source=? AND user_id=?`, email, u.ID) > 0 {
		if err := s.syncForward(r, email); err != nil {
			s.Log.Warn("email.create: forwarder resync", "err", err)
		}
	}
	s.audit(r, "email.create", email, "", true)
	return map[string]any{"id": id, "email": email}, nil
}

// mailQuota checks a mailbox quota (G1: -1 unlimited, never 0) and caps it
// at the package disk limit when there is one (R2-UX-15).
func (s *Server) mailQuota(pkg store.Package, q int64) (int64, error) {
	max := int64(maxSizeMB)
	if limited(pkg.DiskMB) {
		max = pkg.DiskMB
	}
	// R2-UX-15: the package mailbox quota is the largest quota a mailbox may
	// have (cPanel "Max Quota per Email Address"); unlimited is refused then
	if limited(pkg.MailQuotaMB) && pkg.MailQuotaMB > 0 {
		max = min(max, pkg.MailQuotaMB)
		if q == Unlimited {
			return 0, limitErr("quota_mb", max, false)
		}
	}
	if err := checkSize("quota_mb", q, max); err != nil {
		return 0, err
	}
	return q, nil
}

func (s *Server) ownMailbox(r *http.Request) (store.Mailbox, error) {
	m, err := store.One[store.Mailbox](r.Context(), s.Store.DB, `SELECT * FROM mailboxes WHERE id=? AND user_id=?`, idParam(r, "id"), userOf(r).ID)
	if err != nil {
		return m, notFound()
	}
	return m, nil
}

func (s *Server) mailboxPassword(w http.ResponseWriter, r *http.Request) (any, error) {
	var in PasswordReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	m, err := s.ownMailbox(r)
	if err != nil {
		return nil, err
	}
	if err := passwordErr(in.Password, "password"); err != nil {
		return nil, err
	}
	if err := s.agentCall(r, rpc.MMailboxPassword, rpc.Mailbox{User: userOf(r).Username, Email: m.Email, Password: in.Password}, nil); err != nil {
		return nil, err
	}
	s.audit(r, "email.password", m.Email, "", true)
	return nil, nil
}

func (s *Server) mailboxQuota(w http.ResponseWriter, r *http.Request) (any, error) {
	var in QuotaReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	m, err := s.ownMailbox(r)
	if err != nil {
		return nil, err
	}
	if !in.QuotaMB.Set {
		return nil, badField("invalid_quota", "quota_mb")
	}
	quota, err := s.mailQuota(s.packageOf(r.Context(), userOf(r)), in.QuotaMB.Value)
	if err != nil {
		return nil, err
	}
	if err := s.agentCall(r, rpc.MMailboxQuota, rpc.Mailbox{User: userOf(r).Username, Email: m.Email, QuotaMB: agentLimit(quota)}, nil); err != nil {
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `UPDATE mailboxes SET quota_mb=? WHERE id=?`, quota, m.ID); err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *Server) deleteMailbox(w http.ResponseWriter, r *http.Request) (any, error) {
	m, err := s.ownMailbox(r)
	if err != nil {
		return nil, err
	}
	if err := s.agentCall(r, rpc.MMailboxDelete, rpc.MailboxRef{User: userOf(r).Username, Email: m.Email}, nil); err != nil {
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM mailboxes WHERE id=?`, m.ID); err != nil {
		return nil, err
	}
	// remaining forwarders of the address no longer keep a local copy
	if s.count(`SELECT COUNT(*) FROM forwarders WHERE source=? AND user_id=?`, m.Email, userOf(r).ID) > 0 {
		if err := s.syncForward(r, m.Email); err != nil {
			s.Log.Warn("email.delete: forwarder resync", "err", err)
		}
	}
	s.audit(r, "email.delete", m.Email, "", true)
	return nil, nil
}

func (s *Server) listForwarders(w http.ResponseWriter, r *http.Request) (any, error) {
	return store.Select[store.Forwarder](r.Context(), s.Store.DB, `SELECT * FROM forwarders WHERE user_id=? ORDER BY source, destination`, userOf(r).ID)
}

// syncForward pushes the full destination list of one source address to
// Postfix. Only the calling account's rows count: rows of any other account
// (there should be none since SEC-12) can never leak into this address.
func (s *Server) syncForward(r *http.Request, src string) error {
	u := userOf(r)
	rows, err := store.Select[store.Forwarder](r.Context(), s.Store.DB, `SELECT * FROM forwarders WHERE source=? AND user_id=?`, src, u.ID)
	if err != nil {
		return err
	}
	var dests []string
	for _, f := range rows {
		dests = append(dests, f.Destination)
	}
	// a mailbox keeps its own copy (and an identity alias when nothing is
	// forwarded, so a catch-all never swallows its mail)
	if !strings.HasPrefix(src, "@") && s.count(`SELECT COUNT(*) FROM mailboxes WHERE email=? AND user_id=?`, src, u.ID) > 0 {
		dests = append(dests, src)
	}
	return s.agentCall(r, rpc.MMailForwardSet, rpc.MailForward{Owner: u.Username, Source: src, Destinations: dests}, nil)
}

func (s *Server) createForwarder(w http.ResponseWriter, r *http.Request) (any, error) {
	var in ForwarderReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	d, err := s.ownDomainByName(r, in.Domain)
	if err != nil || d.Kind == "sub" {
		return nil, bad("invalid_domain")
	}
	src := strings.ToLower(strings.TrimSpace(in.Source))
	if err := maxLen("source", src, 63); err != nil {
		return nil, err
	}
	if err := maxLen("destination", strings.TrimSpace(in.Destination), 254); err != nil {
		return nil, err
	}
	if src == "*" || src == "" {
		src = "@" + d.Name
	} else {
		if err := validate.EmailLocal(src); err != nil {
			return nil, bad("invalid_email_local")
		}
		src = src + "@" + d.Name
	}
	dest := strings.ToLower(strings.TrimSpace(in.Destination))
	if dest != ":fail:" && dest != ":blackhole:" && validate.Email(dest) != nil {
		return nil, bad("invalid_email")
	}
	if dest == src {
		return nil, bad("forwarder_loop")
	}
	var id int64
	err = s.Store.Tx(r.Context(), func(tx *sql.Tx) error {
		if n, err := txCount(r.Context(), tx, `SELECT COUNT(*) FROM forwarders WHERE source=? AND user_id<>?`, src, u.ID); err != nil {
			return err
		} else if n > 0 {
			return conflict("forwarder_owned_by_another_account")
		}
		if n, err := txCount(r.Context(), tx, `SELECT COUNT(*) FROM forwarders WHERE user_id=?`, u.ID); err != nil {
			return err
		} else if n >= 500 {
			return limitReached("forwarders")
		}
		if strings.HasPrefix(src, "@") {
			// only one default address per domain
			if _, err := tx.ExecContext(r.Context(), `DELETE FROM forwarders WHERE source=? AND user_id=?`, src, u.ID); err != nil {
				return err
			}
		}
		res, err := tx.ExecContext(r.Context(), `INSERT INTO forwarders(user_id,source,destination,created_at) VALUES(?,?,?,?)`, u.ID, src, dest, s.Now().Unix())
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := s.syncForward(r, src); err != nil {
		s.deleteRow(r.Context(), "forwarders", id)
		return nil, err
	}
	s.audit(r, "email.forwarder", src, dest, true)
	return map[string]any{"id": id}, nil
}

func (s *Server) deleteForwarder(w http.ResponseWriter, r *http.Request) (any, error) {
	f, err := store.One[store.Forwarder](r.Context(), s.Store.DB, `SELECT * FROM forwarders WHERE id=? AND user_id=?`, idParam(r, "id"), userOf(r).ID)
	if err != nil {
		return nil, notFound()
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM forwarders WHERE id=?`, f.ID); err != nil {
		return nil, err
	}
	if err := s.syncForward(r, f.Source); err != nil {
		return nil, err
	}
	s.audit(r, "email.forwarder_delete", f.Source, f.Destination, true)
	return nil, nil
}

func (s *Server) deliverability(w http.ResponseWriter, r *http.Request) (any, error) {
	doms, _ := s.domainsOf(r.Context(), userOf(r).ID)
	var out []map[string]any
	for _, d := range doms {
		if d.Kind != "main" && d.Kind != "addon" {
			continue
		}
		row := map[string]any{"domain": d.Name, "spf": false, "dkim": false, "dmarc": false, "mx": false}
		var z rpc.DNSZone
		if err := s.agentCall(r, rpc.MDNSZoneGet, rpc.ZoneRef{Owner: userOf(r).Username, Zone: d.Name}, &z); err == nil {
			for _, rec := range z.Records {
				c := strings.Trim(rec.Content, `"`)
				switch {
				case rec.Type == "TXT" && rec.Name == d.Name && strings.HasPrefix(c, "v=spf1"):
					row["spf"] = true
				case rec.Type == "TXT" && rec.Name == "bpanel._domainkey."+d.Name:
					row["dkim"] = true
				case rec.Type == "TXT" && rec.Name == "_dmarc."+d.Name:
					row["dmarc"] = true
				case rec.Type == "MX" && rec.Name == d.Name:
					row["mx"] = true
				}
			}
		}
		out = append(out, row)
	}
	return out, nil
}

func (s *Server) webmailURL(w http.ResponseWriter, r *http.Request) (any, error) {
	host := s.Cfg.Hostname
	if host == "" {
		host = strings.Split(r.Host, ":")[0]
	}
	return map[string]string{"url": fmt.Sprintf("https://%s:%d/", host, s.Cfg.WebmailPort)}, nil
}

// ---- databases ----------------------------------------------------------------------

func (s *Server) listDatabases(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	dbs, err := store.Select[store.Database](r.Context(), s.Store.DB, `SELECT d.*, COALESCE((SELECT group_concat(du.name, ',') FROM db_grants g JOIN db_users du ON du.id=g.dbuser_id WHERE g.db_id=d.id),'') AS users
		FROM databases d WHERE d.user_id=? ORDER BY d.name`, u.ID)
	if err != nil {
		return nil, err
	}
	users, err := store.Select[store.DBUser](r.Context(), s.Store.DB, `SELECT du.*, COALESCE((SELECT group_concat(d.name, ',') FROM db_grants g JOIN databases d ON d.id=g.db_id WHERE g.dbuser_id=du.id),'') AS dbs
		FROM db_users du WHERE du.user_id=? ORDER BY du.name`, u.ID)
	if err != nil {
		return nil, err
	}
	var sizes rpc.DBSizes
	if err := s.agentCall(r, rpc.MDBSizes, rpc.DBSizesReq{Prefix: u.Username}, &sizes); err != nil {
		s.Log.Info("db sizes", "err", err)
	}
	for i := range dbs {
		dbs[i].SizeBytes = sizes.Sizes[dbs[i].Name]
	}
	return map[string]any{"databases": dbs, "users": users, "prefix": u.Username + "_"}, nil
}

func (s *Server) prefixed(u *store.User, name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if !strings.HasPrefix(name, u.Username+"_") {
		name = u.Username + "_" + name
	}
	return name
}

func (s *Server) createDatabase(w http.ResponseWriter, r *http.Request) (any, error) {
	var in NameReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	id, name, err := s.newDatabase(r, in.Name)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "name": name}, nil
}

func (s *Server) newDatabase(r *http.Request, short string) (int64, string, error) {
	u := userOf(r)
	pkg := s.packageOf(r.Context(), u)
	name := s.prefixed(u, short)
	if len(name) > 64 {
		return 0, "", tooLong("name", 64-len(u.Username)-1)
	}
	if err := validate.DBName(u.Username, name); err != nil {
		return 0, "", badField(err.Error(), "name")
	}
	id, err := s.insertLimited(r.Context(), pkg.MaxDB, "databases", `SELECT COUNT(*) FROM databases WHERE user_id=?`, []any{u.ID},
		`SELECT COUNT(*) FROM databases WHERE name=?`, []any{name},
		`INSERT INTO databases(user_id,name,created_at) VALUES(?,?,?)`, u.ID, name, s.Now().Unix())
	if err != nil {
		return 0, "", err
	}
	if err := s.agentCall(r, rpc.MDBCreate, rpc.DBRef{Owner: u.Username, Name: name}, nil); err != nil {
		s.deleteRow(r.Context(), "databases", id)
		return 0, "", err
	}
	s.audit(r, "db.create", name, "", true)
	return id, name, nil
}

// dbWizard creates a database, a database user and the grant atomically:
// any failure undoes the earlier steps server-side, in reverse order, with
// its own context so a closed browser cannot stop the rollback (H-2).
func (s *Server) dbWizard(w http.ResponseWriter, r *http.Request) (any, error) {
	var in DBWizardReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	if n := s.prefixed(u, in.Name); len(n) > 64 {
		return nil, wizardStep(tooLong("name", 64-len(u.Username)-1), "db")
	} else if err := validate.DBName(u.Username, n); err != nil {
		return nil, wizardStep(badField(err.Error(), "name"), "db")
	}
	uname := s.prefixed(u, in.User)
	if len(uname) > 32 {
		return nil, wizardStep(tooLong("user", 32-len(u.Username)-1), "user")
	}
	if err := validate.DBUser(u.Username, uname); err != nil {
		return nil, wizardStep(badField(err.Error(), "user"), "user")
	}
	if uname == pmaUserName(u.Username) {
		return nil, wizardStep(bad("reserved_db_user"), "user")
	}
	if err := passwordErr(in.Password, "password"); err != nil {
		return nil, wizardStep(err, "user")
	}
	privs, err := grantList(in.Privileges, in.All)
	if err != nil {
		return nil, wizardStep(err, "grant")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Minute)
	defer cancel()
	r = r.WithContext(ctx)
	dbID, dbName, err := s.newDatabase(r, in.Name)
	if err != nil {
		return nil, wizardStep(err, "db")
	}
	var undoErrs []string
	undoDB := func() {
		if err := s.Agent.Call(ctx, rpc.MDBDrop, rpc.DBRef{Owner: u.Username, Name: dbName}, nil); err != nil {
			undoErrs = append(undoErrs, "db.drop: "+agentCode(err))
			return
		}
		s.deleteRow(ctx, "databases", dbID)
	}
	userID, userName, err := s.newDBUser(r, in.User, in.Password)
	if err != nil {
		undoDB()
		return nil, wizardErr(wizardStep(err, "user"), undoErrs)
	}
	if err := s.doGrant(r, u, dbID, dbName, userID, userName, privs); err != nil {
		if derr := s.Agent.Call(ctx, rpc.MDBUserDrop, rpc.DBUserRef{Owner: u.Username, User: userName}, nil); derr != nil {
			undoErrs = append(undoErrs, "db.user.drop: "+agentCode(derr))
		} else {
			s.deleteRow(ctx, "db_users", userID)
		}
		undoDB()
		return nil, wizardErr(wizardStep(err, "grant"), undoErrs)
	}
	s.audit(r, "db.wizard", dbName, userName, true)
	return map[string]any{"db": map[string]any{"id": dbID, "name": dbName}, "user": map[string]any{"id": userID, "name": userName},
		"privileges": privs}, nil
}

// wizardStep tags a client error with the wizard step that failed
// (step: db|user|grant) so the UI can return to that step.
func wizardStep(err error, step string) error {
	var ae *apiError
	var re *rpc.Error
	switch {
	case errors.As(err, &ae) && ae.Status < 500:
		st := ae.Status
		if st == 0 {
			st = 400
		}
		return &apiError{Status: st, Code: ae.Code, Message: ae.Message, Step: step, Field: ae.Field, Max: ae.Max}
	case errors.As(err, &re) && agentStatus(re.Code) < 500:
		return &apiError{Status: agentStatus(re.Code), Code: re.Code, Message: re.Message, Step: step}
	}
	return err
}

// wizardErr returns the step's error; when the rollback itself failed the
// caller gets 500 rollback_incomplete (with the request ID) instead, since
// something may be left behind.
func wizardErr(err error, undoErrs []string) error {
	if len(undoErrs) == 0 {
		return err
	}
	return &apiError{Status: 500, Code: "rollback_incomplete", Message: strings.Join(undoErrs, "; ")}
}

// grantList validates the requested privileges (handoff-ui H-4): ["ALL"] or
// all=true for full rights, otherwise a non-empty list. An empty list used
// to mean ALL PRIVILEGES and is now refused.
func grantList(list []string, all bool) ([]string, error) {
	if all {
		if len(list) > 0 && !(len(list) == 1 && strings.EqualFold(list[0], "ALL")) {
			return nil, bad("invalid_privilege")
		}
		return []string{"ALL"}, nil
	}
	if len(list) == 0 {
		return nil, bad("invalid_privilege")
	}
	if len(list) == 1 && strings.EqualFold(list[0], "ALL") {
		return []string{"ALL"}, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range list {
		p = strings.ToUpper(strings.TrimSpace(p))
		if !validate.DBPrivileges[p] {
			return nil, bad("invalid_privilege")
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

func (s *Server) deleteDatabase(w http.ResponseWriter, r *http.Request) (any, error) {
	d, err := store.One[store.Database](r.Context(), s.Store.DB, `SELECT *, '' AS users FROM databases WHERE id=? AND user_id=?`, idParam(r, "id"), userOf(r).ID)
	if err != nil {
		return nil, notFound()
	}
	if err := s.agentCall(r, rpc.MDBDrop, rpc.DBRef{Owner: userOf(r).Username, Name: d.Name}, nil); err != nil {
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM databases WHERE id=?`, d.ID); err != nil {
		return nil, err
	}
	s.audit(r, "db.delete", d.Name, "", true)
	return nil, nil
}

func (s *Server) createDBUser(w http.ResponseWriter, r *http.Request) (any, error) {
	var in DBUserReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	id, name, err := s.newDBUser(r, in.Name, in.Password)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "name": name}, nil
}

func (s *Server) newDBUser(r *http.Request, short, password string) (int64, string, error) {
	in := DBUserReq{Name: short, Password: password}
	u := userOf(r)
	name := s.prefixed(u, in.Name)
	if len(name) > 32 {
		return 0, "", tooLong("name", 32-len(u.Username)-1)
	}
	if err := validate.DBUser(u.Username, name); err != nil {
		return 0, "", badField(err.Error(), "name")
	}
	if name == pmaUserName(u.Username) {
		return 0, "", bad("reserved_db_user") // used by phpMyAdmin single sign-on
	}
	if err := passwordErr(in.Password, "password"); err != nil {
		return 0, "", err
	}
	id, err := s.insertLimited(r.Context(), Unlimited, "", "", nil,
		`SELECT COUNT(*) FROM db_users WHERE name=?`, []any{name},
		`INSERT INTO db_users(user_id,name,created_at) VALUES(?,?,?)`, u.ID, name, s.Now().Unix())
	if err != nil {
		return 0, "", err
	}
	if err := s.agentCall(r, rpc.MDBUserCreate, rpc.DBUser{Owner: u.Username, User: name, Password: in.Password}, nil); err != nil {
		s.deleteRow(r.Context(), "db_users", id)
		return 0, "", err
	}
	s.audit(r, "db.user_create", name, "", true)
	return id, name, nil
}

func (s *Server) ownDBUser(r *http.Request, id int64) (store.DBUser, error) {
	d, err := store.One[store.DBUser](r.Context(), s.Store.DB, `SELECT *, '' AS dbs FROM db_users WHERE id=? AND user_id=?`, id, userOf(r).ID)
	if err != nil {
		return d, notFound()
	}
	return d, nil
}

func (s *Server) dbUserPassword(w http.ResponseWriter, r *http.Request) (any, error) {
	var in PasswordReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	d, err := s.ownDBUser(r, idParam(r, "id"))
	if err != nil {
		return nil, err
	}
	if err := passwordErr(in.Password, "password"); err != nil {
		return nil, err
	}
	return nil, s.agentCall(r, rpc.MDBUserPassword, rpc.DBUser{Owner: userOf(r).Username, User: d.Name, Password: in.Password}, nil)
}

func (s *Server) deleteDBUser(w http.ResponseWriter, r *http.Request) (any, error) {
	d, err := s.ownDBUser(r, idParam(r, "id"))
	if err != nil {
		return nil, err
	}
	if err := s.agentCall(r, rpc.MDBUserDrop, rpc.DBUserRef{Owner: userOf(r).Username, User: d.Name}, nil); err != nil {
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM db_users WHERE id=?`, d.ID); err != nil {
		return nil, err
	}
	s.audit(r, "db.user_delete", d.Name, "", true)
	return nil, nil
}

func (s *Server) grantDB(w http.ResponseWriter, r *http.Request) (any, error) {
	var in GrantReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	d, err := store.One[store.Database](r.Context(), s.Store.DB, `SELECT *, '' AS users FROM databases WHERE id=? AND user_id=?`, in.DBID, u.ID)
	if err != nil {
		return nil, notFound()
	}
	du, err := s.ownDBUser(r, in.UserID)
	if err != nil {
		return nil, err
	}
	privs, err := grantList(in.Privileges, in.All)
	if err != nil {
		return nil, err
	}
	return nil, s.doGrant(r, u, d.ID, d.Name, du.ID, du.Name, privs)
}

func (s *Server) doGrant(r *http.Request, u *store.User, dbID int64, dbName string, userID int64, userName string, privs []string) error {
	if err := s.agentCall(r, rpc.MDBGrant, rpc.DBGrant{Owner: u.Username, DB: dbName, User: userName, Privileges: privs}, nil); err != nil {
		return err
	}
	p := strings.Join(privs, ",")
	if _, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO db_grants(db_id,dbuser_id,privileges) VALUES(?,?,?) ON CONFLICT(db_id,dbuser_id) DO UPDATE SET privileges=excluded.privileges`, dbID, userID, p); err != nil {
		return err
	}
	s.audit(r, "db.grant", dbName, userName+" "+p, true)
	return nil
}

func (s *Server) revokeDB(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	d, err := store.One[store.Database](r.Context(), s.Store.DB, `SELECT *, '' AS users FROM databases WHERE id=? AND user_id=?`, idParam(r, "db"), u.ID)
	if err != nil {
		return nil, notFound()
	}
	du, err := s.ownDBUser(r, idParam(r, "user"))
	if err != nil {
		return nil, err
	}
	if err := s.agentCall(r, rpc.MDBRevoke, rpc.DBGrant{Owner: u.Username, DB: d.Name, User: du.Name}, nil); err != nil {
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM db_grants WHERE db_id=? AND dbuser_id=?`, d.ID, du.ID); err != nil {
		return nil, err
	}
	s.audit(r, "db.revoke", d.Name, du.Name, true)
	return nil, nil
}

// phpMyAdminSSO creates a short-lived MariaDB user with access to all of the
// account's databases and a one-time token the signon script exchanges.
// The user is dropped and re-created on every call (no stale grants on
// databases that were deleted and re-created), recorded in pma_users and
// dropped by housekeeping after pmaUserTTL and on termination.
func (s *Server) phpMyAdminSSO(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	ctx := r.Context()
	name := pmaUserName(u.Username)
	pw := auth.RandomPassword(24)
	if err := s.agentCall(r, rpc.MDBUserDrop, rpc.DBUserRef{Owner: u.Username, User: name}, nil); err != nil {
		return nil, err
	}
	if err := s.agentCall(r, rpc.MDBUserCreate, rpc.DBUser{Owner: u.Username, User: name, Password: pw}, nil); err != nil {
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(ctx, `INSERT INTO pma_users(db_user,owner_id,created_at) VALUES(?,?,?)
		ON CONFLICT(db_user) DO UPDATE SET owner_id=excluded.owner_id, created_at=excluded.created_at`, name, u.ID, s.Now().Unix()); err != nil {
		return nil, err
	}
	dbs, err := store.Select[store.Database](ctx, s.Store.DB, `SELECT *, '' AS users FROM databases WHERE user_id=?`, u.ID)
	if err != nil {
		return nil, err
	}
	for _, d := range dbs {
		if err := s.agentCall(r, rpc.MDBGrant, rpc.DBGrant{Owner: u.Username, DB: d.Name, User: name, Privileges: []string{"ALL"}}, nil); err != nil {
			return nil, err
		}
	}
	tok := auth.RandomToken(24)
	// SEC-8: the MariaDB password is never stored in clear: it is sealed with
	// a key derived from the one-time token, of which only the hash is kept.
	sealed, err := auth.SealWithToken(tok, pw)
	if err != nil {
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(ctx, `INSERT INTO pma_tokens(hash,db_user,password,expires_at) VALUES(?,?,?,?)`,
		auth.SHA256Hex(tok), name, sealed, s.Now().Add(2*time.Minute).Unix()); err != nil {
		return nil, err
	}
	s.audit(r, "db.phpmyadmin", u.Username, "", true)
	return map[string]string{"url": "/3rdparty/phpMyAdmin/bpanel-signon.php?token=" + tok}, nil
}

// pmaTokenExchange is called by the signon PHP script over loopback only.
func (s *Server) pmaTokenExchange(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !net.ParseIP(host).IsLoopback() || r.Header.Get("X-Forwarded-For") != "" {
		writeJSON(w, 403, apiError{Code: "forbidden"})
		return
	}
	tok := chi.URLParam(r, "token")
	h := auth.SHA256Hex(tok)
	var user, pw string
	if err := s.Store.DB.QueryRow(`SELECT db_user, password FROM pma_tokens WHERE hash=? AND expires_at>?`, h, time.Now().Unix()).Scan(&user, &pw); err != nil {
		writeJSON(w, 404, apiError{Code: "invalid_token"})
		return
	}
	res, err := s.Store.DB.Exec(`DELETE FROM pma_tokens WHERE hash=?`, h)
	if err != nil {
		writeJSON(w, 500, apiError{Code: "internal_error"})
		return
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 { // single use, also under concurrency
		writeJSON(w, 404, apiError{Code: "invalid_token"})
		return
	}
	clear, err := auth.OpenWithToken(tok, pw)
	if err != nil {
		writeJSON(w, 404, apiError{Code: "invalid_token"})
		return
	}
	writeJSON(w, 200, map[string]string{"user": user, "password": clear})
}

// ---- files -----------------------------------------------------------------------------

func (s *Server) fileOp(w http.ResponseWriter, r *http.Request) (any, error) {
	var in rpc.FileOp
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	switch in.Op {
	case "list", "read", "write", "mkdir", "touch", "delete", "rename", "move", "copy", "chmod", "zip", "unzip":
	// upload/download/write_chunk/read_chunk only through the streaming endpoints
	default:
		return nil, badField("unknown_op", "op")
	}
	if len(in.Path) > 4096 {
		return nil, tooLong("path", 4096)
	}
	// names longer than NAME_MAX used to come back as 502 io_error; "." and
	// ".." as the new name as "already exists" (R2-UX-16)
	switch in.Op {
	case "mkdir", "touch", "write":
		if err := validate.FileOpPath(in.Path); err != nil {
			return nil, &apiError{Status: 400, Code: "invalid_filename", Field: "path", Max: 255}
		}
	case "rename", "move", "copy", "zip":
		if in.Dest != "" {
			if err := validate.FileOpPath(in.Dest); err != nil {
				return nil, &apiError{Status: 400, Code: "invalid_filename", Field: "dest", Max: 255}
			}
		}
	}
	in.User = userOf(r).Username
	var res rpc.FileResult
	if err := s.agentCall(r, rpc.MFiles, in, &res); err != nil {
		return nil, err
	}
	if in.Op != "list" && in.Op != "read" {
		s.audit(r, "files."+in.Op, in.Path, in.Dest, true)
	}
	return res, nil
}

// maxUploadRequest bounds one multipart upload request (several files).
const maxUploadRequest = validate.UploadMaxRequest

// fileUpload streams multipart files to the account's home in chunks
// (CODE-7): nothing is buffered whole in memory, every agent message stays
// small, and each file is written to a temporary name and renamed into place
// only when complete. Per-file limit: fileops.MaxUploadBytes.
func (s *Server) fileUpload(w http.ResponseWriter, r *http.Request) (any, error) {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(s.Now().Add(30 * time.Minute)) // not supported by every writer (tests)
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadRequest)
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, bad("bad_upload")
	}
	u := userOf(r)
	// R2-PERF-3: bounded parallel uploads, pooled chunk buffers
	release, ok := s.uploadGate.acquire(r.Context(), 0)
	if !ok {
		return nil, serverBusy()
	}
	defer release()
	dir := r.URL.Query().Get("path")
	haveDir := r.URL.Query().Has("path")
	var done []string
	bufp := getChunk(fileops.MaxChunkBytes)
	defer putChunk(bufp)
	buf := *bufp
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, uploadErr(err)
		}
		switch part.FormName() {
		case "path":
			b, err := io.ReadAll(io.LimitReader(part, 4097))
			if err != nil || len(b) > 4096 {
				return nil, bad("invalid_path")
			}
			dir, haveDir = string(b), true
			continue
		case "file":
		default:
			continue
		}
		if !haveDir {
			return nil, bad("path_must_precede_files")
		}
		name := part.FileName()
		if err := validate.FileName(name); err != nil {
			return nil, &apiError{Status: 400, Code: "invalid_filename", Field: "file", Max: 255}
		}
		if err := s.uploadOne(r, u, path.Join(dir, name), part, buf); err != nil {
			return nil, err
		}
		done = append(done, name)
	}
	s.audit(r, "files.upload", dir, strings.Join(done, ","), true)
	return map[string]any{"uploaded": done}, nil
}

func uploadErr(err error) error {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return &apiError{Status: 413, Code: "file_too_large"}
	}
	return bad("bad_upload")
}

// uploadOne lives in shield.go (v0.4: uploads go through the Shield staging pipeline).

// fileDownload streams a file in chunks (CODE-7); headers are sent after the
// first chunk succeeds, so errors before that are proper JSON errors.
func (s *Server) fileDownload(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(s.Now().Add(60 * time.Minute))
	p := r.URL.Query().Get("path")
	u := userOf(r)
	var res rpc.FileResult
	if err := s.agentCall(r, rpc.MFiles, rpc.FileOp{User: u.Username, Op: "read_chunk", Path: p, Offset: 0, Length: fileops.MaxChunkBytes}, &res); err != nil {
		s.fail(w, r, err)
		return
	}
	b, err := base64.StdEncoding.DecodeString(res.Content)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	total := res.Size
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": path.Base(p)}))
	w.Header().Set("Content-Length", strconv.FormatInt(total, 10))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	off := int64(0)
	for {
		if _, err := w.Write(b); err != nil {
			return // client went away
		}
		off += int64(len(b))
		if off >= total || len(b) == 0 {
			return
		}
		res = rpc.FileResult{}
		if err := s.agentCall(r, rpc.MFiles, rpc.FileOp{User: u.Username, Op: "read_chunk", Path: p, Offset: off, Length: fileops.MaxChunkBytes}, &res); err != nil {
			s.Log.Warn("download aborted", "path", p, "err", err)
			panic(http.ErrAbortHandler) // headers are out: abort the response
		}
		if b, err = base64.StdEncoding.DecodeString(res.Content); err != nil || res.Size != total {
			s.Log.Warn("download aborted: file changed", "path", p)
			panic(http.ErrAbortHandler)
		}
	}
}

// ---- FTP --------------------------------------------------------------------------------

func (s *Server) listFTP(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	accts, err := store.Select[store.FTPAccount](r.Context(), s.Store.DB, `SELECT * FROM ftp_accounts WHERE user_id=? ORDER BY login`, u.ID)
	if err != nil {
		return nil, err
	}
	host := s.Cfg.Hostname
	return map[string]any{"accounts": accts, "server": host, "ftp_port": 21, "sftp_port": 22, "sftp_user": u.Username}, nil
}

func (s *Server) createFTP(w http.ResponseWriter, r *http.Request) (any, error) {
	var in FTPReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	pkg := s.packageOf(r.Context(), u)
	d, err := s.ownDomainByName(r, in.Domain)
	if err != nil {
		return nil, bad("invalid_domain")
	}
	local := strings.ToLower(strings.TrimSpace(in.Login))
	if err := maxLen("login", local, 32); err != nil {
		return nil, err
	}
	if err := validate.FTPLocal(local); err != nil {
		return nil, badField("invalid_ftp_login", "login")
	}
	if err := passwordErr(in.Password, "password"); err != nil {
		return nil, err
	}
	// strict grammar: the directory goes into Pure-FTPd's colon-separated
	// passwd file (SEC-9); private dirs (~/etc, ~/mail, ...) refused (R2-UX-13)
	dir, err := validate.FTPDir(strings.TrimSpace(in.Dir))
	if err != nil {
		return nil, fieldErr(err, "dir", 255)
	}
	quota := in.QuotaMB.or(Unlimited)
	if err := checkSize("quota_mb", quota, maxSizeMB); err != nil {
		return nil, err
	}
	login := local + "@" + d.Name
	id, err := s.insertLimited(r.Context(), pkg.MaxFTP, "ftp_accounts", `SELECT COUNT(*) FROM ftp_accounts WHERE user_id=?`, []any{u.ID},
		`SELECT COUNT(*) FROM ftp_accounts WHERE login=?`, []any{login},
		`INSERT INTO ftp_accounts(user_id,login,dir,quota_mb,created_at) VALUES(?,?,?,?,?)`, u.ID, login, dir, quota, s.Now().Unix())
	if err != nil {
		return nil, err
	}
	if err := s.agentCall(r, rpc.MFTPCreate, rpc.FTPAccount{User: u.Username, Login: login, Password: in.Password, Dir: dir, QuotaMB: agentLimit(quota)}, nil); err != nil {
		s.deleteRow(r.Context(), "ftp_accounts", id)
		return nil, err
	}
	s.audit(r, "ftp.create", login, dir, true)
	return map[string]any{"id": id, "login": login}, nil
}

func (s *Server) ownFTP(r *http.Request) (store.FTPAccount, error) {
	f, err := store.One[store.FTPAccount](r.Context(), s.Store.DB, `SELECT * FROM ftp_accounts WHERE id=? AND user_id=?`, idParam(r, "id"), userOf(r).ID)
	if err != nil {
		return f, notFound()
	}
	return f, nil
}

func (s *Server) ftpPassword(w http.ResponseWriter, r *http.Request) (any, error) {
	var in PasswordReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	f, err := s.ownFTP(r)
	if err != nil {
		return nil, err
	}
	if err := passwordErr(in.Password, "password"); err != nil {
		return nil, err
	}
	return nil, s.agentCall(r, rpc.MFTPPassword, rpc.FTPAccount{User: userOf(r).Username, Login: f.Login, Password: in.Password}, nil)
}

func (s *Server) deleteFTP(w http.ResponseWriter, r *http.Request) (any, error) {
	f, err := s.ownFTP(r)
	if err != nil {
		return nil, err
	}
	if err := s.agentCall(r, rpc.MFTPDelete, rpc.FTPRef{Owner: userOf(r).Username, Login: f.Login}, nil); err != nil {
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM ftp_accounts WHERE id=?`, f.ID); err != nil {
		return nil, err
	}
	s.audit(r, "ftp.delete", f.Login, "", true)
	return nil, nil
}

// ---- cron -----------------------------------------------------------------------------

func (s *Server) listCron(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	jobs, err := store.Select[store.CronJob](r.Context(), s.Store.DB, `SELECT * FROM cron_jobs WHERE user_id=? ORDER BY id`, u.ID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"jobs": jobs, "email": s.Store.Get(fmt.Sprintf("cron_email:%d", u.ID), u.Email)}, nil
}

func (s *Server) syncCron(r *http.Request) error {
	u := userOf(r)
	jobs, err := store.Select[store.CronJob](r.Context(), s.Store.DB, `SELECT * FROM cron_jobs WHERE user_id=? ORDER BY id`, u.ID)
	if err != nil {
		return err
	}
	set := rpc.CronSet{User: u.Username, Email: s.Store.Get(fmt.Sprintf("cron_email:%d", u.ID), u.Email)}
	for _, j := range jobs {
		set.Entries = append(set.Entries, rpc.CronEntry{Schedule: [5]string{j.Minute, j.Hour, j.Dom, j.Month, j.Dow}, Command: j.Command})
	}
	return s.agentCall(r, rpc.MCronSet, set, nil)
}

func (s *Server) createCron(w http.ResponseWriter, r *http.Request) (any, error) {
	var in CronReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	// " 5 " is 5 (R2-UX-14); a value is never cut (R2-UX-10)
	for i, f := range []struct {
		k string
		v *string
	}{{"minute", &in.Minute}, {"hour", &in.Hour}, {"dom", &in.Dom}, {"month", &in.Month}, {"dow", &in.Dow}} {
		*f.v = strings.TrimSpace(*f.v)
		if len(*f.v) > 40 {
			return nil, tooLong(f.k, 40)
		}
		one := []string{"*", "*", "*", "*", "*"}
		one[i] = *f.v
		if err := validate.CronSchedule(one); err != nil {
			return nil, badField("invalid_cron", f.k)
		}
	}
	if err := validate.CronSchedule([]string{in.Minute, in.Hour, in.Dom, in.Month, in.Dow}); err != nil {
		return nil, bad("invalid_cron")
	}
	if len(in.Command) > 1000 {
		return nil, tooLong("command", 1000)
	}
	if err := validate.CronCommand(in.Command); err != nil {
		return nil, badField("invalid_cron_command", "command")
	}
	u := userOf(r)
	id, err := s.insertLimited(r.Context(), 100, "cron_jobs", `SELECT COUNT(*) FROM cron_jobs WHERE user_id=?`, []any{u.ID}, "", nil,
		`INSERT INTO cron_jobs(user_id,minute,hour,dom,month,dow,command,created_at) VALUES(?,?,?,?,?,?,?,?)`,
		u.ID, in.Minute, in.Hour, in.Dom, in.Month, in.Dow, in.Command, s.Now().Unix())
	if err != nil {
		return nil, err
	}
	if err := s.syncCron(r); err != nil {
		s.deleteRow(r.Context(), "cron_jobs", id)
		return nil, err
	}
	s.audit(r, "cron.create", in.Command, "", true)
	return map[string]any{"id": id}, nil
}

func (s *Server) deleteCron(w http.ResponseWriter, r *http.Request) (any, error) {
	res, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM cron_jobs WHERE id=? AND user_id=?`, idParam(r, "id"), userOf(r).ID)
	if err != nil { // never touch res when Exec failed (CODE-11)
		return nil, err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return nil, notFound()
	}
	if err := s.syncCron(r); err != nil {
		return nil, err
	}
	s.audit(r, "cron.delete", chi.URLParam(r, "id"), "", true)
	return nil, nil
}

func (s *Server) cronEmail(w http.ResponseWriter, r *http.Request) (any, error) {
	var in CronEmailReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	in.Email = strings.TrimSpace(in.Email)
	if err := maxLen("email", in.Email, 254); err != nil {
		return nil, err
	}
	if in.Email != "" && validate.Email(in.Email) != nil {
		return nil, badField("invalid_email", "email")
	}
	if err := s.Store.Set(fmt.Sprintf("cron_email:%d", userOf(r).ID), in.Email); err != nil {
		return nil, err
	}
	return nil, s.syncCron(r)
}

// ---- SSL ---------------------------------------------------------------------------------

func (s *Server) sslStatus(w http.ResponseWriter, r *http.Request) (any, error) {
	doms, err := s.domainsOf(r.Context(), userOf(r).ID)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for _, d := range doms {
		if d.Kind == "alias" {
			continue
		}
		var info rpc.SSLInfo
		if err := s.agentCall(r, rpc.MSSLInfo, rpc.DomainRef{Owner: userOf(r).Username, Domain: d.Name}, &info); err != nil {
			s.Log.Info("ssl info", "domain", d.Name, "err", err)
		}
		out = append(out, map[string]any{"id": d.ID, "domain": d.Name, "kind": d.Kind, "status": d.SSLStatus, "cert": info})
	}
	return out, nil
}

func (s *Server) runAutoSSL(w http.ResponseWriter, r *http.Request) (any, error) {
	var in SSLReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	d, err := s.ownDomain(r, in.DomainID)
	if err != nil || d.Kind == "alias" {
		return nil, notFound()
	}
	u := userOf(r)
	info, err := s.issueSSL(r.Context(), u, d)
	if err != nil {
		s.audit(r, "ssl.autossl", d.Name, agentCode(err), false)
		return nil, err
	}
	s.audit(r, "ssl.autossl", d.Name, info.NotAfter, true)
	return info, nil
}

// ---- PHP / disk / logs -----------------------------------------------------------------------

func (s *Server) userPHP(w http.ResponseWriter, r *http.Request) (any, error) {
	var v rpc.PHPVersionsResult
	if err := s.agentCall(r, rpc.MPHPVersions, rpc.Empty{}, &v); err != nil {
		return nil, err
	}
	doms, _ := s.domainsOf(r.Context(), userOf(r).ID)
	type row struct {
		ID        int64  `json:"id"`
		Domain    string `json:"domain"`
		Version   string `json:"version"`
		Inherited bool   `json:"inherited"`
	}
	var rows []row
	u := userOf(r)
	for _, d := range doms {
		if d.Kind == "alias" {
			continue
		}
		rows = append(rows, row{d.ID, d.Name, s.phpFor(u, d), d.PHPVersion == ""})
	}
	return map[string]any{"versions": v.Versions, "domains": rows, "default": s.Store.Get("default_php", "8.3")}, nil
}

func (s *Server) diskUsage(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	var du rpc.DiskUsage
	if err := s.agentCall(r, rpc.MDiskUsage, rpc.DiskUsageReq{User: u.Username}, &du); err != nil {
		return nil, err
	}
	var sizes rpc.DBSizes
	if err := s.agentCall(r, rpc.MDBSizes, rpc.DBSizesReq{Prefix: u.Username}, &sizes); err != nil {
		s.Log.Info("db sizes", "err", err)
	}
	pkg := s.packageOf(r.Context(), u)
	return map[string]any{"usage": du, "databases": sizes.Sizes, "quota_bytes": bytesLimit(pkg.DiskMB)}, nil
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) (any, error) {
	q := r.URL.Query()
	u := userOf(r)
	domain := q.Get("domain")
	if domain == "" {
		domain = u.PrimaryDomain
	}
	d, err := s.ownDomainByName(r, domain)
	if err != nil || d.Kind == "alias" {
		return nil, notFound()
	}
	var out rpc.LogLines
	if err := s.agentCall(r, rpc.MLogTail, rpc.LogTail{User: u.Username, Domain: d.Name, Kind: q.Get("kind"), Lines: 300}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- backups ---------------------------------------------------------------------------------

func (s *Server) listBackups(w http.ResponseWriter, r *http.Request) (any, error) {
	var out rpc.BackupList
	if err := s.agentCall(r, rpc.MBackupList, rpc.AccountRef{User: userOf(r).Username}, &out); err != nil {
		return nil, err
	}
	if out.Snapshots == nil {
		out.Snapshots = []rpc.BackupSnapshot{}
	}
	return out, nil
}

func (s *Server) runBackup(w http.ResponseWriter, r *http.Request) (any, error) {
	var in BackupReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	req := rpc.BackupRun{User: u.Username}
	if in.Databases {
		dbs, err := store.Select[store.Database](r.Context(), s.Store.DB, `SELECT *, '' AS users FROM databases WHERE user_id=?`, u.ID)
		if err != nil {
			return nil, err
		}
		for _, d := range dbs {
			req.Databases = append(req.Databases, d.Name)
		}
	}
	var out rpc.BackupRunResult
	if err := s.agentCall(r, rpc.MBackupRun, req, &out); err != nil {
		s.audit(r, "backup.run", u.Username, agentCode(err), false)
		return nil, err
	}
	s.audit(r, "backup.run", u.Username, strings.Join(out.SnapshotIDs, ","), true)
	return out, nil
}

func (s *Server) restoreBackup(w http.ResponseWriter, r *http.Request) (any, error) {
	var in RestoreReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := validate.Snapshot(in.Snapshot); err != nil {
		return nil, bad("invalid_snapshot")
	}
	u := userOf(r)
	if db, ok := strings.CutPrefix(in.Path, "db:"); ok {
		if s.count(`SELECT COUNT(*) FROM databases WHERE name=? AND user_id=?`, db, u.ID) == 0 {
			return nil, notFound()
		}
	} else if _, err := validate.FilePath(in.Path); err != nil {
		return nil, bad("invalid_path")
	}
	var out rpc.BackupRestoreResult
	if err := s.agentCall(r, rpc.MBackupRestore, rpc.BackupRestore{User: u.Username, Snapshot: in.Snapshot, Path: in.Path, InPlace: in.InPlace}, &out); err != nil {
		s.audit(r, "backup.restore", in.Snapshot, agentCode(err), false)
		return nil, err
	}
	s.audit(r, "backup.restore", in.Snapshot, in.Path+" -> "+out.RestoredTo, true)
	return out, nil
}
