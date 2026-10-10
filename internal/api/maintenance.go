package api

import (
	"context"
	"strconv"
	"strings"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/store"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// ---- phpMyAdmin SSO users ------------------------------------------------------

// pmaUserTTL is how long a phpMyAdmin single-sign-on MariaDB user lives.
const pmaUserTTL = 4 * time.Hour

func pmaUserName(username string) string {
	n := username + "_pma"
	if len(n) > 32 {
		n = n[:32]
	}
	return n
}

// prunePMAUsers drops phpMyAdmin SSO MariaDB users older than ttl, so their
// grants do not linger (and do not apply to a later database with the same
// name).
func (s *Server) prunePMAUsers(ctx context.Context, ttl time.Duration) {
	type row struct {
		DBUser  string `db:"db_user"`
		OwnerID int64  `db:"owner_id"`
	}
	rows, err := store.Select[row](ctx, s.Store.DB, `SELECT db_user, owner_id FROM pma_users WHERE created_at<?`, s.Now().Add(-ttl).Unix())
	if err != nil {
		s.Log.Warn("pma cleanup", "err", err)
		return
	}
	for _, r := range rows {
		owner, _, _ := strings.Cut(r.DBUser, "_")
		if err := s.Agent.Call(ctx, rpc.MDBUserDrop, rpc.DBUserRef{Owner: owner, User: r.DBUser}, nil); err != nil {
			s.Log.Warn("pma cleanup: drop user", "user", r.DBUser, "err", err)
			continue
		}
		if _, err := s.Store.DB.ExecContext(ctx, `DELETE FROM pma_users WHERE db_user=?`, r.DBUser); err != nil {
			s.Log.Warn("pma cleanup", "err", err)
		}
	}
}

// ---- AutoSSL (CODE-6 / SYS-4) --------------------------------------------------

// sslRenewBefore: certificates expiring sooner than this are renewed.
const sslRenewBefore = 30 * 24 * time.Hour

// sslRetryFailed: a failed domain is retried at most this often.
const sslRetryFailed = 24 * time.Hour

// issueSSL obtains a certificate for one site (domain + www + aliases),
// records the outcome and re-applies the account's vhosts so nginx serves it.
func (s *Server) issueSSL(ctx context.Context, u *store.User, d store.Domain) (rpc.SSLInfo, error) {
	var sans []string
	if d.Kind != "sub" {
		sans = append(sans, "www."+d.Name)
	}
	aliases, err := store.Select[store.Domain](ctx, s.Store.DB, `SELECT *, '' AS parent_name FROM domains WHERE parent_id=? AND kind='alias'`, d.ID)
	if err != nil {
		return rpc.SSLInfo{}, err
	}
	for _, a := range aliases {
		sans = append(sans, a.Name, "www."+a.Name)
	}
	email := s.Store.Get("acme_email", u.Email)
	now := s.Now().Unix()
	var info rpc.SSLInfo
	if err := s.Agent.Call(ctx, rpc.MSSLIssue, rpc.SSLIssue{User: u.Username, Domain: d.Name, SANs: sans, Email: email}, &info); err != nil {
		status := "failed"
		if d.SSLStatus == "active" {
			status = "active" // keep serving the old certificate until it expires
		}
		msg := err.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
		if _, derr := s.Store.DB.ExecContext(context.WithoutCancel(ctx), `UPDATE domains SET ssl_status=?, ssl_attempt_at=?, ssl_error=? WHERE id=?`, status, now, msg, d.ID); derr != nil {
			s.Log.Warn("autossl bookkeeping", "err", derr)
		}
		return info, err
	}
	if _, err := s.Store.DB.ExecContext(ctx, `UPDATE domains SET ssl_status='active', ssl_expires=?, ssl_attempt_at=?, ssl_error='' WHERE id=?`, info.NotAfter, now, d.ID); err != nil {
		return info, err
	}
	return info, s.applyWeb(ctx, u)
}

// renewHostnameCert renews the panel hostname certificate (R2-WB-5): it
// was issued once by the installer and never renewed. A Let's Encrypt
// certificate is renewed sslRenewBefore its expiry; a self-signed fallback
// is replaced by a real one, tried at most once a day. The agent copies it
// to the panel, Postfix, Dovecot and Pure-FTPd and reloads them.
func (s *Server) renewHostnameCert(ctx context.Context) {
	host := s.Cfg.Hostname
	if host == "" || s.Cfg.Dev || validate.Domain(host) != nil {
		return
	}
	var info rpc.SSLInfo
	if err := s.Agent.Call(ctx, rpc.MSSLInfo, rpc.DomainRef{Domain: host}, &info); err != nil {
		s.Log.Info("hostname cert: info", "err", err)
		return
	}
	now := s.Now()
	due := !info.Present || info.SelfSigned
	if info.Present && !info.SelfSigned {
		exp, err := time.Parse(time.RFC3339, info.NotAfter)
		due = err != nil || exp.Sub(now) < sslRenewBefore
	}
	if !due {
		return
	}
	if last, err := strconv.ParseInt(s.Store.Get("hostname_ssl_attempt_at", "0"), 10, 64); err == nil && now.Sub(time.Unix(last, 0)) < sslRetryFailed {
		return
	}
	if err := s.Store.Set("hostname_ssl_attempt_at", strconv.FormatInt(now.Unix(), 10)); err != nil {
		s.Log.Warn("hostname cert bookkeeping", "err", err)
	}
	cctx, cancel := context.WithTimeout(ctx, rpc.MethodTimeout(rpc.MSSLIssue)+time.Minute)
	defer cancel()
	var out rpc.SSLInfo
	err := s.Agent.Call(cctx, rpc.MSSLIssue, rpc.SSLIssue{Domain: host, Email: s.Store.Get("acme_email", s.Store.Get("contact_email", ""))}, &out)
	if err != nil {
		s.Log.Warn("hostname certificate renewal failed", "host", host, "err", err)
		s.auditSystem("ssl.renew_hostname", host, agentCode(err), false)
		return
	}
	s.auditSystem("ssl.renew_hostname", host, out.NotAfter, true)
}

// autoSSLRun renews certificates that expire within sslRenewBefore and
// retries failed domains once a day. Runs from the housekeeping loop.
func (s *Server) autoSSLRun(ctx context.Context) {
	if s.Store.Get("feature_autossl", "1") != "1" {
		return
	}
	s.renewHostnameCert(ctx)
	doms, err := store.Select[store.Domain](ctx, s.Store.DB, `SELECT d.*, '' AS parent_name FROM domains d JOIN users u ON u.id=d.user_id
		WHERE d.kind<>'alias' AND u.status='active' AND d.ssl_status IN ('active','failed')`)
	if err != nil {
		s.Log.Warn("autossl", "err", err)
		return
	}
	now := s.Now()
	for _, d := range doms {
		if ctx.Err() != nil {
			return
		}
		due := false
		switch d.SSLStatus {
		case "active":
			exp, err := time.Parse(time.RFC3339, d.SSLExpires)
			due = err != nil || exp.Sub(now) < sslRenewBefore
		case "failed":
			due = now.Sub(time.Unix(d.SSLAttemptAt, 0)) >= sslRetryFailed
		}
		if !due || (d.SSLAttemptAt > 0 && now.Sub(time.Unix(d.SSLAttemptAt, 0)) < 6*time.Hour) {
			continue
		}
		u, err := s.userByID(ctx, d.UserID)
		if err != nil {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, rpc.MethodTimeout(rpc.MSSLIssue)+time.Minute)
		info, err := s.issueSSL(cctx, &u, d)
		cancel()
		if err != nil {
			s.Log.Warn("autossl renewal failed", "domain", d.Name, "err", err)
			s.auditSystem("ssl.renew", d.Name, err.Error(), false)
			continue
		}
		s.auditSystem("ssl.renew", d.Name, info.NotAfter, true)
	}
}

// auditSystem writes an audit row for background jobs.
func (s *Server) auditSystem(action, target, detail string, ok bool) {
	if _, err := s.Store.DB.Exec(`INSERT INTO audit_log(at,actor_id,actor,ip,realm,action,target,detail,ok) VALUES(?,?,?,?,?,?,?,?,?)`,
		s.Now().Unix(), 0, "system", "", "", action, target, detail, ok); err != nil {
		s.Log.Error("audit write", "err", err)
	}
}
