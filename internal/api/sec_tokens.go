package api

// v0.4 security foundation (part C): personal API tokens, MFA recovery codes,
// session management.
//
// API tokens: `Authorization: Bearer bpt_<64 hex>`. Only sha256(token) is
// stored; the plaintext is returned once at creation. A token carries a
// permission subset of its owner's role; every check intersects the two
// (hasPerm). Token requests are CSRF-exempt (no ambient credential), never
// count as "recent authentication", and may not use /auth/* or /account/*
// except GET /auth/me (so a token can neither mint tokens nor manage
// sessions). The plaintext token is never logged: rejections log the 12-char
// prefix only, and redact.String covers the bpt_ class.

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cumabozkurt/bpanel/internal/auth"
	"github.com/cumabozkurt/bpanel/internal/rbac"
	"github.com/cumabozkurt/bpanel/internal/store"
)

const (
	apiTokenPrefix    = "bpt_"
	maxTokensPerUser  = 50
	recoveryCodeCount = 10
	tokenTouchEvery   = 60 // seconds between last_used_at writes
)

// kToken is the context key of the authenticating API token (tokenCtx).
const kToken ctxKey = 100

type tokenCtx struct {
	ID    int64
	Perms map[string]bool
}

func tokenOf(r *http.Request) *tokenCtx { v, _ := r.Context().Value(kToken).(*tokenCtx); return v }

// hasPerm: role permission AND (for token requests) token permission.
func hasPerm(r *http.Request, perm string) bool {
	if !rbac.Has(roleOf(r), perm) {
		return false
	}
	if t := tokenOf(r); t != nil {
		return t.Perms[perm]
	}
	return true
}

type apiToken struct {
	ID         int64  `db:"id" json:"id"`
	UserID     int64  `db:"user_id" json:"-"`
	Name       string `db:"name" json:"name"`
	Hash       string `db:"hash" json:"-"`
	Prefix     string `db:"prefix" json:"prefix"`
	Perms      string `db:"perms" json:"-"`
	IPAllow    string `db:"ip_allow" json:"-"`
	ExpiresAt  int64  `db:"expires_at" json:"expires_at"`
	LastUsedAt int64  `db:"last_used_at" json:"last_used_at"`
	CreatedAt  int64  `db:"created_at" json:"created_at"`
	RevokedAt  int64  `db:"revoked_at" json:"revoked_at"`
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ipAllowed: empty list = any address; entries are CIDRs or single IPs.
func ipAllowed(list, ip string) bool {
	entries := splitList(list)
	if len(entries) == 0 {
		return true
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, e := range entries {
		if p, err := netip.ParsePrefix(e); err == nil && p.Masked().Contains(a) {
			return true
		}
		if b, err := netip.ParseAddr(e); err == nil && b.Unmap() == a {
			return true
		}
	}
	return false
}

func tokenUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="bpanel"`)
	writeJSON(w, 401, apiError{Code: "invalid_api_token"})
}

// tokenRouteAllowed: tokens may not drive the auth/account surface.
func tokenRouteAllowed(r *http.Request) bool {
	p := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if p == "/auth/me" && r.Method == http.MethodGet {
		return true
	}
	return !strings.HasPrefix(p, "/auth/") && !strings.HasPrefix(p, "/account/") && p != "/auth" && p != "/account"
}

// loadBearer authenticates `Authorization: Bearer bpt_...` (installed right
// after loadSession). A request carrying a bearer header never falls back to
// the cookie.
func (s *Server) loadBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if h == "" {
			next.ServeHTTP(w, r)
			return
		}
		scheme, tok, _ := strings.Cut(h, " ")
		tok = strings.TrimSpace(tok)
		if !strings.EqualFold(scheme, "Bearer") || !strings.HasPrefix(tok, apiTokenPrefix) || len(tok) > 200 {
			tokenUnauthorized(w)
			return
		}
		ip := s.clientIP(r)
		pfx := tok[:min(len(tok), 12)]
		if !s.loginIP.Allow("tok:" + ip) {
			w.Header().Set("Retry-After", "10")
			writeJSON(w, 429, apiError{Code: "rate_limited"})
			return
		}
		t, err := store.One[apiToken](r.Context(), s.Store.R, `SELECT * FROM api_tokens WHERE hash=?`, auth.SHA256Hex(tok))
		now := time.Now().Unix()
		reason := ""
		switch {
		case err != nil:
			reason = "unknown"
		case t.RevokedAt != 0:
			reason = "revoked"
		case t.ExpiresAt != 0 && t.ExpiresAt <= now:
			reason = "expired"
		case !ipAllowed(t.IPAllow, ip):
			reason = "ip not allowed"
		}
		var u store.User
		if reason == "" {
			u, err = s.userByID(r.Context(), t.UserID)
			if err != nil || u.Status != "active" || !s.realmAllows(realmOf(r), u.Role) {
				reason = "owner inactive or wrong realm"
			}
		}
		if reason != "" {
			s.Log.Warn("api token rejected", "prefix", pfx, "ip", ip, "reason", reason)
			tokenUnauthorized(w)
			return
		}
		if !tokenRouteAllowed(r) {
			writeJSON(w, 403, apiError{Code: "token_not_allowed"})
			return
		}
		if now-t.LastUsedAt >= tokenTouchEvery {
			if _, err := s.Store.DB.Exec(`UPDATE api_tokens SET last_used_at=? WHERE id=?`, now, t.ID); err != nil {
				s.Log.Warn("token touch", "err", err)
			}
		}
		perms := map[string]bool{}
		for _, p := range splitList(t.Perms) {
			perms[p] = true
		}
		ss := &store.Session{IDHash: "token:" + t.Prefix, UserID: u.ID, Realm: realmOf(r), IP: ip,
			UserAgent: r.UserAgent(), CreatedAt: 0, ExpiresAt: t.ExpiresAt, LastSeen: now}
		ctx := context.WithValue(r.Context(), kSession, ss)
		ctx = context.WithValue(ctx, kUser, &u)
		ctx = context.WithValue(ctx, kToken, &tokenCtx{ID: t.ID, Perms: perms})
		r = r.WithContext(ctx)
		// Non-admin API paths: hosting.read for safe methods, hosting.write otherwise.
		if p := strings.TrimPrefix(r.URL.Path, "/api/v1"); !strings.HasPrefix(p, "/admin") && p != "/auth/me" {
			need := rbac.HostingRead
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
			default:
				need = rbac.HostingWrite
			}
			if !hasPerm(r, need) {
				permDenied(w)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ---- routes ------------------------------------------------------------------

// mountSecAccount adds the token / recovery-code / session endpoints to the
// account group (both realms).
func (s *Server) mountSecAccount(r chi.Router) {
	s.op(r, "GET", "/account/tokens", "account", "List own API tokens", nil, s.h(s.listTokens))
	r.With(s.requireRecentAuth(0)).Group(func(g chi.Router) {
		s.op(g, "POST", "/account/tokens", "account", "Create an API token (recent auth; shown once)", TokenCreateReq{}, s.h(s.createToken))
		s.op(g, "POST", "/account/mfa/recovery", "account", "Generate 10 MFA recovery codes (recent auth; shown once)", nil, s.h(s.genRecovery))
	})
	s.op(r, "DELETE", "/account/tokens/{id}", "account", "Revoke an own API token", nil, s.h(s.revokeToken))
	s.op(r, "GET", "/account/mfa/recovery", "account", "Number of unused recovery codes", nil, s.h(s.recoveryCount))
	s.op(r, "GET", "/account/sessions", "account", "List own active sessions", nil, s.h(s.listSessions))
	s.op(r, "DELETE", "/account/sessions", "account", "End all own sessions except the current one", nil, s.h(s.revokeOtherSessions))
	s.op(r, "DELETE", "/account/sessions/{id}", "account", "End one own session (id = prefix from the list)", nil, s.h(s.revokeSession))
}

// mountSecAdmin adds the admin session-revocation endpoint.
func (s *Server) mountSecAdmin(r chi.Router) {
	s.opPerm(r, rbac.SessionsRevoke, "DELETE", "/admin/users/{id}/sessions", "admin", "End every session of a user", nil, s.h(s.adminRevokeSessions))
}

// ---- tokens ------------------------------------------------------------------

type TokenCreateReq struct {
	Name      string   `json:"name"`
	Perms     []string `json:"perms"`
	ExpiresAt int64    `json:"expires_at,omitempty"` // unix seconds, 0 = never
	IPAllow   []string `json:"ip_allow,omitempty"`   // CIDRs or IPs, v4/v6
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) (any, error) {
	var in TokenCreateReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	role := roleOf(r)
	if !rbac.Has(role, rbac.TokensSelf) {
		return nil, &apiError{Status: 403, Code: "permission_denied"}
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		return nil, &apiError{Status: 400, Code: "bad_params", Field: "name"}
	}
	if len(in.Perms) == 0 || len(in.Perms) > len(rbac.Catalogue) {
		return nil, &apiError{Status: 400, Code: "invalid_perms", Field: "perms"}
	}
	seen := map[string]bool{}
	var perms []string
	for _, p := range in.Perms {
		if !rbac.Known(p) || !rbac.Has(role, p) || p == rbac.TokensSelf {
			return nil, &apiError{Status: 400, Code: "invalid_perms", Field: "perms", Message: p}
		}
		if !seen[p] {
			seen[p] = true
			perms = append(perms, p)
		}
	}
	slices.Sort(perms)
	now := time.Now().Unix()
	if in.ExpiresAt != 0 && in.ExpiresAt <= now {
		return nil, &apiError{Status: 400, Code: "bad_params", Field: "expires_at"}
	}
	if len(in.IPAllow) > 32 {
		return nil, &apiError{Status: 400, Code: "invalid_cidr", Field: "ip_allow"}
	}
	var cidrs []string
	for _, c := range in.IPAllow {
		c = strings.TrimSpace(c)
		if p, err := netip.ParsePrefix(c); err == nil {
			cidrs = append(cidrs, p.Masked().String())
		} else if a, err := netip.ParseAddr(c); err == nil {
			cidrs = append(cidrs, a.Unmap().String())
		} else {
			return nil, &apiError{Status: 400, Code: "invalid_cidr", Field: "ip_allow", Message: truncLog(c)}
		}
	}
	var n int
	if err := s.Store.DB.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE user_id=? AND revoked_at=0`, u.ID).Scan(&n); err != nil {
		return nil, err
	}
	if n >= maxTokensPerUser {
		return nil, limitReached("api_tokens")
	}
	tok := apiTokenPrefix + auth.RandomToken(32)
	prefix := tok[:12]
	res, err := s.Store.DB.Exec(`INSERT INTO api_tokens(user_id,name,hash,prefix,perms,ip_allow,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)`,
		u.ID, in.Name, auth.SHA256Hex(tok), prefix, strings.Join(perms, ","), strings.Join(cidrs, ","), in.ExpiresAt, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	s.audit(r, "account.token_create", u.Username, in.Name+" "+prefix, true)
	return map[string]any{"id": id, "name": in.Name, "prefix": prefix, "token": tok, "perms": perms,
		"ip_allow": cidrs, "expires_at": in.ExpiresAt, "created_at": now}, nil
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	ts, err := store.Select[apiToken](r.Context(), s.Store.R, `SELECT * FROM api_tokens WHERE user_id=? ORDER BY id DESC`, u.ID)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(ts))
	now := time.Now().Unix()
	for _, t := range ts {
		st := "active"
		switch {
		case t.RevokedAt != 0:
			st = "revoked"
		case t.ExpiresAt != 0 && t.ExpiresAt <= now:
			st = "expired"
		}
		out = append(out, map[string]any{"id": t.ID, "name": t.Name, "prefix": t.Prefix, "perms": nonNil(splitList(t.Perms)),
			"ip_allow": nonNil(splitList(t.IPAllow)), "expires_at": t.ExpiresAt, "last_used_at": t.LastUsedAt,
			"created_at": t.CreatedAt, "revoked_at": t.RevokedAt, "status": st})
	}
	return map[string]any{"tokens": out}, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	id := idParam(r, "id")
	res, err := s.Store.DB.Exec(`UPDATE api_tokens SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at=0`, time.Now().Unix(), id, u.ID)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, notFound()
	}
	s.audit(r, "account.token_revoke", u.Username, "", true)
	return nil, nil
}

// ---- recovery codes ------------------------------------------------------------

var recoveryEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

func normRecovery(c string) string {
	if len(c) > 64 {
		return ""
	}
	return strings.ToLower(strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '\t' {
			return -1
		}
		return r
	}, c))
}

func recoveryHash(userID int64, code string) string {
	return auth.SHA256Hex("bprc:" + itoa64(userID) + ":" + normRecovery(code))
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func (s *Server) genRecovery(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	if !u.TOTPEnabled {
		return nil, bad("totp_not_enabled")
	}
	codes := make([]string, recoveryCodeCount)
	now := time.Now().Unix()
	tx, err := s.Store.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM recovery_codes WHERE user_id=?`, u.ID); err != nil {
		return nil, err
	}
	for i := range codes {
		b := make([]byte, 7)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		c := strings.ToLower(recoveryEnc.EncodeToString(b))[:10]
		codes[i] = c[:5] + "-" + c[5:]
		if _, err := tx.Exec(`INSERT INTO recovery_codes(user_id,hash,created_at) VALUES(?,?,?)`, u.ID, recoveryHash(u.ID, c), now); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.audit(r, "account.recovery_generate", u.Username, "", true)
	return map[string]any{"codes": codes}, nil
}

func (s *Server) recoveryCount(w http.ResponseWriter, r *http.Request) (any, error) {
	var n int
	if err := s.Store.DB.QueryRow(`SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used_at=0`, userOf(r).ID).Scan(&n); err != nil {
		return nil, err
	}
	return map[string]any{"remaining": n}, nil
}

// useRecoveryCode consumes one unused recovery code atomically.
func (s *Server) useRecoveryCode(ctx context.Context, userID int64, code string) (bool, error) {
	if normRecovery(code) == "" {
		return false, nil
	}
	res, err := s.Store.DB.ExecContext(ctx, `UPDATE recovery_codes SET used_at=? WHERE user_id=? AND hash=? AND used_at=0`,
		time.Now().Unix(), userID, recoveryHash(userID, code))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return err == nil && n == 1, err
}

// ---- sessions -------------------------------------------------------------------

const sessionIDLen = 16

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) (any, error) {
	u, cur := userOf(r), sessionOf(r)
	now := time.Now().Unix()
	ss, err := store.Select[store.Session](r.Context(), s.Store.R,
		`SELECT * FROM sessions WHERE user_id=? AND expires_at>? AND last_seen>? ORDER BY last_seen DESC`, u.ID, now, now-2*3600)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(ss))
	for _, x := range ss {
		out = append(out, map[string]any{"id": x.IDHash[:sessionIDLen], "realm": x.Realm, "ip": x.IP, "user_agent": x.UserAgent,
			"created_at": x.CreatedAt, "last_seen": x.LastSeen, "impersonated": x.ImpersonatorID != 0,
			"current": cur != nil && cur.IDHash == x.IDHash})
	}
	return map[string]any{"sessions": out}, nil
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	id := chi.URLParam(r, "id")
	if len(id) != sessionIDLen || strings.Trim(id, "0123456789abcdef") != "" {
		return nil, notFound()
	}
	res, err := s.Store.DB.Exec(`DELETE FROM sessions WHERE user_id=? AND substr(id_hash,1,?)=?`, u.ID, sessionIDLen, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, notFound()
	}
	s.audit(r, "account.session_revoke", u.Username, id, true)
	return nil, nil
}

func (s *Server) revokeOtherSessions(w http.ResponseWriter, r *http.Request) (any, error) {
	u, cur := userOf(r), sessionOf(r)
	res, err := s.Store.DB.Exec(`DELETE FROM sessions WHERE user_id=? AND id_hash<>?`, u.ID, cur.IDHash)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	s.audit(r, "account.session_revoke_others", u.Username, itoa64(n), true)
	return map[string]any{"revoked": n}, nil
}

// adminRevokeSessions: DELETE /admin/users/{id}/sessions (sessions.revoke).
// Only super_admin may end another staff member's sessions; resellers only
// their own accounts (canManageAccount).
func (s *Server) adminRevokeSessions(w http.ResponseWriter, r *http.Request) (any, error) {
	id := idParam(r, "id")
	target, err := s.userByID(r.Context(), id)
	if err != nil {
		return nil, notFound()
	}
	role := roleOf(r)
	if target.Role == "admin" && role != rbac.SuperAdmin && target.ID != userOf(r).ID {
		return nil, &apiError{Status: 403, Code: "permission_denied"}
	}
	if target.Role != "admin" && !s.canManageAccount(r, target.ID) {
		return nil, notFound()
	}
	res, err := s.Store.DB.Exec(`DELETE FROM sessions WHERE user_id=?`, target.ID)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	s.audit(r, "admin.sessions_revoke", target.Username, itoa64(n), true)
	return map[string]any{"revoked": n}, nil
}
