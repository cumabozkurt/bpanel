package api

// v0.4 security foundation: role/permission guard for the admin realm,
// step-up (re-)authentication. See internal/rbac for the catalogue.
//
// Every admin route (under /api/v1/admin) passes permGuard, installed once on
// the admin group in Handler. The guard looks up the matched chi route
// pattern in the route→permission table:
//
//   - GET/HEAD: the mapped permission, or rbac.AdminRead when unmapped.
//   - any other method: read-only roles (auditor) are always refused; a mapped
//     route needs its permission; an UNMAPPED mutating route is super_admin
//     only (TestPermEveryMutatingAdminRouteGuarded keeps the table complete).
//   - a route flagged reauth additionally needs a recent password/TOTP
//     authentication (requireRecentAuth).
//
// Role resolution: rbac.Effective(users.role, users.sec_role); every v0.3
// admin (sec_role '') is super_admin, so nothing changes for existing admins.

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cumabozkurt/bpanel/internal/rbac"
)

// DefaultReauthWindow is how long a password/TOTP authentication counts as
// "recent" for requireRecentAuth when no explicit window is given.
const DefaultReauthWindow = 10 * time.Minute

type routePerm struct {
	Perm   string
	Reauth bool
}

var (
	permMu    sync.RWMutex
	permTable = map[string]routePerm{
		"GET /admin/summary": {Perm: rbac.AdminRead},

		"GET /admin/packages":         {Perm: rbac.PackagesRead},
		"POST /admin/packages":        {Perm: rbac.PackagesWrite},
		"PUT /admin/packages/{id}":    {Perm: rbac.PackagesWrite},
		"DELETE /admin/packages/{id}": {Perm: rbac.PackagesWrite},

		"GET /admin/accounts":                 {Perm: rbac.AccountsRead},
		"POST /admin/accounts":                {Perm: rbac.AccountsCreate},
		"POST /admin/accounts/{id}/suspend":   {Perm: rbac.AccountsWrite},
		"POST /admin/accounts/{id}/unsuspend": {Perm: rbac.AccountsWrite},
		"PUT /admin/accounts/{id}/package":    {Perm: rbac.AccountsWrite},
		"POST /admin/accounts/{id}/password":  {Perm: rbac.AccountsPassword},
		"POST /admin/accounts/{id}/login":     {Perm: rbac.AccountsLoginAs},
		"DELETE /admin/accounts/{id}":         {Perm: rbac.AccountsTerminate, Reauth: true},

		"GET /admin/services":                  {Perm: rbac.ServerRead},
		"POST /admin/services/{unit}/{action}": {Perm: rbac.ServerWrite},
		"GET /admin/php":                       {Perm: rbac.ServerRead},
		"POST /admin/php/{version}/{action}":   {Perm: rbac.ServerWrite},
		"GET /admin/server":                    {Perm: rbac.ServerRead},
		"GET /admin/audit":                     {Perm: rbac.AuditRead},
		"GET /admin/settings":                  {Perm: rbac.ServerRead},
		"PUT /admin/settings":                  {Perm: rbac.ServerWrite, Reauth: true},
	}
)

// RoutePerm registers the permission guarding method+path (path relative to
// /api/v1, e.g. "/admin/firewall/rules"). Call it for every admin route you
// add with plain r.Post/...; s.opPerm does it for you.
func RoutePerm(method, path, perm string) { setRoutePerm(method, path, routePerm{Perm: perm}) }

// RoutePermReauth is RoutePerm plus a recent-authentication requirement.
func RoutePermReauth(method, path, perm string) {
	setRoutePerm(method, path, routePerm{Perm: perm, Reauth: true})
}

func setRoutePerm(method, path string, p routePerm) {
	permMu.Lock()
	defer permMu.Unlock()
	permTable[strings.ToUpper(method)+" "+path] = p
}

func lookupRoutePerm(method, path string) (routePerm, bool) {
	permMu.RLock()
	defer permMu.RUnlock()
	p, ok := permTable[strings.ToUpper(method)+" "+path]
	return p, ok
}

// opPerm registers an admin route together with its permission.
func (s *Server) opPerm(r chi.Router, perm, method, path, tag, summary string, body any, h http.HandlerFunc) {
	RoutePerm(method, path, perm)
	s.op(r, method, path, tag, summary, body, h)
}

// opPermReauth is opPerm plus requireRecentAuth.
func (s *Server) opPermReauth(r chi.Router, perm, method, path, tag, summary string, body any, h http.HandlerFunc) {
	RoutePermReauth(method, path, perm)
	s.op(r, method, path, tag, summary, body, h)
}

// roleOf is the caller's effective RBAC role ("" when not logged in).
func roleOf(r *http.Request) string {
	u := userOf(r)
	if u == nil {
		return ""
	}
	return rbac.Effective(u.Role, u.SecRole)
}

// routePath is the matched route pattern relative to /api/v1.
func routePath(r *http.Request) string {
	rc := chi.RouteContext(r.Context())
	if rc == nil {
		return r.URL.Path
	}
	p := rc.RoutePattern()
	p = strings.ReplaceAll(p, "/*/", "/")
	return strings.TrimPrefix(p, "/api/v1")
}

func permDenied(w http.ResponseWriter) {
	writeJSON(w, 403, apiError{Code: "permission_denied"})
}

// requirePerm refuses the request unless the caller's role holds perm.
func (s *Server) requirePerm(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !hasPerm(r, perm) {
				permDenied(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// permGuard applies the route→permission table (installed on the admin group).
func (s *Server) permGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := roleOf(r)
		p, mapped := lookupRoutePerm(r.Method, routePath(r))
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			perm := rbac.AdminRead
			if mapped {
				perm = p.Perm
			}
			if !hasPerm(r, perm) {
				permDenied(w)
				return
			}
		default:
			if rbac.IsReadOnly(role) {
				permDenied(w)
				return
			}
			if mapped {
				if !hasPerm(r, p.Perm) {
					permDenied(w)
					return
				}
			} else if role != rbac.SuperAdmin || tokenOf(r) != nil {
				permDenied(w)
				return
			}
		}
		if mapped && p.Reauth && !s.recentlyAuthenticated(r, DefaultReauthWindow) {
			writeJSON(w, 403, apiError{Code: "reauth_required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// recentlyAuthenticated: the session logged in (password, +TOTP) or passed
// POST /account/reauth within maxAge. Impersonation sessions only count an
// explicit re-auth, never their creation.
func (s *Server) recentlyAuthenticated(r *http.Request, maxAge time.Duration) bool {
	ss := sessionOf(r)
	if ss == nil {
		return false
	}
	at := ss.ReauthAt
	if ss.ImpersonatorID == 0 && ss.CreatedAt > at {
		at = ss.CreatedAt
	}
	if maxAge <= 0 {
		maxAge = DefaultReauthWindow
	}
	return at > 0 && time.Since(time.Unix(at, 0)) <= maxAge
}

// requireRecentAuth refuses with 403 reauth_required unless the session
// authenticated within maxAge (0 = DefaultReauthWindow). The client calls
// POST /api/v1/account/reauth and retries.
func (s *Server) requireRecentAuth(maxAge time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !s.recentlyAuthenticated(r, maxAge) {
				writeJSON(w, 403, apiError{Code: "reauth_required"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ReauthReq confirms the caller's identity again (one of the two).
type ReauthReq struct {
	Password string `json:"password,omitempty"`
	TOTP     string `json:"totp,omitempty"`
}

// reauth: POST /api/v1/account/reauth.
func (s *Server) reauth(w http.ResponseWriter, r *http.Request) (any, error) {
	var in ReauthReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u, ss := userOf(r), sessionOf(r)
	if ss == nil {
		return nil, forbidden()
	}
	// brute-force protection: same throttle and lockout as /auth/login
	ip := s.clientIP(r)
	if !s.loginIP.Allow(ip) {
		w.Header().Set("Retry-After", "10")
		return nil, &apiError{Status: 429, Code: "rate_limited"}
	}
	byIP, byUserIP, _, err := s.recentFailures(ip, u.Username)
	if err != nil {
		return nil, err
	}
	if byIP >= maxFailuresPerIP || byUserIP >= maxFailuresPerUserIP {
		s.authFailure(r, u.Username, ip, "reauth locked")
		return nil, &apiError{Status: 429, Code: "too_many_attempts"}
	}
	switch {
	case in.Password != "":
		if len(in.Password) > 1024 {
			return nil, &apiError{Status: 400, Code: "wrong_current_password", Field: "password"}
		}
		ok, err := s.checkPassword(r.Context(), u.PasswordHash, in.Password)
		if err != nil {
			return nil, err
		}
		if !ok {
			s.recordFailure(ip, u.Username)
			s.authFailure(r, u.Username, ip, "reauth bad password")
			s.audit(r, "account.reauth", u.Username, "wrong password", false)
			return nil, &apiError{Status: 400, Code: "wrong_current_password", Field: "password"}
		}
	case in.TOTP != "":
		if !u.TOTPEnabled {
			return nil, bad("invalid_totp")
		}
		ok, err := s.useTOTP(r.Context(), u.ID, u.TOTPSecret, in.TOTP)
		if err != nil {
			return nil, err
		}
		if !ok {
			s.recordFailure(ip, u.Username)
			s.authFailure(r, u.Username, ip, "reauth bad totp")
			s.audit(r, "account.reauth", u.Username, "wrong totp", false)
			return nil, bad("invalid_totp")
		}
	default:
		return nil, bad("bad_params")
	}
	now := time.Now().Unix()
	if _, err := s.Store.DB.Exec(`UPDATE sessions SET reauth_at=? WHERE id_hash=?`, now, ss.IDHash); err != nil {
		return nil, err
	}
	s.audit(r, "account.reauth", u.Username, "", true)
	return map[string]any{"reauth_at": now, "window_seconds": int64(DefaultReauthWindow / time.Second)}, nil
}

// canManageAccount is the object-level check for account-scoped actions:
// admin staff with an account permission, a reseller only its own accounts,
// technical only granted accounts, a user only itself.
func (s *Server) canManageAccount(r *http.Request, accountID int64) bool {
	u := userOf(r)
	if u == nil {
		return false
	}
	switch role := roleOf(r); role {
	case rbac.SuperAdmin, rbac.ServerAdmin, rbac.SecurityAdmin, rbac.Auditor:
		return rbac.Has(role, rbac.AccountsRead)
	case rbac.Reseller:
		if accountID == u.ID {
			return true
		}
		var n int
		err := s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM users WHERE id=? AND owner_id=?`, accountID, u.ID).Scan(&n)
		return err == nil && n > 0
	case rbac.Technical:
		return s.hasTechGrant(r.Context(), u.ID, accountID)
	case rbac.User:
		return accountID == u.ID
	}
	return false
}

func (s *Server) hasTechGrant(ctx context.Context, userID, accountID int64) bool {
	var n int
	err := s.Store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM tech_grants WHERE user_id=? AND account_id=?`, userID, accountID).Scan(&n)
	return err == nil && n > 0
}
