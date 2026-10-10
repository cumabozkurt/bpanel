// Package api is the unprivileged HTTP side of BPANEL. It serves two realms
// on separate listeners, like the classic layout:
//
//	user panel  : HTTPS 2083 (HTTP 2082 redirects)
//	admin panel : HTTPS 2087 (HTTP 2086 redirects)
//
// Webmail (Roundcube) is served by nginx on HTTPS 2096 (HTTP 2095 redirects).
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cumabozkurt/bpanel/internal/redact"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/auth"
	"github.com/cumabozkurt/bpanel/internal/store"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

const (
	RealmUser  = "user"
	RealmAdmin = "admin"
)

// Config is read from /etc/bpanel/api.json.
type Config struct {
	DBPath         string        `json:"db_path"`
	AgentSocket    string        `json:"agent_socket"`
	Bind           string        `json:"bind"` // address to bind, "" = all
	UserPort       int           `json:"user_port"`
	UserHTTPPort   int           `json:"user_http_port"`
	AdminPort      int           `json:"admin_port"`
	AdminHTTPPort  int           `json:"admin_http_port"`
	WebmailPort    int           `json:"webmail_port"`
	TLSCert        string        `json:"tls_cert"`
	TLSKey         string        `json:"tls_key"`
	PlainHTTP      bool          `json:"plain_http"` // development only
	Hostname       string        `json:"hostname"`
	ServerIP       string        `json:"server_ip"`
	PMAUpstream    string        `json:"pma_upstream"`           // internal nginx serving phpMyAdmin
	DavUpstream    string        `json:"dav_upstream,omitempty"` // v1.1 Radicale (default http://127.0.0.1:5232)
	Dev            bool          `json:"dev"`
	TrustedProxies []string      `json:"trusted_proxies"`
	SecretKeyFile  string        `json:"secret_key_file"` // v0.4 secret store master key ("" = /etc/bpanel/secret.key)
	Secrets        SecretsConfig `json:"secrets"`         // v0.4 baox: provider switch (secrets_provider.go)
}

func DefaultConfig() Config {
	return Config{DBPath: "/var/lib/bpanel/db/bpanel.db", AgentSocket: "/run/bpanel/agent.sock", UserPort: 2083, UserHTTPPort: 2082,
		AdminPort: 2087, AdminHTTPPort: 2086, WebmailPort: 2096, TLSCert: "/etc/bpanel/ssl/panel/fullchain.pem",
		TLSKey: "/etc/bpanel/ssl/panel/privkey.pem", PMAUpstream: "http://127.0.0.1:2090"}
}

type Server struct {
	Cfg      Config
	Store    *store.Store
	Agent    rpc.Caller
	Log      *slog.Logger
	Static   fs.FS
	Version  string
	loginIP  *auth.Limiter
	apiLim   *auth.Limiter
	ops      []opInfo
	cspOnce  sync.Once
	cspCache string
	trusted  []*net.IPNet
	reqSeq   atomic.Uint64
	// Now is the clock (tests replace it).
	Now func() time.Time

	hashGate   *gate        // R2-PERF-1
	uploadGate *gate        // R2-PERF-3
	logSample  *sampler     // R2-PERF-11
	auditCount countCache   // R2-PERF-2
	sysCache   sysInfoCache // R2-PERF-16
	startedAt  time.Time    // R2-PERF-5
	sec        *secState    // v0.4 sec_found.go

	shieldPollMu sync.Mutex // v0.4 shield.go poller
}

func New(cfg Config, st *store.Store, agent rpc.Caller, static fs.FS, log *slog.Logger, version string) *Server {
	if log != nil {
		log = slog.New(redact.NewHandler(log.Handler())) // v0.4: never log secrets
	}
	s := &Server{Cfg: cfg, Store: st, Agent: agent, Static: static, Log: log, Version: version,
		loginIP: auth.NewLimiter(10, 10), apiLim: auth.NewLimiter(1200, 300), Now: time.Now,
		hashGate: newGate(hashSlots()), uploadGate: newGate(uploadSlots), logSample: newSampler(10 * time.Second),
		auditCount: countCache{ttl: 10 * time.Second}, startedAt: time.Now()}
	for _, p := range cfg.TrustedProxies {
		if !strings.Contains(p, "/") {
			if ip := net.ParseIP(p); ip != nil && ip.To4() != nil {
				p += "/32"
			} else {
				p += "/128"
			}
		}
		if _, n, err := net.ParseCIDR(p); err == nil {
			s.trusted = append(s.trusted, n)
		} else if log != nil {
			log.Warn("ignoring invalid trusted_proxies entry", "value", p)
		}
	}
	s.initSec() // v0.4 sec_found.go
	return s
}

// ---- context ------------------------------------------------------------------

type ctxKey int

const (
	kRealm ctxKey = iota
	kSession
	kUser
)

func realmOf(r *http.Request) string     { v, _ := r.Context().Value(kRealm).(string); return v }
func userOf(r *http.Request) *store.User { v, _ := r.Context().Value(kUser).(*store.User); return v }
func sessionOf(r *http.Request) *store.Session {
	v, _ := r.Context().Value(kSession).(*store.Session)
	return v
}

// ---- responses ------------------------------------------------------------------

type apiError struct {
	Status  int    `json:"-"`
	Code    string `json:"error"`
	Message string `json:"message,omitempty"`
	Step    string `json:"step,omitempty"` // multi-step endpoints (db-wizard): which step failed
	// Field names the request field (JSON key) the error is about, so the UI
	// can show it inline (R2-UX-10 and friends).
	Field string `json:"field,omitempty"`
	// Max is the limit that was exceeded (too_long: bytes; invalid_limit: largest value).
	Max int64 `json:"max,omitempty"`
	// Details carries structured context (v0.4 shield_blocked: detections).
	Details any `json:"details,omitempty"`
}

func (e *apiError) Error() string { return e.Code }

func bad(code string) error           { return &apiError{Status: 400, Code: code} }
func unprocessable(code string) error { return &apiError{Status: 422, Code: code} }
func badMsg(code, msg string) error   { return &apiError{Status: 400, Code: code, Message: msg} }
func notFound() error                 { return &apiError{Status: 404, Code: "not_found"} }
func forbidden() error                { return &apiError{Status: 403, Code: "forbidden"} }
func conflict(code string) error      { return &apiError{Status: 409, Code: code} }
func limitReached(what string) error {
	return &apiError{Status: 409, Code: "limit_reached", Message: what}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // the client went away: nothing left to do
}

// agentStatus maps an agent error code to an HTTP status (CODE-10). Unknown
// codes are server-side failures of the action (502); transport problems
// with the agent itself are 503/504.
func agentStatus(code string) int {
	switch code {
	case "not_found", "no_such_user", "invalid_token":
		return http.StatusNotFound
	case "already_exists", "user_exists", "home_exists", "zone_exists", "php_version_in_use", "not_empty", "mail_domain_disabled",
		"ip_exists", "ssh_key_exists", "owned_by_another_account":
		return http.StatusConflict
	case "permission_denied", "unit_not_allowed", "not_managed", "symlink_in_path", "refused", "helper_must_not_run_as_root":
		return http.StatusForbidden
	case "file_too_large", "zip_too_large":
		return http.StatusRequestEntityTooLarge
	case "quota_exceeded", "disk_full":
		return http.StatusInsufficientStorage
	case "is_directory", "not_a_directory", "binary_file", "not_regular_file", "bad_upload", "bad_upload_offset", "bad_offset",
		"bad_zip", "bad_zip_entry", "copy_into_self", "unknown_op", "bad_params", "reserved_username", "db_prefix_required",
		"php_not_installed", "unknown_php_version", "snapshot_kind_mismatch",
		"ssh_invalid_name", "ssh_invalid_key", "php_ext_unknown", "php_version_missing", "not_installed":
		return http.StatusUnprocessableEntity
	case "private_dir", "bad_request", "too_long":
		return http.StatusBadRequest
	case "agent_unreachable":
		return http.StatusServiceUnavailable
	case "agent_timeout":
		return http.StatusGatewayTimeout
	}
	switch {
	case strings.HasPrefix(code, "invalid_"), strings.HasPrefix(code, "password_"):
		return http.StatusBadRequest
	}
	return http.StatusBadGateway
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiError
	var re *rpc.Error
	switch {
	case errors.As(err, &ae):
		if ae.Status == 0 {
			ae.Status = 400
		}
		if ae.Status == http.StatusServiceUnavailable && ae.Code == "server_busy" {
			w.Header().Set("Retry-After", "2")
			writeJSON(w, ae.Status, apiError{Code: ae.Code})
			return
		}
		if ae.Status >= 500 {
			// never send server-side detail to the browser (handoff-ui H-7)
			id := requestID(r)
			s.Log.Error("server error", "path", r.URL.Path, "request_id", id, "code", ae.Code, "msg", ae.Message)
			writeJSON(w, ae.Status, apiError{Code: ae.Code, Message: "request " + id})
			return
		}
		writeJSON(w, ae.Status, ae)
	case errors.As(err, &re):
		status := agentStatus(re.Code)
		s.Log.Warn("agent error", "path", r.URL.Path, "code", re.Code, "msg", re.Message)
		msg := re.Message
		if status >= 500 {
			// agent messages for server-side failures can carry command output
			// and paths: log them, return only the code and a request id
			msg = "request " + requestID(r)
		}
		writeJSON(w, status, apiError{Code: re.Code, Message: msg})
	case errors.Is(err, sql.ErrNoRows):
		writeJSON(w, 404, apiError{Code: "not_found"})
	case store.IsUniqueViolation(err):
		writeJSON(w, 409, apiError{Code: "already_exists"})
	case store.IsDiskFull(err):
		// R2-PERF-13: say what is wrong instead of a bare 500
		s.Log.Error("database: disk full", "path", r.URL.Path, "request_id", requestID(r), "err", err)
		writeJSON(w, http.StatusInsufficientStorage, apiError{Code: "disk_full", Message: "request " + requestID(r)})
	case store.IsBusy(err):
		// R2-PERF-4: a writer held the database longer than busy_timeout
		s.Log.Warn("database busy", "path", r.URL.Path, "request_id", requestID(r))
		w.Header().Set("Retry-After", "2")
		writeJSON(w, http.StatusServiceUnavailable, apiError{Code: "db_busy", Message: "request " + requestID(r)})
	default:
		id := requestID(r)
		s.Log.Error("internal error", "path", r.URL.Path, "request_id", id, "err", err)
		writeJSON(w, 500, apiError{Code: "internal_error", Message: "request " + id})
	}
}

type ridKey struct{}

func requestID(r *http.Request) string {
	if v, ok := r.Context().Value(ridKey{}).(string); ok {
		return v
	}
	return "-"
}

// requestIDs tags every request with an id (also returned as X-Request-ID)
// and turns panics into a JSON 500 instead of a dropped connection (CODE-11).
func (s *Server) requestIDs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := fmt.Sprintf("%x-%d", s.Now().UnixNano()&0xffffffff, s.reqSeq.Add(1))
		w.Header().Set("X-Request-ID", id)
		r = r.WithContext(context.WithValue(r.Context(), ridKey{}, id))
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.Log.Error("panic", "path", r.URL.Path, "request_id", id, "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
				writeJSON(w, 500, apiError{Code: "internal_error", Message: "request " + id})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// h adapts a handler that returns (value, error).
func (s *Server) h(f func(w http.ResponseWriter, r *http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, err := f(w, r)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if v == nil {
			v = map[string]bool{"ok": true}
		}
		writeJSON(w, 200, v)
	}
}

func decode(r *http.Request, v any) error {
	if r.Body == nil {
		return badMsg("bad_json", "empty body")
	}
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return badMsg("bad_json", err.Error())
	}
	return nil
}

// idParam parses a numeric path parameter; an invalid value yields 0, which
// never matches a row, so handlers answer 404.
func idParam(r *http.Request, name string) int64 {
	n, err := strconv.ParseInt(chi.URLParam(r, name), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// ---- client IP ------------------------------------------------------------------

func (s *Server) isTrusted(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	for _, n := range s.trusted {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

// clientIP returns the peer address, or - when the peer is a trusted proxy -
// the right-most X-Forwarded-For entry that is not itself a trusted proxy.
// The left-most entries are client-controlled and never trusted (CODE-20).
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !s.isTrusted(host) {
		return host
	}
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		for _, p := range strings.Split(h, ",") {
			hops = append(hops, strings.TrimSpace(p))
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		ip := hops[i]
		if net.ParseIP(ip) == nil {
			return host // garbage: do not guess
		}
		if !s.isTrusted(ip) {
			return ip
		}
	}
	return host
}

// ---- audit ----------------------------------------------------------------------

func (s *Server) audit(r *http.Request, action, target, detail string, ok bool) {
	if ok && strings.HasPrefix(action, "db.") {
		defer s.dbxAfterDBChange(r, action) // v0.4 dbx.go: keep remote mirrors / limits in step
	}
	actorID, actor := int64(0), ""
	if u := userOf(r); u != nil {
		actorID, actor = u.ID, u.Username
		if ss := sessionOf(r); ss != nil && ss.ImpersonatorID != 0 {
			var imp string
			if err := s.Store.DB.QueryRow(`SELECT username FROM users WHERE id=?`, ss.ImpersonatorID).Scan(&imp); err != nil {
				imp = fmt.Sprintf("#%d", ss.ImpersonatorID)
			}
			actor = imp + " as " + u.Username
		}
	}
	_, err := s.Store.DB.Exec(`INSERT INTO audit_log(at,actor_id,actor,ip,realm,action,target,detail,ok) VALUES(?,?,?,?,?,?,?,?,?)`,
		time.Now().Unix(), actorID, actor, s.clientIP(r), realmOf(r), action, target, detail, ok)
	if err != nil {
		s.Log.Error("audit write", "err", err)
	}
}

// ---- middleware ------------------------------------------------------------------

func (s *Server) withRealm(realm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), kRealm, realm)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if !strings.HasPrefix(r.URL.Path, "/3rdparty/") {
			h.Set("X-Frame-Options", "DENY")
			h.Set("Content-Security-Policy", s.csp())
		}
		if !s.Cfg.PlainHTTP {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

var reInline = regexp.MustCompile(`(?s)<script>(.*?)</script>`)

// csp hashes SvelteKit's inline bootstrap script so script-src can stay 'self'.
// Computed once; safe for concurrent requests (CODE-12).
func (s *Server) csp() string {
	s.cspOnce.Do(s.buildCSP)
	return s.cspCache
}

func (s *Server) buildCSP() {
	hashes := ""
	if s.Static != nil {
		if b, err := fs.ReadFile(s.Static, "index.html"); err == nil {
			for _, m := range reInline.FindAllSubmatch(b, -1) {
				sum := sha256.Sum256(m[1])
				hashes += " 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
			}
		}
	}
	s.cspCache = "default-src 'self'; script-src 'self'" + hashes + "; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
}

func (s *Server) cookieName(realm string) string { return "bp_" + realm + "_session" }

// loadSession attaches the session/user if a valid cookie is present.
func (s *Server) loadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realm := realmOf(r)
		c, err := r.Cookie(s.cookieName(realm))
		if err == nil && c.Value != "" {
			ss, err := store.One[store.Session](r.Context(), s.Store.R, `SELECT * FROM sessions WHERE id_hash=?`, auth.SHA256Hex(c.Value))
			now := time.Now().Unix()
			if err == nil && ss.Realm == realm && ss.ExpiresAt > now && now-ss.LastSeen < 2*3600 {
				u, uerr := s.userByID(r.Context(), ss.UserID)
				if uerr == nil && (u.Status == "active" || ss.ImpersonatorID != 0) {
					if now-ss.LastSeen > 60 {
						if _, err := s.Store.DB.Exec(`UPDATE sessions SET last_seen=? WHERE id_hash=?`, now, ss.IDHash); err != nil {
							s.Log.Warn("session touch", "err", err)
						}
					}
					ctx := context.WithValue(r.Context(), kSession, &ss)
					ctx = context.WithValue(ctx, kUser, &u)
					r = r.WithContext(ctx)
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := userOf(r)
		if u == nil {
			writeJSON(w, 401, apiError{Code: "unauthenticated"})
			return
		}
		if !s.apiLim.Allow("s:" + sessionOf(r).IDHash) {
			// one line per user and window, with the number suppressed (R2-PERF-11)
			if ok, n := s.logSample.allow("api429:" + u.Username); ok {
				s.Log.Warn("rate limited", "user", u.Username, "ip", s.clientIP(r), "suppressed", n)
			}
			w.Header().Set("Retry-After", "1")
			writeJSON(w, 429, apiError{Code: "rate_limited"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrf: state-changing requests need a same-origin Origin (when sent) and,
// with a session, the session's token in X-CSRF-Token. Requests without a
// session (login, one-time token) must be application/json and must not be
// cross-site per Sec-Fetch-Site, which closes login CSRF via text/plain form
// posts (a JSON body survives "name=value" encoding) (SEC: login CSRF).
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if tokenOf(r) != nil { // bearer API token: no ambient credential (sec_tokens.go)
			next.ServeHTTP(w, r)
			return
		}
		if o := r.Header.Get("Origin"); o != "" {
			ou, err := url.Parse(o)
			if err != nil || ou.Host != r.Host {
				writeJSON(w, 403, apiError{Code: "bad_origin"})
				return
			}
		}
		switch r.Header.Get("Sec-Fetch-Site") {
		case "", "same-origin", "none":
		default:
			writeJSON(w, 403, apiError{Code: "bad_origin"})
			return
		}
		if ss := sessionOf(r); ss != nil {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(ss.CSRF)) != 1 {
				writeJSON(w, 403, apiError{Code: "csrf_failed"})
				return
			}
		} else if r.ContentLength != 0 {
			ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if ct != "application/json" {
				writeJSON(w, 415, apiError{Code: "unsupported_media_type"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := userOf(r)
			for _, ro := range roles {
				if u != nil && u.Role == ro {
					next.ServeHTTP(w, r)
					return
				}
			}
			writeJSON(w, 403, apiError{Code: "forbidden"})
		})
	}
}

// ---- router ------------------------------------------------------------------

// Handler builds the router for one realm.
func (s *Server) Handler(realm string) http.Handler {
	r := chi.NewRouter()
	r.Use(s.requestIDs, s.obsxHTTP, s.compress, s.withRealm(realm), s.securityHeaders, s.loadSession, s.loadBearer, s.csrf) // obsxHTTP: v0.4 obsx.go metrics
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 405, apiError{Code: "method_not_allowed"})
	})
	r.Route("/api/v1", func(api chi.Router) {
		s.authRoutes(api)
		api.Group(func(p chi.Router) {
			p.Use(s.requireAuth)
			s.accountRoutes(p)
			s.mountSecCommon(p) // v0.4 sec_found.go
			if realm == RealmUser {
				s.userRoutes(p)
			} else {
				p.Group(func(a chi.Router) {
					a.Use(s.requireRole("admin", "reseller"), s.permGuard, s.resellerACL) // v0.4 RBAC (perm.go) + adminx reseller ACL
					s.adminRoutes(a)
					s.mountSecAdmin(a)       // v0.4 sec_tokens.go
					s.mountSecFound(a)       // v0.4 sec_found.go
					s.mountNetsec(a)         // v0.4 netsec.go
					s.mountUsagexAdmin(a)    // v0.4 usagex.go
					s.mountBackupVerify(a)   // v0.4 backup_verify.go
					s.mountBackupSchedule(a) // v0.4 backup_schedule.go (+ /admin/secrets/rotate)
					s.mountAdminx(a)         // v0.4 adminx.go
					s.mountDbxAdmin(a)       // v0.4 dbx.go
					s.mountXfer(a)           // v0.4 xfer.go (Transfer Tool)
					s.mountAppxAdmin(a)      // v0.4 appx.go
					s.mountObsx(a)           // v0.4 obsx.go
					s.mountMsrvAdmin(a)      // v0.4 msrv.go (remote nodes)
					s.mountClusterx(a)       // v0.4 clusterx.go (DNS cluster, plugins)
				})
			}
		})
		api.NotFound(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 404, apiError{Code: "not_found"}) })
		api.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 405, apiError{Code: "method_not_allowed"}) })
	})
	if realm == RealmUser {
		r.Get("/internal/pma-token/{token}", s.pmaTokenExchange)
		s.mountDevxPublic(r) // v0.4 devx.go: /ddns/update (token auth)
		s.mountMsrvPublic(r) // v0.4 msrv.go: /msrv/join (one-time token)
		r.Handle("/3rdparty/phpMyAdmin/*", s.pmaProxy())
	}
	if realm != RealmUser {
		r.Get("/metrics", s.obsxMetrics) // v0.4 obsx.go (admin token or loopback)
	}
	r.Get("/openapi.json", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, s.OpenAPI()) })
	r.Handle("/*", s.spa())
	if realm == RealmUser {
		// v1.1: CalDAV/CardDAV clients authenticate with HTTP Basic against
		// Radicale; they bypass the panel's session/bearer middleware.
		dav := s.davProxy()
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Path == "/dav" || strings.HasPrefix(req.URL.Path, "/dav/") {
				dav.ServeHTTP(w, req)
				return
			}
			r.ServeHTTP(w, req)
		})
	}
	return r
}

func (s *Server) pmaProxy() http.Handler {
	u, err := url.Parse(s.Cfg.PMAUpstream)
	if err != nil || s.Cfg.PMAUpstream == "" {
		return http.NotFoundHandler()
	}
	p := httputil.NewSingleHostReverseProxy(u)
	return p
}

// spa serves the embedded SvelteKit build with index.html fallback.
func (s *Server) spa() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Static == nil {
			http.Error(w, "UI not built", 500)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if st, err := fs.Stat(s.Static, p); err == nil && !st.IsDir() {
				if strings.HasPrefix(p, "_app/immutable/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				if r.Header.Get("Range") == "" && s.precompressed(w, r, p) {
					return
				}
				http.ServeFileFS(w, r, s.Static, p)
				return
			}
		}
		b, err := fs.ReadFile(s.Static, "index.html")
		if err != nil {
			http.Error(w, "UI not built", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(b)
	})
}

// ---- listeners --------------------------------------------------------------------

// redirectHandler sends plain-HTTP visitors to the HTTPS port. The target
// host is the configured hostname when set (not the client's Host header, so
// it cannot be used as an open redirect).
func redirectHandler(hostname string, port int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := hostname
		if host == "" {
			host = r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if validate.Domain(host) != nil && net.ParseIP(host) == nil {
				http.Error(w, "bad host", http.StatusBadRequest)
				return
			}
		}
		target := fmt.Sprintf("https://%s:%d%s", host, port, r.URL.RequestURI())
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

// Run starts all listeners and blocks until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	var tlsCfg *tls.Config
	if !s.Cfg.PlainHTTP {
		cert, err := loadOrSelfSign(s.Cfg.TLSCert, s.Cfg.TLSKey, s.Cfg.Hostname)
		if err != nil {
			return err
		}
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: cert.get}
	}
	type lis struct {
		port int
		h    http.Handler
		tls  bool
	}
	ls := []lis{
		{s.Cfg.UserPort, s.Handler(RealmUser), true},
		{s.Cfg.AdminPort, s.Handler(RealmAdmin), true},
	}
	if !s.Cfg.PlainHTTP {
		ls = append(ls, lis{s.Cfg.UserHTTPPort, redirectHandler(s.Cfg.Hostname, s.Cfg.UserPort), false},
			lis{s.Cfg.AdminHTTPPort, redirectHandler(s.Cfg.Hostname, s.Cfg.AdminPort), false})
	}
	errc := make(chan error, len(ls))
	var servers []*http.Server
	for _, l := range ls {
		if l.port == 0 {
			continue
		}
		// Slow-body protection (CODE-14). Upload and download handlers extend
		// their own deadlines through http.ResponseController.
		srv := &http.Server{Addr: net.JoinHostPort(s.Cfg.Bind, strconv.Itoa(l.port)), Handler: l.h,
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 10 * time.Minute,
			IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
		servers = append(servers, srv)
		useTLS := l.tls && tlsCfg != nil
		if useTLS {
			srv.TLSConfig = tlsCfg
		}
		go func() {
			s.Log.Info("listening", "addr", srv.Addr, "tls", useTLS)
			var err error
			if useTLS {
				err = srv.ListenAndServeTLS("", "")
			} else {
				err = srv.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	go s.housekeeping(ctx)
	s.startSec(ctx)    // v0.4 sec_found.go
	go s.msrvLoop(ctx) // v0.4 msrv.go: node health checks
	go s.runUsageSampler(ctx)
	go s.probeAgent(ctx)
	go s.runShieldPoller(ctx)
	go s.netsecLoop(ctx) // v0.4 netsec.go: block expiry
	go s.usagexLoop(ctx) // v0.4 usagex.go: bandwidth collector
	go s.leechLoop(ctx)  // v1.1 webx.go: leech protection sweep
	go s.bfLoop(ctx)     // v1.1 usagex.go: re-push the fail2ban allowlist
	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(sctx); err != nil {
			s.Log.Warn("shutdown", "addr", srv.Addr, "err", err)
		}
	}
	return nil
}

func (s *Server) housekeeping(ctx context.Context) {
	// finish or undo provisioning/termination interrupted by a crash (CODE-5).
	// Rows created before this process started cannot be in flight any more:
	// roll them back now instead of after 30 minutes (R2-PERF-5).
	s.reconcileStartup(ctx)
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	lastSSL := time.Time{}
	s.migrateBackupSecrets(ctx) // v0.4 backup_secrets.go: one-time, idempotent
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.prune(ctx)
			s.reconcileProvisioning(ctx, 30*time.Minute)
			if time.Since(lastSSL) >= 6*time.Hour {
				lastSSL = time.Now()
				s.autoSSLRun(ctx)
			}
			s.backupVerifyTick(ctx)   // v0.4: at most one weekly restore verification per tick
			s.backupScheduleTick(ctx) // v0.4: at most one scheduled backup (+ retention) per tick
		}
	}
}

// prober is implemented by agentrpc.Breaker.
type prober interface {
	Probe(ctx context.Context) error
}

// probeAgent keeps the agent circuit breaker current (R2-PERF-6): a hung
// agent is noticed within one interval and requests fail fast with 503
// agent_unreachable instead of waiting for the method timeout.
func (s *Server) probeAgent(ctx context.Context) {
	p, ok := s.Agent.(prober)
	if !ok {
		return
	}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	wasDown := false
	for {
		err := p.Probe(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil && !wasDown {
			s.Log.Warn("agent health check failed; failing fast until it answers", "err", err)
		} else if err == nil && wasDown {
			s.Log.Info("agent answers again")
		}
		wasDown = err != nil
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// prune deletes expired rows and short-lived phpMyAdmin MariaDB users.
func (s *Server) prune(ctx context.Context) {
	now := s.Now().Unix()
	for _, q := range []struct {
		sql string
		arg []any
	}{
		{`DELETE FROM sessions WHERE expires_at<? OR last_seen<?`, []any{now, now - 2*3600}},
		{`DELETE FROM once_tokens WHERE expires_at<?`, []any{now}},
		{`DELETE FROM pma_tokens WHERE expires_at<?`, []any{now}},
		{`DELETE FROM login_failures WHERE at<?`, []any{now - 86400}},
		{`DELETE FROM audit_log WHERE at<?`, []any{now - s.obsxAuditDays()*86400}}, // v0.4 obsx retention (default 180)
	} {
		if _, err := s.Store.DB.ExecContext(ctx, q.sql, q.arg...); err != nil {
			s.Log.Warn("housekeeping", "sql", q.sql, "err", err)
		}
	}
	s.auditCount.clear()
	s.prunePMAUsers(ctx, pmaUserTTL)
	s.pruneSec(ctx)  // v0.4 sec_found.go
	s.obsxPrune(ctx) // v0.4 obsx.go
}
