package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/auth"
	"github.com/cumabozkurt/bpanel/internal/store"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

const userSelect = `SELECT u.*, COALESCE(p.name,'') AS package_name, COALESCE(o.username,'') AS owner_name
	FROM users u LEFT JOIN packages p ON p.id=u.package_id LEFT JOIN users o ON o.id=u.owner_id`

func (s *Server) userByID(ctx context.Context, id int64) (store.User, error) {
	return store.One[store.User](ctx, s.Store.DB, userSelect+` WHERE u.id=?`, id)
}

func (s *Server) userByName(ctx context.Context, name string) (store.User, error) {
	return store.One[store.User](ctx, s.Store.DB, userSelect+` WHERE u.username=?`, name)
}

type LoginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTP     string `json:"totp,omitempty"`
	// RecoveryCode replaces TOTP once (v0.4, sec_tokens.go).
	RecoveryCode string `json:"recovery_code,omitempty"`
}

type OnceReq struct {
	Token string `json:"token"`
}

type PasswordChangeReq struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

type TOTPReq struct {
	Code string `json:"code"`
}

type PrefsReq struct {
	Lang      *string   `json:"lang,omitempty"`
	Theme     *string   `json:"theme,omitempty"`
	Favorites *[]string `json:"favorites,omitempty"` // dashboard tool ids, at most 24 (handoff-ui H-3)
}

func (s *Server) authRoutes(r chi.Router) {
	s.op(r, "GET", "/meta", "auth", "Public server metadata (realm, version, default language)", nil, s.h(s.meta))
	s.op(r, "POST", "/auth/login", "auth", "Log in with username, password and optional TOTP code", LoginReq{}, s.h(s.login))
	s.op(r, "POST", "/auth/once", "auth", "Exchange a one-time login token for a session", OnceReq{}, s.h(s.loginOnce))
	s.op(r, "POST", "/auth/logout", "auth", "End the current session", nil, s.h(s.logout))
	s.op(r, "GET", "/auth/me", "auth", "Current user, session and CSRF token", nil, s.h(s.me))
}

func (s *Server) accountRoutes(r chi.Router) {
	s.op(r, "POST", "/account/password", "account", "Change own password", PasswordChangeReq{}, s.h(s.changePassword))
	s.op(r, "POST", "/account/totp/setup", "account", "Start TOTP enrolment (returns secret and otpauth URL)", nil, s.h(s.totpSetup))
	s.op(r, "POST", "/account/totp/enable", "account", "Confirm TOTP enrolment with a code", TOTPReq{}, s.h(s.totpEnable))
	s.op(r, "POST", "/account/totp/disable", "account", "Disable TOTP (requires a current code)", TOTPReq{}, s.h(s.totpDisable))
	s.op(r, "PUT", "/account/preferences", "account", "Set language, theme and dashboard favorites", PrefsReq{}, s.h(s.setPrefs))
	s.op(r, "POST", "/account/reauth", "account", "Confirm identity again (password or TOTP) for sensitive actions", ReauthReq{}, s.h(s.reauth))
	s.mountSecAccount(r) // v0.4 tokens, recovery codes, sessions (sec_tokens.go)
	s.op(r, "GET", "/account/activity", "account", "Own activity feed for the notifications bell (?limit=&since_id=); resellers also see their accounts", nil, s.h(s.activity))
}

func (s *Server) meta(w http.ResponseWriter, r *http.Request) (any, error) {
	host := s.Cfg.Hostname
	return map[string]any{
		"product": "BOZKURT PANEL", "version": s.Version, "realm": realmOf(r), "hostname": host,
		"default_lang": s.Store.Get("default_lang", "en"), "dev": s.Cfg.Dev,
		"ports":  map[string]int{"user": s.Cfg.UserPort, "admin": s.Cfg.AdminPort, "webmail": s.Cfg.WebmailPort},
		"limits": validate.Limits(), // the UI mirrors these rules (CODE-24)
	}, nil
}

// Lockout policy (SEC-18 / CODE-19): hard locks are per IP and per
// account+IP, so nobody can lock the administrator out from elsewhere.
// Failures for an account from many IPs only add a small, capped delay.
const (
	maxFailuresPerIP     = 10
	maxFailuresPerUserIP = 5
	softDelayAfter       = 8
)

func (s *Server) recentFailures(ip, user string) (byIP, byUserIP, byUser int, err error) {
	since := s.Now().Add(-15 * time.Minute).Unix()
	if err = s.Store.DB.QueryRow(`SELECT COUNT(*) FROM login_failures WHERE ip=? AND at>?`, ip, since).Scan(&byIP); err != nil {
		return
	}
	if err = s.Store.DB.QueryRow(`SELECT COUNT(*) FROM login_failures WHERE username=? AND ip=? AND at>?`, user, ip, since).Scan(&byUserIP); err != nil {
		return
	}
	err = s.Store.DB.QueryRow(`SELECT COUNT(*) FROM login_failures WHERE username=? AND at>?`, user, since).Scan(&byUser)
	return
}

// authFailure writes the line the fail2ban [bpanel] filter matches
// (msg="auth failure" ... ip=<addr>); never the password (H-1).
func (s *Server) authFailure(r *http.Request, user, ip, reason string) {
	s.Log.Warn("auth failure", "realm", realmOf(r), "user", truncLog(user), "ip", ip, "reason", reason)
}

// truncLog shortens a client-supplied value for a log line only.
func truncLog(v string) string {
	if len(v) > 64 {
		return v[:64]
	}
	return v
}

// normTOTP accepts codes as authenticator apps show them ("123 456",
// " 123456 ", "123-456") (R2-UX-23).
func normTOTP(code string) string {
	if len(code) > 32 {
		return code
	}
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '-' || r == '\u00a0' || r == '\u202f' {
			return -1
		}
		return r
	}, code)
}

func (s *Server) recordFailure(ip, user string) {
	if _, err := s.Store.DB.Exec(`INSERT INTO login_failures(ip,username,at) VALUES(?,?,?)`, ip, user, s.Now().Unix()); err != nil {
		s.Log.Warn("record login failure", "err", err)
	}
}

// softDelay slows down distributed guessing against one account without
// ever refusing the right password (capped at 2 s).
var softDelay = func(n int) {
	if n < softDelayAfter {
		return
	}
	d := time.Duration(n-softDelayAfter+1) * 100 * time.Millisecond
	time.Sleep(min(d, 2*time.Second))
}

// useTOTP verifies a code against the account's last accepted step and
// stores the new step atomically, so every code works exactly once (SEC-17).
func (s *Server) useTOTP(ctx context.Context, userID int64, secret, code string) (bool, error) {
	var last int64
	if err := s.Store.DB.QueryRowContext(ctx, `SELECT totp_last_step FROM users WHERE id=?`, userID).Scan(&last); err != nil {
		return false, err
	}
	step, ok := auth.VerifyTOTPStep(secret, normTOTP(code), s.Now(), last)
	if !ok {
		return false, nil
	}
	res, err := s.Store.DB.ExecContext(ctx, `UPDATE users SET totp_last_step=? WHERE id=? AND totp_last_step<?`, step, userID, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return err == nil && n == 1, err
}

func (s *Server) realmAllows(realm, role string) bool {
	if realm == RealmAdmin {
		return role == "admin" || role == "reseller"
	}
	return role == "user" || role == "reseller" // resellers own a hosting account too
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) (any, error) {
	var in LoginReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	ip := s.clientIP(r)
	in.Username = strings.ToLower(strings.TrimSpace(in.Username))
	if !s.loginIP.Allow(ip) {
		// one line per IP and window, with the number suppressed (R2-PERF-11)
		if ok, n := s.logSample.allow("login429:" + ip); ok {
			s.Log.Warn("auth failure", "realm", realmOf(r), "user", truncLog(in.Username), "ip", ip, "reason", "rate limited", "suppressed", n)
		}
		w.Header().Set("Retry-After", "10")
		return nil, &apiError{Status: 429, Code: "rate_limited"}
	}
	if len(in.Username) > 64 || len(in.Password) > 1024 {
		return nil, &apiError{Status: 401, Code: "invalid_credentials"}
	}
	byIP, byUserIP, byUser, err := s.recentFailures(ip, in.Username)
	if err != nil {
		return nil, err
	}
	if byIP >= maxFailuresPerIP || byUserIP >= maxFailuresPerUserIP {
		s.authFailure(r, in.Username, ip, "locked")
		s.audit(r, "auth.locked", in.Username, ip, false)
		return nil, &apiError{Status: 429, Code: "too_many_attempts"}
	}
	softDelay(byUser)
	u, err := s.userByName(r.Context(), in.Username)
	hash := u.PasswordHash
	if err != nil {
		hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g" // equalise timing
	}
	ok, herr := s.checkPassword(r.Context(), hash, in.Password) // bounded argon2 (R2-PERF-1)
	if herr != nil {
		w.Header().Set("Retry-After", "2")
		return nil, herr
	}
	ok = ok && err == nil
	if !ok {
		s.recordFailure(ip, in.Username)
		s.authFailure(r, in.Username, ip, "bad credentials")
		s.audit(r, "auth.login", in.Username, "bad credentials", false)
		return nil, &apiError{Status: 401, Code: "invalid_credentials"}
	}
	if !s.realmAllows(realmOf(r), u.Role) {
		s.audit(r, "auth.login", in.Username, "wrong realm", false)
		return nil, &apiError{Status: 403, Code: "wrong_panel"}
	}
	if u.Status != "active" {
		return nil, &apiError{Status: 403, Code: "account_suspended"}
	}
	if u.TOTPEnabled {
		if in.TOTP == "" && in.RecoveryCode == "" {
			return map[string]any{"totp_required": true}, nil
		}
		var ok bool
		var err error
		if in.RecoveryCode != "" {
			ok, err = s.useRecoveryCode(r.Context(), u.ID, in.RecoveryCode)
		} else {
			ok, err = s.useTOTP(r.Context(), u.ID, u.TOTPSecret, in.TOTP)
		}
		if err != nil {
			return nil, err
		}
		if !ok {
			s.recordFailure(ip, in.Username)
			s.authFailure(r, in.Username, ip, "bad totp")
			s.audit(r, "auth.login", in.Username, "bad or reused totp", false)
			return nil, &apiError{Status: 401, Code: "invalid_totp"}
		}
	}
	if _, err := s.Store.DB.Exec(`DELETE FROM login_failures WHERE username=? AND ip=?`, in.Username, ip); err != nil {
		s.Log.Warn("clear login failures", "err", err)
	}
	return s.startSession(w, r, &u, 0)
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u *store.User, impersonator int64) (any, error) {
	tok := auth.RandomToken(32)
	csrf := auth.RandomToken(16)
	now := time.Now().Unix()
	realm := realmOf(r)
	_, err := s.Store.DB.Exec(`INSERT INTO sessions(id_hash,user_id,impersonator_id,realm,csrf,ip,user_agent,created_at,expires_at,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		auth.SHA256Hex(tok), u.ID, impersonator, realm, csrf, s.clientIP(r), r.UserAgent(), now, now+12*3600, now)
	if err != nil {
		return nil, err
	}
	if impersonator == 0 {
		if _, err := s.Store.DB.Exec(`UPDATE users SET last_login_at=?, last_login_ip=? WHERE id=?`, now, s.clientIP(r), u.ID); err != nil {
			s.Log.Warn("last login update", "err", err)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(realm), Value: tok, Path: "/", HttpOnly: true,
		Secure: !s.Cfg.PlainHTTP, SameSite: http.SameSiteStrictMode, MaxAge: 12 * 3600})
	ctx := context.WithValue(r.Context(), kUser, u)
	s.audit(r.WithContext(ctx), "auth.login", u.Username, "", true)
	return map[string]any{"ok": true, "csrf": csrf}, nil
}

func (s *Server) loginOnce(w http.ResponseWriter, r *http.Request) (any, error) {
	var in OnceReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if !s.loginIP.Allow(s.clientIP(r)) {
		return nil, &apiError{Status: 429, Code: "rate_limited"}
	}
	var uid, imp int64
	var realm string
	h := auth.SHA256Hex(in.Token)
	err := s.Store.DB.QueryRow(`SELECT user_id, realm, impersonator_id FROM once_tokens WHERE hash=? AND used=0 AND expires_at>?`, h, time.Now().Unix()).Scan(&uid, &realm, &imp)
	if err != nil || realm != realmOf(r) {
		return nil, &apiError{Status: 401, Code: "invalid_token"}
	}
	res, err := s.Store.DB.Exec(`UPDATE once_tokens SET used=1 WHERE hash=? AND used=0`, h)
	if err != nil { // res is nil when Exec fails (CODE-11)
		return nil, err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return nil, &apiError{Status: 401, Code: "invalid_token"}
	}
	u, err := s.userByID(r.Context(), uid)
	if err != nil {
		return nil, err
	}
	return s.startSession(w, r, &u, imp)
}

// CreateOnceToken makes a single-use login link token (used by the installer/CLI and "log in as").
func CreateOnceToken(st *store.Store, userID int64, realm string, impersonator int64, ttl time.Duration) (string, error) {
	tok := auth.RandomToken(24)
	_, err := st.DB.Exec(`INSERT INTO once_tokens(hash,user_id,realm,impersonator_id,expires_at) VALUES(?,?,?,?,?)`,
		auth.SHA256Hex(tok), userID, realm, impersonator, time.Now().Add(ttl).Unix())
	return tok, err
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) (any, error) {
	if ss := sessionOf(r); ss != nil {
		if _, err := s.Store.DB.Exec(`DELETE FROM sessions WHERE id_hash=?`, ss.IDHash); err != nil {
			return nil, err
		}
		s.audit(r, "auth.logout", "", "", true)
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(realmOf(r)), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: !s.Cfg.PlainHTTP, SameSite: http.SameSiteStrictMode})
	return nil, nil
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	if u == nil {
		return nil, &apiError{Status: 401, Code: "unauthenticated"}
	}
	ss := sessionOf(r)
	out := map[string]any{"user": u, "csrf": ss.CSRF, "realm": realmOf(r), "default_lang": s.Store.Get("default_lang", "en"),
		"favorites": favoritesOf(u),
		// install profile features, so the UI hides what the server does not run (SYS-5 / H-2)
		"features":         s.features(),
		"web_mode_default": s.Store.Get("web_mode", "nginx-apache")}
	if ss.ImpersonatorID != 0 {
		if imp, err := s.userByID(r.Context(), ss.ImpersonatorID); err == nil {
			out["impersonator"] = imp.Username
		}
	}
	return out, nil
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) (any, error) {
	var in PasswordChangeReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	if len(in.Current) > 1024 {
		return nil, &apiError{Status: 400, Code: "wrong_current_password", Field: "current"}
	}
	okPw, err := s.checkPassword(r.Context(), u.PasswordHash, in.Current)
	if err != nil {
		return nil, err
	}
	if !okPw {
		// R2-UX-22: its own code; no username was typed on this form
		s.audit(r, "account.password", u.Username, "wrong current password", false)
		return nil, &apiError{Status: 400, Code: "wrong_current_password", Field: "current"}
	}
	if err := passwordErr(in.New, "new"); err != nil {
		return nil, err
	}
	h, err := s.hashPassword(r.Context(), in.New)
	if err != nil {
		return nil, err
	}
	if u.SystemUser {
		if err := s.agentCall(r, rpc.MAccountPassword, rpc.AccountPassword{User: u.Username, Password: in.New}, nil); err != nil {
			return nil, err
		}
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `UPDATE users SET password_hash=?, version=version+1 WHERE id=?`, h, u.ID); err != nil {
		// keep panel and system passwords in sync (CODE-15): put the old one back
		if u.SystemUser {
			uctx, cancel := undoCtx(r.Context())
			defer cancel()
			if rerr := s.Agent.Call(uctx, rpc.MAccountPassword, rpc.AccountPassword{User: u.Username, Password: in.Current}, nil); rerr != nil {
				s.Log.Error("password change: could not restore the system password", "user", u.Username, "err", rerr)
			}
		}
		return nil, err
	}
	// end other sessions
	if _, err := s.Store.DB.Exec(`DELETE FROM sessions WHERE user_id=? AND id_hash<>?`, u.ID, sessionOf(r).IDHash); err != nil {
		s.Log.Warn("end other sessions", "err", err)
	}
	s.audit(r, "account.password", u.Username, "", true)
	return nil, nil
}

func (s *Server) totpSetup(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	if u.TOTPEnabled {
		return nil, conflict("totp_already_enabled")
	}
	sec := auth.NewTOTPSecret()
	if _, err := s.Store.DB.Exec(`UPDATE users SET totp_secret=?, totp_last_step=0 WHERE id=?`, sec, u.ID); err != nil {
		return nil, err
	}
	host := s.Cfg.Hostname
	if host == "" {
		host = "BPANEL"
	}
	return map[string]string{"secret": sec, "url": auth.TOTPURL("BOZKURT PANEL ("+host+")", u.Username, sec)}, nil
}

func (s *Server) totpEnable(w http.ResponseWriter, r *http.Request) (any, error) {
	var in TOTPReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	var sec string
	if err := s.Store.DB.QueryRow(`SELECT totp_secret FROM users WHERE id=?`, u.ID).Scan(&sec); err != nil {
		return nil, err
	}
	if sec == "" {
		return nil, bad("invalid_totp")
	}
	ok, err := s.useTOTP(r.Context(), u.ID, sec, in.Code)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, bad("invalid_totp")
	}
	if _, err := s.Store.DB.Exec(`UPDATE users SET totp_enabled=1 WHERE id=?`, u.ID); err != nil {
		return nil, err
	}
	s.audit(r, "account.totp_enable", u.Username, "", true)
	return nil, nil
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request) (any, error) {
	var in TOTPReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	if !u.TOTPEnabled {
		return nil, bad("invalid_totp")
	}
	ok, err := s.useTOTP(r.Context(), u.ID, u.TOTPSecret, in.Code)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, bad("invalid_totp")
	}
	if _, err := s.Store.DB.Exec(`UPDATE users SET totp_enabled=0, totp_secret='' WHERE id=?`, u.ID); err != nil {
		return nil, err
	}
	if _, err := s.Store.DB.Exec(`DELETE FROM recovery_codes WHERE user_id=?`, u.ID); err != nil {
		return nil, err
	}
	s.audit(r, "account.totp_disable", u.Username, "", true)
	return nil, nil
}

func (s *Server) setPrefs(w http.ResponseWriter, r *http.Request) (any, error) {
	var in PrefsReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	if in.Lang != nil {
		if *in.Lang != "" {
			if err := validate.Lang(*in.Lang); err != nil {
				return nil, bad("invalid_language")
			}
		}
		if _, err := s.Store.DB.Exec(`UPDATE users SET lang=? WHERE id=?`, *in.Lang, u.ID); err != nil {
			return nil, err
		}
	}
	if in.Theme != nil {
		if *in.Theme != "light" && *in.Theme != "dark" && *in.Theme != "system" {
			return nil, bad("invalid_theme")
		}
		if _, err := s.Store.DB.Exec(`UPDATE users SET theme=? WHERE id=?`, *in.Theme, u.ID); err != nil {
			return nil, err
		}
	}
	if in.Favorites != nil {
		if err := validate.Favorites(*in.Favorites); err != nil {
			return nil, bad("invalid_favorites")
		}
		b, _ := json.Marshal(*in.Favorites)
		if _, err := s.Store.DB.Exec(`UPDATE users SET favorites=? WHERE id=?`, string(b), u.ID); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// favoritesOf returns the stored favorites, or null when the user never
// saved any (the UI then keeps its defaults / migrates localStorage).
func favoritesOf(u *store.User) []string {
	if u.Favorites == "" {
		return nil
	}
	var out []string
	if json.Unmarshal([]byte(u.Favorites), &out) != nil {
		return nil
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// Activity is one row of the notifications feed (handoff-ui H-1).
type Activity struct {
	ID     int64  `db:"id" json:"id"`
	At     int64  `db:"at" json:"at"`
	Actor  string `db:"actor" json:"actor"`
	Realm  string `db:"realm" json:"realm"`
	Action string `db:"action" json:"action"`
	Target string `db:"target" json:"target"`
	OK     bool   `db:"ok" json:"ok"`
	IP     string `db:"ip" json:"ip"`
}

// activity returns the caller's own audit rows (actions it performed, also
// while impersonated, and failed logins against its username); a reseller
// also sees the rows of the accounts it owns. Admins get their own rows
// here; the full log stays at /admin/audit. The detail column is never
// returned. ?since_id= returns only newer rows; X-Unread-Count carries how
// many rows are newer than since_id.
func (s *Server) activity(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	q := r.URL.Query()
	limit, err := strconv.Atoi(q.Get("limit"))
	if err != nil || limit <= 0 {
		limit = 10
	}
	limit = min(limit, 100)
	since, _ := strconv.ParseInt(q.Get("since_id"), 10, 64)
	where := `(actor_id=? OR (actor_id=0 AND target=? AND action LIKE 'auth.%'))`
	args := []any{u.ID, u.Username}
	if u.Role == "reseller" {
		where = `(actor_id=? OR (actor_id=0 AND target=? AND action LIKE 'auth.%') OR actor_id IN (SELECT id FROM users WHERE owner_id=?))`
		args = append(args, u.ID)
	}
	var unread int64
	if err := s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM audit_log WHERE `+where+` AND id>?`, append(args, since)...).Scan(&unread); err != nil {
		return nil, err
	}
	w.Header().Set("X-Unread-Count", strconv.FormatInt(unread, 10))
	rows, err := store.Select[Activity](r.Context(), s.Store.DB, `SELECT id, at, actor, realm, action, target, ok, ip FROM audit_log WHERE `+where+
		` AND id>? ORDER BY id DESC LIMIT ?`, append(args, since, limit)...)
	if err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []Activity{}
	}
	return map[string]any{"items": rows, "unread": unread}, nil
}
