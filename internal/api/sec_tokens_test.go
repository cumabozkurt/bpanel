package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func (e *env) bearer(method, path, tok, ip string, body any) (int, map[string]any) {
	w := e.do(e.admin, req{method: method, path: path, body: body, ip: ip, headers: map[string]string{"Authorization": "Bearer " + tok}}, nil)
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w.Code, m
}

func mkToken(t *testing.T, s *sess, body map[string]any) (string, int64) {
	t.Helper()
	code, m := s.call("POST", "/api/v1/account/tokens", body)
	if code != 200 {
		t.Fatalf("create token: %d %v", code, m)
	}
	tok, _ := m["token"].(string)
	if !strings.HasPrefix(tok, "bpt_") || len(tok) != 68 {
		t.Fatalf("token shape %q", tok)
	}
	return tok, int64(m["id"].(float64))
}

func TestSecTokenBearerScopes(t *testing.T) {
	e := newEnv(t)
	var logs syncBuf
	e.srv.Log = slog.New(slog.NewTextHandler(&logs, nil))
	root := mustLoginAdmin(t, e)
	tok, id := mkToken(t, root, map[string]any{"name": "ci", "perms": []string{"accounts.read", "admin.read"},
		"ip_allow": []string{"198.51.100.0/24", "2001:db8::/32"}})

	if code, m := e.bearer("GET", "/api/v1/admin/accounts", tok, "198.51.100.9", nil); code != 200 {
		t.Fatalf("permitted GET: %d %v", code, m)
	}
	if code, _ := e.bearer("GET", "/api/v1/admin/accounts", tok, "[2001:db8::5]", nil); code != 200 {
		t.Fatalf("permitted GET v6: %d", code)
	}
	if code, m := e.bearer("GET", "/api/v1/admin/packages", tok, "198.51.100.9", nil); code != 403 || m["error"] != "permission_denied" {
		t.Fatalf("unpermitted GET: %d %v", code, m)
	}
	// no CSRF header needed, but perms still apply
	if code, m := e.bearer("POST", "/api/v1/admin/packages", tok, "198.51.100.9", map[string]any{"name": "x"}); code != 403 || m["error"] != "permission_denied" {
		t.Fatalf("unpermitted POST: %d %v", code, m)
	}
	// tokens cannot drive the account surface (no token minting by token)
	if code, m := e.bearer("GET", "/api/v1/account/tokens", tok, "198.51.100.9", nil); code != 403 || m["error"] != "token_not_allowed" {
		t.Fatalf("account via token: %d %v", code, m)
	}
	if code, _ := e.bearer("GET", "/api/v1/auth/me", tok, "198.51.100.9", nil); code != 200 {
		t.Fatalf("me via token: %d", code)
	}
	// wrong IP
	if code, m := e.bearer("GET", "/api/v1/admin/accounts", tok, "203.0.113.5", nil); code != 401 || m["error"] != "invalid_api_token" {
		t.Fatalf("wrong ip: %d %v", code, m)
	}
	// garbage
	if code, _ := e.bearer("GET", "/api/v1/admin/accounts", "bpt_nope", "198.51.100.9", nil); code != 401 {
		t.Fatalf("unknown token: %d", code)
	}
	var last int64
	_ = e.srv.Store.DB.QueryRow(`SELECT last_used_at FROM api_tokens WHERE id=?`, id).Scan(&last)
	if last == 0 {
		t.Fatal("last_used_at not updated")
	}
	// list hides hash and token
	code, m := root.call("GET", "/api/v1/account/tokens", nil)
	if code != 200 || strings.Contains(fmt.Sprint(m), tok[4:]) {
		t.Fatalf("list: %d %v", code, m)
	}
	// expired
	if _, err := e.srv.Store.DB.Exec(`UPDATE api_tokens SET expires_at=? WHERE id=?`, time.Now().Add(-time.Minute).Unix(), id); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.bearer("GET", "/api/v1/admin/accounts", tok, "198.51.100.9", nil); code != 401 {
		t.Fatalf("expired: %d", code)
	}
	// revoked
	tok2, id2 := mkToken(t, root, map[string]any{"name": "ci2", "perms": []string{"accounts.read"}})
	if code, _ := e.bearer("GET", "/api/v1/admin/accounts", tok2, "", nil); code != 200 {
		t.Fatalf("tok2: %d", code)
	}
	if code, m := root.call("DELETE", fmt.Sprintf("/api/v1/account/tokens/%d", id2), nil); code != 200 {
		t.Fatalf("revoke: %d %v", code, m)
	}
	if code, _ := e.bearer("GET", "/api/v1/admin/accounts", tok2, "", nil); code != 401 {
		t.Fatalf("revoked: %d", code)
	}
	out := logs.String()
	if !strings.Contains(out, "api token rejected") {
		t.Fatalf("expected rejection log lines, got %q", out)
	}
	for _, tk := range []string{tok, tok2} {
		if strings.Contains(out, tk) || strings.Contains(out, tk[12:]) {
			t.Fatalf("token leaked into logs")
		}
	}
}

func TestSecTokenCreateRules(t *testing.T) {
	e := newEnv(t)
	root := mustLoginAdmin(t, e)
	for _, body := range []map[string]any{
		{"name": "x", "perms": []string{}},
		{"name": "x", "perms": []string{"nope.read"}},
		{"name": "x", "perms": []string{"accounts.read"}, "ip_allow": []string{"10.0.0.0/33"}},
		{"name": "x", "perms": []string{"accounts.read"}, "expires_at": 5},
		{"name": "", "perms": []string{"accounts.read"}},
	} {
		if code, m := root.call("POST", "/api/v1/account/tokens", body); code != 400 {
			t.Errorf("%v: %d %v", body, code, m)
		}
	}
	// perms must be a subset of the role
	e.tenant("tokuser", "tokuser.test")
	u := mustLogin(t, e, e.user, "tokuser", "")
	if code, m := u.call("POST", "/api/v1/account/tokens", map[string]any{"name": "x", "perms": []string{"accounts.read"}}); code != 400 || m["error"] != "invalid_perms" {
		t.Fatalf("superset perms: %d %v", code, m)
	}
	// user-realm token: hosting.read allows GET, refuses writes
	code, m := u.call("POST", "/api/v1/account/tokens", map[string]any{"name": "ro", "perms": []string{"hosting.read"}})
	if code != 200 {
		t.Fatalf("user token: %d %v", code, m)
	}
	tok := m["token"].(string)
	w := e.do(e.user, req{method: "GET", path: "/api/v1/user/domains", headers: map[string]string{"Authorization": "Bearer " + tok}}, nil)
	if w.Code != 200 {
		t.Fatalf("user GET via token: %d %s", w.Code, w.Body)
	}
	w = e.do(e.user, req{method: "POST", path: "/api/v1/user/domains", body: map[string]any{"name": "n.test", "kind": "addon"},
		headers: map[string]string{"Authorization": "Bearer " + tok}}, nil)
	if w.Code != 403 {
		t.Fatalf("user POST via ro token: %d %s", w.Code, w.Body)
	}
	// a user token is not valid on the admin panel
	if code, _ := e.bearer("GET", "/api/v1/admin/summary", tok, "", nil); code != 401 {
		t.Fatalf("user token on admin realm: %d", code)
	}
	// creating needs recent auth
	if _, err := e.srv.Store.DB.Exec(`UPDATE sessions SET created_at=?, reauth_at=0`, time.Now().Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if code, m := root.call("POST", "/api/v1/account/tokens", map[string]any{"name": "x", "perms": []string{"accounts.read"}}); code != 403 || m["error"] != "reauth_required" {
		t.Fatalf("stale create: %d %v", code, m)
	}
}

func TestSecRecoveryCodeSingleUse(t *testing.T) {
	e := newEnv(t)
	tu := e.tenant("mfauser", "mfauser.test")
	s := mustLogin(t, e, e.user, "mfauser", "")
	if code, m := s.call("POST", "/api/v1/account/mfa/recovery", nil); code != 400 || m["error"] != "totp_not_enabled" {
		t.Fatalf("no totp: %d %v", code, m)
	}
	if _, err := e.srv.Store.DB.Exec(`UPDATE users SET totp_enabled=1, totp_secret='JBSWY3DPEHPK3PXP' WHERE id=?`, tu.ID); err != nil {
		t.Fatal(err)
	}
	code, m := s.call("POST", "/api/v1/account/mfa/recovery", nil)
	if code != 200 {
		t.Fatalf("gen: %d %v", code, m)
	}
	codes := m["codes"].([]any)
	if len(codes) != 10 {
		t.Fatalf("codes: %v", codes)
	}
	c0 := codes[0].(string)
	login := func(rc string) int {
		w := e.do(e.user, req{method: "POST", path: "/api/v1/auth/login", body: map[string]string{"username": "mfauser", "password": tPW, "recovery_code": rc}}, nil)
		return w.Code
	}
	if c := login(strings.ToUpper(c0)); c != 200 {
		t.Fatalf("recovery login: %d", c)
	}
	if c := login(c0); c != 401 {
		t.Fatalf("reused recovery code: %d", c)
	}
	if c := login("aaaaa-bbbbb"); c != 401 {
		t.Fatalf("bogus recovery code: %d", c)
	}
	if code, m := s.call("GET", "/api/v1/account/mfa/recovery", nil); code != 200 || m["remaining"] != float64(9) {
		t.Fatalf("remaining: %d %v", code, m)
	}
}

func TestSecSessionsListAndRevoke(t *testing.T) {
	e := newEnv(t)
	tu := e.tenant("sessu", "sessu.test")
	s1 := mustLogin(t, e, e.user, "sessu", "")
	s2 := mustLogin(t, e, e.user, "sessu", "198.51.100.8")
	s3 := mustLogin(t, e, e.user, "sessu", "198.51.100.9")
	code, m := s1.call("GET", "/api/v1/account/sessions", nil)
	if code != 200 {
		t.Fatalf("list: %d %v", code, m)
	}
	list := m["sessions"].([]any)
	if len(list) != 3 {
		t.Fatalf("sessions: %v", list)
	}
	var other string
	cur := 0
	for _, x := range list {
		mm := x.(map[string]any)
		if mm["current"] == true {
			cur++
		} else if mm["ip"] == "198.51.100.8" {
			other = mm["id"].(string)
		}
	}
	if cur != 1 || len(other) != 16 {
		t.Fatalf("current=%d other=%q", cur, other)
	}
	if code, m := s1.call("DELETE", "/api/v1/account/sessions/"+other, nil); code != 200 {
		t.Fatalf("revoke: %d %v", code, m)
	}
	if code, _ := s2.call("GET", "/api/v1/auth/me", nil); code != 401 {
		t.Fatalf("revoked session still works: %d", code)
	}
	if code, _ := s3.call("GET", "/api/v1/auth/me", nil); code != 200 {
		t.Fatalf("s3 lost: %d", code)
	}
	if code, m := s1.call("DELETE", "/api/v1/account/sessions", nil); code != 200 || m["revoked"] != float64(1) {
		t.Fatalf("revoke others: %d %v", code, m)
	}
	if code, _ := s3.call("GET", "/api/v1/auth/me", nil); code != 401 {
		t.Fatalf("s3 survived: %d", code)
	}
	if code, _ := s1.call("GET", "/api/v1/auth/me", nil); code != 200 {
		t.Fatalf("current session killed: %d", code)
	}
	// admin: auditor refused, super_admin ends all
	staff(t, e, "audsess", "auditor")
	aud := mustLogin(t, e, e.admin, "audsess", "")
	if code, _ := aud.call("DELETE", fmt.Sprintf("/api/v1/admin/users/%d/sessions", tu.ID), nil); code != 403 {
		t.Fatalf("auditor revoke: %d", code)
	}
	root := mustLoginAdmin(t, e)
	if code, m := root.call("DELETE", fmt.Sprintf("/api/v1/admin/users/%d/sessions", tu.ID), nil); code != 200 {
		t.Fatalf("admin revoke: %d %v", code, m)
	}
	if code, _ := s1.call("GET", "/api/v1/auth/me", nil); code != 401 {
		t.Fatalf("session survived admin revoke: %d", code)
	}
}

func TestSecReauthThrottled(t *testing.T) {
	e := newEnv(t)
	root := mustLoginAdmin(t, e)
	got429 := false
	for i := 0; i < 8; i++ {
		code, _ := root.call("POST", "/api/v1/account/reauth", map[string]any{"password": "wrong-password-x"})
		if code == 429 {
			got429 = true
			break
		}
		if code != 400 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	if !got429 {
		t.Fatal("reauth never locked out")
	}
	// even the right password is refused while locked
	if code, _ := root.call("POST", "/api/v1/account/reauth", map[string]any{"password": "Admin-Pass-123"}); code != 429 {
		t.Fatalf("locked reauth accepted: %d", code)
	}
}
