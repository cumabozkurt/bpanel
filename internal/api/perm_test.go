package api

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cumabozkurt/bpanel/internal/rbac"
)

// superAdminOnly lists mutating admin routes that deliberately have NO table
// entry: only super_admin may call them. Anything else must be in permTable
// (register with s.opPerm / RoutePerm).
var superAdminOnly = map[string]bool{}

// v0.4: every mutating admin route is either permission-mapped or an explicit
// super_admin-only route.
func TestPermEveryMutatingAdminRouteGuarded(t *testing.T) {
	e := newEnv(t)
	rt, ok := e.admin.(chi.Routes)
	if !ok {
		t.Fatal("admin handler is not a chi router")
	}
	var unguarded []string
	n := 0
	err := chi.Walk(rt, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		route = strings.ReplaceAll(route, "/*/", "/")
		if !strings.HasPrefix(route, "/api/v1/admin/") && route != "/api/v1/admin" {
			return nil
		}
		path := strings.TrimPrefix(route, "/api/v1")
		switch method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			return nil
		}
		n++
		key := method + " " + path
		if p, ok := lookupRoutePerm(method, path); ok {
			if !rbac.Known(p.Perm) {
				t.Errorf("%s: unknown permission %q", key, p.Perm)
			}
			return nil
		}
		if !superAdminOnly[key] {
			unguarded = append(unguarded, key)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("walked no mutating admin routes")
	}
	sort.Strings(unguarded)
	for _, k := range unguarded {
		t.Errorf("mutating admin route without a permission (use s.opPerm or add to superAdminOnly): %s", k)
	}
}

func staff(t *testing.T, e *env, name, secRole string) {
	t.Helper()
	id, err := EnsureAdmin(context.Background(), e.srv.Store, name, tPW, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.Store.DB.Exec(`UPDATE users SET sec_role=? WHERE id=?`, secRole, id); err != nil {
		t.Fatal(err)
	}
}

func TestPermAuditorReadOnly(t *testing.T) {
	e := newEnv(t)
	staff(t, e, "aud1", rbac.Auditor)
	s := mustLogin(t, e, e.admin, "aud1", "")
	for _, p := range []string{"/api/v1/admin/accounts", "/api/v1/admin/audit", "/api/v1/admin/packages", "/api/v1/admin/summary"} {
		if code, m := s.call("GET", p, nil); code != 200 {
			t.Errorf("auditor GET %s: %d %v", p, code, m)
		}
	}
	code, m := s.call("POST", "/api/v1/admin/packages", map[string]any{"name": "x"})
	if code != 403 || m["error"] != "permission_denied" {
		t.Fatalf("auditor POST: %d %v", code, m)
	}
	if code, _ := s.call("PUT", "/api/v1/admin/settings", map[string]any{}); code != 403 {
		t.Fatalf("auditor PUT settings: %d", code)
	}
	// a v0.3 admin (sec_role '') is still super_admin
	root, code := e.login(e.admin, "rootadmin", "Admin-Pass-123", "", "")
	if root == nil {
		t.Fatalf("root login %d", code)
	}
	if code, m := root.call("GET", "/api/v1/admin/settings", nil); code != 200 {
		t.Fatalf("root GET settings: %d %v", code, m)
	}
}

func TestPermServerAdminNoSecurityWrite(t *testing.T) {
	// security_admin has no packages.write; server_admin has.
	e := newEnv(t)
	staff(t, e, "secad", rbac.SecurityAdmin)
	s := mustLogin(t, e, e.admin, "secad", "")
	if code, m := s.call("DELETE", "/api/v1/admin/packages/999", nil); code != 403 || m["error"] != "permission_denied" {
		t.Fatalf("security_admin delete package: %d %v", code, m)
	}
	staff(t, e, "srvad", rbac.ServerAdmin)
	s2 := mustLogin(t, e, e.admin, "srvad", "")
	if code, _ := s2.call("DELETE", "/api/v1/admin/packages/999", nil); code == 403 {
		t.Fatalf("server_admin refused packages.write")
	}
}

func TestPermResellerCannotTouchOtherReseller(t *testing.T) {
	e := newEnv(t)
	mk := func(n string) int64 {
		u, _, err := e.srv.CreateAccount(context.Background(), &e.root, CreateAccountReq{Username: n, Domain: n + ".test", Password: tPW,
			PackageID: e.pkg(), Role: "reseller", MaxAccounts: LimitOf(5)})
		if err != nil {
			t.Fatal(err)
		}
		return u.ID
	}
	mk("resa")
	b := mk("resb")
	s := mustLogin(t, e, e.admin, "resa", "")
	for _, c := range []struct {
		m, p string
		body any
	}{
		{"POST", fmt.Sprintf("/api/v1/admin/accounts/%d/suspend", b), map[string]any{"reason": "x"}},
		{"POST", fmt.Sprintf("/api/v1/admin/accounts/%d/password", b), map[string]any{"password": "Another-Pass-2026"}},
		{"DELETE", fmt.Sprintf("/api/v1/admin/accounts/%d", b), nil},
	} {
		code, m := s.call(c.m, c.p, c.body)
		if code != 403 && code != 404 {
			t.Errorf("reseller %s %s on other reseller: %d %v", c.m, c.p, code, m)
		}
	}
	var st string
	_ = e.srv.Store.DB.QueryRow(`SELECT status FROM users WHERE id=?`, b).Scan(&st)
	if st != "active" {
		t.Fatalf("other reseller changed: %s", st)
	}
}

func TestPermReauthRequired(t *testing.T) {
	e := newEnv(t)
	victim := e.tenant("reauthv", "reauthv.test")
	s, code := e.login(e.admin, "rootadmin", "Admin-Pass-123", "", "")
	if s == nil {
		t.Fatalf("login %d", code)
	}
	// age the session past the re-auth window
	old := time.Now().Add(-time.Hour).Unix()
	if _, err := e.srv.Store.DB.Exec(`UPDATE sessions SET created_at=?, reauth_at=0`, old); err != nil {
		t.Fatal(err)
	}
	del := fmt.Sprintf("/api/v1/admin/accounts/%d", victim.ID)
	code, m := s.call("DELETE", del, nil)
	if code != 403 || m["error"] != "reauth_required" {
		t.Fatalf("stale session delete: %d %v", code, m)
	}
	if code, m := s.call("POST", "/api/v1/account/reauth", map[string]any{"password": "wrong-password-x"}); code != 400 {
		t.Fatalf("bad reauth: %d %v", code, m)
	}
	if code, m := s.call("POST", "/api/v1/account/reauth", map[string]any{"password": "Admin-Pass-123"}); code != 200 {
		t.Fatalf("reauth: %d %v", code, m)
	}
	if code, m := s.call("DELETE", del, nil); code != 200 {
		t.Fatalf("delete after reauth: %d %v", code, m)
	}
}
