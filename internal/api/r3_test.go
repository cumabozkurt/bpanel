// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"strings"
	"testing"

	"github.com/cumabozkurt/bpanel/internal/store"
)

func (s *Server) packageOfID(t *testing.T, id int64) store.Package {
	t.Helper()
	p, err := store.One[store.Package](context.Background(), s.Store.DB, `SELECT * FROM packages WHERE id=?`, id)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// v0.3: install-profile feature gates (R2-SYS-16 handoff).
func TestR3FeatureGates(t *testing.T) {
	e := newEnv(t)
	e.tenant("gate", "gate.test")
	u := mustLogin(t, e, e.user, "gate", "")
	cases := []struct{ feature, method, path string }{
		{"dns", "GET", "/api/v1/user/dns/gate.test"},
		{"dns", "POST", "/api/v1/user/dns/gate.test/reset"},
		{"mail", "GET", "/api/v1/user/email/accounts"},
		{"mail", "POST", "/api/v1/user/email/forwarders"},
		{"mail", "GET", "/api/v1/user/webmail"},
		{"webmail", "GET", "/api/v1/user/webmail"},
		{"ftp", "POST", "/api/v1/user/ftp"},
		{"ftp", "DELETE", "/api/v1/user/ftp/1"},
	}
	for _, c := range cases {
		for _, f := range gatedFeatures {
			if err := e.srv.Store.Set("feature_"+f, "1"); err != nil {
				t.Fatal(err)
			}
		}
		if err := e.srv.Store.Set("feature_"+c.feature, "0"); err != nil {
			t.Fatal(err)
		}
		code, m := u.call(c.method, c.path, map[string]any{})
		if code != 409 || m["error"] != "feature_disabled" || m["field"] != c.feature {
			t.Errorf("%s off: %s %s = %d %v", c.feature, c.method, c.path, code, m)
		}
	}
	for _, f := range gatedFeatures {
		_ = e.srv.Store.Set("feature_"+f, "0")
	}
	// GET /user/ftp keeps working (SFTP details), unrelated routes too
	if code, m := u.call("GET", "/api/v1/user/ftp", nil); code != 200 {
		t.Errorf("GET /user/ftp with ftp off: %d %v", code, m)
	}
	if code, m := u.call("GET", "/api/v1/user/domains", nil); code != 200 {
		t.Errorf("domains with everything off: %d %v", code, m)
	}
	// /auth/me reports the flags
	code, m := u.call("GET", "/api/v1/auth/me", nil)
	fs, _ := m["features"].(map[string]any)
	if code != 200 || fs["mail"] != false || fs["dns"] != false || fs["ftp"] != false || fs["webmail"] != false || fs["apache"] != false {
		t.Errorf("me features: %d %v", code, m["features"])
	}
	// back on: the gate is gone
	for _, f := range gatedFeatures {
		_ = e.srv.Store.Set("feature_"+f, "1")
	}
	if code, m := u.call("GET", "/api/v1/user/email/accounts", nil); code != 200 {
		t.Errorf("mail on: %d %v", code, m)
	} else if _, ok := m["package_quota_mb"]; !ok {
		t.Errorf("package_quota_mb missing: %v", m)
	}
}

// R2-UX-15: a mailbox quota is capped at the package mailbox quota.
func TestR3MailboxQuotaCap(t *testing.T) {
	e := newEnv(t)
	s := &Server{}
	pkg := e.srv.packageOfID(t, e.pkg())
	pkg.MailQuotaMB, pkg.DiskMB = 500, 2000
	if _, err := s.mailQuota(pkg, 600); err == nil {
		t.Error("600 MB > 500 MB package quota accepted")
	}
	if _, err := s.mailQuota(pkg, Unlimited); err == nil {
		t.Error("unlimited accepted with a 500 MB package quota")
	}
	if q, err := s.mailQuota(pkg, 500); err != nil || q != 500 {
		t.Errorf("500: %d %v", q, err)
	}
	pkg.MailQuotaMB = Unlimited
	if q, err := s.mailQuota(pkg, Unlimited); err != nil || q != Unlimited {
		t.Errorf("unlimited package: %d %v", q, err)
	}
	if _, err := s.mailQuota(pkg, 2500); err == nil {
		t.Error("2500 MB > 2000 MB disk accepted")
	}
}

// An explicit Apache web mode on a server without Apache is refused, the
// default silently stays nginx.
func TestR3ApacheGate(t *testing.T) {
	e := newEnv(t)
	a := adminLogin(t, e)
	_ = e.srv.Store.Set("feature_apache", "0")
	code, m := a.call("POST", "/api/v1/admin/accounts", map[string]any{"username": "apx", "domain": "apx.test", "password": tPW, "package_id": e.pkg(), "web_mode": "nginx-apache"})
	if code != 409 || m["error"] != "feature_disabled" {
		t.Fatalf("explicit apache: %d %v", code, m)
	}
	code, m = a.call("POST", "/api/v1/admin/accounts", map[string]any{"username": "apy", "domain": "apy.test", "password": tPW, "package_id": e.pkg()})
	if code != 200 {
		t.Fatalf("default mode: %d %v", code, m)
	}
	var mode string
	if err := e.srv.Store.DB.QueryRow(`SELECT web_mode FROM users WHERE username='apy'`).Scan(&mode); err != nil || !strings.EqualFold(mode, "nginx") {
		t.Fatalf("web_mode %q %v", mode, err)
	}
}
