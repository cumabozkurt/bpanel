// SPDX-License-Identifier: Apache-2.0

package api

import (
	"strings"
	"testing"
)

func TestIntegrationsAdminOnly(t *testing.T) {
	e := newEnv(t)
	if _, _, err := e.srv.CreateAccount(t.Context(), &e.root, CreateAccountReq{Username: "rsell", Domain: "rsell.test", Password: tPW,
		PackageID: e.pkg(), Role: "reseller", MaxAccounts: LimitOf(2)}); err != nil {
		t.Fatal(err)
	}
	e.tenant("tuser", "tuser.test")

	rs := mustLogin(t, e, e.admin, "rsell", "")
	if code, _ := rs.call("GET", "/api/v1/admin/integrations", nil); code != 403 {
		t.Fatalf("reseller: %d", code)
	}
	if us, code := e.login(e.admin, "tuser", tPW, "", ""); us != nil {
		if c, _ := us.call("GET", "/api/v1/admin/integrations", nil); c != 403 {
			t.Fatalf("user on admin realm: %d", c)
		}
	} else if code == 200 {
		t.Fatal("user logged in to admin realm without session")
	}
	ut := mustLogin(t, e, e.user, "tuser", "")
	if c, _ := ut.call("GET", "/api/v1/admin/integrations", nil); c == 200 {
		t.Fatal("user realm served admin integrations")
	}

	ad, code := e.login(e.admin, "rootadmin", "Admin-Pass-123", "", "")
	if ad == nil {
		t.Fatalf("admin login %d", code)
	}
	c, m := ad.call("GET", "/api/v1/admin/integrations", nil)
	if c != 200 {
		t.Fatalf("admin: %d %v", c, m)
	}
	ps, _ := m["providers"].([]any)
	if len(ps) < 13 {
		t.Fatalf("providers: %d", len(ps))
	}
	for _, x := range ps {
		p := x.(map[string]any)
		// the fake agent returns no probes: nothing may claim to be installed
		if p["state"] == "installed" {
			t.Errorf("%v installed without probe", p["name"])
		}
		lic := p["license"].(map[string]any)
		if n := p["name"].(string); (n == "monarx" || n == "imunify360") != (lic["class"] == "commercial_optional") {
			t.Errorf("%s license %v", n, lic["class"])
		}
	}
	if m["cached"] == true {
		t.Error("first call cached")
	}
	before := strings.Count(strings.Join(e.ag.methods(), ","), "providers.detect")
	_, m2 := ad.call("GET", "/api/v1/admin/integrations", nil)
	if m2["cached"] != true {
		t.Error("second call not cached")
	}
	_, m3 := ad.call("GET", "/api/v1/admin/integrations?refresh=1", nil)
	if m3["cached"] == true {
		t.Error("refresh=1 served cache")
	}
	if after := strings.Count(strings.Join(e.ag.methods(), ","), "providers.detect"); after != before+1 {
		t.Errorf("detect calls %d -> %d", before, after)
	}
}
