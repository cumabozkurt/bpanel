// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"testing"

	"github.com/cumabozkurt/bpanel/internal/shield"
)

func TestShieldPolicyValidate(t *testing.T) {
	bad := [][]ShieldPolicyRow{
		{{FileClass: "binary"}},
		{{FileClass: "script", OnUnavailable: "quarantine"}}, // not a valid unavailable action
		{{FileClass: "script", OnSuspicious: "allow"}},
		{{FileClass: "script"}, {FileClass: "script"}},
		{{FileClass: "archive", OnUnavailable: "block"}},
	}
	for i, rows := range bad {
		if validateShieldRows(rows) == nil {
			t.Errorf("case %d accepted: %+v", i, rows)
		}
	}
	good := []ShieldPolicyRow{{FileClass: "script", OnUnavailable: "hold", OnSuspicious: "quarantine"},
		{FileClass: "archive", OnSuspicious: "block"}, {FileClass: "other"}, {FileClass: "executable", OnUnavailable: "block"}}
	if err := validateShieldRows(good); err != nil {
		t.Fatal(err)
	}
	g := shield.DefaultPolicy() // unavailable script = block, suspicious script = hold
	if checkNotWeaker([]ShieldPolicyRow{{FileClass: "script", OnUnavailable: "hold"}}, g) == nil {
		t.Error("weaker unavailable accepted")
	}
	if checkNotWeaker([]ShieldPolicyRow{{FileClass: "executable", OnSuspicious: "allow_with_warning"}}, g) == nil {
		t.Error("weaker suspicious accepted")
	}
	if err := checkNotWeaker([]ShieldPolicyRow{{FileClass: "script", OnSuspicious: "quarantine"}, {FileClass: "other", OnUnavailable: "allow_with_warning"}}, g); err != nil {
		t.Error(err)
	}
}

func TestShieldPolicyAPI(t *testing.T) {
	e := newEnv(t)
	ra, rb := e.reseller("rpa"), e.reseller("rpb")
	ca, cb := e.tenant("pcust1", "pcust1.test"), e.tenant("pcust2", "pcust2.test")
	db := e.srv.Store.DB
	_, _ = db.Exec(`UPDATE users SET owner_id=? WHERE id=?`, ra, ca.ID)
	_, _ = db.Exec(`UPDATE users SET owner_id=? WHERE id=?`, rb, cb.ID)

	ad := mustLoginAdmin(t, e)
	// admin: global row, may be weak for "other"
	if code, m := ad.call("PUT", "/api/v1/admin/shield/policies", map[string]any{"account_id": nil,
		"rows": []map[string]any{{"file_class": "script", "on_suspicious": "quarantine"}, {"file_class": "other", "on_unavailable": "allow_with_warning"}}}); code != 200 {
		t.Fatalf("admin global put: %d %v", code, m)
	}
	if code, _ := ad.call("PUT", "/api/v1/admin/shield/policies", map[string]any{"rows": []map[string]any{{"file_class": "nope"}}}); code != 400 {
		t.Fatalf("invalid class: %d", code)
	}
	if code, _ := ad.call("PUT", "/api/v1/admin/shield/policies", map[string]any{"account_id": cb.ID,
		"rows": []map[string]any{{"file_class": "script", "on_unavailable": "allow_with_warning"}}}); code != 200 {
		t.Fatalf("admin may weaken one account: %d", code)
	}
	if p := e.srv.shieldPolicy(context.Background(), cb.ID); p.OnUnavailableScript != shield.ActAllowWarning || p.OnSuspiciousScript != shield.ActQuarantine {
		t.Fatalf("effective policy cust2: %+v", p)
	}

	rs := mustLogin(t, e, e.admin, "rpa", "")
	code, m := rs.call("GET", "/api/v1/admin/shield/policies", nil)
	if code != 200 || m["can_edit_global"] != false {
		t.Fatalf("reseller get: %d %v", code, m)
	}
	if acc, _ := m["accounts"].([]any); len(acc) != 0 {
		t.Fatalf("reseller A sees other accounts' rows: %v", acc)
	}
	if g, _ := m["global"].(map[string]any); len(g["rows"].([]any)) != 2 {
		t.Fatalf("reseller should see global rows: %v", m["global"])
	}
	if code, _ := rs.call("PUT", "/api/v1/admin/shield/policies", map[string]any{"rows": []map[string]any{{"file_class": "other", "on_suspicious": "block"}}}); code != 403 {
		t.Fatalf("reseller global put: %d", code)
	}
	if code, _ := rs.call("PUT", "/api/v1/admin/shield/policies", map[string]any{"account_id": cb.ID, "rows": []map[string]any{{"file_class": "other", "on_suspicious": "block"}}}); code != 404 {
		t.Fatalf("reseller A on B's account: %d", code)
	}
	if code, m := rs.call("PUT", "/api/v1/admin/shield/policies", map[string]any{"account_id": ca.ID, "rows": []map[string]any{{"file_class": "script", "on_suspicious": "hold"}}}); code != 403 || m["error"] != "shield_policy_weaker" {
		t.Fatalf("reseller weaker than global: %d %v", code, m)
	}
	if code, m := rs.call("PUT", "/api/v1/admin/shield/policies", map[string]any{"account_id": ca.ID,
		"rows": []map[string]any{{"file_class": "script", "on_suspicious": "block"}, {"file_class": "other", "on_suspicious": "quarantine"}}}); code != 200 {
		t.Fatalf("reseller own account stricter: %d %v", code, m)
	}
	if code, _ := rs.call("PUT", "/api/v1/admin/shield/policies", map[string]any{"account_id": ra, "rows": []map[string]any{}}); code != 400 && code != 404 {
		t.Fatalf("reseller on a reseller account: %d", code)
	}
	if p := e.srv.shieldPolicy(context.Background(), ca.ID); p.OnSuspiciousScript != shield.ActBlock || p.OnSuspiciousOther != shield.ActQuarantine {
		t.Fatalf("effective policy cust1: %+v", p)
	}
	// hosting user has no access at all
	us := mustLogin(t, e, e.user, "pcust1", "")
	if code, _ := us.call("GET", "/api/v1/admin/shield/policies", nil); code != 401 && code != 403 && code != 404 {
		t.Fatalf("user on admin policies: %d", code)
	}
}
