// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/rbac"
)

// fake agent state for netsec.* (the real agent is tested in internal/agent)
var (
	fakeNsMu      sync.Mutex
	fakeNsToken   string
	fakeNsWafFail bool
)

func fakeNetsec(method string, b []byte) (any, bool, error) {
	fakeNsMu.Lock()
	defer fakeNsMu.Unlock()
	switch method {
	case rpc.MNetsecFwApply:
		fakeNsToken = fmt.Sprintf("tok-%d", time.Now().UnixNano())
		return rpc.NetsecFwApplyResult{Status: "pending", Token: fakeNsToken, Deadline: time.Now().Add(time.Minute), Script: "table inet bpanel {}", SyntaxOK: true}, true, nil
	case rpc.MNetsecFwConfirm:
		var p rpc.NetsecFwConfirmParams
		_ = json.Unmarshal(b, &p)
		if fakeNsToken == "" || p.Token != fakeNsToken {
			return nil, true, &rpc.Error{Code: "fw_no_pending", Message: "no pending change"}
		}
		fakeNsToken = ""
		return rpc.NetsecFwConfirmResult{Status: "confirmed"}, true, nil
	case rpc.MNetsecFwStatus:
		r := rpc.NetsecFwStatusResult{Supported: true, Pending: fakeNsToken != ""}
		if !r.Pending {
			r.LastRollback = "timeout"
		}
		return r, true, nil
	case rpc.MNetsecFwBlock, rpc.MNetsecFwUnblock:
		return rpc.NetsecFwBlockResult{Status: "ok"}, true, nil
	case rpc.MNetsecWafStatus:
		return rpc.NetsecWafStatusResult{Status: "not_installed", Reason: "missing: modsecurity-module"}, true, nil
	case rpc.MNetsecWafApply:
		if fakeNsWafFail {
			return nil, true, &rpc.Error{Code: "waf_configtest_failed", Message: "restored"}
		}
		return rpc.NetsecWafApplyResult{Status: "applied", Server: "nginx"}, true, nil
	}
	return nil, false, nil
}

// fakeNsTimeout simulates the agent's confirm timer firing.
func fakeNsTimeout() { fakeNsMu.Lock(); fakeNsToken = ""; fakeNsMu.Unlock() }

func TestNetsecLockoutGuardRejectsCallerIP(t *testing.T) {
	e := newEnv(t)
	root := mustLoginAdmin(t, e)
	code, m := root.call("POST", "/api/v1/admin/firewall/rules", map[string]any{"action": "deny", "cidr": "192.0.2.0/24"})
	if code != 400 || m["error"] != "fw_lockout" {
		t.Fatalf("deny of caller net: %d %v", code, m)
	}
	if code, m := root.call("POST", "/api/v1/admin/firewall/rules", map[string]any{"action": "deny", "cidr": "203.0.113.0/24"}); code != 200 {
		t.Fatalf("other net: %d %v", code, m)
	}
	// a stored rule that would lock out a different admin IP is caught at apply
	if _, err := e.srv.Store.DB.Exec(`INSERT INTO fw_rules(action,family,cidr) VALUES('deny','ip','192.0.2.10/32')`); err != nil {
		t.Fatal(err)
	}
	if code, m := root.call("POST", "/api/v1/admin/firewall/apply", map[string]any{}); code != 400 || m["error"] != "fw_lockout" {
		t.Fatalf("apply with lockout rule: %d %v", code, m)
	}
	if n := len(e.ag.find(rpc.MNetsecFwApply)); n != 0 {
		t.Fatalf("agent called despite lockout: %d", n)
	}
}

func TestNetsecApplyConfirmAndRollback(t *testing.T) {
	e := newEnv(t)
	root := mustLoginAdmin(t, e)
	if code, m := root.call("POST", "/api/v1/admin/firewall/rules", map[string]any{"action": "allow", "cidr": "198.51.100.0/24", "ports": []int{443}}); code != 200 {
		t.Fatalf("rule: %d %v", code, m)
	}
	// apply, never confirm → agent timer rolls back → status rolled_back
	code, m := root.call("POST", "/api/v1/admin/firewall/apply", map[string]any{})
	if code != 200 || m["status"] != "pending" || m["token"] == "" || m["deadline"] == nil {
		t.Fatalf("apply: %d %v", code, m)
	}
	var p rpc.NetsecFwApplyParams
	_ = json.Unmarshal(e.ag.find(rpc.MNetsecFwApply)[0].Params, &p)
	if p.Ruleset.AdminIP != "192.0.2.10" || p.ConfirmSeconds != 60 {
		t.Fatalf("admin ip/confirm not passed: %+v", p)
	}
	v1 := m["version"]
	fakeNsTimeout()
	_, st := root.call("GET", "/api/v1/admin/firewall/status", nil)
	if st["last_status"] != "rolled_back" || st["pending"] != false {
		t.Fatalf("status after timeout: %v", st)
	}
	if code, m := root.call("POST", "/api/v1/admin/firewall/confirm", map[string]any{"version": v1, "token": "x"}); code != 409 {
		t.Fatalf("confirm rolled back: %d %v", code, m)
	}
	// confirm path
	_, m = root.call("POST", "/api/v1/admin/firewall/apply", map[string]any{"confirm_seconds": 30})
	if code, r := root.call("POST", "/api/v1/admin/firewall/confirm", map[string]any{"version": m["version"], "token": "wrong"}); code != 400 {
		t.Fatalf("wrong token: %d %v", code, r)
	}
	if code, r := root.call("POST", "/api/v1/admin/firewall/confirm", map[string]any{"version": m["version"], "token": m["token"]}); code != 200 || r["status"] != "confirmed" {
		t.Fatalf("confirm: %d %v", code, r)
	}
	_, st = root.call("GET", "/api/v1/admin/firewall/status", nil)
	if st["current_version"] != m["version"] {
		t.Fatalf("current version: %v", st)
	}
	// history + rollback to v1
	_, h := root.call("GET", "/api/v1/admin/firewall/history", nil)
	if hs, _ := h["history"].([]any); len(hs) != 2 {
		t.Fatalf("history: %v", h)
	}
	code, rb := root.call("POST", fmt.Sprintf("/api/v1/admin/firewall/rollback/%v", v1), nil)
	if code != 200 || rb["status"] != "pending" {
		t.Fatalf("rollback: %d %v", code, rb)
	}
	// blocks
	code, b := root.call("POST", "/api/v1/admin/firewall/blocks", map[string]any{"ip": "203.0.113.9", "timeout_seconds": 3600, "reason": "scan"})
	if code != 200 {
		t.Fatalf("block: %d %v", code, b)
	}
	if code, r := root.call("POST", "/api/v1/admin/firewall/blocks", map[string]any{"ip": "192.0.2.10", "timeout_seconds": 60}); code != 400 {
		t.Fatalf("self block: %d %v", code, r)
	}
	if _, err := e.srv.Store.DB.Exec(`UPDATE fw_blocks SET expires_at=1`); err != nil {
		t.Fatal(err)
	}
	if n := e.srv.netsecExpire(t.Context()); n != 1 {
		t.Fatalf("expired %d", n)
	}
}

func TestNetsecRBACAndReauth(t *testing.T) {
	e := newEnv(t)
	staff(t, e, "nsaud", rbac.Auditor)
	aud := mustLogin(t, e, e.admin, "nsaud", "")
	if code, _ := aud.call("GET", "/api/v1/admin/firewall/rules", nil); code != 200 {
		t.Fatalf("auditor read: %d", code)
	}
	if _, _, err := e.srv.CreateAccount(t.Context(), &e.root, CreateAccountReq{Username: "nsres", Domain: "nsres.test", Password: tPW,
		PackageID: e.pkg(), Role: "reseller", MaxAccounts: LimitOf(5)}); err != nil {
		t.Fatal(err)
	}
	res := mustLogin(t, e, e.admin, "nsres", "")
	for _, s := range []*sess{aud, res} {
		for _, c := range []struct{ m, p string }{
			{"POST", "/api/v1/admin/firewall/rules"}, {"POST", "/api/v1/admin/firewall/apply"},
			{"POST", "/api/v1/admin/firewall/blocks"}, {"PUT", "/api/v1/admin/waf/nsres.test"},
		} {
			if code, m := s.call(c.m, c.p, map[string]any{}); code != 403 {
				t.Errorf("%s %s: %d %v", c.m, c.p, code, m)
			}
		}
	}
	root := mustLoginAdmin(t, e)
	if _, err := e.srv.Store.DB.Exec(`UPDATE sessions SET created_at=?, reauth_at=0`, time.Now().Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if code, m := root.call("POST", "/api/v1/admin/firewall/apply", map[string]any{}); code != 403 || m["error"] != "reauth_required" {
		t.Fatalf("stale apply: %d %v", code, m)
	}
	if code, m := root.call("POST", "/api/v1/admin/firewall/rollback/1", nil); code != 403 || m["error"] != "reauth_required" {
		t.Fatalf("stale rollback: %d %v", code, m)
	}
}

func TestNetsecWAF(t *testing.T) {
	e := newEnv(t)
	e.tenant("wafu", "waf.test")
	root := mustLoginAdmin(t, e)
	for _, ex := range [][]string{{"9420x"}, {"1;SecRuleEngine Off"}, {"-1"}, {"0"}} {
		if code, m := root.call("PUT", "/api/v1/admin/waf/waf.test", map[string]any{"mode": "block", "exclusions": ex}); code != 400 || m["error"] != "waf_invalid" {
			t.Errorf("exclusion %v: %d %v", ex, code, m)
		}
	}
	if code, m := root.call("PUT", "/api/v1/admin/waf/waf.test", map[string]any{"mode": "panic"}); code != 400 {
		t.Fatalf("bad mode: %d %v", code, m)
	}
	code, m := root.call("PUT", "/api/v1/admin/waf/waf.test", map[string]any{"mode": "block", "exclusions": []string{"942100", "920350", "942100"}})
	if code != 200 || m["version"] != float64(1) || len(m["exclusions"].([]any)) != 2 {
		t.Fatalf("waf put: %d %v", code, m)
	}
	fakeNsMu.Lock()
	fakeNsWafFail = true
	fakeNsMu.Unlock()
	defer func() { fakeNsMu.Lock(); fakeNsWafFail = false; fakeNsMu.Unlock() }()
	if code, m := root.call("PUT", "/api/v1/admin/waf/waf.test", map[string]any{"mode": "off"}); code < 400 || m["error"] != "waf_configtest_failed" {
		t.Fatalf("failing apply: %d %v", code, m)
	}
	_, l := root.call("GET", "/api/v1/admin/waf", nil)
	ds := l["domains"].([]any)
	if len(ds) == 0 || ds[0].(map[string]any)["mode"] != "block" {
		t.Fatalf("state changed after failed apply: %v", l)
	}
	if l["provider"].(map[string]any)["status"] != "not_installed" {
		t.Fatalf("provider: %v", l["provider"])
	}
	if code, _ := root.call("PUT", "/api/v1/admin/waf/nope.test", map[string]any{"mode": "audit"}); code != 404 {
		t.Fatalf("unknown domain: %d", code)
	}
}
