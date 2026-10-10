// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

func fakeUsagex(method string, b []byte) (any, bool) {
	switch method {
	case rpc.MUsageBandwidthScan:
		var p rpc.BWScanParams
		_ = json.Unmarshal(b, &p)
		out := rpc.BWScanResult{Domains: []rpc.BWDomainResult{}}
		for _, c := range p.Cursors {
			r := rpc.BWDomainResult{Domain: c.Domain, Inode: 7, Offset: c.Offset, Status: "ok", Days: []rpc.BWDay{}}
			if c.Offset == 0 {
				r.Offset = 500
				r.Days = []rpc.BWDay{{Day: "2026-10-09", Bytes: 1000, Hits: 2}, {Day: "2026-10-10", Bytes: 3000, Hits: 4}}
			}
			out.Domains = append(out.Domains, r)
		}
		return out, true
	case rpc.MF2BStatus:
		return rpc.F2BStatusResult{Status: "not_installed", Reason: "fail2ban-client was not found", Jails: []rpc.F2BJail{}}, true
	case rpc.MF2BUnban, rpc.MF2BIgnore:
		return rpc.F2BActionResult{Status: "not_installed"}, true
	}
	return nil, false
}

func TestValidatePHPIni(t *testing.T) {
	ok := map[string]string{"memory_limit": "512m", "upload_max_filesize": "32M", "post_max_size": "64M", "max_execution_time": "60",
		"max_input_vars": "3000", "display_errors": "on", "date.timezone": "Europe/Istanbul"}
	out, err := ValidatePHPIni(ok, 1024)
	if err != nil || out["memory_limit"] != "512M" || out["display_errors"] != "On" {
		t.Fatalf("%v %v", out, err)
	}
	for _, bad := range []map[string]string{
		{"memory_limit": "2048M"},         // over cap
		{"memory_limit": "8M"},            // too small
		{"date.timezone": "Mars/Olympus"}, // not in tz db
		{"date.timezone": "UTC\nfoo=bar"}, // injection
		{"date.timezone": "Local"},
		{"display_errors": "maybe"},
		{"max_execution_time": "0"},
		{"max_input_vars": "1e9"},
		{"upload_max_filesize": "64M", "post_max_size": "8M"},
		{"open_basedir": "/"}, // not allowlisted
		{"upload_max_filesize": "9999G"},
	} {
		if _, err := ValidatePHPIni(bad, 1024); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	var ae *apiError
	if _, err := ValidatePHPIni(map[string]string{"memory_limit": "2G"}, 1024); !errors.As(err, &ae) || ae.Code != "php_ini_memory_cap" {
		t.Fatalf("cap code: %v", err)
	}
}

func TestPHPIniApplyAndRollback(t *testing.T) {
	e := newEnv(t)
	e.tenant("iniu", "ini.test")
	u := mustLogin(t, e, e.user, "iniu", "10.0.0.5")
	code, m := u.call("GET", "/api/v1/user/php-ini", nil)
	if code != 200 || m["version"] == "" {
		t.Fatalf("get: %d %v", code, m)
	}
	v := m["version"].(string)
	if code, m := u.call("PUT", "/api/v1/user/php-ini", map[string]any{"version": v, "settings": map[string]string{"date.timezone": "Nowhere/City"}}); code != 400 || m["error"] != "php_ini_invalid" {
		t.Fatalf("bad tz: %d %v", code, m)
	}
	if code, _ := u.call("PUT", "/api/v1/user/php-ini", map[string]any{"version": "5.6", "settings": map[string]string{}}); code != 400 {
		t.Fatalf("foreign version accepted: %d", code)
	}
	e.ag.reset()
	code, m = u.call("PUT", "/api/v1/user/php-ini", map[string]any{"version": v, "settings": map[string]string{"date.timezone": "Europe/Istanbul", "max_input_vars": "5000", "upload_max_filesize": "128M", "post_max_size": "128M"}})
	if code != 200 {
		t.Fatalf("put: %d %v", code, m)
	}
	calls := e.ag.find(rpc.MPHPPoolApply)
	if len(calls) != 1 {
		t.Fatalf("pool apply calls: %d", len(calls))
	}
	var p rpc.PHPPool
	_ = json.Unmarshal(calls[0].Params, &p)
	if p.User != "iniu" || p.INI["date.timezone"] != "Europe/Istanbul" || p.UploadMax != "128M" || p.INI["post_max_size"] != "128M" {
		t.Fatalf("pool spec: %+v", p)
	}
	// agent rejects (php-fpm -t) -> DB restored to the previous settings
	e.ag.fail[rpc.MPHPPoolApply] = &rpc.Error{Code: "php_config_invalid"}
	if code, _ := u.call("PUT", "/api/v1/user/php-ini", map[string]any{"version": v, "settings": map[string]string{"display_errors": "On"}}); code < 400 {
		t.Fatalf("failing apply: %d", code)
	}
	delete(e.ag.fail, rpc.MPHPPoolApply)
	_, m = u.call("GET", "/api/v1/user/php-ini?version="+v, nil)
	set := m["settings"].(map[string]any)
	if set["date.timezone"] != "Europe/Istanbul" || set["display_errors"] != nil {
		t.Fatalf("not rolled back: %v", set)
	}
}

func TestBandwidthCollectAndViews(t *testing.T) {
	e := newEnv(t)
	e.tenant("bwa", "bwa.test")
	e.tenant("bwb", "bwb.test")
	for i := 0; i < 2; i++ { // second run: cursor advanced, nothing double counted
		if _, err := e.srv.bandwidthCollect(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	a := mustLogin(t, e, e.user, "bwa", "10.0.0.6")
	code, m := a.call("GET", "/api/v1/user/bandwidth?month=2026-10", nil)
	if code != 200 || m["total_bytes"] != float64(4000) || len(m["domains"].([]any)) != 1 || len(m["days"].([]any)) != 2 {
		t.Fatalf("user bw: %d %v", code, m)
	}
	if code, _ := a.call("GET", "/api/v1/user/bandwidth?month=2026-13", nil); code != 400 {
		t.Fatalf("bad month: %d", code)
	}
	root := mustLoginAdmin(t, e)
	_, m = root.call("GET", "/api/v1/admin/bandwidth?month=2026-10", nil)
	if m["total_bytes"] != float64(8000) {
		t.Fatalf("admin bw: %v", m)
	}
}

func TestUserWAFOwnershipAndLock(t *testing.T) {
	e := newEnv(t)
	wa := e.tenant("wafa", "wafa.test")
	e.tenant("wafb", "wafb.test")
	a := mustLogin(t, e, e.user, "wafa", "10.0.0.7")
	_, m := a.call("GET", "/api/v1/user/waf", nil)
	if ds := m["domains"].([]any); len(ds) != 1 || ds[0].(map[string]any)["domain"] != "wafa.test" {
		t.Fatalf("list: %v", m)
	}
	if code, _ := a.call("PUT", "/api/v1/user/waf/wafb.test", map[string]any{"mode": "off"}); code != 404 {
		t.Fatalf("foreign domain: %d", code)
	}
	if code, m := a.call("PUT", "/api/v1/user/waf/wafa.test", map[string]any{"mode": "block"}); code != 200 || m["mode"] != "block" {
		t.Fatalf("own domain: %d %v", code, m)
	}
	root := mustLoginAdmin(t, e)
	if code, m := root.call("PUT", "/api/v1/admin/accounts/"+strconv.FormatInt(wa.ID, 10)+"/waf/wafa.test", map[string]any{"mode": "block", "lock": true}); code != 200 || m["locked"] != true {
		t.Fatalf("admin lock: %d %v", code, m)
	}
	if code, m := root.call("PUT", "/api/v1/admin/accounts/"+strconv.FormatInt(wa.ID, 10)+"/waf/wafb.test", map[string]any{"mode": "off"}); code != 404 {
		t.Fatalf("domain of another account: %d %v", code, m)
	}
	if code, m := a.call("PUT", "/api/v1/user/waf/wafa.test", map[string]any{"mode": "off"}); code != 403 || m["error"] != "waf_locked" {
		t.Fatalf("locked: %d %v", code, m)
	}
}

func TestBruteForce(t *testing.T) {
	e := newEnv(t)
	root := mustLoginAdmin(t, e)
	code, m := root.call("GET", "/api/v1/admin/brute-force", nil)
	if code != 200 || m["fail2ban"].(map[string]any)["status"] != "not_installed" {
		t.Fatalf("status: %d %v", code, m)
	}
	if code, _ := root.call("POST", "/api/v1/admin/brute-force/allowlist", map[string]any{"ip": "1.2.3.4; rm"}); code != 400 {
		t.Fatalf("bad ip: %d", code)
	}
	code, m = root.call("POST", "/api/v1/admin/brute-force/allowlist", map[string]any{"ip": "203.0.113.0/24", "note": "office"})
	if code != 200 || m["fail2ban"] != "not_installed" {
		t.Fatalf("allow: %d %v", code, m)
	}
	if code, _ := root.call("POST", "/api/v1/admin/brute-force/allowlist", map[string]any{"ip": "203.0.113.9/24"}); code != 409 {
		t.Fatalf("dup: %d", code)
	}
	if code, m := root.call("POST", "/api/v1/admin/brute-force/unban", map[string]any{"jail": "sshd", "ip": "198.51.100.1"}); code != 409 || m["error"] != "f2b_not_installed" {
		t.Fatalf("unban: %d %v", code, m)
	}
	if code, _ := root.call("DELETE", "/api/v1/admin/brute-force/allowlist/1", nil); code != 200 {
		t.Fatalf("del: %d", code)
	}
}
