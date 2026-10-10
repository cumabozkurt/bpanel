// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

func TestWebxAPI(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	e.tenant("bob", "bob.test")
	a := mustLogin(t, e, e.user, "alice", "")
	b := mustLogin(t, e, e.user, "bob", "")
	var id int64
	if err := e.srv.Store.DB.QueryRow(`SELECT id FROM domains WHERE name='alice.test'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("/api/v1/user/web/%d", id)
	e.ag.reset()

	code, m := a.call("PUT", base+"/privacy", map[string]any{"dirs": []any{map[string]any{"path": "admin", "realm": "Staff", "users": []any{map[string]any{"name": "ops", "password": "Long-Pass-123"}}}}})
	if code != 200 {
		t.Fatalf("privacy: %d %v", code, m)
	}
	if s, _ := json.Marshal(m); strings.Contains(string(s), "$2y$") {
		t.Fatalf("hash leaked: %s", s)
	}
	var params rpc.WebxApplyParams
	for _, c := range e.ag.calls {
		if c.Method == rpc.MWebxApply {
			_ = json.Unmarshal(c.Params, &params)
		}
	}
	if params.User != "alice" || params.Vhost.Domain != "alice.test" || len(params.Config.Privacy) != 1 ||
		!strings.HasPrefix(params.Config.Privacy[0].Users[0].Hash, "$2y$10$") || strings.Contains(string(e.ag.calls[len(e.ag.calls)-1].Params), "Long-Pass-123") {
		t.Fatalf("agent params: %+v", params)
	}
	// keep the password when it is omitted; a new user needs one
	if code, m := a.call("PUT", base+"/privacy", map[string]any{"dirs": []any{map[string]any{"path": "/admin/", "users": []any{map[string]any{"name": "ops"}}}}}); code != 200 {
		t.Fatalf("keep password: %d %v", code, m)
	}
	if code, m := a.call("PUT", base+"/privacy", map[string]any{"dirs": []any{map[string]any{"path": "/admin/", "users": []any{map[string]any{"name": "new"}}}}}); code != 400 || m["error"] != "webx_password_required" {
		t.Fatalf("new user without password: %d %v", code, m)
	}
	// the other sections
	if code, m := a.call("PUT", base+"/hotlink", map[string]any{"enabled": true, "allowed": []string{"partner.test"}, "exts": []string{"jpg"}}); code != 200 {
		t.Fatalf("hotlink: %d %v", code, m)
	}
	if code, m := a.call("PUT", base+"/error-pages", map[string]any{"pages": map[string]string{"404": "<h1>x</h1>"}}); code != 200 {
		t.Fatalf("error pages: %d %v", code, m)
	}
	if code, m := a.call("PUT", base+"/mime", map[string]any{"types": []any{map[string]string{"ext": "webmanifest", "type": "application/manifest+json"}}}); code != 200 {
		t.Fatalf("mime: %d %v", code, m)
	}
	if code, m := a.call("PUT", base+"/ip-blocker", map[string]any{"deny": []string{"192.0.2.1", "198.51.100.0/24"}}); code != 200 {
		t.Fatalf("deny: %d %v", code, m)
	}
	_, g := a.call("GET", base+"/extras", nil)
	if g["domain"] != "alice.test" || len(g["deny"].([]any)) != 2 || len(g["mime"].([]any)) != 1 || g["hotlink"].(map[string]any)["enabled"] != true ||
		g["privacy"].([]any)[0].(map[string]any)["users"].([]any)[0] != "ops" {
		t.Fatalf("get: %v", g)
	}
	// injection attempts are 400 and never reach the agent
	n := len(e.ag.calls)
	for path, body := range map[string]any{
		"/privacy":     map[string]any{"dirs": []any{map[string]any{"path": "/a;\n}", "users": []any{map[string]any{"name": "x", "password": "Long-Pass-123"}}}}},
		"/hotlink":     map[string]any{"enabled": true, "allowed": []string{"a.test;\n"}, "exts": []string{"jpg"}},
		"/mime":        map[string]any{"types": []any{map[string]string{"ext": "x", "type": "text/x;}"}}},
		"/ip-blocker":  map[string]any{"deny": []string{"1.2.3.4; allow all"}},
		"/error-pages": map[string]any{"pages": map[string]string{"418": "x"}},
	} {
		if code, m := a.call("PUT", base+path, body); code != 400 {
			t.Errorf("%s accepted: %d %v", path, code, m)
		}
	}
	if len(e.ag.calls) != n {
		t.Fatal("invalid input reached the agent")
	}
	// another account cannot read or change alice's domain
	if code, _ := b.call("GET", base+"/extras", nil); code != 404 {
		t.Fatalf("bob read alice: %d", code)
	}
	if code, _ := b.call("PUT", base+"/ip-blocker", map[string]any{"deny": []string{}}); code != 404 {
		t.Fatalf("bob wrote alice: %d", code)
	}
	_, l := b.call("GET", "/api/v1/user/web/extras", nil)
	for _, d := range l["domains"].([]any) {
		if d.(map[string]any)["domain"] == "alice.test" {
			t.Fatal("bob lists alice's domain")
		}
	}
	// agent failure: nothing persisted
	e.ag.mu.Lock()
	e.ag.fail = map[string]error{rpc.MWebxApply: &rpc.Error{Code: "webx_configtest_failed"}}
	e.ag.mu.Unlock()
	if code, m := a.call("PUT", base+"/ip-blocker", map[string]any{"deny": []string{"203.0.113.5"}}); code < 400 || m["error"] != "webx_configtest_failed" {
		t.Fatalf("agent failure: %d %v", code, m)
	}
	var cfg string
	_ = e.srv.Store.DB.QueryRow(`SELECT config FROM webx_domains WHERE domain_id=?`, id).Scan(&cfg)
	if strings.Contains(cfg, "203.0.113.5") || !strings.Contains(cfg, "198.51.100.0/24") {
		t.Fatalf("failed apply persisted: %s", cfg)
	}
}
