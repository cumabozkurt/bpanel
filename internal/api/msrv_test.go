package api

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cumabozkurt/bpanel/internal/msrv"
)

func TestMsrvAPIEnrolRotateRevoke(t *testing.T) {
	e := newEnv(t)
	e.srv.Cfg.SecretKeyFile = filepath.Join(t.TempDir(), "secret.key")
	as := mustLoginAdmin(t, e)

	// validation
	if code, m := as.call("POST", "/api/v1/admin/servers", map[string]any{"name": "Bad Name!", "roles": []string{"web"}}); code != 400 || m["error"] != "msrv_bad_name" {
		t.Fatalf("bad name: %d %v", code, m)
	}
	if code, m := as.call("POST", "/api/v1/admin/servers", map[string]any{"name": "n1", "roles": []string{"root"}}); code != 400 || m["error"] != "msrv_bad_roles" {
		t.Fatalf("bad roles: %d %v", code, m)
	}
	if code, m := as.call("POST", "/api/v1/admin/servers", map[string]any{"name": "n1", "address": "nope", "roles": []string{"web"}}); code != 400 || m["error"] != "msrv_bad_address" {
		t.Fatalf("bad address: %d %v", code, m)
	}
	code, m := as.call("POST", "/api/v1/admin/servers", map[string]any{"name": "web1", "address": "127.0.0.1:1", "roles": []string{"web", "dns"}})
	if code != 200 {
		t.Fatalf("create: %d %v", code, m)
	}
	tok, _ := m["token"].(string)
	if !strings.HasPrefix(tok, "bpj_") || !strings.Contains(m["command"].(string), "bpanel-agent join") {
		t.Fatalf("token/command: %v", m)
	}
	// the token is never stored in clear
	var n int
	_ = e.srv.Store.DB.QueryRow(`SELECT COUNT(*) FROM msrv_join_tokens WHERE token_hash=?`, tok).Scan(&n)
	if n != 0 {
		t.Fatal("token stored in clear")
	}
	if code, m := as.call("POST", "/api/v1/admin/servers", map[string]any{"name": "web1", "roles": []string{"web"}}); code != 409 || m["error"] != "msrv_name_taken" {
		t.Fatalf("dup: %d %v", code, m)
	}

	// join over the public endpoint (no session)
	_, csr, _ := msrv.NewNodeKeyAndCSR("web1")
	w := e.do(e.user, req{method: "POST", path: "/msrv/join", body: map[string]string{"token": tok, "csr": string(csr)}}, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("join: %d %s", w.Code, w.Body.String())
	}
	// single use
	w = e.do(e.user, req{method: "POST", path: "/msrv/join", body: map[string]string{"token": tok, "csr": string(csr)}}, nil)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "msrv_token_invalid") {
		t.Fatalf("replay: %d %s", w.Code, w.Body.String())
	}
	// garbage CSR with a fresh token is refused and burns the token
	code, m = as.call("POST", "/api/v1/admin/servers/1/rotate", nil)
	if code != 200 {
		t.Fatalf("rotate: %d %v", code, m)
	}
	w = e.do(e.user, req{method: "POST", path: "/msrv/join", body: map[string]string{"token": m["token"].(string), "csr": "junk"}}, nil)
	if w.Code != 400 {
		t.Fatalf("junk csr: %d %s", w.Code, w.Body.String())
	}

	code, m = as.call("GET", "/api/v1/admin/servers", nil)
	nodes, _ := m["nodes"].([]any)
	if code != 200 || len(nodes) != 1 || nodes[0].(map[string]any)["status"] != "active" || m["ca_fingerprint"] == "" {
		t.Fatalf("list: %d %v", code, m)
	}
	// health against a closed port: stored as down, never a fake ok
	code, m = as.call("POST", "/api/v1/admin/servers/1/health", nil)
	if code != 200 || m["ok"] != false || m["error"] == "" {
		t.Fatalf("health: %d %v", code, m)
	}
	// push: one job per node, node_id recorded
	code, m = as.call("POST", "/api/v1/admin/servers/push", map[string]any{"bundle": "revocations", "node_ids": []int64{1, 99}})
	if code != 200 {
		t.Fatalf("push: %d %v", code, m)
	}
	refs := m["jobs"].([]any)
	if len(refs) != 2 || refs[0].(map[string]any)["job_id"] == nil || refs[1].(map[string]any)["error"] != "msrv_node_unknown" {
		t.Fatalf("push refs: %v", refs)
	}
	if code, m = as.call("GET", "/api/v1/admin/servers/1/jobs", nil); code != 200 || len(m["jobs"].([]any)) != 1 {
		t.Fatalf("node jobs: %d %v", code, m)
	}
	if code, m = as.call("POST", "/api/v1/admin/servers/push", map[string]any{"bundle": "shell", "node_ids": []int64{1}}); code != 400 || m["error"] != "msrv_bad_bundle" {
		t.Fatalf("bad bundle: %d %v", code, m)
	}
	// revoke: node revoked, rotate refused afterwards
	if code, m = as.call("POST", "/api/v1/admin/servers/1/revoke", nil); code != 200 {
		t.Fatalf("revoke: %d %v", code, m)
	}
	if code, m = as.call("POST", "/api/v1/admin/servers/1/rotate", nil); code != 409 || m["error"] != "msrv_cert_revoked" {
		t.Fatalf("rotate revoked: %d %v", code, m)
	}
	if code, _ = as.call("POST", "/api/v1/admin/servers/42/revoke", nil); code != 404 {
		t.Fatalf("revoke unknown: %d", code)
	}
	// admin API is not reachable from the user realm / tenants
	e.tenant("alice", "alice.test")
	us := mustLogin(t, e, e.user, "alice", "")
	if code, _ = us.call("GET", "/api/v1/admin/servers", nil); code != 404 && code != 403 && code != 401 {
		t.Fatalf("tenant reached admin servers: %d", code)
	}
}
