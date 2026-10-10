// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/clusterx"
)

func TestClusterxDNSAPI(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	a, code := e.login(e.admin, "rootadmin", "Admin-Pass-123", "", "")
	if a == nil {
		t.Fatalf("login %d", code)
	}
	if c, m := a.call("POST", "/api/v1/admin/dns-cluster/secondaries", map[string]any{"ip": "127.0.0.1"}); c != 400 || m["error"] != "cluster_invalid_ip" {
		t.Fatalf("loopback: %d %v", c, m)
	}
	e.ag.reset()
	c, m := a.call("POST", "/api/v1/admin/dns-cluster/secondaries", map[string]any{"ip": "192.0.2.53", "name": "ns2"})
	if c != 200 {
		t.Fatalf("add: %d %v", c, m)
	}
	var p rpc.ClusterApplyReq
	for _, cl := range e.ag.calls {
		if cl.Method == rpc.MClusterApply {
			_ = json.Unmarshal(cl.Params, &p)
		}
	}
	if strings.Join(p.Secondaries, ",") != "192.0.2.53" || strings.Join(p.Zones, ",") != "alice.test" {
		t.Fatalf("agent params: %+v", p)
	}
	if c, m := a.call("POST", "/api/v1/admin/dns-cluster/secondaries", map[string]any{"ip": "192.0.2.53"}); c != 409 || m["error"] != "cluster_duplicate" {
		t.Fatalf("dup: %d %v", c, m)
	}
	// agent failure: the row is not kept
	e.ag.fail[rpc.MClusterApply] = &rpc.Error{Code: "cluster_reload_failed", Message: "x"}
	if c, _ := a.call("POST", "/api/v1/admin/dns-cluster/secondaries", map[string]any{"ip": "192.0.2.54"}); c < 400 {
		t.Fatalf("agent failure accepted: %d", c)
	}
	delete(e.ag.fail, rpc.MClusterApply)
	var n int
	e.srv.Store.DB.QueryRow(`SELECT COUNT(*) FROM dns_cluster_secondaries`).Scan(&n)
	if n != 1 {
		t.Fatalf("rows: %d", n)
	}
	// SOA status (stubbed resolver of serials)
	old := clusterQuerySOA
	defer func() { clusterQuerySOA = old }()
	clusterQuerySOA = func(_ context.Context, server, zone string, _ time.Duration) clusterx.SOAResult {
		if server == "127.0.0.1:53" {
			return clusterx.SOAResult{Serial: 2026101005, Found: true}
		}
		return clusterx.SOAResult{Serial: 2026101004, Found: true}
	}
	c, m = a.call("GET", "/api/v1/admin/dns-cluster/status", nil)
	if c != 200 {
		t.Fatalf("status: %d %v", c, m)
	}
	zs := m["zones"].([]any)
	if st := zs[0].(map[string]any)["secondaries"].(map[string]any)["192.0.2.53"]; st != "behind" {
		t.Fatalf("state: %v", m)
	}
	clusterQuerySOA = func(_ context.Context, server, zone string, _ time.Duration) clusterx.SOAResult {
		if server == "127.0.0.1:53" {
			return clusterx.SOAResult{Serial: 7, Found: true}
		}
		return clusterx.SOAResult{Err: errors.New("i/o timeout")}
	}
	_, m = a.call("GET", "/api/v1/admin/dns-cluster/status", nil)
	if st := m["zones"].([]any)[0].(map[string]any)["secondaries"].(map[string]any)["192.0.2.53"]; st != "unreachable" {
		t.Fatalf("unreachable: %v", m)
	}
	// remote PowerDNS API: SSRF guard on the URL
	if c, m := a.call("POST", "/api/v1/admin/dns-cluster/remotes", map[string]any{"name": "r", "url": "http://127.0.0.1:8081", "api_key": "secretkey123", "primary_ip": "192.0.2.1"}); c != 422 || m["error"] != "webhook_url_blocked" {
		t.Fatalf("ssrf: %d %v", c, m)
	}
	// users never reach the admin tool
	u := mustLogin(t, e, e.user, "alice", "")
	if c, _ := u.call("GET", "/api/v1/admin/dns-cluster", nil); c != 404 && c != 403 {
		t.Fatalf("user reached admin route: %d", c)
	}
	var sid int64
	e.srv.Store.DB.QueryRow(`SELECT id FROM dns_cluster_secondaries`).Scan(&sid)
	if c, m := a.call("DELETE", "/api/v1/admin/dns-cluster/secondaries/"+itoa(sid), nil); c != 200 {
		t.Fatalf("delete: %d %v", c, m)
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func pluginArchive(priv ed25519.PrivateKey, manifest string, extra map[string][]byte) string {
	files := map[string][]byte{"plugin.json": []byte(manifest), "ui/index.html": []byte("<h1>hello</h1>")}
	for k, v := range extra {
		files[k] = v
	}
	files["plugin.sig"] = clusterx.Sign(files, priv)
	return base64.StdEncoding.EncodeToString(clusterx.PackTarGz(files))
}

func TestClusterxPluginsAPI(t *testing.T) {
	e := newEnv(t)
	e.srv.Cfg.SecretKeyFile = filepath.Join(t.TempDir(), "secret.key")
	a, _ := e.login(e.admin, "rootadmin", "Admin-Pass-123", "", "")
	e.srv.sec.resolver = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	manifest := `{"name":"hello","version":"1.0.0","author":"Example","license":"Apache-2.0","permissions":["ui.page","events.subscribe"],"ui_entry":"index.html","hooks":[{"events":["account.*"],"url":"https://hooks.example.com/x"}]}`
	good := pluginArchive(priv, manifest, nil)

	// no trusted key yet
	if c, m := a.call("POST", "/api/v1/admin/plugins/inspect", map[string]any{"archive": good}); c != 400 || m["error"] != "plugin_untrusted" {
		t.Fatalf("untrusted: %d %v", c, m)
	}
	if c, m := a.call("POST", "/api/v1/admin/plugin-keys", map[string]any{"name": "me", "pubkey": "nope"}); c != 400 || m["error"] != "plugin_invalid_key" {
		t.Fatalf("bad key: %d %v", c, m)
	}
	if c, m := a.call("POST", "/api/v1/admin/plugin-keys", map[string]any{"name": "me", "pubkey": base64.StdEncoding.EncodeToString(pub)}); c != 200 {
		t.Fatalf("key: %d %v", c, m)
	}
	// wrong signer, permission outside the allowlist, traversal
	if c, m := a.call("POST", "/api/v1/admin/plugins", map[string]any{"archive": pluginArchive(other, manifest, nil)}); c != 400 || m["error"] != "plugin_bad_signature" {
		t.Fatalf("bad sig: %d %v", c, m)
	}
	evil := strings.Replace(manifest, `"events.subscribe"]`, `"events.subscribe","shell.root"]`, 1)
	if c, m := a.call("POST", "/api/v1/admin/plugins", map[string]any{"archive": pluginArchive(priv, evil, nil)}); c != 400 || m["error"] != "plugin_permission_denied" {
		t.Fatalf("perm: %d %v", c, m)
	}
	if c, m := a.call("POST", "/api/v1/admin/plugins", map[string]any{"archive": pluginArchive(priv, manifest, map[string][]byte{"ui/../../../etc/cron.d/x": []byte("x")})}); c != 400 || m["error"] != "plugin_unsafe_path" {
		t.Fatalf("traversal: %d %v", c, m)
	}
	c, m := a.call("POST", "/api/v1/admin/plugins/inspect", map[string]any{"archive": good})
	if c != 200 || len(m["capabilities"].([]any)) != 2 {
		t.Fatalf("inspect: %d %v", c, m)
	}
	e.ag.reset()
	if c, m := a.call("POST", "/api/v1/admin/plugins", map[string]any{"archive": good}); c != 200 {
		t.Fatalf("install: %d %v", c, m)
	}
	if len(e.ag.calls) == 0 || e.ag.calls[len(e.ag.calls)-1].Method != rpc.MPluginInstall {
		t.Fatalf("agent not called: %+v", e.ag.calls)
	}
	// enable registers the hook as a webhook; disable removes it
	if c, m := a.call("POST", "/api/v1/admin/plugins/hello/enable", map[string]any{"enabled": true}); c != 200 {
		t.Fatalf("enable: %d %v", c, m)
	}
	var hooks int
	e.srv.Store.DB.QueryRow(`SELECT COUNT(*) FROM webhooks WHERE name LIKE 'plugin:hello:%'`).Scan(&hooks)
	if hooks != 1 {
		t.Fatalf("hooks: %d", hooks)
	}
	// static UI: sandboxed, only for enabled plugins, no traversal
	dir := t.TempDir()
	oldRoot := PluginRoot
	defer func() { PluginRoot = oldRoot }()
	PluginRoot = dir
	os.MkdirAll(filepath.Join(dir, "hello", "ui"), 0o755)
	os.WriteFile(filepath.Join(dir, "hello", "ui", "index.html"), []byte("<h1>hello</h1>"), 0o644)
	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("s"), 0o644)
	w := e.do(a.h, req{method: "GET", path: "/api/v1/admin/plugins/hello/ui/index.html"}, a)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "sandbox") || w.Body.String() != "<h1>hello</h1>" {
		t.Fatalf("asset: %d %v %q", w.Code, w.Header(), w.Body.String())
	}
	for _, p := range []string{"/api/v1/admin/plugins/hello/ui/../../secret.txt", "/api/v1/admin/plugins/hello/ui/%2e%2e/%2e%2e/secret.txt", "/api/v1/admin/plugins/hello/ui/"} {
		if w := e.do(a.h, req{method: "GET", path: p}, a); w.Code == 200 && w.Body.String() == "s" {
			t.Fatalf("traversal served %s", p)
		}
	}
	// an enabled plugin cannot be overwritten in place
	if c, m := a.call("POST", "/api/v1/admin/plugins", map[string]any{"archive": good}); c != 409 || m["error"] != "plugin_exists" {
		t.Fatalf("upgrade while enabled: %d %v", c, m)
	}
	if c, _ := a.call("POST", "/api/v1/admin/plugins/hello/enable", map[string]any{"enabled": false}); c != 200 {
		t.Fatal("disable")
	}
	e.srv.Store.DB.QueryRow(`SELECT COUNT(*) FROM webhooks WHERE name LIKE 'plugin:hello:%'`).Scan(&hooks)
	if hooks != 0 {
		t.Fatalf("hooks after disable: %d", hooks)
	}
	if w := e.do(a.h, req{method: "GET", path: "/api/v1/admin/plugins/hello/ui/index.html"}, a); w.Code != 404 {
		t.Fatalf("disabled plugin served: %d", w.Code)
	}
	if c, _ := a.call("DELETE", "/api/v1/admin/plugins/hello", nil); c != 200 {
		t.Fatal("remove")
	}
	c, m = a.call("GET", "/api/v1/admin/plugins", nil)
	if c != 200 || len(m["plugins"].([]any)) != 0 || len(m["keys"].([]any)) != 1 {
		t.Fatalf("list: %d %v", c, m)
	}
}
