// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"fmt"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/appx"
)

func TestAppxAPI(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	e.tenant("bob", "bob.test")
	a := mustLogin(t, e, e.user, "alice", "")
	b := mustLogin(t, e, e.user, "bob", "")
	var did int64
	if err := e.srv.Store.DB.QueryRow(`SELECT id FROM domains WHERE name='alice.test'`).Scan(&did); err != nil {
		t.Fatal(err)
	}
	e.ag.reset()
	app := func(name, root, urlPath string) map[string]any {
		return map[string]any{"name": name, "runtime": "node", "version": "22", "root": root, "startup": "server.js", "domain_id": did, "url_path": urlPath,
			"env": map[string]string{"API_KEY": "x"}}
	}
	code, m := a.call("POST", "/api/v1/user/apps", app("api", "apps/api", "/api"))
	if code != 200 || m["port"].(float64) != 30000 || m["url"] != "https://alice.test/api/" {
		t.Fatalf("create: %d %v", code, m)
	}
	id := int64(m["id"].(float64))
	var p rpc.AppxAppApplyParams
	cs := e.ag.find(rpc.MAppxAppApply)
	if len(cs) != 1 || json.Unmarshal(cs[0].Params, &p) != nil || p.User != "alice" || len(p.Domains) != 1 || p.Domains[0].Vhost.Domain != "alice.test" ||
		len(p.Domains[0].Proxies) != 1 || p.Domains[0].Proxies[0].Port != 30000 {
		t.Fatalf("agent params: %+v", p)
	}
	// port allocation: next free port
	if code, m := a.call("POST", "/api/v1/user/apps", app("web", "apps/web", "/")); code != 200 || m["port"].(float64) != 30001 {
		t.Fatalf("second: %d %v", code, m)
	}
	// same URL twice, traversal, duplicate name, env reserved
	if code, m := a.call("POST", "/api/v1/user/apps", app("dup", "apps/x", "/api/")); code != 400 || m["error"] != "appx_url_path_taken" {
		t.Fatalf("url taken: %d %v", code, m)
	}
	if code, m := a.call("POST", "/api/v1/user/apps", app("esc", "../bob", "/esc")); code != 400 || m["error"] != "appx_invalid_path" {
		t.Fatalf("traversal: %d %v", code, m)
	}
	if code, m := a.call("POST", "/api/v1/user/apps", app("api", "apps/y", "/y")); code != 400 || m["error"] != "already_exists" {
		t.Fatalf("dup name: %d %v", code, m)
	}
	bad := app("envx", "apps/z", "/z")
	bad["env"] = map[string]string{"PORT": "80"}
	if code, m := a.call("POST", "/api/v1/user/apps", bad); code != 400 || m["error"] != "appx_invalid_env" {
		t.Fatalf("env: %d %v", code, m)
	}
	// ownership: bob sees nothing, cannot drive or delete alice's app, cannot use alice's domain
	if code, _ := b.call("POST", fmt.Sprintf("/api/v1/user/apps/%d/ctl", id), map[string]any{"action": "stop"}); code != 404 {
		t.Fatalf("bob ctl: %d", code)
	}
	if code, _ := b.call("DELETE", fmt.Sprintf("/api/v1/user/apps/%d", id), nil); code != 404 {
		t.Fatalf("bob delete: %d", code)
	}
	if code, _ := b.call("POST", "/api/v1/user/apps", app("steal", "apps/s", "/s")); code != 404 {
		t.Fatalf("bob on alice's domain: %d", code)
	}
	// agent failure undoes the row and frees the port
	e.ag.fail[rpc.MAppxAppApply] = &rpc.Error{Code: "appx_runtime_missing"}
	if code, m := a.call("POST", "/api/v1/user/apps", app("fails", "apps/f", "/f")); code == 200 {
		t.Fatalf("agent failure accepted: %v", m)
	}
	delete(e.ag.fail, rpc.MAppxAppApply)
	var n int
	_ = e.srv.Store.DB.QueryRow(`SELECT COUNT(*) FROM appx_apps WHERE name='fails'`).Scan(&n)
	if n != 0 {
		t.Fatal("row left after agent failure")
	}
	if code, m := a.call("DELETE", fmt.Sprintf("/api/v1/user/apps/%d", id), nil); code != 200 {
		t.Fatalf("delete: %d %v", code, m)
	}

	// installer
	if code, m := a.call("GET", "/api/v1/user/installer/catalog", nil); code != 200 || len(m["apps"].([]any)) < 16 {
		t.Fatalf("catalog: %d %v", code, m)
	}
	if code, m := a.call("POST", "/api/v1/user/installer/install", map[string]any{"app": "nosuchapp", "domain_id": did}); code != 400 || m["error"] != "appx_app_unavailable" {
		t.Fatalf("unknown app: %d %v", code, m)
	}
	saved := appx.Catalog
	appx.Catalog = append(append([]appx.CatalogApp{}, saved...), appx.CatalogApp{ID: "offapp", Name: "Off", Category: "cms", Disabled: "test"})
	code, m = a.call("POST", "/api/v1/user/installer/install", map[string]any{"app": "offapp", "domain_id": did})
	appx.Catalog = saved
	if code != 400 || m["error"] != "appx_app_unavailable" {
		t.Fatalf("disabled app: %d %v", code, m)
	}
	if code, m := a.call("POST", "/api/v1/user/installer/install", map[string]any{"app": "wordpress", "domain_id": did, "path": "../../etc"}); code != 400 || m["error"] != "appx_invalid_path" {
		t.Fatalf("install traversal: %d %v", code, m)
	}
	code, m = a.call("POST", "/api/v1/user/installer/install", map[string]any{"app": "wordpress", "domain_id": did, "path": "blog"})
	if code != 200 || m["url"] != "https://alice.test/blog/" || m["db_password"] != nil {
		t.Fatalf("install: %d %v", code, m)
	}
	var ip rpc.AppxInstallParams
	ic := e.ag.find(rpc.MAppxInstall)
	if len(ic) != 1 || json.Unmarshal(ic[0].Params, &ip) != nil || ip.User != "alice" || ip.DB.DBName == "" || ip.DB.DBPassword == "" || len(e.ag.find(rpc.MDBCreate)) == 0 {
		t.Fatalf("install params: %+v", ip)
	}
	inst := int64(m["id"].(float64))
	if code, _ := b.call("POST", fmt.Sprintf("/api/v1/user/wordpress/%d/maintenance", inst), map[string]any{"on": true}); code != 404 {
		t.Fatalf("bob maintenance: %d", code)
	}
	if code, m := a.call("POST", fmt.Sprintf("/api/v1/user/wordpress/%d/maintenance", inst), map[string]any{"on": true}); code != 200 {
		t.Fatalf("maintenance: %d %v", code, m)
	}
	// a failed download drops the database it created
	e.ag.reset()
	e.ag.fail[rpc.MAppxInstall] = &rpc.Error{Code: "appx_checksum_mismatch"}
	if code, m := a.call("POST", "/api/v1/user/installer/install", map[string]any{"app": "drupal", "domain_id": did, "path": "d"}); code == 200 || m["error"] != "appx_checksum_mismatch" {
		t.Fatalf("mismatch: %d %v", code, m)
	}
	if len(e.ag.find(rpc.MDBDrop)) != 1 || len(e.ag.find(rpc.MDBUserDrop)) != 1 {
		t.Fatalf("database not rolled back: %v", e.ag.methods())
	}
}
