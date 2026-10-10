// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// fakePGStatus is what the fake agent reports for pg.status.
var fakePGStatus = "ok"

func fakeDbx(method string, b []byte) (any, bool) {
	switch method {
	case rpc.MPGStatus:
		return rpc.PGStatus{Status: fakePGStatus, Version: "16.4"}, true
	case rpc.MPGSizes:
		var p rpc.PGSizesReq
		_ = json.Unmarshal(b, &p)
		return rpc.DBSizes{Sizes: map[string]int64{p.Owner + "_app": 4096}}, true
	case rpc.MDBXProcessList:
		return rpc.DBXProcList{Processes: []rpc.DBXProcess{}, MariaDB: rpc.DBXEngineStatus{Status: "ok"}, PostgreSQL: rpc.DBXEngineStatus{Status: fakePGStatus}}, true
	case rpc.MDBXRemoteSync:
		return rpc.DBXRemoteResult{}, true
	}
	return nil, false
}

func TestDbxRemoteHostsOwnershipAndValidation(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	e.tenant("mallory", "mallory.test")
	as := mustLogin(t, e, e.user, "alice", "")
	ms := mustLogin(t, e, e.user, "mallory", "")
	// switched off server-wide: refused, nothing sent to the agent
	if code, m := as.call("POST", "/api/v1/user/databases/remote", map[string]any{"host": "203.0.113.5"}); code != 409 || m["error"] != "remote_db_disabled" {
		t.Fatalf("disabled: %d %v", code, m)
	}
	e.srv.Store.Set("dbx_remote_enabled", "1")
	for _, h := range []string{"%", "10.0.0.%", "127.0.0.1", "localhost", "0.0.0.0/0", "10.0.0.1/24", "x'@'%", "2001:db8::/64", "a_b.example.com"} {
		if code, m := as.call("POST", "/api/v1/user/databases/remote", map[string]any{"host": h}); code != 400 || m["error"] != "invalid_remote_host" {
			t.Errorf("host %q: %d %v", h, code, m)
		}
	}
	if code, m := as.call("POST", "/api/v1/user/databases/remote", map[string]any{"host": "10.20.0.0/16"}); code != 200 {
		t.Fatalf("add: %d %v", code, m)
	}
	syncs := e.ag.find(rpc.MDBXRemoteSync)
	if len(syncs) == 0 {
		t.Fatal("no remote sync sent")
	}
	var p rpc.DBXRemoteSync
	_ = json.Unmarshal(syncs[len(syncs)-1].Params, &p)
	if p.Owner != "alice" || len(p.Hosts) != 1 || p.Hosts[0] != "10.20.0.0/16" {
		t.Errorf("sync params %+v", p)
	}
	code, m := as.call("GET", "/api/v1/user/databases/remote", nil)
	hs, _ := m["hosts"].([]any)
	if code != 200 || len(hs) != 1 || hs[0].(map[string]any)["mysql_host"] != "10.20.0.0/255.255.0.0" {
		t.Fatalf("list: %d %v", code, m)
	}
	id := int64(hs[0].(map[string]any)["id"].(float64))
	// another tenant can neither see nor delete it
	if _, m := ms.call("GET", "/api/v1/user/databases/remote", nil); len(m["hosts"].([]any)) != 0 {
		t.Errorf("foreign hosts visible: %v", m)
	}
	if code, _ := ms.call("DELETE", fmt.Sprintf("/api/v1/user/databases/remote/%d", id), nil); code != 404 {
		t.Errorf("foreign delete: %d", code)
	}
	if code, _ := as.call("DELETE", fmt.Sprintf("/api/v1/user/databases/remote/%d", id), nil); code != 200 {
		t.Errorf("own delete: %d", code)
	}
}

func TestDbxPostgresOwnershipAndNotInstalled(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	e.tenant("mallory", "mallory.test")
	as := mustLogin(t, e, e.user, "alice", "")
	ms := mustLogin(t, e, e.user, "mallory", "")
	defer func() { fakePGStatus = "ok" }()
	fakePGStatus = "not_installed"
	if code, m := as.call("POST", "/api/v1/user/postgresql", map[string]any{"name": "app", "password": tPW}); code != 422 || m["error"] != "pg_not_installed" {
		t.Fatalf("not installed: %d %v", code, m)
	}
	if len(e.ag.find(rpc.MPGCreate)) != 0 {
		t.Fatal("pg.create sent although not installed")
	}
	fakePGStatus = "ok"
	for _, n := range []string{"a\"b", "x; DROP DATABASE postgres", "-ab", strings.Repeat("x", 70)} {
		if code, _ := as.call("POST", "/api/v1/user/postgresql", map[string]any{"name": n, "password": tPW}); code != 400 {
			t.Errorf("name %q: %d", n, code)
		}
	}
	if code, m := as.call("POST", "/api/v1/user/postgresql", map[string]any{"name": "app", "password": tPW}); code != 200 || m["name"] != "alice_app" {
		t.Fatalf("create: %d %v", code, m)
	}
	var p rpc.PGDB
	c := e.ag.find(rpc.MPGCreate)
	_ = json.Unmarshal(c[0].Params, &p)
	if len(c) != 1 || p.Owner != "alice" || p.Name != "alice_app" {
		t.Errorf("params %d %+v", len(c), p)
	}
	code, m := as.call("GET", "/api/v1/user/postgresql", nil)
	dbs, _ := m["databases"].([]any)
	if code != 200 || len(dbs) != 1 || dbs[0].(map[string]any)["size_bytes"].(float64) != 4096 {
		t.Fatalf("list: %d %v", code, m)
	}
	id := int64(dbs[0].(map[string]any)["id"].(float64))
	if code, _ := ms.call("DELETE", fmt.Sprintf("/api/v1/user/postgresql/%d", id), nil); code != 404 {
		t.Errorf("foreign delete: %d", code)
	}
	if code, _ := ms.call("PUT", fmt.Sprintf("/api/v1/user/postgresql/%d/password", id), map[string]any{"password": tPW}); code != 404 {
		t.Errorf("foreign password: %d", code)
	}
	if code, m := as.call("PUT", fmt.Sprintf("/api/v1/user/postgresql/%d/password", id), map[string]any{"password": tPW}); code != 200 {
		t.Errorf("own password: %d %v", code, m)
	}
	if code, _ := as.call("DELETE", fmt.Sprintf("/api/v1/user/postgresql/%d", id), nil); code != 200 {
		t.Errorf("own delete: %d", code)
	}
}

func TestDbxProcessesAndLimits(t *testing.T) {
	e := newEnv(t)
	acc := e.tenant("alice", "alice.test")
	as := mustLogin(t, e, e.user, "alice", "")
	if code, m := as.call("GET", "/api/v1/user/databases/processes", nil); code != 200 {
		t.Fatalf("processes: %d %v", code, m)
	}
	for _, body := range []map[string]any{{"engine": "oracle", "id": 1}, {"engine": "mariadb", "id": 0}} {
		if code, _ := as.call("POST", "/api/v1/user/databases/processes/kill", body); code != 400 {
			t.Errorf("kill %v: %d", body, code)
		}
	}
	if code, _ := as.call("POST", "/api/v1/user/databases/processes/kill", map[string]any{"engine": "mariadb", "id": 12}); code != 200 {
		t.Errorf("kill: %d", code)
	}
	var k rpc.DBXKill
	_ = json.Unmarshal(e.ag.find(rpc.MDBXKill)[0].Params, &k)
	if k.Owner != "alice" || k.ID != 12 {
		t.Errorf("kill params %+v", k)
	}
	// the admin sets the connection limit
	ad := mustLoginAdmin(t, e)
	path := fmt.Sprintf("/api/v1/admin/accounts/%d/db-limits", acc.ID)
	if code, _ := ad.call("PUT", path, map[string]any{"max_user_connections": -3}); code != 400 {
		t.Errorf("negative limit: %d", code)
	}
	if code, m := ad.call("PUT", path, map[string]any{"max_user_connections": 15}); code != 200 {
		t.Fatalf("limit: %d %v", code, m)
	}
	var p rpc.DBXRemoteSync
	s := e.ag.find(rpc.MDBXRemoteSync)
	_ = json.Unmarshal(s[len(s)-1].Params, &p)
	if p.MaxConn != 15 || p.Owner != "alice" {
		t.Errorf("sync %+v", p)
	}
	if code, m := ad.call("GET", path, nil); code != 200 || m["max_user_connections"].(float64) != 15 {
		t.Errorf("get limit: %d %v", code, m)
	}
}
