// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

func devxFakeDNS(e *env) {
	e.srv.sec.resolver = func(_ context.Context, h string) ([]net.IP, error) {
		switch h {
		case "internal.example":
			return []net.IP{net.ParseIP("192.168.1.10")}, nil
		case "rebind.example":
			return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("127.0.0.1")}, nil
		}
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
}

func TestDevxGitAPI(t *testing.T) {
	e := newEnv(t)
	devxFakeDNS(e)
	e.tenant("alice", "alice.test")
	e.tenant("bob", "bob.test")
	a := mustLogin(t, e, e.user, "alice", "")
	b := mustLogin(t, e, e.user, "bob", "")
	e.ag.reset()
	for url, want := range map[string]string{
		"file:///etc/passwd":                 "git_url_scheme",
		"/home/bob/site":                     "git_url_scheme",
		"http://example.com/a.git":           "git_url_scheme",
		"https://internal.example/a.git":     "target_blocked",
		"https://rebind.example/a.git":       "target_blocked",
		"https://169.254.169.254/latest.git": "target_blocked",
		"ssh://git@[::1]/x.git":              "target_blocked",
		"https://u:p@example.com/a.git":      "git_url_credentials",
	} {
		code, m := a.call("POST", "/api/v1/user/git", map[string]any{"name": "site", "clone_url": url})
		if code != 422 || m["error"] != want {
			t.Errorf("%s: %d %v want %s", url, code, m, want)
		}
	}
	if code, m := a.call("POST", "/api/v1/user/git", map[string]any{"name": "site", "path": "../bob"}); code != 400 || m["error"] != "git_path_invalid" {
		t.Errorf("path escape: %d %v", code, m)
	}
	if code, m := a.call("POST", "/api/v1/user/git", map[string]any{"name": "site", "deploy_path": "etc/x"}); code != 400 || m["error"] != "git_deploy_path_invalid" {
		t.Errorf("deploy path: %d %v", code, m)
	}
	if n := len(e.ag.find(rpc.MGitClone)) + len(e.ag.find(rpc.MGitInit)); n != 0 {
		t.Fatalf("agent called for rejected input (%d)", n)
	}
	code, m := a.call("POST", "/api/v1/user/git", map[string]any{"name": "site", "clone_url": "git@github.com:me/site.git", "deploy_path": "public_html"})
	if code != 200 {
		t.Fatalf("clone: %d %v", code, m)
	}
	cl := e.ag.find(rpc.MGitClone)
	var p rpc.GitClone
	if len(cl) != 1 || json.Unmarshal(cl[0].Params, &p) != nil || p.User != "alice" || p.Path != "repositories/site" || p.URL != "ssh://git@github.com/me/site.git" || p.AllowPrivate {
		t.Fatalf("clone params %+v", p)
	}
	id := int64(m["id"].(float64))
	if code, _ := a.call("POST", "/api/v1/user/git", map[string]any{"name": "site2", "path": "repositories/site"}); code != 409 {
		t.Errorf("duplicate path: %d", code)
	}
	// ownership: bob sees nothing of alice's
	for _, c := range [][2]string{{"GET", ""}, {"PUT", ""}, {"POST", "/deploy"}, {"DELETE", ""}} {
		if code, _ := b.call(c[0], fmt.Sprintf("/api/v1/user/git/%d%s", id, c[1]), map[string]any{"pull": true, "deploy_path": "public_html"}); code != 404 {
			t.Errorf("bob %s %s: %d", c[0], c[1], code)
		}
	}
	if _, m := b.call("GET", "/api/v1/user/git", nil); len(m["repos"].([]any)) != 0 {
		t.Errorf("bob lists alice's repos: %v", m)
	}
	e.ag.reset()
	if code, m := a.call("POST", fmt.Sprintf("/api/v1/user/git/%d/deploy", id), map[string]any{"pull": true, "deploy": true}); code != 200 {
		t.Fatalf("deploy: %d %v", code, m)
	}
	var d rpc.GitDeploy
	if dc := e.ag.find(rpc.MGitDeploy); len(dc) != 1 || json.Unmarshal(dc[0].Params, &d) != nil || d.DeployPath != "public_html" || !d.Pull || d.User != "alice" {
		t.Fatalf("deploy params %+v", d)
	}
	if code, _ := a.call("DELETE", fmt.Sprintf("/api/v1/user/git/%d?files=1", id), nil); code != 200 || len(e.ag.find(rpc.MGitRemove)) != 1 {
		t.Fatalf("delete: %d", code)
	}
}

func TestDevxTrackDNSAPI(t *testing.T) {
	e := newEnv(t)
	devxFakeDNS(e)
	e.tenant("alice", "alice.test")
	a := mustLogin(t, e, e.user, "alice", "")
	for _, h := range []string{"-n", "a;b.com", "localhost"} {
		if code, _ := a.call("GET", "/api/v1/user/dns-lookup?host="+h, nil); code != 400 {
			t.Errorf("lookup %q: %d", h, code)
		}
	}
	if code, _ := a.call("GET", "/api/v1/user/dns-lookup?host=example.com&type=AXFR", nil); code != 400 {
		t.Errorf("AXFR allowed: %d", code)
	}
	if code, m := a.call("POST", "/api/v1/user/traceroute", map[string]any{"host": "internal.example"}); code != 422 || m["error"] != "target_blocked" {
		t.Errorf("traceroute internal: %d %v", code, m)
	}
	if code, m := a.call("POST", "/api/v1/user/traceroute", map[string]any{"host": "10.0.0.1"}); code != 422 {
		t.Errorf("traceroute private ip: %d %v", code, m)
	}
	if code, _ := a.call("POST", "/api/v1/user/traceroute", map[string]any{"host": "example.com"}); code != 200 || len(e.ag.find(rpc.MTraceRoute)) != 1 {
		t.Errorf("traceroute: %d", code)
	}
	// rate limit (3/min, burst 2): the next calls are refused
	got429 := false
	for i := 0; i < 4; i++ {
		if code, _ := a.call("POST", "/api/v1/user/traceroute", map[string]any{"host": "example.com"}); code == 429 {
			got429 = true
		}
	}
	if !got429 {
		t.Error("traceroute not rate limited")
	}
}

func TestDevxDDNS(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	e.tenant("bob", "bob.test")
	a := mustLogin(t, e, e.user, "alice", "")
	b := mustLogin(t, e, e.user, "bob", "")
	var main int64
	_ = e.srv.Store.DB.QueryRow(`SELECT id FROM domains WHERE name='alice.test'`).Scan(&main)
	if code, m := a.call("POST", "/api/v1/user/domains", map[string]any{"name": "home", "kind": "sub", "parent_id": main}); code != 200 {
		t.Fatalf("sub: %d %v", code, m)
	}
	var sub int64
	_ = e.srv.Store.DB.QueryRow(`SELECT id FROM domains WHERE name='home.alice.test'`).Scan(&sub)
	if code, m := a.call("POST", "/api/v1/user/ddns", map[string]any{"domain_id": main}); code != 422 || m["error"] != "ddns_not_subdomain" {
		t.Errorf("main domain: %d %v", code, m)
	}
	if code, _ := b.call("POST", "/api/v1/user/ddns", map[string]any{"domain_id": sub}); code != 404 {
		t.Errorf("bob on alice's subdomain: %d", code)
	}
	code, m := a.call("POST", "/api/v1/user/ddns", map[string]any{"domain_id": sub})
	if code != 200 {
		t.Fatalf("ddns: %d %v", code, m)
	}
	tok := m["token"].(string)
	var stored string
	var hid int64
	_ = e.srv.Store.DB.QueryRow(`SELECT id, token_hash FROM ddns_hosts WHERE domain_id=?`, sub).Scan(&hid, &stored)
	sum := sha256.Sum256([]byte(tok))
	if stored != hex.EncodeToString(sum[:]) || strings.Contains(stored, tok) {
		t.Fatalf("token not stored hashed: %q", stored)
	}
	if _, l := a.call("GET", "/api/v1/user/ddns", nil); strings.Contains(fmt.Sprint(l), tok) || strings.Contains(fmt.Sprint(l), stored) {
		t.Fatal("list leaks the token or its hash")
	}
	upd := func(q string) (int, string) {
		w := e.do(e.user, req{method: "GET", path: "/ddns/update?" + q, ip: "198.51.100.77"}, nil)
		return w.Code, strings.TrimSpace(w.Body.String())
	}
	e.ag.reset()
	if c, body := upd("token=" + tok + "&ip=203.0.113.9"); c != 200 || body != "good 203.0.113.9" {
		t.Fatalf("update: %d %q", c, body)
	}
	var rr rpc.RRSet
	if rc := e.ag.find(rpc.MDNSRRSetReplace); len(rc) != 1 || json.Unmarshal(rc[0].Params, &rr) != nil ||
		rr.Owner != "alice" || rr.Zone != "alice.test" || rr.Name != "home.alice.test" || rr.Type != "A" || rr.Records[0] != "203.0.113.9" {
		t.Fatalf("rrset %+v", rr)
	}
	if c, body := upd("token=" + tok + "&ip=203.0.113.9"); c != 200 || body != "nochg 203.0.113.9" {
		t.Errorf("nochg: %d %q", c, body)
	}
	if c, body := upd("token=" + tok + "&ip=2001:db8::5"); c != 200 || body != "good 2001:db8::5" {
		t.Errorf("v6: %d %q", c, body)
	}
	if c, body := upd("token=" + tok + "&ip=127.0.0.1"); c != 400 || body != "badip" {
		t.Errorf("loopback: %d %q", c, body)
	}
	if c, body := upd("token=" + tok[:len(tok)-2] + "xx"); c != 401 || body != "badauth" {
		t.Errorf("wrong token: %d %q", c, body)
	}
	if c, _ := upd("token=nope"); c != 401 {
		t.Errorf("garbage token: %d", c)
	}
	// rotate: the old token stops working
	_, m2 := a.call("POST", "/api/v1/user/ddns", map[string]any{"domain_id": sub})
	if m2["token"] == tok {
		t.Fatal("token not rotated")
	}
	if c, _ := upd("token=" + tok + "&ip=203.0.113.10"); c != 401 && c != 429 {
		t.Errorf("old token after rotation: %d", c)
	}
	if code, _ := b.call("DELETE", fmt.Sprintf("/api/v1/user/ddns/%d", hid), nil); code != 404 {
		t.Errorf("bob deletes alice's ddns: %d", code)
	}
	if code, _ := a.call("DELETE", fmt.Sprintf("/api/v1/user/ddns/%d", hid), nil); code != 200 {
		t.Errorf("delete: %d", code)
	}
}

func TestDevxTerminalWS(t *testing.T) {
	e := newEnv(t)
	u := e.tenant("alice", "alice.test")
	a := mustLogin(t, e, e.user, "alice", "")
	ts := httptest.NewServer(e.user)
	defer ts.Close()
	dial := func(origin string) (*websocket.Conn, int) {
		cfg, _ := websocket.NewConfig(strings.Replace(ts.URL, "http", "ws", 1)+"/api/v1/user/terminal/ws?cols=90&rows=20", origin)
		cfg.Header = http.Header{"Cookie": {a.cookie.Name + "=" + a.cookie.Value}}
		ws, err := websocket.DialConfig(cfg)
		if err != nil {
			var de *websocket.DialError
			if strings.Contains(fmt.Sprint(err), "bad status") || (de != nil) {
				return nil, 403
			}
			return nil, -1
		}
		return ws, 101
	}
	if _, code := dial(ts.URL); code == 101 {
		t.Fatal("terminal opened without shell access")
	}
	if code, m := a.call("GET", "/api/v1/user/terminal", nil); code != 200 || m["shell_access"] != false {
		t.Fatalf("status %d %v", code, m)
	}
	if _, err := e.srv.Store.DB.Exec(`INSERT INTO account_overrides(user_id, shell_access) VALUES(?,1)`, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, code := dial("https://evil.example"); code == 101 {
		t.Fatal("cross-origin WebSocket accepted")
	}
	if len(e.ag.find(rpc.MTermOpen)) != 0 {
		t.Fatal("agent opened a PTY for a refused request")
	}
	ws, code := dial(ts.URL)
	if code != 101 {
		t.Fatalf("dial: %d", code)
	}
	if err := websocket.Message.Send(ws, `{"t":"i","d":"ls\r"}`); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(e.ag.find(rpc.MTermWrite)) == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	var w rpc.TermIO
	if wc := e.ag.find(rpc.MTermWrite); len(wc) == 0 || json.Unmarshal(wc[0].Params, &w) != nil || string(w.Data) != "ls\r" || w.User != "alice" {
		t.Fatalf("write %+v", w)
	}
	var o rpc.TermOpen
	_ = json.Unmarshal(e.ag.find(rpc.MTermOpen)[0].Params, &o)
	if o.User != "alice" || o.Cols != 90 || o.Rows != 20 {
		t.Fatalf("open %+v", o)
	}
	ws.Close()
	for time.Now().Before(deadline.Add(2*time.Second)) && len(e.ag.find(rpc.MTermClose)) == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if len(e.ag.find(rpc.MTermClose)) != 1 {
		t.Fatal("session not closed on disconnect")
	}
	// stale login: re-authentication required
	if _, err := e.srv.Store.DB.Exec(`UPDATE sessions SET created_at=?, reauth_at=0`, time.Now().Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, code := dial(ts.URL); code == 101 {
		t.Fatal("terminal opened without recent authentication")
	}
}
