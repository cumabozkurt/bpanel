package api

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/rbac"
)

// fakeV11 answers the v1.1 server-scope agent methods.
func fakeV11(method string, b []byte) (any, bool) {
	switch method {
	case rpc.MMailQueueList:
		return rpc.MailQueueListResult{Status: "ok", Total: 2, Messages: []rpc.QueueMsg{
			{ID: "AAA111", Queue: "deferred", Sender: "a@x.test", Recipients: []rpc.QueueRcpt{{Address: "b@y.test", Reason: "timeout"}}},
			{ID: "BBB222", Queue: "hold", Sender: "c@x.test", Recipients: []rpc.QueueRcpt{{Address: "d@z.test"}}},
		}}, true
	case rpc.MMailQueueAction:
		var p rpc.MailQueueActionParams
		_ = json.Unmarshal(b, &p)
		return rpc.MailQueueActionResult{Status: "ok", Affected: len(p.IDs)}, true
	case rpc.MMailQueueShow:
		return rpc.MailQueueShowResult{Status: "ok", Text: "Subject: hi"}, true
	case rpc.MMailTrace:
		return rpc.MailTraceResult{Status: "ok", Steps: []rpc.TraceStep{{Check: "virtual_mailbox", Result: "pass"}}}, true
	case rpc.MNetIPs:
		return rpc.NetIPsResult{Interfaces: []rpc.NetIface{{Name: "eth0", Up: true, Addrs: []rpc.NetAddr{{IP: "10.0.0.5", Prefix: 24, Family: "ipv4", Scope: "private"}}}}}, true
	case rpc.MSysHostname:
		var p rpc.SysHostnameParams
		_ = json.Unmarshal(b, &p)
		return rpc.SysHostnameResult{Previous: "old.example.com", Hostname: p.Hostname, Steps: []string{"hostnamectl"}}, true
	case rpc.MPHPExtList:
		return rpc.PHPExtListResult{Status: "ok", Manager: "apt", Extensions: []rpc.PHPExt{{Name: "intl", Package: "php8.3-intl"}}}, true
	case rpc.MPHPExtSet:
		return rpc.PHPExtSetResult{Status: "ok"}, true
	case rpc.MLogStats:
		return rpc.LogStatsResult{}, true
	case rpc.MWebxLeechScan:
		var p rpc.LeechScanParams
		_ = json.Unmarshal(b, &p)
		hits := []rpc.LeechHit{}
		for _, path := range p.Paths {
			hits = append(hits, rpc.LeechHit{Path: path, Login: "ops", IPs: 9})
		}
		return rpc.LeechScanResult{Status: "ok", Hits: hits}, true
	case rpc.MMailRoutingSet:
		return rpc.MailRoutingResult{Status: "applied"}, true
	case rpc.MDavSync, rpc.MDavStatus:
		return rpc.DavStatusResult{Status: "ok"}, true
	case rpc.MGPGList:
		return rpc.GPGListResult{}, true
	case rpc.MSSHKeyList:
		return rpc.SSHKeyListResult{}, true
	}
	return nil, false
}

func TestV11SitePublisherAndImages(t *testing.T) {
	e := newEnv(t)
	e.tenant("pub", "pub.test")
	u := mustLogin(t, e, e.user, "pub", "")
	code, m := u.call("GET", "/api/v1/user/site-publisher", nil)
	doms, _ := m["domains"].([]any)
	if code != 200 || len(doms) != 1 {
		t.Fatalf("info %d %v", code, m)
	}
	d := doms[0].(map[string]any)
	home := filepath.Join(e.ag.homes, "pub")
	if err := os.MkdirAll(filepath.Join(home, d["docroot"].(string)), 0o755); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"domain_id": d["id"], "template": "business", "lang": "tr", "fields": map[string]any{"title": "Bozkurt <Ltd>", "email": "info@pub.test"}}
	if code, m := u.call("POST", "/api/v1/user/site-publisher", body); code != 200 {
		t.Fatalf("publish %d %v", code, m)
	}
	html, err := os.ReadFile(filepath.Join(home, d["docroot"].(string), "index.html"))
	if err != nil || !bytes.Contains(html, []byte("Bozkurt &lt;Ltd&gt;")) || bytes.Contains(html, []byte("<Ltd>")) {
		t.Fatalf("index.html not escaped/written: %v %s", err, html)
	}
	if code, m := u.call("POST", "/api/v1/user/site-publisher", body); code != 409 || m["error"] != "site_exists" {
		t.Errorf("second publish %d %v", code, m)
	}
	body["overwrite"] = true
	if code, _ := u.call("POST", "/api/v1/user/site-publisher", body); code != 200 {
		t.Errorf("overwrite %d", code)
	}
	body["template"] = "nope"
	if code, m := u.call("POST", "/api/v1/user/site-publisher", body); code != 400 || m["error"] != "site_template_unknown" {
		t.Errorf("bad template %d %v", code, m)
	}
	// images
	img := image.NewRGBA(image.Rect(0, 0, 400, 200))
	img.Set(1, 1, color.RGBA{255, 0, 0, 255})
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	if err := os.WriteFile(filepath.Join(home, "pic.png"), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	code, m = u.call("POST", "/api/v1/user/images", map[string]any{"path": "pic.png", "op": "thumbnail", "width": 100})
	if code != 200 || m["path"] != "thumbnails/tn_pic.png" {
		t.Fatalf("thumbnail %d %v", code, m)
	}
	if _, err := os.Stat(filepath.Join(home, "thumbnails", "tn_pic.png")); err != nil {
		t.Fatal(err)
	}
	if code, m := u.call("POST", "/api/v1/user/images", map[string]any{"path": "pic.png", "op": "convert", "format": "jpeg"}); code != 200 || m["path"] != "pic.jpg" {
		t.Errorf("convert %d %v", code, m)
	}
	if code, m := u.call("POST", "/api/v1/user/images", map[string]any{"path": "../../etc/passwd", "op": "convert", "format": "png"}); code == 200 {
		t.Errorf("traversal accepted %d %v", code, m)
	}
	// feature switch
	_ = e.srv.Store.Set("feature_images", "0")
	if code, m := u.call("POST", "/api/v1/user/images", map[string]any{"path": "pic.png", "op": "thumbnail"}); code != 409 || m["field"] != "images" {
		t.Errorf("feature off %d %v", code, m)
	}
}

func TestV11PGBrowser(t *testing.T) {
	e := newEnv(t)
	tu := e.tenant("pgu", "pgu.test")
	e.tenant("pgo", "pgo.test")
	other, _ := e.srv.userByName(context.Background(), "pgo")
	if _, err := e.srv.Store.DB.Exec(`INSERT INTO pg_databases(id,user_id,name,created_at) VALUES(7,?,'pgu_app',0),(8,?,'pgo_app',0)`, tu.ID, other.ID); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "psql")
	// fake psql: checks the password env and the role, prints CSV
	_ = os.WriteFile(script, []byte("#!/bin/sh\n[ \"$PGPASSWORD\" = good-pass ] || { echo 'psql: error: FATAL:  password authentication failed for user' >&2; exit 2; }\n"+
		"case \"$*\" in *'-U pgu_app -d pgu_app'*) ;; *) echo bad args >&2; exit 3;; esac\ncat >/dev/null\nprintf 'id,name\\n1,\"a,b\"\\n2,x\\n'\n"), 0o755)
	old := psqlBin
	psqlBin = script
	defer func() { psqlBin = old }()
	u := mustLogin(t, e, e.user, "pgu", "")
	code, m := u.call("GET", "/api/v1/user/postgresql/browser", nil)
	if code != 200 || m["status"] != "ok" || len(m["databases"].([]any)) != 1 {
		t.Fatalf("info %d %v", code, m)
	}
	code, m = u.call("POST", "/api/v1/user/postgresql/browser/query", map[string]any{"database_id": 7, "password": "good-pass", "sql": "select 1"})
	rows, _ := m["rows"].([]any)
	if code != 200 || len(rows) != 2 || rows[0].([]any)[1] != "a,b" {
		t.Fatalf("query %d %v", code, m)
	}
	if code, m := u.call("POST", "/api/v1/user/postgresql/browser/query", map[string]any{"database_id": 7, "password": "wrong", "sql": "select 1"}); code != 400 || m["error"] != "pg_auth_failed" {
		t.Errorf("wrong pw %d %v", code, m)
	}
	if code, _ := u.call("POST", "/api/v1/user/postgresql/browser/tables", map[string]any{"database_id": 8, "password": "good-pass"}); code != 404 {
		t.Errorf("foreign database %d", code)
	}
	if code, m := u.call("POST", "/api/v1/user/postgresql/browser/query", map[string]any{"database_id": 7, "password": "good-pass", "sql": `\! id`}); code != 400 || m["error"] != "pg_bad_sql" {
		t.Errorf("meta command %d %v", code, m)
	}
	psqlBin = filepath.Join(dir, "missing-psql")
	if code, m := u.call("GET", "/api/v1/user/postgresql/browser", nil); code != 200 || m["status"] != "not_installed" {
		t.Errorf("not installed %d %v", code, m)
	}
}

func TestV11Cloudflare(t *testing.T) {
	var created []string
	cf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good-token-1234567890abcdef" {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}]}`))
			return
		}
		switch {
		case r.URL.Path == "/user/tokens/verify":
			_, _ = w.Write([]byte(`{"success":true,"result":{"status":"active"}}`))
		case r.URL.Path == "/zones":
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"z1","name":"cf.test","status":"active","plan":{"name":"Free"}}]}`))
		case r.URL.Path == "/zones/z1/dns_records" && r.Method == "GET":
			_, _ = w.Write([]byte(`{"success":true,"result":[]}`))
		case r.URL.Path == "/zones/z1/dns_records" && r.Method == "POST":
			var rec map[string]any
			_ = json.NewDecoder(r.Body).Decode(&rec)
			created = append(created, rec["type"].(string))
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"success":false}`))
		}
	}))
	defer cf.Close()
	oldNS := lookupNS
	lookupNS = func(ctx context.Context, d string) ([]*net.NS, error) {
		return []*net.NS{{Host: "ada.ns.cloudflare.com."}}, nil
	}
	defer func() { lookupNS = oldNS }()
	e := newEnv(t)
	withSecrets(t, e)
	dnsxOn(e.ag)
	_ = e.srv.Store.Set("cloudflare_api_base", cf.URL)
	e.tenant("cfu", "cf.test")
	u := mustLogin(t, e, e.user, "cfu", "")
	if code, m := u.call("PUT", "/api/v1/user/cloudflare", map[string]any{"token": "bad-token-1234567890abcdef"}); code != 400 || m["error"] != "cloudflare_auth" {
		t.Fatalf("bad token %d %v", code, m)
	}
	code, m := u.call("PUT", "/api/v1/user/cloudflare", map[string]any{"token": "good-token-1234567890abcdef"})
	if code != 200 || m["linked"] != true {
		t.Fatalf("link %d %v", code, m)
	}
	d := m["domains"].([]any)[0].(map[string]any)
	if d["on_cloudflare"] != true || d["in_account"] != true {
		t.Errorf("detect %v", d)
	}
	if strings.Contains(mustJSONString(m), "good-token") {
		t.Error("token echoed")
	}
	code, m = u.call("POST", "/api/v1/user/cloudflare/sync", map[string]any{"domain_id": d["id"], "dry_run": true})
	if code != 200 || len(m["missing"].([]any)) == 0 || len(created) != 0 {
		t.Fatalf("dry run %d %v", code, m)
	}
	code, m = u.call("POST", "/api/v1/user/cloudflare/sync", map[string]any{"domain_id": d["id"]})
	if code != 200 || len(created) == 0 {
		t.Fatalf("sync %d %v %v", code, m, created)
	}
	if code, m := u.call("DELETE", "/api/v1/user/cloudflare", nil); code != 200 || m["linked"] != false {
		t.Errorf("unlink %d %v", code, m)
	}
	if code, m := u.call("POST", "/api/v1/user/cloudflare/sync", map[string]any{"domain_id": d["id"]}); code != 409 || m["error"] != "cloudflare_not_linked" {
		t.Errorf("after unlink %d %v", code, m)
	}
}

func mustJSONString(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestV11AdminTools(t *testing.T) {
	e := newEnv(t)
	tu := e.tenant("ipu", "ipu.test")
	root := adminLogin(t, e)
	code, m := root.call("GET", "/api/v1/admin/mail-queue?q=z.test", nil)
	if code != 200 || len(m["messages"].([]any)) != 1 {
		t.Fatalf("queue %d %v", code, m)
	}
	if code, m := root.call("POST", "/api/v1/admin/mail-queue/action", map[string]any{"action": "explode", "ids": []string{"AAA111"}}); code != 400 || m["error"] != "invalid_queue_action" {
		t.Errorf("bad action %d %v", code, m)
	}
	if code, m := root.call("POST", "/api/v1/admin/mail-queue/action", map[string]any{"action": "delete"}); code != 400 || m["error"] != "queue_ids_required" {
		t.Errorf("no ids %d %v", code, m)
	}
	if code, m := root.call("POST", "/api/v1/admin/mail-queue/action", map[string]any{"action": "delete", "ids": []string{"AAA111"}}); code != 200 || m["affected"] != float64(1) {
		t.Errorf("delete %d %v", code, m)
	}
	oldTXT, oldMX := lookupTXT, lookupMX
	lookupTXT = func(ctx context.Context, n string) ([]string, error) { return []string{"v=spf1 mx -all"}, nil }
	lookupMX = func(ctx context.Context, n string) ([]*net.MX, error) { return nil, &net.DNSError{IsNotFound: true} }
	defer func() { lookupTXT, lookupMX = oldTXT, oldMX }()
	code, m = root.call("GET", "/api/v1/admin/mail-troubleshooter?address=user@ipu.test", nil)
	if code != 200 || !strings.Contains(mustJSONString(m), "dns_spf") {
		t.Errorf("trace %d %v", code, m)
	}
	// IP functions
	if code, m := root.call("POST", "/api/v1/admin/ips", map[string]any{"ip": "127.0.0.1", "dev": "eth0"}); code != 400 || m["error"] != "invalid_ip" {
		t.Errorf("loopback %d %v", code, m)
	}
	if code, m := root.call("POST", "/api/v1/admin/ips", map[string]any{"ip": "10.0.0.9", "dev": "eth0;rm"}); code != 400 || m["error"] != "invalid_interface" {
		t.Errorf("bad dev %d %v", code, m)
	}
	if code, m := root.call("PUT", "/api/v1/admin/accounts/"+itoa64(tu.ID)+"/ip", map[string]any{"ip": "10.9.9.9"}); code != 400 || m["error"] != "ip_not_configured" {
		t.Errorf("unconfigured %d %v", code, m)
	}
	e.ag.reset()
	code, m = root.call("PUT", "/api/v1/admin/accounts/"+itoa64(tu.ID)+"/ip", map[string]any{"ip": "10.0.0.5"})
	if code != 200 || m["dedicated"] != true || len(e.ag.find(rpc.MDNSRRSetReplace)) == 0 {
		t.Fatalf("assign %d %v", code, m)
	}
	if !strings.Contains(string(e.ag.find(rpc.MDNSRRSetReplace)[0].Params), "10.0.0.5") {
		t.Error("A record not pointed at the dedicated IP")
	}
	if code, m := root.call("POST", "/api/v1/admin/ips/remove", map[string]any{"ip": "10.0.0.5", "dev": "eth0"}); code != 409 || m["error"] != "ip_in_use" {
		t.Errorf("remove in use %d %v", code, m)
	}
	// hostname
	if code, m := root.call("PUT", "/api/v1/admin/hostname", map[string]any{"hostname": "bad_host"}); code != 400 || m["error"] != "invalid_hostname" {
		t.Errorf("bad hostname %d %v", code, m)
	}
	if code, m := root.call("PUT", "/api/v1/admin/hostname", map[string]any{"hostname": "panel.example.org"}); code != 200 || m["hostname"] != "panel.example.org" {
		t.Errorf("hostname %d %v", code, m)
	}
	// tweak settings
	if code, m := root.call("PUT", "/api/v1/admin/tweak-settings", map[string]any{"values": map[string]string{"server_ip": "1.2.3.4"}}); code != 400 || m["error"] != "unknown_setting" {
		t.Errorf("unknown %d %v", code, m)
	}
	if code, m := root.call("PUT", "/api/v1/admin/tweak-settings", map[string]any{"values": map[string]string{"leech_sweep_minutes": "1"}}); code != 400 || m["error"] != "invalid_setting" {
		t.Errorf("range %d %v", code, m)
	}
	if code, m := root.call("PUT", "/api/v1/admin/tweak-settings", map[string]any{"values": map[string]string{"feature_calendars": "0", "leech_sweep_minutes": "30"}}); code != 200 {
		t.Errorf("tweak %d %v", code, m)
	}
	if e.srv.featureOn("calendars") || e.srv.tweakInt("leech_sweep_minutes", 10) != 30 {
		t.Error("tweak not stored")
	}
	u := mustLogin(t, e, e.user, "ipu", "")
	if code, m := u.call("GET", "/api/v1/user/calendars", nil); code != 409 || m["field"] != "calendars" {
		t.Errorf("calendars off %d %v", code, m)
	}
	// PHP extensions
	if code, m := root.call("GET", "/api/v1/admin/php/8.3/extensions", nil); code != 200 || len(m["extensions"].([]any)) != 1 {
		t.Errorf("ext list %d %v", code, m)
	}
	if code, m := root.call("GET", "/api/v1/admin/php/x;y/extensions", nil); code != 400 {
		t.Errorf("bad version %d %v", code, m)
	}
	if code, m := root.call("PUT", "/api/v1/admin/php/8.3/extensions/intl", map[string]any{"install": true}); code != 200 {
		t.Errorf("ext set %d %v", code, m)
	}
	if code, m := root.call("GET", "/api/v1/admin/billing", nil); code != 200 || len(m["events"].([]any)) == 0 {
		t.Errorf("billing %d %v", code, m)
	}
	// RBAC: auditor reads but never writes; the tenant never reaches admin routes
	staff(t, e, "v11aud", rbac.Auditor)
	aud := mustLogin(t, e, e.admin, "v11aud", "")
	if code, _ := aud.call("GET", "/api/v1/admin/mail-queue", nil); code != 200 {
		t.Errorf("auditor read %d", code)
	}
	for _, c := range []struct{ m, p string }{{"POST", "/api/v1/admin/mail-queue/action"}, {"POST", "/api/v1/admin/ips"},
		{"PUT", "/api/v1/admin/hostname"}, {"PUT", "/api/v1/admin/tweak-settings"}, {"PUT", "/api/v1/admin/php/8.3/extensions/intl"}} {
		if code, _ := aud.call(c.m, c.p, map[string]any{}); code != 403 {
			t.Errorf("auditor %s %s = %d", c.m, c.p, code)
		}
	}
}

func TestV11UserTools(t *testing.T) {
	e := newEnv(t)
	e.tenant("vu", "vu.test")
	u := mustLogin(t, e, e.user, "vu", "")
	if code, m := u.call("GET", "/api/v1/user/stats/visitors", nil); code != 200 || len(m["domains"].([]any)) != 1 {
		t.Errorf("visitors list %d %v", code, m)
	}
	if code, _ := u.call("GET", "/api/v1/user/stats/visitors?domain=other.test", nil); code != 404 {
		t.Errorf("foreign domain %d", code)
	}
	if code, m := u.call("GET", "/api/v1/user/stats/visitors?domain=vu.test", nil); code != 200 || m["domain"] != "vu.test" {
		t.Errorf("visitors %d %v", code, m)
	}
	_ = e.srv.Store.Set("feature_visitors", "0")
	if code, m := u.call("GET", "/api/v1/user/stats/visitors", nil); code != 409 || m["field"] != "visitors" {
		t.Errorf("visitors off %d %v", code, m)
	}
	code, m := u.call("GET", "/api/v1/auth/me", nil)
	fs, _ := m["features"].(map[string]any)
	if code != 200 || fs["visitors"] != false || fs["calendars"] != true {
		t.Errorf("me features %v", fs)
	}
}

func TestV11WebExtrasAndMail(t *testing.T) {
	e := newEnv(t)
	e.tenant("wx", "wx.test")
	u := mustLogin(t, e, e.user, "wx", "")
	var id int64
	if err := e.srv.Store.DB.QueryRow(`SELECT id FROM domains WHERE name='wx.test'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/user/web/" + itoa64(id)
	if code, m := u.call("PUT", base+"/indexes", map[string]any{"indexes": []any{map[string]string{"path": "/files/", "mode": "on"}}}); code != 200 {
		t.Fatalf("indexes %d %v", code, m)
	}
	if code, m := u.call("PUT", base+"/handlers", map[string]any{"handlers": []any{map[string]string{"ext": "php", "handler": "text-plain"}}}); code != 400 || m["error"] != "webx_invalid_handler" {
		t.Errorf("php handler %d %v", code, m)
	}
	if code, m := u.call("PUT", base+"/handlers", map[string]any{"handlers": []any{map[string]string{"ext": "shtml", "handler": "server-parsed"}}}); code != 200 {
		t.Errorf("ssi handler %d %v", code, m)
	}
	if code, m := u.call("PUT", base+"/leech", map[string]any{"path": "/admin/", "leech_max": 3}); code == 200 {
		t.Errorf("leech on unprotected dir accepted %v", m)
	}
	if code, m := u.call("PUT", base+"/privacy", map[string]any{"dirs": []any{map[string]any{"path": "/admin/", "users": []any{map[string]any{"name": "ops", "password": "Long-Pass-123"}}}}}); code != 200 {
		t.Fatalf("privacy %d %v", code, m)
	}
	if code, m := u.call("PUT", base+"/leech", map[string]any{"path": "/admin/", "leech_max": 3}); code != 200 {
		t.Fatalf("leech %d %v", code, m)
	}
	code, m := u.call("POST", base+"/leech/scan", nil)
	if code != 200 {
		t.Fatalf("scan %d %v", code, m)
	}
	_, g := u.call("GET", base+"/extras", nil)
	if !strings.Contains(mustJSONString(g), `"disabled":["ops"]`) {
		t.Errorf("ops not disabled by leech scan: %v", g)
	}
	if code, m := u.call("POST", base+"/leech/enable", map[string]any{"path": "/admin/", "user": "ops"}); code != 200 {
		t.Errorf("enable %d %v", code, m)
	}
	// mail: routing, BoxTrapper, calendars
	if code, m := u.call("POST", "/api/v1/user/email/accounts", map[string]any{"local": "box", "domain": "wx.test", "password": tPW, "quota_mb": 100}); code != 200 {
		t.Fatalf("mailbox %d %v", code, m)
	}
	if code, m := u.call("PUT", "/api/v1/user/email/routing/wx.test", map[string]any{"mode": "backup"}); code != 200 || m["effective"] != "backup" {
		t.Errorf("routing %d %v", code, m)
	}
	if code, _ := u.call("PUT", "/api/v1/user/email/routing/other.test", map[string]any{"mode": "local"}); code != 404 {
		t.Errorf("foreign routing %d", code)
	}
	_, bl := u.call("GET", "/api/v1/user/email/boxtrapper", nil)
	boxes, _ := bl["mailboxes"].([]any)
	if len(boxes) != 1 {
		t.Fatalf("boxtrapper list %v", bl)
	}
	bid := itoa64(int64(boxes[0].(map[string]any)["mailbox_id"].(float64)))
	if code, m := u.call("PUT", "/api/v1/user/email/boxtrapper/"+bid, map[string]any{"enabled": true, "whitelist": []string{"friend@x.test", "@trusted.test"}, "folder": "Quarantine"}); code != 200 || m["enabled"] != true {
		t.Errorf("boxtrapper %d %v", code, m)
	}
	if code, m := u.call("PUT", "/api/v1/user/calendars/"+bid, map[string]any{"password": "short"}); code != 400 || m["error"] != "weak_password" {
		t.Errorf("weak dav pw %d %v", code, m)
	}
	if code, m := u.call("PUT", "/api/v1/user/calendars/"+bid, map[string]any{"password": "Calendar-Pass-2026"}); code != 200 {
		t.Errorf("dav enable %d %v", code, m)
	}
	var hash string
	_ = e.srv.Store.DB.QueryRow(`SELECT hash FROM dav_logins`).Scan(&hash)
	if !strings.HasPrefix(hash, "$2y$") {
		t.Errorf("dav hash %q", hash)
	}
	if code, m := u.call("GET", "/api/v1/user/calendars", nil); code != 200 || !strings.Contains(mustJSONString(m), "/dav/box@wx.test/") {
		t.Errorf("dav list %d %v", code, m)
	}
	if code, _ := u.call("GET", "/api/v1/user/gpg", nil); code != 200 {
		t.Errorf("gpg %d", code)
	}
	if code, _ := u.call("GET", "/api/v1/user/ssh-keys", nil); code != 200 {
		t.Errorf("ssh %d", code)
	}
}

func TestV11DavProxy(t *testing.T) {
	var gotPath, gotAuth, gotCookie, gotScript string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotCookie, gotScript = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Cookie"), r.Header.Get("X-Script-Name")
		w.WriteHeader(207)
	}))
	defer up.Close()
	e := newEnv(t)
	e.srv.Cfg.DavUpstream = up.URL
	h := e.srv.Handler(RealmUser)
	r := httptest.NewRequest("PROPFIND", "/dav/a@x.test/", nil)
	r.SetBasicAuth("a@x.test", "pw")
	r.Header.Set("Cookie", "bp_session=secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 207 || gotPath != "/a@x.test/" || gotAuth == "" || gotCookie != "" || gotScript != "/dav" {
		t.Fatalf("proxy %d path=%q auth=%q cookie=%q script=%q", w.Code, gotPath, gotAuth, gotCookie, gotScript)
	}
	_ = e.srv.Store.Set("feature_calendars", "0")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("PROPFIND", "/dav/", nil))
	if w.Code != 404 {
		t.Errorf("calendars off: %d", w.Code)
	}
}
