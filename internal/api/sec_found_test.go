package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cumabozkurt/bpanel/internal/events"
	"github.com/cumabozkurt/bpanel/internal/jobs"
	"github.com/cumabozkurt/bpanel/internal/redact"
)

func secEnv(t *testing.T) (*env, *syncBuf) {
	e := newEnv(t)
	e.srv.Cfg.SecretKeyFile = filepath.Join(t.TempDir(), "secret.key")
	buf := &syncBuf{}
	e.srv.Log = slog.New(redact.NewHandler(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return e, buf
}

func (s *sess) callH(method, path string, body any, hdr map[string]string) (int, map[string]any, http.Header) {
	w := s.e.do(s.h, req{method: method, path: path, body: body, headers: hdr}, s)
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w.Code, m, w.Header()
}

func TestSecSecretStoreWiredNoLeak(t *testing.T) {
	e, logs := secEnv(t)
	a := mustLoginAdmin(t, e)
	if st := e.srv.Secrets().Status(); st["status"] != "ok" {
		t.Fatal(st)
	}
	a.call("PUT", "/api/v1/admin/webhooks/settings", map[string]any{"allow_private": true})
	const sec = "my-very-secret-signing-key-123"
	code, m := a.call("POST", "/api/v1/admin/webhooks", map[string]any{"name": "h1", "url": "http://127.0.0.1:9/x", "secret": sec, "events": []string{"shield.*"}})
	if code != 200 || m["secret"] != sec {
		t.Fatalf("create: %d %v", code, m)
	}
	id := int64(m["id"].(float64))
	w := e.do(a.h, req{method: "GET", path: "/api/v1/admin/webhooks"}, a)
	if w.Code != 200 || strings.Contains(w.Body.String(), sec) || !strings.Contains(w.Body.String(), `"has_secret":true`) {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var raw string
	e.srv.Store.DB.QueryRow(`SELECT secret FROM webhooks WHERE id=?`, id).Scan(&raw)
	if strings.Contains(raw, sec) {
		t.Fatal("plaintext secret in webhooks table")
	}
	var ct []byte
	e.srv.Store.DB.QueryRow(`SELECT ciphertext FROM secrets WHERE name=?`, secretName(id)).Scan(&ct)
	if len(ct) == 0 || strings.Contains(string(ct), sec) {
		t.Fatal("secret not encrypted at rest")
	}
	// rotate the signing secret: new value returned once, still not listed
	code, m = a.call("POST", fmt.Sprintf("/api/v1/admin/webhooks/%d/secret", id), nil)
	if code != 200 || !strings.HasPrefix(m["secret"].(string), "whsec_") {
		t.Fatal(code, m)
	}
	newSec := m["secret"].(string)
	w = e.do(a.h, req{method: "GET", path: "/api/v1/admin/webhooks"}, a)
	if strings.Contains(w.Body.String(), newSec) {
		t.Fatal("rotated secret listed")
	}
	if strings.Contains(logs.String(), sec) || strings.Contains(logs.String(), newSec) {
		t.Fatal("secret in logs")
	}
	// delete removes the secret record
	if code, _ := a.call("DELETE", fmt.Sprintf("/api/v1/admin/webhooks/%d", id), nil); code != 200 {
		t.Fatal(code)
	}
	var n int
	e.srv.Store.DB.QueryRow(`SELECT COUNT(*) FROM secrets`).Scan(&n)
	if n != 0 {
		t.Fatal("secret left after delete")
	}
}

func TestSecIdempotency(t *testing.T) {
	e, _ := secEnv(t)
	a := mustLoginAdmin(t, e)
	body := map[string]any{"username": "idemone", "domain": "idemone.test", "password": tPW, "package_id": e.pkg()}
	hdr := map[string]string{"Idempotency-Key": "k-123"}
	c1, m1, _ := a.callH("POST", "/api/v1/admin/accounts", body, hdr)
	if c1 != 200 {
		t.Fatalf("first: %d %v", c1, m1)
	}
	c2, m2, h2 := a.callH("POST", "/api/v1/admin/accounts", body, hdr)
	if c2 != c1 || h2.Get("Idempotent-Replayed") != "true" || fmt.Sprint(m1) != fmt.Sprint(m2) {
		t.Fatalf("replay: %d %v %v", c2, m2, h2)
	}
	var n int
	e.srv.Store.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE username='idemone'`).Scan(&n)
	if n != 1 {
		t.Fatalf("accounts created: %d", n)
	}
	body["domain"] = "other.test"
	if c, m, _ := a.callH("POST", "/api/v1/admin/accounts", body, hdr); c != 422 || m["error"] != "idempotency_conflict" {
		t.Fatalf("conflict: %d %v", c, m)
	}
	// no key: normal behaviour (second create is a real duplicate error, not a replay)
	body["domain"] = "idemone.test"
	if c, _, h := a.callH("POST", "/api/v1/admin/accounts", body, nil); c == 200 || h.Get("Idempotent-Replayed") != "" {
		t.Fatalf("no key: %d", c)
	}
	// expired keys (>24h) no longer replay
	e.srv.Store.DB.Exec(`UPDATE idempotency_keys SET created_at=created_at-90000`)
	e.srv.pruneSec(context.Background())
	var k int
	e.srv.Store.DB.QueryRow(`SELECT COUNT(*) FROM idempotency_keys`).Scan(&k)
	if k != 0 {
		t.Fatal("idempotency keys not pruned")
	}
	if c, _, _ := a.callH("POST", "/api/v1/admin/accounts", body, map[string]string{"Idempotency-Key": "bad key"}); c != 400 {
		t.Fatalf("invalid key: %d", c)
	}
}

func TestSecJobsEndpoint(t *testing.T) {
	e, _ := secEnv(t)
	a := mustLoginAdmin(t, e)
	ten := e.tenant("jobten", "jobten.test")
	other := e.tenant("jobtwo", "jobtwo.test")
	ctx := context.Background()
	e.srv.Jobs().Register("t.ok", func(ctx context.Context, j *jobs.Job) (any, error) { return map[string]string{"x": "y"}, nil })
	own, _ := e.srv.Jobs().Enqueue(ctx, jobs.Spec{Kind: "t.ok", ActorID: ten.ID})
	foreign, _ := e.srv.Jobs().Enqueue(ctx, jobs.Spec{Kind: "t.ok", ActorID: other.ID})
	for e.srv.Jobs().RunOnce(ctx) {
	}
	us, code := e.login(e.user, "jobten", tPW, "", "192.0.2.20")
	if us == nil {
		t.Fatal(code)
	}
	if c, m := us.call("GET", "/api/v1/jobs/"+own, nil); c != 200 || m["status"] != "succeeded" {
		t.Fatalf("own: %d %v", c, m)
	}
	if c, _ := us.call("GET", "/api/v1/jobs/"+foreign, nil); c != 404 {
		t.Fatalf("foreign: %d", c)
	}
	if c, _ := a.call("GET", "/api/v1/jobs/"+foreign, nil); c != 200 {
		t.Fatalf("admin: %d", c)
	}
	// crash recovery through the server's runner
	id, _ := e.srv.Jobs().Enqueue(ctx, jobs.Spec{Kind: "t.ok", ActorID: ten.ID})
	e.srv.Store.DB.Exec(`UPDATE jobs SET status='running' WHERE id=?`, id)
	if n, _ := e.srv.Jobs().Recover(ctx); n != 1 {
		t.Fatal("not recovered")
	}
	e.srv.Jobs().RunOnce(ctx)
	if j, _ := e.srv.Jobs().Get(ctx, id); j.Status != jobs.Succeeded {
		t.Fatal(j.Status)
	}
}

func TestSecEventsPersistAndScope(t *testing.T) {
	e, _ := secEnv(t)
	a := mustLoginAdmin(t, e)
	rs := e.reseller("evres")
	mine := e.tenant("evmine", "evmine.test")
	theirs := e.tenant("evtheirs", "evtheirs.test")
	e.srv.Store.DB.Exec(`UPDATE users SET owner_id=? WHERE id=?`, rs, mine.ID)
	ctx := context.Background()
	e.srv.eventSink(ctx, events.Event{Type: "shield.malware_found", Severity: events.Warning, AccountID: mine.ID, At: time.Now().Unix(), Data: map[string]any{"path": "/x"}})
	e.srv.eventSink(ctx, events.Event{Type: "shield.malware_found", Severity: events.Critical, AccountID: theirs.ID, At: time.Now().Unix()})
	e.srv.eventSink(ctx, events.Event{Type: "netsec.ban", Severity: events.Info, At: time.Now().Unix()})
	// Publish goes through the sink installed by api.New
	events.SetSink(e.srv.eventSink)
	events.Publish(ctx, events.Event{Type: "iso.limit_hit", Severity: events.Info, AccountID: mine.ID})
	events.Flush()
	if c, m := a.call("GET", "/api/v1/admin/events", nil); c != 200 || m["total"].(float64) != 4 {
		t.Fatalf("admin all: %d %v", c, m)
	}
	if c, m := a.call("GET", "/api/v1/admin/events?type=shield.*&severity=critical", nil); c != 200 || m["total"].(float64) != 1 {
		t.Fatalf("filter: %d %v", c, m)
	}
	if c, m := a.call("GET", "/api/v1/admin/events?limit=1&offset=1", nil); c != 200 || len(m["events"].([]any)) != 1 {
		t.Fatalf("page: %d %v", c, m)
	}
	r, code := e.login(e.admin, "evres", tPW, "", "192.0.2.30")
	if r == nil {
		t.Fatal(code)
	}
	c, m := r.call("GET", "/api/v1/admin/events", nil)
	if c != 200 || m["total"].(float64) != 2 {
		t.Fatalf("reseller: %d %v", c, m)
	}
	for _, ev := range m["events"].([]any) {
		if int64(ev.(map[string]any)["account_id"].(float64)) != mine.ID {
			t.Fatal("reseller saw a foreign event")
		}
	}
	// retention
	e.srv.Store.DB.Exec(`UPDATE events SET ts=ts-100*86400 WHERE type='netsec.ban'`)
	e.srv.pruneSec(ctx)
	if _, m := a.call("GET", "/api/v1/admin/events", nil); m["total"].(float64) != 3 {
		t.Fatal("retention prune", m)
	}
}

func TestSecWebhookSignatureAndRetry(t *testing.T) {
	e, _ := secEnv(t)
	a := mustLoginAdmin(t, e)
	var mu sync.Mutex
	var got []*http.Request
	var bodies [][]byte
	fail := true
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got, bodies = append(got, r), append(bodies, b)
		f := fail
		mu.Unlock()
		if f {
			w.WriteHeader(500)
		}
	}))
	defer ts.Close()
	// non-super-admin cannot flip allow_private (reseller has no webhooks perm at all)
	if c, _ := a.call("PUT", "/api/v1/admin/webhooks/settings", map[string]any{"allow_private": true}); c != 200 {
		t.Fatal(c)
	}
	const sec = "signing-secret-0123456789"
	c, m := a.call("POST", "/api/v1/admin/webhooks", map[string]any{"name": "rcv", "url": ts.URL + "/hook", "secret": sec, "events": []string{"shield.*"}})
	if c != 200 {
		t.Fatal(c, m)
	}
	hid := int64(m["id"].(float64))
	ctx := context.Background()
	e.srv.eventSink(ctx, events.Event{Type: "netsec.ban", Severity: events.Info, At: time.Now().Unix()}) // not subscribed
	e.srv.eventSink(ctx, events.Event{Type: "shield.quarantine", Severity: events.Warning, AccountID: 3, At: time.Now().Unix(), Data: map[string]any{"path": "/a"}})
	clk := newTestClock(time.Now())
	e.srv.Now = clk.Now
	now := clk.Now()
	for i := 1; i <= webhookMaxTries; i++ {
		if n := e.srv.webhookTick(ctx); n != 1 {
			t.Fatalf("tick %d: %d due", i, n)
		}
		var st string
		var att int
		var next int64
		e.srv.Store.DB.QueryRow(`SELECT status,attempts,next_at FROM webhook_deliveries WHERE webhook_id=?`, hid).Scan(&st, &att, &next)
		if att != i {
			t.Fatalf("attempts %d != %d", att, i)
		}
		if i < webhookMaxTries {
			if st != "pending" || next != now.Add(webhookBackoff(i)).Unix() {
				t.Fatalf("try %d: %s next=%d", i, st, next-now.Unix())
			}
			if e.srv.webhookTick(ctx) != 0 {
				t.Fatal("retried before backoff elapsed")
			}
			now = now.Add(webhookBackoff(i))
			clk.Set(now)
		} else if st != "failed" {
			t.Fatalf("final status %s", st)
		}
	}
	if webhookBackoff(1) != 30*time.Second || webhookBackoff(2) != time.Minute || webhookBackoff(5) != 8*time.Minute || webhookBackoff(30) != time.Hour {
		t.Fatal("backoff schedule")
	}
	// success path + signature verification
	mu.Lock()
	fail = false
	mu.Unlock()
	if c, _ := a.call("POST", fmt.Sprintf("/api/v1/admin/webhooks/%d/test", hid), nil); c != 200 {
		t.Fatal(c)
	}
	e.srv.webhookTick(ctx)
	mu.Lock()
	r, b := got[len(got)-1], bodies[len(bodies)-1]
	mu.Unlock()
	mac := hmac.New(sha256.New, []byte(sec))
	mac.Write([]byte(r.Header.Get("X-BPanel-Timestamp") + "."))
	mac.Write(b)
	if r.Header.Get("X-BPanel-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("signature does not verify")
	}
	if r.Header.Get("X-BPanel-Event") != "webhook.test" || r.Header.Get("X-BPanel-Id") == "" {
		t.Fatal(r.Header)
	}
	// the earlier event delivery body carried the event
	mu.Lock()
	first := bodies[0]
	mu.Unlock()
	if !strings.Contains(string(first), `"type":"shield.quarantine"`) || strings.Contains(string(first), sec) {
		t.Fatal(string(first))
	}
	c, m = a.call("GET", fmt.Sprintf("/api/v1/admin/webhooks/%d/deliveries", hid), nil)
	ds := m["deliveries"].([]any)
	if c != 200 || len(ds) != 2 || ds[0].(map[string]any)["status"] != "delivered" || ds[1].(map[string]any)["status"] != "failed" {
		t.Fatalf("deliveries: %d %v", c, m)
	}
}

func TestSecWebhookSSRF(t *testing.T) {
	e, _ := secEnv(t)
	a := mustLoginAdmin(t, e)
	for _, u := range []string{"http://127.0.0.1:8080/", "http://169.254.169.254/latest/meta-data", "http://[::1]/", "http://10.1.2.3/", "http://[fd00::1]/", "http://100.100.100.200/"} {
		if c, m := a.call("POST", "/api/v1/admin/webhooks", map[string]any{"name": "x", "url": u}); c != 422 || m["error"] != "webhook_url_blocked" {
			t.Fatalf("%s: %d %v", u, c, m)
		}
	}
	for _, u := range []string{"ftp://example.com/", "http://user:pw@example.com/", "nonsense"} {
		if c, m := a.call("POST", "/api/v1/admin/webhooks", map[string]any{"name": "x", "url": u}); c != 422 || m["error"] != "invalid_webhook_url" {
			t.Fatalf("%s: %d %v", u, c, m)
		}
	}
	// a public-looking name that resolves to loopback is refused
	e.srv.sec.resolver = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("127.0.0.1")}, nil
	}
	if c, m := a.call("POST", "/api/v1/admin/webhooks", map[string]any{"name": "x", "url": "https://rebind.example/"}); c != 422 || m["error"] != "webhook_url_blocked" {
		t.Fatalf("resolver: %d %v", c, m)
	}
	// DNS rebinding: a hook that passed the check earlier but now points at
	// loopback is refused by the dialer at connect time.
	hit := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer ts.Close()
	now := time.Now().Unix()
	res, _ := e.srv.Store.DB.Exec(`INSERT INTO webhooks(name,url,secret,events,enabled,created_at) VALUES('r',?,'',?,1,?)`, ts.URL, "", now)
	hid, _ := res.LastInsertId()
	e.srv.Secrets().Put(context.Background(), secretName(hid), []byte("0123456789abcdef"))
	e.srv.Store.DB.Exec(`INSERT INTO webhook_deliveries(webhook_id,event_id,status,next_at,created_at) VALUES(?,0,'pending',0,?)`, hid, now)
	e.srv.webhookTick(context.Background())
	var errc string
	e.srv.Store.DB.QueryRow(`SELECT error FROM webhook_deliveries WHERE webhook_id=?`, hid).Scan(&errc)
	if hit || errc != "webhook_url_blocked" {
		t.Fatalf("rebinding not blocked: hit=%v err=%q", hit, errc)
	}
	for ip, want := range map[string]bool{"127.0.0.1": true, "::ffff:127.0.0.1": true, "169.254.169.254": true, "fd00:ec2::254": true,
		"192.168.1.1": true, "172.16.0.1": true, "0.0.0.0": true, "8.8.8.8": false, "2606:4700:4700::1111": false} {
		if blockedIP(net.ParseIP(ip)) != want {
			t.Errorf("blockedIP(%s) != %v", ip, want)
		}
	}
	// only super_admin may enable private targets
	e.srv.Store.DB.Exec(`UPDATE users SET sec_role='security_admin' WHERE id=?`, e.root.ID)
	if c, m := a.call("PUT", "/api/v1/admin/webhooks/settings", map[string]any{"allow_private": true}); c != 403 {
		t.Fatalf("security_admin flipped allow_private: %d %v", c, m)
	}
}
