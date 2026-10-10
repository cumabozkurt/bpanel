// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/smtp"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/obsx"
)

// obsxFakeCaller wraps the test agent and answers the obsx methods.
type obsxFakeCaller struct {
	rpc.Caller
	mu      sync.Mutex
	entries []obsx.FIMEntry
	disks   []rpc.ObsxDisk
}

func (c *obsxFakeCaller) Call(ctx context.Context, method string, params, out any) error {
	c.mu.Lock()
	var v any
	switch method {
	case rpc.MObsxFIMScan:
		v = rpc.ObsxFIMResult{Entries: append([]obsx.FIMEntry{}, c.entries...)}
	case rpc.MObsxOSHealth:
		v = rpc.ObsxHealth{Disks: c.disks, Checks: []obsx.HealthCheck{{ID: "raid", Status: obsx.HUnsupported, Reason: "test"}}}
	}
	c.mu.Unlock()
	if v == nil {
		return c.Caller.Call(ctx, method, params, out)
	}
	b, _ := json.Marshal(v)
	return json.Unmarshal(b, out)
}

func obsxEnv(t *testing.T) (*env, *obsxFakeCaller) {
	e := newEnv(t)
	fc := &obsxFakeCaller{Caller: e.srv.Agent}
	e.srv.Agent = fc
	return e, fc
}

func TestObsxMetricsEndpoint(t *testing.T) {
	e, fc := obsxEnv(t)
	fc.disks = []rpc.ObsxDisk{{Mount: "/", UsedPct: 50, InodePct: 5}}
	admin := mustLoginAdmin(t, e)
	admin.call("GET", "/api/v1/admin/obsx/rules", nil)
	w := e.do(e.admin, req{method: "GET", path: "/metrics"}, admin)
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("metrics: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	body := w.Body.String()
	for _, want := range []string{`bpanel_http_requests_total{method="GET",route="/api/v1/admin/obsx/rules",code="2xx"}`, "# TYPE bpanel_http_request_duration_seconds histogram",
		`bpanel_disk_used_ratio{mount="/"} 0.5`, "bpanel_agent_calls_total"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	// anonymous remote client refused; loopback allowed by default; disabled by setting
	if w := e.do(e.admin, req{method: "GET", path: "/metrics", ip: "203.0.113.9"}, nil); w.Code != 403 {
		t.Fatalf("remote anon: %d", w.Code)
	}
	if w := e.do(e.admin, req{method: "GET", path: "/metrics", ip: "127.0.0.1"}, nil); w.Code != 200 {
		t.Fatalf("loopback: %d", w.Code)
	}
	e.srv.Store.Set("obsx_metrics_localhost", "0")
	if w := e.do(e.admin, req{method: "GET", path: "/metrics", ip: "127.0.0.1"}, nil); w.Code != 403 {
		t.Fatalf("loopback disabled: %d", w.Code)
	}
	if w := e.do(e.user, req{method: "GET", path: "/metrics", ip: "127.0.0.1"}, nil); w.Code == 200 {
		t.Fatal("user realm must not serve /metrics")
	}
}

func TestObsxAlertDedupCooldownAndIncidents(t *testing.T) {
	e, _ := obsxEnv(t)
	ctx := context.Background()
	base := time.Unix(1_800_000_000, 0)
	clk := newTestClock(base)
	e.srv.Now = clk.Now
	rule, _ := e.srv.obsxRule(ctx, obsx.RuleDiskFull)
	rule.Cooldown = 600
	id1, n1 := e.srv.obsxRaise(ctx, rule, "disk:/", "disk full", "", 0)
	clk.Set(base.Add(5 * time.Minute))
	id2, n2 := e.srv.obsxRaise(ctx, rule, "disk:/", "disk full", "", 0)
	clk.Set(base.Add(11 * time.Minute))
	id3, n3 := e.srv.obsxRaise(ctx, rule, "disk:/", "disk full", "", 0)
	if id1 == 0 || id1 != id2 || id2 != id3 || !n1 || n2 || !n3 {
		t.Fatalf("dedup/cooldown: ids %d %d %d notify %v %v %v", id1, id2, id3, n1, n2, n3)
	}
	var cnt int
	e.srv.Store.DB.QueryRow(`SELECT count FROM obsx_incidents WHERE id=?`, id1).Scan(&cnt)
	if cnt != 3 {
		t.Fatalf("count %d", cnt)
	}
	admin := mustLoginAdmin(t, e)
	path := fmt.Sprintf("/api/v1/admin/obsx/incidents/%d/action", id1)
	if c, m := admin.call("POST", path, map[string]any{"action": "reopen"}); c != 409 || m["error"] != "incident_bad_transition" {
		t.Fatalf("reopen open: %d %v", c, m)
	}
	if c, m := admin.call("POST", path, map[string]any{"action": "ack"}); c != 200 || m["incident"].(map[string]any)["status"] != "acknowledged" {
		t.Fatalf("ack: %d %v", c, m)
	}
	if c, m := admin.call("POST", path, map[string]any{"action": "assign", "assignee_id": e.root.ID}); c != 200 || m["incident"].(map[string]any)["assignee"] == "" {
		t.Fatalf("assign: %d %v", c, m)
	}
	if c, m := admin.call("POST", path, map[string]any{"action": "assign", "assignee_id": 999999}); c != 400 || m["error"] != "obsx_bad_assignee" {
		t.Fatalf("bad assignee: %d %v", c, m)
	}
	if c, m := admin.call("POST", path, map[string]any{"action": "resolve", "note": "freed space"}); c != 200 || m["incident"].(map[string]any)["status"] != "resolved" {
		t.Fatalf("resolve: %d %v", c, m)
	}
	c, m := admin.call("GET", fmt.Sprintf("/api/v1/admin/obsx/incidents/%d", id1), nil)
	hist := m["history"].([]any)
	if c != 200 || len(hist) != 4 || hist[3].(map[string]any)["note"] != "freed space" {
		t.Fatalf("history: %d %v", c, m)
	}
	// after resolve the same key opens a new incident and notifies at once
	clk.Set(base.Add(12 * time.Minute))
	id4, n4 := e.srv.obsxRaise(ctx, rule, "disk:/", "disk full", "", 0)
	if id4 == id1 || !n4 {
		t.Fatalf("new incident after resolve: %d %v", id4, n4)
	}
	// disabled rule raises nothing
	rule.Enabled = false
	if id, _ := e.srv.obsxRaise(ctx, rule, "disk:/x", "t", "", 0); id != 0 {
		t.Fatal("disabled rule raised")
	}
}

func TestObsxEvaluateDiskAndAutoResolve(t *testing.T) {
	e, fc := obsxEnv(t)
	ctx := context.Background()
	e.srv.Store.Set("obsx_fim_interval_min", "0")
	fc.disks = []rpc.ObsxDisk{{Mount: "/", UsedPct: 95}}
	if out := e.srv.obsxEvaluate(ctx); out[obsx.RuleDiskFull] != 1 {
		t.Fatalf("disk rule: %v", out)
	}
	fc.mu.Lock()
	fc.disks = []rpc.ObsxDisk{{Mount: "/", UsedPct: 40}}
	fc.mu.Unlock()
	e.srv.obsx().health = nil
	e.srv.obsxEvaluate(ctx)
	var st string
	e.srv.Store.DB.QueryRow(`SELECT status FROM obsx_incidents WHERE dedup_key='disk:/'`).Scan(&st)
	if st != "resolved" {
		t.Fatalf("auto resolve: %q", st)
	}
}

func TestObsxFIMChangeDetection(t *testing.T) {
	e, fc := obsxEnv(t)
	admin := mustLoginAdmin(t, e)
	if c, m := admin.call("POST", "/api/v1/admin/obsx/fim/check", nil); c != 409 || m["error"] != "obsx_no_baseline" {
		t.Fatalf("no baseline: %d %v", c, m)
	}
	fc.entries = []obsx.FIMEntry{{Path: "/etc/ssh/sshd_config", Mode: obsx.FIMHash, SHA256: "aa", Size: 3}, {Path: "/etc/shadow", Mode: obsx.FIMMeta, MTime: 10}}
	if c, m := admin.call("POST", "/api/v1/admin/obsx/fim/baseline", nil); c != 200 || m["files"].(float64) != 2 {
		t.Fatalf("baseline: %d %v", c, m)
	}
	if c, m := admin.call("POST", "/api/v1/admin/obsx/fim/check", nil); c != 200 || len(m["changes"].([]any)) != 0 {
		t.Fatalf("clean check: %d %v", c, m)
	}
	fc.mu.Lock()
	fc.entries = []obsx.FIMEntry{{Path: "/etc/ssh/sshd_config", Mode: obsx.FIMHash, SHA256: "bb", Size: 3}, {Path: "/etc/shadow", Mode: obsx.FIMMeta, MTime: 11}}
	fc.mu.Unlock()
	c, m := admin.call("POST", "/api/v1/admin/obsx/fim/check", nil)
	if c != 200 || len(m["changes"].([]any)) != 2 {
		t.Fatalf("changed: %d %v", c, m)
	}
	var n int
	e.srv.Store.DB.QueryRow(`SELECT COUNT(*) FROM obsx_incidents WHERE rule='fim_change' AND status='open'`).Scan(&n)
	if n != 1 {
		t.Fatalf("fim incident: %d", n)
	}
	if c, m := admin.call("GET", "/api/v1/admin/obsx/fim", nil); c != 200 || m["baseline_files"].(float64) != 2 || m["last"] == nil {
		t.Fatalf("status: %d %v", c, m)
	}
}

func TestObsxRetentionPrune(t *testing.T) {
	e, _ := obsxEnv(t)
	ctx := context.Background()
	now := e.srv.Now()
	db := e.srv.Store.DB
	old, recent := now.AddDate(0, 0, -100).Unix(), now.AddDate(0, 0, -10).Unix()
	db.Exec(`INSERT INTO audit_log(at,action) VALUES(?, 'old.one'),(?, 'recent.one')`, old, recent)
	db.Exec(`INSERT INTO bw_daily(domain,day,bytes) VALUES('a.test',?,1),('a.test',?,1)`, now.AddDate(0, 0, -60).UTC().Format("2006-01-02"), now.UTC().Format("2006-01-02"))
	db.Exec(`INSERT INTO obsx_incidents(dedup_key,rule,severity,title,status,first_at,last_at,resolved_at) VALUES('k','r','info','t','resolved',?,?,?),('k2','r','info','t','open',?,?,0)`, old, old, old, old, old)
	admin := mustLoginAdmin(t, e)
	if c, m := admin.call("PUT", "/api/v1/admin/obsx/settings", map[string]any{"audit_days": 3}); c != 400 || m["error"] != "obsx_bad_retention" {
		t.Fatalf("bounds: %d %v", c, m)
	}
	if c, m := admin.call("PUT", "/api/v1/admin/obsx/settings", map[string]any{"audit_days": 30, "bandwidth_days": 31, "incidents_days": 30}); c != 200 {
		t.Fatalf("set: %d %v", c, m)
	}
	e.srv.prune(ctx)
	var a1, a2, bw, inc int
	db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='old.one'`).Scan(&a1)
	db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='recent.one'`).Scan(&a2)
	db.QueryRow(`SELECT COUNT(*) FROM bw_daily`).Scan(&bw)
	db.QueryRow(`SELECT COUNT(*) FROM obsx_incidents`).Scan(&inc)
	if a1 != 0 || a2 != 1 || bw != 1 || inc != 1 {
		t.Fatalf("prune: old audit %d recent audit %d bw %d incidents %d", a1, a2, bw, inc)
	}
}

func TestObsxChannels(t *testing.T) {
	e, _ := obsxEnv(t)
	e.srv.Cfg.SecretKeyFile = filepath.Join(t.TempDir(), "secret.key")
	admin := mustLoginAdmin(t, e)
	if c, m := admin.call("POST", "/api/v1/admin/obsx/channels", map[string]any{"name": "x", "kind": "pagerduty"}); c != 400 || m["error"] != "obsx_bad_channel_kind" {
		t.Fatalf("kind: %d %v", c, m)
	}
	if c, m := admin.call("POST", "/api/v1/admin/obsx/channels", map[string]any{"name": "s", "kind": "slack", "secret": "https://evil.example/x"}); c != 400 || m["error"] != "obsx_bad_secret" {
		t.Fatalf("slack url: %d %v", c, m)
	}
	var posted []string
	oldPost, oldMail := obsxPost, obsxSendMail
	defer func() { obsxPost, obsxSendMail = oldPost, oldMail }()
	obsxPost = func(s *Server, ctx context.Context, u, ct string, body []byte) (int, error) {
		posted = append(posted, u+" "+string(body))
		return 200, nil
	}
	var mailed []string
	obsxSendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		mailed = append(mailed, strings.Join(to, ","))
		return nil
	}
	hook := "https://hooks.slack.com/services/T000/B000/XXXXXXXX"
	c, m := admin.call("POST", "/api/v1/admin/obsx/channels", map[string]any{"name": "ops", "kind": "slack", "secret": hook, "min_severity": "warning"})
	if c != 200 {
		t.Fatalf("create: %d %v", c, m)
	}
	id := int64(m["id"].(float64))
	c, m = admin.call("GET", "/api/v1/admin/obsx/channels", nil)
	if b, _ := json.Marshal(m); strings.Contains(string(b), "XXXXXXXX") || c != 200 {
		t.Fatal("secret leaked in list")
	}
	if c, m := admin.call("POST", fmt.Sprintf("/api/v1/admin/obsx/channels/%d/test", id), nil); c != 200 || len(posted) != 1 || !strings.HasPrefix(posted[0], hook) {
		t.Fatalf("test send: %d %v %v", c, m, posted)
	}
	if c, _ := admin.call("POST", "/api/v1/admin/obsx/channels", map[string]any{"name": "mail", "kind": "email", "target": "ops@example.com", "min_severity": "critical"}); c != 200 {
		t.Fatal("email channel")
	}
	e.srv.obsxNotify(context.Background(), "warning", "w", "")
	if len(mailed) != 0 || len(posted) != 2 {
		t.Fatalf("severity filter: mailed %v posted %d", mailed, len(posted))
	}
	e.srv.obsxNotify(context.Background(), "critical", "c", "")
	if len(mailed) != 1 || len(posted) != 3 {
		t.Fatalf("critical: mailed %v posted %d", mailed, len(posted))
	}
}
