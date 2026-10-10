package api

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/events"
	"github.com/cumabozkurt/bpanel/internal/isolation"
)

var (
	fakeIsoMu    sync.Mutex
	fakeIsoStats = map[string]isolation.Stats{}
	fakeIsoUnsup bool
)

// fakeIsolation answers isolation.* for fakeAgent.
func fakeIsolation(method string, b []byte) (any, bool) {
	var p rpc.IsolationUser
	_ = json.Unmarshal(b, &p)
	fakeIsoMu.Lock()
	defer fakeIsoMu.Unlock()
	switch method {
	case rpc.MIsolationApply:
		return rpc.IsolationApplyResult{Status: "applied_files_only", Unit: isolation.SliceName(p.User)}, true
	case rpc.MIsolationStatus:
		return rpc.IsolationStatusResult{Probe: isolation.ProbeResult{Supported: !fakeIsoUnsup}}, true
	case rpc.MIsolationStats:
		if fakeIsoUnsup {
			return rpc.IsolationStatsResult{Status: "unsupported", Reason: "no cgroup v2"}, true
		}
		return rpc.IsolationStatsResult{Status: "ok", Stats: fakeIsoStats[p.User]}, true
	}
	return nil, false
}

func setIsoStats(user string, st isolation.Stats) {
	fakeIsoMu.Lock()
	fakeIsoStats[user] = st
	fakeIsoMu.Unlock()
}

func (e *env) reseller(name string) int64 {
	e.t.Helper()
	rs, _, err := e.srv.CreateAccount(context.Background(), &e.root, CreateAccountReq{Username: name, Domain: name + ".test", Password: tPW,
		PackageID: e.pkg(), Role: "reseller", MaxAccounts: LimitOf(5), ResellerDiskMB: LimitOf(5000)})
	if err != nil {
		e.t.Fatal(err)
	}
	return rs.ID
}

func TestIsolationResellerLimits(t *testing.T) {
	e := newEnv(t)
	r1, r2 := e.reseller("rsone"), e.reseller("rstwo")
	c1, c2 := e.tenant("cone", "cone.test"), e.tenant("ctwo", "ctwo.test")
	db := e.srv.Store.DB
	db.Exec(`UPDATE users SET owner_id=? WHERE id=?`, r1, c1.ID)
	db.Exec(`UPDATE users SET owner_id=? WHERE id=?`, r2, c2.ID)

	admin := mustLoginAdmin(t, e)
	code, m := admin.call("POST", "/api/v1/admin/limit-profiles", map[string]any{"name": "small", "cpu_percent": 50, "mem_max_mb": 512, "mem_high_mb": 400, "tasks_max": 100})
	if code != 200 {
		t.Fatalf("create profile: %d %v", code, m)
	}
	pid := int64(m["id"].(float64))
	// reseller rsone is itself capped by "small"
	if code, m := admin.call("PUT", fmt.Sprintf("/api/v1/admin/accounts/%d/limits", r1), map[string]any{"profile_id": pid}); code != 200 || m["applied"] != true {
		t.Fatalf("admin set reseller limits: %d %v", code, m)
	}
	rs := mustLogin(t, e, e.admin, "rsone", "")
	if code, _ := rs.call("POST", "/api/v1/admin/limit-profiles", map[string]any{"name": "x"}); code != 403 {
		t.Fatalf("reseller created global profile: %d", code)
	}
	if code, _ := rs.call("PUT", fmt.Sprintf("/api/v1/admin/accounts/%d/limits", c2.ID), map[string]any{"profile_id": pid}); code != 403 {
		t.Fatalf("reseller set limits on another reseller's account: %d", code)
	}
	if code, _ := rs.call("PUT", fmt.Sprintf("/api/v1/admin/accounts/%d/limits", r1), map[string]any{"overrides": map[string]int64{}}); code != 403 {
		t.Fatalf("reseller lifted its own limits: %d", code)
	}
	code, m = rs.call("PUT", fmt.Sprintf("/api/v1/admin/accounts/%d/limits", c1.ID), map[string]any{"profile_id": pid, "overrides": map[string]int64{"mem_max_mb": 1024}})
	if code != 403 || m["error"] != "limit_exceeds_allowance" {
		t.Fatalf("exceeding allowance: %d %v", code, m)
	}
	if code, _ := rs.call("PUT", fmt.Sprintf("/api/v1/admin/accounts/%d/limits", c1.ID), map[string]any{}); code != 403 {
		t.Fatalf("unlimited child under capped reseller: %d", code)
	}
	code, m = rs.call("PUT", fmt.Sprintf("/api/v1/admin/accounts/%d/limits", c1.ID), map[string]any{"profile_id": pid, "overrides": map[string]int64{"mem_max_mb": 256, "mem_high_mb": 200}})
	if code != 200 || m["status"] != "applied_files_only" {
		t.Fatalf("own account within allowance: %d %v", code, m)
	}
	var ap rpc.IsolationApply
	calls := e.ag.find(rpc.MIsolationApply)
	_ = json.Unmarshal(calls[len(calls)-1].Params, &ap)
	if ap.User != "cone" || ap.Profile.MemMaxMB != 256 || ap.Profile.CPUPercent != 50 {
		t.Fatalf("apply params: %+v", ap)
	}
	if code, _ := rs.call("GET", fmt.Sprintf("/api/v1/admin/accounts/%d/usage?range=1h", c2.ID), nil); code != 403 {
		t.Fatalf("reseller read other usage: %d", code)
	}
	if code, _ := rs.call("GET", "/api/v1/admin/accounts/1/usage?range=99d", nil); code != 403 && code != 400 {
		t.Fatalf("bad range: %d", code)
	}
	if code, _ := admin.call("DELETE", fmt.Sprintf("/api/v1/admin/limit-profiles/%d", pid), nil); code != 409 {
		t.Fatalf("delete in-use profile: %d", code)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action LIKE 'iso.%'`).Scan(&n)
	if n < 3 {
		t.Fatalf("audit entries: %d", n)
	}
}

func TestIsolationUserSeesOwnUsage(t *testing.T) {
	e := newEnv(t)
	a, b := e.tenant("alice", "alice.test"), e.tenant("bob", "bob.test")
	now := e.srv.Now().Unix() / usageBucket * usageBucket
	e.srv.Store.DB.Exec(`INSERT INTO usage_samples(account_id,bucket_ts,cpu_usec,mem_bytes,pids) VALUES(?,?,?,?,?),(?,?,?,?,?)`,
		a.ID, now, 1000, 111, 1, b.ID, now, 2000, 222, 2)
	s := mustLogin(t, e, e.user, "alice", "")
	code, m := s.call("GET", "/api/v1/user/usage?range=1h", nil)
	if code != 200 {
		t.Fatalf("usage: %d %v", code, m)
	}
	pts := m["points"].([]any)
	if len(pts) != 1 || pts[0].(map[string]any)["mem_bytes"].(float64) != 111 || m["username"] != "alice" {
		t.Fatalf("own usage: %v", m)
	}
	// the user realm has no admin usage routes
	if code, _ := s.call("GET", fmt.Sprintf("/api/v1/admin/accounts/%d/usage", b.ID), nil); code == 200 {
		t.Fatal("user read admin usage route")
	}
}

func TestUsageSamplerBucketsPruneAndEvents(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("carol", "carol.test")
	var mu sync.Mutex
	var got []events.Event
	stop := events.Subscribe(func(ev events.Event) {
		if ev.Type == "iso.limit_hit" {
			mu.Lock()
			got = append(got, ev)
			mu.Unlock()
		}
	})
	defer stop()
	base := time.Unix(1_800_000_000/usageBucket*usageBucket, 0)
	setIsoStats("carol", isolation.Stats{CPUUsageUsec: 1_000_000, MemCurrent: 100, IORBytes: 10, PidsCurrent: 2, PidsMax: 50})
	e.srv.sampleUsage(context.Background(), base)
	setIsoStats("carol", isolation.Stats{CPUUsageUsec: 4_000_000, MemCurrent: 300, IORBytes: 30, PidsCurrent: 3, PidsMax: 50})
	e.srv.sampleUsage(context.Background(), base.Add(60*time.Second))
	setIsoStats("carol", isolation.Stats{CPUUsageUsec: 5_000_000, MemCurrent: 200, IORBytes: 40, PidsCurrent: 50, PidsMax: 50, OOMKills: 1, MemMaxEvents: 4})
	e.srv.sampleUsage(context.Background(), base.Add(120*time.Second))
	var rows int
	var cpu, mem, ior, pids int64
	var evs string
	e.srv.Store.DB.QueryRow(`SELECT COUNT(*), SUM(cpu_usec), MAX(mem_bytes), SUM(io_r), MAX(pids), MAX(events) FROM usage_samples WHERE account_id=?`, a.ID).
		Scan(&rows, &cpu, &mem, &ior, &pids, &evs)
	if rows != 1 || cpu != 4_000_000 || mem != 300 || ior != 30 || pids != 50 {
		t.Fatalf("bucket upsert: rows=%d cpu=%d mem=%d io=%d pids=%d", rows, cpu, mem, ior, pids)
	}
	var em map[string]int64
	_ = json.Unmarshal([]byte(evs), &em)
	if em["oom_kill"] != 1 || em["mem_max"] != 4 || em["pids_max"] != 1 {
		t.Fatalf("events: %s", evs)
	}
	events.Flush()
	mu.Lock()
	if len(got) != 1 || got[0].Severity != events.Critical || got[0].AccountID != a.ID {
		t.Fatalf("published: %+v", got)
	}
	mu.Unlock()
	// a later bucket, then prune everything older than 30 days
	e.srv.sampleUsage(context.Background(), base.Add(10*time.Minute))
	n, err := e.srv.pruneUsage(context.Background(), base.Add(30*24*time.Hour+6*time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	// unsupported agent: recorded once, sampling paused
	fakeIsoMu.Lock()
	fakeIsoUnsup = true
	fakeIsoMu.Unlock()
	defer func() { fakeIsoMu.Lock(); fakeIsoUnsup = false; fakeIsoMu.Unlock() }()
	e.ag.reset()
	e.srv.sampleUsage(context.Background(), base.Add(time.Hour))
	e.srv.sampleUsage(context.Background(), base.Add(time.Hour+time.Minute))
	if st := samplerStateOf(e.srv).status(); st["status"] != "unsupported" || len(e.ag.find(rpc.MIsolationStats)) != 1 {
		t.Fatalf("unsupported: %v calls=%d", st, len(e.ag.find(rpc.MIsolationStats)))
	}
}
