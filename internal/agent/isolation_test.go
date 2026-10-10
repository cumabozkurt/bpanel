// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/isolation"
)

func isoEnv(t *testing.T) (*testEnv, string, string) {
	e := newTestEnv(t)
	units, cg := t.TempDir(), t.TempDir()
	oldU, oldC, oldS := isolationUnitDir, isolationCgroupRoot, systemdPID1
	isolationUnitDir, isolationCgroupRoot = units, cg
	systemdPID1 = func() bool { return false }
	t.Cleanup(func() { isolationUnitDir, isolationCgroupRoot, systemdPID1 = oldU, oldC, oldS })
	return e, units, cg
}

func callIso(t *testing.T, e *testEnv, method string, params any) (any, error) {
	raw, _ := json.Marshal(params)
	if err := e.a.gate(method, raw); err != nil {
		return nil, err
	}
	return e.a.routes[method](context.Background(), raw)
}

func TestIsolationApplyFilesOnly(t *testing.T) {
	e, units, _ := isoEnv(t)
	out, err := callIso(t, e, rpc.MIsolationApply, rpc.IsolationApply{User: "tenant",
		Profile: isolation.Profile{CPUPercent: 100, MemMaxMB: 256, TasksMax: 50}})
	if err != nil {
		t.Fatal(err)
	}
	r := out.(rpc.IsolationApplyResult)
	if r.Status != "applied_files_only" || r.Unit != "bpanel-u-tenant.slice" {
		t.Fatalf("%+v", r)
	}
	b, err := os.ReadFile(filepath.Join(units, "bpanel-u-tenant.slice"))
	if err != nil || !strings.Contains(string(b), "MemoryMax=256M") || !strings.Contains(string(b), "TasksMax=50") {
		t.Fatalf("unit: %v\n%s", err, b)
	}
}

func TestIsolationRefusals(t *testing.T) {
	e, units, _ := isoEnv(t)
	cases := []struct {
		m string
		p any
	}{
		{rpc.MIsolationApply, rpc.IsolationApply{User: "root", Profile: isolation.Profile{MemMaxMB: 64}}},    // not managed
		{rpc.MIsolationApply, rpc.IsolationApply{User: "opsuser", Profile: isolation.Profile{MemMaxMB: 64}}}, // not managed
		{rpc.MIsolationApply, rpc.IsolationApply{User: "", Profile: isolation.Profile{}}},                    // owner required
		{rpc.MIsolationApply, rpc.IsolationApply{User: "tenant", Profile: isolation.Profile{MemMaxMB: -1}}},  // invalid
		{rpc.MIsolationApply, rpc.IsolationApply{User: "tenant", Profile: isolation.Profile{IOReadBps: 1}, IOPath: "/dev/sda x"}},
		{rpc.MIsolationStats, rpc.IsolationUser{User: "../etc"}},
	}
	for i, c := range cases {
		if _, err := callIso(t, e, c.m, c.p); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if ents, _ := os.ReadDir(units); len(ents) != 0 {
		t.Errorf("refused calls wrote files: %v", ents)
	}
	// unknown fields refused by strict decoding
	raw := json.RawMessage(`{"user":"tenant","profile":{},"evil":1}`)
	if _, err := e.a.routes[rpc.MIsolationApply](context.Background(), raw); err == nil {
		t.Error("unknown field accepted")
	}
}

func TestIsolationStatusAndStats(t *testing.T) {
	e, _, cg := isoEnv(t)
	out, err := callIso(t, e, rpc.MIsolationStatus, rpc.IsolationUser{})
	if err != nil {
		t.Fatal(err)
	}
	if s := out.(rpc.IsolationStatusResult); s.Probe.CgroupV2 || s.Probe.Reason == "" {
		t.Errorf("%+v", s)
	}
	out, _ = callIso(t, e, rpc.MIsolationStats, rpc.IsolationUser{User: "tenant"})
	if s := out.(rpc.IsolationStatsResult); s.Status != "unsupported" {
		t.Errorf("%+v", s)
	}
	os.WriteFile(filepath.Join(cg, "cgroup.controllers"), []byte("cpu io memory pids\n"), 0o644)
	out, _ = callIso(t, e, rpc.MIsolationStats, rpc.IsolationUser{User: "tenant"})
	if s := out.(rpc.IsolationStatsResult); s.Status != "not_running" {
		t.Errorf("%+v", s)
	}
	dir := isolation.CgroupDir(cg, "tenant")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "memory.current"), []byte("4096\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "memory.events"), []byte("high 1\nmax 2\noom_kill 3\n"), 0o644)
	out, _ = callIso(t, e, rpc.MIsolationStats, rpc.IsolationUser{User: "tenant"})
	if s := out.(rpc.IsolationStatsResult); s.Status != "ok" || s.Stats.MemCurrent != 4096 || s.Stats.OOMKills != 3 {
		t.Errorf("%+v", s)
	}
	out, _ = callIso(t, e, rpc.MIsolationStatus, rpc.IsolationUser{User: "tenant"})
	if s := out.(rpc.IsolationStatusResult); !s.Probe.Supported || !s.CgroupPresent || s.UnitPresent {
		t.Errorf("%+v", s)
	}
}
