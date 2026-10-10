// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/shield"
)

type downEngine struct{}

func (downEngine) Name() string                            { return "fake-clamd" }
func (downEngine) Kind() string                            { return shield.KindExternal }
func (downEngine) Available(context.Context) bool          { return false }
func (downEngine) SignatureVersion(context.Context) string { return "down" }
func (downEngine) Status(context.Context) shield.ProviderStatus {
	return shield.ProviderStatus{Name: "fake-clamd", Kind: shield.KindExternal, Status: shield.StatusUnavailable, Reason: "socket refused"}
}
func (downEngine) Scan(context.Context, shield.Target) (shield.EngineResult, error) {
	return shield.EngineResult{Engine: "fake-clamd", Error: "unavailable"}, shield.ErrUnavailable
}

func shieldEnv(t *testing.T, down bool) *testEnv {
	t.Helper()
	e := newTestEnv(t)
	e.a.Cfg.ShieldDir = filepath.Join(t.TempDir(), "shield")
	oldE, oldP := shieldEngines, shieldPlace
	shieldEngines = func(dir string) (active, all []shield.MalwareScannerProvider) {
		h := &shield.Heuristic{}
		if down {
			return []shield.MalwareScannerProvider{h, downEngine{}}, []shield.MalwareScannerProvider{h, downEngine{}}
		}
		return []shield.MalwareScannerProvider{h}, []shield.MalwareScannerProvider{h}
	}
	// tests do not run as root: place by copying instead of the setuid files helper
	shieldPlace = func(a *Agent, ctx context.Context, user, staged, rel string) error {
		h, err := a.home(user)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(staged)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(h.home, rel), b, 0o644)
	}
	t.Cleanup(func() { shieldEngines, shieldPlace = oldE, oldP })
	return e
}

func shCall[T any](t *testing.T, a *Agent, m string, p any) (T, string) {
	t.Helper()
	b, _ := json.Marshal(p)
	r := r2dispatch(t, a, m, string(b))
	var out T
	if r.Error == nil && r.Result != nil {
		rb, _ := json.Marshal(r.Result)
		_ = json.Unmarshal(rb, &out)
	}
	return out, r2code(r)
}

func stage(t *testing.T, a *Agent, id string, data []byte) {
	t.Helper()
	if _, c := shCall[struct{}](t, a, rpc.MShieldStageChunk, rpc.ShieldStageChunk{User: "tenant", ID: id, Content: base64.StdEncoding.EncodeToString(data)}); c != "ok" {
		t.Fatalf("stage chunk: %s", c)
	}
}

func homeOf(t *testing.T, a *Agent) string {
	h, err := a.home("tenant")
	if err != nil {
		t.Fatal(err)
	}
	return h.home
}

func TestShieldUploadPipeline(t *testing.T) {
	e := shieldEnv(t, false)
	home := homeOf(t, e.a)
	// clean upload is placed
	stage(t, e.a, "clean0001", []byte("hello world"))
	r, c := shCall[rpc.ShieldStageCommitResult](t, e.a, rpc.MShieldStageCommit, rpc.ShieldStageCommit{User: "tenant", ID: "clean0001", Path: "a.txt", Name: "a.txt"})
	if c != "ok" || !r.Placed || r.Action != "allow" {
		t.Fatalf("clean: %s %+v", c, r)
	}
	if b, _ := os.ReadFile(filepath.Join(home, "a.txt")); string(b) != "hello world" {
		t.Fatalf("placed content %q", b)
	}
	// EICAR is not placed, goes to quarantine, journal has it
	stage(t, e.a, "eicar0001", []byte("x "+shield.EICAR))
	r, c = shCall[rpc.ShieldStageCommitResult](t, e.a, rpc.MShieldStageCommit, rpc.ShieldStageCommit{User: "tenant", ID: "eicar0001", Path: "e.txt", Name: "e.txt"})
	if c != "ok" || r.Placed || r.Outcome != "infected" || r.QuarantineID == "" || len(r.Detections) == 0 || r.EventUID == "" {
		t.Fatalf("eicar: %s %+v", c, r)
	}
	if _, err := os.Stat(filepath.Join(home, "e.txt")); err == nil {
		t.Fatal("infected upload placed")
	}
	if ents, _ := os.ReadDir(filepath.Join(e.a.Cfg.ShieldDir, "staging", "tenant")); len(ents) != 0 {
		t.Fatalf("staging left behind: %d", len(ents))
	}
	ev, c := shCall[rpc.ShieldEventsResult](t, e.a, rpc.MShieldEvents, rpc.ShieldEventsReq{})
	if c != "ok" || len(ev.Events) != 1 || ev.Events[0].UID != r.EventUID || ev.Events[0].Account != "tenant" {
		t.Fatalf("events: %s %+v", c, ev)
	}
	if ev2, _ := shCall[rpc.ShieldEventsResult](t, e.a, rpc.MShieldEvents, rpc.ShieldEventsReq{Since: ev.LastSeq}); len(ev2.Events) != 0 {
		t.Fatalf("since: %+v", ev2)
	}
	ql, c := shCall[rpc.ShieldQListResult](t, e.a, rpc.MShieldQList, rpc.ShieldQListReq{User: "tenant"})
	if c != "ok" || len(ql.Items) != 1 || ql.Items[0].OrigPath != filepath.Join(home, "e.txt") {
		t.Fatalf("qlist: %s %+v", c, ql)
	}
	// bad ids / wrong account
	if _, c := shCall[struct{}](t, e.a, rpc.MShieldStageChunk, rpc.ShieldStageChunk{User: "tenant", ID: "../../x", Content: ""}); c != "invalid_stage_id" {
		t.Fatalf("stage id: %s", c)
	}
	if _, c := shCall[rpc.ShieldStageCommitResult](t, e.a, rpc.MShieldStageCommit, rpc.ShieldStageCommit{User: "tenant", ID: "nothere01", Path: "/etc/x"}); c != "invalid_path" {
		t.Fatalf("abs path: %s", c)
	}
	if _, c := shCall[shield.QuarantineMeta](t, e.a, rpc.MShieldQDelete, rpc.ShieldQRef{User: "tenant", ID: "nope"}); c != "not_found" {
		t.Fatalf("q delete unknown: %s", c)
	}
	if _, c := shCall[shield.QuarantineMeta](t, e.a, rpc.MShieldQDelete, rpc.ShieldQRef{User: "tenant", ID: r.QuarantineID}); c != "ok" {
		t.Fatalf("q delete: %s", c)
	}
}

func TestShieldScannerDownBlocksScripts(t *testing.T) {
	e := shieldEnv(t, true)
	home := homeOf(t, e.a)
	stage(t, e.a, "php000001", []byte("<?php echo 1;"))
	r, c := shCall[rpc.ShieldStageCommitResult](t, e.a, rpc.MShieldStageCommit, rpc.ShieldStageCommit{User: "tenant", ID: "php000001", Path: "i.php", Name: "i.php"})
	if c != "ok" || r.Placed || r.Action != "block" || r.Outcome != "scanner_unavailable" {
		t.Fatalf("down+php: %s %+v", c, r)
	}
	if _, err := os.Stat(filepath.Join(home, "i.php")); err == nil {
		t.Fatal("php placed while scanner down")
	}
	// a non-script is allowed with a warning (recorded)
	stage(t, e.a, "txt000001", []byte("plain"))
	r, c = shCall[rpc.ShieldStageCommitResult](t, e.a, rpc.MShieldStageCommit, rpc.ShieldStageCommit{User: "tenant", ID: "txt000001", Path: "t.txt", Name: "t.txt"})
	if c != "ok" || !r.Placed || r.Action != "allow_with_warning" || r.EventUID == "" {
		t.Fatalf("down+txt: %s %+v", c, r)
	}
	st, c := shCall[rpc.ShieldStatusResult](t, e.a, rpc.MShieldStatus, struct{}{})
	if c != "ok" || len(st.Engines) != 2 || st.Engines[1].Status != shield.StatusUnavailable || st.Realtime != "off" {
		t.Fatalf("status: %s %+v", c, st)
	}
}

func TestShieldOnDemandScan(t *testing.T) {
	e := shieldEnv(t, false)
	home := homeOf(t, e.a)
	if err := os.WriteFile(filepath.Join(home, "bad.txt"), []byte(shield.EICAR), 0o644); err != nil {
		t.Fatal(err)
	}
	r, c := shCall[rpc.ShieldScanResult](t, e.a, rpc.MShieldScan, rpc.ShieldScanReq{User: "tenant", Path: "bad.txt"})
	if c != "ok" || r.Result.Outcome != shield.OutInfected || r.QuarantineID == "" {
		t.Fatalf("scan: %s %+v", c, r)
	}
	if _, err := os.Stat(filepath.Join(home, "bad.txt")); err == nil {
		t.Fatal("infected file not quarantined")
	}
	// paths outside the home are refused (.., absolute, symlink)
	outside := filepath.Join(filepath.Dir(filepath.Dir(home)), "outside")
	_ = os.WriteFile(filepath.Join(outside, "x"), []byte("x"), 0o644)
	_ = os.Symlink(outside, filepath.Join(home, "ln"))
	for _, p := range []string{"../../outside/x", filepath.Join(outside, "x"), "ln/x"} {
		if _, c := shCall[rpc.ShieldScanResult](t, e.a, rpc.MShieldScan, rpc.ShieldScanReq{User: "tenant", Path: p}); c != "path_outside_home" {
			t.Fatalf("%s: %s", p, c)
		}
	}
	// false positive => allowlisted + restored
	m, c := shCall[shield.QuarantineMeta](t, e.a, rpc.MShieldQFP, rpc.ShieldQRef{User: "tenant", ID: r.QuarantineID, Scope: "account"})
	if c != "ok" || m.FalsePositive != "account" {
		t.Fatalf("fp: %s %+v", c, m)
	}
	if b, err := os.ReadFile(filepath.Join(home, "bad.txt")); err != nil || string(b) != shield.EICAR {
		t.Fatalf("not restored: %v", err)
	}
}
