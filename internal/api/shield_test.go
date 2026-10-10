// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/shield"
)

// fake agent side of the Shield pipeline: staging files under homes/.stage,
// the real shield scanner (heuristic engine, optionally a "down" engine),
// placement into homes/<user>/<path>, an in-memory journal and quarantine.
type fakeShieldState struct {
	mu      sync.Mutex
	down    bool
	journal []rpc.ShieldEvent
	quar    map[string]shield.QuarantineMeta
}

var fakeShields sync.Map // *fakeAgent -> *fakeShieldState

func fakeShieldOf(a *fakeAgent) *fakeShieldState {
	v, _ := fakeShields.LoadOrStore(a, &fakeShieldState{quar: map[string]shield.QuarantineMeta{}})
	return v.(*fakeShieldState)
}

type fakeDown struct{}

func (fakeDown) Name() string                            { return "fake-clamd" }
func (fakeDown) Kind() string                            { return shield.KindExternal }
func (fakeDown) Available(context.Context) bool          { return false }
func (fakeDown) SignatureVersion(context.Context) string { return "down" }
func (fakeDown) Status(context.Context) shield.ProviderStatus {
	return shield.ProviderStatus{Name: "fake-clamd", Status: "unavailable"}
}
func (fakeDown) Scan(context.Context, shield.Target) (shield.EngineResult, error) {
	return shield.EngineResult{Engine: "fake-clamd", Error: "unavailable"}, shield.ErrUnavailable
}

func fakeShield(a *fakeAgent, method string, b []byte) (any, bool, error) {
	if !strings.HasPrefix(method, "shield.") {
		return nil, false, nil
	}
	st := fakeShieldOf(a)
	st.mu.Lock()
	defer st.mu.Unlock()
	stageFile := func(user, id string) string {
		d := filepath.Join(a.homes, ".stage", user)
		_ = os.MkdirAll(d, 0o700)
		return filepath.Join(d, id)
	}
	journal := func(ev rpc.ShieldEvent) rpc.ShieldEvent {
		ev.Seq = int64(len(st.journal) + 1)
		ev.UID = fmt.Sprintf("u%d-%d", time.Now().UnixNano(), ev.Seq)
		ev.TS = time.Now().Unix()
		st.journal = append(st.journal, ev)
		return ev
	}
	switch method {
	case rpc.MShieldStageChunk:
		var p rpc.ShieldStageChunk
		_ = json.Unmarshal(b, &p)
		data, _ := base64.StdEncoding.DecodeString(p.Content)
		f, err := os.OpenFile(stageFile(p.User, p.ID), os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			return nil, true, err
		}
		defer f.Close()
		_, err = f.WriteAt(data, p.Offset)
		return struct{}{}, true, err
	case rpc.MShieldStageAbort:
		var p rpc.ShieldStageRef
		_ = json.Unmarshal(b, &p)
		_ = os.Remove(stageFile(p.User, p.ID))
		return struct{}{}, true, nil
	case rpc.MShieldStageCommit:
		var p rpc.ShieldStageCommit
		_ = json.Unmarshal(b, &p)
		sp := stageFile(p.User, p.ID)
		defer os.Remove(sp)
		sc := shield.NewScanner()
		if st.down {
			sc.Engines = append(sc.Engines, fakeDown{})
		}
		r, err := sc.ScanNamed(context.Background(), sp, p.Name)
		if err != nil {
			return nil, true, err
		}
		d := shield.Decide(r.Outcome, r.Type.Class, p.Policy)
		res := rpc.ShieldStageCommitResult{Action: string(d.Action), Reason: d.Reason, Outcome: string(r.Outcome), SHA256: r.SHA256, Detections: r.Detections}
		switch d.Action {
		case shield.ActAllow, shield.ActAllowWarning:
			data, _ := os.ReadFile(sp)
			if err := os.WriteFile(filepath.Join(a.homes, p.User, p.Path), data, 0o644); err != nil {
				return nil, true, &rpc.Error{Code: "not_found", Message: p.Path}
			}
			res.Placed = true
		case shield.ActQuarantine, shield.ActHold:
			res.QuarantineID = fmt.Sprintf("q%d", len(st.quar)+1)
			st.quar[res.QuarantineID] = shield.QuarantineMeta{ID: res.QuarantineID, Account: p.User, OrigPath: p.Path, SHA256: r.SHA256, Detections: r.Detections, TS: time.Now()}
		}
		if d.Record || r.Outcome != shield.OutClean {
			res.EventUID = journal(rpc.ShieldEvent{Kind: "upload", Source: "upload", Account: p.User, Path: p.Path, Outcome: res.Outcome,
				Action: res.Action, Detections: r.Detections, QuarantineID: res.QuarantineID}).UID
		}
		return res, true, nil
	case rpc.MShieldEvents:
		var p rpc.ShieldEventsReq
		_ = json.Unmarshal(b, &p)
		out := rpc.ShieldEventsResult{Events: []rpc.ShieldEvent{}, LastSeq: int64(len(st.journal))}
		for _, ev := range st.journal {
			if ev.Seq > p.Since {
				out.Events = append(out.Events, ev)
			}
		}
		return out, true, nil
	case rpc.MShieldQList:
		out := rpc.ShieldQListResult{Items: []shield.QuarantineMeta{}}
		for _, m := range st.quar {
			out.Items = append(out.Items, m)
		}
		return out, true, nil
	case rpc.MShieldQDelete, rpc.MShieldQRestore, rpc.MShieldQFP:
		var p rpc.ShieldQRef
		_ = json.Unmarshal(b, &p)
		m, ok := st.quar[p.ID]
		if !ok || m.Account != p.User {
			return nil, true, &rpc.Error{Code: "not_found", Message: "quarantine item"}
		}
		delete(st.quar, p.ID)
		journal(rpc.ShieldEvent{Kind: "delete", Source: "admin", Account: p.User, QuarantineID: p.ID})
		return m, true, nil
	case rpc.MShieldStatus:
		return rpc.ShieldStatusResult{Engines: []shield.ProviderStatus{{Name: "bpanel-heuristic", Status: "ok"}}, Realtime: "off", LastSeq: int64(len(st.journal))}, true, nil
	case rpc.MShieldScan:
		return rpc.ShieldScanResult{}, true, nil
	}
	return nil, false, nil
}

func uploadFile(t *testing.T, e *env, s *sess, name string, data []byte) (int, map[string]any) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("path", "public_html")
	fw, _ := mw.CreateFormFile("file", name)
	_, _ = fw.Write(data)
	_ = mw.Close()
	w := e.do(e.user, req{method: "POST", path: "/api/v1/user/files/upload", raw: &body, ctype: mw.FormDataContentType()}, s)
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w.Code, m
}

func TestShieldUploadEICARBlocked(t *testing.T) {
	e := newEnv(t)
	u := e.tenant("alice", "alice.test")
	_ = os.MkdirAll(filepath.Join(e.ag.homes, "alice", "public_html"), 0o755)
	s := mustLogin(t, e, e.user, "alice", "")
	// clean upload is placed
	if code, m := uploadFile(t, e, s, "ok.txt", []byte("hello")); code != 200 {
		t.Fatalf("clean upload: %d %v", code, m)
	}
	if b, _ := os.ReadFile(filepath.Join(e.ag.homes, "alice", "public_html", "ok.txt")); string(b) != "hello" {
		t.Fatalf("clean file %q", b)
	}
	// EICAR is refused with the detections and recorded
	code, m := uploadFile(t, e, s, "eicar.com", []byte(shield.EICAR))
	if code != 422 || m["error"] != "shield_blocked" {
		t.Fatalf("eicar upload: %d %v", code, m)
	}
	det, _ := m["details"].(map[string]any)
	if dl, _ := det["detections"].([]any); len(dl) == 0 {
		t.Fatalf("no detections in %v", m)
	}
	if _, err := os.Stat(filepath.Join(e.ag.homes, "alice", "public_html", "eicar.com")); err == nil {
		t.Fatal("infected upload placed")
	}
	var n int
	var sig string
	_ = e.srv.Store.DB.QueryRow(`SELECT COUNT(*), MAX(signature) FROM shield_detections WHERE account_id=? AND outcome='infected'`, u.ID).Scan(&n, &sig)
	if n != 1 || sig == "" {
		t.Fatalf("detection rows: %d %q", n, sig)
	}
	// the poller sees the same event again: deduplicated
	e.srv.shieldPollOnce(context.Background())
	_ = e.srv.Store.DB.QueryRow(`SELECT COUNT(*) FROM shield_detections`).Scan(&n)
	if n != 1 {
		t.Fatalf("poller duplicated: %d", n)
	}
	// the user sees it and can ask for a restore
	code, m = s.call("GET", "/api/v1/user/shield/detections", nil)
	items, _ := m["items"].([]any)
	if code != 200 || len(items) != 1 {
		t.Fatalf("user detections: %d %v", code, m)
	}
	id := int64(items[0].(map[string]any)["id"].(float64))
	if code, m := s.call("POST", fmt.Sprintf("/api/v1/user/shield/detections/%d/request-restore", id), nil); code != 200 {
		t.Fatalf("request restore: %d %v", code, m)
	}
	// admin: list, CSV export, quarantine delete
	as := mustLoginAdmin(t, e)
	if code, m := as.call("GET", "/api/v1/admin/shield/detections?limit=10", nil); code != 200 || m["total"].(float64) != 1 {
		t.Fatalf("admin detections: %d %v", code, m)
	}
	w := e.do(e.admin, req{method: "GET", path: "/api/v1/admin/shield/detections?format=csv"}, as)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "eicar.com") || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("csv: %d %s", w.Code, w.Body.String())
	}
	code, m = as.call("GET", "/api/v1/admin/shield/quarantine", nil)
	qi, _ := m["items"].([]any)
	if code != 200 || len(qi) != 1 {
		t.Fatalf("quarantine list: %d %v", code, m)
	}
	qid := qi[0].(map[string]any)["item"].(map[string]any)["id"].(string)
	if code, m := as.call("DELETE", "/api/v1/admin/shield/quarantine/"+qid, nil); code != 200 {
		t.Fatalf("quarantine delete: %d %v", code, m)
	}
	if code, m := as.call("GET", "/api/v1/admin/shield/status", nil); code != 200 || m["notice"] == nil {
		t.Fatalf("status: %d %v", code, m)
	}
}

func TestShieldScannerDownScriptBlocked(t *testing.T) {
	e := newEnv(t)
	e.tenant("bob", "bob.test")
	_ = os.MkdirAll(filepath.Join(e.ag.homes, "bob", "public_html"), 0o755)
	fakeShieldOf(e.ag).down = true
	s := mustLogin(t, e, e.user, "bob", "")
	code, m := uploadFile(t, e, s, "shell.php", []byte("<?php echo 1;"))
	if code != 422 || m["error"] != "shield_blocked" {
		t.Fatalf("down + php: %d %v", code, m)
	}
	if _, err := os.Stat(filepath.Join(e.ag.homes, "bob", "public_html", "shell.php")); err == nil {
		t.Fatal("php placed while scanner down")
	}
	// a non-script is allowed (with a recorded warning)
	if code, m := uploadFile(t, e, s, "readme.txt", []byte("hi")); code != 200 {
		t.Fatalf("down + txt: %d %v", code, m)
	}
	var n int
	_ = e.srv.Store.DB.QueryRow(`SELECT COUNT(*) FROM shield_detections WHERE outcome='scanner_unavailable'`).Scan(&n)
	if n != 2 {
		t.Fatalf("unavailable rows: %d", n)
	}
}

func TestShieldResellerScope(t *testing.T) {
	e := newEnv(t)
	ra, rb := e.reseller("rsa"), e.reseller("rsb")
	ca, cb := e.tenant("cust1", "cust1.test"), e.tenant("cust2", "cust2.test")
	db := e.srv.Store.DB
	_, _ = db.Exec(`UPDATE users SET owner_id=? WHERE id=?`, ra, ca.ID)
	_, _ = db.Exec(`UPDATE users SET owner_id=? WHERE id=?`, rb, cb.ID)
	for i, acct := range []string{"cust1", "cust2"} {
		e.srv.storeShieldEvent(context.Background(), rpc.ShieldEvent{UID: fmt.Sprintf("x%d", i), TS: 1, Kind: "scan", Account: acct, Path: "/x",
			Outcome: "infected", QuarantineID: fmt.Sprintf("qq%d", i), Detections: []shield.Detection{{Engine: "e", Signature: "S", Severity: "critical"}}})
	}
	fakeShieldOf(e.ag).quar["qq1"] = shield.QuarantineMeta{ID: "qq1", Account: "cust2"}
	s := mustLogin(t, e, e.admin, "rsa", "")
	code, m := s.call("GET", "/api/v1/admin/shield/detections", nil)
	items, _ := m["items"].([]any)
	if code != 200 || len(items) != 1 || items[0].(map[string]any)["account"] != "cust1" {
		t.Fatalf("reseller A sees: %d %v", code, m)
	}
	if code, m := s.call("GET", fmt.Sprintf("/api/v1/admin/shield/detections?account_id=%d", cb.ID), nil); code != 200 || m["total"].(float64) != 0 {
		t.Fatalf("reseller A filter on B's account: %d %v", code, m)
	}
	code, m = s.call("GET", "/api/v1/admin/shield/quarantine", nil)
	if qi, _ := m["items"].([]any); code != 200 || len(qi) != 0 {
		t.Fatalf("reseller A quarantine: %d %v", code, m)
	}
	if code, _ := s.call("DELETE", "/api/v1/admin/shield/quarantine/qq1", nil); code != 404 {
		t.Fatalf("reseller A deletes B's item: %d", code)
	}
	if code, _ := s.call("POST", "/api/v1/admin/shield/scan", map[string]any{"account_id": cb.ID, "path": "x"}); code != 404 {
		t.Fatalf("reseller A scans B's account: %d", code)
	}
	if code, _ := s.call("POST", "/api/v1/admin/shield/quarantine/qq0/false-positive", map[string]any{"scope": "global"}); code != 403 {
		t.Fatalf("reseller global allowlist: %d", code)
	}
	// a hosting user only sees its own
	us := mustLogin(t, e, e.user, "cust2", "")
	code, m = us.call("GET", "/api/v1/user/shield/detections", nil)
	if items, _ := m["items"].([]any); code != 200 || len(items) != 1 || items[0].(map[string]any)["account"] != "cust2" {
		t.Fatalf("user sees: %d %v", code, m)
	}
	if code, _ := us.call("POST", "/api/v1/user/shield/detections/1/request-restore", nil); code != 404 {
		t.Fatalf("user requests restore of another account's detection: %d", code)
	}
}
