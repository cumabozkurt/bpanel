//go:build dev

// SPDX-License-Identifier: Apache-2.0

package mockagent

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

func stage(t *testing.T, m *Mock, user, id, content string) {
	t.Helper()
	b64 := base64.StdEncoding.EncodeToString([]byte(content))
	if err := m.Call(context.Background(), rpc.MShieldStageChunk, rpc.ShieldStageChunk{User: user, ID: id, Content: b64}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestMockShieldUpload(t *testing.T) {
	m := New(t.TempDir())
	ctx := context.Background()
	os.MkdirAll(filepath.Join(m.Base, "alice", "public_html"), 0o755)
	stage(t, m, "alice", "s1", "<?php echo 1;")
	var res rpc.ShieldStageCommitResult
	if err := m.Call(ctx, rpc.MShieldStageCommit, rpc.ShieldStageCommit{User: "alice", ID: "s1", Path: "public_html/a.php", Name: "a.php"}, &res); err != nil {
		t.Fatal(err)
	}
	if !res.Placed || res.Outcome != "clean" {
		t.Fatalf("want placed clean, got %+v", res)
	}
	if b, err := os.ReadFile(filepath.Join(m.Base, "alice", "public_html", "a.php")); err != nil || string(b) != "<?php echo 1;" {
		t.Fatalf("placed file: %q %v", b, err)
	}

	stage(t, m, "alice", "s2", "x")
	res = rpc.ShieldStageCommitResult{}
	if err := m.Call(ctx, rpc.MShieldStageCommit, rpc.ShieldStageCommit{User: "alice", ID: "s2", Path: "public_html/eicar.com", Name: "eicar.com"}, &res); err != nil {
		t.Fatal(err)
	}
	if res.Placed || res.Action != "block" || len(res.Detections) != 1 {
		t.Fatalf("eicar must be blocked: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(m.Base, "alice", "public_html", "eicar.com")); err == nil {
		t.Fatal("blocked file was placed")
	}

	// path escape refused
	stage(t, m, "alice", "s3", "x")
	if err := m.Call(ctx, rpc.MShieldStageCommit, rpc.ShieldStageCommit{User: "alice", ID: "s3", Path: "../bob/x"}, nil); err == nil {
		t.Fatal("escape accepted")
	}
	// bad offset refused, abort clears
	stage(t, m, "alice", "s4", "ab")
	if err := m.Call(ctx, rpc.MShieldStageChunk, rpc.ShieldStageChunk{User: "alice", ID: "s4", Offset: 9, Content: "eA=="}, nil); err == nil {
		t.Fatal("bad offset accepted")
	}
	if err := m.Call(ctx, rpc.MShieldStageAbort, rpc.ShieldStageRef{User: "alice", ID: "s4"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Call(ctx, rpc.MShieldStageCommit, rpc.ShieldStageCommit{User: "alice", ID: "s4", Path: "x"}, nil); err == nil {
		t.Fatal("aborted stage committed")
	}

	var st rpc.ShieldStatusResult
	if err := m.Call(ctx, rpc.MShieldStatus, struct{}{}, &st); err != nil || st.Realtime != "unsupported" || len(st.Engines) != 1 {
		t.Fatalf("status %+v %v", st, err)
	}
	var q rpc.ShieldQListResult
	if err := m.Call(ctx, rpc.MShieldQList, rpc.ShieldQListReq{}, &q); err != nil || len(q.Items) != 0 {
		t.Fatalf("qlist %+v %v", q, err)
	}
	var ev rpc.ShieldEventsResult
	if err := m.Call(ctx, rpc.MShieldEvents, rpc.ShieldEventsReq{Since: 5}, &ev); err != nil || len(ev.Events) != 0 || ev.LastSeq != 5 {
		t.Fatalf("events %+v %v", ev, err)
	}
}
