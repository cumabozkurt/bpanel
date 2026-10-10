//go:build dev

// SPDX-License-Identifier: Apache-2.0

package mockagent

import (
	"context"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

func TestMockDevx(t *testing.T) {
	m := New(t.TempDir())
	ctx := context.Background()
	var info rpc.GitInfo
	if err := m.Call(ctx, rpc.MGitClone, rpc.GitClone{User: "alice", Path: "repositories/x", URL: "file:///etc"}, &info); err == nil {
		t.Fatal("file:// accepted")
	}
	if err := m.Call(ctx, rpc.MGitInit, rpc.GitRepoRef{User: "alice", Path: "repositories/x"}, &info); err != nil || info.Branch != "main" {
		t.Fatal(err)
	}
	if err := m.Call(ctx, rpc.MGitInfo, rpc.GitRepoRef{User: "alice", Path: "repositories/x"}, &info); err != nil {
		t.Fatal(err)
	}
	if err := m.Call(ctx, rpc.MTermOpen, rpc.TermOpen{User: "alice"}, nil); err == nil {
		t.Fatal("mock terminal must be unsupported")
	}
	var tr rpc.TraceRouteResult
	if err := m.Call(ctx, rpc.MTraceRoute, rpc.TraceRoute{Host: "example.com"}, &tr); err != nil || tr.Status != "not_installed" {
		t.Fatal(tr, err)
	}
}
