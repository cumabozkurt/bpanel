//go:build dev

// SPDX-License-Identifier: Apache-2.0

package mockagent

import (
	"context"
	"errors"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/webx"
)

func TestMockWebx(t *testing.T) {
	m := New(t.TempDir())
	vh := rpc.Vhost{User: "demo", Domain: "demo.test", DocRoot: "public_html"}
	var out rpc.WebxApplyResult
	if err := m.Call(context.Background(), rpc.MWebxApply, rpc.WebxApplyParams{User: "demo", Vhost: vh,
		Config: webx.Config{Domain: "demo.test", Deny: []string{"192.0.2.1"}}}, &out); err != nil || out.Status != "applied" || !out.Wired {
		t.Fatalf("%+v %v", out, err)
	}
	err := m.Call(context.Background(), rpc.MWebxApply, rpc.WebxApplyParams{User: "demo", Vhost: vh,
		Config: webx.Config{Domain: "demo.test", Deny: []string{"1.2.3.4;\nallow all"}}}, &out)
	var re *rpc.Error
	if !errors.As(err, &re) || re.Code != "webx_invalid_ip" {
		t.Fatalf("injection: %v", err)
	}
}
