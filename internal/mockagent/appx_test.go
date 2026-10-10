//go:build dev

// SPDX-License-Identifier: Apache-2.0

package mockagent

import (
	"context"
	"errors"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/appx"
)

func TestMockAppx(t *testing.T) {
	m := New(t.TempDir())
	ctx := context.Background()
	var rt rpc.AppxRuntimesResult
	if err := m.Call(ctx, rpc.MAppxRuntimes, struct{}{}, &rt); err != nil || len(rt.Runtimes) == 0 {
		t.Fatal(rt, err)
	}
	var res rpc.AppxAppResult
	app := appx.App{ID: 1, User: "demo", Name: "api", Runtime: "node", Version: "22", Root: "apps/api", Startup: "index.js", Port: 30000}
	if err := m.Call(ctx, rpc.MAppxAppApply, rpc.AppxAppApplyParams{User: "demo", App: app}, &res); err != nil || res.Status != "applied" {
		t.Fatal(res, err)
	}
	app.Root = "../etc"
	err := m.Call(ctx, rpc.MAppxAppApply, rpc.AppxAppApplyParams{User: "demo", App: app}, &res)
	var re *rpc.Error
	if !errors.As(err, &re) || re.Code != "appx_invalid_path" {
		t.Fatal(err)
	}
	var st rpc.AppxCtlResult
	if err := m.Call(ctx, rpc.MAppxAppCtl, rpc.AppxAppRef{User: "demo", ID: 1, Action: "start"}, &st); err != nil || st.Active != "active" {
		t.Fatal(st, err)
	}
	var in rpc.AppxInstallResult
	if err := m.Call(ctx, rpc.MAppxInstall, rpc.AppxInstallParams{User: "demo", App: "wordpress", Dest: "public_html",
		DB: appx.WPConfig{DBName: "demo_wp", DBUser: "demo_wp", DBPassword: "Xx-123456"}}, &in); err != nil || !in.Config {
		t.Fatal(in, err)
	}
	var wp rpc.AppxWPResult
	if err := m.Call(ctx, rpc.MAppxWP, rpc.AppxWPParams{User: "demo", Path: "public_html", Action: "maintenance_on"}, &wp); err != nil || !wp.Maintenance {
		t.Fatal(wp, err)
	}
}
