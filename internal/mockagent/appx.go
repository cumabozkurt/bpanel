//go:build dev

// SPDX-License-Identifier: Apache-2.0

package mockagent

// Dev-mode answers for the v0.4 appx methods: inputs are validated with the
// real internal/appx code; app state lives in memory, nothing is run or
// downloaded.

import (
	"sync"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/appx"
)

var mockAppx = struct {
	sync.Mutex
	active map[int64]string
	maint  map[string]bool
}{active: map[int64]string{}, maint: map[string]bool{}}

func appxCode(err error) error {
	if e, ok := err.(*appx.Error); ok {
		return &rpc.Error{Code: e.Code, Message: e.Msg}
	}
	return err
}

// IsAppxMethod reports whether mockAppxCall answers method.
func IsAppxMethod(method string) bool {
	switch method {
	case rpc.MAppxRuntimes, rpc.MAppxAppApply, rpc.MAppxAppRemove, rpc.MAppxAppCtl, rpc.MAppxAppLogs, rpc.MAppxAppDeps,
		rpc.MAppxInstall, rpc.MAppxWP, rpc.MAppxWPCLIInstall:
		return true
	}
	return false
}

func mockAppxCall(method string, params any) (any, error) {
	mockAppx.Lock()
	defer mockAppx.Unlock()
	switch method {
	case rpc.MAppxRuntimes:
		return rpc.AppxRuntimesResult{Runtimes: []rpc.AppxRuntime{{Runtime: "node", Version: "22.11.0", Path: "/usr/bin/node"},
			{Runtime: "python", Version: "3.12.3", Path: "/usr/bin/python3"}}, Systemd: true, WPCLI: false, PHPCLI: true}, nil
	case rpc.MAppxAppApply:
		var p rpc.AppxAppApplyParams
		if err := conv(params, &p); err != nil {
			return nil, err
		}
		a := p.App
		if err := a.Validate(); err != nil {
			return nil, appxCode(err)
		}
		for _, d := range p.Domains {
			if _, err := appx.RenderProxy(d.Proxies); err != nil {
				return nil, appxCode(err)
			}
		}
		return rpc.AppxAppResult{Status: "applied", Systemd: true, Unit: appx.UnitName(a.ID), Wired: len(p.Domains) > 0}, nil
	case rpc.MAppxAppRemove:
		var p rpc.AppxAppRef
		_ = conv(params, &p)
		delete(mockAppx.active, p.ID)
		return rpc.AppxAppResult{Status: "removed", Systemd: true, Unit: appx.UnitName(p.ID)}, nil
	case rpc.MAppxAppCtl:
		var p rpc.AppxAppRef
		_ = conv(params, &p)
		switch p.Action {
		case "start", "restart":
			mockAppx.active[p.ID] = "active"
		case "stop":
			mockAppx.active[p.ID] = "inactive"
		}
		st := mockAppx.active[p.ID]
		if st == "" {
			st = "inactive"
		}
		pid := 0
		if st == "active" {
			pid = 4242
		}
		return rpc.AppxCtlResult{Active: st, Sub: map[string]string{"active": "running", "inactive": "dead"}[st], PID: pid}, nil
	case rpc.MAppxAppLogs:
		return rpc.AppxOutput{Output: "2026-10-10T12:00:00+0000 dev bpanel-app: (dev mode: no journal)\n"}, nil
	case rpc.MAppxAppDeps:
		return rpc.AppxOutput{Output: "(dev mode: dependencies are not installed)\n"}, nil
	case rpc.MAppxInstall:
		var p rpc.AppxInstallParams
		if err := conv(params, &p); err != nil {
			return nil, err
		}
		c, ok := appx.Find(p.App)
		if !ok || !c.Enabled {
			return nil, &rpc.Error{Code: "appx_app_unavailable"}
		}
		if _, err := appx.CleanRel(p.Dest); err != nil {
			return nil, appxCode(err)
		}
		cfg := false
		if c.ID == "wordpress" {
			if _, err := appx.RenderWPConfig(p.DB); err != nil {
				return nil, appxCode(err)
			}
			cfg = true
		}
		return rpc.AppxInstallResult{Version: c.Version, Files: 1, Config: cfg}, nil
	case rpc.MAppxWP:
		var p rpc.AppxWPParams
		_ = conv(params, &p)
		switch p.Action {
		case "maintenance_on":
			mockAppx.maint[p.User+"/"+p.Path] = true
		case "maintenance_off":
			delete(mockAppx.maint, p.User+"/"+p.Path)
		case "core_update":
			return nil, &rpc.Error{Code: "appx_wpcli_missing", Message: "WP-CLI is not installed (dev mode)"}
		}
		wp, _ := appx.Find("wordpress")
		return rpc.AppxWPResult{Version: wp.Version, Maintenance: mockAppx.maint[p.User+"/"+p.Path]}, nil
	case rpc.MAppxWPCLIInstall:
		return nil, &rpc.Error{Code: "appx_unsupported", Message: "dev mode: nothing is downloaded"}
	}
	return nil, &rpc.Error{Code: "unknown_method"}
}
