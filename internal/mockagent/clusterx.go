//go:build dev

// SPDX-License-Identifier: Apache-2.0

package mockagent

// Dev-mode answers for the v0.4 clusterx methods. Inputs are validated with
// the real internal/clusterx code; nothing is written or restarted. The
// cluster answer says "mock" in its reason so the UI never mistakes it for a
// real PowerDNS reload.

import (
	"errors"
	"sync"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/clusterx"
)

var mockPlugins = struct {
	sync.Mutex
	files map[string]int
}{files: map[string]int{}}

func clusterxCode(err error) error {
	var e *clusterx.Error
	if errors.As(err, &e) {
		return &rpc.Error{Code: e.Code, Message: e.Msg}
	}
	return err
}

func mockClusterx(method string, params any) (any, error) {
	switch method {
	case rpc.MClusterApply:
		var p rpc.ClusterApplyReq
		if err := conv(params, &p); err != nil {
			return nil, err
		}
		if _, err := clusterx.RenderPdnsConf(p.Secondaries); err != nil {
			return nil, clusterxCode(err)
		}
		n := 0
		if len(p.Secondaries) > 0 {
			n = len(p.Zones)
		}
		return rpc.ClusterApplyResult{Status: "ok", Reason: "mock agent: nothing written", ConfPath: "/etc/powerdns/pdns.d/bpanel-cluster.conf", Notified: n}, nil
	case rpc.MPluginInstall:
		var p rpc.PluginInstallReq
		if err := conv(params, &p); err != nil {
			return nil, err
		}
		files, m, err := clusterx.Load(p.Archive)
		if err != nil {
			return nil, clusterxCode(err)
		}
		if m.Name != p.Name {
			return nil, &rpc.Error{Code: "plugin_invalid_manifest", Message: "manifest name does not match"}
		}
		mockPlugins.Lock()
		mockPlugins.files[m.Name] = len(files)
		mockPlugins.Unlock()
		return rpc.PluginResult{Path: "/usr/local/bpanel/plugins/" + m.Name, Files: len(files)}, nil
	case rpc.MPluginRemove:
		var p rpc.PluginRemoveReq
		if err := conv(params, &p); err != nil {
			return nil, err
		}
		if !clusterx.ValidName(p.Name) {
			return nil, &rpc.Error{Code: "plugin_invalid_manifest", Message: "invalid plugin name"}
		}
		mockPlugins.Lock()
		delete(mockPlugins.files, p.Name)
		mockPlugins.Unlock()
		return rpc.Empty{}, nil
	}
	return nil, &rpc.Error{Code: "unknown_method", Message: method}
}
