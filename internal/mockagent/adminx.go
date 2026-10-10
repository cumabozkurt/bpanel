//go:build dev

package mockagent

import (
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// mockUpdates answers the v0.4 adminx update methods with a fixed, clearly
// mock state (manager "apt (mock)"); apply never touches the host.
func mockUpdates(method string, params any) any {
	if method == rpc.MUpdatesApply {
		var p rpc.UpdatesApply
		conv(params, &p)
		return rpc.UpdatesApplyResult{Status: "applied", Manager: "apt (mock)", RebootRequired: true, RebootStarted: false,
			Reason: "mock agent: nothing was installed"}
	}
	return rpc.UpdatesStatus{Status: "ok", Manager: "apt (mock)", Upgradable: 3, Security: 1,
		Packages: []string{"curl", "openssl", "vim"}, RebootRequired: true, RebootKnown: true, CheckedAt: time.Now().Unix()}
}
