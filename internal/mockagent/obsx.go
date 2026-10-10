//go:build dev

// SPDX-License-Identifier: Apache-2.0

package mockagent

import (
	"sync"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/obsx"
)

// mockObsx answers the obsx probes for the dev/test mock agent. Health
// checks are all reported as unsupported "simulated by the mock agent" so
// nothing looks like a real system; the FIM scan returns an in-memory file
// set that tests can change with SetFIMEntries.

var (
	obsxMu  sync.Mutex
	obsxFIM = map[*Mock][]obsx.FIMEntry{}
)

// SetFIMEntries replaces the simulated FIM scan result.
func (m *Mock) SetFIMEntries(e []obsx.FIMEntry) {
	obsxMu.Lock()
	obsxFIM[m] = append([]obsx.FIMEntry{}, e...)
	obsxMu.Unlock()
}

func (m *Mock) mockObsx(method string) any {
	switch method {
	case rpc.MObsxFIMScan:
		obsxMu.Lock()
		defer obsxMu.Unlock()
		e, ok := obsxFIM[m]
		if !ok {
			e = []obsx.FIMEntry{{Path: "/etc/bpanel/bpanel.toml", Mode: obsx.FIMHash, SHA256: "0000000000000000000000000000000000000000000000000000000000000000", Size: 10}}
		}
		return rpc.ObsxFIMResult{Entries: append([]obsx.FIMEntry{}, e...), Missing: []string{}, Errors: []string{}, Reason: mockWhy}
	default:
		why := mockWhy
		var cs []obsx.HealthCheck
		for _, id := range []string{"reboot_required", "time_sync", "smart", "raid", "log_rotation", "failed_units"} {
			cs = append(cs, obsx.HealthCheck{ID: id, Status: obsx.HUnsupported, Reason: why})
		}
		return rpc.ObsxHealth{Checks: cs, Disks: []rpc.ObsxDisk{{Mount: "/", Total: 100 << 30, Used: 40 << 30, UsedPct: 40, Inodes: 1000000, InodesUsed: 100000, InodePct: 10}}, Reason: why}
	}
}
