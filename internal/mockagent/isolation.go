//go:build dev

// SPDX-License-Identifier: Apache-2.0

package mockagent

import (
	"math/rand/v2"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/isolation"
)

var mockStart = time.Now()

// mockIsolation answers isolation.* in dev mode. Nothing is enforced: apply
// reports applied_files_only, stats are synthetic but monotonic.
func mockIsolation(method string, params any) any {
	var p rpc.IsolationUser
	conv(params, &p)
	switch method {
	case rpc.MIsolationApply:
		var a rpc.IsolationApply
		conv(params, &a)
		return rpc.IsolationApplyResult{Status: "applied_files_only", Unit: isolation.SliceName(a.User), Reason: "mock agent: nothing is enforced"}
	case rpc.MIsolationStatus:
		return rpc.IsolationStatusResult{Probe: isolation.ProbeResult{CgroupV2: true, Controllers: []string{"cpu", "io", "memory", "pids"}, Supported: true},
			User: p.User}
	}
	el := uint64(time.Since(mockStart).Seconds())
	return rpc.IsolationStatsResult{Status: "ok", Stats: isolation.Stats{
		CPUUsageUsec: el * 50000, MemCurrent: uint64(64<<20 + rand.IntN(32<<20)), IORBytes: el * 4096, IOWBytes: el * 2048,
		PidsCurrent: uint64(3 + rand.IntN(5)), PidsMax: -1}}
}
