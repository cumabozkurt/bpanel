// SPDX-License-Identifier: Apache-2.0

package agentrpc

import "github.com/cumabozkurt/bpanel/internal/obsx"

// v0.4 obsx: file-integrity scan of a fixed allowlist and OS health probes.
const (
	MObsxFIMScan  = "obsx.fim.scan"  // fingerprint the agent's FIM allowlist (no params from the API)
	MObsxOSHealth = "obsx.os.health" // reboot-required, time sync, SMART, RAID, logrotate, failed units, disk/inode
)

type ObsxFIMReq struct{}

type ObsxFIMResult struct {
	Entries []obsx.FIMEntry `json:"entries"`
	Missing []string        `json:"missing"`
	Errors  []string        `json:"errors"`
	Reason  string          `json:"reason,omitempty"`
}

type ObsxHealthReq struct{}

// ObsxDisk is usage of one mount point.
type ObsxDisk struct {
	Mount      string  `json:"mount"`
	Total      uint64  `json:"total"`
	Used       uint64  `json:"used"`
	UsedPct    float64 `json:"used_pct"`
	Inodes     uint64  `json:"inodes"`
	InodesUsed uint64  `json:"inodes_used"`
	InodePct   float64 `json:"inode_pct"`
}

type ObsxHealth struct {
	Checks []obsx.HealthCheck `json:"checks"`
	Disks  []ObsxDisk         `json:"disks"`
	Reason string             `json:"reason,omitempty"`
}
