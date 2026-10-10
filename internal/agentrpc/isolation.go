// SPDX-License-Identifier: Apache-2.0

package agentrpc

import "github.com/cumabozkurt/bpanel/internal/isolation"

// Per-account resource isolation (v0.4): one systemd slice per account,
// bpanel-u-<user>.slice under bpanel.slice.
const (
	MIsolationApply  = "isolation.apply"  // write the account slice unit (+ daemon-reload)
	MIsolationStatus = "isolation.status" // cgroup v2 probe (+ slice file state for one account)
	MIsolationStats  = "isolation.stats"  // cgroup counters of one account slice
)

// IsolationApply sets an account's limits. IOPath is the block device the IO
// limits apply to; required only when the profile has IO limits.
type IsolationApply struct {
	User    string            `json:"user"`
	Profile isolation.Profile `json:"profile"`
	IOPath  string            `json:"io_path,omitempty"`
}

// IsolationApplyResult: Status is "applied" (unit written and systemd
// reloaded) or "applied_files_only" (unit written, systemd is not PID 1 or
// the agent runs with no_systemd, so nothing is enforced yet).
type IsolationApplyResult struct {
	Status string `json:"status"`
	Unit   string `json:"unit"`
	Reason string `json:"reason,omitempty"`
}

// IsolationUser names one account (optional for status).
type IsolationUser struct {
	User string `json:"user"`
}

// IsolationStatusResult is the kernel probe plus, for a named account,
// whether its slice unit file and its cgroup exist.
type IsolationStatusResult struct {
	Probe         isolation.ProbeResult `json:"probe"`
	SystemdPID1   bool                  `json:"systemd_pid1"`
	User          string                `json:"user,omitempty"`
	UnitPresent   bool                  `json:"unit_present,omitempty"`
	CgroupPresent bool                  `json:"cgroup_present,omitempty"`
}

// IsolationStatsResult: Status is "ok" or "not_running" (the slice cgroup
// does not exist: no process of the account is running or systemd never
// created it) or "unsupported" (no cgroup v2).
type IsolationStatsResult struct {
	Status string          `json:"status"`
	Reason string          `json:"reason,omitempty"`
	Stats  isolation.Stats `json:"stats"`
}
