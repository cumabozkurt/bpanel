// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"os"
	"path/filepath"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/isolation"
)

// Overridable in tests.
var (
	isolationUnitDir    = "/etc/systemd/system"
	isolationCgroupRoot = "/sys/fs/cgroup"
	// systemdPID1 reports whether systemd is the init system (sd_booted(3):
	// /run/systemd/system exists).
	systemdPID1 = func() bool {
		fi, err := os.Stat("/run/systemd/system")
		return err == nil && fi.IsDir()
	}
)

func init() {
	accountField[rpc.MIsolationApply] = struct {
		key      string
		optional bool
	}{"user", false}
	accountField[rpc.MIsolationStats] = struct {
		key      string
		optional bool
	}{"user", false}
	accountField[rpc.MIsolationStatus] = struct {
		key      string
		optional bool
	}{"user", true} // empty user = server-level kernel probe
}

func (a *Agent) isolationRoutes() map[string]handler {
	m := map[string]handler{
		rpc.MIsolationApply:  bind(a.isolationApply),
		rpc.MIsolationStatus: bind(a.isolationStatus),
		rpc.MIsolationStats:  bind(a.isolationStats),
	}
	mergeRoutes(m, a.isolationRoutesB())
	return m
}

func isolationUser(a *Agent, user string) error {
	if !isolation.UserRe.MatchString(user) {
		return errf("invalid_user", "account name does not match ^[a-z][a-z0-9]{1,15}$")
	}
	_, err := a.managedHome(user) // defence in depth; the gate checked it too
	return err
}

func (a *Agent) isolationApply(ctx context.Context, p rpc.IsolationApply) (rpc.IsolationApplyResult, error) {
	var res rpc.IsolationApplyResult
	if err := isolationUser(a, p.User); err != nil {
		return res, err
	}
	unit, err := isolation.RenderSlice(p.User, p.Profile, p.IOPath)
	if err != nil {
		return res, errf("invalid_limit", "%v", err)
	}
	res.Unit = isolation.SliceName(p.User)
	path := filepath.Join(isolationUnitDir, res.Unit)
	if err := writeAtomic(path, []byte(unit), 0o644, -1, -1); err != nil {
		return res, errf("isolation_failed", "write unit: %v", err)
	}
	if a.Cfg.NoSystemd || !systemdPID1() {
		res.Status = "applied_files_only"
		res.Reason = "systemd is not PID 1 (or agent runs with no_systemd): unit written, limits not enforced"
		return res, nil
	}
	if _, err := run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return res, errf("isolation_failed", "daemon-reload: %v", err)
	}
	res.Status = "applied"
	return res, nil
}

func (a *Agent) isolationStatus(_ context.Context, p rpc.IsolationUser) (rpc.IsolationStatusResult, error) {
	res := rpc.IsolationStatusResult{Probe: isolation.Probe(isolationCgroupRoot), SystemdPID1: systemdPID1()}
	if p.User == "" {
		return res, nil
	}
	if err := isolationUser(a, p.User); err != nil {
		return res, err
	}
	res.User = p.User
	if _, err := os.Stat(filepath.Join(isolationUnitDir, isolation.SliceName(p.User))); err == nil {
		res.UnitPresent = true
	}
	if fi, err := os.Stat(isolation.CgroupDir(isolationCgroupRoot, p.User)); err == nil && fi.IsDir() {
		res.CgroupPresent = true
	}
	return res, nil
}

func (a *Agent) isolationStats(_ context.Context, p rpc.IsolationUser) (rpc.IsolationStatsResult, error) {
	var res rpc.IsolationStatsResult
	if err := isolationUser(a, p.User); err != nil {
		return res, err
	}
	if pr := isolation.Probe(isolationCgroupRoot); !pr.CgroupV2 {
		res.Status, res.Reason = "unsupported", pr.Reason
		return res, nil
	}
	st, err := isolation.ReadStats(isolation.CgroupDir(isolationCgroupRoot, p.User))
	if err != nil {
		res.Status, res.Reason = "not_running", "slice cgroup does not exist"
		return res, nil
	}
	res.Status, res.Stats = "ok", st
	return res, nil
}

// mergeRoutes adds module routes to the dispatch table; a duplicate method
// name is a programming error.
func mergeRoutes(dst, src map[string]handler) {
	for k, h := range src {
		if _, dup := dst[k]; dup {
			panic("agent: duplicate method " + k)
		}
		dst[k] = h
	}
}
