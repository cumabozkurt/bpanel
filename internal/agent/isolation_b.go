// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"os"
	"strconv"
	"strings"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/isolation"
)

// Overridable in tests.
var (
	hidepidMountinfo = "/proc/self/mountinfo"
	hidepidFstabPath = "/etc/fstab"
	sshJailConf      = isolation.SSHJailConf
	sshdBin          = "sshd"
)

func init() {
	gateExempt[rpc.MIsolationHidepidStatus] = "server (read-only probe)"
	gateExempt[rpc.MIsolationSSHApply] = "server file; every listed user is checked with managedHome in the handler"
}

func (a *Agent) isolationRoutesB() map[string]handler {
	return map[string]handler{
		rpc.MIsolationHidepidStatus: bind(a.isolationHidepidStatus),
		rpc.MIsolationSSHApply:      bind(a.isolationSSHApply),
	}
}

func groupGID(name string) int {
	b, _ := os.ReadFile(groupFile)
	for _, l := range strings.Split(string(b), "\n") {
		p := strings.Split(l, ":")
		if len(p) > 2 && p[0] == name {
			if n, err := strconv.Atoi(p[2]); err == nil {
				return n
			}
		}
	}
	return -1
}

func (a *Agent) isolationHidepidStatus(_ context.Context, _ struct{}) (rpc.HidepidStatus, error) {
	r := rpc.HidepidStatus{Group: isolation.ProcGroup, GroupGID: groupGID(isolation.ProcGroup), GID: -1}
	mi, err := os.ReadFile(hidepidMountinfo)
	if err != nil {
		r.Status, r.Reason = "unsupported", "cannot read mountinfo"
		return r, nil
	}
	m := isolation.ParseProcMount(string(mi))
	r.Hidepid, r.GID = m.Hidepid, m.GID
	if fs, err := os.ReadFile(hidepidFstabPath); err == nil && r.GroupGID > 0 {
		r.FstabConfigured = isolation.ValidateFstab(string(fs), r.GroupGID) == nil
	}
	switch {
	case !m.Found:
		r.Status, r.Reason = "unsupported", "/proc is not mounted as proc"
	case m.Hidden() && r.GroupGID > 0 && m.GID == r.GroupGID:
		r.Status = "active"
	case r.FstabConfigured:
		r.Status, r.Reason = "configured_reboot_pending", "fstab has hidepid=2 but the live /proc mount does not (remount or reboot)"
	default:
		r.Status = "not_configured"
		if m.Hidden() {
			r.Reason = "hidepid is on but the exempt gid is not " + isolation.ProcGroup
		}
	}
	return r, nil
}

// isolationSSHApply replaces the jail snippet, validates the whole sshd
// configuration with `sshd -t`, and restores the previous snippet (or removes
// the new one) when validation fails, so a bad render can never lock
// operators out at the next sshd reload. Reload is left to service.action.
func (a *Agent) isolationSSHApply(ctx context.Context, p rpc.IsolationSSHApply) (rpc.IsolationSSHResult, error) {
	res := rpc.IsolationSSHResult{File: sshJailConf, Users: len(p.Users)}
	if len(p.Users) > 5000 {
		return res, errf("invalid_params", "too many users")
	}
	for _, u := range p.Users {
		if err := isolationUser(a, u); err != nil {
			return res, err
		}
	}
	conf, err := isolation.RenderSSHJail(p.Users, p.Mode)
	if err != nil {
		return res, errf("invalid_params", "%v", err)
	}
	prev, prevErr := os.ReadFile(sshJailConf)
	if err := writeAtomic(sshJailConf, []byte(conf), 0o644, -1, -1); err != nil {
		return res, errf("isolation_failed", "write sshd snippet: %v", err)
	}
	if !have(sshdBin) {
		res.Status, res.Reason = "applied_unvalidated", "sshd is not installed; snippet written but not validated"
		return res, nil
	}
	if _, err := run(ctx, nil, sshdBin, "-t"); err != nil {
		if prevErr == nil {
			_ = writeAtomic(sshJailConf, prev, 0o644, -1, -1)
		} else {
			_ = os.Remove(sshJailConf)
		}
		return res, errf("isolation_failed", "sshd -t rejected the jail config; previous config restored")
	}
	res.Status = "applied"
	return res, nil
}
