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
	// login shells set by isolationSSHApply (v1.1)
	loginShell    = "/bin/bash"
	noLoginShell  = "/usr/sbin/nologin"
	setLoginShell = func(ctx context.Context, user, shell string) error {
		_, err := run(ctx, nil, "usermod", "--shell", shell, "--", user)
		return err
	}
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
	for _, u := range append(append([]string{}, p.Users...), p.Shell...) {
		if err := isolationUser(a, u); err != nil {
			return res, err
		}
	}
	jailed := map[string]bool{}
	for _, u := range p.Users {
		jailed[u] = true
	}
	for _, u := range p.Shell {
		if jailed[u] {
			return res, errf("invalid_params", "%s is both jailed and granted a shell", u)
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
		return res, a.syncLoginShells(ctx, p)
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
	if err := a.syncLoginShells(ctx, p); err != nil {
		return res, err
	}
	return res, nil
}

// syncLoginShells gives accounts with shell access a real login shell and
// puts nologin back for jailed ones (only when it differs). A jailed account
// keeps working over SFTP: internal-sftp does not run the login shell.
func (a *Agent) syncLoginShells(ctx context.Context, p rpc.IsolationSSHApply) error {
	want := map[string]string{}
	jailShell := noLoginShell
	if p.Mode == isolation.SSHModeCage {
		jailShell = loginShell // sshd runs the cage ForceCommand through the login shell
	}
	for _, u := range p.Users {
		want[u] = jailShell
	}
	for _, u := range p.Shell {
		want[u] = loginShell
	}
	for u, sh := range want {
		e, err := a.managedHome(u)
		if err != nil {
			return err
		}
		if e.shell == sh || (sh == noLoginShell && !termShells[e.shell]) {
			continue
		}
		if err := setLoginShell(ctx, u, sh); err != nil {
			return errf("isolation_failed", "set login shell of %s: %v", u, err)
		}
	}
	return nil
}
