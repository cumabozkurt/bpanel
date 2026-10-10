// SPDX-License-Identifier: Apache-2.0

package agent

// v0.4 adminx: server update status / apply for Update Preferences.
// Read-only status runs `apt list --upgradable` or `dnf check-update
// [--security]` with a timeout; reboot-required comes from
// /var/run/reboot-required (Debian/Ubuntu) or `needs-restarting -r` (EL).
// Apply runs only when the admin triggers it (the API wraps it in a job).
// Missing tools answer not_installed / unsupported, never a fake success.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// Overridable in tests.
var (
	updRebootFile    = "/var/run/reboot-required"
	updLookPath      = exec.LookPath
	updStatusTimeout = 90 * time.Second
	updApplyTimeout  = 45 * time.Minute
)

func init() {
	gateExempt[rpc.MUpdatesStatus] = "server (read-only package manager probe)"
	gateExempt[rpc.MUpdatesApply] = "server packages; admin-triggered job only"
}

func (a *Agent) updatesRoutes() map[string]handler {
	return map[string]handler{
		rpc.MUpdatesStatus: bind(a.updatesStatus),
		rpc.MUpdatesApply:  bind(a.updatesApply),
	}
}

// updRun runs argv with a timeout and a fixed C locale; it returns stdout and
// the exit code (-1 when the program could not run or timed out).
func updRun(ctx context.Context, timeout time.Duration, argv ...string) (string, int, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive"}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if cctx.Err() != nil {
		return out.String(), -1, errors.New("command timed out")
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out.String(), ee.ExitCode(), nil
	}
	if err != nil {
		return out.String(), -1, err
	}
	return out.String(), 0, nil
}

func updManager() (string, string) {
	if p, err := updLookPath("apt-get"); err == nil {
		return "apt", p
	}
	if p, err := updLookPath("dnf"); err == nil {
		return "dnf", p
	}
	return "", ""
}

// parseAptUpgradable parses `apt list --upgradable` output.
func parseAptUpgradable(out string) (names []string, security int) {
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "Listing") || strings.HasPrefix(l, "WARNING") || !strings.Contains(l, "/") {
			continue
		}
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		name, suites, _ := strings.Cut(f[0], "/")
		names = append(names, name)
		if strings.Contains(suites, "-security") {
			security++
		}
	}
	return names, security
}

// parseDNFCheckUpdate parses `dnf -q check-update` output (name.arch version repo).
func parseDNFCheckUpdate(out string) []string {
	var names []string
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) != 3 || strings.HasPrefix(l, " ") || strings.EqualFold(f[0], "Obsoleting") {
			continue
		}
		names = append(names, f[0])
	}
	return names
}

func capList(n []string) []string {
	sort.Strings(n)
	if len(n) > 200 {
		n = n[:200]
	}
	return n
}

func (a *Agent) rebootRequired(ctx context.Context, mgr string) (required, known bool) {
	if _, err := os.Stat(updRebootFile); err == nil {
		return true, true
	}
	if mgr == "apt" {
		return false, true // update-notifier-common writes the flag file
	}
	if p, err := updLookPath("needs-restarting"); err == nil {
		_, code, err := updRun(ctx, 60*time.Second, p, "-r")
		if err == nil && (code == 0 || code == 1) {
			return code == 1, true
		}
	}
	return false, false
}

func (a *Agent) updatesStatus(ctx context.Context, p rpc.UpdatesStatusReq) (rpc.UpdatesStatus, error) {
	res := rpc.UpdatesStatus{CheckedAt: time.Now().Unix()}
	mgr, bin := updManager()
	res.Manager = mgr
	switch mgr {
	case "":
		res.Status, res.Reason = "not_installed", "neither apt-get nor dnf found"
		return res, nil
	case "apt":
		aptBin, err := updLookPath("apt")
		if err != nil {
			res.Status, res.Reason = "not_installed", "apt not found"
			return res, nil
		}
		out, code, err := updRun(ctx, updStatusTimeout, aptBin, "list", "--upgradable")
		if err != nil || code != 0 {
			res.Status, res.Reason = "error", "apt list --upgradable failed"
			return res, nil
		}
		names, sec := parseAptUpgradable(out)
		res.Upgradable, res.Security, res.Packages = len(names), sec, capList(names)
	case "dnf":
		out, code, err := updRun(ctx, updStatusTimeout, bin, "-q", "check-update")
		if err != nil || (code != 0 && code != 100) {
			res.Status, res.Reason = "error", "dnf check-update failed"
			return res, nil
		}
		names := parseDNFCheckUpdate(out)
		res.Upgradable, res.Packages = len(names), capList(names)
		if sout, scode, serr := updRun(ctx, updStatusTimeout, bin, "-q", "check-update", "--security"); serr == nil && (scode == 0 || scode == 100) {
			res.Security = len(parseDNFCheckUpdate(sout))
		}
	}
	res.RebootRequired, res.RebootKnown = a.rebootRequired(ctx, mgr)
	res.Status = "ok"
	return res, nil
}

func (a *Agent) updatesApply(ctx context.Context, p rpc.UpdatesApply) (rpc.UpdatesApplyResult, error) {
	res := rpc.UpdatesApplyResult{}
	mgr, bin := updManager()
	res.Manager = mgr
	defer a.lock("system-updates")()
	switch mgr {
	case "":
		res.Status, res.Reason = "not_installed", "neither apt-get nor dnf found"
		return res, nil
	case "apt":
		if p.SecurityOnly {
			ua, err := updLookPath("unattended-upgrade")
			if err != nil {
				res.Status, res.Reason = "unsupported", "security-only updates on apt need the unattended-upgrades package (free, Debian/Ubuntu)"
				return res, nil
			}
			if _, code, err := updRun(ctx, updApplyTimeout, ua); err != nil || code != 0 {
				return res, errf("updates_failed", "unattended-upgrade exited %d", code)
			}
		} else {
			if _, code, err := updRun(ctx, updApplyTimeout, bin, "update"); err != nil || code != 0 {
				return res, errf("updates_failed", "apt-get update exited %d", code)
			}
			if _, code, err := updRun(ctx, updApplyTimeout, bin, "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "upgrade"); err != nil || code != 0 {
				return res, errf("updates_failed", "apt-get upgrade exited %d", code)
			}
		}
	case "dnf":
		argv := []string{bin, "-y", "upgrade"}
		if p.SecurityOnly {
			argv = append(argv, "--security")
		}
		if _, code, err := updRun(ctx, updApplyTimeout, argv...); err != nil || code != 0 {
			return res, errf("updates_failed", "dnf upgrade exited %d", code)
		}
	}
	res.Status = "applied"
	res.RebootRequired, _ = a.rebootRequired(ctx, mgr)
	if res.RebootRequired && p.AutoReboot {
		if sd, err := updLookPath("shutdown"); err == nil {
			if _, code, err := updRun(ctx, 30*time.Second, sd, "-r", "+2", "BPanel: rebooting after updates"); err == nil && code == 0 {
				res.RebootStarted = true
			}
		}
	}
	return res, nil
}
