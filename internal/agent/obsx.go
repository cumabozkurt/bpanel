// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/obsx"
)

// v0.4 obsx. Read-only server probes. Every external program (timedatectl,
// chronyc, smartctl [GPL-2.0, separate process], systemctl, logrotate) is run
// argv-only with a timeout; a missing program is reported as not_installed,
// a missing kernel interface as unsupported. Nothing is pretended.
//
// The FIM scan takes no parameters from the API: the target list is the
// fixed allowlist obsx.DefaultFIMTargets plus the panel binaries, so the API
// cannot turn it into an arbitrary file reader. /etc/shadow and /etc/passwd
// are fingerprinted by metadata only (never read).

var (
	obsxRoot          = "" // test prefix for the probed paths
	obsxHave          = have
	obsxRun           = run
	obsxTimeout       = 20 * time.Second
	obsxPanelBins     = []string{"/usr/local/bin/bpanel", "/usr/local/bin/bpanel-agent", "/usr/bin/bpanel", "/usr/bin/bpanel-agent", "/opt/bpanel/bin"}
	obsxMounts        = []string{"/", "/home", "/var"}
	obsxFIMTargetsFor = func() []obsx.FIMTarget { return obsx.DefaultFIMTargets(obsxPanelBins) }
)

func init() {
	gateExempt[rpc.MObsxFIMScan] = "server (read-only fingerprint of a fixed allowlist)"
	gateExempt[rpc.MObsxOSHealth] = "server (read-only health probes)"
}

func (a *Agent) obsxRoutes() map[string]handler {
	return map[string]handler{
		rpc.MObsxFIMScan:  bind(a.obsxFIMScan),
		rpc.MObsxOSHealth: bind(a.obsxOSHealth),
	}
}

func obsxCmd(ctx context.Context, argv ...string) (string, error) {
	c, cancel := context.WithTimeout(ctx, obsxTimeout)
	defer cancel()
	return obsxRun(c, nil, argv...)
}

func (a *Agent) obsxFIMScan(ctx context.Context, _ rpc.ObsxFIMReq) (rpc.ObsxFIMResult, error) {
	ts := obsxFIMTargetsFor()
	if obsxRoot != "" {
		for i := range ts {
			ts[i].Path = filepath.Join(obsxRoot, ts[i].Path)
		}
	}
	e, m, errs := obsx.Scan(ts)
	if e == nil {
		e = []obsx.FIMEntry{}
	}
	return rpc.ObsxFIMResult{Entries: e, Missing: m, Errors: errs}, nil
}

func pth(p string) string { return filepath.Join(obsxRoot, p) }

func (a *Agent) obsxOSHealth(ctx context.Context, _ rpc.ObsxHealthReq) (rpc.ObsxHealth, error) {
	var out rpc.ObsxHealth
	out.Checks = []obsx.HealthCheck{
		obsxReboot(), obsxTime(ctx), obsxSmart(ctx), obsxRaid(), obsxLogrotate(), obsxFailedUnits(ctx),
	}
	for _, m := range obsxMounts {
		var st syscall.Statfs_t
		if err := syscall.Statfs(pth(m), &st); err != nil {
			continue
		}
		d := rpc.ObsxDisk{Mount: m, Total: st.Blocks * uint64(st.Bsize), Inodes: st.Files}
		d.Used = (st.Blocks - st.Bfree) * uint64(st.Bsize)
		d.InodesUsed = st.Files - st.Ffree
		if d.Total > 0 {
			d.UsedPct = float64(d.Used) * 100 / float64(d.Total)
		}
		if d.Inodes > 0 {
			d.InodePct = float64(d.InodesUsed) * 100 / float64(d.Inodes)
		}
		dup := false
		for _, x := range out.Disks {
			if x.Total == d.Total && x.Used == d.Used && x.Inodes == d.Inodes {
				dup = true // same filesystem mounted at both points
			}
		}
		if !dup {
			out.Disks = append(out.Disks, d)
		}
	}
	return out, nil
}

func obsxReboot() obsx.HealthCheck {
	c := obsx.HealthCheck{ID: "reboot_required", Status: obsx.HOK}
	if _, err := os.Stat(pth("/var/run/reboot-required")); err == nil {
		c.Status, c.Reason = obsx.HWarn, "/var/run/reboot-required present"
		if b, err := os.ReadFile(pth("/var/run/reboot-required.pkgs")); err == nil {
			c.Details = strings.Fields(string(b))
		}
		return c
	}
	if _, err := os.Stat(pth("/etc/debian_version")); err != nil && !obsxHave("needs-restarting") {
		return obsx.HealthCheck{ID: "reboot_required", Status: obsx.HUnknown, Reason: "no reboot-required marker on this distribution and needs-restarting not installed"}
	}
	return c
}

func systemdRunning() bool {
	_, err := os.Stat(pth("/run/systemd/system"))
	return err == nil
}

func obsxTime(ctx context.Context) obsx.HealthCheck {
	if obsxHave("chronyc") {
		if o, err := obsxCmd(ctx, "chronyc", "tracking"); err == nil {
			return obsx.ParseChrony(o)
		}
	}
	if !obsxHave("timedatectl") {
		return obsx.HealthCheck{ID: "time_sync", Status: obsx.HNotInstalled, Reason: "neither chronyc nor timedatectl is installed"}
	}
	if !systemdRunning() {
		return obsx.HealthCheck{ID: "time_sync", Status: obsx.HUnsupported, Reason: "systemd is not PID 1 (timedatectl unavailable)"}
	}
	o, err := obsxCmd(ctx, "timedatectl", "show")
	if err != nil {
		return obsx.HealthCheck{ID: "time_sync", Status: obsx.HUnknown, Reason: "timedatectl show failed"}
	}
	return obsx.ParseTimedatectl(o)
}

func obsxSmart(ctx context.Context) obsx.HealthCheck {
	if !obsxHave("smartctl") {
		return obsx.HealthCheck{ID: "smart", Status: obsx.HNotInstalled, Reason: "smartmontools (smartctl) is not installed"}
	}
	ents, _ := os.ReadDir(pth("/sys/block"))
	c := obsx.HealthCheck{ID: "smart", Status: obsx.HOK}
	n := 0
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "dm-") || strings.HasPrefix(name, "md") || strings.HasPrefix(name, "zram") {
			continue
		}
		if !isSafeName(name) {
			continue
		}
		n++
		o, _ := obsxCmd(ctx, "smartctl", "-H", "/dev/"+name) // non-zero exit carries status bits; parse output
		st, line := obsx.ParseSmart("/dev/"+name, o)
		c.Details = append(c.Details, line)
		if st == obsx.HFail {
			c.Status, c.Reason = obsx.HFail, "SMART health check failed"
		} else if st == obsx.HUnknown && c.Status == obsx.HOK {
			c.Status = obsx.HUnknown
			c.Reason = "SMART not available on some devices (virtual disk?)"
		}
	}
	if n == 0 {
		return obsx.HealthCheck{ID: "smart", Status: obsx.HUnsupported, Reason: "no physical block devices found"}
	}
	return c
}

func isSafeName(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return s != ""
}

func obsxRaid() obsx.HealthCheck {
	b, err := os.ReadFile(pth("/proc/mdstat"))
	if err != nil {
		return obsx.HealthCheck{ID: "raid", Status: obsx.HUnsupported, Reason: "/proc/mdstat not present (md driver not loaded)"}
	}
	return obsx.ParseMdstat(string(b))
}

func obsxLogrotate() obsx.HealthCheck {
	if !obsxHave("logrotate") {
		return obsx.HealthCheck{ID: "log_rotation", Status: obsx.HNotInstalled, Reason: "logrotate is not installed"}
	}
	for _, p := range []string{"/var/lib/logrotate/status", "/var/lib/logrotate/logrotate.status", "/var/lib/logrotate.status"} {
		fi, err := os.Stat(pth(p))
		if err != nil {
			continue
		}
		age := time.Since(fi.ModTime())
		if age > 48*time.Hour {
			return obsx.HealthCheck{ID: "log_rotation", Status: obsx.HWarn, Reason: "logrotate has not run for " + age.Truncate(time.Hour).String(), Details: []string{p}}
		}
		return obsx.HealthCheck{ID: "log_rotation", Status: obsx.HOK, Details: []string{p + " " + fi.ModTime().UTC().Format(time.RFC3339)}}
	}
	return obsx.HealthCheck{ID: "log_rotation", Status: obsx.HUnknown, Reason: "logrotate state file not found (never ran?)"}
}

func obsxFailedUnits(ctx context.Context) obsx.HealthCheck {
	if !obsxHave("systemctl") {
		return obsx.HealthCheck{ID: "failed_units", Status: obsx.HNotInstalled, Reason: "systemctl not installed"}
	}
	if !systemdRunning() {
		return obsx.HealthCheck{ID: "failed_units", Status: obsx.HUnsupported, Reason: "systemd is not PID 1"}
	}
	o, err := obsxCmd(ctx, "systemctl", "--failed", "--no-legend", "--plain", "--no-pager")
	if err != nil {
		return obsx.HealthCheck{ID: "failed_units", Status: obsx.HUnknown, Reason: "systemctl --failed failed"}
	}
	return obsx.ParseFailedUnits(o)
}
