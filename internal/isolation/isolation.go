// SPDX-License-Identifier: Apache-2.0

// Package isolation renders per-account systemd resource slices and
// sandboxed PHP-FPM services, reads cgroup v2 usage counters and probes
// whether the running kernel supports the controllers BPANEL needs.
//
// Layout (v0.4 design): every hosting account gets
// bpanel-u-<user>.slice, a child of bpanel.slice (systemd derives the
// parent from the dash-separated name: bpanel-u-alice.slice lives in
// bpanel.slice/bpanel-u.slice/). All per-account processes (PHP-FPM, cron,
// SSH) are placed in that slice so one account cannot starve the others.
package isolation

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// UserRe is the accepted account name syntax. It is deliberately narrower
// than POSIX so a name can be embedded in unit names and paths unescaped.
var UserRe = regexp.MustCompile(`^[a-z][a-z0-9]{1,15}$`)

var phpVerRe = regexp.MustCompile(`^[0-9]\.[0-9]{1,2}$`)

// ioPathRe: an absolute block device or mount path, no spaces/control chars.
var ioPathRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,200}$`)

// Profile is one resource limit set. Zero means "no limit" for every field.
type Profile struct {
	CPUPercent  int   `json:"cpu_percent"`   // CPUQuota, 100 = one core; max 6400
	CPUWeight   int   `json:"cpu_weight"`    // 1..10000 (systemd default 100)
	MemMaxMB    int64 `json:"mem_max_mb"`    // hard limit (OOM kill inside the slice)
	MemHighMB   int64 `json:"mem_high_mb"`   // throttle/reclaim threshold, must be <= MemMaxMB
	IOReadBps   int64 `json:"io_read_bps"`   // bytes/s
	IOWriteBps  int64 `json:"io_write_bps"`  // bytes/s
	IOReadIOPS  int64 `json:"io_read_iops"`  // ops/s
	IOWriteIOPS int64 `json:"io_write_iops"` // ops/s
	TasksMax    int   `json:"tasks_max"`     // pids.max
	InodeLimit  int64 `json:"inode_limit"`   // enforced by setquota, not the slice
	DiskMB      int64 `json:"disk_mb"`       // enforced by setquota, not the slice
	EntryProcs  int   `json:"entry_procs"`   // concurrent PHP-FPM children (pm.max_children)
}

// Validate rejects negative and out-of-range values.
func (p Profile) Validate() error {
	var errs []string
	neg := func(name string, v int64) {
		if v < 0 {
			errs = append(errs, name+" is negative")
		}
	}
	neg("cpu_percent", int64(p.CPUPercent))
	neg("cpu_weight", int64(p.CPUWeight))
	neg("mem_max_mb", p.MemMaxMB)
	neg("mem_high_mb", p.MemHighMB)
	neg("io_read_bps", p.IOReadBps)
	neg("io_write_bps", p.IOWriteBps)
	neg("io_read_iops", p.IOReadIOPS)
	neg("io_write_iops", p.IOWriteIOPS)
	neg("tasks_max", int64(p.TasksMax))
	neg("inode_limit", p.InodeLimit)
	neg("disk_mb", p.DiskMB)
	neg("entry_procs", int64(p.EntryProcs))
	if p.CPUPercent > 6400 {
		errs = append(errs, "cpu_percent above 6400")
	}
	if p.CPUWeight > 10000 {
		errs = append(errs, "cpu_weight above 10000")
	}
	if p.MemMaxMB > 0 && p.MemMaxMB < 16 {
		errs = append(errs, "mem_max_mb below 16")
	}
	if p.MemMaxMB > 0 && p.MemHighMB > p.MemMaxMB {
		errs = append(errs, "mem_high_mb above mem_max_mb")
	}
	if p.TasksMax > 0 && p.TasksMax < 4 {
		errs = append(errs, "tasks_max below 4")
	}
	if p.TasksMax > 4194304 {
		errs = append(errs, "tasks_max too large")
	}
	if p.EntryProcs > 1000 {
		errs = append(errs, "entry_procs above 1000")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// HasIO reports whether any IO limit is set.
func (p Profile) HasIO() bool {
	return p.IOReadBps > 0 || p.IOWriteBps > 0 || p.IOReadIOPS > 0 || p.IOWriteIOPS > 0
}

// SliceName returns bpanel-u-<user>.slice.
func SliceName(user string) string { return "bpanel-u-" + user + ".slice" }

// FPMServiceName returns bpanel-php-<user>-<ver>.service (ver "8.3").
func FPMServiceName(user, phpVer string) string {
	return "bpanel-php-" + user + "-" + phpVer + ".service"
}

// CgroupDir is where systemd places the slice in the unified hierarchy.
func CgroupDir(root, user string) string {
	return root + "/bpanel.slice/bpanel-u.slice/" + SliceName(user)
}

// RenderSlice renders the slice unit. ioPath is the block device (or a path
// on the filesystem, which systemd resolves to its device) the IO limits
// apply to; it is required when the profile has IO limits.
func RenderSlice(user string, p Profile, ioPath string) (string, error) {
	if !UserRe.MatchString(user) {
		return "", fmt.Errorf("invalid user %q", user)
	}
	if err := p.Validate(); err != nil {
		return "", err
	}
	if p.HasIO() && !ioPathRe.MatchString(ioPath) {
		return "", fmt.Errorf("io limits need a valid device path")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by BOZKURT PANEL - do not edit\n[Unit]\nDescription=BPANEL account %s\nBefore=slices.target\n\n[Slice]\n", user)
	b.WriteString("CPUAccounting=yes\nMemoryAccounting=yes\nIOAccounting=yes\nTasksAccounting=yes\n")
	if p.CPUPercent > 0 {
		fmt.Fprintf(&b, "CPUQuota=%d%%\n", p.CPUPercent)
	}
	if p.CPUWeight > 0 {
		fmt.Fprintf(&b, "CPUWeight=%d\n", p.CPUWeight)
	}
	if p.MemHighMB > 0 {
		fmt.Fprintf(&b, "MemoryHigh=%dM\n", p.MemHighMB)
	}
	if p.MemMaxMB > 0 {
		fmt.Fprintf(&b, "MemoryMax=%dM\nMemorySwapMax=0\n", p.MemMaxMB)
	}
	if p.IOReadBps > 0 {
		fmt.Fprintf(&b, "IOReadBandwidthMax=%s %d\n", ioPath, p.IOReadBps)
	}
	if p.IOWriteBps > 0 {
		fmt.Fprintf(&b, "IOWriteBandwidthMax=%s %d\n", ioPath, p.IOWriteBps)
	}
	if p.IOReadIOPS > 0 {
		fmt.Fprintf(&b, "IOReadIOPSMax=%s %d\n", ioPath, p.IOReadIOPS)
	}
	if p.IOWriteIOPS > 0 {
		fmt.Fprintf(&b, "IOWriteIOPSMax=%s %d\n", ioPath, p.IOWriteIOPS)
	}
	if p.TasksMax > 0 {
		fmt.Fprintf(&b, "TasksMax=%d\n", p.TasksMax)
	}
	return b.String(), nil
}

// RenderFPMService renders a per-account PHP-FPM master running in the
// account's slice with a private filesystem view.
//
// NoNewPrivileges is left OFF on purpose: Postfix's sendmail(1), which PHP's
// mail() invokes, hands mail to the setgid "postdrop" binary; with
// NoNewPrivileges=yes the setgid bit is ignored and every PHP mail() fails.
// The pool itself still runs as the unprivileged account user and the
// filesystem is read-only outside the bind paths below.
func RenderFPMService(user, phpVer string) (string, error) {
	if !UserRe.MatchString(user) {
		return "", fmt.Errorf("invalid user %q", user)
	}
	if !phpVerRe.MatchString(phpVer) {
		return "", fmt.Errorf("invalid php version %q", phpVer)
	}
	home := "/home/" + user
	conf := fmt.Sprintf("/etc/bpanel/php-fpm/%s/%s.conf", phpVer, user)
	return fmt.Sprintf(`# Managed by BOZKURT PANEL - do not edit
[Unit]
Description=BPANEL PHP %[2]s FPM for %[1]s
After=network.target

[Service]
Type=notify
Slice=%[3]s
ExecStart=/usr/sbin/php-fpm%[2]s --nodaemonize --fpm-config %[4]s
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure
RuntimeDirectory=php/%[1]s
RuntimeDirectoryPreserve=no
ProtectSystem=strict
ProtectHome=tmpfs
BindPaths=%[5]s
ReadWritePaths=/run/php /var/spool/postfix/maildrop
PrivateTmp=yes
PrivateDevices=yes
ProtectProc=invisible
ProcSubset=pid
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=no
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
# NoNewPrivileges=no: postdrop (setgid) must work for PHP mail().
NoNewPrivileges=no

[Install]
WantedBy=multi-user.target
`, user, phpVer, SliceName(user), conf, home), nil
}
