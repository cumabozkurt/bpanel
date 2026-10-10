// SPDX-License-Identifier: Apache-2.0

package isolation

import (
	"fmt"
	"strconv"
	"strings"
)

// ProcGroup is the group exempt from hidepid=2: the panel (bpanel), the apps
// runner, and monitoring agents must still see every process.
const ProcGroup = "bpanel-proc"

// FstabMarker tags the line the installer owns.
const FstabMarker = "# bpanel: hidepid (managed)"

// ProcFstabLine is the /etc/fstab entry mounting /proc with hidepid=2.
func ProcFstabLine(gid int) (string, error) {
	if gid <= 0 || gid > 1<<31-2 {
		return "", fmt.Errorf("invalid gid %d", gid)
	}
	return fmt.Sprintf("proc /proc proc defaults,nosuid,nodev,noexec,hidepid=2,gid=%d 0 0", gid), nil
}

// RenderFstab returns fstab with exactly one /proc entry (ours). Any other
// /proc entry is commented out (kept, prefixed "#bpanel-replaced: ").
// changed=false when the content is already as wanted, which makes re-runs
// no-ops. Every other line is preserved byte for byte.
func RenderFstab(existing string, gid int) (out string, changed bool, err error) {
	want, err := ProcFstabLine(gid)
	if err != nil {
		return "", false, err
	}
	lines := strings.Split(strings.TrimRight(existing, "\n"), "\n")
	if existing == "" {
		lines = nil
	}
	var res []string
	placed := false
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if strings.TrimSpace(l) == FstabMarker {
			continue // re-emitted next to our line
		}
		f := strings.Fields(l)
		if len(f) >= 2 && !strings.HasPrefix(f[0], "#") && f[1] == "/proc" {
			if !placed && l == want {
				res = append(res, FstabMarker, want)
				placed = true
				continue
			}
			res = append(res, "#bpanel-replaced: "+l)
			continue
		}
		res = append(res, l)
	}
	if !placed {
		res = append(res, FstabMarker, want)
	}
	out = strings.Join(res, "\n") + "\n"
	return out, out != existing, nil
}

// ValidateFstab is a structural check run before the file is installed:
// every entry has 4-6 fields, numeric dump/pass, and exactly one /proc entry
// carrying hidepid=2 and the expected gid.
func ValidateFstab(content string, gid int) error {
	procs := 0
	for n, l := range strings.Split(content, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(t)
		if len(f) < 4 || len(f) > 6 {
			return fmt.Errorf("fstab line %d: %d fields", n+1, len(f))
		}
		for _, x := range f[4:] {
			if _, err := strconv.Atoi(x); err != nil {
				return fmt.Errorf("fstab line %d: dump/pass %q not numeric", n+1, x)
			}
		}
		if f[1] == "/proc" {
			procs++
			o := "," + f[3] + ","
			if f[2] != "proc" || !strings.Contains(o, ",hidepid=2,") || !strings.Contains(o, fmt.Sprintf(",gid=%d,", gid)) {
				return fmt.Errorf("fstab line %d: /proc entry lacks hidepid=2,gid=%d", n+1, gid)
			}
		}
	}
	if procs != 1 {
		return fmt.Errorf("fstab: %d /proc entries, want 1", procs)
	}
	return nil
}

// RemountProcArgv applies the options to the running system without a reboot.
func RemountProcArgv(gid int) []string {
	return []string{"mount", "-o", fmt.Sprintf("remount,hidepid=2,gid=%d", gid), "/proc"}
}

// ProcMount describes the live /proc mount as read from /proc/self/mountinfo.
type ProcMount struct {
	Found   bool   `json:"found"`
	Hidepid string `json:"hidepid"` // "", "0"/"off", "1"/"noaccess", "2"/"invisible", "ptraceable"
	GID     int    `json:"gid"`     // -1 when not set
}

// Hidden reports whether other users' processes are invisible.
func (m ProcMount) Hidden() bool { return m.Hidepid == "2" || m.Hidepid == "invisible" }

// ParseProcMount finds the /proc mount in mountinfo content (proc(5)); the
// super options (after " - ") carry hidepid/gid.
func ParseProcMount(mountinfo string) ProcMount {
	m := ProcMount{GID: -1}
	for _, l := range strings.Split(mountinfo, "\n") {
		parts := strings.SplitN(l, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		pre, post := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(pre) < 5 || pre[4] != "/proc" || len(post) < 1 || post[0] != "proc" {
			continue
		}
		m = ProcMount{Found: true, GID: -1}
		opts := pre[5:]
		if len(post) >= 3 {
			opts = append(opts, post[2])
		}
		for _, o := range strings.Split(strings.Join(opts, ","), ",") {
			if v, ok := strings.CutPrefix(o, "hidepid="); ok {
				m.Hidepid = v
			}
			if v, ok := strings.CutPrefix(o, "gid="); ok {
				if g, err := strconv.Atoi(v); err == nil {
					m.GID = g
				}
			}
		}
	}
	return m
}
