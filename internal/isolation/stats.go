// SPDX-License-Identifier: Apache-2.0

package isolation

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Stats are the cgroup v2 counters for one account slice. Counters that the
// kernel did not expose stay zero; Missing lists the files that were absent.
type Stats struct {
	CPUUsageUsec  uint64   `json:"cpu_usage_usec"`
	MemCurrent    uint64   `json:"mem_current"`
	MemHighEvents uint64   `json:"mem_high_events"`
	MemMaxEvents  uint64   `json:"mem_max_events"`
	OOMKills      uint64   `json:"oom_kills"`
	IORBytes      uint64   `json:"io_rbytes"`
	IOWBytes      uint64   `json:"io_wbytes"`
	PidsCurrent   uint64   `json:"pids_current"`
	PidsMax       int64    `json:"pids_max"` // -1 = "max" (unlimited)
	Missing       []string `json:"missing,omitempty"`
}

// ParseKV parses "key value" lines (cpu.stat, memory.events).
func ParseKV(s string) map[string]uint64 {
	m := map[string]uint64{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 {
			continue
		}
		if v, err := strconv.ParseUint(f[1], 10, 64); err == nil {
			m[f[0]] = v
		}
	}
	return m
}

// ParseIOStat sums rbytes/wbytes over all devices in io.stat
// ("8:0 rbytes=1 wbytes=2 rios=3 wios=4 dbytes=0 dios=0").
func ParseIOStat(s string) (r, w uint64) {
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		for _, kv := range strings.Fields(sc.Text()) {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				continue
			}
			switch k {
			case "rbytes":
				r += n
			case "wbytes":
				w += n
			}
		}
	}
	return r, w
}

// ParseUintFile parses a single-number file; "max" returns -1.
func ParseUintFile(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "max" {
		return -1
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// ReadStats reads the counters of the cgroup directory dir.
func ReadStats(dir string) (Stats, error) {
	var st Stats
	if fi, err := os.Stat(dir); err != nil {
		return st, err
	} else if !fi.IsDir() {
		return st, os.ErrNotExist
	}
	read := func(name string) (string, bool) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			st.Missing = append(st.Missing, name)
			return "", false
		}
		return string(b), true
	}
	if s, ok := read("cpu.stat"); ok {
		st.CPUUsageUsec = ParseKV(s)["usage_usec"]
	}
	if s, ok := read("memory.current"); ok {
		if n := ParseUintFile(s); n > 0 {
			st.MemCurrent = uint64(n)
		}
	}
	if s, ok := read("memory.events"); ok {
		m := ParseKV(s)
		st.MemHighEvents, st.MemMaxEvents, st.OOMKills = m["high"], m["max"], m["oom_kill"]
	}
	if s, ok := read("io.stat"); ok {
		st.IORBytes, st.IOWBytes = ParseIOStat(s)
	}
	if s, ok := read("pids.current"); ok {
		if n := ParseUintFile(s); n > 0 {
			st.PidsCurrent = uint64(n)
		}
	}
	if s, ok := read("pids.max"); ok {
		st.PidsMax = ParseUintFile(s)
	}
	return st, nil
}

// ProbeResult says whether per-account isolation can be enforced here.
type ProbeResult struct {
	CgroupV2    bool     `json:"cgroup_v2"`
	Controllers []string `json:"controllers"`
	Missing     []string `json:"missing,omitempty"`
	Supported   bool     `json:"supported"`
	Reason      string   `json:"reason,omitempty"`
}

// Required controllers for slices.
var Required = []string{"cpu", "memory", "io", "pids"}

// Probe inspects the cgroup v2 hierarchy mounted at root (normally
// /sys/fs/cgroup).
func Probe(root string) ProbeResult {
	var r ProbeResult
	b, err := os.ReadFile(filepath.Join(root, "cgroup.controllers"))
	if err != nil {
		r.Reason = "cgroup v2 unified hierarchy not mounted at " + root
		return r
	}
	r.CgroupV2 = true
	r.Controllers = strings.Fields(string(b))
	have := map[string]bool{}
	for _, c := range r.Controllers {
		have[c] = true
	}
	for _, c := range Required {
		if !have[c] {
			r.Missing = append(r.Missing, c)
		}
	}
	if len(r.Missing) > 0 {
		r.Reason = "controllers not available: " + strings.Join(r.Missing, ",")
		return r
	}
	r.Supported = true
	return r
}
