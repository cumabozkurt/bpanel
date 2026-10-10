// SPDX-License-Identifier: Apache-2.0

package isolation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	ok := Profile{CPUPercent: 100, CPUWeight: 100, MemMaxMB: 512, MemHighMB: 448, TasksMax: 64}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []Profile{{CPUPercent: -1}, {MemMaxMB: 256, MemHighMB: 512}, {TasksMax: 2}, {CPUWeight: 20000}, {MemMaxMB: 4}}
	for i, p := range bad {
		if p.Validate() == nil {
			t.Errorf("case %d accepted: %+v", i, p)
		}
	}
}

func TestRenderSlice(t *testing.T) {
	p := Profile{CPUPercent: 150, CPUWeight: 50, MemMaxMB: 512, MemHighMB: 400, IOReadBps: 10485760, IOWriteIOPS: 200, TasksMax: 100}
	s, err := RenderSlice("alice", p, "/dev/sda")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CPUQuota=150%", "CPUWeight=50", "MemoryMax=512M", "MemoryHigh=400M",
		"IOReadBandwidthMax=/dev/sda 10485760", "IOWriteIOPSMax=/dev/sda 200", "TasksMax=100", "[Slice]"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	if strings.Contains(s, "IOWriteBandwidthMax") {
		t.Error("unset limit rendered")
	}
	for _, u := range []string{"Alice", "a", "root/../x", "al ice", "1abc", "abcdefghijklmnopq"} {
		if _, err := RenderSlice(u, p, "/dev/sda"); err == nil {
			t.Errorf("user %q accepted", u)
		}
	}
	if _, err := RenderSlice("alice", p, "/dev/sda\nExecStart=/bin/sh"); err == nil {
		t.Error("newline in io path accepted")
	}
	if _, err := RenderSlice("alice", Profile{MemMaxMB: 64}, ""); err != nil {
		t.Errorf("no io limits should not need io path: %v", err)
	}
}

func TestRenderFPMService(t *testing.T) {
	s, err := RenderFPMService("bob", "8.3")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Slice=bpanel-u-bob.slice", "ProtectSystem=strict", "ProtectHome=tmpfs",
		"BindPaths=/home/bob", "PrivateTmp=yes", "ProtectProc=invisible", "PrivateDevices=yes",
		"ReadWritePaths=/run/php /var/spool/postfix/maildrop", "NoNewPrivileges=no", "/usr/sbin/php-fpm8.3"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	if _, err := RenderFPMService("bob", "8.3;rm"); err == nil {
		t.Error("bad version accepted")
	}
	if FPMServiceName("bob", "8.3") != "bpanel-php-bob-8.3.service" {
		t.Error("service name")
	}
}

const fxCPU = "usage_usec 123456\nuser_usec 100000\nsystem_usec 23456\nnr_periods 10\nnr_throttled 3\nthrottled_usec 999\n"
const fxMemEvents = "low 0\nhigh 7\nmax 3\noom 1\noom_kill 2\noom_group_kill 0\n"
const fxIO = "8:0 rbytes=4096 wbytes=8192 rios=1 wios=2 dbytes=0 dios=0\n259:0 rbytes=100 wbytes=50 rios=1 wios=1 dbytes=0 dios=0\n"

func TestParsers(t *testing.T) {
	if ParseKV(fxCPU)["usage_usec"] != 123456 {
		t.Error("cpu.stat")
	}
	m := ParseKV(fxMemEvents)
	if m["high"] != 7 || m["max"] != 3 || m["oom_kill"] != 2 {
		t.Errorf("memory.events %v", m)
	}
	r, w := ParseIOStat(fxIO)
	if r != 4196 || w != 8242 {
		t.Errorf("io.stat r=%d w=%d", r, w)
	}
	if ParseUintFile("max\n") != -1 || ParseUintFile("42\n") != 42 {
		t.Error("single value")
	}
}

func TestReadStatsFixtureDir(t *testing.T) {
	d := t.TempDir()
	files := map[string]string{"cpu.stat": fxCPU, "memory.events": fxMemEvents, "io.stat": fxIO,
		"memory.current": "1048576\n", "pids.current": "5\n", "pids.max": "max\n"}
	for k, v := range files {
		os.WriteFile(filepath.Join(d, k), []byte(v), 0o644)
	}
	st, err := ReadStats(d)
	if err != nil {
		t.Fatal(err)
	}
	if st.CPUUsageUsec != 123456 || st.MemCurrent != 1048576 || st.OOMKills != 2 || st.MemHighEvents != 7 ||
		st.IORBytes != 4196 || st.PidsCurrent != 5 || st.PidsMax != -1 || len(st.Missing) != 0 {
		t.Errorf("%+v", st)
	}
	os.Remove(filepath.Join(d, "io.stat"))
	st, _ = ReadStats(d)
	if len(st.Missing) != 1 || st.Missing[0] != "io.stat" {
		t.Errorf("missing %v", st.Missing)
	}
	if _, err := ReadStats(filepath.Join(d, "nope")); err == nil {
		t.Error("absent dir")
	}
}

func TestProbe(t *testing.T) {
	d := t.TempDir()
	if r := Probe(d); r.CgroupV2 || r.Supported || r.Reason == "" {
		t.Errorf("%+v", r)
	}
	os.WriteFile(filepath.Join(d, "cgroup.controllers"), []byte("cpuset cpu memory pids\n"), 0o644)
	if r := Probe(d); !r.CgroupV2 || r.Supported || len(r.Missing) != 1 || r.Missing[0] != "io" {
		t.Errorf("%+v", r)
	}
	os.WriteFile(filepath.Join(d, "cgroup.controllers"), []byte("cpuset cpu io memory pids\n"), 0o644)
	if r := Probe(d); !r.Supported {
		t.Errorf("%+v", r)
	}
}
