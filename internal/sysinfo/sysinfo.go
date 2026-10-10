// Package sysinfo reads host metrics from /proc and statfs; no privileges needed.
package sysinfo

import (
	"bufio"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/distro"
)

func Collect() agentrpc.SysInfo {
	var s agentrpc.SysInfo
	s.Hostname, _ = os.Hostname()
	if m, err := distro.OSRelease("/"); err == nil {
		s.OS = m["PRETTY_NAME"]
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		s.Kernel = strings.TrimSpace(string(b))
	}
	s.Arch = runtime.GOARCH
	s.CPUs = runtime.NumCPU()
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		f := strings.Fields(string(b))
		if len(f) > 0 {
			v, _ := strconv.ParseFloat(f[0], 64)
			s.UptimeSec = int64(v)
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		for i := 0; i < 3 && i < len(f); i++ {
			s.Load[i], _ = strconv.ParseFloat(f[i], 64)
		}
	}
	if f, err := os.Open("/proc/cpuinfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), ":")
			if ok && (strings.TrimSpace(k) == "model name" || strings.TrimSpace(k) == "Model") {
				s.CPUModel = strings.TrimSpace(v)
				break
			}
		}
		f.Close()
	}
	mem := map[string]uint64{}
	if f, err := os.Open("/proc/meminfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fl := strings.Fields(sc.Text())
			if len(fl) >= 2 {
				v, _ := strconv.ParseUint(fl[1], 10, 64)
				mem[strings.TrimSuffix(fl[0], ":")] = v * 1024
			}
		}
		f.Close()
	}
	s.MemTotal = mem["MemTotal"]
	if mem["MemAvailable"] <= s.MemTotal {
		s.MemUsed = s.MemTotal - mem["MemAvailable"]
	}
	s.SwapTotal = mem["SwapTotal"]
	if mem["SwapFree"] <= s.SwapTotal {
		s.SwapUsed = s.SwapTotal - mem["SwapFree"]
	}
	var st syscall.Statfs_t
	if syscall.Statfs("/", &st) == nil {
		s.DiskTotal = st.Blocks * uint64(st.Bsize)
		s.DiskUsed = (st.Blocks - st.Bfree) * uint64(st.Bsize)
	}
	s.CPUPercent = cpuPercent()
	if ents, err := os.ReadDir("/proc"); err == nil {
		for _, e := range ents {
			if _, err := strconv.Atoi(e.Name()); err == nil {
				s.Processes++
			}
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			if ipn.IP.To4() != nil {
				s.IPv4 = append(s.IPv4, ipn.IP.String())
			} else {
				s.IPv6 = append(s.IPv6, ipn.IP.String())
			}
		}
	}
	return s
}

func cpuTimes() (idle, total uint64) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	line, _, _ := strings.Cut(string(b), "\n")
	f := strings.Fields(line)
	for i, v := range f[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		total += n
		if i == 3 || i == 4 {
			idle += n
		}
	}
	return
}

func cpuPercent() float64 {
	i1, t1 := cpuTimes()
	time.Sleep(200 * time.Millisecond)
	i2, t2 := cpuTimes()
	if t2 <= t1 {
		return 0
	}
	p := 100 * (1 - float64(i2-i1)/float64(t2-t1))
	return float64(int(p*10)) / 10
}

// PrimaryIPv4 returns the first non-loopback IPv4 address or "".
func PrimaryIPv4() string {
	s := Collect()
	if len(s.IPv4) > 0 {
		return s.IPv4[0]
	}
	return ""
}
