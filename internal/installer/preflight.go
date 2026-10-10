package installer

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/cumabozkurt/bpanel/internal/sysinfo"
)

// Signs of another control panel or an already configured server.
var foreignPaths = map[string]string{
	"/usr/local/cpanel":    "cPanel",
	"/usr/local/psa":       "Plesk",
	"/usr/local/hestia":    "HestiaCP",
	"/usr/local/vesta":     "VestaCP",
	"/usr/local/CyberCP":   "CyberPanel",
	"/www/server/panel":    "aaPanel",
	"/etc/webmin":          "Webmin/Virtualmin",
	"/usr/local/ispconfig": "ISPConfig",
	"/home/clp":            "CloudPanel",
}

var foreignBins = []string{"nginx", "apache2", "httpd", "mysqld", "mariadbd", "postfix", "exim4", "named", "pdns_server", "dovecot"}

// Preflight results are also used by tests.
type Finding struct {
	Fatal bool
	Msg   string
	// Req marks a hardware/system requirement (RAM, disk, systemd), which
	// --force cannot override, as opposed to signs of a server that is not
	// fresh (R2-SYS-18: "not fresh: 10 GB free disk space required").
	Req bool
}

func (in *Installer) preflight(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New(T(in.O.Lang, "not_root"))
	}
	if !in.L.Supported() && !in.O.AllowUnsupported {
		return fmt.Errorf(T(in.O.Lang, "unsupported"), in.L.Pretty)
	}
	var fatal, req []string
	for _, f := range in.checks() {
		switch {
		case f.Fatal && f.Req:
			req = append(req, f.Msg)
		case f.Fatal:
			fatal = append(fatal, f.Msg)
		default:
			in.warn(f.Msg)
		}
	}
	if len(req) > 0 {
		return fmt.Errorf(T(in.O.Lang, "requirements"), strings.Join(req, "; "))
	}
	// Services we installed in an earlier run are not "foreign".
	if len(fatal) > 0 && !in.O.Force && !in.done("packages") {
		return fmt.Errorf(T(in.O.Lang, "not_fresh"), strings.Join(fatal, "; "))
	}
	for _, f := range fatal {
		in.warn(f)
	}
	if in.O.Hostname == "" {
		h, _ := os.Hostname()
		in.O.Hostname = h
	}
	if err := ValidHostname(in.O.Hostname); err != nil {
		return fmt.Errorf("%v (set it with --hostname panel.example.com)", err)
	}
	in.S.Hostname = in.O.Hostname
	in.S.Profile = in.O.Profile
	in.S.ServerIP = sysinfo.PrimaryIPv4()
	return nil
}

func (in *Installer) checks() []Finding {
	var out []Finding
	si := sysinfo.Collect()
	if si.MemTotal < 900<<20 {
		out = append(out, Finding{Fatal: true, Req: true, Msg: fmt.Sprintf("at least 1 GB RAM required (found %d MB)", si.MemTotal>>20)})
	} else if si.MemTotal < 1900<<20 && in.O.Profile == "full" {
		out = append(out, Finding{Fatal: false, Msg: "less than 2 GB RAM: the 'web' profile (no mail) is recommended"})
	}
	var st syscall.Statfs_t
	if syscall.Statfs("/", &st) == nil && st.Bavail*uint64(st.Bsize) < 10<<30 {
		out = append(out, Finding{Fatal: true, Req: true, Msg: fmt.Sprintf("at least 10 GB of free disk space is required on / (%.1f GB free)", float64(st.Bavail*uint64(st.Bsize))/(1<<30))})
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		out = append(out, Finding{Fatal: false, Msg: "cgroups v2 not detected: per-account CPU/memory limits will not apply"})
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil && !in.O.NoSystemd {
		out = append(out, Finding{Fatal: true, Req: true, Msg: "systemd is required"})
	}
	if b, err := os.ReadFile("/proc/1/environ"); err == nil && (strings.Contains(string(b), "container=lxc") || strings.Contains(string(b), "container=docker")) {
		out = append(out, Finding{Fatal: false, Msg: "running in a container: disk quotas and resource limits may not work"})
	}
	if !in.done("packages") {
		for p, name := range foreignPaths {
			if _, err := os.Stat(p); err == nil {
				out = append(out, Finding{Fatal: true, Msg: name + " is installed (" + p + ")"})
			}
		}
		for _, b := range foreignBins {
			if have(b) {
				out = append(out, Finding{Fatal: true, Msg: b + " is already installed"})
			}
		}
		for _, p := range RequiredPorts(in.O.Profile) {
			if p == 53 {
				// systemd-resolved's stub (127.0.0.53/54) is turned off when
				// PowerDNS is configured (SYS-2); anything else is a conflict.
				if other := otherListeners(53); len(other) > 0 {
					out = append(out, Finding{Fatal: true, Msg: "port 53 is in use by " + strings.Join(other, ", ")})
				} else if len(stubListeners()) > 0 {
					out = append(out, Finding{Fatal: false, Msg: "systemd-resolved listens on 127.0.0.53:53; its stub listener will be turned off so PowerDNS can answer on port 53"})
				}
				continue
			}
			if !portFree(p) {
				out = append(out, Finding{Fatal: true, Msg: fmt.Sprintf("port %d is in use", p)})
			}
		}
	}
	h := in.O.Hostname
	if h == "" {
		h, _ = os.Hostname()
	}
	if strings.Count(h, ".") < 2 {
		out = append(out, Finding{Fatal: false, Msg: fmt.Sprintf("hostname %q is not a fully qualified name like panel.example.com; the hostname certificate will be self-signed", h)})
	} else if addrs, err := net.LookupHost(h); err != nil || len(addrs) == 0 {
		out = append(out, Finding{Fatal: false, Msg: fmt.Sprintf("hostname %s does not resolve yet; AutoSSL for the panel will be retried later", h)})
	}
	return out
}

func portFree(p int) bool {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// listeners parses /proc/net/{tcp,tcp6,udp,udp6} and returns the local
// addresses listening on port (TCP LISTEN or bound UDP sockets).
func listeners(port int) []string {
	hexPort := fmt.Sprintf(":%04X", port)
	seen := map[string]bool{}
	var out []string
	for _, f := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, err := os.ReadFile("/proc/net/" + f)
		if err != nil {
			continue
		}
		for i, l := range strings.Split(string(b), "\n") {
			fl := strings.Fields(l)
			if i == 0 || len(fl) < 4 || !strings.HasSuffix(fl[1], hexPort) {
				continue
			}
			if strings.HasPrefix(f, "tcp") && fl[3] != "0A" { // LISTEN
				continue
			}
			if strings.HasPrefix(f, "udp") && fl[3] != "07" { // unconnected
				continue
			}
			a := procAddr(strings.TrimSuffix(fl[1], hexPort))
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}

// procAddr turns a /proc/net hex address into text.
func procAddr(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		return h
	}
	// /proc/net prints each 32-bit word in host (little-endian) order
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return net.IP(b).String()
}

func isResolvedStub(a string) bool { return a == "127.0.0.53" || a == "127.0.0.54" }

// stubListeners returns systemd-resolved's stub listeners on port 53.
func stubListeners() []string {
	var out []string
	for _, a := range listeners(53) {
		if isResolvedStub(a) {
			out = append(out, a)
		}
	}
	return out
}

// otherListeners returns port listeners that are not systemd-resolved's stub.
func otherListeners(port int) []string {
	var out []string
	for _, a := range listeners(port) {
		if !isResolvedStub(a) {
			out = append(out, a)
		}
	}
	return out
}
