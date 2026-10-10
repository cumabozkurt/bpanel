// SPDX-License-Identifier: Apache-2.0

package agent

// providers.detect (v0.4 provider framework): a read-only inventory of the
// server components BPANEL drives. For every component the agent
//
//   - stats a fixed list of absolute binary paths (no PATH lookup, no input
//     from the request: the method takes no parameters),
//   - runs the first present binary with its version flag through
//     exec.CommandContext (argv, never a shell) with a 5 s timeout, a
//     minimal environment and output capped at 4 KiB,
//   - reads the ActiveState of its systemd unit (only when systemd is PID 1),
//   - checks that BPANEL's own configuration for it exists.
//
// It never installs, starts, stops or reconfigures anything. Errors are
// reduced to short machine reasons; command output is never returned
// beyond the parsed version string.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/distro"
)

// probeSpec describes how to find one component.
type probeSpec struct {
	name string
	// bins are absolute paths, tried in order; for multi (PHP-FPM) every
	// present path is a separate installed version.
	bins  []string
	multi bool
	args  []string       // version flag(s)
	re    *regexp.Regexp // first submatch = version; nil = genericVersion
	// existsOnly: never execute the binary (third-party commercial agents).
	existsOnly bool
	unit       string
	configured func() bool
	// health runs after a successful version check; returns a problem or "".
	health func(ctx context.Context) string
	// embedded components live inside the agent binary (lego).
	embedded func() (version string, ok bool)
}

var genericVersion = regexp.MustCompile(`\b(\d+\.\d+(?:\.\d+)?)`)

// probeSpecsHook replaces the probe table (tests only).
var probeSpecsHook func(a *Agent) []probeSpec

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func (a *Agent) probeSpecs() []probeSpec {
	if probeSpecsHook != nil {
		return probeSpecsHook(a)
	}
	l := a.L
	yes := func() bool { return true }
	var phpBins []string
	for _, v := range distro.KnownPHP {
		phpBins = append(phpBins, l.PHPFor(v).Binary)
	}
	apacheBin := "/usr/sbin/apache2"
	mariadb := []string{"/usr/sbin/mariadbd", "/usr/sbin/mysqld"}
	if l.Family == distro.RHEL {
		apacheBin = "/usr/sbin/httpd"
		mariadb = []string{"/usr/libexec/mariadbd", "/usr/libexec/mysqld", "/usr/sbin/mariadbd"}
	}
	restic := a.Cfg.ResticBin
	if !filepath.IsAbs(restic) {
		restic = "/usr/local/lib/bpanel/bin/restic"
	}
	return []probeSpec{
		{name: "nginx", bins: []string{"/usr/sbin/nginx"}, args: []string{"-v"}, re: regexp.MustCompile(`nginx/(\d+\.\d+\.\d+)`),
			unit: l.NginxUnit, configured: func() bool { return exists(l.NginxVhosts) }},
		{name: "apache", bins: []string{apacheBin}, args: []string{"-v"}, re: regexp.MustCompile(`Apache/(\d+\.\d+\.\d+)`),
			unit: l.ApacheUnit, configured: func() bool { return exists(l.ApacheVhosts) }},
		{name: "php-fpm", bins: phpBins, multi: true, args: []string{"-v"}, re: regexp.MustCompile(`PHP (\d+\.\d+\.\d+)`),
			unit: l.PHPFor(l.DefaultPHP).Unit, configured: yes},
		{name: "mariadb", bins: mariadb, args: []string{"--version"}, re: regexp.MustCompile(`Ver (\d+\.\d+\.\d+)`),
			unit: l.MariaDBUnit, configured: func() bool { return exists(filepath.Dir(l.MySQLSocket)) }},
		{name: "powerdns", bins: []string{"/usr/sbin/pdns_server"}, args: []string{"--version"},
			re: regexp.MustCompile(`(?:Server|Authoritative[^0-9]*)\s*(\d+\.\d+\.\d+)`), unit: l.PDNSUnit,
			configured: func() bool { return a.Cfg.PDNSKey != "" && a.Cfg.PDNSURL != "" },
			health: func(ctx context.Context) string {
				var out map[string]any
				if err := a.pdns(ctx, "GET", "/api/v1/servers/localhost", nil, &out); err != nil {
					return "api_unreachable"
				}
				return ""
			}},
		{name: "postfix", bins: []string{"/usr/sbin/postconf"}, args: []string{"-d", "mail_version"},
			re: regexp.MustCompile(`mail_version\s*=\s*(\d+\.\d+(?:\.\d+)?)`), unit: "postfix",
			configured: func() bool { return exists(a.postfixDir()) }},
		{name: "dovecot", bins: []string{"/usr/sbin/dovecot"}, args: []string{"--version"}, unit: "dovecot",
			configured: func() bool { return exists(filepath.Join(l.DovecotDir, "bpanel")) }},
		{name: "rspamd", bins: []string{"/usr/bin/rspamd"}, args: []string{"--version"}, unit: l.RspamdUnit, configured: yes},
		{name: "fail2ban", bins: []string{"/usr/bin/fail2ban-client"}, args: []string{"--version"}, unit: "fail2ban", configured: yes},
		{name: "restic", bins: []string{restic, "/usr/bin/restic"}, args: []string{"version"},
			re: regexp.MustCompile(`restic (\d+\.\d+\.\d+)`), configured: func() bool { return a.Cfg.BackupRepo != "" && exists(a.Cfg.BackupRepo) }},
		{name: "lego", embedded: legoVersion, configured: yes},
		{name: "imunify360", bins: []string{"/usr/bin/imunify360-agent"}, existsOnly: true, unit: "imunify360", configured: yes},
		{name: "monarx", bins: []string{"/usr/bin/monarx-agent"}, existsOnly: true, unit: "monarx-agent", configured: yes},
	}
}

// legoVersion reports the lego module compiled into this binary.
func legoVersion() (string, bool) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "", true // still embedded; version unknown (tests)
	}
	for _, d := range bi.Deps {
		if strings.HasPrefix(d.Path, "github.com/go-acme/lego/") {
			return strings.TrimPrefix(d.Version, "v"), true
		}
	}
	return "", true
}

// limitedBuf keeps at most n bytes.
type limitedBuf struct {
	b bytes.Buffer
	n int
}

func (l *limitedBuf) Write(p []byte) (int, error) {
	if room := l.n - l.b.Len(); room > 0 {
		if len(p) > room {
			l.b.Write(p[:room])
		} else {
			l.b.Write(p)
		}
	}
	return len(p), nil
}

// versionOf runs bin with args and parses the version. The binary is one of
// the fixed paths above; nothing from the request reaches argv.
func versionOf(ctx context.Context, bin string, args []string, re *regexp.Regexp) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "HOME=/nonexistent"}
	cmd.Stdin = nil
	out := &limitedBuf{n: 4096}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	s := out.b.String()
	if re == nil {
		re = genericVersion
	}
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		return m[1], nil // some tools exit non-zero after printing the version
	}
	if err == nil {
		err = errNoVersion
	}
	return "", err
}

type probeErr string

func (e probeErr) Error() string { return string(e) }

const errNoVersion = probeErr("no version in output")

// hasSystemd: systemd is PID 1 and the agent may query it.
func (a *Agent) hasSystemd() bool {
	return !a.Cfg.NoSystemd && exists("/run/systemd/system")
}

// unitState reads ActiveState of a fixed unit name; "" when not loaded.
func unitState(ctx context.Context, unit string) string {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, _ := run(cctx, nil, "systemctl", "show", unit, "-p", "ActiveState,LoadState") //nolint:errcheck // output is what counts
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		kv[k] = v
	}
	if kv["LoadState"] == "not-found" || kv["LoadState"] == "" {
		return ""
	}
	return kv["ActiveState"]
}

func (a *Agent) probe(ctx context.Context, sp probeSpec, systemd bool) rpc.ProviderProbe {
	p := rpc.ProviderProbe{Component: sp.name, Unit: sp.unit}
	if sp.embedded != nil {
		p.Unit = ""
		p.Binary = "embedded"
		p.Version, p.Present = sp.embedded()
		p.Configured = sp.configured == nil || sp.configured()
		return p
	}
	var versions []string
	for _, b := range sp.bins {
		if !filepath.IsAbs(b) || !exists(b) {
			continue
		}
		if !p.Present {
			p.Present, p.Binary = true, b
		}
		if sp.existsOnly {
			break
		}
		v, err := versionOf(ctx, b, sp.args, sp.re)
		if err != nil {
			p.Problem = "version_check_failed"
			continue // a single-version component may have a second path
		}
		versions = append(versions, v)
		if !sp.multi {
			p.Binary = b
			break
		}
	}
	if len(versions) > 0 {
		p.Problem = ""
		p.Version = strings.Join(versions, ", ")
	}
	if !p.Present {
		return p
	}
	p.Configured = sp.configured == nil || sp.configured()
	if systemd && sp.unit != "" {
		p.UnitState = unitState(ctx, sp.unit)
	}
	if p.Problem == "" && p.Configured && sp.health != nil && (p.UnitState == "" || p.UnitState == "active") {
		p.Problem = sp.health(ctx)
	}
	return p
}

func (a *Agent) providersDetect(ctx context.Context, _ rpc.Empty) (rpc.ProvidersDetectResult, error) {
	specs := a.probeSpecs()
	res := rpc.ProvidersDetectResult{Systemd: a.hasSystemd(), Probes: make([]rpc.ProviderProbe, len(specs))}
	if a.L != nil {
		res.Distro, res.Family = a.L.Pretty, string(a.L.Family)
	}
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, sp := range specs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res.Probes[i] = a.probe(ctx, sp, res.Systemd)
		}()
	}
	wg.Wait()
	sort.SliceStable(res.Probes, func(i, j int) bool { return res.Probes[i].Component < res.Probes[j].Component })
	return res, nil
}
