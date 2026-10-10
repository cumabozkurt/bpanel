package installer

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/api"
	"github.com/cumabozkurt/bpanel/internal/auth"
	"github.com/cumabozkurt/bpanel/internal/distro"
	"github.com/cumabozkurt/bpanel/internal/store"
)

// Check is one self-test result.
type Check struct {
	Name string
	Err  error
}

// SelfTest checks the agent, services, listeners and an end-to-end account
// lifecycle (create -> vhost -> PHP pool -> terminate). Used by the installer
// and by `bpanel selftest`.
func SelfTest(ctx context.Context, cfg api.Config, socket string, e2e bool) []Check {
	return SelfTestUnits(ctx, cfg, socket, e2e, nil, "")
}

// ProfileUnits lists the services a profile installs. The self-test only
// checks these: a minimal install has no Apache, PowerDNS or mail (SYS-5).
func ProfileUnits(l *distro.Layout, profile string) []string { return l.ProfileUnits(profile) }

// SelfTestUnits is SelfTest restricted to the given units (nil = all known);
// webMode is passed to the e2e vhost ("nginx" on the minimal profile).
func SelfTestUnits(ctx context.Context, cfg api.Config, socket string, e2e bool, units []string, webMode string) []Check {
	var out []Check
	add := func(n string, err error) { out = append(out, Check{n, err}) }
	cl := rpc.NewClient(socket)
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	var ping rpc.PingResult
	add("agent socket", cl.Call(cctx, rpc.MPing, rpc.Empty{}, &ping))
	var svc rpc.ServiceStatus
	if err := cl.Call(cctx, rpc.MServiceStatus, rpc.ServiceStatusReq{Units: units}, &svc); err != nil {
		add("service status", err)
	}
	for _, s := range svc.Services {
		var err error
		name := "service " + s.Unit
		if s.Active != "active" {
			if SocketActive(ctx, s.Unit) {
				name += " (socket-activated)" // R2-SYS-7: Ubuntu's ssh.socket
			} else {
				err = fmt.Errorf("%s/%s", s.Active, s.Sub)
			}
		}
		add(name, err)
	}
	st, err := store.Open(cfg.DBPath)
	add("panel database", err)
	if st != nil {
		st.Close()
	}
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, p := range []struct {
		name string
		url  string
		want string
	}{
		{"user panel https :2083", fmt.Sprintf("https://127.0.0.1:%d/api/v1/meta", cfg.UserPort), `"realm":"user"`},
		{"admin panel https :2087", fmt.Sprintf("https://127.0.0.1:%d/api/v1/meta", cfg.AdminPort), `"realm":"admin"`},
	} {
		resp, err := hc.Get(p.url)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || !strings.Contains(string(b), p.want) {
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
			}
		}
		add(p.name, err)
	}
	for _, p := range []struct {
		port, to int
	}{{cfg.UserHTTPPort, cfg.UserPort}, {cfg.AdminHTTPPort, cfg.AdminPort}} {
		resp, err := hc.Get(fmt.Sprintf("http://127.0.0.1:%d/", p.port))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != 301 || !strings.Contains(resp.Header.Get("Location"), fmt.Sprintf(":%d/", p.to)) {
				err = fmt.Errorf("expected 301 to :%d, got %d %s", p.to, resp.StatusCode, resp.Header.Get("Location"))
			}
		}
		add(fmt.Sprintf("redirect :%d -> :%d", p.port, p.to), err)
	}
	if !e2e {
		return out
	}
	// end-to-end through the real agent
	user := "bptest" + fmt.Sprint(time.Now().Unix()%10000)
	pw := auth.RandomPassword(20)
	var cr rpc.AccountCreateResult
	err = cl.Call(cctx, rpc.MAccountCreate, rpc.AccountCreate{User: user, Password: pw, QuotaMB: 100}, &cr)
	add("e2e: create account", err)
	if err == nil {
		var versions rpc.PHPVersionsResult
		cl.Call(cctx, rpc.MPHPVersions, rpc.Empty{}, &versions)
		php := ""
		for _, v := range versions.Versions {
			if v.Default && v.Installed {
				php = v.Version
			}
		}
		add("e2e: PHP-FPM pool", cl.Call(cctx, rpc.MPHPPoolApply, rpc.PHPPool{User: user, Version: php}, nil))
		dom := user + ".selftest.invalid"
		add("e2e: nginx/apache vhost (config tested)", cl.Call(cctx, rpc.MVhostApply, rpc.Vhost{User: user, Domain: dom, DocRoot: "public_html", PHPVersion: php, Mode: webMode}, nil))
		herr := ProbeSite(cctx, "http://127.0.0.1/", dom, user)
		add("e2e: site answers over HTTP", herr)
		cl.Call(cctx, rpc.MVhostRemove, rpc.DomainRef{Owner: user, Domain: dom}, nil)
		removeDomlogs(dom) // R2-SYS-14: no selftest debris in /var/log/bpanel/domlogs
		cl.Call(cctx, rpc.MPHPPoolRemove, rpc.PHPPoolRef{User: user, Version: php}, nil)
		add("e2e: terminate account", cl.Call(cctx, rpc.MAccountTerminate, rpc.AccountRef{User: user}, nil))
	}
	return out
}

// SocketActive reports whether unit is started on demand by an active
// <unit>.socket (Ubuntu 24.04 runs sshd as ssh.socket + ssh.service, and
// ssh.service stays inactive until the first connection: R2-SYS-7).
func SocketActive(ctx context.Context, unit string) bool {
	if strings.ContainsAny(unit, "/ ") || unit == "" {
		return false
	}
	unit = strings.TrimSuffix(unit, ".service")
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "systemctl", "is-active", unit+".socket").Output()
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

// probeSchedule is the wait before each try of ProbeSite: nginx's
// `systemctl reload` returns before the new workers serve the new vhost, so
// the first requests can still hit the catch-all server (R2-SYS-5).
var probeSchedule = []time.Duration{0, 100 * time.Millisecond, 200 * time.Millisecond, 300 * time.Millisecond,
	500 * time.Millisecond, 750 * time.Millisecond, time.Second, time.Second, 1500 * time.Millisecond,
	2 * time.Second, 2 * time.Second, 3 * time.Second, 3 * time.Second}

// ProbeSite requests url with the Host header host until the body contains
// want, retrying with backoff (about 17 s in total). Redirects are never
// followed: a 3xx means the request reached the catch-all server, which
// redirects to the panel, so the vhost is not active yet.
func ProbeSite(ctx context.Context, url, host, want string) error {
	hc := &http.Client{Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var last error
	for _, wait := range probeSchedule {
		select {
		case <-ctx.Done():
			if last == nil {
				last = ctx.Err()
			}
			return last
		case <-time.After(wait):
		}
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return err
		}
		req.Host = host
		resp, err := hc.Do(req)
		if err != nil {
			last = err
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == 200 && strings.Contains(string(b), want):
			return nil
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			last = fmt.Errorf("HTTP %d to %s from the catch-all server (vhost for %s not active)", resp.StatusCode, resp.Header.Get("Location"), host)
		default:
			last = fmt.Errorf("HTTP %d, default page of %s not served", resp.StatusCode, host)
		}
	}
	return last
}

// domlogDir holds per-domain access/error logs (written by nginx/Apache).
var domlogDir = "/var/log/bpanel/domlogs"

// removeDomlogs deletes the per-domain logs of a self-test domain.
func removeDomlogs(dom string) {
	if dom == "" || strings.ContainsAny(dom, "/*?[") {
		return
	}
	files, _ := filepath.Glob(filepath.Join(domlogDir, dom+".*"))
	for _, f := range files {
		_ = os.Remove(f)
	}
}

func (in *Installer) selftest(ctx context.Context) error {
	if in.O.NoSystemd {
		in.warn("self-test skipped in --no-systemd mode")
		return nil
	}
	cfg := apiConfig()
	failed := 0
	for _, c := range SelfTestUnits(ctx, cfg, cfg.AgentSocket, true, ProfileUnits(in.L, in.O.Profile), in.webMode()) {
		if c.Err != nil {
			failed++
			fmt.Fprintf(in.out, "    ✘ %-40s %v\n", c.Name, c.Err)
			in.logf("selftest FAIL %s: %v", c.Name, c.Err)
		} else {
			fmt.Fprintf(in.out, "    ✔ %s\n", c.Name)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d self-test check(s) failed", failed)
	}
	return nil
}

func (in *Installer) summary(ctx context.Context) error {
	cfg := apiConfig()
	link := ""
	if st, err := store.Open(cfg.DBPath); err == nil {
		var id int64
		if st.DB.QueryRow(`SELECT id FROM users WHERE username=?`, in.O.AdminUser).Scan(&id) == nil {
			if tok, err := api.CreateOnceToken(st, id, api.RealmAdmin, 0, 15*time.Minute); err == nil {
				link = fmt.Sprintf("https://%s:2087/login/once/%s", in.O.Hostname, tok)
			}
		}
		st.Close()
		_ = os.Chown(cfg.DBPath, lookupUID("bpanel"), lookupGID("bpanel"))
	}
	h := in.O.Hostname
	fmt.Fprintln(in.out)
	fmt.Fprintf(in.out, T(in.O.Lang, "done_title")+"\n", in.Version)
	fmt.Fprintf(in.out, T(in.O.Lang, "done_admin")+"\n", h)
	fmt.Fprintf(in.out, T(in.O.Lang, "done_user")+"\n", h)
	if in.full() {
		fmt.Fprintf(in.out, T(in.O.Lang, "done_webmail")+"\n", h)
	}
	if link != "" {
		fmt.Fprintf(in.out, T(in.O.Lang, "done_login")+"\n", link)
	}
	if in.S.AdminPass != "" {
		fmt.Fprintf(in.out, T(in.O.Lang, "done_creds")+"\n", in.O.AdminUser, in.S.AdminPass)
	}
	fmt.Fprintf(in.out, T(in.O.Lang, "done_log")+"\n", LogFile)
	if in.S.Reboot {
		fmt.Fprintln(in.out, T(in.O.Lang, "done_reboot"))
	}
	if len(in.S.Warnings) > 0 {
		fmt.Fprintln(in.out, T(in.O.Lang, "done_warnings"))
		seen := map[string]bool{}
		for _, w := range in.S.Warnings {
			if !seen[w] {
				fmt.Fprintln(in.out, "  - "+w)
				seen[w] = true
			}
		}
	}
	fmt.Fprintln(in.out, T(in.O.Lang, "next_steps"))
	return nil
}

// webMode is the vhost mode of new accounts: nginx-only without Apache.
func (in *Installer) webMode() string {
	if in.web() {
		return "nginx-apache"
	}
	return "nginx"
}
