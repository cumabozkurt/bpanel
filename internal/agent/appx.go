// SPDX-License-Identifier: Apache-2.0

package agent

// v0.4 appx: Application Manager, app installer and WordPress toolkit.
//
//   - Apps run as bpanel-app@<id>.service: a hardened template unit plus a
//     per-app drop-in (User=<account>, Slice=bpanel-u-<account>.slice,
//     ExecStart=<detected runtime> <startup file>). Without systemd as PID 1
//     start/stop/logs answer appx_unsupported; nothing is faked.
//   - The public URL is an nginx location rendered from root-owned state
//     (/var/lib/bpanel/appx/proxy/<domain>.json) into
//     /etc/nginx/bpanel-appx.d/<domain>.conf inside the vhost transaction
//     (config test + rollback); "/" is served by the vhost template itself.
//   - Installs download only URLs from the Go catalogue, verify the pinned
//     checksum before anything is unpacked, and extract inside an os.Root of
//     the destination as the account's uid/gid.

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/appx"
	"github.com/cumabozkurt/bpanel/internal/isolation"
)

var (
	appxStateDir   = "/var/lib/bpanel/appx"
	appxNginxDir   = "/etc/nginx/bpanel-appx.d"
	appxUnitDir    = "/etc/systemd/system"
	appxEnvDir     = "/etc/bpanel/apps"
	appxWPCLIPath  = appx.WPCLIPath
	appxPHPCLI     = []string{"/usr/bin/php", "/usr/local/bin/php"}
	appxSystemd    = func(a *Agent) bool { return !a.Cfg.NoSystemd && systemdPID1() }
	appxRuntimeBin = []string{"/usr/bin/node", "/usr/local/bin/node", "/usr/bin/nodejs", "/opt/bpanel/runtimes/node-*/bin/node",
		"/usr/bin/python3", "/usr/bin/python3.*", "/usr/local/bin/python3", "/opt/bpanel/runtimes/python-*/bin/python3",
		"/usr/bin/ruby", "/usr/bin/ruby3.*", "/usr/local/bin/ruby", "/opt/bpanel/runtimes/ruby-*/bin/ruby"}
	// appxFetch downloads url into w (replaced in tests).
	appxFetch = func(ctx context.Context, url string, w io.Writer, max int64) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		// some mirrors (download.phpbb.com) only serve wget/curl-style clients
		req.Header.Set("User-Agent", "Wget/1.21 (compatible; bpanel-agent/"+Version+"; +https://github.com/cumabozkurt/bpanel)")
		resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return errf("appx_download_failed", "HTTP %d", resp.StatusCode)
		}
		n, err := io.Copy(w, io.LimitReader(resp.Body, max+1))
		if err == nil && n > max {
			return errf("appx_download_failed", "download larger than the limit")
		}
		return err
	}
	// appxRunCmd runs an argv with a timeout and returns combined output (replaced in tests).
	appxRunCmd = func(ctx context.Context, timeout time.Duration, argv ...string) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		var buf bytes.Buffer
		cmd.Stdout, cmd.Stderr = &buf, &buf
		cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
		err := cmd.Run()
		if ctx.Err() == context.DeadlineExceeded {
			return tail(buf.String()), errf("appx_timeout", "timed out after %s", timeout)
		}
		return tail(buf.String()), err
	}
	verRe = regexp.MustCompile(`([0-9]+\.[0-9]+(\.[0-9]+)?)`)
)

func tail(s string) string {
	if len(s) > 8192 {
		return s[len(s)-8192:]
	}
	return s
}

func init() {
	for _, m := range []string{rpc.MAppxAppApply, rpc.MAppxAppRemove, rpc.MAppxAppCtl, rpc.MAppxAppLogs, rpc.MAppxAppDeps, rpc.MAppxInstall, rpc.MAppxWP} {
		accountField[m] = struct {
			key      string
			optional bool
		}{"user", false}
	}
	gateExempt[rpc.MAppxRuntimes] = "server (read-only runtime probe)"
	gateExempt[rpc.MAppxWPCLIInstall] = "server tool; admin-only API, fixed official URL + published sha512"
}

func (a *Agent) appxRoutes() map[string]handler {
	return map[string]handler{
		rpc.MAppxRuntimes: bind(a.appxRuntimes), rpc.MAppxAppApply: bind(a.appxAppApply), rpc.MAppxAppRemove: bind(a.appxAppRemove),
		rpc.MAppxAppCtl: bind(a.appxAppCtl), rpc.MAppxAppLogs: bind(a.appxAppLogs), rpc.MAppxAppDeps: bind(a.appxAppDeps),
		rpc.MAppxInstall: bind(a.appxInstall), rpc.MAppxWP: bind(a.appxWP), rpc.MAppxWPCLIInstall: bind(a.appxWPCLIInstall),
	}
}

// ---- runtimes ----

func detectRuntimes(ctx context.Context) []rpc.AppxRuntime {
	out := []rpc.AppxRuntime{}
	seen := map[string]bool{}
	for _, g := range appxRuntimeBin {
		ms, _ := filepath.Glob(g)
		for _, p := range ms {
			real, err := filepath.EvalSymlinks(p)
			if err != nil || seen[real] || strings.HasSuffix(p, "-config") {
				continue
			}
			if fi, err := os.Stat(real); err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 || fi.Mode()&0o022 != 0 {
				continue // missing, not executable, or group/world-writable
			}
			seen[real] = true
			o, err := appxRunCmd(ctx, 5*time.Second, p, "--version")
			v := verRe.FindString(o)
			if err != nil || v == "" {
				continue
			}
			rt := appx.RuntimePython
			if strings.Contains(filepath.Base(p), "node") {
				rt = appx.RuntimeNode
			} else if strings.Contains(filepath.Base(p), "ruby") {
				rt = appx.RuntimeRuby
			}
			out = append(out, rpc.AppxRuntime{Runtime: rt, Version: v, Path: p})
		}
	}
	return out
}

func appxFirstExec(paths []string) string {
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

func (a *Agent) appxRuntimes(ctx context.Context, _ struct{}) (rpc.AppxRuntimesResult, error) {
	return rpc.AppxRuntimesResult{Runtimes: detectRuntimes(ctx), Systemd: appxSystemd(a), WPCLI: regularFile(appxWPCLIPath),
		PHPCLI: appxFirstExec(appxPHPCLI) != ""}, nil
}

// runtimeFor picks the detected binary whose version starts with want.
func runtimeFor(ctx context.Context, rt, want string) (string, error) {
	for _, r := range detectRuntimes(ctx) {
		if r.Runtime == rt && (r.Version == want || strings.HasPrefix(r.Version, want+".")) {
			return r.Path, nil
		}
	}
	return "", errf("appx_runtime_missing", "%s %s is not installed on this server", rt, want)
}

// ---- state ----

type appxAppState struct {
	User string   `json:"user"`
	App  appx.App `json:"app"`
	Bin  string   `json:"bin"`
}

type appxProxyState struct {
	User    string       `json:"user"`
	Entries []appx.Proxy `json:"entries"`
}

func appxAppFile(id int64) string {
	return filepath.Join(appxStateDir, "apps", strconv.FormatInt(id, 10)+".json")
}
func appxProxyFile(d string) string { return filepath.Join(appxStateDir, "proxy", d+".json") }
func appxDropIn(id int64) string {
	return filepath.Join(appxUnitDir, appx.UnitName(id)+".d", "bpanel.conf")
}

func (a *Agent) appxLoad(user string, id int64) (appxAppState, error) {
	var st appxAppState
	b, err := os.ReadFile(appxAppFile(id))
	if err != nil || json.Unmarshal(b, &st) != nil {
		return st, errf("appx_not_found", "application %d not found", id)
	}
	if st.User != user {
		return st, errf("owned_by_another_account", "application %d belongs to another account", id)
	}
	return st, nil
}

// appxProxyFor returns the validated proxy entries of a domain for its owner.
func appxProxyFor(domain, user string) []appx.Proxy {
	b, err := os.ReadFile(appxProxyFile(domain))
	if err != nil {
		return nil
	}
	var st appxProxyState
	if json.Unmarshal(b, &st) != nil || st.User != user {
		return nil
	}
	if _, err := appx.RenderProxy(append([]appx.Proxy(nil), st.Entries...)); err != nil {
		return nil
	}
	return st.Entries
}

// appxVhostFields sets the template fields (include path, "/" port).
func (a *Agent) appxVhostFields(d *vhostData) {
	if d.Suspended || d.Redirect != "" {
		return
	}
	ents := appxProxyFor(d.Domain, d.User)
	if len(ents) == 0 {
		return
	}
	d.AppXRootPort = appx.RootPort(ents)
	if len(ents) > 1 || d.AppXRootPort == 0 {
		d.AppXInclude = filepath.Join(appxNginxDir, d.Domain+".conf")
	}
}

// appxWrite writes or removes the include inside the vhost transaction.
func (a *Agent) appxWrite(tx *transaction, p rpc.Vhost) error {
	np := filepath.Join(appxNginxDir, p.Domain+".conf")
	d := vhostData{Vhost: p}
	a.appxVhostFields(&d)
	if d.AppXInclude == "" {
		return tx.remove(np)
	}
	s, err := appx.RenderProxy(appxProxyFor(p.Domain, p.User))
	if err != nil {
		return errf("appx_invalid", "%v", err)
	}
	return tx.write(np, []byte(s), 0o644)
}

func putFile(p string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return webxPut(p, b, mode, -1)
}

// appxDomains stores each domain's proxy state and re-applies its vhost.
func (a *Agent) appxDomains(ctx context.Context, user string, doms []rpc.AppxDomain) (bool, error) {
	wired := false
	for _, d := range doms {
		dn := normName(d.Vhost.Domain)
		if d.Vhost.User != user || dn == "" || strings.ContainsAny(dn, "/\\") {
			return false, errf("appx_invalid", "vhost does not belong to the account")
		}
		if o, had, err := a.readOwner(kindWeb, dn); err != nil {
			return false, err
		} else if had && o.Owner != user {
			return false, errf("owned_by_another_account", "%s is served for another account", dn)
		}
		if _, err := appx.RenderProxy(append([]appx.Proxy(nil), d.Proxies...)); err != nil {
			return false, err
		}
		pf := appxProxyFile(dn)
		old, hadOld := os.ReadFile(pf)
		var err error
		if len(d.Proxies) == 0 {
			err = os.Remove(pf)
			if os.IsNotExist(err) {
				err = nil
			}
		} else {
			b, _ := json.Marshal(appxProxyState{User: user, Entries: d.Proxies})
			err = putFile(pf, b, 0o600)
		}
		if err != nil {
			return false, errf("appx_write_failed", "cannot store proxy state")
		}
		if _, err := a.vhostApply(ctx, d.Vhost); err != nil {
			if hadOld == nil {
				_ = putFile(pf, old, 0o600)
			} else {
				_ = os.Remove(pf)
			}
			return false, err
		}
		wired = wired || len(d.Proxies) > 0
	}
	return wired, nil
}

// ---- apps ----

func (a *Agent) appxAppApply(ctx context.Context, p rpc.AppxAppApplyParams) (rpc.AppxAppResult, error) {
	res := rpc.AppxAppResult{Systemd: appxSystemd(a)}
	app := p.App
	app.User = p.User
	if err := app.Validate(); err != nil {
		return res, appxErr(err)
	}
	if app.ID <= 0 || app.Port < 1024 || app.Port > 65535 {
		return res, errf("appx_invalid", "invalid id or port")
	}
	if old, err := a.appxLoad(p.User, app.ID); err != nil && !isCode(err, "appx_not_found") {
		return res, err
	} else if err == nil && old.User != p.User {
		return res, errf("owned_by_another_account", "application belongs to another account")
	}
	e, err := a.home(p.User)
	if err != nil {
		return res, err
	}
	root, err := openHome(e)
	if err != nil {
		return res, err
	}
	fi, err := root.Stat(filepath.Join(app.Root, app.Startup))
	root.Close()
	if err != nil || !fi.Mode().IsRegular() {
		return res, errf("appx_startup_missing", "%s/%s does not exist in your home", app.Root, app.Startup)
	}
	bin, err := runtimeFor(ctx, app.Runtime, app.Version)
	if err != nil {
		return res, err
	}
	if app.Runtime == appx.RuntimePython {
		if venv := filepath.Join(e.home, app.Root, ".venv/bin/python"); fileExistsNoFollow(venv) {
			bin = venv
		}
	}
	defer a.lock("appx")()
	envFile := filepath.Join(appxEnvDir, strconv.FormatInt(app.ID, 10)+".env")
	drop, err := appx.RenderDropIn(app, e.home, isolation.SliceName(p.User), bin, envFile)
	if err != nil {
		return res, appxErr(err)
	}
	st, _ := json.Marshal(appxAppState{User: p.User, App: app, Bin: bin})
	for _, w := range []struct {
		p    string
		b    []byte
		mode os.FileMode
	}{
		{envFile, []byte(appx.RenderEnvFile(app.Env)), 0o600},
		{filepath.Join(appxUnitDir, "bpanel-app@.service"), []byte(appx.UnitTemplate), 0o644},
		{appxDropIn(app.ID), []byte(drop), 0o644},
		{appxAppFile(app.ID), st, 0o600},
	} {
		if err := putFile(w.p, w.b, w.mode); err != nil {
			return res, errf("appx_write_failed", "cannot write %s", filepath.Base(w.p))
		}
	}
	if res.Systemd {
		if _, err := appxRunCmd(ctx, 30*time.Second, "systemctl", "daemon-reload"); err != nil {
			a.Log.Warn("appx daemon-reload", "err", err)
		}
	}
	if res.Wired, err = a.appxDomains(ctx, p.User, p.Domains); err != nil {
		return res, err
	}
	res.Status, res.Unit = "applied", appx.UnitName(app.ID)
	a.Log.Info("appx app applied", "user", p.User, "id", app.ID)
	return res, nil
}

func (a *Agent) appxAppRemove(ctx context.Context, p rpc.AppxAppRef) (rpc.AppxAppResult, error) {
	res := rpc.AppxAppResult{Systemd: appxSystemd(a), Unit: appx.UnitName(p.ID)}
	if _, err := a.appxLoad(p.User, p.ID); err != nil && !isCode(err, "appx_not_found") {
		return res, err
	}
	defer a.lock("appx")()
	if res.Systemd {
		_, _ = appxRunCmd(ctx, 60*time.Second, "systemctl", "disable", "--now", res.Unit)
	}
	_ = os.RemoveAll(filepath.Dir(appxDropIn(p.ID)))
	_ = os.Remove(filepath.Join(appxEnvDir, strconv.FormatInt(p.ID, 10)+".env"))
	_ = os.Remove(appxAppFile(p.ID))
	if res.Systemd {
		_, _ = appxRunCmd(ctx, 30*time.Second, "systemctl", "daemon-reload")
	}
	if _, err := a.appxDomains(ctx, p.User, p.Domains); err != nil {
		return res, err
	}
	res.Status = "removed"
	return res, nil
}

func (a *Agent) appxAppCtl(ctx context.Context, p rpc.AppxAppRef) (rpc.AppxCtlResult, error) {
	var res rpc.AppxCtlResult
	if _, err := a.appxLoad(p.User, p.ID); err != nil {
		return res, err
	}
	if !appxSystemd(a) {
		return res, errf("appx_unsupported", "systemd is not PID 1 on this server: applications cannot be run as services")
	}
	unit := appx.UnitName(p.ID)
	var argv []string
	switch p.Action {
	case "start":
		argv = []string{"systemctl", "enable", "--now", unit}
	case "stop":
		argv = []string{"systemctl", "disable", "--now", unit}
	case "restart":
		argv = []string{"systemctl", "restart", unit}
	case "status":
	default:
		return res, errf("appx_invalid", "unknown action %q", p.Action)
	}
	if argv != nil {
		if out, err := appxRunCmd(ctx, 60*time.Second, argv...); err != nil {
			return res, errf("appx_ctl_failed", "%s", strings.TrimSpace(tail(out)))
		}
	}
	out, err := appxRunCmd(ctx, 15*time.Second, "systemctl", "show", "-p", "ActiveState,SubState,MainPID", unit)
	if err != nil {
		return res, errf("appx_ctl_failed", "cannot read the service state")
	}
	for _, l := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
		switch k {
		case "ActiveState":
			res.Active = v
		case "SubState":
			res.Sub = v
		case "MainPID":
			res.PID, _ = strconv.Atoi(v)
		}
	}
	return res, nil
}

func (a *Agent) appxAppLogs(ctx context.Context, p rpc.AppxAppRef) (rpc.AppxOutput, error) {
	if _, err := a.appxLoad(p.User, p.ID); err != nil {
		return rpc.AppxOutput{}, err
	}
	if !appxSystemd(a) {
		return rpc.AppxOutput{}, errf("appx_unsupported", "systemd is not PID 1 on this server: no service journal")
	}
	n := p.Lines
	if n <= 0 || n > 1000 {
		n = 200
	}
	out, err := appxRunCmd(ctx, 20*time.Second, "journalctl", "-u", appx.UnitName(p.ID), "-n", strconv.Itoa(n), "--no-pager", "-o", "short-iso")
	if err != nil {
		return rpc.AppxOutput{}, errf("appx_ctl_failed", "cannot read the journal")
	}
	return rpc.AppxOutput{Output: out}, nil
}

// cageArgv runs argv as the account inside its slice/cgroup (the same two
// paths as cron: systemd-run, or the agent's cage-exec without systemd).
func (a *Agent) cageArgv(e passwdEntry, dir string, argv ...string) []string {
	env := []string{"/usr/bin/env", "-i", "HOME=" + e.home, "USER=" + e.name, "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"}
	if appxSystemd(a) {
		return append(append([]string{"/usr/bin/systemd-run", "--quiet", "--collect", "--wait", "--pipe",
			"--slice=" + isolation.SliceName(e.name), "--uid=" + strconv.Itoa(e.uid), "--gid=" + strconv.Itoa(e.gid),
			"--property=NoNewPrivileges=yes", "--property=PrivateTmp=yes", "--property=RuntimeMaxSec=900",
			"--working-directory=" + dir, "--"}, env...), argv...)
	}
	return append(append([]string{isolation.CageExecBin, "cage-exec", "--cgroup", isolation.CgroupDir(isolationCgroupRoot, e.name),
		"--uid", strconv.Itoa(e.uid), "--gid", strconv.Itoa(e.gid), "--chdir", dir, "--"}, env...), argv...)
}

func (a *Agent) appxAppDeps(ctx context.Context, p rpc.AppxAppRef) (rpc.AppxOutput, error) {
	st, err := a.appxLoad(p.User, p.ID)
	if err != nil {
		return rpc.AppxOutput{}, err
	}
	e, err := a.home(p.User)
	if err != nil {
		return rpc.AppxOutput{}, err
	}
	root, err := openHome(e)
	if err != nil {
		return rpc.AppxOutput{}, err
	}
	defer root.Close()
	dir := filepath.Join(e.home, st.App.Root)
	var steps [][]string
	if st.App.Runtime == appx.RuntimeNode {
		if _, err := root.Stat(filepath.Join(st.App.Root, "package.json")); err != nil {
			return rpc.AppxOutput{}, errf("appx_no_manifest", "package.json not found in %s", st.App.Root)
		}
		npm := filepath.Join(filepath.Dir(st.Bin), "npm")
		if !fileExistsNoFollow(npm) && appxFirstExec([]string{npm}) == "" {
			return rpc.AppxOutput{}, errf("appx_runtime_missing", "npm is not installed next to %s", st.Bin)
		}
		steps = [][]string{{npm, "install", "--omit=dev", "--no-audit", "--no-fund"}}
	} else if st.App.Runtime == appx.RuntimeRuby {
		// Ruby gems: Gemfile -> bundler into <app>/vendor/bundle (never system-wide).
		if _, err := root.Stat(filepath.Join(st.App.Root, "Gemfile")); err != nil {
			return rpc.AppxOutput{}, errf("appx_no_manifest", "Gemfile not found in %s", st.App.Root)
		}
		bundle := appxFirstExec([]string{filepath.Join(filepath.Dir(st.Bin), "bundle"), "/usr/bin/bundle", "/usr/local/bin/bundle"})
		if bundle == "" {
			return rpc.AppxOutput{}, errf("appx_runtime_missing", "bundler is not installed next to %s", st.Bin)
		}
		steps = [][]string{{bundle, "config", "set", "--local", "path", "vendor/bundle"}, {bundle, "install", "--jobs", "2"}}
	} else {
		if _, err := root.Stat(filepath.Join(st.App.Root, "requirements.txt")); err != nil {
			return rpc.AppxOutput{}, errf("appx_no_manifest", "requirements.txt not found in %s", st.App.Root)
		}
		py := st.Bin
		if !strings.HasSuffix(py, ".venv/bin/python") {
			steps = append(steps, []string{py, "-m", "venv", ".venv"})
		}
		steps = append(steps, []string{filepath.Join(dir, ".venv/bin/pip"), "install", "--no-input", "-r", "requirements.txt"})
	}
	defer a.lock("appx-deps-" + p.User)()
	var out strings.Builder
	for _, s := range steps {
		o, err := appxRunCmd(ctx, 10*time.Minute, a.cageArgv(e, dir, s...)...)
		out.WriteString(o)
		if err != nil {
			if isCode(err, "appx_timeout") {
				return rpc.AppxOutput{Output: tail(out.String())}, err
			}
			return rpc.AppxOutput{Output: tail(out.String())}, errf("appx_deps_failed", "%s failed", filepath.Base(s[0]))
		}
	}
	a.Log.Info("appx deps installed", "user", p.User, "id", p.ID)
	return rpc.AppxOutput{Output: tail(out.String())}, nil
}

// ---- installer ----

var allowedLeftovers = map[string]bool{"index.html": true, "cgi-bin": true, ".well-known": true}

// appxExtractInto verifies archive and unpacks it into dest (inside home
// root), owned by uid:gid. dest must be empty apart from the panel's
// default page, which is renamed (never deleted).
func appxExtractInto(home *os.Root, dest string, c appx.CatalogApp, archive string, uid, gid, dirGID int) (int, error) {
	if err := appx.VerifyFile(archive, c.SHA256, c.SHA1); err != nil {
		return 0, err
	}
	if err := mkdirOwned(home, dest, 0o750, uid, dirGID, false); err != nil {
		return 0, err
	}
	sub, err := home.OpenRoot(dest)
	if err != nil {
		return 0, errf("appx_invalid_path", "cannot open %s", dest)
	}
	defer sub.Close()
	d, err := sub.Open(".")
	if err != nil {
		return 0, err
	}
	names, _ := d.Readdirnames(-1)
	d.Close()
	for _, n := range names {
		if !allowedLeftovers[n] {
			return 0, errf("appx_dest_not_empty", "%s is not empty", dest)
		}
	}
	for _, n := range names {
		if n == "index.html" {
			_ = sub.Rename(n, n+".bpanel-bak")
		}
	}
	f, err := os.Open(archive)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n, err := appx.ExtractApp(f, c, sub, uid, gid)
	if err != nil {
		return n, err
	}
	for _, rn := range c.Renames {
		if _, err := sub.Lstat(rn[1]); err == nil {
			continue
		}
		if err := sub.Rename(rn[0], rn[1]); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return n, errf("appx_write_failed", "cannot rename %s", rn[0])
		}
	}
	return n, nil
}

func (a *Agent) appxInstall(ctx context.Context, p rpc.AppxInstallParams) (rpc.AppxInstallResult, error) {
	var res rpc.AppxInstallResult
	c, ok := appx.Find(p.App)
	if !ok || !c.Enabled {
		return res, errf("appx_app_unavailable", "%s is not installable", p.App)
	}
	dest, err := appx.CleanRel(p.Dest)
	if err != nil {
		return res, appxErr(err)
	}
	var wpc string
	if c.ID == "wordpress" {
		if wpc, err = appx.RenderWPConfig(p.DB); err != nil {
			return res, appxErr(err)
		}
	}
	e, err := a.home(p.User)
	if err != nil {
		return res, err
	}
	defer a.lock("appx-install-" + p.User)()
	dl := filepath.Join(appxStateDir, "dl")
	if err := os.MkdirAll(dl, 0o700); err != nil {
		return res, errf("appx_write_failed", "cannot create the download directory")
	}
	tmp, err := os.CreateTemp(dl, c.ID+"-*")
	if err != nil {
		return res, errf("appx_write_failed", "cannot create a temporary file")
	}
	defer os.Remove(tmp.Name())
	ferr := appxFetch(ctx, c.URL, tmp, appx.MaxArchiveBytes)
	tmp.Close()
	if ferr != nil {
		if isCode(ferr, "appx_download_failed") {
			return res, ferr
		}
		return res, errf("appx_download_failed", "download of %s failed", c.Name)
	}
	home, err := openHome(e)
	if err != nil {
		return res, err
	}
	defer home.Close()
	webGID := e.gid
	if g, err := groupID(a.L.WebGroup); err == nil {
		webGID = g
	}
	n, err := appxExtractInto(home, dest, c, tmp.Name(), e.uid, e.gid, webGID)
	if err != nil {
		return res, appxErr(err)
	}
	if wpc != "" {
		cf := filepath.Join(dest, "wp-config.php")
		if err := home.WriteFile(cf, []byte(wpc), 0o600); err != nil {
			return res, errf("appx_write_failed", "cannot write wp-config.php")
		}
		_ = home.Lchown(cf, e.uid, e.gid)
		res.Config = true
	}
	res.Version, res.Files = c.Version, n
	a.Log.Info("appx installed", "user", p.User, "app", c.ID, "version", c.Version, "dest", dest)
	return res, nil
}

// ---- WordPress ----

func (a *Agent) appxWP(ctx context.Context, p rpc.AppxWPParams) (rpc.AppxWPResult, error) {
	var res rpc.AppxWPResult
	rel, err := appx.CleanRel(p.Path)
	if err != nil {
		return res, appxErr(err)
	}
	e, err := a.home(p.User)
	if err != nil {
		return res, err
	}
	home, err := openHome(e)
	if err != nil {
		return res, err
	}
	defer home.Close()
	wp, err := home.OpenRoot(rel)
	if err != nil {
		return res, errf("appx_not_wordpress", "%s is not a WordPress installation", rel)
	}
	defer wp.Close()
	readInfo := func() {
		b, _ := wp.ReadFile("wp-includes/version.php")
		res.Version = appx.ParseWPVersion(b)
		_, err := wp.Lstat(".maintenance")
		res.Maintenance = err == nil
		res.WPCLI = regularFile(appxWPCLIPath)
	}
	readInfo()
	if res.Version == "" {
		return res, errf("appx_not_wordpress", "%s is not a WordPress installation", rel)
	}
	switch p.Action {
	case "info":
	case "maintenance_on":
		if err := wp.WriteFile(".maintenance", appx.MaintenanceFile(), 0o644); err != nil {
			return res, errf("appx_write_failed", "cannot write .maintenance")
		}
		_ = wp.Lchown(".maintenance", e.uid, e.gid)
	case "maintenance_off":
		if err := wp.Remove(".maintenance"); err != nil && !os.IsNotExist(err) {
			return res, errf("appx_write_failed", "cannot remove .maintenance")
		}
	case "core_update":
		php := appxFirstExec(appxPHPCLI)
		if !res.WPCLI {
			return res, errf("appx_wpcli_missing", "WP-CLI is not installed on this server")
		}
		if php == "" {
			return res, errf("appx_php_cli_missing", "the PHP command-line binary is not installed")
		}
		dir := filepath.Join(e.home, rel)
		out, err := appxRunCmd(ctx, 10*time.Minute, a.cageArgv(e, dir, php, appxWPCLIPath, "core", "update", "--path="+dir)...)
		res.Output = out
		if err != nil {
			if isCode(err, "appx_timeout") {
				return res, err
			}
			return res, errf("appx_wp_update_failed", "WP-CLI core update failed")
		}
	default:
		return res, errf("appx_invalid", "unknown action %q", p.Action)
	}
	out := res.Output
	readInfo()
	res.Output = out
	a.Log.Info("appx wp", "user", p.User, "path", rel, "action", p.Action)
	return res, nil
}

// appxWPCLIInstall installs the official WP-CLI phar after checking it
// against the sha512 published next to it.
func (a *Agent) appxWPCLIInstall(ctx context.Context, _ struct{}) (rpc.AppxWPResult, error) {
	var sum bytes.Buffer
	if err := appxFetch(ctx, appx.WPCLISHA512URL, &sum, 1024); err != nil {
		return rpc.AppxWPResult{}, errf("appx_download_failed", "cannot fetch the WP-CLI checksum")
	}
	want := strings.ToLower(strings.TrimSpace(strings.Fields(sum.String() + " x")[0]))
	if len(want) != 128 {
		return rpc.AppxWPResult{}, errf("appx_checksum_missing", "published WP-CLI checksum is malformed")
	}
	var phar bytes.Buffer
	if err := appxFetch(ctx, appx.WPCLIPharURL, &phar, 64<<20); err != nil {
		return rpc.AppxWPResult{}, errf("appx_download_failed", "cannot fetch WP-CLI")
	}
	h := sha512.Sum512(phar.Bytes())
	if hex.EncodeToString(h[:]) != want {
		return rpc.AppxWPResult{}, errf("appx_checksum_mismatch", "WP-CLI does not match its published sha512")
	}
	if err := putFile(appxWPCLIPath, phar.Bytes(), 0o755); err != nil {
		return rpc.AppxWPResult{}, errf("appx_write_failed", "cannot install WP-CLI")
	}
	a.Log.Info("appx wp-cli installed", "path", appxWPCLIPath)
	return rpc.AppxWPResult{WPCLI: true}, nil
}

// ---- helpers ----

func appxErr(err error) error {
	if e, ok := err.(*appx.Error); ok {
		return errf(e.Code, "%s", e.Msg)
	}
	return err
}

func isCode(err error, code string) bool {
	e, ok := err.(*rpc.Error)
	return ok && e.Code == code
}

func fileExistsNoFollow(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}
