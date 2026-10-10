package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/distro"
	"github.com/cumabozkurt/bpanel/internal/validate"
	"github.com/cumabozkurt/bpanel/templates"
)

type vhostData struct {
	HTTP2On bool
	rpc.Vhost
	TemplateVersion int
	Names           []string
	DocRoot         string
	PHPSocket       string
	CertFile        string
	KeyFile         string
	// WAFInclude / ApacheWAFInclude: per-domain WAF snippet; "" renders nothing (netsec_waf.go).
	WAFInclude       string
	ApacheWAFInclude string
	// WebXInclude / ApacheWebXInclude: per-domain web extras; "" renders nothing (webx.go).
	WebXInclude       string
	ApacheWebXInclude string
	// AppXInclude / AppXRootPort: application proxy locations; "" / 0 render nothing (appx.go).
	AppXInclude  string
	AppXRootPort int
}

func (a *Agent) certPaths(domain string) (string, string) {
	d := filepath.Join(a.Cfg.SSLDir, domain)
	return filepath.Join(d, "fullchain.pem"), filepath.Join(d, "privkey.pem")
}

func (a *Agent) validateVhost(p *rpc.Vhost) error {
	if err := validate.Username(p.User); err != nil {
		return errf(err.Error(), "%s", p.User)
	}
	if err := validate.Domain(p.Domain); err != nil {
		return errf("invalid_domain", "%s", p.Domain)
	}
	for _, al := range p.Aliases {
		if err := validate.Domain(al); err != nil {
			return errf("invalid_domain", "%s", al)
		}
	}
	rel, err := validate.DocRoot(p.DocRoot)
	if err != nil {
		return errf("invalid_docroot", "%q", p.DocRoot)
	}
	p.DocRoot = rel
	if p.PHPVersion == "" {
		p.PHPVersion = a.L.DefaultPHP
	}
	if err := validate.PHPVersion(p.PHPVersion); err != nil {
		return errf("invalid_php_version", "%s", p.PHPVersion)
	}
	if p.Mode != "nginx" {
		p.Mode = "nginx-apache"
	}
	if !a.apacheEnabled() {
		p.Mode = "nginx" // minimal profile: no Apache installed (SYS-5 / H-2)
	}
	if p.Redirect != "" && (!strings.HasPrefix(p.Redirect, "http://") && !strings.HasPrefix(p.Redirect, "https://") ||
		!validate.ConfigSafe(p.Redirect) || len(p.Redirect) > 2000) {
		return errf("invalid_redirect", "%s", p.Redirect)
	}
	return nil
}

// RenderVhost renders the nginx and apache files without touching the system (used by tests).
func (a *Agent) RenderVhost(p rpc.Vhost, home string) (nginx, apache []byte, err error) {
	nginx, apache, _, _, err = a.renderVhost(p, home)
	return
}

// renderVhost also returns the per-domain web-extras includes (v0.4 webx).
func (a *Agent) renderVhost(p rpc.Vhost, home string) (nginx, apache, wxNginx, wxApache []byte, err error) {
	if err = a.validateVhost(&p); err != nil {
		return
	}
	d := vhostData{Vhost: p, TemplateVersion: templates.Version, DocRoot: filepath.Join(home, p.DocRoot),
		PHPSocket: a.L.PHPFor(p.PHPVersion).Socket(p.User), HTTP2On: a.http2On()}
	d.Names = append([]string{p.Domain}, p.Aliases...)
	d.CertFile, d.KeyFile = a.certPaths(p.Domain)
	d.WAFInclude, d.ApacheWAFInclude = a.wafIncludesFor(p.Domain)
	a.appxVhostFields(&d) // v0.4 appx proxy
	if wxNginx, wxApache, err = a.webxFor(d); err != nil {
		return
	}
	if wxNginx != nil {
		d.WebXInclude = filepath.Join(webxNginxDir, p.Domain+".conf")
	}
	if wxApache != nil {
		d.ApacheWebXInclude = filepath.Join(a.apacheWebxDir(), p.Domain+".conf")
	}
	if nginx, err = templates.Render("nginx-vhost.conf.tmpl", d); err != nil {
		return
	}
	apache, err = templates.Render("apache-vhost.conf.tmpl", d)
	return
}

func (a *Agent) vhostApply(ctx context.Context, p rpc.Vhost) (rpc.Empty, error) {
	if err := a.validateVhost(&p); err != nil {
		return rpc.Empty{}, err
	}
	e, err := a.home(p.User)
	if err != nil {
		return rpc.Empty{}, err
	}
	// CODE-27: the domain and every alias must be (or become) the account's
	// in the agent registry; a name held by another account is refused.
	undo, err := a.claimVhost(p)
	if err != nil {
		return rpc.Empty{}, err
	}
	ok := false
	defer func() {
		if !ok {
			undo()
		}
	}()
	if p.SSL {
		c, k := a.certPaths(p.Domain)
		if _, err := os.Stat(c); err != nil {
			p.SSL = false
		} else if _, err := os.Stat(k); err != nil {
			p.SSL = false
		}
	}
	// Create a missing docroot inside the home without following symlinks
	// (SEC-2 / CODE-3): a tenant symlink such as ~/web -> /etc/systemd/system
	// makes this fail instead of creating and chowning a directory there.
	webGID, gerr := groupID(a.L.WebGroup)
	if gerr != nil {
		webGID = e.gid
	}
	root, err := openHome(e)
	if err != nil {
		return rpc.Empty{}, err
	}
	err = mkdirOwned(root, p.DocRoot, 0o750, e.uid, webGID, false)
	root.Close()
	if err != nil {
		return rpc.Empty{}, err
	}
	for _, d := range []string{a.domlogDir, filepath.Join(a.acmeDir, ".well-known", "acme-challenge")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return rpc.Empty{}, err
		}
	}
	nginx, apache, wxNginx, wxApache, err := a.renderVhost(p, e.home)
	if err != nil {
		return rpc.Empty{}, err
	}
	defer a.lock("web")()
	tx := newTx()
	if err := a.webxWrite(tx, p.Domain, wxNginx, wxApache); err != nil { // v0.4 webx include
		tx.rollback()
		return rpc.Empty{}, err
	}
	if err := a.appxWrite(tx, p); err != nil { // v0.4 appx proxy include
		tx.rollback()
		return rpc.Empty{}, err
	}
	if err := tx.write(filepath.Join(a.L.NginxVhosts, p.Domain+".conf"), nginx, 0o644); err != nil {
		tx.rollback()
		return rpc.Empty{}, err
	}
	apPath := filepath.Join(a.L.ApacheVhosts, p.Domain+".conf")
	if p.Mode == "nginx-apache" {
		err = tx.write(apPath, apache, 0o644)
	} else {
		err = tx.remove(apPath)
	}
	if err != nil {
		tx.rollback()
		return rpc.Empty{}, err
	}
	if err := a.testAndReloadWeb(ctx); err != nil {
		tx.rollback()
		return rpc.Empty{}, err
	}
	ok = true
	keep := map[string]bool{}
	for _, al := range p.Aliases {
		keep[normName(al)] = true
	}
	a.releaseChildren(p.Domain, p.User, keep)
	return rpc.Empty{}, nil
}

// claimVhost registers the vhost's names for its account and returns a
// function that releases the names this call newly registered.
func (a *Agent) claimVhost(p rpc.Vhost) (func(), error) {
	var fresh []string
	undo := func() {
		for _, n := range fresh {
			if err := a.release(kindWeb, n, p.User); err != nil {
				a.Log.Warn("owner registry: undo claim", "name", n, "err", err)
			}
		}
	}
	names := append([]string{p.Domain}, p.Aliases...)
	for i, n := range names {
		_, had, err := a.readOwner(kindWeb, n)
		if err != nil {
			undo()
			return nil, err
		}
		if !had {
			if inferred := a.inferOwner(n); inferred != "" && inferred != p.User {
				undo()
				return nil, errf("owned_by_another_account", "%s is served for another account", n)
			}
		}
		parent := ""
		if i > 0 {
			parent = normName(p.Domain)
		}
		if err := a.claim(kindWeb, n, p.User, parent); err != nil {
			undo()
			return nil, err
		}
		if !had {
			fresh = append(fresh, n)
		}
	}
	return undo, nil
}

func (a *Agent) testAndReloadWeb(ctx context.Context) error {
	if err := a.configTest(ctx, a.L.NginxUnit); err != nil {
		return errf("nginx_config_invalid", "%v", err)
	}
	if a.apacheEnabled() {
		if err := a.configTest(ctx, a.L.ApacheUnit); err != nil {
			return errf("apache_config_invalid", "%v", err)
		}
		if err := a.systemctl(ctx, "reload", a.L.ApacheUnit); err != nil {
			a.Log.Warn("apache reload", "err", err)
		}
	}
	return a.systemctl(ctx, "reload", a.L.NginxUnit)
}

// apacheEnabled is false on the minimal profile (no Apache installed).
func (a *Agent) apacheEnabled() bool {
	return a.Cfg.Profile != "minimal"
}

// http2On reports whether nginx understands "http2 on;" (>= 1.25.1). The
// result of "nginx -v" is cached; unknown versions use the old listen form,
// which every supported nginx accepts (H-5).
func (a *Agent) http2On() bool {
	a.http2Once.Do(func() {
		if a.http2Probe != nil {
			a.http2 = a.http2Probe()
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "nginx", "-v").CombinedOutput()
		if err == nil {
			a.http2 = nginxHTTP2On(string(out))
		}
	})
	return a.http2
}

// nginxHTTP2On parses "nginx version: nginx/1.26.3".
func nginxHTTP2On(v string) bool {
	_, ver, ok := strings.Cut(v, "nginx/")
	if !ok {
		return false
	}
	ver = strings.Fields(ver + " ")[0]
	var maj, min, pat int
	if n, _ := fmt.Sscanf(ver, "%d.%d.%d", &maj, &min, &pat); n < 2 {
		return false
	}
	return maj > 1 || (maj == 1 && (min > 25 || (min == 25 && pat >= 1)))
}

func (a *Agent) vhostRemove(ctx context.Context, p rpc.DomainRef) (rpc.Empty, error) {
	if err := validate.Domain(p.Domain); err != nil {
		return rpc.Empty{}, errf("invalid_domain", "%s", p.Domain)
	}
	if err := a.mustOwn(kindWeb, p.Domain, p.Owner); err != nil {
		return rpc.Empty{}, err
	}
	defer a.lock("web")()
	tx := newTx()
	if err := tx.remove(filepath.Join(a.L.NginxVhosts, p.Domain+".conf")); err != nil {
		return rpc.Empty{}, err
	}
	if err := tx.remove(filepath.Join(a.L.ApacheVhosts, p.Domain+".conf")); err != nil {
		tx.rollback()
		return rpc.Empty{}, err
	}
	if err := a.testAndReloadWeb(ctx); err != nil {
		tx.rollback()
		return rpc.Empty{}, err
	}
	a.releaseChildren(p.Domain, p.Owner, nil)
	if err := a.release(kindWeb, p.Domain, p.Owner); err != nil {
		a.Log.Warn("owner registry: release", "name", p.Domain, "err", err)
	}
	return rpc.Empty{}, nil
}

// ---- PHP-FPM ----------------------------------------------------------------

type poolData struct {
	rpc.PHPPool
	TemplateVersion int
	Socket          string
	Home            string
}

var iniKeyOK = func(k string) bool {
	allowed := map[string]bool{"display_errors": true, "max_input_time": true, "max_input_vars": true,
		"date.timezone": true, "short_open_tag": true, "output_buffering": true, "allow_url_fopen": true,
		"session.gc_maxlifetime": true, "error_reporting": true, "zlib.output_compression": true,
		"post_max_size": true} // v0.4 usagex: post_max_size (php_ini page; later line overrides the template default)
	return allowed[k]
}

func (a *Agent) phpPoolApply(ctx context.Context, p rpc.PHPPool) (rpc.Empty, error) {
	if err := validate.Username(p.User); err != nil {
		return rpc.Empty{}, errf(err.Error(), "%s", p.User)
	}
	if err := validate.PHPVersion(p.Version); err != nil {
		return rpc.Empty{}, errf("invalid_php_version", "%s", p.Version)
	}
	e, err := a.home(p.User)
	if err != nil {
		return rpc.Empty{}, err
	}
	ph := a.L.PHPFor(p.Version)
	if _, err := os.Stat(ph.Binary); err != nil {
		return rpc.Empty{}, errf("php_not_installed", "PHP %s is not installed", p.Version)
	}
	if p.MaxChildren <= 0 || p.MaxChildren > 200 {
		p.MaxChildren = 10
	}
	if !sizeOK(p.MemoryLimit) {
		p.MemoryLimit = "256M"
	}
	if !sizeOK(p.UploadMax) {
		p.UploadMax = "64M"
	}
	if p.MaxExecution <= 0 || p.MaxExecution > 3600 {
		p.MaxExecution = 120
	}
	for k, v := range p.INI {
		if !iniKeyOK(k) || !iniValueOK(v) {
			return rpc.Empty{}, errf("invalid_ini", "%s", k)
		}
	}
	b, err := templates.Render("pool.conf.tmpl", poolData{PHPPool: p, TemplateVersion: templates.Version, Socket: ph.Socket(p.User), Home: e.home})
	if err != nil {
		return rpc.Empty{}, err
	}
	defer a.lock("php-" + p.Version)()
	tx := newTx()
	if err := tx.write(filepath.Join(ph.PoolDir, "bpanel-"+p.User+".conf"), b, 0o644); err != nil {
		tx.rollback()
		return rpc.Empty{}, err
	}
	if _, err := run(ctx, nil, ph.Binary, "-t"); err != nil {
		tx.rollback()
		return rpc.Empty{}, errf("php_config_invalid", "%v", err)
	}
	if err := a.systemctl(ctx, "reload", ph.Unit); err != nil {
		tx.rollback()
		return rpc.Empty{}, errf("php_reload_failed", "%v", err)
	}
	return rpc.Empty{}, nil
}

// iniValueOK accepts a php_admin_value only when it cannot end the line or
// open a new section/expansion (R2-WB-12): no ASCII separators, and no
// Unicode line/paragraph separators (U+2028/U+2029), NEL (U+0085), other
// control or format characters, or invalid UTF-8.
func iniValueOK(v string) bool {
	if len(v) > 100 || !utf8.ValidString(v) || strings.ContainsAny(v, "\n\r;[]=\"'`$\\{}\x00") {
		return false
	}
	for _, r := range v {
		if r == 0x2028 || r == 0x2029 || r == 0x85 || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || !unicode.IsPrint(r) && r != ' ' {
			return false
		}
	}
	return true
}

func sizeOK(s string) bool {
	if s == "" || len(s) > 6 {
		return false
	}
	for i, c := range s {
		if c >= '0' && c <= '9' {
			continue
		}
		if i == len(s)-1 && (c == 'M' || c == 'G' || c == 'K') {
			continue
		}
		return false
	}
	return true
}

func (a *Agent) phpPoolRemove(ctx context.Context, p rpc.PHPPoolRef) (rpc.Empty, error) {
	if err := validate.Username(p.User); err != nil {
		return rpc.Empty{}, errf(err.Error(), "%s", p.User)
	}
	if err := validate.PHPVersion(p.Version); err != nil {
		return rpc.Empty{}, errf("invalid_php_version", "%s", p.Version)
	}
	ph := a.L.PHPFor(p.Version)
	defer a.lock("php-" + p.Version)()
	err := os.Remove(filepath.Join(ph.PoolDir, "bpanel-"+p.User+".conf"))
	if os.IsNotExist(err) {
		return rpc.Empty{}, nil // nothing to do: no reload storm on cleanup paths (SYS-9)
	}
	if err != nil {
		return rpc.Empty{}, err
	}
	if _, err := os.Stat(ph.Binary); err == nil {
		return rpc.Empty{}, a.systemctl(ctx, "reload", ph.Unit)
	}
	return rpc.Empty{}, nil
}

// poolsInUse lists the account pools configured for one PHP version.
func poolsInUse(ph distro.PHP) []string {
	ents, err := os.ReadDir(ph.PoolDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, "bpanel-") && strings.HasSuffix(n, ".conf") {
			out = append(out, strings.TrimSuffix(strings.TrimPrefix(n, "bpanel-"), ".conf"))
		}
	}
	return out
}

func (a *Agent) phpVersions(ctx context.Context, _ rpc.Empty) (rpc.PHPVersionsResult, error) {
	var out rpc.PHPVersionsResult
	for _, v := range distro.KnownPHP {
		ph := a.L.PHPFor(v)
		pv := rpc.PHPVersion{Version: v, Unit: ph.Unit, Binary: ph.Binary, Default: v == a.L.DefaultPHP}
		if _, err := os.Stat(ph.Binary); err == nil {
			pv.Installed = true
			if !a.Cfg.NoSystemd {
				// is-active exits non-zero for inactive units; the output is what counts
				s, _ := run(ctx, nil, "systemctl", "is-active", ph.Unit) //nolint:errcheck
				pv.Running = strings.TrimSpace(s) == "active"
			}
		}
		out.Versions = append(out.Versions, pv)
	}
	return out, nil
}

// placeholderPool keeps php-fpm startable when no account uses a version yet
// (FPM refuses to start without pools) and replaces the distro "www" pool.
func placeholderPool(ph distro.PHP) string {
	sock := ph.Socket("placeholder")
	return fmt.Sprintf(`; Managed by BOZKURT PANEL: idle placeholder so PHP-FPM can start with no accounts.
[bpanel-placeholder]
user = nobody
group = nogroup
listen = %s
listen.mode = 0600
pm = ondemand
pm.max_children = 1
pm.process_idle_timeout = 10s
`, sock)
}

// EnsurePHPBase disables the distro www pool and writes the placeholder (used by installer too).
func EnsurePHPBase(l *distro.Layout, v string) error {
	ph := l.PHPFor(v)
	if err := os.MkdirAll(ph.PoolDir, 0o755); err != nil {
		return err
	}
	www := filepath.Join(ph.PoolDir, "www.conf")
	if _, err := os.Stat(www); err == nil {
		if err := os.Rename(www, www+".bpanel-disabled"); err != nil {
			return err
		}
	}
	pp := placeholderPool(ph)
	if l.Family == distro.RHEL {
		pp = strings.Replace(pp, "group = nogroup", "group = nobody", 1)
	}
	return writeAtomic(filepath.Join(ph.PoolDir, "00-bpanel-placeholder.conf"), []byte(pp), 0o644, -1, -1)
}

func (a *Agent) phpInstall(ctx context.Context, p rpc.PHPInstall) (rpc.Empty, error) {
	if err := validate.PHPVersion(p.Version); err != nil {
		return rpc.Empty{}, errf("invalid_php_version", "%s", p.Version)
	}
	known := false
	for _, v := range distro.KnownPHP {
		known = known || v == p.Version
	}
	if !known {
		return rpc.Empty{}, errf("unknown_php_version", "%s", p.Version)
	}
	defer a.lock("packages")()
	pkgs := a.L.PHPPackages(p.Version)
	ph := a.L.PHPFor(p.Version)
	if p.Remove {
		if p.Version == a.L.DefaultPHP {
			return rpc.Empty{}, errf("refused", "the default PHP version cannot be removed")
		}
		if users := poolsInUse(ph); len(users) > 0 {
			return rpc.Empty{}, errf("php_version_in_use", "PHP %s still serves: %s", p.Version, strings.Join(users, ", "))
		}
		if !a.Cfg.NoSystemd {
			if _, err := run(ctx, nil, "systemctl", "disable", "--now", ph.Unit); err != nil {
				a.Log.Warn("php remove: disable unit", "unit", ph.Unit, "err", err)
			}
		}
		var argv []string
		if a.L.Family == distro.Debian {
			argv = append([]string{"apt-get", "-y", "remove"}, pkgs...)
		} else {
			argv = append([]string{"dnf", "-y", "remove"}, pkgs...)
		}
		_, err := run(ctx, nil, argv...)
		return rpc.Empty{}, err
	}
	var argv []string
	if a.L.Family == distro.Debian {
		// a fresh image has empty/stale package lists: refresh first, or the
		// install fails with "Unable to locate package" (SYS: PHP install)
		if _, err := run(ctx, nil, "apt-get", "-q", "update"); err != nil {
			return rpc.Empty{}, errf("php_install_failed", "apt-get update: %v", err)
		}
		argv = append([]string{"apt-get", "-y", "-o", "Dpkg::Options::=--force-confold", "install"}, pkgs...)
	} else {
		argv = append([]string{"dnf", "-y", "install"}, pkgs...)
	}
	if _, err := run(ctx, nil, argv...); err != nil {
		return rpc.Empty{}, errf("php_install_failed", "%v", err)
	}
	if err := EnsurePHPBase(a.L, p.Version); err != nil {
		return rpc.Empty{}, err
	}
	if _, err := run(ctx, nil, ph.Binary, "-t"); err != nil {
		return rpc.Empty{}, errf("php_config_invalid", "%v", err)
	}
	if err := a.systemctl(ctx, "enable", ph.Unit); err != nil {
		return rpc.Empty{}, err
	}
	return rpc.Empty{}, a.systemctl(ctx, "restart", ph.Unit)
}
