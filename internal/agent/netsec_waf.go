// SPDX-License-Identifier: Apache-2.0

package agent

// v0.4 network security, part B: per-domain WAF includes for the web server
// BPANEL already runs. No WAF engine is linked into BPANEL: nginx uses the
// libmodsecurity v3 connector (libnginx-mod-http-modsecurity), Apache uses
// mod_security2; both load the OWASP CRS from the distribution package.
//
// netsec.waf.apply writes /etc/bpanel/waf/<domain>.conf (SecLang rules) and a
// server-level snippet (nginx: /etc/nginx/bpanel-waf.d/<domain>.conf, Apache:
// <apache conf dir>/bpanel-waf.d/<domain>.conf), runs the web server config
// test with a fixed argv (nginx -t / apachectl configtest) and restores the
// previous files when the test fails. Without the module/CRS packages the
// action answers not_installed and writes nothing.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/netsec"
)

var (
	// wafPrefix roots every fixed WAF path (tests only; "" in production).
	wafPrefix = ""
	// fixed binaries for the config test (no PATH lookup)
	wafNginxBins  = []string{"/usr/sbin/nginx"}
	wafApacheBins = []string{"/usr/sbin/apache2ctl", "/usr/sbin/apachectl"}
	// fixed module / package paths probed by netsec.waf.status
	wafNginxModules  = []string{"/usr/lib/nginx/modules/ngx_http_modsecurity_module.so", "/usr/lib64/nginx/modules/ngx_http_modsecurity_module.so"}
	wafApacheModules = []string{"/usr/lib/apache2/modules/mod_security2.so", "/usr/lib64/httpd/modules/mod_security2.so"}
	wafModSecConfs   = []string{"/etc/nginx/modsec/modsecurity.conf", "/etc/modsecurity/modsecurity.conf"}
	wafCRSSetups     = []string{"/etc/modsecurity/crs/crs-setup.conf", "/usr/share/modsecurity-crs/crs-setup.conf", "/etc/httpd/modsecurity.d/crs-setup.conf"}
	wafCRSRuleDirs   = []string{"/usr/share/modsecurity-crs/rules", "/usr/share/mod_modsecurity_crs/rules"}
	wafRulesDir      = "/etc/bpanel/waf"
	wafNginxSnippets = "/etc/nginx/bpanel-waf.d"
	// wafReload reloads the web server after a successful wired apply.
	wafReload = func(a *Agent, ctx context.Context, unit string) error { return a.systemctl(ctx, "reload", unit) }
)

func init() {
	gateExempt[rpc.MNetsecWafApply] = "server (admin-only WAF include, domain validated; files under fixed WAF dirs only)"
	gateExempt[rpc.MNetsecWafStatus] = "server (read-only probe)"
}

func (a *Agent) netsecWafRoutes() map[string]handler {
	return map[string]handler{
		rpc.MNetsecWafApply:  bind(a.wafApply),
		rpc.MNetsecWafStatus: bind(a.wafStatus),
	}
}

func wp(p string) string { return wafPrefix + p }

func firstFile(ps []string) string {
	for _, p := range ps {
		if fi, err := os.Stat(wp(p)); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

func firstExec(ps []string) string {
	for _, p := range ps {
		if fi, err := os.Stat(wp(p)); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

func firstDirWithConf(ps []string) string {
	for _, p := range ps {
		if m, _ := filepath.Glob(filepath.Join(wp(p), "*.conf")); len(m) > 0 {
			return p
		}
	}
	return ""
}

func (a *Agent) apacheWafDir() string {
	return filepath.Join(filepath.Dir(a.L.ApacheVhosts), "bpanel-waf.d")
}

// wafProbe never fakes: every reported path exists on the host.
func (a *Agent) wafProbe() rpc.NetsecWafStatusResult {
	r := rpc.NetsecWafStatusResult{Status: "not_installed"}
	crsDir := firstDirWithConf(wafCRSRuleDirs)
	if crsDir != "" {
		r.Paths.CRSRules = filepath.Join(crsDir, "*.conf")
	} else {
		r.Missing = append(r.Missing, "owasp-crs")
	}
	r.Paths.CRSSetup = firstFile(wafCRSSetups)
	if r.Paths.CRSSetup == "" {
		r.Missing = append(r.Missing, "crs-setup.conf")
	}
	r.Paths.ModSecConf = firstFile(wafModSecConfs)
	switch {
	case firstExec(wafNginxBins) != "" && firstFile(wafNginxModules) != "":
		r.Server, r.Module = "nginx", firstFile(wafNginxModules)
		if r.Paths.ModSecConf == "" {
			r.Missing = append(r.Missing, "modsecurity.conf")
		}
	case firstExec(wafApacheBins) != "" && firstFile(wafApacheModules) != "":
		r.Server, r.Module = "apache", firstFile(wafApacheModules)
		// mod_security2 loads its base config and (on Alma) the CRS globally;
		// per-vhost includes only set the engine mode and exclusions.
		r.Paths.ModSecConf = ""
	default:
		r.Missing = append(r.Missing, "modsecurity-module")
	}
	if len(r.Missing) == 0 {
		r.Status = "installed"
	} else {
		r.Reason = "missing: " + strings.Join(r.Missing, ", ")
	}
	return r
}

func (a *Agent) wafStatus(ctx context.Context, _ rpc.NetsecWafStatusParams) (rpc.NetsecWafStatusResult, error) {
	return a.wafProbe(), nil
}

func (a *Agent) wafConfigTest(ctx context.Context, server string) error {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if server == "nginx" {
		bin := firstExec(wafNginxBins)
		if bin == "" {
			return errf("waf_unsupported", "nginx not found")
		}
		_, err := run(cctx, nil, wp(bin), "-t")
		return err
	}
	bin := firstExec(wafApacheBins)
	if bin == "" {
		return errf("waf_unsupported", "apachectl not found")
	}
	_, err := run(cctx, nil, wp(bin), "configtest")
	return err
}

type fileBackup struct {
	path string
	old  []byte
	had  bool
}

func backupFile(p string) fileBackup {
	b, err := os.ReadFile(p)
	return fileBackup{path: p, old: b, had: err == nil}
}

func (f fileBackup) restore() {
	if f.had {
		_ = wafWriteAtomic(f.path, f.old)
	} else {
		_ = os.Remove(f.path)
	}
}

func wafWriteAtomic(p string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (a *Agent) wafApply(ctx context.Context, p rpc.NetsecWafApplyParams) (rpc.NetsecWafApplyResult, error) {
	var res rpc.NetsecWafApplyResult
	c := p.Config
	if err := c.Normalize(); err != nil {
		return res, errf("waf_invalid", "%v", err)
	}
	pr := a.wafProbe()
	res.Server = pr.Server
	if pr.Status != "installed" {
		res.Status, res.Reason = "not_installed", pr.Reason
		return res, nil
	}
	rulesFile := filepath.Join(wafRulesDir, c.Domain+".conf")
	rules, err := netsec.RenderModSec(c, pr.Paths, p.Version)
	if err != nil {
		return res, errf("waf_invalid", "%v", err)
	}
	var snipPath, snippet, unit, vhost string
	if pr.Server == "nginx" {
		snipPath = filepath.Join(wafNginxSnippets, c.Domain+".conf")
		snippet = netsec.RenderNginxSnippet(c.Domain, rulesFile, c.Mode)
		unit, vhost = a.L.NginxUnit, filepath.Join(a.L.NginxVhosts, c.Domain+".conf")
	} else {
		snipPath = filepath.Join(a.apacheWafDir(), c.Domain+".conf")
		snippet = netsec.RenderApacheSnippet(c.Domain, rulesFile, c.Mode)
		unit, vhost = a.L.ApacheUnit, filepath.Join(a.L.ApacheVhosts, c.Domain+".conf")
	}
	if p.Vhost != nil && (p.Vhost.Domain != c.Domain) {
		return res, errf("waf_invalid", "vhost domain does not match WAF domain")
	}
	unlock := a.lock("web")
	locked := true
	defer func() {
		if locked {
			unlock()
		}
	}()
	bk := []fileBackup{backupFile(wp(rulesFile)), backupFile(wp(snipPath))}
	rollback := func() {
		for _, b := range bk {
			b.restore()
		}
	}
	if pr.Server == "apache" && c.Mode != netsec.WAFOff {
		bk = append(bk, backupFile(wp(wafApacheBaseConf)))
		if err := ensureApacheModSecBase(); err != nil {
			rollback()
			return res, errf("waf_write_failed", "cannot write the ModSecurity base config")
		}
	}
	if c.Mode == netsec.WAFOff {
		// off: no snippet at all, so the re-rendered vhost carries no directive
		_ = os.Remove(wp(rulesFile))
		_ = os.Remove(wp(snipPath))
	} else {
		if err := wafWriteAtomic(wp(rulesFile), []byte(rules)); err != nil {
			rollback()
			return res, errf("waf_write_failed", "cannot write WAF rules")
		}
		if err := wafWriteAtomic(wp(snipPath), []byte(snippet)); err != nil {
			rollback()
			return res, errf("waf_write_failed", "cannot write WAF include")
		}
	}
	if p.Vhost != nil {
		// Re-apply the vhost through the normal path: it re-renders with the
		// include (or without it for off), runs the config test, rolls the
		// vhost files back on failure and reloads on success.
		unlock()
		locked = false
		if _, err := a.vhostApply(ctx, *p.Vhost); err != nil {
			unlock = a.lock("web")
			locked = true
			rollback()
			a.Log.Warn("waf vhost re-apply failed; WAF files restored", "domain", c.Domain)
			return res, errf("waf_configtest_failed", "web server config test failed; previous WAF and vhost files restored")
		}
		res.Status, res.Wired = "applied", true
		return res, nil
	}
	if err := a.wafConfigTest(ctx, pr.Server); err != nil {
		rollback()
		a.Log.Warn("waf config test failed; files restored", "domain", c.Domain)
		return res, errf("waf_configtest_failed", "web server config test failed; previous WAF files restored")
	}
	vb, verr := os.ReadFile(wp(vhost))
	has := verr == nil && strings.Contains(string(vb), snipPath)
	if (c.Mode != netsec.WAFOff && has) || (c.Mode == netsec.WAFOff && verr == nil && !has) {
		res.Wired = true
		if err := wafReload(a, ctx, unit); err != nil {
			a.Log.Warn("waf reload", "err", err)
		}
	}
	res.Status = "applied"
	if !res.Wired {
		res.Reason = "vhost_not_wired"
	}
	return res, nil
}

// Debian and Ubuntu ship mod_security2's base settings only as
// modsecurity.conf-recommended, which security2.conf does not load: without
// it there is no audit log (SecAuditLog) and no request-body inspection.
var (
	wafApacheBaseConf        = "/etc/modsecurity/modsecurity.conf"
	wafApacheBaseRecommended = "/etc/modsecurity/modsecurity.conf-recommended"
)

// ensureApacheModSecBase installs the recommended base config when none
// exists, with the engine Off globally: every domain's mode comes from its
// own include (SecRuleEngine On / DetectionOnly), so sites without a WAF
// setting are not inspected. An existing modsecurity.conf is never touched.
func ensureApacheModSecBase() error {
	if _, err := os.Stat(wp(wafApacheBaseConf)); err == nil {
		return nil
	}
	rec, err := os.ReadFile(wp(wafApacheBaseRecommended))
	if err != nil {
		return nil // no recommended file (e.g. AlmaLinux ships its own base config)
	}
	lines := strings.Split(string(rec), "\n")
	for i, l := range lines {
		switch t := strings.TrimSpace(l); {
		case strings.HasPrefix(t, "SecRuleEngine "):
			lines[i] = "SecRuleEngine Off"
		case strings.HasPrefix(t, "SecRequestBodyLimitAction "):
			// inspect the first 13 MB of large uploads instead of refusing them
			lines[i] = "SecRequestBodyLimitAction ProcessPartial"
		}
	}
	body := "# Installed by BOZKURT PANEL from modsecurity.conf-recommended; the engine is\n" +
		"# Off here and switched on per domain by /etc/bpanel/waf/<domain>.conf.\n" + strings.Join(lines, "\n")
	return wafWriteAtomic(wp(wafApacheBaseConf), []byte(body))
}

// wafIncludesFor returns the per-domain WAF snippet paths the vhost templates
// include. A path is returned only when the snippet exists (mode != off) and,
// for nginx, the ModSecurity module is installed: nginx rejects an unknown
// "modsecurity" directive, so a missing module must render nothing.
func (a *Agent) wafIncludesFor(domain string) (nginx, apache string) {
	if firstFile(wafNginxModules) != "" {
		if p := filepath.Join(wafNginxSnippets, domain+".conf"); regularFile(wp(p)) {
			nginx = p
		}
	}
	if a.L.ApacheVhosts != "" && firstFile(wafApacheModules) != "" {
		if p := filepath.Join(a.apacheWafDir(), domain+".conf"); regularFile(wp(p)) {
			apache = p
		}
	}
	return
}

func regularFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}
