// SPDX-License-Identifier: Apache-2.0

package agent

// v0.4 webx: per-domain web extras. webx.apply validates the config,
// stores it with its password files and error pages under
// /var/lib/bpanel/webx/<domain>/ (outside every docroot, root-owned), then
// re-applies the vhost through vhostApply. vhostApply renders ONE nginx
// include (/etc/nginx/bpanel-webx.d/<domain>.conf) and ONE Apache include
// (<apache conf>/bpanel-webx.d/<domain>.conf) from that state in the same
// transaction as the vhost, runs the config test and rolls everything back on
// failure; webx.apply then also restores the previous state directory.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/webx"
)

var (
	webxStateDir = "/var/lib/bpanel/webx"
	webxNginxDir = "/etc/nginx/bpanel-webx.d"
)

// webxState is what is stored per domain; User binds it to the account so a
// domain later re-added by another account never inherits it.
type webxState struct {
	User   string      `json:"user"`
	Config webx.Config `json:"config"`
}

func (a *Agent) webxRoutes() map[string]handler {
	return map[string]handler{rpc.MWebxApply: bind(a.webxApply)}
}

func init() {
	accountField[rpc.MWebxApply] = struct {
		key      string
		optional bool
	}{"user", false}
}

func (a *Agent) apacheWebxDir() string {
	return filepath.Join(filepath.Dir(a.L.ApacheVhosts), "bpanel-webx.d")
}

func webxDomainDir(domain string) string { return filepath.Join(webxStateDir, domain) }

// webxFor renders the includes for a validated vhost; nil when the domain
// has no extras (or is suspended / a redirect, which serve nothing else).
func (a *Agent) webxFor(d vhostData) (ng, ap []byte, err error) {
	if d.Suspended || d.Redirect != "" || !webx.ValidDomain(d.Domain) {
		return nil, nil, nil
	}
	b, rerr := os.ReadFile(filepath.Join(webxDomainDir(d.Domain), "config.json"))
	if rerr != nil {
		return nil, nil, nil
	}
	var st webxState
	if json.Unmarshal(b, &st) != nil || st.User != d.User {
		return nil, nil, nil
	}
	c := st.Config
	if c.Normalize() != nil || c.Domain != d.Domain || c.Empty() {
		return nil, nil, nil
	}
	dir := webxDomainDir(d.Domain)
	rc := webx.RenderCtx{Mode: d.Mode, PHPSocket: d.PHPSocket, DocRoot: d.DocRoot, Names: d.Names, ErrorsDir: filepath.Join(dir, "errors")}
	for i := range c.Privacy {
		rc.HtpasswdPaths = append(rc.HtpasswdPaths, filepath.Join(dir, "htpasswd", strconv.Itoa(i)))
	}
	if ng, err = webx.RenderNginx(&c, rc); err != nil {
		return nil, nil, errf("webx_invalid", "%v", err)
	}
	if d.Mode == "nginx-apache" {
		if ap, err = webx.RenderApache(&c, rc); err != nil {
			return nil, nil, errf("webx_invalid", "%v", err)
		}
	}
	return ng, ap, nil
}

// webxWrite writes the include files inside the vhost transaction.
func (a *Agent) webxWrite(tx *transaction, domain string, ng, ap []byte) error {
	np := filepath.Join(webxNginxDir, domain+".conf")
	var err error
	if ng != nil {
		err = tx.write(np, ng, 0o644)
	} else {
		err = tx.remove(np)
	}
	if err != nil || a.L.ApacheVhosts == "" {
		return err
	}
	apPath := filepath.Join(a.apacheWebxDir(), domain+".conf")
	if ap != nil {
		return tx.write(apPath, ap, 0o644)
	}
	return tx.remove(apPath)
}

// dirSnapshot keeps every regular file below a directory for rollback.
type dirSnapshot struct {
	root  string
	files map[string][]byte
	modes map[string]os.FileMode
	gids  map[string]int
}

func snapshotDir(root string) dirSnapshot {
	s := dirSnapshot{root: root, files: map[string][]byte{}, modes: map[string]os.FileMode{}, gids: map[string]int{}}
	_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			if b, e := os.ReadFile(p); e == nil {
				s.files[p], s.modes[p] = b, fi.Mode().Perm()
			}
		}
		return nil
	})
	return s
}

func (s dirSnapshot) restore() {
	_ = os.RemoveAll(s.root)
	for p, b := range s.files {
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, b, s.modes[p])
	}
}

func webxPut(p string, b []byte, mode os.FileMode, gid int) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	_ = os.Chmod(tmp, mode)
	if gid >= 0 {
		_ = os.Chown(tmp, 0, gid)
	}
	return os.Rename(tmp, p)
}

func (a *Agent) webxApply(ctx context.Context, p rpc.WebxApplyParams) (rpc.WebxApplyResult, error) {
	var res rpc.WebxApplyResult
	c := p.Config
	if err := c.Normalize(); err != nil {
		if e, ok := err.(*webx.Error); ok {
			return res, errf(e.Code, "%s", e.Msg)
		}
		return res, errf("webx_invalid", "%v", err)
	}
	if p.Vhost.User != p.User || normName(p.Vhost.Domain) != c.Domain {
		return res, errf("webx_invalid", "vhost does not match the domain or account")
	}
	if o, had, err := a.readOwner(kindWeb, c.Domain); err != nil {
		return res, err
	} else if had && o.Owner != p.User {
		return res, errf("owned_by_another_account", "%s is served for another account", c.Domain)
	}
	defer a.lock("webx")()
	dir := webxDomainDir(c.Domain)
	snap := snapshotDir(dir)
	gid := -1
	if g, err := groupID(a.L.WebGroup); err == nil {
		gid = g
	}
	write := func() error {
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
		if c.Empty() {
			return nil
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		for i, d := range c.Privacy {
			// 0640 root:<web group>: nginx/Apache read it, tenants cannot
			if err := webxPut(filepath.Join(dir, "htpasswd", strconv.Itoa(i)), webx.Htpasswd(d), 0o640, gid); err != nil {
				return err
			}
		}
		for _, k := range c.SortedErrorCodes() {
			if err := webxPut(filepath.Join(dir, "errors", k+".html"), []byte(c.ErrorPages[k]), 0o644, -1); err != nil {
				return err
			}
		}
		b, _ := json.Marshal(webxState{User: p.User, Config: c})
		return webxPut(filepath.Join(dir, "config.json"), b, 0o600, -1)
	}
	if err := write(); err != nil {
		snap.restore()
		return res, errf("webx_write_failed", "cannot write web extras")
	}
	if _, err := a.vhostApply(ctx, p.Vhost); err != nil {
		snap.restore()
		a.Log.Warn("webx vhost re-apply failed; previous state restored", "domain", c.Domain)
		if e, ok := err.(*rpc.Error); ok && (e.Code == "nginx_config_invalid" || e.Code == "apache_config_invalid") {
			return res, errf("webx_configtest_failed", "web server config test failed; previous configuration restored")
		}
		return res, err
	}
	res.Status = "applied"
	res.Wired = regularFile(filepath.Join(webxNginxDir, c.Domain+".conf"))
	return res, nil
}
