// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/clusterx"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// v0.4 clusterx. The DNS cluster uses PowerDNS's own primary/secondary
// replication (AXFR + NOTIFY; PowerDNS is GPL-2.0 and runs as a separate
// process). The agent owns one include file, backs it up, restarts pdns,
// health-checks the API and rolls back when pdns does not come back.
// Plugins are only ever static files: the agent re-runs the same safe
// extraction as the API and writes them under PluginRoot.

var (
	ClusterConfPath = "/etc/powerdns/pdns.d/bpanel-cluster.conf"
	PluginRoot      = "/usr/local/bpanel/plugins"
	clusterHave     = have
	clusterRestart  = func(a *Agent, ctx context.Context) error { return a.systemctl(ctx, "restart", a.L.PDNSUnit) }
	clusterHealth   = func(a *Agent, ctx context.Context) error { return a.pdns(ctx, "GET", "", nil, nil) }
	clusterZoneKind = func(a *Agent, ctx context.Context, zone string) error {
		return a.pdns(ctx, "PUT", "/zones/"+fqdn(zone), map[string]any{"kind": "Master"}, nil)
	}
	clusterZoneNote = func(a *Agent, ctx context.Context, zone string) error {
		return a.pdns(ctx, "PUT", "/zones/"+fqdn(zone)+"/notify", nil, nil)
	}
	clusterHealthTry = 10
	clusterHealthGap = time.Second
)

func init() {
	gateExempt[rpc.MClusterApply] = "server (PowerDNS include file; admin-only API, IPs validated, backup + rollback)"
	gateExempt[rpc.MPluginInstall] = "server (static plugin files under PluginRoot; admin-only API, archive re-validated)"
	gateExempt[rpc.MPluginRemove] = "server (removes PluginRoot/<name>; name validated, symlinks refused)"
}

func (a *Agent) clusterxRoutes() map[string]handler {
	return map[string]handler{
		rpc.MClusterApply:  bind(a.clusterApply),
		rpc.MPluginInstall: bind(a.pluginInstall),
		rpc.MPluginRemove:  bind(a.pluginRemove),
	}
}

func (a *Agent) clusterApply(ctx context.Context, p rpc.ClusterApplyReq) (rpc.ClusterApplyResult, error) {
	res := rpc.ClusterApplyResult{ConfPath: ClusterConfPath}
	conf, err := clusterx.RenderPdnsConf(p.Secondaries)
	if err != nil {
		return res, errf("cluster_invalid_ip", "%v", err)
	}
	if len(p.Zones) > 5000 {
		return res, errf("invalid_domain", "too many zones")
	}
	for _, z := range p.Zones {
		if err := validate.Domain(strings.TrimSuffix(z, ".")); err != nil {
			return res, errf("invalid_domain", "%s", z)
		}
	}
	if !clusterHave("pdns_server") && !clusterHave("pdnsutil") {
		res.Status, res.Reason = "not_installed", "PowerDNS Authoritative (pdns_server) is not installed"
		return res, nil
	}
	dir := filepath.Dir(ClusterConfPath)
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		res.Status, res.Reason = "not_installed", dir+" does not exist (PowerDNS include-dir)"
		return res, nil
	}
	defer a.lock("pdns")()
	old, oerr := os.ReadFile(ClusterConfPath)
	hadOld := oerr == nil
	if !hadOld && !errors.Is(oerr, os.ErrNotExist) {
		return res, errf("cluster_write_failed", "read current config")
	}
	if string(old) != conf {
		if conf == "" {
			if err := os.Remove(ClusterConfPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return res, errf("cluster_write_failed", "remove config")
			}
		} else if err := writeAtomic(ClusterConfPath, []byte(conf), 0o644, -1, -1); err != nil {
			return res, errf("cluster_write_failed", "write config")
		}
		if err := a.clusterRestartHealthy(ctx); err != nil {
			// roll back to the previous file and bring pdns back
			if hadOld {
				_ = writeAtomic(ClusterConfPath, old, 0o644, -1, -1)
			} else {
				_ = os.Remove(ClusterConfPath)
			}
			_ = a.clusterRestartHealthy(ctx)
			return res, errf("cluster_reload_failed", "PowerDNS did not come back with the new configuration; previous configuration restored")
		}
	}
	res.ZoneErrors = map[string]string{}
	if conf != "" {
		zones := append([]string(nil), p.Zones...)
		sort.Strings(zones)
		for _, z := range zones {
			if err := clusterZoneKind(a, ctx, z); err != nil {
				res.ZoneErrors[z] = "kind"
				continue
			}
			if err := clusterZoneNote(a, ctx, z); err != nil {
				res.ZoneErrors[z] = "notify"
				continue
			}
			res.Notified++
		}
	}
	res.Status = "ok"
	return res, nil
}

func (a *Agent) clusterRestartHealthy(ctx context.Context) error {
	if err := clusterRestart(a, ctx); err != nil {
		return err
	}
	var err error
	for i := 0; i < clusterHealthTry; i++ {
		if err = clusterHealth(a, ctx); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(clusterHealthGap):
		}
	}
	return err
}

func pluginDir(name string) (string, error) {
	if !clusterx.ValidName(name) {
		return "", errf("plugin_invalid_manifest", "invalid plugin name")
	}
	return filepath.Join(PluginRoot, name), nil
}

func (a *Agent) pluginInstall(ctx context.Context, p rpc.PluginInstallReq) (rpc.PluginResult, error) {
	res := rpc.PluginResult{}
	files, m, err := clusterx.Load(p.Archive)
	if err != nil {
		var ce *clusterx.Error
		if errors.As(err, &ce) {
			return res, errf(ce.Code, "%s", ce.Msg)
		}
		return res, errf("plugin_invalid_archive", "invalid archive")
	}
	if m.Name != p.Name {
		return res, errf("plugin_invalid_manifest", "manifest name does not match")
	}
	dst, err := pluginDir(m.Name)
	if err != nil {
		return res, err
	}
	defer a.lock("plugins")()
	if err := os.MkdirAll(PluginRoot, 0o755); err != nil {
		return res, errf("plugin_write_failed", "create plugin root")
	}
	if st, err := os.Lstat(PluginRoot); err != nil || !st.IsDir() {
		return res, errf("plugin_write_failed", "plugin root is not a directory")
	}
	rnd := make([]byte, 6)
	_, _ = rand.Read(rnd)
	tmp := filepath.Join(PluginRoot, "."+m.Name+".tmp-"+hex.EncodeToString(rnd))
	if err := os.Mkdir(tmp, 0o755); err != nil {
		return res, errf("plugin_write_failed", "create staging dir")
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tmp)
		}
	}()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		target := filepath.Join(tmp, filepath.FromSlash(n))
		if !strings.HasPrefix(target, tmp+string(os.PathSeparator)) {
			return res, errf("plugin_unsafe_path", "path escapes the plugin directory")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return res, errf("plugin_write_failed", "mkdir")
		}
		f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
		if err != nil {
			return res, errf("plugin_write_failed", "create file")
		}
		_, werr := f.Write(files[n])
		cerr := f.Close()
		if werr != nil || cerr != nil {
			return res, errf("plugin_write_failed", "write file")
		}
	}
	old := ""
	if _, err := os.Lstat(dst); err == nil {
		old = filepath.Join(PluginRoot, "."+m.Name+".old-"+hex.EncodeToString(rnd))
		if err := os.Rename(dst, old); err != nil {
			return res, errf("plugin_write_failed", "move old version aside")
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		if old != "" {
			_ = os.Rename(old, dst)
		}
		return res, errf("plugin_write_failed", "activate plugin")
	}
	cleanup = false
	if old != "" {
		_ = os.RemoveAll(old)
	}
	a.Log.Info("plugin installed", "name", m.Name, "version", m.Version, "files", len(files))
	return rpc.PluginResult{Path: dst, Files: len(files)}, nil
}

func (a *Agent) pluginRemove(ctx context.Context, p rpc.PluginRemoveReq) (rpc.Empty, error) {
	dst, err := pluginDir(p.Name)
	if err != nil {
		return rpc.Empty{}, err
	}
	defer a.lock("plugins")()
	if st, err := os.Lstat(dst); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return rpc.Empty{}, errf("plugin_unsafe_path", "plugin directory is a symlink")
	}
	if err := os.RemoveAll(dst); err != nil {
		return rpc.Empty{}, errf("plugin_write_failed", "remove plugin")
	}
	a.Log.Info("plugin removed", "name", p.Name)
	return rpc.Empty{}, nil
}
