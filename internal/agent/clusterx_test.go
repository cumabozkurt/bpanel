// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/clusterx"
	"github.com/cumabozkurt/bpanel/internal/distro"
)

func clusterTestAgent(t *testing.T) (*Agent, string) {
	d := t.TempDir()
	a := New(Config{OwnersDir: filepath.Join(d, "owners"), NetsecDir: filepath.Join(d, "ns"), NoSystemd: true}, &distro.Layout{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return a, d
}

func rpcCode(err error) string {
	var re *rpc.Error
	if errors.As(err, &re) {
		return re.Code
	}
	return ""
}

func TestClusterApplyWritesAndRollsBack(t *testing.T) {
	a, d := clusterTestAgent(t)
	oldPath, oldHave, oldRestart, oldHealth, oldKind, oldNote, oldGap := ClusterConfPath, clusterHave, clusterRestart, clusterHealth, clusterZoneKind, clusterZoneNote, clusterHealthGap
	defer func() {
		ClusterConfPath, clusterHave, clusterRestart, clusterHealth, clusterZoneKind, clusterZoneNote, clusterHealthGap = oldPath, oldHave, oldRestart, oldHealth, oldKind, oldNote, oldGap
	}()
	clusterHealthGap = time.Millisecond
	ctx := context.Background()

	// pdns absent -> not_installed, nothing written
	ClusterConfPath = filepath.Join(d, "pdns.d", "bpanel-cluster.conf")
	clusterHave = func(string) bool { return false }
	res, err := a.clusterApply(ctx, rpc.ClusterApplyReq{Secondaries: []string{"192.0.2.2"}})
	if err != nil || res.Status != "not_installed" {
		t.Fatalf("absent: %+v %v", res, err)
	}
	clusterHave = func(string) bool { return true }
	res, _ = a.clusterApply(ctx, rpc.ClusterApplyReq{Secondaries: []string{"192.0.2.2"}})
	if res.Status != "not_installed" || !strings.Contains(res.Reason, "pdns.d") {
		t.Fatalf("no include dir: %+v", res)
	}
	os.MkdirAll(filepath.Dir(ClusterConfPath), 0o755)

	restarts, healthy := 0, true
	clusterRestart = func(*Agent, context.Context) error { restarts++; return nil }
	clusterHealth = func(*Agent, context.Context) error {
		if healthy {
			return nil
		}
		return errors.New("down")
	}
	kinds := []string{}
	clusterZoneKind = func(_ *Agent, _ context.Context, z string) error { kinds = append(kinds, z); return nil }
	clusterZoneNote = func(_ *Agent, _ context.Context, z string) error {
		if z == "bad.test" {
			return errors.New("x")
		}
		return nil
	}
	// invalid IP never reaches the disk
	if _, err := a.clusterApply(ctx, rpc.ClusterApplyReq{Secondaries: []string{"127.0.0.1"}}); rpcCode(err) != "cluster_invalid_ip" {
		t.Fatalf("loopback: %v", err)
	}
	res, err = a.clusterApply(ctx, rpc.ClusterApplyReq{Secondaries: []string{"192.0.2.2", "192.0.2.3"}, Zones: []string{"example.test", "bad.test"}})
	if err != nil || res.Status != "ok" || res.Notified != 1 || res.ZoneErrors["bad.test"] != "notify" || restarts != 1 || len(kinds) != 2 {
		t.Fatalf("apply: %+v %v restarts=%d kinds=%v", res, err, restarts, kinds)
	}
	b, _ := os.ReadFile(ClusterConfPath)
	if !strings.Contains(string(b), "allow-axfr-ips=192.0.2.2,192.0.2.3") {
		t.Fatalf("conf: %s", b)
	}
	// unchanged config: no restart
	a.clusterApply(ctx, rpc.ClusterApplyReq{Secondaries: []string{"192.0.2.3", "192.0.2.2"}})
	if restarts != 1 {
		t.Fatalf("restarted without change: %d", restarts)
	}
	// pdns does not come back -> previous file restored, error
	healthy = false
	_, err = a.clusterApply(ctx, rpc.ClusterApplyReq{Secondaries: []string{"198.51.100.9"}})
	if rpcCode(err) != "cluster_reload_failed" {
		t.Fatalf("rollback: %v", err)
	}
	b2, _ := os.ReadFile(ClusterConfPath)
	if string(b2) != string(b) {
		t.Fatalf("not rolled back: %s", b2)
	}
	// empty list removes the managed file
	healthy = true
	if res, err := a.clusterApply(ctx, rpc.ClusterApplyReq{}); err != nil || res.Status != "ok" {
		t.Fatal(err)
	}
	if _, err := os.Stat(ClusterConfPath); !os.IsNotExist(err) {
		t.Fatal("conf not removed")
	}
}

func TestPluginInstallRemove(t *testing.T) {
	a, d := clusterTestAgent(t)
	old := PluginRoot
	defer func() { PluginRoot = old }()
	PluginRoot = filepath.Join(d, "plugins")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	files := map[string][]byte{
		"plugin.json":   []byte(`{"name":"hello","version":"1.0.0","author":"T","license":"MIT","permissions":["ui.page"],"ui_entry":"index.html"}`),
		"ui/index.html": []byte("<h1>hi</h1>"),
		"ui/js/app.js":  []byte("1"),
	}
	files["plugin.sig"] = clusterx.Sign(files, priv)
	ctx := context.Background()
	if _, err := a.pluginInstall(ctx, rpc.PluginInstallReq{Name: "other", Archive: clusterx.PackTarGz(files)}); rpcCode(err) != "plugin_invalid_manifest" {
		t.Fatalf("name mismatch: %v", err)
	}
	res, err := a.pluginInstall(ctx, rpc.PluginInstallReq{Name: "hello", Archive: clusterx.PackTarGz(files)})
	if err != nil || res.Files != 4 {
		t.Fatalf("install: %+v %v", res, err)
	}
	if b, _ := os.ReadFile(filepath.Join(PluginRoot, "hello", "ui", "js", "app.js")); string(b) != "1" {
		t.Fatal("file missing")
	}
	// upgrade replaces atomically, no staging leftovers
	files["ui/js/app.js"] = []byte("2")
	if _, err := a.pluginInstall(ctx, rpc.PluginInstallReq{Name: "hello", Archive: clusterx.PackTarGz(files)}); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(PluginRoot)
	if len(ents) != 1 {
		t.Fatalf("leftovers: %v", ents)
	}
	// traversal is rejected by the agent too (defence in depth)
	evil := map[string][]byte{"plugin.json": files["plugin.json"], "ui/../../x": []byte("x")}
	if _, err := a.pluginInstall(ctx, rpc.PluginInstallReq{Name: "hello", Archive: clusterx.PackTarGz(evil)}); rpcCode(err) != "plugin_unsafe_path" {
		t.Fatalf("traversal: %v", err)
	}
	if _, err := a.pluginRemove(ctx, rpc.PluginRemoveReq{Name: "../etc"}); rpcCode(err) != "plugin_invalid_manifest" {
		t.Fatalf("bad name: %v", err)
	}
	os.Symlink(d, filepath.Join(PluginRoot, "linked"))
	if _, err := a.pluginRemove(ctx, rpc.PluginRemoveReq{Name: "linked"}); rpcCode(err) != "plugin_unsafe_path" {
		t.Fatalf("symlink remove: %v", err)
	}
	if _, err := a.pluginRemove(ctx, rpc.PluginRemoveReq{Name: "hello"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(PluginRoot, "hello")); !os.IsNotExist(err) {
		t.Fatal("not removed")
	}
}
