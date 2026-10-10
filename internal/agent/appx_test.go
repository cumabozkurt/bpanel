// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/appx"
)

func appxEnv(t *testing.T) *testEnv {
	e := newTestEnv(t)
	oS, oN, oU, oE, oR, oX, oW := appxStateDir, appxNginxDir, appxUnitDir, appxEnvDir, appxRuntimeBin, appxRunCmd, appxWPCLIPath
	appxStateDir, appxNginxDir = filepath.Join(e.base, "appx"), filepath.Join(e.base, "nginx-appx")
	appxUnitDir, appxEnvDir = filepath.Join(e.base, "units"), filepath.Join(e.base, "apps-env")
	appxWPCLIPath = filepath.Join(e.base, "wp-cli.phar")
	node := filepath.Join(e.base, "bin", "node")
	os.MkdirAll(filepath.Dir(node), 0o755)
	os.WriteFile(node, []byte("#!/bin/sh\necho v22.11.0\n"), 0o755)
	appxRuntimeBin = []string{node}
	appxRunCmd = func(ctx context.Context, d time.Duration, argv ...string) (string, error) {
		if argv[0] == node {
			return "v22.11.0\n", nil
		}
		return "", nil
	}
	t.Cleanup(func() {
		appxStateDir, appxNginxDir, appxUnitDir, appxEnvDir, appxRuntimeBin, appxRunCmd, appxWPCLIPath = oS, oN, oU, oE, oR, oX, oW
	})
	return e
}

func TestAppxAppApplyProxyAndUnsupported(t *testing.T) {
	e := appxEnv(t)
	ctx := context.Background()
	os.MkdirAll(filepath.Join(e.home, "apps/api"), 0o755)
	os.WriteFile(filepath.Join(e.home, "apps/api/server.js"), []byte("//"), 0o644)
	vh := rpc.Vhost{User: "tenant", Domain: "t.test", DocRoot: "public_html", PHPVersion: "8.3", Mode: "nginx"}
	app := appx.App{ID: 7, Name: "api", Runtime: "node", Version: "22", Root: "apps/api", Startup: "server.js", Domain: "t.test", URLPath: "/api", Port: 30001,
		Env: map[string]string{"TOKEN": "x"}}
	res, err := e.a.appxAppApply(ctx, rpc.AppxAppApplyParams{User: "tenant", App: app,
		Domains: []rpc.AppxDomain{{Vhost: vh, Proxies: []appx.Proxy{{URLPath: "/api", Port: 30001}}}}})
	if err != nil || res.Status != "applied" || res.Systemd || !res.Wired {
		t.Fatalf("%+v %v", res, err)
	}
	drop, _ := os.ReadFile(appxDropIn(7))
	if !strings.Contains(string(drop), "User=tenant") || !strings.Contains(string(drop), "Slice=bpanel-u-tenant.slice") {
		t.Fatalf("drop-in:\n%s", drop)
	}
	if fi, _ := os.Stat(filepath.Join(appxEnvDir, "7.env")); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Fatal("env file not 0600")
	}
	inc, _ := os.ReadFile(filepath.Join(appxNginxDir, "t.test.conf"))
	ng, _ := os.ReadFile(filepath.Join(e.base, "nginx", "t.test.conf"))
	if !strings.Contains(string(inc), "proxy_pass http://127.0.0.1:30001/;") || !strings.Contains(string(ng), "bpanel-appx.d") && !strings.Contains(string(ng), "nginx-appx/t.test.conf") {
		t.Fatalf("proxy not wired:\n%s\n%s", inc, ng)
	}
	// "/" goes through the template itself
	if _, err := e.a.appxDomains(ctx, "tenant", []rpc.AppxDomain{{Vhost: vh, Proxies: []appx.Proxy{{URLPath: "/", Port: 30001}}}}); err != nil {
		t.Fatal(err)
	}
	ng, _ = os.ReadFile(filepath.Join(e.base, "nginx", "t.test.conf"))
	if !strings.Contains(string(ng), "proxy_pass http://127.0.0.1:30001;") || regularFile(filepath.Join(appxNginxDir, "t.test.conf")) {
		t.Fatalf("root proxy:\n%s", ng)
	}
	// no systemd as PID 1: start/logs are refused, never faked
	if _, err := e.a.appxAppCtl(ctx, rpc.AppxAppRef{User: "tenant", ID: 7, Action: "start"}); code(err) != "appx_unsupported" {
		t.Fatal(err)
	}
	if _, err := e.a.appxAppLogs(ctx, rpc.AppxAppRef{User: "tenant", ID: 7}); code(err) != "appx_unsupported" {
		t.Fatal(err)
	}
	// another account cannot drive the app
	if _, err := e.a.appxAppCtl(ctx, rpc.AppxAppRef{User: "opsuser", ID: 7, Action: "stop"}); code(err) != "owned_by_another_account" {
		t.Fatal(err)
	}
	// startup outside the home / missing runtime are refused
	bad := app
	bad.Root = "../outside"
	if _, err := e.a.appxAppApply(ctx, rpc.AppxAppApplyParams{User: "tenant", App: bad}); code(err) != "appx_invalid_path" {
		t.Fatal(err)
	}
	bad = app
	bad.Version = "18"
	if _, err := e.a.appxAppApply(ctx, rpc.AppxAppApplyParams{User: "tenant", App: bad}); code(err) != "appx_runtime_missing" {
		t.Fatal(err)
	}
	if _, err := e.a.appxAppRemove(ctx, rpc.AppxAppRef{User: "tenant", ID: 7, Domains: []rpc.AppxDomain{{Vhost: vh}}}); err != nil {
		t.Fatal(err)
	}
	if regularFile(appxDropIn(7)) || regularFile(appxProxyFile("t.test")) {
		t.Fatal("remove left files")
	}
}

func wpArchive(t *testing.T) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range [][2]string{{"wordpress/index.php", "<?php"}, {"wordpress/wp-includes/version.php", "<?php $wp_version = '7.1.3';"}} {
		tw.WriteHeader(&tar.Header{Name: f[0], Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(f[1]))})
		tw.Write([]byte(f[1]))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestAppxInstallChecksumAndOwnership(t *testing.T) {
	e := appxEnv(t)
	ctx := context.Background()
	arc := wpArchive(t)
	oF, oC := appxFetch, appx.Catalog
	t.Cleanup(func() { appxFetch, appx.Catalog = oF, oC })
	appxFetch = func(ctx context.Context, url string, w io.Writer, max int64) error {
		_, err := w.Write(arc)
		return err
	}
	sum := sha256.Sum256(arc)
	wp := appx.Catalog[0]
	wp.SHA1 = ""
	wp.SHA256 = strings.Repeat("0", 64) // tampered download / wrong pin
	appx.Catalog = []appx.CatalogApp{wp}
	db := appx.WPConfig{DBName: "tenant_wp", DBUser: "tenant_wp", DBPassword: "Secret-123"}
	if _, err := e.a.appxInstall(ctx, rpc.AppxInstallParams{User: "tenant", App: "wordpress", Dest: "public_html/blog", DB: db}); code(err) != "appx_checksum_mismatch" {
		t.Fatalf("mismatch accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.home, "public_html/blog/index.php")); err == nil {
		t.Fatal("files extracted despite checksum mismatch")
	}
	wp.SHA256 = hex.EncodeToString(sum[:])
	appx.Catalog = []appx.CatalogApp{wp}
	res, err := e.a.appxInstall(ctx, rpc.AppxInstallParams{User: "tenant", App: "wordpress", Dest: "public_html/blog", DB: db})
	if err != nil || !res.Config || res.Files == 0 {
		t.Fatalf("%+v %v", res, err)
	}
	for _, f := range []string{"index.php", "wp-config.php", "wp-includes/version.php"} {
		fi, err := os.Lstat(filepath.Join(e.home, "public_html/blog", f))
		if err != nil {
			t.Fatal(err)
		}
		if st := fi.Sys().(*syscall.Stat_t); int(st.Uid) != os.Getuid() {
			t.Fatalf("%s owned by %d", f, st.Uid)
		}
	}
	if fi, _ := os.Stat(filepath.Join(e.home, "public_html/blog/wp-config.php")); fi.Mode().Perm() != 0o600 {
		t.Fatal("wp-config not 0600")
	}
	// second install into a non-empty dir is refused; escaping dest refused
	if _, err := e.a.appxInstall(ctx, rpc.AppxInstallParams{User: "tenant", App: "wordpress", Dest: "public_html/blog", DB: db}); code(err) != "appx_dest_not_empty" {
		t.Fatal(err)
	}
	if _, err := e.a.appxInstall(ctx, rpc.AppxInstallParams{User: "tenant", App: "wordpress", Dest: "../outside", DB: db}); code(err) != "appx_invalid_path" {
		t.Fatal(err)
	}
	if _, err := e.a.appxInstall(ctx, rpc.AppxInstallParams{User: "tenant", App: "matomo", Dest: "x"}); code(err) != "appx_app_unavailable" {
		t.Fatal(err)
	}
	// WordPress toolkit
	r, err := e.a.appxWP(ctx, rpc.AppxWPParams{User: "tenant", Path: "public_html/blog", Action: "maintenance_on"})
	if err != nil || !r.Maintenance || r.Version != "7.1.3" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = e.a.appxWP(ctx, rpc.AppxWPParams{User: "tenant", Path: "public_html/blog", Action: "maintenance_off"})
	if err != nil || r.Maintenance {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := e.a.appxWP(ctx, rpc.AppxWPParams{User: "tenant", Path: "public_html/blog", Action: "core_update"}); code(err) != "appx_wpcli_missing" {
		t.Fatal(err)
	}
	if _, err := e.a.appxWP(ctx, rpc.AppxWPParams{User: "tenant", Path: "public_html", Action: "info"}); code(err) != "appx_not_wordpress" {
		t.Fatal(err)
	}
}

func TestAppxWPCLIChecksum(t *testing.T) {
	e := appxEnv(t)
	oF := appxFetch
	t.Cleanup(func() { appxFetch = oF })
	appxFetch = func(ctx context.Context, url string, w io.Writer, max int64) error {
		if strings.HasSuffix(url, ".sha512") {
			_, err := w.Write([]byte(strings.Repeat("a", 128) + "\n"))
			return err
		}
		_, err := w.Write([]byte("phar"))
		return err
	}
	if _, err := e.a.appxWPCLIInstall(context.Background(), struct{}{}); code(err) != "appx_checksum_mismatch" {
		t.Fatal(err)
	}
	if regularFile(appxWPCLIPath) {
		t.Fatal("unverified phar installed")
	}
	_ = e
}
