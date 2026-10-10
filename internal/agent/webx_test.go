// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/webx"
)

const webxHash = "$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"

func webxEnv(t *testing.T) *testEnv {
	t.Helper()
	e := newTestEnv(t)
	oldS, oldN := webxStateDir, webxNginxDir
	webxStateDir, webxNginxDir = filepath.Join(e.base, "webx"), filepath.Join(e.base, "nginx-webx")
	t.Cleanup(func() { webxStateDir, webxNginxDir = oldS, oldN })
	return e
}

func TestWebxApplyWiresVhostAndRollsBack(t *testing.T) {
	e := webxEnv(t)
	ctx := context.Background()
	vh := rpc.Vhost{User: "tenant", Domain: "t.test", DocRoot: "public_html", PHPVersion: "8.3", Mode: "nginx-apache"}
	cfg := webx.Config{Domain: "t.test",
		Privacy:    []webx.PrivacyDir{{Path: "/secret", Users: []webx.PrivacyUser{{Name: "bob", Hash: webxHash}}}},
		ErrorPages: map[string]string{"404": "<h1>gone</h1>"},
		Deny:       []string{"192.0.2.1"}}
	res, err := e.a.webxApply(ctx, rpc.WebxApplyParams{User: "tenant", Config: cfg, Vhost: vh})
	if err != nil || res.Status != "applied" || !res.Wired {
		t.Fatalf("apply: %+v %v", res, err)
	}
	ng, _ := os.ReadFile(filepath.Join(e.base, "nginx", "t.test.conf"))
	inc := filepath.Join(webxNginxDir, "t.test.conf")
	if !strings.Contains(string(ng), `include "`+inc+`";`) {
		t.Fatalf("vhost lacks webx include:\n%s", ng)
	}
	snip, _ := os.ReadFile(inc)
	if !strings.Contains(string(snip), "deny 192.0.2.1;") || !strings.Contains(string(snip), `location ^~ "/secret/"`) {
		t.Fatalf("snippet:\n%s", snip)
	}
	ap, _ := os.ReadFile(filepath.Join(e.base, "apache", "t.test.conf"))
	if !strings.Contains(string(ap), "bpanel-webx.d/t.test.conf") {
		t.Fatalf("apache vhost lacks include:\n%s", ap)
	}
	hp := filepath.Join(webxStateDir, "t.test", "htpasswd", "0")
	if b, _ := os.ReadFile(hp); string(b) != "bob:"+webxHash+"\n" {
		t.Fatalf("htpasswd %q", b)
	}
	if fi, _ := os.Stat(hp); fi.Mode().Perm() != 0o640 {
		t.Fatalf("htpasswd mode %v", fi.Mode())
	}
	if b, _ := os.ReadFile(filepath.Join(webxStateDir, "t.test", "errors", "404.html")); string(b) != "<h1>gone</h1>" {
		t.Fatal("error page not stored outside the docroot")
	}

	// config test fails -> previous include, vhost and state restored
	e.a.configTestFn = func(context.Context, string) error { return errors.New("bad") }
	cfg2 := cfg
	cfg2.Deny = []string{"198.51.100.0/24"}
	if _, err := e.a.webxApply(ctx, rpc.WebxApplyParams{User: "tenant", Config: cfg2, Vhost: vh}); code(err) != "webx_configtest_failed" {
		t.Fatalf("want webx_configtest_failed, got %v", err)
	}
	if b, _ := os.ReadFile(inc); string(b) != string(snip) {
		t.Fatalf("include not rolled back:\n%s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(webxStateDir, "t.test", "config.json")); !strings.Contains(string(b), "192.0.2.1") {
		t.Fatal("state not rolled back")
	}
	e.a.configTestFn = func(context.Context, string) error { return nil }

	// another account cannot inherit or overwrite the state
	addTenant(t, e, "other")
	if _, err := e.a.webxApply(ctx, rpc.WebxApplyParams{User: "other", Config: cfg, Vhost: rpc.Vhost{User: "other", Domain: "t.test", DocRoot: "public_html"}}); code(err) != "owned_by_another_account" {
		t.Fatalf("takeover: %v", err)
	}
	if ng, _, err := e.a.RenderVhost(rpc.Vhost{User: "other", Domain: "t.test", DocRoot: "public_html"}, e.home); err != nil || strings.Contains(string(ng), "bpanel-webx") {
		t.Fatalf("other account inherited webx state: %v\n%s", err, ng)
	}
	// mismatched vhost refused
	if _, err := e.a.webxApply(ctx, rpc.WebxApplyParams{User: "tenant", Config: cfg, Vhost: rpc.Vhost{User: "tenant", Domain: "x.test", DocRoot: "public_html"}}); code(err) != "webx_invalid" {
		t.Fatalf("mismatch: %v", err)
	}
	// injection refused before anything is written
	bad := cfg
	bad.Privacy = []webx.PrivacyDir{{Path: "/a;\n}", Users: cfg.Privacy[0].Users}}
	if _, err := e.a.webxApply(ctx, rpc.WebxApplyParams{User: "tenant", Config: bad, Vhost: vh}); code(err) != "webx_invalid_path" {
		t.Fatalf("injection: %v", err)
	}
	// suspended vhost renders no extras
	sv := vh
	sv.Suspended = true
	if ng, _, _ := e.a.RenderVhost(sv, e.home); strings.Contains(string(ng), "bpanel-webx") {
		t.Fatal("suspended vhost includes web extras")
	}
	// clearing everything removes the include and the state
	if _, err := e.a.webxApply(ctx, rpc.WebxApplyParams{User: "tenant", Config: webx.Config{Domain: "t.test"}, Vhost: vh}); err != nil {
		t.Fatal(err)
	}
	if regularFile(inc) || regularFile(filepath.Join(webxStateDir, "t.test", "config.json")) {
		t.Fatal("include/state left after clearing")
	}
	ng, _ = os.ReadFile(filepath.Join(e.base, "nginx", "t.test.conf"))
	if strings.Contains(string(ng), "bpanel-webx") {
		t.Fatal("vhost still includes cleared extras")
	}
}

func TestWebxGateClassified(t *testing.T) {
	if f, ok := accountField[rpc.MWebxApply]; !ok || f.key != "user" {
		t.Fatal("webx.apply is not gated on its account")
	}
}
