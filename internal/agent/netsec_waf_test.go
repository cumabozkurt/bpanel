// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/distro"
	"github.com/cumabozkurt/bpanel/internal/netsec"
)

// wafEnv roots every fixed WAF path in a temp dir and installs a fake nginx
// whose `-t` exits with *exitCode (0 = config ok).
func wafEnv(t *testing.T, installed bool) (*Agent, string) {
	t.Helper()
	root := t.TempDir()
	old := wafPrefix
	wafPrefix = root
	t.Cleanup(func() { wafPrefix = old })
	mk := func(p, body string, mode os.FileMode) {
		if err := os.MkdirAll(filepath.Dir(root+p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(root+p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	mk("/usr/sbin/nginx", "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/argv.log\"\nexit $(cat \"$(dirname \"$0\")/exit\" 2>/dev/null || echo 0)\n", 0o755)
	if installed {
		mk("/usr/lib/nginx/modules/ngx_http_modsecurity_module.so", "", 0o644)
		mk("/etc/modsecurity/modsecurity.conf", "", 0o644)
		mk("/etc/modsecurity/crs/crs-setup.conf", "", 0o644)
		mk("/usr/share/modsecurity-crs/rules/REQUEST-901.conf", "", 0o644)
	}
	a := New(Config{NetsecDir: t.TempDir(), NoSystemd: true}, &distro.Layout{NginxUnit: "nginx", NginxVhosts: "/etc/nginx/bpanel.d"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return a, root
}

func TestWafNotInstalledNeverFakes(t *testing.T) {
	a, root := wafEnv(t, false)
	st, _ := a.wafStatus(context.Background(), rpc.NetsecWafStatusParams{})
	if st.Status != "not_installed" || !strings.Contains(st.Reason, "modsecurity-module") {
		t.Fatalf("status: %+v", st)
	}
	res, err := a.wafApply(context.Background(), rpc.NetsecWafApplyParams{Config: netsec.WAFConfig{Domain: "a.test", Mode: "audit"}, Version: 1})
	if err != nil || res.Status != "not_installed" {
		t.Fatalf("apply: %+v %v", res, err)
	}
	if _, err := os.Stat(root + "/etc/bpanel/waf/a.test.conf"); err == nil {
		t.Fatal("wrote files while not installed")
	}
}

func TestWafApplyAndRollbackOnConfigTestFailure(t *testing.T) {
	a, root := wafEnv(t, true)
	ctx := context.Background()
	res, err := a.wafApply(ctx, rpc.NetsecWafApplyParams{Config: netsec.WAFConfig{Domain: "a.test", Mode: "audit", Exclusions: []int{942100}}, Version: 1})
	if err != nil || res.Status != "applied" || res.Wired || res.Server != "nginx" {
		t.Fatalf("apply: %+v %v", res, err)
	}
	rules, _ := os.ReadFile(root + "/etc/bpanel/waf/a.test.conf")
	for _, want := range []string{"SecRuleEngine DetectionOnly", "Include /usr/share/modsecurity-crs/rules/*.conf", "SecRuleRemoveById 942100", "Include /etc/modsecurity/crs/crs-setup.conf"} {
		if !strings.Contains(string(rules), want) {
			t.Errorf("rules missing %q:\n%s", want, rules)
		}
	}
	snip, _ := os.ReadFile(root + "/etc/nginx/bpanel-waf.d/a.test.conf")
	if !strings.Contains(string(snip), "modsecurity_rules_file /etc/bpanel/waf/a.test.conf;") {
		t.Fatalf("snippet: %s", snip)
	}
	argv, _ := os.ReadFile(root + "/usr/sbin/argv.log")
	if strings.TrimSpace(string(argv)) != "-t" {
		t.Fatalf("config test argv: %q", argv)
	}
	// failing config test → previous files restored
	if err := os.WriteFile(root+"/usr/sbin/exit", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = a.wafApply(ctx, rpc.NetsecWafApplyParams{Config: netsec.WAFConfig{Domain: "a.test", Mode: "block"}, Version: 2})
	var re *rpc.Error
	if err == nil || !errors.As(err, &re) || re.Code != "waf_configtest_failed" {
		t.Fatalf("want waf_configtest_failed, got %v", err)
	}
	after, _ := os.ReadFile(root + "/etc/bpanel/waf/a.test.conf")
	if string(after) != string(rules) {
		t.Fatalf("rules not rolled back:\n%s", after)
	}
	// a brand-new domain whose test fails leaves no files behind
	_, _ = a.wafApply(ctx, rpc.NetsecWafApplyParams{Config: netsec.WAFConfig{Domain: "b.test", Mode: "audit"}, Version: 1})
	if _, err := os.Stat(root + "/etc/bpanel/waf/b.test.conf"); err == nil {
		t.Fatal("new file left after failed test")
	}
	// invalid input is refused before touching anything
	if _, err := a.wafApply(ctx, rpc.NetsecWafApplyParams{Config: netsec.WAFConfig{Domain: "../etc", Mode: "audit"}}); err == nil {
		t.Fatal("path domain accepted")
	}
}

// On Debian/Ubuntu Apache only modsecurity.conf-recommended exists; the first
// apply installs it as modsecurity.conf with the engine Off globally, and a
// later apply never overwrites an admin's own file.
func TestWafApacheBaseConfigInstalled(t *testing.T) {
	_, root := wafEnv(t, false)
	rec := "SecRuleEngine DetectionOnly\nSecRequestBodyAccess On\nSecAuditLog /var/log/apache2/modsec_audit.log\n"
	if err := os.MkdirAll(root+"/etc/modsecurity", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+wafApacheBaseRecommended, []byte(rec), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureApacheModSecBase(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(root + wafApacheBaseConf)
	if !strings.Contains(string(got), "\nSecRuleEngine Off\n") || strings.Contains(string(got), "DetectionOnly") ||
		!strings.Contains(string(got), "SecAuditLog /var/log/apache2/modsec_audit.log") {
		t.Fatalf("base config:\n%s", got)
	}
	if err := os.WriteFile(root+wafApacheBaseConf, []byte("# admin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureApacheModSecBase(); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(root + wafApacheBaseConf); string(got) != "# admin\n" {
		t.Fatalf("admin file overwritten: %s", got)
	}
}
