// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"os"
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/netsec"
)

// v0.4 netsec C: the vhost carries the WAF include only for audit/block with
// the module installed; off (or a missing module) renders no directive.
func TestWafVhostWiring(t *testing.T) {
	ctx := context.Background()
	vh := rpc.Vhost{User: "tenant", Domain: "a.test", DocRoot: "public_html", PHPVersion: "8.3", Mode: "nginx"}
	render := func(a *Agent) string {
		t.Helper()
		ng, _, err := a.RenderVhost(vh, "/home/tenant")
		if err != nil {
			t.Fatal(err)
		}
		return string(ng)
	}
	const inc = `include "/etc/nginx/bpanel-waf.d/a.test.conf";`

	a, root := wafEnv(t, true)
	if s := render(a); strings.Contains(s, "bpanel-waf.d") {
		t.Fatalf("include before any WAF config:\n%s", s)
	}
	res, err := a.wafApply(ctx, rpc.NetsecWafApplyParams{Config: netsec.WAFConfig{Domain: "a.test", Mode: "audit"}, Version: 1})
	if err != nil || res.Status != "applied" {
		t.Fatalf("apply: %+v %v", res, err)
	}
	if s := render(a); !strings.Contains(s, inc) {
		t.Fatalf("audit: include missing:\n%s", s)
	}
	// mismatched vhost domain is refused
	bad := vh
	bad.Domain = "b.test"
	if _, err := a.wafApply(ctx, rpc.NetsecWafApplyParams{Config: netsec.WAFConfig{Domain: "a.test", Mode: "audit"}, Vhost: &bad}); err == nil {
		t.Fatal("mismatched vhost domain accepted")
	}
	// module removed → nginx would reject `modsecurity`: render nothing
	if err := os.Remove(root + "/usr/lib/nginx/modules/ngx_http_modsecurity_module.so"); err != nil {
		t.Fatal(err)
	}
	if s := render(a); strings.Contains(s, "bpanel-waf.d") {
		t.Fatalf("include rendered without module:\n%s", s)
	}
	if err := os.WriteFile(root+"/usr/lib/nginx/modules/ngx_http_modsecurity_module.so", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// off → snippet and rules removed → no directive
	if _, err := a.wafApply(ctx, rpc.NetsecWafApplyParams{Config: netsec.WAFConfig{Domain: "a.test", Mode: "off"}, Version: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root + "/etc/nginx/bpanel-waf.d/a.test.conf"); err == nil {
		t.Fatal("snippet left for mode off")
	}
	if s := render(a); strings.Contains(s, "bpanel-waf.d") || strings.Contains(s, "modsecurity") {
		t.Fatalf("off: directive rendered:\n%s", s)
	}
	// existing vhost file already including the snippet → wired:true without re-apply
	if err := os.MkdirAll(root+"/etc/nginx/bpanel.d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+"/etc/nginx/bpanel.d/a.test.conf", []byte("server { "+inc+" }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = a.wafApply(ctx, rpc.NetsecWafApplyParams{Config: netsec.WAFConfig{Domain: "a.test", Mode: "block"}, Version: 3})
	if err != nil || !res.Wired {
		t.Fatalf("want wired: %+v %v", res, err)
	}
}
