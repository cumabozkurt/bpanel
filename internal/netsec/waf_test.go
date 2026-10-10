// SPDX-License-Identifier: Apache-2.0

package netsec

import (
	"strings"
	"testing"
)

func TestWAFExclusionValidation(t *testing.T) {
	for _, bad := range [][]string{{"12a"}, {"1 2"}, {"-5"}, {"0"}, {"99999999"}, {"942100\nSecRuleEngine Off"}, {"0x10"}} {
		if _, err := ParseWAFExclusions(bad); err == nil || !IsCode(err, "waf_invalid") {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
	got, err := ParseWAFExclusions([]string{" 942100", "920350", "942100", ""})
	if err != nil || len(got) != 2 || got[0] != 920350 {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestWAFRender(t *testing.T) {
	p := WAFPaths{ModSecConf: "/etc/modsecurity/modsecurity.conf", CRSSetup: "/etc/modsecurity/crs/crs-setup.conf", CRSRules: "/usr/share/modsecurity-crs/rules/*.conf"}
	s, err := RenderModSec(WAFConfig{Domain: "Ex.test"}, p, 3)
	if err != nil || !strings.Contains(s, "SecRuleEngine DetectionOnly") || !strings.Contains(s, "version 3") {
		t.Fatalf("default audit: %v\n%s", err, s)
	}
	s, _ = RenderModSec(WAFConfig{Domain: "ex.test", Mode: WAFBlock, Exclusions: []int{5, 3}}, p, 1)
	if !strings.Contains(s, "SecRuleEngine On") || strings.Index(s, "SecRuleRemoveById 3") > strings.Index(s, "SecRuleRemoveById 5") {
		t.Fatalf("block:\n%s", s)
	}
	s, _ = RenderModSec(WAFConfig{Domain: "ex.test", Mode: WAFOff, Exclusions: []int{5}}, p, 1)
	if !strings.Contains(s, "SecRuleEngine Off") || strings.Contains(s, "Include") {
		t.Fatalf("off:\n%s", s)
	}
	for _, d := range []string{"../x", "a/b.test", "a", "x.test;", ""} {
		if _, err := RenderModSec(WAFConfig{Domain: d}, p, 1); err == nil {
			t.Errorf("domain %q accepted", d)
		}
	}
	if !strings.Contains(RenderNginxSnippet("a.test", "/etc/bpanel/waf/a.test.conf", WAFAudit), "modsecurity on;") {
		t.Fatal("nginx snippet")
	}
}
