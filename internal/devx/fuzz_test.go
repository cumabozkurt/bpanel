// SPDX-License-Identifier: Apache-2.0

package devx

import (
	"strings"
	"testing"

	"github.com/cumabozkurt/bpanel/internal/validate"
)

// FuzzHostAndToken covers DDNS/hostname-shaped inputs: lookup targets,
// DDNS tokens, clone URLs, repo paths and the shared domain validator.
func FuzzHostAndToken(f *testing.F) {
	for _, s := range []string{"example.test", "-oProxyCommand=x", "1.2.3.4", "a..b", "https://github.com/a/b.git", "git@github.com:a/b.git", "ext::sh -c x", "sub.example.test.", "bpt_x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if ValidHost(s) {
			h := strings.TrimSuffix(strings.TrimSpace(s), ".")
			if strings.HasPrefix(h, "-") || strings.ContainsAny(h, " \t\r\n\x00;|&$`'\"/\\") {
				t.Fatalf("ValidHost(%q) accepted unsafe", s)
			}
		}
		if WellFormedToken(s) && strings.ContainsAny(s, " \r\n\x00&?#=/") {
			t.Fatalf("token %q accepted", s)
		}
		if p, err := CleanRel(s); err == nil {
			if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "-") || strings.Contains("/"+p+"/", "/../") {
				t.Fatalf("CleanRel(%q)=%q", s, p)
			}
		}
		_, _ = ParseCloneURL(s)
		_ = ValidBranch(s)
		if validate.Domain(s) == nil && validate.ConfigSafe(s) && strings.ContainsAny(s, " \r\n\x00;{}\"'") {
			t.Fatalf("domain %q accepted unsafe", s)
		}
	})
}
