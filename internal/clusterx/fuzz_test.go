// SPDX-License-Identifier: Apache-2.0

package clusterx

import (
	"strings"
	"testing"
)

func FuzzPluginLoad(f *testing.F) {
	f.Add(PackTarGz(map[string][]byte{"plugin.json": []byte(`{"name":"hello","version":"1.0.0","author":"a","license":"MIT","permissions":[]}`), "ui/index.html": []byte("<p>")}))
	f.Add(PackTarGz(map[string][]byte{"../evil": []byte("x")}))
	f.Add([]byte("not a tarball"))
	f.Fuzz(func(t *testing.T, data []byte) {
		files, err := Extract(data)
		if err != nil {
			return
		}
		for p := range files {
			if !ValidRelPath(p) {
				t.Fatalf("Extract returned invalid path %q", p)
			}
		}
		_, _, _ = Load(data)
	})
}

func FuzzManifest(f *testing.F) {
	f.Add([]byte(`{"name":"hello","version":"1.0.0","author":"a","license":"MIT","permissions":["read:accounts"],"ui_entry":"index.html","hooks":[{"events":["account.created"],"url":"https://x.test/h"}]}`))
	f.Add([]byte(`{"name":"../x","ui_entry":"../../etc/passwd"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := ParseManifest(data)
		if err != nil || m == nil {
			return
		}
		if m.Validate(nil) == nil {
			if !ValidName(m.Name) {
				t.Fatalf("invalid name accepted %q", m.Name)
			}
			if m.UIEntry != "" && (strings.Contains(m.UIEntry, "..") || strings.HasPrefix(m.UIEntry, "/")) {
				t.Fatalf("ui_entry escapes: %q", m.UIEntry)
			}
		}
	})
}

func FuzzRelPathAndIPs(f *testing.F) {
	for _, s := range []string{"ui/a.js", "../a", "a//b", "/abs", "192.0.2.1", "::1", "10.0.0.1;x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if ValidRelPath(s) && (strings.HasPrefix(s, "/") || strings.Contains("/"+s+"/", "/../") || strings.ContainsAny(s, "\x00\\")) {
			t.Fatalf("ValidRelPath(%q) true", s)
		}
		if ip, err := ValidateSecondaryIP(s); err == nil {
			if strings.ContainsAny(ip, " ;\n{}\"") {
				t.Fatalf("ip %q unsafe", ip)
			}
			if _, err := RenderPdnsConf([]string{ip}); err != nil {
				t.Fatalf("valid ip %q not renderable: %v", ip, err)
			}
		}
	})
}
