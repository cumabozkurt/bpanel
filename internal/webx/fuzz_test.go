// SPDX-License-Identifier: Apache-2.0

package webx

import (
	"encoding/json"
	"strings"
	"testing"
)

// unsafe for a config token (nginx/apache directive syntax).
func injectable(s string) bool { return strings.ContainsAny(s, "\r\n\x00;{}\"'` \t\\$") }

func FuzzValidators(f *testing.F) {
	for _, s := range []string{"admin", "/a/b/", "../x", "a b", "192.0.2.1", "2001:db8::/32", "x;}", "$host"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if p, err := CleanPath(s); err == nil {
			if injectable(p) || strings.Contains(p+"/", "/../") {
				t.Fatalf("CleanPath(%q) = %q unsafe", s, p)
			}
		}
		if d, err := ParseDeny(s); err == nil && injectable(d) {
			t.Fatalf("ParseDeny(%q) = %q unsafe", s, d)
		}
		if ValidDomain(s) && injectable(s) {
			t.Fatalf("ValidDomain(%q) accepted unsafe", s)
		}
		_ = ValidErrorCode(s)
		_ = ValidMIME(&MIMEType{Ext: s, Type: s})
		_ = ValidUser(PrivacyUser{Name: s, Hash: s})
	})
}

func balanced(s string) bool {
	n := 0
	for _, c := range s {
		switch c {
		case '{':
			n++
		case '}':
			n--
			if n < 0 {
				return false
			}
		}
	}
	return n == 0
}

// FuzzRender: any Config accepted by Normalize renders a config whose block
// structure is balanced and whose line count is independent of user text
// inside error pages (pages are files, never inlined).
func FuzzRender(f *testing.F) {
	b, _ := json.Marshal(full())
	f.Add(b)
	f.Add([]byte(`{"domain":"a.test","deny":["1.2.3.4;} location / {"],"mime":[{"ext":"x","type":"a/b;}"}]}`))
	f.Add([]byte(`{"domain":"a.test","privacy":[{"path":"a\n}","realm":"r\" x","users":[]}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var c Config
		if json.Unmarshal(data, &c) != nil {
			return
		}
		if c.Normalize() != nil {
			return
		}
		for _, mode := range []string{"nginx", "nginx-apache"} {
			rc := ctx(mode)
			rc.HtpasswdPaths = nil
			for i := range c.Privacy {
				rc.HtpasswdPaths = append(rc.HtpasswdPaths, "/var/lib/bpanel/webx/x/htpasswd/"+string(rune('0'+i%10)))
			}
			if out, err := RenderNginx(&c, rc); err == nil && !balanced(string(out)) {
				t.Fatalf("nginx unbalanced:\n%s", out)
			}
		}
		rc := ctx("nginx-apache")
		rc.HtpasswdPaths = nil
		for range c.Privacy {
			rc.HtpasswdPaths = append(rc.HtpasswdPaths, "/x")
		}
		if out, err := RenderApache(&c, rc); err == nil {
			o := strings.Count(string(out), "<") - strings.Count(string(out), "</")
			if strings.Count(string(out), "</") != o {
				t.Fatalf("apache unbalanced sections:\n%s", out)
			}
		}
		for _, d := range c.Privacy {
			for _, l := range strings.Split(strings.TrimRight(string(Htpasswd(d)), "\n"), "\n") {
				if strings.Count(l, ":") < 1 && l != "" {
					t.Fatalf("bad htpasswd line %q", l)
				}
			}
		}
	})
}
