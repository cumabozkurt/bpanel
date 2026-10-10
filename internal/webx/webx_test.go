// SPDX-License-Identifier: Apache-2.0

package webx

import (
	"os"
	"strings"
	"testing"
)

const hash = "$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"

func full() Config {
	return Config{
		Domain:     "Example.test",
		Privacy:    []PrivacyDir{{Path: "admin", Realm: "Staff only", Users: []PrivacyUser{{Name: "bob", Hash: hash}}}},
		Hotlink:    Hotlink{Enabled: true, Allowed: []string{"https://partner.test"}, Exts: []string{".JPG", "png"}, AllowEmpty: true},
		ErrorPages: map[string]string{"404": "<h1>nope</h1>", "503": "<h1>later</h1>"},
		MIME:       []MIMEType{{Ext: ".webmanifest", Type: "application/manifest+json"}, {Ext: "png", Type: "image/png"}},
		Deny:       []string{"192.0.2.7", "2001:db8::/32", "198.51.100.9/24"},
	}
}

func ctx(mode string) RenderCtx {
	return RenderCtx{Mode: mode, PHPSocket: "/run/php/php8.3-fpm-u.sock", DocRoot: "/home/u/public_html", Names: []string{"example.test", "www.example.test"},
		HtpasswdPaths: []string{"/var/lib/bpanel/webx/example.test/htpasswd/0"}, ErrorsDir: "/var/lib/bpanel/webx/example.test/errors"}
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := "testdata/" + name
	if os.Getenv("BPANEL_WRITE_GOLDEN") == "1" {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (regenerate with BPANEL_WRITE_GOLDEN=1)", err)
	}
	if string(want) != string(got) {
		t.Fatalf("%s mismatch:\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

func TestNormalizeAndGolden(t *testing.T) {
	c := full()
	if err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	if c.Domain != "example.test" || c.Privacy[0].Path != "/admin/" || c.Hotlink.Allowed[0] != "partner.test" ||
		c.Hotlink.Exts[0] != "jpg" || c.MIME[1].Ext != "webmanifest" || c.Deny[2] != "198.51.100.0/24" {
		t.Fatalf("normalize: %+v", c)
	}
	for _, mode := range []string{"nginx", "nginx-apache"} {
		ng, err := RenderNginx(&c, ctx(mode))
		if err != nil {
			t.Fatal(err)
		}
		golden(t, "nginx-"+mode+".conf", ng)
	}
	ap, err := RenderApache(&c, ctx("nginx-apache"))
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "apache.conf", ap)
	if string(Htpasswd(c.Privacy[0])) != "bob:"+hash+"\n" {
		t.Fatal("htpasswd")
	}
}

func TestEmptyRendersNothing(t *testing.T) {
	c := Config{Domain: "a.test", ErrorPages: map[string]string{"404": "  "}}
	if err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	ng, err := RenderNginx(&c, ctx("nginx"))
	if err != nil || ng != nil {
		t.Fatalf("empty rendered %q %v", ng, err)
	}
}

// Every injection attempt (newline, ';', braces, quotes, '$') is refused.
func TestInjectionRefused(t *testing.T) {
	evil := []string{"x;\ndeny all", "x}", "x{", `x"`, "x$y", "x\nAddType", "x y;", "x#", "x\ry", "x\\"}
	for _, e := range evil {
		cases := map[string]func(*Config){
			"path":    func(c *Config) { c.Privacy[0].Path = "/" + e + "/" },
			"realm":   func(c *Config) { c.Privacy[0].Realm = e },
			"user":    func(c *Config) { c.Privacy[0].Users[0].Name = e },
			"hash":    func(c *Config) { c.Privacy[0].Users[0].Hash = hash + e },
			"referer": func(c *Config) { c.Hotlink.Allowed = []string{e} },
			"ext":     func(c *Config) { c.Hotlink.Exts = []string{e} },
			"mimeext": func(c *Config) { c.MIME[0].Ext = e },
			"mime":    func(c *Config) { c.MIME[0].Type = "text/" + e },
			"ip":      func(c *Config) { c.Deny = []string{"192.0.2.1" + e} },
			"domain":  func(c *Config) { c.Domain = "a" + e + ".test" },
			"errcode": func(c *Config) { c.ErrorPages = map[string]string{"404" + e: "x"} },
		}
		for name, mut := range cases {
			c := full()
			mut(&c)
			if err := c.Normalize(); err == nil {
				t.Errorf("%s accepted %q", name, e)
			}
		}
	}
	// the renderer re-checks even when Normalize was bypassed
	c := full()
	_ = c.Normalize()
	c.MIME[0].Type = "text/x;\nevil"
	if _, err := RenderNginx(&c, ctx("nginx")); err == nil {
		t.Error("renderer accepted unvalidated MIME type")
	}
	c = full()
	_ = c.Normalize()
	c.Privacy[0].Realm = "a\"b"
	if _, err := RenderApache(&c, ctx("nginx-apache")); err == nil {
		t.Error("renderer accepted unvalidated realm")
	}
	r := ctx("nginx")
	r.DocRoot = "/home/u/x;"
	c = full()
	_ = c.Normalize()
	if _, err := RenderNginx(&c, r); err == nil {
		t.Error("renderer accepted unsafe docroot")
	}
}

func TestValidators(t *testing.T) {
	for _, p := range []string{"/", "", "../etc", "/a/../b", "/.git/", "/a//.env"} {
		if _, err := CleanPath(p); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}
	if p, err := CleanPath("//a/b"); err != nil || p != "/a/b/" {
		t.Errorf("clean: %q %v", p, err)
	}
	for _, ip := range []string{"0.0.0.0/0", "::/0", "300.1.1.1", "fe80::1%eth0", "1.2.3.4/33", "example.com"} {
		if _, err := ParseDeny(ip); err == nil {
			t.Errorf("deny %q accepted", ip)
		}
	}
	if v, _ := ParseDeny("::ffff:192.0.2.1"); v != "192.0.2.1" {
		t.Errorf("unmap: %q", v)
	}
	for _, m := range []MIMEType{{"php", "text/plain"}, {"phtml", "text/html"}, {"x", "evil/type"}, {"x", "text"}, {"x", "text/"}} {
		if ValidMIME(&m) == nil {
			t.Errorf("mime %+v accepted", m)
		}
	}
	if ValidErrorCode("418") || ValidErrorCode("0404") || !ValidErrorCode("502") {
		t.Error("error codes")
	}
	c := Config{Domain: "a.test", Hotlink: Hotlink{Enabled: true}}
	if c.Normalize() == nil {
		t.Error("hotlink without extensions accepted")
	}
	c = Config{Domain: "a.test", ErrorPages: map[string]string{"404": strings.Repeat("x", MaxErrorPage+1)}}
	if c.Normalize() == nil {
		t.Error("oversized error page accepted")
	}
}
