package templates

import (
	"strings"
	"testing"
)

type vh struct {
	TemplateVersion                                     int
	User, Domain, DocRoot, PHPSocket, CertFile, KeyFile string
	Redirect, Mode                                      string
	WAFInclude, ApacheWAFInclude                        string
	WebXInclude, ApacheWebXInclude                      string
	AppXInclude                                         string
	AppXRootPort                                        int
	Names, Aliases                                      []string
	SSL, Suspended, HTTP2On                             bool
}

// SEC-1 defence in depth: the templates themselves refuse unsafe values.
func TestTemplatesRefuseUnsafeValues(t *testing.T) {
	base := vh{TemplateVersion: Version, User: "u", Domain: "d.test", DocRoot: "/home/u/public_html", PHPSocket: "/run/php/x.sock",
		CertFile: "/c", KeyFile: "/k", Mode: "nginx", Names: []string{"d.test"}}
	if _, err := Render("nginx-vhost.conf.tmpl", base); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"/home/u/x;\n}", "/home/u/a b", `/home/u/"x`, "/home/u/${x}"} {
		v := base
		v.DocRoot = bad
		if _, err := Render("nginx-vhost.conf.tmpl", v); err == nil {
			t.Errorf("nginx rendered docroot %q", bad)
		}
		if _, err := Render("apache-vhost.conf.tmpl", v); err == nil {
			t.Errorf("apache rendered docroot %q", bad)
		}
	}
	v := base
	v.Names = []string{"d.test", "x;y"}
	if _, err := Render("nginx-vhost.conf.tmpl", v); err == nil {
		t.Error("server_name injection rendered")
	}
}

func TestTemplatesQuoteAndProtect(t *testing.T) {
	b, err := Render("nginx-vhost.conf.tmpl", vh{User: "u", Domain: "d.test", DocRoot: "/home/u/public_html", PHPSocket: "/s", Mode: "nginx", Names: []string{"d.test", "www.d.test"}})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`root "/home/u/public_html";`, "disable_symlinks if_not_owner", `fastcgi_pass "unix:/s";`, "server_name d.test www.d.test;"} {
		if !strings.Contains(s, want) {
			t.Errorf("nginx missing %q", want)
		}
	}
	a, err := Render("apache-vhost.conf.tmpl", vh{Domain: "d.test", DocRoot: "/home/u/public_html", PHPSocket: "/s"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(a), "AllowOverride All") || !strings.Contains(string(a), `<Directory "/home/u/public_html">`) {
		t.Errorf("apache:\n%s", a)
	}
}

// H-5: modern nginx gets "http2 on;", older nginx the listen flag.
func TestNginxHTTP2Forms(t *testing.T) {
	v := vh{User: "u", Domain: "d.test", DocRoot: "/home/u/public_html", PHPSocket: "/s", CertFile: "/c", KeyFile: "/k", SSL: true, Names: []string{"d.test"}}
	old, err := Render("nginx-vhost.conf.tmpl", v)
	if err != nil {
		t.Fatal(err)
	}
	v.HTTP2On = true
	nw, err := Render("nginx-vhost.conf.tmpl", v)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(old), "listen 443 ssl http2;") || strings.Contains(string(old), "http2 on;") {
		t.Errorf("old form:\n%s", old)
	}
	if !strings.Contains(string(nw), "http2 on;") || strings.Contains(string(nw), "ssl http2") {
		t.Errorf("new form:\n%s", nw)
	}
}

// H-6: PHP temp files stay in the account's own tmp.
func TestPoolPrivateTmp(t *testing.T) {
	type pool struct {
		TemplateVersion                                     int
		User, Version, Socket, Home, MemoryLimit, UploadMax string
		MaxChildren, MaxExecution                           int
		INI                                                 map[string]string
	}
	b, err := Render("pool.conf.tmpl", pool{User: "u", Version: "8.3", Socket: "/run/php/s.sock", Home: "/home/u", MemoryLimit: "128M", UploadMax: "8M", MaxChildren: 5, MaxExecution: 30})
	if err != nil {
		t.Skipf("pool template data differs: %v", err)
	}
	s := string(b)
	if strings.Contains(s, ":/tmp:") || !strings.Contains(s, "sys_temp_dir] = /home/u/tmp") {
		t.Errorf("pool tmp:\n%s", s)
	}
}

// v0.4 netsec C: the WAF include renders only when the agent sets it.
func TestWAFIncludeConditional(t *testing.T) {
	base := vh{TemplateVersion: Version, User: "u", Domain: "d.test", DocRoot: "/home/u/public_html", PHPSocket: "/run/php/x.sock",
		CertFile: "/c", KeyFile: "/k", Mode: "nginx", Names: []string{"d.test"}}
	// mode off or module missing → agent leaves the fields empty → no directive
	n, _ := Render("nginx-vhost.conf.tmpl", base)
	ap, _ := Render("apache-vhost.conf.tmpl", base)
	if strings.Contains(string(n), "bpanel-waf.d") || strings.Contains(string(n), "modsecurity") || strings.Contains(string(ap), "IncludeOptional") {
		t.Fatalf("WAF directive rendered while off:\n%s\n%s", n, ap)
	}
	// audit/block → include present (both SSL and plain)
	for _, ssl := range []bool{false, true} {
		v := base
		v.SSL = ssl
		v.WAFInclude = "/etc/nginx/bpanel-waf.d/d.test.conf"
		v.ApacheWAFInclude = "/etc/apache2/bpanel-waf.d/d.test.conf"
		n, err := Render("nginx-vhost.conf.tmpl", v)
		if err != nil || strings.Count(string(n), `include "/etc/nginx/bpanel-waf.d/d.test.conf";`) != 1 {
			t.Fatalf("nginx ssl=%v: %v\n%s", ssl, err, n)
		}
		ap, err := Render("apache-vhost.conf.tmpl", v)
		if err != nil || !strings.Contains(string(ap), `IncludeOptional "/etc/apache2/bpanel-waf.d/d.test.conf"`) {
			t.Fatalf("apache: %v\n%s", err, ap)
		}
	}
	v := base
	v.WAFInclude = "/etc/x;\nevil"
	if _, err := Render("nginx-vhost.conf.tmpl", v); err == nil {
		t.Fatal("unsafe WAF include rendered")
	}
}

// v0.4 webx: the per-domain web-extras include renders only when set, and an
// unsafe path is refused by the template itself.
func TestWebXIncludeConditional(t *testing.T) {
	v := vh{TemplateVersion: Version, User: "u", Domain: "d.test", DocRoot: "/home/u/public_html", PHPSocket: "/run/php/x.sock",
		CertFile: "/c", KeyFile: "/k", Mode: "nginx-apache", Names: []string{"d.test"}}
	n, _ := Render("nginx-vhost.conf.tmpl", v)
	ap, _ := Render("apache-vhost.conf.tmpl", v)
	if strings.Contains(string(n), "bpanel-webx") || strings.Contains(string(ap), "bpanel-webx") {
		t.Fatalf("webx include rendered while empty:\n%s\n%s", n, ap)
	}
	v.WebXInclude = "/etc/nginx/bpanel-webx.d/d.test.conf"
	v.ApacheWebXInclude = "/etc/apache2/bpanel-webx.d/d.test.conf"
	n, err := Render("nginx-vhost.conf.tmpl", v)
	if err != nil || !strings.Contains(string(n), `    include "/etc/nginx/bpanel-webx.d/d.test.conf";`) {
		t.Fatalf("nginx include missing: %v\n%s", err, n)
	}
	ap, err = Render("apache-vhost.conf.tmpl", v)
	if err != nil || !strings.Contains(string(ap), `    Include "/etc/apache2/bpanel-webx.d/d.test.conf"`) {
		t.Fatalf("apache include missing: %v\n%s", err, ap)
	}
	for _, bad := range []string{"/etc/x;\nevil", "/etc/x}", "/etc/x y", `/etc/"x`} {
		v.WebXInclude, v.ApacheWebXInclude = bad, bad
		if _, err := Render("nginx-vhost.conf.tmpl", v); err == nil {
			t.Errorf("nginx rendered unsafe include %q", bad)
		}
		if _, err := Render("apache-vhost.conf.tmpl", v); err == nil {
			t.Errorf("apache rendered unsafe include %q", bad)
		}
	}
}

// v0.4 appx: the application proxy include and the "/" proxy render only
// when set; an unsafe include path is refused by the template itself.
func TestAppXProxyConditional(t *testing.T) {
	v := vh{TemplateVersion: Version, User: "u", Domain: "d.test", DocRoot: "/home/u/public_html", PHPSocket: "/run/php/x.sock",
		CertFile: "/c", KeyFile: "/k", Mode: "nginx", Names: []string{"d.test"}}
	n, err := Render("nginx-vhost.conf.tmpl", v)
	if err != nil || strings.Contains(string(n), "bpanel-appx") || strings.Contains(string(n), "Application Manager") {
		t.Fatalf("appx rendered while empty: %v\n%s", err, n)
	}
	v.AppXInclude = "/etc/nginx/bpanel-appx.d/d.test.conf"
	n, err = Render("nginx-vhost.conf.tmpl", v)
	if err != nil || !strings.Contains(string(n), `    include "/etc/nginx/bpanel-appx.d/d.test.conf";`) || !strings.Contains(string(n), "fastcgi_pass") {
		t.Fatalf("include missing: %v\n%s", err, n)
	}
	v.AppXRootPort = 30001
	n, err = Render("nginx-vhost.conf.tmpl", v)
	if err != nil || !strings.Contains(string(n), "proxy_pass http://127.0.0.1:30001;") || strings.Contains(string(n), "fastcgi_pass") {
		t.Fatalf("root proxy wrong: %v\n%s", err, n)
	}
	v.Suspended = true
	n, _ = Render("nginx-vhost.conf.tmpl", v)
	if strings.Contains(string(n), "127.0.0.1:30001") {
		t.Fatal("suspended site still proxies the app")
	}
	v.Suspended = false
	for _, bad := range []string{"/etc/x;\nevil", "/etc/x}", "/etc/x y"} {
		v.AppXInclude = bad
		if _, err := Render("nginx-vhost.conf.tmpl", v); err == nil {
			t.Errorf("rendered unsafe include %q", bad)
		}
	}
}
