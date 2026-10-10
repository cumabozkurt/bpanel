// SPDX-License-Identifier: Apache-2.0

package webx

import (
	"fmt"
	"strings"

	"github.com/cumabozkurt/bpanel/internal/validate"
)

// ErrorsURL is the internal URL prefix the custom error pages are served
// from (files live outside the docroot, see RenderCtx.ErrorsDir).
const ErrorsURL = "/.bpanel-errors/"

// RenderCtx carries the server-side facts the includes need.
type RenderCtx struct {
	Mode          string   // "nginx" or "nginx-apache"
	PHPSocket     string   // PHP-FPM socket (nginx mode, protected dirs)
	DocRoot       string   // absolute docroot
	Names         []string // server names of the vhost (hotlink self-referers)
	HtpasswdPaths []string // one per Privacy entry, same order
	ErrorsDir     string   // absolute directory holding <code>.html
}

// Htpasswd renders a protected directory's password file.
func Htpasswd(d PrivacyDir) []byte {
	var b strings.Builder
	for _, u := range d.Users {
		if ValidUser(u) == nil {
			b.WriteString(u.Name + ":" + u.Hash + "\n")
		}
	}
	return []byte(b.String())
}

// tok refuses any value that could break out of a token (defence in depth:
// everything reaching here was already validated by Normalize).
func tok(vals ...string) error {
	for _, v := range vals {
		if !validate.ConfigSafe(v) {
			return fmt.Errorf("webx: unsafe value %q refused", v)
		}
	}
	return nil
}

func reDomain(d string) string { return strings.ReplaceAll(d, ".", `\.`) }

func (r RenderCtx) check(c *Config) error {
	if err := tok(r.PHPSocket, r.DocRoot, r.ErrorsDir); err != nil {
		return err
	}
	if len(r.HtpasswdPaths) != len(c.Privacy) {
		return fmt.Errorf("webx: htpasswd paths do not match protected directories")
	}
	if err := tok(r.HtpasswdPaths...); err != nil {
		return err
	}
	if err := tok(r.Names...); err != nil {
		return err
	}
	for _, d := range c.Privacy {
		if !reRealm.MatchString(d.Realm) {
			return fmt.Errorf("webx: unsafe realm refused")
		}
		if err := tok(d.Path); err != nil {
			return err
		}
	}
	for _, m := range c.MIME {
		mm := m
		if err := ValidMIME(&mm); err != nil || mm != m {
			return fmt.Errorf("webx: unsafe MIME type refused")
		}
	}
	for _, e := range c.Hotlink.Exts {
		if !reExt.MatchString(e) {
			return fmt.Errorf("webx: unsafe extension refused")
		}
	}
	for _, d := range c.Hotlink.Allowed {
		if !ValidDomain(d) {
			return fmt.Errorf("webx: unsafe domain refused")
		}
	}
	for _, ip := range c.Deny {
		if v, err := ParseDeny(ip); err != nil || v != ip {
			return fmt.Errorf("webx: unsafe address refused")
		}
	}
	for _, k := range c.SortedErrorCodes() {
		if !ValidErrorCode(k) {
			return fmt.Errorf("webx: unsupported error code refused")
		}
	}
	return nil
}

func (r RenderCtx) staticTail() string {
	if r.Mode == "nginx" {
		return "try_files $uri =404;"
	}
	return "try_files $uri @apache;"
}

func (r RenderCtx) referers(c *Config) string {
	parts := []string{}
	if c.Hotlink.AllowEmpty {
		parts = append(parts, "none", "blocked")
	}
	parts = append(parts, "server_names")
	for _, d := range append([]string{c.Domain}, c.Hotlink.Allowed...) {
		parts = append(parts, d, "*."+d)
	}
	return "valid_referers " + strings.Join(parts, " ") + ";"
}

// RenderNginx returns the nginx include (server context) or nil when the
// config renders nothing.
func RenderNginx(c *Config, r RenderCtx) ([]byte, error) {
	if c == nil || c.Empty() {
		return nil, nil
	}
	if err := r.check(c); err != nil {
		return nil, err
	}
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("# Managed by BOZKURT PANEL (web extras) — changes are overwritten.")
	if len(c.Deny) > 0 {
		w("# IP blocker")
		for _, ip := range c.Deny {
			w("deny %s;", ip)
		}
	}
	if codes := c.SortedErrorCodes(); len(codes) > 0 {
		w("# custom error pages (served from outside the docroot)")
		for _, k := range codes {
			w("error_page %s %s%s.html;", k, ErrorsURL, k)
		}
		w(`location ^~ %s { internal; alias "%s/"; }`, ErrorsURL, r.ErrorsDir)
	}
	hot := map[string]bool{}
	if c.Hotlink.Enabled {
		for _, e := range c.Hotlink.Exts {
			hot[e] = true
		}
	}
	if len(c.MIME) > 0 {
		w("# extra MIME types")
		for _, m := range c.MIME {
			w(`location ~* \.%s$ {`, m.Ext)
			w("    types { }")
			w(`    default_type "%s";`, m.Type)
			if hot[m.Ext] {
				w("    %s", r.referers(c))
				w("    if ($invalid_referer) { return 403; }")
			}
			w("    %s", r.staticTail())
			w("}")
		}
	}
	if c.Hotlink.Enabled {
		w("# hotlink protection")
		w(`location ~* \.(?:%s)$ {`, strings.Join(c.Hotlink.Exts, "|"))
		w("    %s", r.referers(c))
		w("    if ($invalid_referer) { return 403; }")
		w("    expires 7d;")
		w("    %s", r.staticTail())
		w("}")
	}
	for i, d := range c.Privacy {
		w("# directory privacy")
		w(`location ^~ "%s" {`, d.Path)
		w(`    auth_basic "%s";`, d.Realm)
		w(`    auth_basic_user_file "%s";`, r.HtpasswdPaths[i])
		w(`    location ~ /\.(ht|git|svn|env) { deny all; }`)
		if r.Mode == "nginx" {
			w("    try_files $uri $uri/ =404;")
			w(`    location ~ \.php$ {`)
			w("        try_files $uri =404;")
			w(`        fastcgi_split_path_info ^(.+\.php)(/.+)$;`)
			w(`        fastcgi_pass "unix:%s";`, r.PHPSocket)
			w("        fastcgi_index index.php;")
			w("        include fastcgi_params;")
			w("        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;")
			w("        fastcgi_param HTTPS $https if_not_empty;")
			w("        fastcgi_read_timeout 300;")
			w("    }")
		} else {
			w("    proxy_pass http://127.0.0.1:8080;")
			w("    proxy_set_header Host $host;")
			w("    proxy_set_header X-Real-IP $remote_addr;")
			w("    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
			w("    proxy_set_header X-Forwarded-Proto $scheme;")
			w("    proxy_read_timeout 300;")
		}
		w("}")
	}
	return []byte(b.String()), nil
}

// RenderApache returns the Apache include (VirtualHost context) or nil.
func RenderApache(c *Config, r RenderCtx) ([]byte, error) {
	if c == nil || c.Empty() {
		return nil, nil
	}
	if err := r.check(c); err != nil {
		return nil, err
	}
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("# Managed by BOZKURT PANEL (web extras) — changes are overwritten.")
	if codes := c.SortedErrorCodes(); len(codes) > 0 {
		w(`Alias %s "%s/"`, ErrorsURL, r.ErrorsDir)
		w(`<Directory "%s">`, r.ErrorsDir)
		w("    Options None")
		w("    AllowOverride None")
		w("    Require all granted")
		w("</Directory>")
		for _, k := range codes {
			w("ErrorDocument %s %s%s.html", k, ErrorsURL, k)
		}
	}
	for _, m := range c.MIME {
		w("AddType %s .%s", m.Type, m.Ext)
	}
	if len(c.Deny) > 0 {
		// effective only when Apache sees the client address (mod_remoteip);
		// nginx in front enforces the same list in every mode.
		w(`<Directory "%s">`, r.DocRoot)
		w("    <RequireAll>")
		w("        Require all granted")
		for _, ip := range c.Deny {
			w("        Require not ip %s", ip)
		}
		w("    </RequireAll>")
		w("</Directory>")
	}
	if c.Hotlink.Enabled {
		w("<IfModule mod_rewrite.c>")
		w("    RewriteEngine On")
		if c.Hotlink.AllowEmpty {
			w("    RewriteCond %%{HTTP_REFERER} !^$")
		}
		seen := map[string]bool{}
		for _, d := range append(append([]string{}, r.Names...), append([]string{c.Domain}, c.Hotlink.Allowed...)...) {
			if seen[d] {
				continue
			}
			seen[d] = true
			w(`    RewriteCond %%{HTTP_REFERER} !^https?://([^/]+\.)?%s(:[0-9]+)?(/|$) [NC]`, reDomain(d))
		}
		w(`    RewriteRule \.(%s)$ - [F,NC]`, strings.Join(c.Hotlink.Exts, "|"))
		w("</IfModule>")
	}
	for i, d := range c.Privacy {
		w(`<Directory "%s%s">`, r.DocRoot, strings.TrimSuffix(d.Path, "/"))
		w("    AuthType Basic")
		w(`    AuthName "%s"`, d.Realm)
		w(`    AuthUserFile "%s"`, r.HtpasswdPaths[i])
		w("    Require valid-user")
		w("</Directory>")
	}
	return []byte(b.String()), nil
}
