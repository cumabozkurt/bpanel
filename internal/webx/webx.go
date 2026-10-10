// SPDX-License-Identifier: Apache-2.0

// Package webx holds the per-domain web extras of the user panel (v0.4):
// directory privacy (HTTP basic auth), hotlink protection, custom error
// pages, extra MIME types and an IP deny list. Everything a domain has is
// rendered into ONE nginx include and ONE Apache include which the vhost
// templates pull in when non-empty (see internal/agent/webx.go).
//
// Every value is validated here against strict allowlists before it is
// rendered, and the renderer re-checks each token, so no user input can
// close a directive, open a block or start a new line (no newline, ';',
// '{', '}', quote, '$', '\\', '#', whitespace where a token is expected).
package webx

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cumabozkurt/bpanel/internal/validate"
)

// Limits keep the include small and the config test fast.
const (
	MaxPrivacyDirs  = 50
	MaxPrivacyUsers = 50
	MaxHotlinkHosts = 50
	MaxHotlinkExts  = 40
	MaxMIME         = 100
	MaxDeny         = 500
	MaxErrorPage    = 64 << 10
)

// ErrorCodes are the HTTP statuses a custom page can be set for.
var ErrorCodes = []int{400, 401, 403, 404, 500, 502, 503}

// PrivacyUser is one basic-auth login; Hash is a bcrypt hash ($2y$/$2b$/$2a$).
type PrivacyUser struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
}

// PrivacyDir protects Path (URL path below the docroot, "/dir/") with basic auth.
type PrivacyDir struct {
	Path  string        `json:"path"`
	Realm string        `json:"realm"`
	Users []PrivacyUser `json:"users"`
}

// Hotlink denies requests for Exts whose Referer is neither the domain
// itself, one of Allowed (subdomains included) nor (AllowEmpty) absent.
type Hotlink struct {
	Enabled    bool     `json:"enabled"`
	Allowed    []string `json:"allowed"`
	Exts       []string `json:"exts"`
	AllowEmpty bool     `json:"allow_empty"`
}

// MIMEType maps one file extension to a media type.
type MIMEType struct {
	Ext  string `json:"ext"`
	Type string `json:"type"`
}

// Config is the whole per-domain state. ErrorPages maps "404" -> HTML.
type Config struct {
	Domain     string            `json:"domain"`
	Privacy    []PrivacyDir      `json:"privacy"`
	Hotlink    Hotlink           `json:"hotlink"`
	ErrorPages map[string]string `json:"error_pages"`
	MIME       []MIMEType        `json:"mime"`
	Deny       []string          `json:"deny"`
}

// Error is a validation failure; Code is an API error code.
type Error struct{ Code, Msg string }

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func bad(code, f string, a ...any) error { return &Error{Code: code, Msg: fmt.Sprintf(f, a...)} }

var (
	reSeg      = regexp.MustCompile(`^[A-Za-z0-9_~-][A-Za-z0-9._~-]{0,99}$`)
	reRealm    = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,64}$`)
	reUser     = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)
	reBcrypt   = regexp.MustCompile(`^\$2[aby]\$(0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}$`)
	reExt      = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
	reMIMESub  = regexp.MustCompile(`^[a-z0-9][a-z0-9.+_-]{0,99}$`)
	mimeTops   = map[string]bool{"application": true, "audio": true, "font": true, "image": true, "model": true, "text": true, "video": true}
	execExts   = map[string]bool{"php": true, "php3": true, "php4": true, "php5": true, "php7": true, "php8": true, "phtml": true, "phar": true, "pht": true, "phps": true, "cgi": true, "pl": true, "py": true, "sh": true, "shtml": true, "htaccess": true, "htpasswd": true, "fcgi": true, "asp": true, "aspx": true, "jsp": true}
	ErrInvalid = errors.New("webx_invalid")
)

// ValidDomain reports whether d is an acceptable vhost domain.
func ValidDomain(d string) bool { return validate.Domain(d) == nil && validate.ConfigSafe(d) }

// CleanPath normalises a protected URL path to "/a/b/". The root "/" is
// refused (protect a sub-directory; a site-wide prompt would also block the
// ACME challenge).
func CleanPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || len(p) > 255 || !validate.ConfigSafe(p) {
		return "", bad("webx_invalid_path", "invalid path")
	}
	segs := []string{}
	for _, s := range strings.Split(strings.Trim(p, "/"), "/") {
		if s == "" {
			continue
		}
		if s == "." || s == ".." || strings.HasPrefix(s, ".") || !reSeg.MatchString(s) {
			return "", bad("webx_invalid_path", "invalid path segment")
		}
		segs = append(segs, s)
	}
	if len(segs) == 0 {
		return "", bad("webx_invalid_path", "the site root cannot be protected; choose a directory")
	}
	return "/" + strings.Join(segs, "/") + "/", nil
}

// ParseDeny validates one IP or CIDR and returns its canonical form.
func ParseDeny(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		pf, err := netip.ParsePrefix(s)
		if err != nil || pf.Addr().Zone() != "" {
			return "", bad("webx_invalid_ip", "invalid CIDR")
		}
		pf = pf.Masked()
		if pf.Bits() == 0 {
			return "", bad("webx_invalid_ip", "refusing to block every address")
		}
		return pf.String(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return "", bad("webx_invalid_ip", "invalid IP address")
	}
	return a.Unmap().String(), nil
}

// ValidMIME validates one mapping (ext without dot, lower-case type).
func ValidMIME(m *MIMEType) error {
	m.Ext = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(m.Ext), "."))
	m.Type = strings.ToLower(strings.TrimSpace(m.Type))
	if !reExt.MatchString(m.Ext) {
		return bad("webx_invalid_mime", "invalid extension")
	}
	if execExts[m.Ext] {
		return bad("webx_invalid_mime", "extension %s is reserved for scripts", m.Ext)
	}
	top, sub, ok := strings.Cut(m.Type, "/")
	if !ok || !mimeTops[top] || !reMIMESub.MatchString(sub) {
		return bad("webx_invalid_mime", "invalid media type")
	}
	return nil
}

// ValidUser validates a basic-auth login name and bcrypt hash.
func ValidUser(u PrivacyUser) error {
	if !reUser.MatchString(u.Name) {
		return bad("webx_invalid_user", "invalid user name")
	}
	if !reBcrypt.MatchString(u.Hash) {
		return bad("webx_invalid_user", "invalid password hash")
	}
	return nil
}

// ValidErrorCode reports whether c is one of ErrorCodes.
func ValidErrorCode(c string) bool {
	n, err := strconv.Atoi(c)
	if err != nil || strconv.Itoa(n) != c {
		return false
	}
	for _, x := range ErrorCodes {
		if x == n {
			return true
		}
	}
	return false
}

// Normalize validates and canonicalises the whole config in place.
func (c *Config) Normalize() error {
	c.Domain = strings.ToLower(strings.TrimSpace(c.Domain))
	if !ValidDomain(c.Domain) {
		return bad("webx_invalid", "invalid domain")
	}
	if len(c.Privacy) > MaxPrivacyDirs {
		return bad("webx_invalid", "too many protected directories")
	}
	seenP := map[string]bool{}
	for i := range c.Privacy {
		d := &c.Privacy[i]
		p, err := CleanPath(d.Path)
		if err != nil {
			return err
		}
		if seenP[p] {
			return bad("webx_invalid_path", "directory listed twice")
		}
		seenP[p], d.Path = true, p
		if d.Realm == "" {
			d.Realm = "Restricted"
		}
		if !reRealm.MatchString(d.Realm) {
			return bad("webx_invalid", "invalid realm")
		}
		if len(d.Users) > MaxPrivacyUsers {
			return bad("webx_invalid", "too many users")
		}
		seenU := map[string]bool{}
		for _, u := range d.Users {
			if err := ValidUser(u); err != nil {
				return err
			}
			if seenU[u.Name] {
				return bad("webx_invalid_user", "user listed twice")
			}
			seenU[u.Name] = true
		}
	}
	sort.Slice(c.Privacy, func(i, j int) bool { return c.Privacy[i].Path < c.Privacy[j].Path })
	h := &c.Hotlink
	if len(h.Allowed) > MaxHotlinkHosts || len(h.Exts) > MaxHotlinkExts {
		return bad("webx_invalid_hotlink", "too many entries")
	}
	al := []string{}
	seen := map[string]bool{}
	for _, d := range h.Allowed {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimPrefix(strings.TrimPrefix(d, "https://"), "http://")
		if !ValidDomain(d) {
			return bad("webx_invalid_hotlink", "invalid domain")
		}
		if !seen[d] {
			seen[d] = true
			al = append(al, d)
		}
	}
	h.Allowed = al
	ex := []string{}
	seen = map[string]bool{}
	for _, e := range h.Exts {
		e = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(e), "."))
		if !reExt.MatchString(e) {
			return bad("webx_invalid_hotlink", "invalid extension")
		}
		if !seen[e] {
			seen[e] = true
			ex = append(ex, e)
		}
	}
	h.Exts = ex
	if h.Enabled && len(h.Exts) == 0 {
		return bad("webx_invalid_hotlink", "list at least one extension")
	}
	for k, v := range c.ErrorPages {
		if !ValidErrorCode(k) {
			return bad("webx_invalid_error_page", "unsupported status code")
		}
		if len(v) > MaxErrorPage {
			return bad("webx_invalid_error_page", "page too large")
		}
		if strings.TrimSpace(v) == "" {
			delete(c.ErrorPages, k)
		}
	}
	if len(c.MIME) > MaxMIME {
		return bad("webx_invalid_mime", "too many types")
	}
	seen = map[string]bool{}
	for i := range c.MIME {
		if err := ValidMIME(&c.MIME[i]); err != nil {
			return err
		}
		if seen[c.MIME[i].Ext] {
			return bad("webx_invalid_mime", "extension listed twice")
		}
		seen[c.MIME[i].Ext] = true
	}
	sort.Slice(c.MIME, func(i, j int) bool { return c.MIME[i].Ext < c.MIME[j].Ext })
	if len(c.Deny) > MaxDeny {
		return bad("webx_invalid_ip", "too many entries")
	}
	dn := []string{}
	seen = map[string]bool{}
	for _, s := range c.Deny {
		v, err := ParseDeny(s)
		if err != nil {
			return err
		}
		if !seen[v] {
			seen[v] = true
			dn = append(dn, v)
		}
	}
	c.Deny = dn
	return nil
}

// Empty reports whether nothing would be rendered.
func (c *Config) Empty() bool {
	return len(c.Privacy) == 0 && !c.Hotlink.Enabled && len(c.ErrorPages) == 0 && len(c.MIME) == 0 && len(c.Deny) == 0
}

// SortedErrorCodes returns the codes that have a page, ascending.
func (c *Config) SortedErrorCodes() []string {
	out := []string{}
	for k := range c.ErrorPages {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
