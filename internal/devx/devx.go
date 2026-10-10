// SPDX-License-Identifier: Apache-2.0

// Package devx holds the pure, testable logic of the v0.4 developer tools:
// git clone-URL validation (scheme allowlist + SSRF guard), repository path
// rules, dynamic-DNS tokens (random, stored only as SHA-256), host
// validation for DNS lookups / traceroute, and the git argv builders.
package devx

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// Error carries a stable error code (matches the API/agent catalogue).
type Error struct{ Code string }

func (e *Error) Error() string { return e.Code }

// Code returns the code of a devx error ("" otherwise).
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

var (
	hostRe   = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)
	sshUser  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	scpLike  = regexp.MustCompile(`^([A-Za-z0-9._-]{1,64})@([A-Za-z0-9.-]{1,253}):([^:\\]+)$`)
	repoPath = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	helperRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*::`)
	branchRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$`)
)

// CloneURL is a validated remote.
type CloneURL struct {
	Normalized string // https://... or ssh://...
	Host       string
}

// ParseCloneURL accepts https://host/path, ssh://[user@]host[:port]/path and
// scp-like user@host:path (normalised to ssh://). Everything else is
// rejected: file://, http://, git://, ext::, local paths, credentials in
// https URLs, option-looking hosts (argument injection), query strings.
func ParseCloneURL(raw string) (CloneURL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 1024 || strings.ContainsAny(raw, " \t\r\n\x00") || strings.HasPrefix(raw, "-") {
		return CloneURL{}, &Error{Code: "git_url_invalid"}
	}
	if helperRe.MatchString(raw) { // ext::, fd:: transport helpers
		return CloneURL{}, &Error{Code: "git_url_scheme"}
	}
	if m := scpLike.FindStringSubmatch(raw); m != nil && !strings.Contains(raw, "://") {
		raw = "ssh://" + m[1] + "@" + m[2] + "/" + strings.TrimPrefix(m[3], "/")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return CloneURL{}, &Error{Code: "git_url_invalid"}
	}
	switch u.Scheme {
	case "https":
		if u.User != nil {
			return CloneURL{}, &Error{Code: "git_url_credentials"}
		}
	case "ssh":
		if u.User != nil {
			if _, has := u.User.Password(); has || !sshUser.MatchString(u.User.Username()) {
				return CloneURL{}, &Error{Code: "git_url_credentials"}
			}
		}
	default:
		return CloneURL{}, &Error{Code: "git_url_scheme"}
	}
	host := u.Hostname()
	if host == "" || strings.HasPrefix(host, "-") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return CloneURL{}, &Error{Code: "git_url_invalid"}
	}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err != nil && !hostRe.MatchString(host) {
		return CloneURL{}, &Error{Code: "git_url_invalid"}
	}
	p := u.EscapedPath()
	if p == "" || p == "/" || !repoPath.MatchString(strings.ReplaceAll(p, "%20", "")) || strings.Contains(p, "..") {
		return CloneURL{}, &Error{Code: "git_url_invalid"}
	}
	if port := u.Port(); port != "" && (len(port) > 5 || strings.TrimLeft(port, "0123456789") != "") {
		return CloneURL{}, &Error{Code: "git_url_invalid"}
	}
	return CloneURL{Normalized: u.String(), Host: host}, nil
}

// Resolver resolves a host name to addresses.
type Resolver func(ctx context.Context, host string) ([]net.IP, error)

// CheckHost resolves host (or parses an IP literal) and refuses when any
// address is blocked (private, loopback, link-local, metadata ...).
func CheckHost(ctx context.Context, host string, resolve Resolver, blocked func(net.IP) bool) error {
	var ips []net.IP
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		ips = []net.IP{ip}
	} else {
		var err error
		ips, err = resolve(ctx, host)
		if err != nil || len(ips) == 0 {
			return &Error{Code: "host_unresolvable"}
		}
	}
	for _, ip := range ips {
		if blocked(ip) {
			return &Error{Code: "target_blocked"}
		}
	}
	return nil
}

// DefaultResolver uses the system resolver.
func DefaultResolver(ctx context.Context, host string) ([]net.IP, error) {
	as, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(as))
	for _, a := range as {
		out = append(out, a.IP)
	}
	return out, nil
}

var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, c := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "64:ff9b::/96", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8"} {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}()

// BlockedIP is the agent-side copy of the API webhook SSRF blocklist (same
// ranges as internal/api blockedNets); the agent re-checks right before git
// connects, which narrows the DNS-rebinding window.
func BlockedIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	a = a.Unmap()
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast()
}

// CleanRel validates a path relative to the home: no absolute paths, no
// "..", no hidden top-level system dirs, limited charset.
func CleanRel(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || len(p) > 255 || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "-") || !repoPath.MatchString(p) {
		return "", &Error{Code: "git_path_invalid"}
	}
	c := path.Clean(p)
	if c != strings.TrimSuffix(p, "/") || c == "." || strings.HasPrefix(c, "..") || strings.Contains(c, "/../") {
		return "", &Error{Code: "git_path_invalid"}
	}
	for _, seg := range strings.Split(c, "/") {
		if seg == ".." || seg == ".git" || strings.HasPrefix(seg, "-") {
			return "", &Error{Code: "git_path_invalid"}
		}
	}
	top := strings.SplitN(c, "/", 2)[0]
	switch top {
	case ".ssh", ".bpanel", "etc", "mail", "logs", "tmp", ".config", ".gnupg":
		return "", &Error{Code: "git_path_invalid"}
	}
	return c, nil
}

// ValidBranch reports whether b is an acceptable branch name ("" allowed).
func ValidBranch(b string) bool {
	return b == "" || (branchRe.MatchString(b) && !strings.Contains(b, "..") && !strings.HasSuffix(b, ".lock") && !strings.HasSuffix(b, "/"))
}

// ValidHost validates a lookup / traceroute target: a host name or an IP
// literal, never option-looking.
func ValidHost(h string) bool {
	h = strings.TrimSuffix(strings.TrimSpace(h), ".")
	if h == "" || len(h) > 253 || strings.HasPrefix(h, "-") {
		return false
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Zone() == "" // qa fuzz: "::% 0" (zones carry arbitrary text)
	}
	return hostRe.MatchString(h) && strings.Contains(h, ".")
}

// GitSafeConfig are the -c options every git call gets: only https and ssh
// transports (no file://, ext::, git://, also for submodules), no
// interactive prompts, no credential helpers from the system config.
var GitSafeConfig = []string{
	"-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "protocol.ssh.allow=always",
	"-c", "protocol.file.allow=never", "-c", "credential.helper=", "-c", "core.askPass=/bin/false",
	"-c", "submodule.recurse=false", "-c", "core.hooksPath=/dev/null",
}

// GitEnvArgv prefixes a git invocation with /usr/bin/env so the caged
// process gets GIT_TERMINAL_PROMPT=0 etc. (cage-exec resets the environment).
func GitEnvArgv(git string, args ...string) []string {
	out := []string{"/usr/bin/env", "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false", "SSH_ASKPASS=/bin/false",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_SSH_COMMAND=ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15",
		git}
	out = append(out, GitSafeConfig...)
	return append(out, args...)
}

// ---- dynamic DNS tokens ----------------------------------------------------------

// TokenPrefix marks DDNS tokens (redaction-friendly).
const TokenPrefix = "bpd_"

// NewToken returns a fresh token (shown once) and its storage hash.
func NewToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	token = TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), nil
}

// HashToken is the stored form: hex SHA-256 (tokens carry 256 random bits,
// so a slow KDF adds nothing).
func HashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// WellFormedToken rejects obviously bad input before any DB lookup.
func WellFormedToken(t string) bool {
	if !strings.HasPrefix(t, TokenPrefix) || len(t) != len(TokenPrefix)+43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(t[len(TokenPrefix):])
	return err == nil
}
