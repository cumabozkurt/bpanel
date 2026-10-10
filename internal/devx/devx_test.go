// SPDX-License-Identifier: Apache-2.0

package devx

import (
	"context"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestParseCloneURL(t *testing.T) {
	good := map[string]string{
		"https://github.com/user/repo.git":     "https://github.com/user/repo.git",
		"ssh://git@github.com/user/repo.git":   "ssh://git@github.com/user/repo.git",
		"git@github.com:user/repo.git":         "ssh://git@github.com/user/repo.git",
		"ssh://git@example.com:2222/a/b.git":   "ssh://git@example.com:2222/a/b.git",
		"https://codeberg.org/forgejo/forgejo": "https://codeberg.org/forgejo/forgejo",
	}
	for in, want := range good {
		u, err := ParseCloneURL(in)
		if err != nil || u.Normalized != want {
			t.Errorf("%s: %v %q", in, err, u.Normalized)
		}
	}
	bad := map[string]string{
		"file:///etc/passwd":             "git_url_scheme",
		"/home/bob/repo":                 "git_url_scheme",
		"../other":                       "git_url_scheme",
		"http://github.com/a/b":          "git_url_scheme",
		"git://github.com/a/b":           "git_url_scheme",
		"ext::sh -c touch% /tmp/pwned":   "git_url_invalid",
		"ext::ssh":                       "git_url_scheme",
		"fd::17":                         "git_url_scheme",
		"https://user:pw@github.com/a/b": "git_url_credentials",
		"ssh://-oProxyCommand=evil/a":    "git_url_invalid",
		"-uhttps://github.com/a":         "git_url_invalid",
		"https://github.com/a/b?x=1":     "git_url_invalid",
		"https://github.com/":            "git_url_invalid",
		"https://github.com/../../etc":   "git_url_invalid",
		"FILE:///etc":                    "git_url_scheme",
		"https://github.com/a b":         "git_url_invalid",
	}
	for in, want := range bad {
		_, err := ParseCloneURL(in)
		if Code(err) != want {
			t.Errorf("%q: got %v want %s", in, err, want)
		}
	}
}

func TestSSRFGuard(t *testing.T) {
	res := func(m map[string][]string) Resolver {
		return func(_ context.Context, h string) ([]net.IP, error) {
			var out []net.IP
			for _, s := range m[h] {
				out = append(out, net.ParseIP(s))
			}
			return out, nil
		}
	}(map[string][]string{"internal.example": {"10.1.2.3"}, "meta.example": {"169.254.169.254"},
		"mixed.example": {"93.184.216.34", "127.0.0.1"}, "ok.example": {"93.184.216.34", "2606:2800:220:1::1"}})
	for h, want := range map[string]string{"internal.example": "target_blocked", "meta.example": "target_blocked",
		"mixed.example": "target_blocked", "127.0.0.1": "target_blocked", "::1": "target_blocked", "[fd00::1]": "target_blocked",
		"::ffff:10.0.0.1": "target_blocked", "100.64.1.1": "target_blocked", "nx.example": "host_unresolvable", "ok.example": ""} {
		if got := Code(CheckHost(context.Background(), h, res, BlockedIP)); got != want {
			t.Errorf("%s: %q want %q", h, got, want)
		}
	}
}

func TestCleanRel(t *testing.T) {
	for _, ok := range []string{"repositories/site", "public_html/app", "a"} {
		if _, err := CleanRel(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "/etc", "../x", "a/../../x", ".ssh/x", "a/.git", "-rf", "a b", ".bpanel", "mail/x", "a/./b"} {
		if _, err := CleanRel(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestHostAndBranch(t *testing.T) {
	for _, h := range []string{"example.com", "1.1.1.1", "2606:4700::1111", "a-b.example.co.uk."} {
		if !ValidHost(h) {
			t.Errorf("%s rejected", h)
		}
	}
	for _, h := range []string{"", "-n", "localhost", "a;b.com", "a b.com", strings.Repeat("a", 300)} {
		if ValidHost(h) {
			t.Errorf("%q accepted", h)
		}
	}
	if !ValidBranch("main") || !ValidBranch("release/1.2") || ValidBranch("-x") || ValidBranch("a..b") || ValidBranch("x.lock") {
		t.Fatal("branch rules")
	}
}

func TestTokens(t *testing.T) {
	tok, h, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if !WellFormedToken(tok) || HashToken(tok) != h || strings.Contains(h, tok[len(TokenPrefix):]) || len(h) != 64 {
		t.Fatalf("token %q hash %q", tok, h)
	}
	tok2, h2, _ := NewToken()
	if tok2 == tok || h2 == h {
		t.Fatal("tokens not random")
	}
	for _, b := range []string{"", "bpd_", "bpd_short", "xxx_" + tok[4:], tok + "x"} {
		if WellFormedToken(b) {
			t.Errorf("%q accepted", b)
		}
	}
}

func TestGitArgv(t *testing.T) {
	a := strings.Join(GitEnvArgv("/usr/bin/git", "clone", "--", "https://x/y"), " ")
	for _, want := range []string{"GIT_TERMINAL_PROMPT=0", "protocol.file.allow=never", "protocol.allow=never", "-- https://x/y"} {
		if !strings.Contains(a, want) {
			t.Errorf("argv lacks %q: %s", want, a)
		}
	}
}

func TestOpenPTY(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	m, s, err := OpenPTY()
	if err != nil {
		t.Skipf("no pty here: %v", err)
	}
	defer m.Close()
	defer s.Close()
	if err := SetWinsize(m, 100, 30); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("hi\n")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 16)
	n, err := m.Read(b)
	if err != nil || !strings.Contains(string(b[:n]), "hi") {
		t.Fatalf("%q %v", b[:n], err)
	}
	_ = os.Stdout
}
