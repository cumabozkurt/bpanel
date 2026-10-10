package installer

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cumabozkurt/bpanel/internal/agent"
	"github.com/cumabozkurt/bpanel/internal/distro"
)

// R2-SYS-6 / R2-E2E-1: restic binary and restic cache never share a path,
// and the agent uses the installer's paths.
func TestResticPaths(t *testing.T) {
	ac := agent.DefaultConfig()
	if ac.ResticBin != ResticBin {
		t.Fatalf("agent restic_bin %q, installer installs %q", ac.ResticBin, ResticBin)
	}
	if strings.HasPrefix(ResticBin, CacheDir) || ResticBin == ResticCacheDir {
		t.Fatalf("restic binary %s inside the cache", ResticBin)
	}
	if !strings.Contains(Tmpfiles, "d "+ResticCacheDir+" 0700 root root -") {
		t.Fatalf("tmpfiles lacks the restic cache dir:\n%s", Tmpfiles)
	}
}

// R2-SYS-2 / R2-E2E-4: openssh-server on every profile and family.
func TestPackageListOpenSSH(t *testing.T) {
	for _, id := range []string{"ubuntu", "almalinux", "debian"} {
		l, err := distro.ForRelease(map[string]string{"ID": id})
		if err != nil {
			t.Fatal(err)
		}
		for _, prof := range []string{"minimal", "web", "full"} {
			found, curl := false, false
			for _, p := range PackageList(l, prof, nil) {
				found = found || p == "openssh-server"
				curl = curl || p == "curl"
			}
			if !found {
				t.Errorf("%s/%s: openssh-server missing", id, prof)
			}
			if curl && l.Family == distro.RHEL {
				t.Errorf("%s/%s: curl conflicts with curl-minimal (R2-SYS-1)", id, prof)
			}
		}
	}
}

// R2-PERF-1 / R2-PERF-14: unit settings.
func TestUnitsR2(t *testing.T) {
	for _, want := range []string{"Environment=GOMEMLIMIT=", "MemoryMax=", "MemoryHigh="} {
		if !strings.Contains(UnitAPI, want) {
			t.Errorf("API unit lacks %s", want)
		}
	}
	if !strings.Contains(UnitAgent, "ExecStartPre=-"+LibDir+"/bpanel-installer restic-unlock") {
		t.Error("agent unit lacks the non-fatal restic unlock")
	}
}

// R2-E2E-3: Dovecot 2.4 syntax chosen by version.
func TestDovecotConf(t *testing.T) {
	for in, want := range map[string]bool{"2.3.21 (47349e2482)": false, "2.4.1-4 (7d8c0e5759)": true, "2.4.0": true,
		"3.0.0": true, "": false, "garbage": false, "2.10.1": true} {
		if got := DovecotVersion24(in); got != want {
			t.Errorf("DovecotVersion24(%q)=%v", in, got)
		}
	}
	c23 := DovecotConf(false, "/c", "/k", "/p", "h.test")
	c24 := DovecotConf(true, "/c", "/k", "/p", "h.test")
	for _, w := range []string{"mail_location = maildir:~", "ssl_cert = </c", "args = scheme=SSHA512 username_format=%u /p", "quota = maildir:User quota"} {
		if !strings.Contains(c23, w) {
			t.Errorf("2.3 conf lacks %q", w)
		}
	}
	for _, w := range []string{"mail_driver = maildir", "mail_path = %{home}", "ssl_server_cert_file = /c", "passwd_file_path = /p",
		"auth_allow_cleartext = no", "quota \"User quota\" {", "sieve_script personal {", "postmaster_address = postmaster@h.test"} {
		if !strings.Contains(c24, w) {
			t.Errorf("2.4 conf lacks %q", w)
		}
	}
	for _, bad := range []string{"mail_location", "ssl_cert =", "disable_plaintext_auth", "$mail_plugins", "plugin {"} {
		if strings.Contains(c24, bad) {
			t.Errorf("2.4 conf contains 2.3 setting %q", bad)
		}
	}
}

// R2-WB-15: hostname and email validation.
func TestValidateOptions(t *testing.T) {
	for _, h := range []string{"panel.example.com", "PANEL.Example.COM", "noble", "a-b.c-d.example"} {
		if err := ValidHostname(h); err != nil {
			t.Errorf("%q rejected: %v", h, err)
		}
	}
	for _, h := range []string{"", "panel.example.com;\n listen 1", "a..b", "-a.b", "a-.b", "pan el.com", "1.2.3.4", "panel.example.com.",
		"x{y}.com", "p\"a.com", strings.Repeat("a", 64) + ".com"} {
		if ValidHostname(h) == nil {
			t.Errorf("%q accepted", h)
		}
	}
	for _, e := range []string{"", "admin@example.com", "a.b+c@mail.example.org"} {
		if err := ValidEmail(e); err != nil {
			t.Errorf("%q rejected: %v", e, err)
		}
	}
	for _, e := range []string{"a@b.cd\nroot: |/bin/sh", "admin", "Admin <a@b.com>", "a@b", "a b@c.com", "a@b.com;x", "'a'@b.com", "a@-b.com"} {
		if ValidEmail(e) == nil {
			t.Errorf("%q accepted", e)
		}
	}
	if ValidateOptions(Options{ExtraPHP: []string{"8.2;rm"}}) == nil {
		t.Error("bad PHP version accepted")
	}
}

func TestVersionLess(t *testing.T) {
	for _, c := range []struct {
		a, b string
		less bool
	}{{"0.1.0", "0.2.0", true}, {"0.2.0", "0.2.0", false}, {"0.2.0", "0.10.0", true}, {"v0.3.0", "0.2.9", false},
		{"0.2.0-rc1", "0.2.0", false}, {"", "0.1.0", true}, {"1.0", "0.9.9", false}} {
		if got := VersionLess(c.a, c.b); got != c.less {
			t.Errorf("VersionLess(%q,%q)=%v", c.a, c.b, got)
		}
	}
}

// R2-WB-16: exactly one key with the pinned fingerprint.
func TestCheckKeyListing(t *testing.T) {
	one := "pub:-:4096:1:FFA232EDBF21E25E:1438077983:::-:::scESC::::::23\nfpr:::::::::3FA347D5E599BE4595CA2576FFA232EDBF21E25E:\nsub:-:4096:1:FE2A076B3EF4A6C1:1438077983::::::e::::::23:\nfpr:::::::::B188282805BCD56103A7147BFE2A076B3EF4A6C1:\n"
	if err := checkKeyListing(one, RspamdKeyFPR); err != nil {
		t.Fatal(err)
	}
	if checkKeyListing(one, PDNSKeyFPR) == nil {
		t.Fatal("wrong fingerprint accepted")
	}
	two := one + "pub:-:4096:1:AAAA:1:::-:::scSC::::::23:\nfpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\n"
	if checkKeyListing(two, RspamdKeyFPR) == nil {
		t.Fatal("extra key accepted")
	}
	// the expected fingerprint only as a subkey
	sub := "pub:-:4096:1:AAAA:1:::-:::scSC::::::23:\nfpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\nsub:-:4096:1:X:1::::::e::::::23:\nfpr:::::::::" + RspamdKeyFPR + ":\n"
	if checkKeyListing(sub, RspamdKeyFPR) == nil {
		t.Fatal("subkey fingerprint accepted as primary")
	}
}

// R2-WB-20: the fail2ban filter only ever bans the ip field of the API's
// own log line, whatever the username holds (checked against real slog text).
func TestFail2banFilterAnchored(t *testing.T) {
	var re *regexp.Regexp
	for _, l := range strings.Split(Fail2banPanelFilter, "\n") {
		if v, ok := strings.CutPrefix(l, "failregex = "); ok {
			re = regexp.MustCompile(strings.Replace(v, "<HOST>", `(?P<host>[0-9a-fA-F:.]+)`, 1))
		}
	}
	if re == nil {
		t.Fatal("no failregex")
	}
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	cases := []struct{ user, ip string }{
		{"bob", "198.51.100.7"}, {"x ip=203.0.113.9 y", "198.51.100.8"}, {`a" ip=203.0.113.10`, "198.51.100.9"},
		{"q\nmsg=\"auth failure\" realm=user user=z ip=203.0.113.11", "198.51.100.10"}, {"", "2001:db8::5"}, {"ip=203.0.113.12", "198.51.100.11"},
	}
	for _, c := range cases {
		buf.Reset()
		log.Warn("auth failure", "realm", "user", "user", c.user, "ip", c.ip, "reason", "bad password")
		line := "Oct  9 15:00:00 host bpanel-api[1]: " + strings.TrimSpace(buf.String())
		m := re.FindStringSubmatch(line)
		if m == nil || m[re.SubexpIndex("host")] != c.ip {
			t.Errorf("user %q: matched %v, want ip %s\n%s", c.user, m, c.ip, line)
		}
	}
	buf.Reset()
	log.Info("login ok", "user", "x", "note", `msg="auth failure" realm=user user=z ip=203.0.113.13`)
	if re.MatchString(buf.String()) {
		t.Errorf("non-failure line matched: %s", buf.String())
	}
}

// R2-SYS-5: the probe retries, never follows the catch-all redirect and
// sends the vhost's Host header.
func TestProbeSite(t *testing.T) {
	old := probeSchedule
	probeSchedule = []time.Duration{0, 10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond}
	defer func() { probeSchedule = old }()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "bptest1.selftest.invalid" {
			t.Errorf("Host %q", r.Host)
		}
		if n.Add(1) < 3 {
			http.Redirect(w, r, "https://panel.test:2083/", http.StatusFound)
			return
		}
		w.Write([]byte("<h1>bptest1</h1>"))
	}))
	defer srv.Close()
	if err := ProbeSite(context.Background(), srv.URL+"/", "bptest1.selftest.invalid", "bptest1"); err != nil {
		t.Fatal(err)
	}
	n.Store(-100)
	err := ProbeSite(context.Background(), srv.URL+"/", "bptest1.selftest.invalid", "bptest1")
	if err == nil || !strings.Contains(err.Error(), "catch-all") {
		t.Fatalf("want catch-all error, got %v", err)
	}
}

// R2-SYS-16: minimal profile flags DNS/FTP/mail off for the API.
func TestCapabilities(t *testing.T) {
	m := Capabilities{Profile: "minimal", Features: ProfileFeatures("minimal")}.Settings()
	for _, k := range []string{"feature_dns", "feature_ftp", "feature_mail", "feature_apache", "feature_webmail"} {
		if m[k] != "0" {
			t.Errorf("minimal %s=%q", k, m[k])
		}
	}
	f := Capabilities{Profile: "full", Features: ProfileFeatures("full"), DovecotSyntax: "2.4"}.Settings()
	for _, k := range []string{"feature_dns", "feature_ftp", "feature_mail", "feature_apache"} {
		if f[k] != "1" {
			t.Errorf("full %s=%q", k, f[k])
		}
	}
	if f["dovecot_syntax"] != "2.4" {
		t.Error("dovecot_syntax not exported")
	}
	if w := ProfileFeatures("web"); w["mail"] || !w["dns"] || !w["ftp"] {
		t.Errorf("web features %v", w)
	}
}
