// SPDX-License-Identifier: Apache-2.0

package clusterx

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return "other:" + err.Error()
}

func TestValidateSecondaryIP(t *testing.T) {
	good := map[string]string{"192.0.2.10": "192.0.2.10", " 10.0.0.5 ": "10.0.0.5", "2001:db8::53": "2001:db8::53", "::ffff:198.51.100.7": "198.51.100.7"}
	for in, want := range good {
		got, err := ValidateSecondaryIP(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q %v", in, got, err)
		}
	}
	for _, in := range []string{"", "ns2.example.com", "127.0.0.1", "::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "169.254.1.1", "fe80::1",
		"fe80::1%eth0", "255.255.255.255", "1.2.3.4/24", "1.2.3.4:53", "1.2.3.4,5.6.7.8", "1.2.3.4\nallow-axfr-ips=0.0.0.0/0"} {
		if _, err := ValidateSecondaryIP(in); code(err) != "cluster_invalid_ip" {
			t.Errorf("%q accepted (%v)", in, err)
		}
	}
	ips, err := NormalizeIPs([]string{"192.0.2.2", "192.0.2.1", "192.0.2.2"})
	if err != nil || strings.Join(ips, ",") != "192.0.2.1,192.0.2.2" {
		t.Fatalf("normalize: %v %v", ips, err)
	}
}

func TestRenderPdnsConf(t *testing.T) {
	c, err := RenderPdnsConf([]string{"192.0.2.2", "2001:db8::2"})
	if err != nil || !strings.Contains(c, "allow-axfr-ips=192.0.2.2,2001:db8::2\n") || !strings.Contains(c, "also-notify=192.0.2.2,2001:db8::2\n") || !strings.Contains(c, "primary=yes") {
		t.Fatalf("conf: %q %v", c, err)
	}
	if c, err := RenderPdnsConf(nil); c != "" || err != nil {
		t.Fatalf("empty: %q %v", c, err)
	}
	if _, err := RenderPdnsConf([]string{"127.0.0.1"}); err == nil {
		t.Fatal("loopback rendered")
	}
}

func TestSerialCompareAndSOAState(t *testing.T) {
	cases := []struct {
		a, b uint32
		want int
	}{{1, 1, 0}, {1, 2, -1}, {2, 1, 1}, {4294967295, 0, -1}, {0, 4294967295, 1}, {2026101001, 2026101002, -1}, {100, 100 + 1<<31 - 1, -1}}
	for _, c := range cases {
		if got := SerialCompare(c.a, c.b); got != c.want {
			t.Errorf("SerialCompare(%d,%d)=%d want %d", c.a, c.b, got, c.want)
		}
	}
	p := SOAResult{Serial: 2026101005, Found: true}
	if s := CompareSOA(p, SOAResult{Serial: 2026101005, Found: true}); s != StateInSync {
		t.Error(s)
	}
	if s := CompareSOA(p, SOAResult{Serial: 2026101001, Found: true}); s != StateBehind {
		t.Error(s)
	}
	if s := CompareSOA(p, SOAResult{Serial: 2026101009, Found: true}); s != StateAhead {
		t.Error(s)
	}
	if s := CompareSOA(p, SOAResult{Err: errors.New("timeout")}); s != StateUnreachable {
		t.Error(s)
	}
	if s := CompareSOA(p, SOAResult{}); s != StateMissing {
		t.Error(s)
	}
	if s := CompareSOA(SOAResult{Err: errors.New("x")}, SOAResult{Serial: 1, Found: true}); s != StateUnknown {
		t.Error(s)
	}
}

// TestQuerySOA runs a real DNS server on loopback (miekg/dns) and an address
// that never answers.
func TestQuerySOA(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no udp:", err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc("example.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		rr, _ := dns.NewRR("example.test. 300 IN SOA ns1.example.test. host.example.test. 2026101007 3600 600 604800 300")
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go srv.ActivateAndServe()
	defer srv.Shutdown()
	time.Sleep(50 * time.Millisecond)
	addr := pc.LocalAddr().String()
	r := QuerySOA(context.Background(), addr, "example.test", 2*time.Second)
	if r.Err != nil || !r.Found || r.Serial != 2026101007 {
		t.Fatalf("soa: %+v", r)
	}
	if r := QuerySOA(context.Background(), addr, "other.test", 2*time.Second); r.Found || r.Err != nil {
		t.Fatalf("refused zone: %+v", r)
	}
	// a bound but silent UDP socket: must time out, not hang
	silent, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer silent.Close()
	start := time.Now()
	if r := QuerySOA(context.Background(), silent.LocalAddr().String(), "example.test", 300*time.Millisecond); r.Err == nil {
		t.Fatalf("silent server answered: %+v", r)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout not honoured")
	}
}

// ---- plugins ------------------------------------------------------------------

func tgz(t *testing.T, entries ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, h := range entries {
		body := []byte{}
		if h.Typeflag == tar.TypeReg {
			body = bytes.Repeat([]byte("x"), int(h.Size))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write(body)
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func reg(name string) *tar.Header {
	return &tar.Header{Name: name, Typeflag: tar.TypeReg, Size: 3, Mode: 0o644}
}

func TestExtractRejectsUnsafeEntries(t *testing.T) {
	cases := map[string][]*tar.Header{
		"traversal":      {reg("plugin.json"), reg("ui/../../etc/passwd")},
		"traversal2":     {reg("plugin.json"), reg("../plugin.json")},
		"absolute":       {reg("plugin.json"), reg("/etc/cron.d/x")},
		"symlink":        {reg("plugin.json"), {Name: "ui/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}},
		"hardlink":       {reg("plugin.json"), {Name: "ui/hard", Typeflag: tar.TypeLink, Linkname: "plugin.json"}},
		"device":         {reg("plugin.json"), {Name: "ui/dev", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3}},
		"fifo":           {reg("plugin.json"), {Name: "ui/fifo", Typeflag: tar.TypeFifo}},
		"outside ui":     {reg("plugin.json"), reg("bin/run.sh")},
		"backslash":      {reg("plugin.json"), reg(`ui\..\x`)},
		"dotdot dir":     {reg("plugin.json"), {Name: "ui/../", Typeflag: tar.TypeDir}},
		"hidden segment": {reg("plugin.json"), reg("ui/a/../b")},
	}
	for name, hs := range cases {
		_, err := Extract(tgz(t, hs...))
		if code(err) != "plugin_unsafe_path" {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if _, err := Extract(tgz(t, reg("plugin.json"), &tar.Header{Name: "ui/big", Typeflag: tar.TypeReg, Size: MaxFileBytes + 1})); code(err) != "plugin_too_large" {
		t.Errorf("big file: %v", err)
	}
	if _, err := Extract(bytes.Repeat([]byte{0}, MaxArchiveBytes+1)); code(err) != "plugin_too_large" {
		t.Errorf("big archive: %v", err)
	}
	if _, err := Extract([]byte("not gzip")); code(err) != "plugin_invalid_archive" {
		t.Errorf("garbage: %v", err)
	}
	if _, err := Extract(tgz(t, reg("ui/index.html"))); code(err) != "plugin_invalid_manifest" {
		t.Errorf("no manifest: %v", err)
	}
	if _, err := Extract(tgz(t, reg("plugin.json"), reg("./ui/index.html"), &tar.Header{Name: "ui/", Typeflag: tar.TypeDir})); err != nil {
		t.Errorf("good archive rejected: %v", err)
	}
}

const goodManifest = `{"name":"hello","version":"1.0.0","author":"Example","license":"Apache-2.0","permissions":["ui.page","events.subscribe","agent.read"],
"ui_entry":"index.html","agent_actions":["system.info"],"hooks":[{"events":["account.*"],"url":"https://hooks.example.com/bpanel"}]}`

func signed(t *testing.T, manifest string, priv ed25519.PrivateKey) map[string][]byte {
	files := map[string][]byte{"plugin.json": []byte(manifest), "ui/index.html": []byte("<h1>hi</h1>")}
	files["plugin.sig"] = Sign(files, priv)
	return files
}

func TestManifestAllowlists(t *testing.T) {
	files := map[string][]byte{"ui/index.html": nil}
	m, err := ParseManifest([]byte(goodManifest))
	if err != nil || m.Validate(files) != nil {
		t.Fatalf("good manifest: %v %v", err, m.Validate(files))
	}
	bad := map[string]string{
		`"permissions":["ui.page","root.exec"]`:                                  "plugin_permission_denied",
		`"permissions":["ui.page","events.subscribe"]`:                           "plugin_permission_denied", // agent_actions without agent.read
		`"agent_actions":["account.create"]`:                                     "plugin_unknown_action",
		`"agent_actions":["system.info; rm -rf /"]`:                              "plugin_unknown_action",
		`"name":"../etc"`:                                                        "plugin_invalid_manifest",
		`"version":"latest"`:                                                     "plugin_invalid_manifest",
		`"ui_entry":"../index.html"`:                                             "plugin_unsafe_path",
		`"ui_entry":"missing.html"`:                                              "plugin_invalid_manifest",
		`"hooks":[{"events":["account.*"],"url":"file:///etc/passwd"}]`:          "plugin_invalid_manifest",
		`"hooks":[{"events":["account.*"],"url":"https://u:p@example.com/"}]`:    "plugin_invalid_manifest",
		`"hooks":[{"events":["BAD EVENT"],"url":"https://hooks.example.com/x"}]`: "plugin_invalid_manifest",
	}
	repl := map[string]string{"permissions": `"permissions":["ui.page","events.subscribe","agent.read"]`, "agent_actions": `"agent_actions":["system.info"]`,
		"name": `"name":"hello"`, "version": `"version":"1.0.0"`, "ui_entry": `"ui_entry":"index.html"`,
		"hooks": `"hooks":[{"events":["account.*"],"url":"https://hooks.example.com/bpanel"}]`}
	for frag, want := range bad {
		key := strings.Trim(strings.SplitN(frag, ":", 2)[0], `"`)
		js := strings.Replace(goodManifest, repl[key], frag, 1)
		if js == goodManifest {
			t.Fatalf("replacement for %s did not apply", key)
		}
		m, err := ParseManifest([]byte(js))
		if err == nil {
			err = m.Validate(files)
		}
		if code(err) != want {
			t.Errorf("%s: got %v want %s", frag, err, want)
		}
	}
	if _, err := ParseManifest([]byte(`{"name":"x","exec":"/bin/sh"}`)); code(err) != "plugin_invalid_manifest" {
		t.Error("unknown manifest field accepted")
	}
}

func TestSignatureVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	files := signed(t, goodManifest, priv)
	id, err := Verify(files, []ed25519.PublicKey{pub2, pub})
	if err != nil || id != KeyID(pub) {
		t.Fatalf("good signature: %v %v", id, err)
	}
	// signed by an untrusted key
	if _, err := Verify(signed(t, goodManifest, priv2), []ed25519.PublicKey{pub}); code(err) != "plugin_bad_signature" {
		t.Errorf("untrusted signer: %v", err)
	}
	// tampered file after signing
	tam := map[string][]byte{}
	for k, v := range files {
		tam[k] = v
	}
	tam["ui/index.html"] = []byte("<script>evil()</script>")
	if _, err := Verify(tam, []ed25519.PublicKey{pub}); code(err) != "plugin_bad_signature" {
		t.Errorf("tampered: %v", err)
	}
	// added file after signing
	tam2 := map[string][]byte{"ui/extra.js": []byte("x")}
	for k, v := range files {
		tam2[k] = v
	}
	if _, err := Verify(tam2, []ed25519.PublicKey{pub}); code(err) != "plugin_bad_signature" {
		t.Errorf("added file: %v", err)
	}
	delete(tam2, "plugin.sig")
	if _, err := Verify(tam2, []ed25519.PublicKey{pub}); code(err) != "plugin_bad_signature" {
		t.Errorf("missing sig: %v", err)
	}
	if _, err := Verify(files, nil); code(err) != "plugin_untrusted" {
		t.Errorf("no keys: %v", err)
	}
	// round trip through an archive
	got, m, err := Load(PackTarGz(files))
	if err != nil || m.Name != "hello" {
		t.Fatalf("load: %v", err)
	}
	if _, err := Verify(got, []ed25519.PublicKey{pub}); err != nil {
		t.Fatalf("verify after pack: %v", err)
	}
	if _, err := ParsePublicKey(base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicKey("AAAA"); code(err) != "plugin_invalid_key" {
		t.Fatal("short key accepted")
	}
}
