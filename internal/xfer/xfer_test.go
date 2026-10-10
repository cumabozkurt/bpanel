// SPDX-License-Identifier: Apache-2.0

package xfer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type member struct {
	name, body, link string
	typ              byte
	size             int64 // header size override (oversize test)
}

func writeTGZ(t *testing.T, ms []member) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, m := range ms {
		h := &tar.Header{Name: m.name, Mode: 0o644, Typeflag: m.typ, Linkname: m.link}
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(m.body))
		}
		if h.Typeflag == tar.TypeDir {
			h.Mode = 0o755
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte(m.body))
		}
	}
	tw.Close()
	gz.Close()
	p := filepath.Join(t.TempDir(), "a.tar.gz")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// synthetic cPanel account (no real customer data)
func cpmoveFixture() []member {
	r := "cpmove-alice/"
	return []member{
		{name: r, typ: tar.TypeDir},
		{name: r + "version", body: "pkgacct version: 10\n"},
		{name: r + "cp/alice", body: "USER=alice\nDNS=alice.test\nDNS1=addon.test\nPLAN=basic\nCONTACTEMAIL=owner@example.org\n"},
		{name: r + "userdata/main", body: "---\naddon_domains:\n  addon.test: addon.alice.test\nmain_domain: alice.test\nparked_domains:\n  - parked.test\nsub_domains:\n  - addon.alice.test\n  - blog.alice.test\n"},
		{name: r + "userdata/alice.test", body: "---\ndocumentroot: /home/alice/public_html\n"},
		{name: r + "homedir/public_html/index.html", body: "<h1>hi</h1>"},
		{name: r + "homedir/public_html/link", typ: tar.TypeSymlink, link: "index.html"},
		{name: r + "mysql/alice_wp.sql", body: "CREATE TABLE t (id int);\n"},
		{name: r + "mysql.sql", body: "GRANT USAGE ON *.* TO 'alice'@'localhost';\n"},
		{name: r + "dnszones/alice.test.db", body: "$TTL 300\nalice.test. IN SOA ns1.x. h.x. 1 2 3 4 5\nwww IN A 192.0.2.10\n"},
		{name: r + "va/alice.test", body: "info@alice.test: someone@example.org\nevil@alice.test: \"|/usr/bin/evil\"\n*: alice\n"},
		{name: r + "etc/alice.test/passwd", body: "info:x:1000:1000::/home/alice/mail/alice.test/info:/home/alice\n"},
		{name: r + "etc/alice.test/shadow", body: "info:$6$salt$hash:19000::::::\n"},
		{name: r + "etc/alice.test/quota", body: "info:1048576000\n"},
		{name: r + "cron/alice", body: "* * * * * rm -rf /\n"},
		{name: r + "sslcerts/alice_test.crt", body: "-----BEGIN CERTIFICATE-----\n"},
	}
}

func TestCPanelAnalyse(t *testing.T) {
	p := writeTGZ(t, cpmoveFixture())
	m, err := Analyse(p, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if m.Format != FormatCPanel || m.Account.Username != "alice" || m.Account.MainDomain != "alice.test" || m.Root != "cpmove-alice" {
		t.Fatalf("account: %+v root=%s", m.Account, m.Root)
	}
	kinds := map[string]string{}
	for _, d := range m.Domains {
		kinds[d.Name] = d.Kind
	}
	if kinds["alice.test"] != "main" || kinds["addon.test"] != "addon" || kinds["parked.test"] != "parked" || kinds["blog.alice.test"] != "sub" || kinds["addon.alice.test"] != "" {
		t.Fatalf("domains: %+v", m.Domains)
	}
	if len(m.Databases) != 1 || m.Databases[0].Name != "alice_wp" {
		t.Fatalf("dbs: %+v", m.Databases)
	}
	if len(m.Zones) != 1 || !strings.Contains(m.Zones[0].Text, "192.0.2.10") {
		t.Fatalf("zones: %+v", m.Zones)
	}
	if len(m.Forwarders) != 1 || m.Forwarders[0].To[0] != "someone@example.org" {
		t.Fatalf("pipe forwarder must be dropped: %+v", m.Forwarders)
	}
	if len(m.Mailboxes) != 1 || !m.Mailboxes[0].HasHash || m.Mailboxes[0].QuotaMB != 1000 {
		t.Fatalf("mailboxes: %+v", m.Mailboxes)
	}
	if m.Home.Files != 1 {
		t.Fatalf("home: %+v", m.Home)
	}
	un := map[string]bool{}
	for _, u := range m.Unsupported {
		un[u.Part] = true
	}
	if !un["cron"] || !un["mysql.sql"] || !un["ssl"] {
		t.Fatalf("unsupported: %+v", m.Unsupported)
	}
	// extraction of homedir stays inside dest
	dest := t.TempDir()
	n, _, err := Extract(p, dest, DefaultLimits, ExtractOptions{Prefix: m.HomePrefix()})
	if err != nil || n != 1 {
		t.Fatalf("extract n=%d err=%v", n, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "public_html/link")); string(b) != "<h1>hi</h1>" {
		t.Fatal("symlink inside root not restored")
	}
}

func TestRejectsUnsafeArchives(t *testing.T) {
	cases := map[string][]member{
		"traversal": {{name: "cpmove-x/homedir/../../etc/passwd", body: "x"}},
		"absolute":  {{name: "/etc/passwd", body: "x"}},
		"symlink":   {{name: "cpmove-x/homedir/l", typ: tar.TypeSymlink, link: "../../../../etc"}},
		"abs-link":  {{name: "cpmove-x/homedir/l", typ: tar.TypeSymlink, link: "/etc/shadow"}},
		"hardlink":  {{name: "cpmove-x/homedir/h", typ: tar.TypeLink, link: "cpmove-x/cp/x"}},
		"device":    {{name: "cpmove-x/homedir/d", typ: tar.TypeChar}},
	}
	for name, ms := range cases {
		p := writeTGZ(t, ms)
		if _, err := Analyse(p, DefaultLimits); !errors.Is(err, ErrUnsafe) {
			t.Errorf("%s: want ErrUnsafe, got %v", name, err)
		}
		if _, _, err := Extract(p, t.TempDir(), DefaultLimits, ExtractOptions{}); !errors.Is(err, ErrUnsafe) {
			t.Errorf("%s extract: want ErrUnsafe, got %v", name, err)
		}
	}
}

func TestRejectsOversize(t *testing.T) {
	p := writeTGZ(t, append(cpmoveFixture(), member{name: "cpmove-alice/homedir/big", body: strings.Repeat("x", 4096)}))
	if _, err := Analyse(p, Limits{MaxEntries: 1000, MaxEntryBytes: 1024, MaxTotalBytes: 1 << 20}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("entry size: %v", err)
	}
	if _, err := Analyse(p, Limits{MaxEntries: 1000, MaxEntryBytes: 1 << 20, MaxTotalBytes: 2048}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("total size: %v", err)
	}
	if _, err := Analyse(p, Limits{MaxEntries: 3, MaxEntryBytes: 1 << 20, MaxTotalBytes: 1 << 20}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("entry count: %v", err)
	}
}

func buildBPanel(t *testing.T, tamper func(w *Writer)) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "acct.tar.gz")
	f, _ := os.Create(p)
	gz := gzip.NewWriter(f)
	w := NewWriter(gz)
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(w.AddDir("homedir", 0o755))
	must(w.AddBytes("homedir/public_html/index.php", []byte("<?php echo 1;")))
	must(w.AddSymlink("homedir/www", "public_html"))
	must(w.AddSymlink("homedir/evil", "../../etc")) // silently not exported
	must(w.AddBytes("mysql/bob_shop.sql", []byte("CREATE TABLE x(i int);")))
	must(w.AddBytes("dnszones/bob.test.zone", []byte("www 300 IN A 192.0.2.1\n")))
	must(w.AddBytes("mail/mailboxes.json", []byte(`[{"address":"me@bob.test","quota_mb":50,"hash":"{SHA512-CRYPT}$6$x$y"}]`)))
	if tamper != nil {
		tamper(w)
	}
	must(w.Close(Manifest{Account: Account{Username: "bob", MainDomain: "bob.test", Email: "b@example.org"},
		Domains:    []Domain{{Name: "bob.test", Kind: "main"}, {Name: "shop.test", Kind: "addon"}},
		Databases:  []Database{{Name: "bob_shop", Dump: "mysql/bob_shop.sql"}},
		Zones:      []Zone{{Domain: "bob.test", Member: "dnszones/bob.test.zone"}},
		Forwarders: []Forwarder{{From: "sales@bob.test", To: []string{"x@example.org"}}}}))
	gz.Close()
	f.Close()
	return p
}

func TestBPanelRoundTrip(t *testing.T) {
	m, err := Analyse(buildBPanel(t, nil), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if m.Format != FormatBPanel || m.Account.Username != "bob" || len(m.Domains) != 2 || len(m.Databases) != 1 ||
		len(m.Zones) != 1 || !strings.Contains(m.Zones[0].Text, "192.0.2.1") || len(m.Mailboxes) != 1 || !m.Mailboxes[0].HasHash ||
		len(m.Forwarders) != 1 || m.Home.Files != 1 {
		t.Fatalf("model: %+v", m)
	}
}

func TestBPanelChecksumMismatch(t *testing.T) {
	p := buildBPanel(t, nil)
	// rewrite the archive with one member's content changed but the same manifest
	var ms []member
	var manifest string
	err := WalkFile(p, DefaultLimits, func(e Entry, body io.Reader) error {
		bb, _ := io.ReadAll(body)
		b := string(bb)
		switch {
		case e.Name == ManifestName:
			manifest = b
		case e.Type == tar.TypeReg:
			if e.Name == "mysql/bob_shop.sql" {
				b = strings.Replace(b, "int", "INT", 1) // same size, different content
			}
			ms = append(ms, member{name: e.Name, body: b})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ms = append(ms, member{name: ManifestName, body: manifest})
	if _, err := Analyse(writeTGZ(t, ms), DefaultLimits); !errors.Is(err, ErrChecksum) {
		t.Fatalf("want checksum mismatch, got %v", err)
	}
	// extra member not in manifest
	ms = append(ms[:len(ms)-1], member{name: "homedir/extra", body: "x"}, member{name: ManifestName, body: manifest})
	if _, err := Analyse(writeTGZ(t, ms), DefaultLimits); !errors.Is(err, ErrChecksum) {
		t.Fatalf("want checksum error for extra member, got %v", err)
	}
}

func TestHestiaRecognised(t *testing.T) {
	p := writeTGZ(t, []member{{name: "hestia/user.conf", body: "NAME='x'\n"}, {name: "pam/passwd", body: "x:x:1000"}})
	if _, err := Analyse(p, DefaultLimits); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("want unsupported, got %v", err)
	}
	if _, err := Analyse(writeTGZ(t, []member{{name: "random.txt", body: "x"}}), DefaultLimits); !errors.Is(err, ErrFormat) {
		t.Fatalf("want unknown format, got %v", err)
	}
}

type fakeRes map[string][]string

func (f fakeRes) LookupIPAddr(_ context.Context, h string) ([]net.IPAddr, error) {
	var out []net.IPAddr
	for _, s := range f[h] {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

func TestRemoteGuard(t *testing.T) {
	res := fakeRes{"good.example": {"203.0.113.5"}, "rebind.example": {"203.0.113.5", "127.0.0.1"}, "lan.example": {"10.0.0.5"}}
	if ip, err := ResolveSafe(context.Background(), res, "good.example", false); err != nil || ip != "203.0.113.5" {
		t.Fatal(ip, err)
	}
	for _, h := range []string{"rebind.example", "lan.example", "127.0.0.1", "169.254.169.254", "::1", "0.0.0.0"} {
		if _, err := ResolveSafe(context.Background(), res, h, false); !errors.Is(err, ErrRemoteBlocked) {
			t.Errorf("%s: want blocked, got %v", h, err)
		}
	}
	if _, err := ResolveSafe(context.Background(), res, "lan.example", true); err != nil {
		t.Errorf("private allowed when enabled: %v", err)
	}
	bad := []Remote{
		{Host: "-oProxyCommand=x", User: "root", RemotePath: "/a.tar.gz", Auth: "key"},
		{Host: "h.example", User: "root", RemotePath: "/a;rm -rf.tar.gz", Auth: "key"},
		{Host: "h.example", User: "root", RemotePath: "/x/../a.tar.gz", Auth: "key"},
		{Host: "h.example", User: "root", RemotePath: "/a.tar.gz", Auth: "agent"},
		{Host: "h.example", User: "Root$", RemotePath: "/a.tar.gz", Auth: "key"},
	}
	for _, r := range bad {
		if err := r.Validate(); !errors.Is(err, ErrRemoteInvalid) {
			t.Errorf("%+v: want invalid", r)
		}
	}
	r := Remote{Host: "h.example", User: "root", RemotePath: "/backup/cpmove-a.tar.gz", Auth: "key"}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	argv := ScpArgv(r, "203.0.113.5", "/k", "/kh", "/dest", 20)
	j := strings.Join(argv, " ")
	if argv[0] != "scp" || !strings.Contains(j, "StrictHostKeyChecking=accept-new") || !strings.Contains(j, " -s ") ||
		!strings.Contains(j, "-- root@203.0.113.5:/backup/cpmove-a.tar.gz /dest") {
		t.Fatal(j)
	}
}
