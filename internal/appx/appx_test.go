// SPDX-License-Identifier: Apache-2.0

package appx

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestCleanRelContainment(t *testing.T) {
	for _, ok := range []string{"apps/api", "x", "a/b.c/d_e-f"} {
		if _, err := CleanRel(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "/etc", "../x", "a/../../b", "a/./b", "a b", "a\\b", "a;b", "~/x", "a/$HOME"} {
		if _, err := CleanRel(bad); code(err) != "appx_invalid_path" {
			t.Errorf("%q accepted (%v)", bad, err)
		}
	}
	if !Within("public_html", "public_html/blog") || Within("public_html", "public_html2") {
		t.Fatal("Within")
	}
}

func TestURLPath(t *testing.T) {
	if p, _ := CleanURLPath(""); p != "/" {
		t.Fatal(p)
	}
	if p, _ := CleanURLPath("api/v1/"); p != "/api/v1" {
		t.Fatal(p)
	}
	for _, bad := range []string{"/a b", "/../x", "/.well-known/acme-challenge", "/a;}", "/a{"} {
		if _, err := CleanURLPath(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAllocPort(t *testing.T) {
	p, err := AllocPort(map[int]bool{30000: true, 30001: true}, 30000, 30005)
	if err != nil || p != 30002 {
		t.Fatal(p, err)
	}
	if _, err := AllocPort(map[int]bool{30000: true, 30001: true}, 30000, 30001); code(err) != "appx_no_free_port" {
		t.Fatal(err)
	}
	if _, err := AllocPort(nil, 80, 90); code(err) != "appx_port_range" {
		t.Fatal(err)
	}
}

func TestValidateAndUnit(t *testing.T) {
	a := App{User: "alice", Name: "api", Runtime: "node", Version: "22", Root: "apps/api", Startup: "server.js", Domain: "a.test", URLPath: "api", Port: 30001,
		Env: map[string]string{"DB_URL": `x"y$z`}}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	u, err := RenderDropIn(a, "/home/alice", "bpanel-u-alice.slice", "/usr/bin/node", "/etc/bpanel/apps/1.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"User=alice", "Slice=bpanel-u-alice.slice", "ExecStart=/usr/bin/node /home/alice/apps/api/server.js", "Environment=PORT=30001", "ReadWritePaths=/home/alice/apps/api"} {
		if !strings.Contains(u, w) {
			t.Errorf("drop-in lacks %q:\n%s", w, u)
		}
	}
	if !strings.Contains(UnitTemplate, "NoNewPrivileges=yes") || !strings.Contains(UnitTemplate, "ProtectSystem=strict") {
		t.Fatal("hardening missing")
	}
	if env := RenderEnvFile(a.Env); env != "DB_URL=\"x\\\"y\\$z\"\n" {
		t.Fatalf("env %q", env)
	}
	for _, e := range []map[string]string{{"PORT": "1"}, {"LD_PRELOAD": "/x"}, {"lower": "x"}, {"A": "x\ny"}} {
		b := a
		b.Env = e
		if err := b.Validate(); code(err) != "appx_invalid_env" {
			t.Errorf("env %v accepted", e)
		}
	}
	b := a
	b.Runtime = "ruby"
	if err := b.Validate(); code(err) != "appx_invalid_runtime" {
		t.Fatal(err)
	}
}

func TestRenderProxy(t *testing.T) {
	s, err := RenderProxy([]Proxy{{"/api", 30001}, {"/", 30002}})
	if err != nil || !strings.Contains(s, "location ^~ /api/ {") || !strings.Contains(s, "proxy_pass http://127.0.0.1:30001/;") || strings.Contains(s, "30002") {
		t.Fatalf("%v\n%s", err, s)
	}
	if RootPort([]Proxy{{"/api", 1}, {"/", 30002}}) != 30002 {
		t.Fatal("root port")
	}
	if _, err := RenderProxy([]Proxy{{"/a", 30001}, {"/a/", 30002}}); code(err) != "appx_url_path_taken" {
		t.Fatal(err)
	}
	if _, err := RenderProxy([]Proxy{{"/a;", 30001}}); err == nil {
		t.Fatal("unsafe path rendered")
	}
}

type ent struct {
	name, body string
	typ        byte
}

func mkTar(t *testing.T, ents []ent) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range ents {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o644, Size: int64(len(e.body))}
		if e.typ == tar.TypeDir {
			h.Size = 0
		}
		if e.typ == tar.TypeSymlink {
			h.Linkname, h.Size = "/etc/passwd", 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestExtractStripAndContainment(t *testing.T) {
	dir := t.TempDir()
	root, _ := os.OpenRoot(dir)
	defer root.Close()
	good := mkTar(t, []ent{{"wordpress/", "", tar.TypeDir}, {"wordpress/index.php", "<?php", tar.TypeReg}, {"wordpress/wp-includes/version.php", "$wp_version = '7.1.3';", tar.TypeReg}})
	if _, err := Extract(bytes.NewReader(good), "tar.gz", "wordpress", root, -1, -1); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "wp-includes/version.php"))
	if ParseWPVersion(b) != "7.1.3" {
		t.Fatalf("version %q", b)
	}
	for _, bad := range [][]ent{
		{{"wordpress/../../evil", "x", tar.TypeReg}},
		{{"/etc/cron.d/x", "x", tar.TypeReg}},
		{{"other/x", "x", tar.TypeReg}},
		{{"wordpress/link", "", tar.TypeSymlink}},
	} {
		d2 := t.TempDir()
		r2, _ := os.OpenRoot(d2)
		if _, err := Extract(bytes.NewReader(mkTar(t, bad)), "tar.gz", "wordpress", r2, -1, -1); code(err) != "appx_archive_unsafe" {
			t.Errorf("%v: %v", bad, err)
		}
		r2.Close()
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "evil")); err == nil {
		t.Fatal("escaped")
	}
}

func TestVerifyFileMismatch(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.tgz")
	os.WriteFile(p, []byte("payload"), 0o600)
	sum := sha256.Sum256([]byte("payload"))
	if err := VerifyFile(p, hex.EncodeToString(sum[:]), ""); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFile(p, strings.Repeat("0", 64), ""); code(err) != "appx_checksum_mismatch" {
		t.Fatal(err)
	}
	if err := VerifyFile(p, hex.EncodeToString(sum[:]), strings.Repeat("0", 40)); code(err) != "appx_checksum_mismatch" {
		t.Fatal(err)
	}
	if err := VerifyFile(p, "", ""); code(err) != "appx_checksum_missing" {
		t.Fatal(err)
	}
}

func TestCatalogPinned(t *testing.T) {
	if Catalog[0].ID != "wordpress" {
		t.Fatal("WordPress must be first")
	}
	for _, c := range Catalog {
		if c.Enabled && (c.URL == "" || len(c.SHA256) != 64 || !strings.HasPrefix(c.URL, "https://") || c.Version == "") {
			t.Errorf("%s enabled without a pinned https URL + sha256", c.ID)
		}
		if !c.Enabled && c.Disabled == "" {
			t.Errorf("%s disabled without a reason", c.ID)
		}
	}
}

func TestWPConfig(t *testing.T) {
	a, err := RenderWPConfig(WPConfig{DBName: "alice_wp", DBUser: "alice_wp", DBPassword: "s3cr3t!x"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := RenderWPConfig(WPConfig{DBName: "alice_wp", DBUser: "alice_wp", DBPassword: "s3cr3t!x"})
	if a == b || !strings.Contains(a, "define( 'NONCE_SALT', '") || !strings.Contains(a, "$table_prefix = 'wp_';") {
		t.Fatal("salts not random or config incomplete")
	}
	if _, err := RenderWPConfig(WPConfig{DBName: "x", DBUser: "y", DBPassword: "a'b"}); err == nil {
		t.Fatal("quote in password accepted")
	}
	if !bytes.Contains(MaintenanceFile(), []byte("time()")) {
		t.Fatal("maintenance")
	}
}
