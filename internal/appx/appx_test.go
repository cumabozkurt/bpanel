// SPDX-License-Identifier: Apache-2.0

package appx

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
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
	b.Runtime = "perl"
	if err := b.Validate(); code(err) != "appx_invalid_runtime" {
		t.Fatal(err)
	}
	b.Runtime = RuntimeRuby // v1.1: Ruby (Rack/Rails) apps
	if err := b.Validate(); err != nil {
		t.Fatalf("ruby refused: %v", err)
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
		if e.typ == tar.TypeSymlink || e.typ == tar.TypeLink {
			h.Linkname, h.Size = "/etc/passwd", 0
			if e.body != "" {
				h.Linkname = e.body
			}
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

func mkZip(t *testing.T, ents []ent, symlink string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range ents {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if strings.HasSuffix(e.name, "/") {
			h.SetMode(fs.ModeDir | 0o755)
		} else {
			h.SetMode(0o644)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(e.body))
	}
	if symlink != "" {
		h := &zip.FileHeader{Name: symlink}
		h.SetMode(fs.ModeSymlink | 0o777)
		w, _ := zw.CreateHeader(h)
		w.Write([]byte("/etc/passwd"))
	}
	zw.Close()
	return buf.Bytes()
}

func extractBytes(t *testing.T, data []byte, c CatalogApp) (string, error) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(t.TempDir(), "a")
	os.WriteFile(p, data, 0o600)
	f, _ := os.Open(p)
	defer f.Close()
	root, _ := os.OpenRoot(dir)
	defer root.Close()
	_, err := ExtractApp(f, c, root, -1, -1)
	return dir, err
}

func TestExtractZip(t *testing.T) {
	good := mkZip(t, []ent{{"grav/", "", 0}, {"grav/index.php", "<?php", 0}, {"grav/user/config/system.yaml", "a: 1", 0}}, "")
	dir, err := extractBytes(t, good, CatalogApp{Format: "zip", Strip: "grav"})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "user/config/system.yaml")); string(b) != "a: 1" {
		t.Fatalf("got %q", b)
	}
	for name, data := range map[string][]byte{
		"traversal": mkZip(t, []ent{{"grav/../../evil", "x", 0}}, ""),
		"absolute":  mkZip(t, []ent{{"/etc/x", "x", 0}}, ""),
		"outside":   mkZip(t, []ent{{"other/x", "x", 0}}, ""),
		"symlink":   mkZip(t, []ent{{"grav/a", "x", 0}}, "grav/link"),
		"notzip":    []byte("not a zip"),
	} {
		if _, err := extractBytes(t, data, CatalogApp{Format: "zip", Strip: "grav"}); code(err) != "appx_archive_unsafe" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestExtractStripOnly(t *testing.T) {
	// MyBB / OpenCart / Matomo ship docs next to the application directory.
	z := mkZip(t, []ent{{"Documentation/index.html", "doc", 0}, {"Upload/index.php", "<?php", 0}}, "")
	if _, err := extractBytes(t, z, CatalogApp{Format: "zip", Strip: "Upload"}); code(err) != "appx_archive_unsafe" {
		t.Fatalf("strict strip must refuse: %v", err)
	}
	dir, err := extractBytes(t, z, CatalogApp{Format: "zip", Strip: "Upload", StripOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "index.php")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "Documentation")); err == nil {
		t.Fatal("entry outside Upload/ extracted")
	}
	// unsafe names stay errors even with StripOnly
	bad := mkZip(t, []ent{{"x/../../evil", "x", 0}}, "")
	if _, err := extractBytes(t, bad, CatalogApp{Format: "zip", Strip: "Upload", StripOnly: true}); code(err) != "appx_archive_unsafe" {
		t.Fatal(err)
	}
	tgz := mkTar(t, []ent{{"How to install.html", "x", tar.TypeReg}, {"matomo/index.php", "<?php", tar.TypeReg}})
	if dir, err = extractBytes(t, tgz, CatalogApp{Format: "tar.gz", Strip: "matomo", StripOnly: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "index.php")); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogShape(t *testing.T) {
	seen := map[string]bool{}
	cats := map[string]bool{"cms": true, "blog": true, "wiki": true, "forum": true, "shop": true, "analytics": true, "marketing": true, "files": true}
	enabled := 0
	for _, c := range Catalog {
		if seen[c.ID] || !nameRe.MatchString(c.ID) {
			t.Errorf("bad or duplicate id %q", c.ID)
		}
		seen[c.ID] = true
		if !cats[c.Category] {
			t.Errorf("%s: category %q", c.ID, c.Category)
		}
		if !c.Enabled {
			continue
		}
		enabled++
		if c.Format != "tar.gz" && c.Format != "tar.bz2" && c.Format != "zip" {
			t.Errorf("%s: format %q", c.ID, c.Format)
		}
		if !versionRe.MatchString(c.MinPHP) {
			t.Errorf("%s: min php %q", c.ID, c.MinPHP)
		}
		if c.PostInstall == "" || c.License == "" || !strings.HasPrefix(c.Homepage, "https://") {
			t.Errorf("%s: missing metadata", c.ID)
		}
		if c.StripOnly && c.Strip == "" {
			t.Errorf("%s: StripOnly without Strip", c.ID)
		}
		for _, rn := range c.Renames {
			if _, err := CleanRel(rn[0]); err != nil {
				t.Errorf("%s: rename %v", c.ID, rn)
			}
			if _, err := CleanRel(rn[1]); err != nil {
				t.Errorf("%s: rename %v", c.ID, rn)
			}
		}
	}
	if enabled < 15 {
		t.Errorf("only %d installable apps", enabled)
	}
}

// TestCatalogArchives checks every enabled entry against the real upstream
// file: BPANEL_APPX_ARCHIVES=<dir> holding the downloads (named like the
// last segment of the URL). Each one must match its pinned checksum and
// extract cleanly (no links, no escaping entries, Strip present).
func TestCatalogArchives(t *testing.T) {
	dir := os.Getenv("BPANEL_APPX_ARCHIVES")
	if dir == "" {
		t.Skip("BPANEL_APPX_ARCHIVES not set")
	}
	for _, c := range Catalog {
		if !c.Enabled {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			p := filepath.Join(dir, path.Base(c.URL))
			if _, err := os.Stat(p); err != nil {
				t.Skip("not downloaded")
			}
			if err := VerifyFile(p, c.SHA256, c.SHA1); err != nil {
				t.Fatal(err)
			}
			f, _ := os.Open(p)
			defer f.Close()
			out := t.TempDir()
			root, _ := os.OpenRoot(out)
			defer root.Close()
			n, err := ExtractApp(f, c, root, -1, -1)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(out, "index.php")); err != nil {
				t.Errorf("no index.php at the top after extracting %d entries", n)
			}
		})
	}
}

func TestExtractLinksBecomeCopies(t *testing.T) {
	ok := mkTar(t, []ent{
		{"nc/dist/a.js.map.license", "a.js.license", tar.TypeSymlink}, // link before its target
		{"nc/dist/a.js.license", "SPDX: AGPL", tar.TypeReg},
		{"nc/lib/b.txt", "../dist/a.js.license", tar.TypeSymlink},
		{"nc/hard.txt", "nc/dist/a.js.license", tar.TypeLink},
	})
	dir, err := extractBytes(t, ok, CatalogApp{Format: "tar.gz", Strip: "nc"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"dist/a.js.map.license", "lib/b.txt", "hard.txt"} {
		st, err := os.Lstat(filepath.Join(dir, p))
		if err != nil || !st.Mode().IsRegular() {
			t.Fatalf("%s: %v %v", p, st, err)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, p)); string(b) != "SPDX: AGPL" {
			t.Fatalf("%s = %q", p, b)
		}
	}
	for name, bad := range map[string][]ent{
		"absolute": {{"nc/x", "/etc/passwd", tar.TypeSymlink}},
		"escape":   {{"nc/x", "../../etc/passwd", tar.TypeSymlink}},
		"outside":  {{"nc/x", "../other", tar.TypeSymlink}},
		"dangling": {{"nc/x", "missing", tar.TypeSymlink}},
		"dir":      {{"nc/d/", "", tar.TypeDir}, {"nc/x", "d", tar.TypeSymlink}},
		"cycle":    {{"nc/x", "y", tar.TypeSymlink}, {"nc/y", "x", tar.TypeSymlink}},
		"hardout":  {{"nc/x", "other/y", tar.TypeLink}},
	} {
		if _, err := extractBytes(t, mkTar(t, bad), CatalogApp{Format: "tar.gz", Strip: "nc"}); code(err) != "appx_archive_unsafe" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestExtractChownsImplicitParents(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	// no directory entries at all: every parent is implicit
	data := mkTar(t, []ent{{"app/a/b/c/file.php", "<?php", tar.TypeReg}})
	dir := t.TempDir()
	p := filepath.Join(t.TempDir(), "a.tgz")
	os.WriteFile(p, data, 0o600)
	f, _ := os.Open(p)
	defer f.Close()
	root, _ := os.OpenRoot(dir)
	defer root.Close()
	if _, err := ExtractApp(f, CatalogApp{Format: "tar.gz", Strip: "app"}, root, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"a", "a/b", "a/b/c", "a/b/c/file.php"} {
		st, _ := os.Lstat(filepath.Join(dir, d))
		if uid := st.Sys().(*syscall.Stat_t).Uid; uid != 65534 {
			t.Errorf("%s owned by %d", d, uid)
		}
	}
}
