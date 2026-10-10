package shield

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func write(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func fakeClamd(t *testing.T) (*FakeClamd, *Clamd) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "clamd.sock")
	f, err := StartFakeClamd(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	c := NewClamd("unix:" + sock)
	c.Timeout = 5 * time.Second
	return f, c
}

func TestClamdFake(t *testing.T) {
	ctx := context.Background()
	f, c := fakeClamd(t)
	dir := t.TempDir()
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if st := c.Status(ctx); st.Status != StatusOK || st.SigVersion != "27423" {
		t.Fatalf("status %+v", st)
	}
	if v := c.SignatureVersion(ctx); !strings.HasPrefix(v, "clamav:ClamAV 1.0.7/27423") {
		t.Fatal(v)
	}
	r, err := c.Scan(ctx, Target{Path: write(t, dir, "e.txt", []byte("hello "+EICAR))})
	if err != nil || r.Verdict != Infected || r.Detections[0].Signature != "Eicar-Test-Signature" {
		t.Fatalf("eicar: %+v %v", r, err)
	}
	r, err = c.Scan(ctx, Target{Path: write(t, dir, "ok.txt", bytes.Repeat([]byte("clean "), 50000))})
	if err != nil || r.Verdict != Clean {
		t.Fatalf("clean: %+v %v", r, err)
	}
	// client-side limit
	c.MaxStream = 1000
	if _, err := c.Scan(ctx, Target{Path: write(t, dir, "big.txt", make([]byte, 5000))}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("client limit: %v", err)
	}
	// server-side StreamMaxLength
	c.MaxStream = 0
	f.MaxLen = 1000
	if _, err := c.Scan(ctx, Target{Path: write(t, dir, "big2.txt", make([]byte, 200000))}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("server limit: %v", err)
	}
	// old DB -> degraded
	f.Version = "ClamAV 1.0.7/27000/Mon Jan  5 08:00:00 2026"
	if st := c.Status(ctx); st.Status != StatusDegraded {
		t.Fatalf("want degraded: %+v", st)
	}
	// down
	d := NewClamd("unix:" + filepath.Join(dir, "missing.sock"))
	if st := d.Status(ctx); st.Status != StatusNotInstalled {
		t.Fatalf("missing: %+v", st)
	}
	if _, err := d.Scan(ctx, Target{Path: filepath.Join(dir, "ok.txt")}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestParseInstream(t *testing.T) {
	r, err := parseInstreamReply("stream: PUA.Win.Packer FOUND", EngineResult{})
	if err != nil || r.Verdict != Suspicious {
		t.Fatal(r, err)
	}
	if _, err := parseInstreamReply("stream: Can't allocate memory ERROR", EngineResult{}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

// Harmless synthetic samples: they only contain the patterns, nothing runs.
var webshells = map[string]struct {
	name, body, rule string
}{
	"eval_b64":   {"a.php", `<?php @eval(base64_decode("ZWNobyAnaGknOw==")); ?>`, "php_eval_decode"},
	"chain":      {"b.php", `<?php $x = gzinflate(base64_decode($blob)); ?>`, "php_decode_chain"},
	"input_exec": {"c.php", `<?php if(isset($_GET['c'])) { system($_GET['c']); } ?>`, "php_input_exec"},
	"taint":      {"d.php", "<?php\n$cmd = $_POST['x'];\necho shell_exec($cmd);\n", "php_input_exec"},
	"assert":     {"e.php", `<?php assert($_REQUEST['a']); ?>`, "php_assert_input"},
	"preg_e":     {"f.php", `<?php preg_replace("/.*/e", $_COOKIE['p'], ''); ?>`, "php_preg_replace_e"},
	"filesman":   {"g.php", `<?php $default_action = 'FilesMan'; echo "WSO 2.5"; ?>`, "webshell_marker"},
	"callable":   {"h.php", `<?php $_GET['f']($_GET['a']); ?>`, "php_input_callable"},
	"chr":        {"i.php", `<?php $f = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109).chr(40).chr(41).chr(59); ?>`, "php_chr_concat"},
	"img":        {"logo.gif", "GIF89a\x01\x00\x01\x00<?php echo 1; ?>", "php_in_image"},
	"double":     {"avatar.php.jpg", "\xff\xd8\xff\xe0 jpeg data", "double_extension"},
}

func TestHeuristicWebshells(t *testing.T) {
	for k, s := range webshells {
		ids := MatchHeuristics([]byte(s.body), s.name)
		found := false
		for _, id := range ids {
			found = found || id == s.rule
		}
		if !found {
			t.Errorf("%s: want %s, got %v", k, s.rule, ids)
		}
	}
	rb := make([]byte, 3000)
	_, _ = rand.Read(rb)
	blob := "<?php $p = '" + base64.StdEncoding.EncodeToString(rb) + "'; ?>"
	if ids := MatchHeuristics([]byte(blob), "x.php"); len(ids) != 1 || ids[0] != "long_base64_entropy" {
		t.Errorf("base64 blob: %v", ids)
	}
	if ids := MatchHeuristics([]byte("abc "+EICAR), "e.com"); len(ids) == 0 || ids[0] != "eicar_test" {
		t.Errorf("eicar: %v", ids)
	}
}

const wpLike = `<?php
/**
 * Plugin Name: Hello Dolly-like
 * Description: harmless WordPress-style plugin.
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }
function hd_get_lyric() {
	$lyrics = "Hello, Dolly\nWell, hello, Dolly";
	$lyrics = explode( "\n", $lyrics );
	return wptexturize( $lyrics[ mt_rand( 0, count( $lyrics ) - 1 ) ] );
}
add_action( 'admin_notices', function () {
	$page = isset( $_GET['page'] ) ? sanitize_key( $_GET['page'] ) : '';
	$data = base64_encode( wp_json_encode( array( 'p' => $page ) ) );
	printf( '<p id="dolly">%s</p>', esc_html( hd_get_lyric() ) );
	$out = array();
	exec( 'true', $out ); // fixed command, no request input
} );
$cfg = json_decode( base64_decode( get_option( 'hd_cfg', 'e30=' ) ), true );
`

func TestCleanNotFlagged(t *testing.T) {
	if ids := MatchHeuristics([]byte(wpLike), "wp-content/plugins/hello/hello.php"); len(ids) != 0 {
		t.Fatalf("false positive: %v", ids)
	}
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{1, 2, 3}, 100)...)
	if ids := MatchHeuristics(png, "a.png"); len(ids) != 0 {
		t.Fatalf("png: %v", ids)
	}
}

func TestFileType(t *testing.T) {
	cases := []struct {
		data, name, kind string
		class            FileClass
		disg             bool
	}{
		{"<?php echo 1;", "x.php", "php", ClassScript, false},
		{"<?php echo 1;", "x.jpg", "php", ClassScript, true},
		{"GIF89a<?php x", "x.gif", "php", ClassScript, true},
		{"\x7fELF\x02\x01", "x", "elf", ClassExecutable, false},
		{"\x7fELF\x02\x01", "x.png", "elf", ClassExecutable, true},
		{"PK\x03\x04rest", "a.zip", "zip", ClassArchive, false},
		{"\x1f\x8b\x08", "a.gz", "gzip", ClassArchive, false},
		{"\x89PNG\r\n\x1a\nxx", "a.png", "png", ClassOther, false},
		{"\xff\xd8\xff\xe0", "a.jpg", "jpeg", ClassOther, false},
		{"%PDF-1.7", "a.pdf", "pdf", ClassOther, false},
		{"#!/bin/sh\necho", "run", "shell", ClassScript, false},
		{"hello", "notes.txt", "text", ClassOther, false},
	}
	for _, c := range cases {
		ft := DetectType([]byte(c.data), c.name)
		if ft.Kind != c.kind || ft.Class != c.class || ft.Disguised != c.disg {
			t.Errorf("%q %s: got %+v", c.data, c.name, ft)
		}
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "a.txt", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("a"))
	_ = tw.Close()
	if ft := DetectType(buf.Bytes(), "a.tar"); ft.Kind != "tar" {
		t.Errorf("tar: %+v", ft)
	}
}

func TestPolicy(t *testing.T) {
	p := DefaultPolicy()
	cases := []struct {
		o Outcome
		c FileClass
		a Action
	}{
		{OutClean, ClassScript, ActAllow},
		{OutInfected, ClassOther, ActQuarantine},
		{OutSuspicious, ClassScript, ActHold},
		{OutSuspicious, ClassOther, ActAllowWarning},
		{OutSuspicious, ClassArchive, ActBlock},
		{OutUnavailable, ClassScript, ActBlock},
		{OutTimeout, ClassExecutable, ActBlock},
		{OutUnavailable, ClassOther, ActAllowWarning},
	}
	for _, c := range cases {
		if d := Decide(c.o, c.c, p); d.Action != c.a || (c.o != OutClean && !d.Record) {
			t.Errorf("%s/%s: %+v", c.o, c.c, d)
		}
	}
	// a permissive policy can never turn into a silent allow
	lax := AccountPolicy{OnInfected: ActAllow, OnUnavailableScript: ActAllow}
	if d := Decide(OutInfected, ClassScript, lax); d.Action != ActQuarantine {
		t.Error(d)
	}
	if d := Decide(OutUnavailable, ClassScript, lax); d.Action != ActAllowWarning || !d.Record {
		t.Error(d)
	}
}

func TestScannerEICARAndClamdDown(t *testing.T) {
	ctx := context.Background()
	_, c := fakeClamd(t)
	dir := t.TempDir()
	s := NewScanner(c)
	r, err := s.Scan(ctx, write(t, dir, "eicar.txt", []byte(EICAR)))
	if err != nil || r.Outcome != OutInfected || r.Decision.Action != ActQuarantine {
		t.Fatalf("%+v %v", r, err)
	}
	engines := map[string]bool{}
	for _, d := range r.Detections {
		engines[d.Engine] = true
	}
	if !engines["clamav"] || !engines["bpanel-heuristic"] {
		t.Fatalf("both engines should detect: %+v", r.Detections)
	}
	clean := write(t, dir, "index.php", []byte(wpLike))
	if r, _ := s.Scan(ctx, clean); r.Outcome != OutClean || r.Decision.Action != ActAllow {
		t.Fatalf("clean: %+v", r)
	}
	// clamd down: clean php can no longer be verified -> blocked
	down := NewScanner(NewClamd("unix:" + filepath.Join(dir, "nope.sock")))
	r, _ = down.Scan(ctx, clean)
	if r.Outcome != OutUnavailable || r.Decision.Action != ActBlock {
		t.Fatalf("down php: %+v", r)
	}
	r, _ = down.Scan(ctx, write(t, dir, "notes.txt", []byte("hi")))
	if r.Decision.Action != ActAllowWarning || !r.Decision.Record {
		t.Fatalf("down txt: %+v", r)
	}
	// but known-bad is still caught by the builtin engine
	r, _ = down.Scan(ctx, write(t, dir, "s.php", []byte(webshells["input_exec"].body)))
	if r.Outcome != OutInfected {
		t.Fatalf("down shell: %+v", r)
	}
}

func TestScannerRescanOnChange(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "x.php", []byte("<?php echo 1;"))
	s := NewScanner()
	s.afterEngines = func(attempt int) {
		if attempt == 0 {
			_ = os.WriteFile(p, []byte(`<?php system($_GET['c']);`), 0o644)
		}
	}
	r, err := s.Scan(context.Background(), p)
	if err != nil || r.Rescans != 1 || r.Outcome != OutInfected {
		t.Fatalf("%+v %v", r, err)
	}
	// keeps changing -> no verdict, php blocked
	n := 0
	s.afterEngines = func(int) { n++; _ = os.WriteFile(p, bytes.Repeat([]byte("x"), n), 0o644) }
	r, _ = s.Scan(context.Background(), p)
	if r.Outcome != OutUnavailable || r.Decision.Action != ActBlock || n != 4 {
		t.Fatalf("unstable: %+v n=%d", r, n)
	}
	// symlinks are not followed
	_ = os.Symlink(p, filepath.Join(dir, "link.php"))
	if _, err := s.Scan(context.Background(), filepath.Join(dir, "link.php")); err == nil {
		t.Fatal("symlink scanned")
	}
}

type verProvider struct {
	ver   atomic.Value
	scans atomic.Int32
}

func (v *verProvider) Name() string                            { return "fakever" }
func (v *verProvider) Kind() string                            { return KindExternal }
func (v *verProvider) Status(context.Context) ProviderStatus   { return ProviderStatus{Status: StatusOK} }
func (v *verProvider) Available(context.Context) bool          { return true }
func (v *verProvider) SignatureVersion(context.Context) string { return v.ver.Load().(string) }
func (v *verProvider) Scan(context.Context, Target) (EngineResult, error) {
	v.scans.Add(1)
	return EngineResult{Verdict: Clean}, nil
}

func TestCacheInvalidation(t *testing.T) {
	ctx := context.Background()
	vp := &verProvider{}
	vp.ver.Store("db1")
	s := NewScanner(vp)
	p := write(t, t.TempDir(), "a.php", []byte(wpLike))
	r1, _ := s.Scan(ctx, p)
	r2, _ := s.Scan(ctx, p)
	if r1.Cached || !r2.Cached || vp.scans.Load() != 1 {
		t.Fatalf("cache: %v %v %d", r1.Cached, r2.Cached, vp.scans.Load())
	}
	vp.ver.Store("db2") // new signatures
	r3, _ := s.Scan(ctx, p)
	if r3.Cached || vp.scans.Load() != 2 {
		t.Fatalf("not invalidated: %+v", r3)
	}
	c := NewVerdictCache()
	c.Put("h", "v", OutUnavailable, nil)
	if c.Len() != 0 {
		t.Fatal("unavailable cached")
	}
	c.Put("h", "v", OutClean, nil)
	if _, ok := c.Get("h", "v2"); ok || c.Len() != 0 {
		t.Fatal("version mismatch must miss and evict")
	}
}

func mkZip(t *testing.T, files map[string][]byte, symlink string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for n, d := range files {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(d)
	}
	if symlink != "" {
		h := &zip.FileHeader{Name: symlink}
		h.SetMode(os.ModeSymlink | 0o777)
		w, _ := zw.CreateHeader(h)
		_, _ = w.Write([]byte("/etc/passwd"))
	}
	_ = zw.Close()
	return buf.Bytes()
}

func TestArchiveLimits(t *testing.T) {
	dir := t.TempDir()
	lim := DefaultArchiveLimits()
	lim.MaxTotal = 50 << 20
	ok := write(t, dir, "ok.zip", mkZip(t, map[string][]byte{"a/b.txt": []byte("hi"), "c.php": []byte("<?php echo 1;")}, ""))
	if ents, err := InspectArchive(ok, lim); err != nil || len(ents) != 2 {
		t.Fatalf("ok: %v %v", ents, err)
	}
	out := filepath.Join(dir, "out")
	if w, err := ExtractArchive(ok, out, lim); err != nil || len(w) != 2 {
		t.Fatalf("extract: %v %v", w, err)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "a", "b.txt")); string(b) != "hi" {
		t.Fatal("content")
	}
	slip := write(t, dir, "slip.zip", mkZip(t, map[string][]byte{"../../evil.php": []byte("x")}, ""))
	if _, err := ExtractArchive(slip, filepath.Join(dir, "o2"), lim); !errors.Is(err, ErrArchivePath) {
		t.Fatalf("zip-slip: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "evil.php")); err == nil {
		t.Fatal("escaped file written")
	}
	abs := write(t, dir, "abs.zip", mkZip(t, map[string][]byte{"/etc/cron.d/x": []byte("x")}, ""))
	if _, err := InspectArchive(abs, lim); !errors.Is(err, ErrArchivePath) {
		t.Fatalf("abs: %v", err)
	}
	ln := write(t, dir, "ln.zip", mkZip(t, map[string][]byte{"a": []byte("x")}, "link"))
	if _, err := InspectArchive(ln, lim); !errors.Is(err, ErrArchiveLink) {
		t.Fatalf("symlink: %v", err)
	}
	bomb := write(t, dir, "bomb.zip", mkZip(t, map[string][]byte{"zeros.bin": make([]byte, 60<<20)}, ""))
	if _, err := InspectArchive(bomb, lim); !errors.Is(err, ErrArchiveBomb) {
		t.Fatalf("bomb: %v", err)
	}
	many := map[string][]byte{}
	for i := 0; i < 30; i++ {
		many[strings.Repeat("f", i+1)] = []byte("x")
	}
	l2 := lim
	l2.MaxEntries = 10
	if _, err := InspectArchive(write(t, dir, "many.zip", mkZip(t, many, "")), l2); !errors.Is(err, ErrArchiveEntries) {
		t.Fatalf("entries: %v", err)
	}
	// nesting: zip in zip in zip in zip
	z := mkZip(t, map[string][]byte{"x.txt": []byte("x")}, "")
	for i := 0; i < 4; i++ {
		z = mkZip(t, map[string][]byte{"n.zip": z}, "")
	}
	if _, err := InspectArchive(write(t, dir, "nest.zip", z), lim); !errors.Is(err, ErrArchiveDepth) {
		t.Fatalf("depth: %v", err)
	}
	// tar.gz with symlink + webshell member detected through the scanner
	var tb bytes.Buffer
	gz := gzip.NewWriter(&tb)
	tw := tar.NewWriter(gz)
	body := []byte(webshells["filesman"].body)
	_ = tw.WriteHeader(&tar.Header{Name: "wp/shell.php", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gz.Close()
	tgz := write(t, dir, "site.tar.gz", tb.Bytes())
	r, err := NewScanner().Scan(context.Background(), tgz)
	if err != nil || r.Outcome != OutInfected || r.Detections[0].Entry != "wp/shell.php" {
		t.Fatalf("tgz scan: %+v %v", r, err)
	}
	var sb bytes.Buffer
	tw = tar.NewWriter(&sb)
	_ = tw.WriteHeader(&tar.Header{Name: "l", Linkname: "/etc/shadow", Typeflag: tar.TypeSymlink})
	_ = tw.Close()
	if _, err := InspectArchive(write(t, dir, "ln.tar", sb.Bytes()), lim); !errors.Is(err, ErrArchiveLink) {
		t.Fatalf("tar symlink: %v", err)
	}
	// rejected archive -> suspicious -> blocked
	r, _ = NewScanner().Scan(context.Background(), slip)
	if r.Outcome != OutSuspicious || r.Decision.Action != ActBlock {
		t.Fatalf("slip scan: %+v", r)
	}
}

func TestYaraProvider(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	rules, err := WriteBuiltinRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	y := NewYara(rules)
	y.Bin = "definitely-not-yara-bpanel"
	if st := y.Status(ctx); st.Status != StatusNotInstalled {
		t.Fatalf("%+v", st)
	}
	if _, err := y.Scan(ctx, Target{Path: rules}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	// fake yara binary exercising argv + output parsing
	fake := write(t, dir, "yara", []byte("#!/bin/sh\nif [ \"$1\" = --version ]; then echo 4.5.0; exit 0; fi\n"+
		"case \"$7\" in *bad*) echo 'BPANEL_Webshell_Markers [verdict=\"infected\",severity=\"critical\",description=\"x\"] '\"$7\";; esac\nexit 0\n"))
	_ = os.Chmod(fake, 0o755)
	y.Bin = fake
	if st := y.Status(ctx); st.Status != StatusOK || st.Version != "4.5.0" {
		t.Fatalf("%+v", st)
	}
	r, err := y.Scan(ctx, Target{Path: write(t, dir, "bad.php", []byte("x"))})
	if err != nil || r.Verdict != Infected || r.Detections[0].Signature != "BPANEL_Webshell_Markers" || r.Detections[0].Severity != SevCritical {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = y.Scan(ctx, Target{Path: write(t, dir, "good.php", []byte("x"))})
	if err != nil || r.Verdict != Clean {
		t.Fatalf("%+v %v", r, err)
	}
	if !bytes.Contains(BuiltinYaraRules, []byte("rule BPANEL_EICAR_Test")) {
		t.Fatal("embed")
	}
}
