//go:build restictest

package backup

// Real end-to-end test against the restic binary.
//   BPANEL_RESTIC=/path/to/restic go test -tags restictest -v ./internal/backup
// Skips when no binary is found.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func findRestic(t *testing.T) string {
	for _, p := range []string{os.Getenv("BPANEL_RESTIC"), "/tmp/restic/restic", "/usr/local/lib/bpanel/bin/restic"} {
		if p == "" {
			continue
		}
		if out, err := exec.Command(p, "version").Output(); err == nil {
			t.Logf("using %s: %s", p, strings.TrimSpace(string(out)))
			return p
		}
	}
	t.Skip("restic binary not found")
	return ""
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestResticEndToEnd(t *testing.T) {
	bin := findRestic(t)
	base := t.TempDir()
	home := filepath.Join(base, "home", "alice")
	files := map[string][]byte{
		"public_html/index.php":         []byte("<?php echo 'hi';"),
		"public_html/assets/app.css":    bytes.Repeat([]byte("body{color:red}\n"), 4000),
		"public_html/uploads/photo.bin": bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 300000),
		"db/shop.sql":                   []byte("-- dump\nCREATE TABLE t(id int);\nINSERT INTO t VALUES (1),(2),(3);\n"),
		"backups/old.tar":               []byte("excluded"),
	}
	for rel, b := range files {
		p := filepath.Join(home, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pass := filepath.Join(base, "secrets", "alice.pass")
	if err := EnsurePasswordFile(pass, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	e := &Engine{Bin: bin, Target: Target{Kind: KindLocal, Path: filepath.Join(base, "repos")}, PasswordFile: pass,
		CacheDir: filepath.Join(base, "cache"), ManifestDir: filepath.Join(base, "manifests"), SecretUID: os.Getuid(), Timeout: 5 * time.Minute}
	ctx := t.Context()

	id, m, err := e.BackupDir(ctx, "alice", home, []string{filepath.Join(home, "backups")})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("backup ok: snapshot=%s manifest_files=%d", id[:8], len(m.Files))
	if len(m.Files) != 4 {
		t.Fatalf("manifest has %d files, want 4", len(m.Files))
	}
	if out, err := e.Forget(ctx, "alice", DefaultRetention); err != nil {
		t.Fatal(err, out)
	}
	snaps, _ := e.Snapshots(ctx, "alice", "files")
	t.Logf("retention applied: %d snapshot(s) kept", len(snaps))

	// damage the live account
	os.Remove(filepath.Join(home, "db/shop.sql"))
	os.WriteFile(filepath.Join(home, "public_html/index.php"), []byte("defaced"), 0o644)

	// single-file restore
	r1 := filepath.Join(base, "restore-one")
	if err := e.Restore(ctx, "alice", id, filepath.Join(home, "db/shop.sql"), r1); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(r1, home, "db/shop.sql"))
	if err != nil || sha(got) != sha(files["db/shop.sql"]) {
		t.Fatalf("single file restore mismatch: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r1, home, "public_html/index.php")); err == nil {
		t.Fatal("single-file restore restored more than asked")
	}
	t.Logf("single-file restore ok: db/shop.sql sha256=%s", sha(got)[:16])

	// full account restore
	r2 := filepath.Join(base, "restore-all")
	if err := e.Restore(ctx, "alice", "latest", "", r2); err != nil {
		t.Fatal(err)
	}
	n := 0
	for rel, b := range files {
		got, err := os.ReadFile(filepath.Join(r2, home, rel))
		if rel == "backups/old.tar" {
			if err == nil {
				t.Fatal("excluded file was backed up")
			}
			continue
		}
		if err != nil || sha(got) != sha(b) {
			t.Fatalf("full restore mismatch %s: %v", rel, err)
		}
		n++
	}
	t.Logf("full restore ok: %d files identical to originals", n)

	v := e.VerifyRestore(ctx, "alice", VerifyOptions{ReadDataSubset: "100%", TempDir: base})
	t.Logf("verify (clean): status=%s files_checked=%d mismatches=%d check_ok=%v err=%q", v.Status, v.FilesChecked, v.Mismatches, v.CheckOK, v.Error)
	if v.Status != "ok" || v.FilesChecked != 4 || v.Mismatches != 0 || !v.CheckOK {
		t.Fatalf("clean verification failed: %+v", v)
	}

	// tamper: flip bytes in the middle of every pack file
	packs, _ := filepath.Glob(filepath.Join(base, "repos", "alice", "data", "*", "*"))
	if len(packs) == 0 {
		t.Fatal("no pack files")
	}
	for _, p := range packs {
		os.Chmod(p, 0o644)
		b, _ := os.ReadFile(p)
		for i := len(b) / 3; i < len(b)/3+64 && i < len(b); i++ {
			b[i] ^= 0xff
		}
		os.WriteFile(p, b, 0o644)
	}
	t.Logf("tampered %d pack file(s)", len(packs))
	os.RemoveAll(filepath.Join(base, "cache"))
	v2 := e.VerifyRestore(ctx, "alice", VerifyOptions{ReadDataSubset: "100%", TempDir: base})
	t.Logf("verify (tampered): status=%s files_checked=%d mismatches=%d missing=%d check_ok=%v err=%.300q", v2.Status, v2.FilesChecked, v2.Mismatches, v2.Missing, v2.CheckOK, v2.Error)
	if v2.Status == "ok" || v2.CheckOK {
		t.Fatalf("tampered repository passed verification: %+v", v2)
	}
	if strings.Contains(v2.Error, "RESTIC_PASSWORD") {
		t.Fatal("secret env leaked into error")
	}
}

// v0.4 part B: password only via RESTIC_PASSWORD (secret store path, no file)
// and retention (forget --prune --json) after backups, against real restic.
func TestResticEnvPasswordRetention(t *testing.T) {
	bin := findRestic(t)
	base := t.TempDir()
	home := filepath.Join(base, "home", "bob")
	os.MkdirAll(home, 0o755)
	pw := "0123456789abcdef0123456789abcdef-secretstore"
	e := &Engine{Bin: bin, Target: Target{Kind: KindLocal, Path: filepath.Join(base, "repos")}, Password: pw,
		CacheDir: filepath.Join(base, "cache"), ManifestDir: filepath.Join(base, "manifests"), Timeout: 5 * time.Minute}
	ctx := t.Context()
	if err := e.Init(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		os.WriteFile(filepath.Join(home, "f.txt"), []byte(strings.Repeat("x", i+1)), 0o644)
		if _, _, err := e.BackupDir(ctx, "bob", home, nil); err != nil {
			t.Fatal(err)
		}
	}
	out, err := e.Forget(ctx, "bob", Retention{Last: 1})
	if err != nil {
		t.Fatal(err)
	}
	kept, removed := ForgetCounts(out)
	t.Logf("retention: kept=%d removed=%d", kept, removed)
	if kept != 1 || removed != 2 {
		t.Fatalf("kept=%d removed=%d", kept, removed)
	}
	snaps, err := e.Snapshots(ctx, "bob", "")
	if err != nil || len(snaps) != 1 {
		t.Fatalf("snapshots after prune: %d %v", len(snaps), err)
	}
	bad := &Engine{Bin: bin, Target: e.Target, Password: "wrong-password-123456", CacheDir: e.CacheDir, Timeout: time.Minute}
	if _, err := bad.Snapshots(ctx, "bob", ""); err == nil || strings.Contains(err.Error(), "wrong-password-123456") {
		t.Fatalf("wrong password must fail without echoing it: %v", err)
	}
}
