package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateSieveActive(t *testing.T) {
	root := t.TempDir()
	box := filepath.Join(root, "alice", "mail", "example.com", "info")
	if err := os.MkdirAll(filepath.Join(box, "sieve"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sieve/bpanel.sieve", filepath.Join(box, ".dovecot.sieve")); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(box, ".dovecot.svbin"), []byte("x"), 0o600)
	// a box whose new link already exists is left alone
	box2 := filepath.Join(root, "alice", "mail", "example.com", "sales")
	_ = os.MkdirAll(box2, 0o700)
	_ = os.Symlink("sieve/a.sieve", filepath.Join(box2, ".dovecot.sieve"))
	_ = os.Symlink("sieve/b.sieve", filepath.Join(box2, "dovecot.sieve"))
	// a symlinked mail dir is not followed
	other := t.TempDir()
	_ = os.MkdirAll(filepath.Join(other, "d", "x"), 0o700)
	_ = os.Symlink("t", filepath.Join(other, "d", "x", ".dovecot.sieve"))
	_ = os.MkdirAll(filepath.Join(root, "mallory"), 0o700)
	_ = os.Symlink(other, filepath.Join(root, "mallory", "mail"))

	if n := migrateSieveActive(root); n != 1 {
		t.Fatalf("migrated %d, want 1", n)
	}
	if l, err := os.Readlink(filepath.Join(box, "dovecot.sieve")); err != nil || l != "sieve/bpanel.sieve" {
		t.Fatalf("new link: %q %v", l, err)
	}
	if _, err := os.Lstat(filepath.Join(box, ".dovecot.svbin")); !os.IsNotExist(err) {
		t.Fatal("stale svbin kept")
	}
	if l, _ := os.Readlink(filepath.Join(box2, "dovecot.sieve")); l != "sieve/b.sieve" {
		t.Fatal("existing link replaced")
	}
	if _, err := os.Lstat(filepath.Join(other, "d", "x", ".dovecot.sieve")); err != nil {
		t.Fatal("followed a symlinked mail dir")
	}
}

func TestDovecotSieveActiveNotDotPrefixed(t *testing.T) {
	for _, v24 := range []bool{false, true} {
		c := DovecotConf(v24, "c", "k", "p", "h.example")
		if !strings.Contains(c, "~/dovecot.sieve") || strings.Contains(c, "~/.dovecot.sieve") {
			t.Fatalf("v24=%v: sieve active path must be ~/dovecot.sieve", v24)
		}
	}
}

func TestDovecotHomeOutsideMaildirRoot(t *testing.T) {
	for _, v24 := range []bool{false, true} {
		c := DovecotConf(v24, "c", "k", "p", "h.example")
		if !strings.Contains(c, "home=%{userdb:home}/bpanel-home") && !strings.Contains(c, "home = %{userdb:home}/bpanel-home") {
			t.Fatalf("v24=%v: Dovecot home not moved out of the Maildir root:\n%s", v24, c)
		}
		// the mail path must be bound before home is replaced
		mi := strings.Index(c, "mail_path = %{userdb:home}")
		if !v24 {
			mi = strings.Index(c, "mail=maildir:%{userdb:home}")
		}
		hi := strings.Index(c, "/bpanel-home")
		if mi < 0 || mi > hi {
			t.Fatalf("v24=%v: mail path must precede the home override", v24)
		}
	}
}

func TestMigrateDovecotHome(t *testing.T) {
	box := filepath.Join(t.TempDir(), "box")
	_ = os.MkdirAll(filepath.Join(box, ".dovecot.lda-dupes.locks"), 0o700)
	_ = os.WriteFile(filepath.Join(box, ".dovecot.lda-dupes"), []byte("d"), 0o600)
	_ = os.Symlink("/etc/passwd", filepath.Join(box, "x"))
	migrateDovecotHome(box)
	if b, err := os.ReadFile(filepath.Join(box, "bpanel-home", ".dovecot.lda-dupes")); err != nil || string(b) != "d" {
		t.Fatalf("dupes not moved: %v", err)
	}
	for _, n := range []string{".dovecot.lda-dupes", ".dovecot.lda-dupes.locks"} {
		if _, err := os.Lstat(filepath.Join(box, n)); !os.IsNotExist(err) {
			t.Errorf("%s left in the Maildir root", n)
		}
	}
	if fi, err := os.Stat(filepath.Join(box, "bpanel-home")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("home dir: %v %v", fi, err)
	}
	migrateDovecotHome(box) // idempotent
}
