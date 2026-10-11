package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// realDovecotSettle keeps the production implementation for its own test;
// every other test runs with a no-op so mailbox tests stay fast.
var realDovecotSettle = dovecotSettle

func init() { dovecotSettle = func(string) {} }

// TestDovecotSettle: after the settle the passwd-file's mtime lies in a
// later wall-clock second than the edit, so Dovecot (which caches the file
// per second by mtime+size) is guaranteed to reload it on the next lookup.
func TestDovecotSettle(t *testing.T) {
	p := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(p, []byte("a@b.test:x\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	edit := time.Now()
	start := time.Now()
	realDovecotSettle(p)
	if d := time.Since(start); d > 1100*time.Millisecond {
		t.Fatalf("settle took %v, want <= ~1s", d)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.ModTime().Unix() <= edit.Unix() {
		t.Fatalf("mtime second %d not after edit second %d", st.ModTime().Unix(), edit.Unix())
	}
}
