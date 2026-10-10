package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cumabozkurt/bpanel/internal/store"
)

func newLocal(t *testing.T) (*Local, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	kp := filepath.Join(dir, "etc", "secret.key")
	l, err := NewLocal(st.DB, kp)
	if err != nil {
		t.Fatal(err)
	}
	return l, st, kp
}

func TestKeyFileCreated0600(t *testing.T) {
	_, _, kp := newLocal(t)
	fi, err := os.Stat(kp)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 || fi.Size() != 32 {
		t.Fatalf("key file mode=%v size=%d", fi.Mode().Perm(), fi.Size())
	}
	// loose perms are tightened on open
	os.Chmod(kp, 0o644)
	if _, err := NewLocal(nil, kp); err != nil {
		t.Fatal(err)
	}
	fi, _ = os.Stat(kp)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("not tightened: %v", fi.Mode().Perm())
	}
	os.WriteFile(kp, []byte("short"), 0o600)
	if _, err := NewLocal(nil, kp); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestPutGetListDelete(t *testing.T) {
	l, st, _ := newLocal(t)
	ctx := context.Background()
	val := []byte("s3cr3t-VALUE-xyz")
	if err := l.Put(ctx, "webhook/1", val); err != nil {
		t.Fatal(err)
	}
	got, err := l.Get(ctx, "webhook/1")
	if err != nil || !bytes.Equal(got, val) {
		t.Fatalf("get=%q %v", got, err)
	}
	// ciphertext at rest is not the plaintext
	var ct []byte
	st.DB.QueryRow(`SELECT ciphertext FROM secrets WHERE name='webhook/1'`).Scan(&ct)
	if bytes.Contains(ct, val) {
		t.Fatal("plaintext at rest")
	}
	ms, err := l.List(ctx)
	if err != nil || len(ms) != 1 {
		t.Fatal(ms, err)
	}
	b, _ := json.Marshal(ms)
	if strings.Contains(string(b), "s3cr3t") {
		t.Fatal("value leaked in list")
	}
	if err := l.Put(ctx, "bad name!", val); err != ErrBadName {
		t.Fatal(err)
	}
	// AAD binds the row to its name: swapping ciphertext across names fails
	l.Put(ctx, "other", []byte("x"))
	st.DB.Exec(`UPDATE secrets SET ciphertext=(SELECT ciphertext FROM secrets WHERE name='webhook/1'), nonce=(SELECT nonce FROM secrets WHERE name='webhook/1') WHERE name='other'`)
	if _, err := l.Get(ctx, "other"); err != ErrCorrupt {
		t.Fatalf("swap: %v", err)
	}
	if err := l.Delete(ctx, "webhook/1"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Get(ctx, "webhook/1"); err != ErrNotFound {
		t.Fatal(err)
	}
}

func TestSealOpen(t *testing.T) {
	l, _, _ := newLocal(t)
	ctx := context.Background()
	s, err := l.Seal(ctx, []byte("hello"), "ctx-a")
	if err != nil || !IsSealed(s) || strings.Contains(s, "hello") {
		t.Fatal(s, err)
	}
	p, err := l.Open(ctx, s, "ctx-a")
	if err != nil || string(p) != "hello" {
		t.Fatal(p, err)
	}
	if _, err := l.Open(ctx, s, "ctx-b"); err == nil {
		t.Fatal("wrong aad opened")
	}
}

func TestRotate(t *testing.T) {
	l, st, kp := newLocal(t)
	ctx := context.Background()
	for _, n := range []string{"a", "b", "c"} {
		l.Put(ctx, n, []byte("v-"+n))
	}
	sealed, _ := l.Seal(ctx, []byte("ext"), "x")
	old := l.cur
	n, err := l.Rotate(ctx)
	if err != nil || n != 3 {
		t.Fatal(n, err)
	}
	if l.cur == old {
		t.Fatal("key id unchanged")
	}
	var cnt int
	st.DB.QueryRow(`SELECT COUNT(*) FROM secrets WHERE key_id<>?`, l.cur).Scan(&cnt)
	if cnt != 0 {
		t.Fatal("rows left on old key")
	}
	// ring exists (0600) until FinishRotation; old sealed values still open
	fi, err := os.Stat(kp + ".ring")
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatal("ring", err)
	}
	// a restart during rotation still opens old-key values via the ring
	l2, err := NewLocal(st.DB, kp)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := l2.Open(ctx, sealed, "x"); err != nil || string(p) != "ext" {
		t.Fatal(p, err)
	}
	re, err := l.Reseal(ctx, sealed, "x")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.FinishRotation(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(kp + ".ring"); !os.IsNotExist(err) {
		t.Fatal("ring not removed")
	}
	if _, err := l.Open(ctx, sealed, "x"); err != ErrUnknownKey {
		t.Fatalf("old key still usable: %v", err)
	}
	if p, _ := l.Open(ctx, re, "x"); string(p) != "ext" {
		t.Fatal("reseal")
	}
	for _, n := range []string{"a", "b", "c"} {
		if p, err := l.Get(ctx, n); err != nil || string(p) != "v-"+n {
			t.Fatal(n, err)
		}
	}
	// a fresh process reading only the key file opens everything
	l3, _ := NewLocal(st.DB, kp)
	if p, err := l3.Get(ctx, "a"); err != nil || string(p) != "v-a" {
		t.Fatal(err)
	}
}

func TestOpenBaoStub(t *testing.T) {
	var o OpenBao
	if err := o.Put(context.Background(), "a", nil); err != ErrNotConfigured {
		t.Fatal(err)
	}
	if o.Status()["status"] != "not_configured" {
		t.Fatal()
	}
}
