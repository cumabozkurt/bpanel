package secrets

// Unit tests for the OpenBao provider against an in-process fake that
// implements the subset of the OpenBao HTTP API BPANEL uses (AppRole login,
// renew-self, KV v2 data/metadata/LIST, Transit encrypt/decrypt/rotate,
// sys/health). The same suite runs against a real `bao server -dev` in
// openbao_real_test.go (build tag `openbao`).

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cumabozkurt/bpanel/internal/store"
)

type fakeKV struct {
	val     map[string]any
	version int
	created time.Time
	updated time.Time
}

type fakeBao struct {
	mu        sync.Mutex
	tokens    map[string]bool
	n         int
	lease     int
	kv        map[string]*fakeKV // key = path under prefix
	tver      int
	fail      int // next N requests answer 503
	logins    int
	renews    int
	requests  int
	sawSecret bool
}

func newFakeBao() *fakeBao {
	return &fakeBao{tokens: map[string]bool{}, kv: map[string]*fakeKV{}, lease: 3600, tver: 1}
}

func (f *fakeBao) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	wj := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if v != nil {
			json.NewEncoder(w).Encode(v)
		}
	}
	if f.fail > 0 {
		f.fail--
		wj(503, map[string]any{"errors": []string{"temporarily unavailable"}})
		return
	}
	var in map[string]any
	json.NewDecoder(r.Body).Decode(&in)
	p := strings.TrimPrefix(r.URL.Path, "/v1/")
	if p == "sys/health" {
		wj(200, map[string]any{"initialized": true, "sealed": false})
		return
	}
	if p == "auth/approle/login" {
		if in["role_id"] != "role-1" || in["secret_id"] != "s3cr3t-id" {
			wj(400, map[string]any{"errors": []string{"invalid role or secret ID"}})
			return
		}
		f.sawSecret = true
		f.n++
		f.logins++
		tok := "hvs.fake" + strconv.Itoa(f.n)
		f.tokens[tok] = true
		wj(200, map[string]any{"auth": map[string]any{"client_token": tok, "lease_duration": f.lease, "renewable": true}})
		return
	}
	tok := r.Header.Get("X-Vault-Token")
	if !f.tokens[tok] {
		wj(403, map[string]any{"errors": []string{"permission denied"}})
		return
	}
	switch {
	case p == "auth/token/renew-self":
		f.renews++
		wj(200, map[string]any{"auth": map[string]any{"client_token": tok, "lease_duration": f.lease, "renewable": true}})
	case strings.HasPrefix(p, "secret/data/bpanel/"):
		k := strings.TrimPrefix(p, "secret/data/bpanel/")
		switch r.Method {
		case http.MethodPost:
			d, _ := in["data"].(map[string]any)
			e := f.kv[k]
			now := time.Now().UTC()
			if e == nil {
				e = &fakeKV{created: now}
				f.kv[k] = e
			}
			e.val, e.updated = d, now
			e.version++
			wj(200, map[string]any{"data": map[string]any{"version": e.version}})
		case http.MethodGet:
			e := f.kv[k]
			if e == nil {
				wj(404, map[string]any{"errors": []string{}})
				return
			}
			wj(200, map[string]any{"data": map[string]any{"data": e.val}})
		}
	case strings.HasPrefix(p, "secret/metadata/bpanel"):
		k := strings.TrimPrefix(strings.TrimPrefix(p, "secret/metadata/bpanel"), "/")
		switch r.Method {
		case "LIST":
			pre := k
			if pre != "" {
				pre += "/"
			}
			seen := map[string]bool{}
			for name := range f.kv {
				if !strings.HasPrefix(name, pre) {
					continue
				}
				rest := strings.TrimPrefix(name, pre)
				if i := strings.Index(rest, "/"); i >= 0 {
					rest = rest[:i+1]
				}
				seen[rest] = true
			}
			if len(seen) == 0 {
				wj(404, map[string]any{"errors": []string{}})
				return
			}
			keys := []string{}
			for k := range seen {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			wj(200, map[string]any{"data": map[string]any{"keys": keys}})
		case http.MethodGet:
			e := f.kv[k]
			if e == nil {
				wj(404, map[string]any{"errors": []string{}})
				return
			}
			wj(200, map[string]any{"data": map[string]any{"created_time": e.created.Format(time.RFC3339Nano), "updated_time": e.updated.Format(time.RFC3339Nano), "current_version": e.version}})
		case http.MethodDelete:
			delete(f.kv, k)
			w.WriteHeader(204)
		}
	case p == "transit/encrypt/bpanel":
		pt, _ := in["plaintext"].(string)
		c, _ := in["context"].(string)
		ct := "vault:v" + strconv.Itoa(f.tver) + ":" + base64.StdEncoding.EncodeToString([]byte(c+"|"+pt))
		wj(200, map[string]any{"data": map[string]any{"ciphertext": ct}})
	case p == "transit/decrypt/bpanel":
		ct, _ := in["ciphertext"].(string)
		c, _ := in["context"].(string)
		parts := strings.SplitN(ct, ":", 3)
		raw, err := base64.StdEncoding.DecodeString(parts[len(parts)-1])
		ctxPart, pt, ok := strings.Cut(string(raw), "|")
		if err != nil || !ok || ctxPart != c {
			wj(400, map[string]any{"errors": []string{"cipher: message authentication failed"}})
			return
		}
		wj(200, map[string]any{"data": map[string]any{"plaintext": pt}})
	case p == "transit/keys/bpanel/rotate":
		f.tver++
		wj(200, map[string]any{"data": map[string]any{"latest_version": f.tver}})
	default:
		wj(404, map[string]any{"errors": []string{"no handler for route"}})
	}
}

// runProviderSuite is the conformance suite shared with the real-server test.
func runProviderSuite(t *testing.T, ob *OpenBao) {
	t.Helper()
	ctx := context.Background()
	if err := ob.Ping(ctx); err != nil {
		t.Fatal("ping:", err)
	}
	vals := map[string][]byte{
		"backup/repo:alice": []byte("pa$$w0rd-alice"),
		"backup/repo:bob":   {0, 1, 2, 255},
		"smtp.relay":        []byte("relay-secret"),
	}
	for n, v := range vals {
		if err := ob.Put(ctx, n, v); err != nil {
			t.Fatalf("put %s: %v", n, err)
		}
	}
	for n, v := range vals {
		got, err := ob.Get(ctx, n)
		if err != nil || !bytes.Equal(got, v) {
			t.Fatalf("get %s: %v %q", n, err, got)
		}
	}
	if err := ob.Put(ctx, "smtp.relay", []byte("v2")); err != nil {
		t.Fatal(err)
	}
	if got, _ := ob.Get(ctx, "smtp.relay"); string(got) != "v2" {
		t.Fatalf("overwrite: %q", got)
	}
	ms, err := ob.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, m := range ms {
		names = append(names, m.Name)
		if m.Name == "smtp.relay" && m.KeyID != "kv-v2" {
			t.Fatalf("version meta %+v", m)
		}
		if m.CreatedAt == 0 {
			t.Fatalf("created_at missing %+v", m)
		}
	}
	if strings.Join(names, ",") != "backup/repo:alice,backup/repo:bob,smtp.relay" {
		t.Fatalf("list = %v", names)
	}
	if _, err := ob.Get(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing get: %v", err)
	}
	if err := ob.Put(ctx, "../etc", []byte("x")); !errors.Is(err, ErrBadName) {
		t.Fatalf("bad name: %v", err)
	}
	if err := ob.Delete(ctx, "backup/repo:bob"); err != nil {
		t.Fatal(err)
	}
	if err := ob.Delete(ctx, "backup/repo:bob"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete: %v", err)
	}
	if _, err := ob.Get(ctx, "backup/repo:bob"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get deleted: %v", err)
	}
	// Transit envelope
	s1, err := ob.Seal(ctx, []byte("column-secret"), "users.totp:7")
	if err != nil {
		t.Fatal(err)
	}
	if !IsSealed(s1) || strings.Contains(s1, "column-secret") {
		t.Fatalf("sealed form %q", s1)
	}
	if p, err := ob.Open(ctx, s1, "users.totp:7"); err != nil || string(p) != "column-secret" {
		t.Fatalf("open: %v %q", err, p)
	}
	if _, err := ob.Open(ctx, s1, "users.totp:8"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("aad mismatch must fail: %v", err)
	}
	if _, err := ob.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	s2, err := ob.Reseal(ctx, s1, "users.totp:7")
	if err != nil || s2 == s1 {
		t.Fatalf("reseal: %v", err)
	}
	if p, err := ob.Open(ctx, s2, "users.totp:7"); err != nil || string(p) != "column-secret" {
		t.Fatalf("open resealed: %v", err)
	}
	if p, err := ob.Open(ctx, s1, "users.totp:7"); err != nil || string(p) != "column-secret" {
		t.Fatalf("old version must still open: %v", err)
	}
	st := ob.Status()
	if st["status"] != "ok" || st["authenticated"] != true {
		t.Fatalf("status %v", st)
	}
	b, _ := json.Marshal(st)
	if strings.Contains(string(b), ob.cfg.SecretID) || strings.Contains(string(b), ob.token) {
		t.Fatal("status leaks credentials")
	}
}

func fakeClient(t *testing.T, f *fakeBao) *OpenBao {
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	ob, err := NewOpenBao(OpenBaoConfig{Addr: srv.URL, RoleID: "role-1", SecretID: "s3cr3t-id", TransitKey: "bpanel", AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	ob.sleep = func(time.Duration) {}
	return ob
}

func TestOpenBaoFakeSuite(t *testing.T) {
	runProviderSuite(t, fakeClient(t, newFakeBao()))
}

func TestOpenBaoRetryAndRelogin(t *testing.T) {
	f := newFakeBao()
	ob := fakeClient(t, f)
	ctx := context.Background()
	f.fail = 2 // two 503s, third attempt succeeds
	if err := ob.Put(ctx, "a", []byte("1")); err != nil {
		t.Fatal("retry:", err)
	}
	f.fail = 10
	err := ob.Put(ctx, "a", []byte("1"))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want unavailable, got %v", err)
	}
	f.fail = 0
	// revoke the token server-side: provider must log in again transparently.
	f.mu.Lock()
	f.tokens = map[string]bool{}
	before := f.logins
	f.mu.Unlock()
	if v, err := ob.Get(ctx, "a"); err != nil || string(v) != "1" {
		t.Fatalf("relogin: %v", err)
	}
	if f.logins != before+1 {
		t.Fatalf("logins %d -> %d", before, f.logins)
	}
}

func TestOpenBaoTokenRenewal(t *testing.T) {
	f := newFakeBao()
	f.lease = 60
	ob := fakeClient(t, f)
	now := time.Now()
	ob.now = func() time.Time { return now }
	ctx := context.Background()
	if err := ob.Put(ctx, "a", []byte("1")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(50 * time.Second) // inside the last third of the TTL
	if _, err := ob.Get(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if f.renews != 1 || f.logins != 1 {
		t.Fatalf("renews=%d logins=%d", f.renews, f.logins)
	}
	now = now.Add(5 * time.Minute) // expired: fresh login
	if _, err := ob.Get(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if f.logins != 2 {
		t.Fatalf("logins=%d", f.logins)
	}
}

func TestOpenBaoBadCredsNoLeak(t *testing.T) {
	f := newFakeBao()
	srv := httptest.NewServer(f)
	defer srv.Close()
	ob, _ := NewOpenBao(OpenBaoConfig{Addr: srv.URL, RoleID: "role-1", SecretID: "WRONG-secret-id-xyz", AllowInsecureHTTP: true})
	err := ob.Put(context.Background(), "a", []byte("value-xyz"))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "WRONG-secret-id-xyz") || strings.Contains(err.Error(), "value-xyz") {
		t.Fatalf("error leaks secret: %v", err)
	}
}

func TestOpenBaoTLSPinning(t *testing.T) {
	f := newFakeBao()
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	ob, err := NewOpenBao(OpenBaoConfig{Addr: srv.URL, CACertFile: ca, RoleID: "role-1", SecretID: "s3cr3t-id"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ob.Put(context.Background(), "a", []byte("1")); err != nil {
		t.Fatal("pinned CA must work:", err)
	}
	// wrong SPKI pin -> refused
	ob2, _ := NewOpenBao(OpenBaoConfig{Addr: srv.URL, CACertFile: ca, PinSHA256: strings.Repeat("00", 32), RoleID: "role-1", SecretID: "s3cr3t-id", Retries: 1})
	if err := ob2.Put(context.Background(), "a", []byte("1")); err == nil {
		t.Fatal("pin mismatch accepted")
	}
	// another CA (a different test server's cert) -> refused; system pool never used
	// (httptest servers all share one cert, so mint an unrelated self-signed CA)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "other-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	ca2 := filepath.Join(dir, "ca2.pem")
	os.WriteFile(ca2, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	ob3, _ := NewOpenBao(OpenBaoConfig{Addr: srv.URL, CACertFile: ca2, RoleID: "role-1", SecretID: "s3cr3t-id", Retries: 1})
	if err := ob3.Put(context.Background(), "a", []byte("1")); err == nil {
		t.Fatal("untrusted CA accepted")
	}
	// https without a CA file is refused at construction; http needs opt-in
	if _, err := NewOpenBao(OpenBaoConfig{Addr: srv.URL, RoleID: "r", SecretID: "s"}); err == nil {
		t.Fatal("https without ca accepted")
	}
	if _, err := NewOpenBao(OpenBaoConfig{Addr: "http://127.0.0.1:1", RoleID: "r", SecretID: "s"}); err == nil {
		t.Fatal("plain http accepted without opt-in")
	}
}

func TestLoadOpenBaoConfigMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "openbao.json")
	os.WriteFile(p, []byte(`{"addr":"https://x:8200","role_id":"r","secret_id":"s"}`), 0o644)
	if _, err := LoadOpenBaoConfig(p); err == nil {
		t.Fatal("0644 config accepted")
	}
	os.Chmod(p, 0o600)
	c, err := LoadOpenBaoConfig(p)
	if err != nil || c.RoleID != "r" {
		t.Fatal(err)
	}
	if _, err := LoadOpenBaoConfig(p + ".missing"); !errors.Is(err, ErrNotConfigured) {
		t.Fatal(err)
	}
}

func TestMigrateLocalToOpenBaoAndBack(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	l, err := NewLocal(st.DB, filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		l.Put(ctx, "k"+strconv.Itoa(i), []byte("v"+strconv.Itoa(i)))
	}
	legacySealed, _ := l.Seal(ctx, []byte("old-column"), "aad1")
	ob := fakeClient(t, newFakeBao())
	ob.Legacy = l
	res, err := Migrate(ctx, l, ob)
	if err != nil || res.Copied != 5 || res.Verified != 5 {
		t.Fatalf("migrate: %+v %v", res, err)
	}
	if p, err := ob.Open(ctx, legacySealed, "aad1"); err != nil || string(p) != "old-column" {
		t.Fatalf("legacy open via openbao: %v", err)
	}
	// back: into a fresh local store
	st2, _ := store.Open(filepath.Join(t.TempDir(), "db2.sqlite"))
	defer st2.Close()
	l2, _ := NewLocal(st2.DB, filepath.Join(t.TempDir(), "secret2.key"))
	res, err = Migrate(ctx, ob, l2)
	if err != nil || res.Verified != 5 {
		t.Fatalf("migrate back: %+v %v", res, err)
	}
	// verify failure path: destination that drops writes
	res, err = Migrate(ctx, l, dropStore{l2})
	if !errors.Is(err, ErrMigrateVerify) || len(res.Failed) != 5 {
		t.Fatalf("verify must fail: %+v %v", res, err)
	}
}

type dropStore struct{ *Local }

func (dropStore) Put(context.Context, string, []byte) error { return nil }
func (dropStore) Get(context.Context, string) ([]byte, error) {
	return []byte("different"), nil
}
