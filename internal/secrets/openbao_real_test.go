//go:build openbao

package secrets

// Real integration test against an OpenBao server in -dev mode with dev TLS.
//
//	BPANEL_BAO=/path/to/bao go test -tags openbao -v -run Real ./internal/secrets
//
// Skips when no `bao` binary is found. The test enables AppRole and Transit,
// writes a least-privilege policy, mints a role_id/secret_id, and runs the
// same conformance suite as the fake, over TLS with only the dev CA trusted.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"crypto/tls"
	"crypto/x509"

	"github.com/cumabozkurt/bpanel/internal/store"
)

func findBao(t *testing.T) string {
	for _, p := range []string{os.Getenv("BPANEL_BAO"), "/usr/local/bin/bao", "/usr/bin/bao"} {
		if p == "" {
			continue
		}
		if out, err := exec.Command(p, "version").Output(); err == nil {
			t.Logf("using %s: %s", p, bytes.TrimSpace(out))
			return p
		}
	}
	t.Skip("bao binary not found (set BPANEL_BAO)")
	return ""
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

const rootTok = "bpanel-dev-root"

func TestOpenBaoReal(t *testing.T) {
	bin := findBao(t)
	dir := t.TempDir()
	port := freePort(t)
	addr := "https://127.0.0.1:" + strconv.Itoa(port)
	cmd := exec.Command(bin, "server", "-dev", "-dev-tls", "-dev-tls-cert-dir="+dir,
		"-dev-root-token-id="+rootTok, "-dev-listen-address=127.0.0.1:"+strconv.Itoa(port))
	logf, _ := os.Create(filepath.Join(dir, "bao.log"))
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Env = append(os.Environ(), "HOME="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })

	caFile := filepath.Join(dir, "vault-ca.pem")
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(caFile); err == nil {
			break
		}
		if time.Now().After(deadline) {
			b, _ := os.ReadFile(filepath.Join(dir, "bao.log"))
			t.Fatalf("bao did not write its dev CA:\n%s", b)
		}
		time.Sleep(200 * time.Millisecond)
	}
	pem, _ := os.ReadFile(caFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	root := func(method, path string, body any) map[string]any {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		for i := 0; ; i++ {
			req, _ := http.NewRequest(method, addr+"/v1/"+path, rd)
			req.Header.Set("X-Vault-Token", rootTok)
			res, err := hc.Do(req)
			if err != nil {
				if i < 50 {
					time.Sleep(200 * time.Millisecond)
					continue
				}
				t.Fatal(err)
			}
			b, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode >= 300 {
				t.Fatalf("%s %s: %d %s", method, path, res.StatusCode, b)
			}
			var m map[string]any
			json.Unmarshal(b, &m)
			return m
		}
	}
	root("POST", "sys/auth/approle", map[string]any{"type": "approle"})
	root("POST", "sys/mounts/transit", map[string]any{"type": "transit"})
	root("POST", "transit/keys/bpanel", map[string]any{"derived": true})
	policy := `
path "secret/data/bpanel/*"     { capabilities = ["create","read","update"] }
path "secret/metadata/bpanel"   { capabilities = ["list"] }
path "secret/metadata/bpanel/*" { capabilities = ["read","list","delete"] }
path "transit/encrypt/bpanel"   { capabilities = ["update"] }
path "transit/decrypt/bpanel"   { capabilities = ["update"] }
path "transit/keys/bpanel/rotate" { capabilities = ["update"] }
`
	root("POST", "sys/policies/acl/bpanel", map[string]any{"policy": policy})
	root("POST", "auth/approle/role/bpanel", map[string]any{"token_policies": []string{"bpanel"}, "token_ttl": "10m", "token_max_ttl": "1h"})
	roleID := root("GET", "auth/approle/role/bpanel/role-id", nil)["data"].(map[string]any)["role_id"].(string)
	secretID := root("POST", "auth/approle/role/bpanel/secret-id", map[string]any{})["data"].(map[string]any)["secret_id"].(string)

	cfgPath := filepath.Join(dir, "openbao.json")
	cb, _ := json.Marshal(OpenBaoConfig{Addr: addr, CACertFile: caFile, RoleID: roleID, SecretID: secretID, TransitKey: "bpanel"})
	os.WriteFile(cfgPath, cb, 0o600)
	oc, err := LoadOpenBaoConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	ob, err := NewOpenBao(oc)
	if err != nil {
		t.Fatal(err)
	}
	runProviderSuite(t, ob)

	// token renewal against the real server
	ob.mu.Lock()
	exp1 := ob.tokenExp
	ob.mu.Unlock()
	time.Sleep(1100 * time.Millisecond)
	if err := ob.RenewNow(context.Background()); err != nil {
		t.Fatal("renew-self:", err)
	}
	ob.mu.Lock()
	exp2 := ob.tokenExp
	ob.mu.Unlock()
	if !exp2.After(exp1) {
		t.Fatalf("renewal did not extend token: %v -> %v", exp1, exp2)
	}
	// least privilege: the AppRole token cannot read outside its prefix
	if r, err := ob.do(context.Background(), "GET", "secret/data/other/x", nil, true); err != nil || r.status != 403 {
		t.Fatalf("policy not enforced: %v %d", err, r.status)
	}

	// migration local -> real OpenBao -> local
	st, _ := store.Open(filepath.Join(dir, "db.sqlite"))
	defer st.Close()
	l, _ := NewLocal(st.DB, filepath.Join(dir, "secret.key"))
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		l.Put(ctx, fmt.Sprintf("mig/item-%02d", i), []byte(fmt.Sprintf("value-%d", i)))
	}
	res, err := Migrate(ctx, l, ob)
	if err != nil || res.Verified != 20 {
		t.Fatalf("migrate to openbao: %+v %v", res, err)
	}
	st2, _ := store.Open(filepath.Join(dir, "db2.sqlite"))
	defer st2.Close()
	l2, _ := NewLocal(st2.DB, filepath.Join(dir, "secret2.key"))
	res2, err := Migrate(ctx, ob, l2)
	if err != nil {
		t.Fatalf("migrate back: %+v %v", res2, err)
	}
	t.Logf("real OpenBao: suite ok, renewal ok, policy ok, migrated %d -> openbao, %d back", res.Verified, res2.Verified)
}
