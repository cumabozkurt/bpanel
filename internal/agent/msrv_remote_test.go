package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/distro"
	"github.com/cumabozkurt/bpanel/internal/msrv"
	"github.com/cumabozkurt/bpanel/internal/store"
)

type memKV struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (k *memKV) Get(_ context.Context, n string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.m[n]
	if !ok {
		return nil, errors.New("not_found")
	}
	return v, nil
}

func (k *memKV) Put(_ context.Context, n string, v []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m[n] = append([]byte(nil), v...)
	return nil
}

type msrvEnv struct {
	mgr    *msrv.Manager
	a      *Agent
	nodeID int64
	addr   string
	dir    string
}

func enrolNode(t *testing.T, mgr *msrv.Manager, dir, name string, roles []string) (int64, string) {
	t.Helper()
	ctx := context.Background()
	n, tok, _, err := mgr.Store.CreateNode(ctx, name, "", roles, 1)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := mgr.CA(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key, csr, err := msrv.NewNodeKeyAndCSR("test-node")
	if err != nil {
		t.Fatal(err)
	}
	en, err := mgr.Store.Enroll(ctx, ca, tok, csr)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(dir, 0o700)
	for f, b := range map[string]string{"node.key": string(key), "node.crt": en.CertPEM, "ca.crt": en.CAPEM} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return n.ID, tok
}

func newMsrvEnv(t *testing.T, roles []string) *msrvEnv {
	t.Helper()
	base := t.TempDir()
	st, err := store.Open(filepath.Join(base, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })
	mgr := &msrv.Manager{Store: &msrv.Store{DB: st.DB}, KV: &memKV{m: map[string][]byte{}}}
	dir := filepath.Join(base, "node")
	id, _ := enrolNode(t, mgr, dir, "node1", roles)

	l, err := distro.ForRelease(map[string]string{"ID": "ubuntu", "VERSION_ID": "24.04"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.RemoteDir = dir
	cfg.NoSystemd = true
	a := New(cfg, l, slog.New(slog.NewTextHandler(io.Discard, nil)))
	tcfg, gotRoles, err := a.RemoteTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(gotRoles, ",") != strings.Join(roles, ",") {
		t.Fatalf("roles from cert = %v", gotRoles)
	}
	if tcfg.MinVersion != tls.VersionTLS13 || tcfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("listener must be TLS1.3 + RequireAndVerifyClientCert")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go a.ServeRemote(ctx, tls.NewListener(ln, tcfg), gotRoles)
	addr := ln.Addr().String()
	if err := mgr.Store.SetAddress(context.Background(), id, addr); err != nil {
		t.Fatal(err)
	}
	return &msrvEnv{mgr: mgr, a: a, nodeID: id, addr: addr, dir: dir}
}

func msrvCode(err error) string {
	var re *rpc.Error
	if errors.As(err, &re) {
		return re.Code
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestMsrvMTLSHandshakeAndHealth(t *testing.T) {
	e := newMsrvEnv(t, []string{"monitor", "web"})
	ctx := context.Background()
	h := e.mgr.Check(ctx, e.nodeID)
	if !h.OK || h.Version != Version || h.CertNotAfter == 0 {
		t.Fatalf("health = %+v", h)
	}
	n, _ := e.mgr.Store.Get(ctx, e.nodeID)
	if n.Health != "ok" || n.LatencyMS < 0 || n.Version != Version {
		t.Fatalf("stored health = %+v", n)
	}
	// same typed protocol: system.info works remotely too
	c, _, err := e.mgr.CallerFor(ctx, e.nodeID, nil)
	if err != nil {
		t.Fatal(err)
	}
	var p rpc.PingResult
	if err := c.Call(ctx, rpc.MPing, rpc.Empty{}, &p); err != nil {
		t.Fatal(err)
	}
}

func TestMsrvRemoteAllowlist(t *testing.T) {
	e := newMsrvEnv(t, []string{"web"})
	ctx := context.Background()
	c, _, err := e.mgr.CallerFor(ctx, e.nodeID, nil)
	if err != nil {
		t.Fatal(err)
	}
	// a method the agent has but which is never allowed over the network
	if err := c.Call(ctx, rpc.MFiles, map[string]any{"user": "x"}, nil); msrvCode(err) != "msrv_method_not_allowed" {
		t.Fatalf("files remotely: %v", err)
	}
	// a role-bound method for a role this node does not carry
	if err := c.Call(ctx, rpc.MDNSZoneGet, map[string]any{"owner": "x"}, nil); msrvCode(err) != "msrv_method_not_allowed" {
		t.Fatalf("dns on a web node: %v", err)
	}
	// unknown methods are refused as well
	if err := c.Call(ctx, "system.exec", map[string]any{}, nil); msrvCode(err) != "msrv_method_not_allowed" {
		t.Fatalf("unknown: %v", err)
	}
	if !RemoteMethodAllowed(rpc.MVhostApply, []string{"web"}) || RemoteMethodAllowed(rpc.MVhostApply, []string{"dns"}) {
		t.Fatal("role table")
	}
}

func TestMsrvWrongCARejected(t *testing.T) {
	e := newMsrvEnv(t, []string{"web"})
	ctx := context.Background()
	other, _, err := msrv.NewCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := other.IssuePanel(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kp, _ := tls.X509KeyPair(certPEM, keyPEM)
	realCA, _ := e.mgr.CA(ctx)
	// 1) panel cert from a foreign CA: the agent refuses the handshake
	c := msrv.NodeCaller(e.addr, msrv.ClientTLSConfig(realCA.Pool(), kp, e.nodeID, func(string) bool { return false }, nil))
	if err := c.Call(ctx, rpc.MPing, rpc.Empty{}, nil); err == nil {
		t.Fatal("agent accepted a client certificate from a foreign CA")
	}
	// 2) panel that trusts a foreign CA cannot verify the node
	good, _ := e.mgr.PanelCert(ctx)
	c = msrv.NodeCaller(e.addr, msrv.ClientTLSConfig(other.Pool(), good, e.nodeID, func(string) bool { return false }, nil))
	if err := c.Call(ctx, rpc.MPing, rpc.Empty{}, nil); err == nil {
		t.Fatal("panel accepted a node certificate it cannot chain")
	}
	// 3) no client certificate at all
	c = msrv.NodeCaller(e.addr, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}) //nolint:gosec
	if err := c.Call(ctx, rpc.MPing, rpc.Empty{}, nil); err == nil {
		t.Fatal("agent accepted a connection without client certificate")
	}
	// 4) wrong node id expected: identity mismatch
	c = msrv.NodeCaller(e.addr, msrv.ClientTLSConfig(realCA.Pool(), good, e.nodeID+1, func(string) bool { return false }, nil))
	if err := c.Call(ctx, rpc.MPing, rpc.Empty{}, nil); err == nil {
		t.Fatal("panel accepted the wrong node")
	}
}

func TestMsrvRevokedRejected(t *testing.T) {
	e := newMsrvEnv(t, []string{"web"})
	ctx := context.Background()
	// panel side: node serial revoked → handshake refused by the panel
	n, _ := e.mgr.Store.Get(ctx, e.nodeID)
	if err := e.mgr.Store.RevokeSerial(ctx, n.CertSerial, "test"); err != nil {
		t.Fatal(err)
	}
	if h := e.mgr.Check(ctx, e.nodeID); h.OK || !strings.Contains(h.Error, "revoked") {
		t.Fatalf("revoked node still healthy: %+v", h)
	}
	_, _ = e.mgr.Store.DB.Exec(`DELETE FROM msrv_revoked`)
	// agent side: push a revocation list containing the panel's serial
	pc, _ := e.mgr.PanelCert(ctx)
	leaf, _ := msrv.ParseCert(pemOf(pc.Certificate[0]))
	if err := e.mgr.Store.RevokeSerial(ctx, msrv.SerialHex(leaf.SerialNumber), "test"); err != nil {
		t.Fatal(err)
	}
	// the push itself still works: the node does not know yet
	if _, err := e.mgr.Push(ctx, msrv.PushPayload{NodeID: e.nodeID, Bundle: "revocations"}); err != nil {
		t.Fatal(err)
	}
	if h := e.mgr.Check(ctx, e.nodeID); h.OK {
		t.Fatal("agent accepted a revoked panel certificate")
	}
	// revoking the node marks it and refuses before dialing
	if err := e.mgr.Store.Revoke(ctx, e.nodeID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.mgr.CallerFor(ctx, e.nodeID, nil); !errors.Is(err, msrv.ErrRevoked) {
		t.Fatalf("CallerFor revoked = %v", err)
	}
}

func TestMsrvTokenSingleUseAndExpiry(t *testing.T) {
	e := newMsrvEnv(t, []string{"web"})
	ctx := context.Background()
	ca, _ := e.mgr.CA(ctx)
	_, csr, _ := msrv.NewNodeKeyAndCSR("x")
	// single use: re-enrol a second node, then replay its token
	_, tok := enrolNode(t, e.mgr, filepath.Join(t.TempDir(), "n2"), "node2", []string{"dns"})
	if _, err := e.mgr.Store.Enroll(ctx, ca, tok, csr); !errors.Is(err, msrv.ErrTokenInvalid) {
		t.Fatalf("replayed token: %v", err)
	}
	// expiry: 15 minutes
	_, tok3, _, err := e.mgr.Store.CreateNode(ctx, "node3", "10.0.0.3:8445", []string{"db"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	e.mgr.Store.Now = func() time.Time { return time.Now().Add(msrv.TokenTTL + time.Minute) }
	if _, err := e.mgr.Store.Enroll(ctx, ca, tok3, csr); !errors.Is(err, msrv.ErrTokenInvalid) {
		t.Fatalf("expired token: %v", err)
	}
	e.mgr.Store.Now = nil
	if _, err := e.mgr.Store.Enroll(ctx, ca, "bpj_garbage", csr); !errors.Is(err, msrv.ErrTokenInvalid) {
		t.Fatal("garbage token accepted")
	}
	// rotation: new cert, old serial revoked, node keeps working with the new one
	old, _ := e.mgr.Store.Get(ctx, e.nodeID)
	rt, _, err := e.mgr.Store.NewRotateToken(ctx, e.nodeID, 1)
	if err != nil {
		t.Fatal(err)
	}
	key, csr2, _ := msrv.NewNodeKeyAndCSR("x")
	en, err := e.mgr.Store.Enroll(ctx, ca, rt, csr2)
	if err != nil || en.NodeID != e.nodeID {
		t.Fatalf("rotate: %v", err)
	}
	if !e.mgr.Store.IsRevoked(old.CertSerial) {
		t.Fatal("old serial not revoked after rotation")
	}
	if h := e.mgr.Check(ctx, e.nodeID); h.OK {
		t.Fatal("node still served the rotated-out certificate and the panel accepted it")
	}
	_ = os.WriteFile(filepath.Join(e.dir, "node.key"), key, 0o600)
	_ = os.WriteFile(filepath.Join(e.dir, "node.crt"), []byte(en.CertPEM), 0o600)
	tcfg, roles, err := e.a.RemoteTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go e.a.ServeRemote(cctx, tls.NewListener(ln, tcfg), roles)
	_ = e.mgr.Store.SetAddress(ctx, e.nodeID, ln.Addr().String())
	if h := e.mgr.Check(ctx, e.nodeID); !h.OK {
		t.Fatalf("rotated node not healthy: %+v", h)
	}
}

func pemOf(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// `bpanel-agent join` against an HTTPS panel pinned by fingerprint.
func TestMsrvJoinCommand(t *testing.T) {
	base := t.TempDir()
	st, err := store.Open(filepath.Join(base, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	mgr := &msrv.Manager{Store: &msrv.Store{DB: st.DB}, KV: &memKV{m: map[string][]byte{}}}
	ca, _ := mgr.CA(context.Background())
	_, tok, _, err := mgr.Store.CreateNode(context.Background(), "edge1", "", []string{"dns", "web"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in JoinRequest
		_ = json.NewDecoder(r.Body).Decode(&in)
		en, err := mgr.Store.Enroll(r.Context(), ca, in.Token, []byte(in.CSR))
		if err != nil {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"error":"msrv_token_invalid"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(en)
	}))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	fp := hex.EncodeToString(sum[:])
	dir := filepath.Join(base, "node")
	if err := Join(srv.URL, tok, dir, "", strings.Repeat("0", 64)); err == nil {
		t.Fatal("join accepted a panel with the wrong fingerprint")
	}
	if err := Join(srv.URL, tok, dir, "", fp); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"node.key", "node.crt", "ca.crt"} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, err, fi)
		}
	}
	if err := Join(srv.URL, tok, dir, "", fp); err == nil || !strings.Contains(err.Error(), "msrv_token_invalid") {
		t.Fatalf("token reused: %v", err)
	}
	if err := Join("http://"+strings.TrimPrefix(srv.URL, "https://"), tok, dir, "", fp); err == nil {
		t.Fatal("plain http panel accepted")
	}
}
