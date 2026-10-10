package agent

// v0.4 msrv (spec §16): opt-in remote listener. It speaks exactly the same
// typed, allowlisted JSON protocol as the unix socket, over TLS 1.3 with a
// mandatory client certificate signed by the panel CA (and only the panel's
// identity, bpanel://panel, with a non-revoked serial). On top of the normal
// method table a REMOTE allowlist applies: only the methods below may be
// called over the network, and role-bound methods only when this node's own
// certificate carries that role. Without remote_listen nothing changes.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/msrv"
)

const defaultRemoteDir = "/etc/bpanel/node"

// remoteMethods: method → required node role ("" = any enrolled node).
var remoteMethods = map[string]string{
	rpc.MPing: "", rpc.MSysInfo: "", rpc.MMsrvRevokedSet: "",
	rpc.MNetsecFwApply: "", rpc.MNetsecFwConfirm: "", rpc.MNetsecFwStatus: "",
	rpc.MNetsecFwBlock: "", rpc.MNetsecFwUnblock: "", rpc.MNetsecFwList: "",
	rpc.MServiceStatus: "monitor",
	rpc.MAccountCreate: "web", rpc.MAccountExists: "web", rpc.MAccountSuspend: "web", rpc.MAccountPassword: "web",
	rpc.MAccountQuota: "web", rpc.MAccountTerminate: "web",
	rpc.MVhostApply: "web", rpc.MVhostRemove: "web", rpc.MPHPPoolApply: "web", rpc.MPHPPoolRemove: "web", rpc.MPHPVersions: "web",
	rpc.MDNSZoneCreate: "dns", rpc.MDNSZoneDelete: "dns", rpc.MDNSZoneGet: "dns", rpc.MDNSRRSetReplace: "dns", rpc.MDNSRRSetDelete: "dns",
	rpc.MMailDomainOn: "mail", rpc.MMailDomainOff: "mail", rpc.MMailboxCreate: "mail", rpc.MMailboxDelete: "mail",
	rpc.MMailboxPassword: "mail", rpc.MMailboxQuota: "mail",
	rpc.MDBCreate: "db", rpc.MDBDrop: "db", rpc.MDBUserCreate: "db", rpc.MDBUserDrop: "db", rpc.MDBUserPassword: "db",
	rpc.MDBGrant: "db", rpc.MDBRevoke: "db", rpc.MDBSizes: "db",
	rpc.MBackupRun: "backup", rpc.MBackupList: "backup", rpc.MBackupVerify: "backup",
}

func init() {
	gateExempt[rpc.MMsrvRevokedSet] = "server (msrv revocation list file under remote_dir)"
}

// RemoteMethodAllowed reports whether method may be called remotely on a node
// carrying roles.
func RemoteMethodAllowed(method string, roles []string) bool {
	need, ok := remoteMethods[method]
	if !ok {
		return false
	}
	if need == "" {
		return true
	}
	for _, r := range roles {
		if r == need {
			return true
		}
	}
	return false
}

func (a *Agent) msrvRoutes() map[string]handler {
	return map[string]handler{rpc.MMsrvRevokedSet: bind(a.msrvRevokedSet)}
}

func (a *Agent) remoteDir() string {
	if a.Cfg.RemoteDir != "" {
		return a.Cfg.RemoteDir
	}
	return defaultRemoteDir
}

var revokedMu sync.Mutex

func (a *Agent) msrvRevokedSet(_ context.Context, p rpc.MsrvRevokedSetParams) (rpc.MsrvRevokedSetResult, error) {
	if len(p.Serials) > 100000 {
		return rpc.MsrvRevokedSetResult{}, errf("bad_params", "too many serials")
	}
	clean := make([]string, 0, len(p.Serials))
	for _, s := range p.Serials {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || len(s) > 64 || strings.Trim(s, "0123456789abcdef") != "" {
			return rpc.MsrvRevokedSetResult{}, errf("bad_params", "invalid serial")
		}
		clean = append(clean, s)
	}
	b, _ := json.Marshal(clean)
	revokedMu.Lock()
	defer revokedMu.Unlock()
	dir := a.remoteDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return rpc.MsrvRevokedSetResult{}, err
	}
	tmp := filepath.Join(dir, ".revoked.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return rpc.MsrvRevokedSetResult{}, err
	}
	if err := os.Rename(tmp, filepath.Join(dir, "revoked.json")); err != nil {
		return rpc.MsrvRevokedSetResult{}, err
	}
	return rpc.MsrvRevokedSetResult{Count: len(clean)}, nil
}

// remoteRevoked reads remote_dir/revoked.json on every handshake (fail
// closed on a corrupt file; a missing file means nothing is revoked).
func (a *Agent) remoteRevoked(serial string) bool {
	b, err := os.ReadFile(filepath.Join(a.remoteDir(), "revoked.json"))
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	var list []string
	if json.Unmarshal(b, &list) != nil {
		return true
	}
	for _, s := range list {
		if s == serial {
			return true
		}
	}
	return false
}

// RemoteTLSConfig loads node.key/node.crt/ca.crt from remote_dir and returns
// the listener config plus this node's roles (from its own certificate).
func (a *Agent) RemoteTLSConfig() (*tls.Config, []string, error) {
	dir := a.remoteDir()
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, nil, err
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, "node.crt"))
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "node.key"))
	if err != nil {
		return nil, nil, err
	}
	cfg, err := msrv.ServerTLSConfig(caPEM, certPEM, keyPEM, a.remoteRevoked)
	if err != nil {
		return nil, nil, err
	}
	c, err := msrv.ParseCert(certPEM)
	if err != nil {
		return nil, nil, err
	}
	id, err := msrv.IdentityOf(c)
	if err != nil {
		return nil, nil, err
	}
	return cfg, id.Roles, nil
}

// StartRemote runs the remote listener when remote_listen is configured.
func (a *Agent) StartRemote(ctx context.Context) error {
	if a.Cfg.RemoteListen == "" {
		return nil
	}
	cfg, roles, err := a.RemoteTLSConfig()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", a.Cfg.RemoteListen)
	if err != nil {
		return err
	}
	a.Log.Info("agent remote listener (mTLS)", "addr", ln.Addr().String(), "roles", roles)
	go a.ServeRemote(ctx, tls.NewListener(ln, cfg), roles)
	return nil
}

// ServeRemote accepts TLS connections on ln (exported for tests).
func (a *Agent) ServeRemote(ctx context.Context, ln net.Listener, roles []string) {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case a.connSem() <- struct{}{}:
		case <-ctx.Done():
			c.Close()
			return
		}
		go func() {
			defer func() { <-a.connSem() }()
			a.handleRemoteConn(ctx, c, roles)
		}()
	}
}

func (a *Agent) handleRemoteConn(ctx context.Context, c net.Conn, roles []string) {
	defer c.Close()
	tc, ok := c.(*tls.Conn)
	if !ok {
		return
	}
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	hctx, hcancel := context.WithTimeout(ctx, 10*time.Second)
	err := tc.HandshakeContext(hctx)
	hcancel()
	if err != nil {
		a.Log.Warn("remote handshake rejected", "peer", c.RemoteAddr().String(), "err", err)
		return
	}
	_ = c.SetDeadline(time.Time{})
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReaderSize(c, 64<<10)
	line, err := a.readRequest(br)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			a.writeResp(c, rpc.Response{Error: &rpc.Error{Code: "bad_request", Message: err.Error()}})
		}
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	var req rpc.Request
	if err := json.Unmarshal(line, &req); err != nil {
		a.writeResp(c, rpc.Response{Error: &rpc.Error{Code: "bad_request", Message: err.Error()}})
		return
	}
	if !RemoteMethodAllowed(req.Method, roles) {
		a.Log.Warn("remote method refused", "method", req.Method, "peer", c.RemoteAddr().String())
		a.writeResp(c, rpc.Response{ID: req.ID, Error: &rpc.Error{Code: "msrv_method_not_allowed", Message: req.Method}})
		return
	}
	a.Log.Info("remote action", "method", req.Method, "peer", c.RemoteAddr().String())
	cctx, cancel := context.WithTimeout(ctx, rpc.MethodTimeout(req.Method))
	defer cancel()
	go func() {
		var b [1]byte
		_, _ = br.Read(b[:])
		cancel()
	}()
	a.writeResp(c, a.Dispatch(cctx, req))
}
