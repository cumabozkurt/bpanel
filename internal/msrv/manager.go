package msrv

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/netsec"
)

// PanelRenewBefore: the panel client certificate is re-issued when it has
// less than this left.
const PanelRenewBefore = 30 * 24 * time.Hour

// Manager is the panel side: CA, panel client certificate, node callers,
// health checks and config pushes.
type Manager struct {
	Store *Store
	KV    KV
	Now   func() time.Time

	mu    sync.Mutex
	ca    *CA
	panel *tls.Certificate
	leaf  *x509.Certificate
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// CA loads (or creates) the panel CA.
func (m *Manager) CA(ctx context.Context) (*CA, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.caLocked(ctx)
}

func (m *Manager) caLocked(ctx context.Context) (*CA, error) {
	if m.ca != nil {
		return m.ca, nil
	}
	ca, err := LoadOrCreateCA(ctx, m.KV, m.now())
	if err != nil {
		return nil, err
	}
	m.ca = ca
	return ca, nil
}

// PanelCert returns the panel's client certificate, issuing or renewing it
// (the old serial is revoked on renewal; push the revocation list after).
func (m *Manager) PanelCert(ctx context.Context) (tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if m.panel != nil && m.leaf.NotAfter.Sub(now) > PanelRenewBefore {
		return *m.panel, nil
	}
	ca, err := m.caLocked(ctx)
	if err != nil {
		return tls.Certificate{}, err
	}
	kb, kerr := m.KV.Get(ctx, SecretPanelKey)
	cb, cerr := m.KV.Get(ctx, SecretPanelCert)
	if kerr == nil && cerr == nil {
		if kp, err := tls.X509KeyPair(cb, kb); err == nil {
			if leaf, err := x509.ParseCertificate(kp.Certificate[0]); err == nil && leaf.NotAfter.Sub(now) > PanelRenewBefore {
				m.panel, m.leaf = &kp, leaf
				return kp, nil
			} else if err == nil {
				_ = m.Store.RevokeSerial(ctx, SerialHex(leaf.SerialNumber), "panel cert renewed")
			}
		}
	}
	certPEM, keyPEM, err := ca.IssuePanel(now)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := m.KV.Put(ctx, SecretPanelKey, keyPEM); err != nil {
		return tls.Certificate{}, fmt.Errorf("%w: %v", ErrCAUnusable, err)
	}
	if err := m.KV.Put(ctx, SecretPanelCert, certPEM); err != nil {
		return tls.Certificate{}, fmt.Errorf("%w: %v", ErrCAUnusable, err)
	}
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, _ := x509.ParseCertificate(kp.Certificate[0])
	m.panel, m.leaf = &kp, leaf
	return kp, nil
}

// CallerFor returns an agent client for an active node. The node's serial is
// checked against the revocation table on every handshake. seen (optional)
// receives the node's verified certificate.
func (m *Manager) CallerFor(ctx context.Context, nodeID int64, seen func(*x509.Certificate)) (rpc.Caller, *Node, error) {
	n, err := m.Store.Get(ctx, nodeID)
	if err != nil {
		return nil, nil, err
	}
	if n.Status == "revoked" {
		return nil, n, ErrRevoked
	}
	if n.Status != "active" {
		return nil, n, ErrNodeUnknown
	}
	if n.Address == "" {
		return nil, n, ErrNoAddress
	}
	ca, err := m.CA(ctx)
	if err != nil {
		return nil, n, err
	}
	pc, err := m.PanelCert(ctx)
	if err != nil {
		return nil, n, err
	}
	cfg := ClientTLSConfig(ca.Pool(), pc, nodeID, m.Store.IsRevoked, seen)
	return NodeCaller(n.Address, cfg), n, nil
}

// HealthResult is one ping of a node.
type HealthResult struct {
	NodeID       int64  `json:"node_id"`
	OK           bool   `json:"ok"`
	LatencyMS    int64  `json:"latency_ms"`
	Version      string `json:"version,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	CertNotAfter int64  `json:"cert_not_after,omitempty"`
	Error        string `json:"error,omitempty"`
}

// Check pings one node over mTLS and stores the result.
func (m *Manager) Check(ctx context.Context, nodeID int64) HealthResult {
	res := HealthResult{NodeID: nodeID, LatencyMS: -1}
	var notAfter int64
	c, _, err := m.CallerFor(ctx, nodeID, func(x *x509.Certificate) { notAfter = x.NotAfter.Unix() })
	if err == nil {
		start := time.Now()
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		var p rpc.PingResult
		err = c.Call(cctx, rpc.MPing, rpc.Empty{}, &p)
		cancel()
		if err == nil {
			res.OK, res.LatencyMS, res.Version, res.Hostname, res.CertNotAfter = true, time.Since(start).Milliseconds(), p.Version, p.Hostname, notAfter
		}
	}
	if err != nil {
		res.Error = errCode(err)
	}
	if !errors.Is(err, ErrNodeUnknown) {
		_ = m.Store.SetHealth(ctx, nodeID, res.OK, time.Duration(res.LatencyMS)*time.Millisecond, res.Version, res.Error, notAfter)
	}
	return res
}

func errCode(err error) string {
	var re *rpc.Error
	if errors.As(err, &re) {
		if re.Message != "" {
			return re.Code + ": " + re.Message
		}
		return re.Code
	}
	return err.Error()
}

// CheckAll pings every active node (sequentially; node counts are small).
func (m *Manager) CheckAll(ctx context.Context) []HealthResult {
	nodes, err := m.Store.List(ctx)
	if err != nil {
		return nil
	}
	out := []HealthResult{}
	for _, n := range nodes {
		if n.Status != "active" || n.Address == "" {
			continue
		}
		out = append(out, m.Check(ctx, n.ID))
	}
	return out
}

// ---- config push -----------------------------------------------------------------

// Bundles are the named configuration bundles an admin may push.
var Bundles = []string{"firewall", "revocations"}

// PushPayload is the job payload of kind JobPush.
type PushPayload struct {
	NodeID  int64           `json:"node_id"`
	Bundle  string          `json:"bundle"`
	Ruleset *netsec.Ruleset `json:"ruleset,omitempty"`
}

// JobPush is the jobs kind for config pushes.
const JobPush = "msrv.push"

// Push executes one bundle on one node. It is safe to re-run: the firewall
// bundle replaces the node's bpanel table as a whole, the revocation list is
// replaced as a whole.
func (m *Manager) Push(ctx context.Context, p PushPayload) (map[string]any, error) {
	c, _, err := m.CallerFor(ctx, p.NodeID, nil)
	if err != nil {
		return nil, err
	}
	switch p.Bundle {
	case "revocations":
		serials, err := m.Store.RevokedSerials(ctx)
		if err != nil {
			return nil, err
		}
		var out rpc.MsrvRevokedSetResult
		if err := c.Call(ctx, rpc.MMsrvRevokedSet, rpc.MsrvRevokedSetParams{Serials: serials}, &out); err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "count": out.Count}, nil
	case "firewall":
		if p.Ruleset == nil {
			return nil, errors.New("msrv_bad_bundle")
		}
		var ap rpc.NetsecFwApplyResult
		if err := c.Call(ctx, rpc.MNetsecFwApply, rpc.NetsecFwApplyParams{Ruleset: *p.Ruleset, ConfirmSeconds: 60}, &ap); err != nil {
			return nil, err
		}
		if ap.Status != "pending" {
			return map[string]any{"status": ap.Status, "reason": ap.Reason}, nil
		}
		// confirm over a NEW connection: if the new rules cut the panel off,
		// the confirm fails and the node rolls back on its own
		var cf rpc.NetsecFwConfirmResult
		if err := c.Call(ctx, rpc.MNetsecFwConfirm, rpc.NetsecFwConfirmParams{Token: ap.Token}, &cf); err != nil {
			return map[string]any{"status": "rolled_back_pending", "reason": errCode(err)}, err
		}
		return map[string]any{"status": cf.Status}, nil
	}
	return nil, errors.New("msrv_bad_bundle")
}

// DecodePush parses a job payload.
func DecodePush(raw json.RawMessage) (PushPayload, error) {
	var p PushPayload
	err := json.Unmarshal(raw, &p)
	return p, err
}
