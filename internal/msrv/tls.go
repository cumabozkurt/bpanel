package msrv

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// RevokedFn reports whether a certificate serial (lower-case hex) is revoked.
// It is consulted on every handshake.
type RevokedFn func(serial string) bool

func verifyLeaf(cs tls.ConnectionState, pool *x509.CertPool, usage x509.ExtKeyUsage, revoked RevokedFn) (Identity, error) {
	if len(cs.PeerCertificates) == 0 {
		return Identity{}, errors.New("no peer certificate")
	}
	leaf := cs.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return Identity{}, err
	}
	id, err := IdentityOf(leaf)
	if err != nil {
		return id, err
	}
	if revoked == nil || revoked(id.Serial) {
		return id, ErrRevoked
	}
	return id, nil
}

// ServerTLSConfig is the agent remote listener's config: TLS 1.3 only,
// client certificate required, verified against the panel CA only, and the
// client must be the panel (URI bpanel://panel) with a non-revoked serial.
func ServerTLSConfig(caPEM, certPEM, keyPEM []byte, revoked RevokedFn) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("bad CA PEM")
	}
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{kp},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			id, err := verifyLeaf(cs, pool, x509.ExtKeyUsageClientAuth, revoked)
			if err != nil {
				return err
			}
			if !id.Panel {
				return errors.New("client is not the panel")
			}
			return nil
		},
	}, nil
}

// ClientTLSConfig is the panel's config for dialing node nodeID: the server
// certificate must chain to the panel CA, name exactly that node, and not be
// revoked. Host names are not used for identity (nodes are addressed by IP or
// any name); the identity URI is.
func ClientTLSConfig(ca *x509.CertPool, panel tls.Certificate, nodeID int64, revoked RevokedFn, seen func(*x509.Certificate)) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{panel},
		RootCAs:            ca,
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyConnection below (CA + node identity + revocation)
		VerifyConnection: func(cs tls.ConnectionState) error {
			id, err := verifyLeaf(cs, ca, x509.ExtKeyUsageServerAuth, revoked)
			if err != nil {
				return err
			}
			if id.Panel || id.NodeID != nodeID {
				return fmt.Errorf("peer is node %d, expected %d", id.NodeID, nodeID)
			}
			if seen != nil {
				seen(cs.PeerCertificates[0])
			}
			return nil
		},
	}
}

// NodeCaller returns an agentrpc client that speaks the normal agent JSON
// protocol to a remote node over mTLS.
func NodeCaller(addr string, cfg *tls.Config) *rpc.Client {
	c := &rpc.Client{}
	c.DialFn = func(ctx context.Context) (net.Conn, error) {
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: cfg}
		return d.DialContext(ctx, "tcp", addr)
	}
	return c
}
