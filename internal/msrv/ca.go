// Package msrv implements BPANEL's multi-server support (spec §16): a
// panel-side certificate authority, one-time node enrolment tokens, mTLS
// configuration for the panel ↔ remote agent channel, revocation, health
// checks and config pushes as node-targeted jobs.
//
// Everything is stdlib crypto (crypto/x509, crypto/ecdsa P-256, TLS 1.3).
// The CA private key lives only in the panel's SecretStore.
package msrv

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Secret names used in the panel SecretStore.
const (
	SecretCAKey      = "msrv/ca.key"
	SecretCACert     = "msrv/ca.crt"
	SecretPanelKey   = "msrv/panel.key"
	SecretPanelCert  = "msrv/panel.crt"
	CAValidity       = 10 * 365 * 24 * time.Hour
	NodeCertValidity = 90 * 24 * time.Hour
	PanelURI         = "bpanel://panel"
)

// Roles a node may carry.
var Roles = []string{"web", "dns", "mail", "db", "backup", "monitor"}

// Errors (codes are the API error codes).
var (
	ErrBadRoles     = errors.New("msrv_bad_roles")
	ErrBadCSR       = errors.New("msrv_bad_csr")
	ErrTokenInvalid = errors.New("msrv_token_invalid")
	ErrRevoked      = errors.New("msrv_cert_revoked")
	ErrNodeUnknown  = errors.New("msrv_node_unknown")
	ErrNoAddress    = errors.New("msrv_no_address")
	ErrCAUnusable   = errors.New("msrv_ca_unavailable")
)

// KV is the subset of secrets.SecretStore the CA needs.
type KV interface {
	Get(ctx context.Context, name string) ([]byte, error)
	Put(ctx context.Context, name string, value []byte) error
}

// CA is the panel certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	PEM  []byte
}

// NormalizeRoles validates, de-duplicates and sorts roles.
func NormalizeRoles(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, r := range in {
		r = strings.ToLower(strings.TrimSpace(r))
		if r == "" {
			continue
		}
		ok := false
		for _, k := range Roles {
			if k == r {
				ok = true
			}
		}
		if !ok {
			return nil, ErrBadRoles
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil, ErrBadRoles
	}
	sort.Strings(out)
	return out, nil
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// SerialHex is the canonical serial string stored in the DB.
func SerialHex(n *big.Int) string { return strings.ToLower(n.Text(16)) }

func encKey(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseKey parses a PKCS#8 PEM private key.
func ParseKey(b []byte) (crypto.Signer, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("key is not a signer")
	}
	return s, nil
}

// ParseCert parses the first PEM certificate.
func ParseCert(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("no PEM certificate")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// NewCA creates a fresh self-signed ECDSA P-256 CA.
func NewCA(now time.Time) (*CA, []byte, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "BPANEL node CA", Organization: []string{"BPANEL"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(CAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := encKey(k)
	if err != nil {
		return nil, nil, err
	}
	return &CA{Cert: c, Key: k, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, keyPEM, nil
}

// LoadOrCreateCA reads the CA from the secret store, creating it on first use.
func LoadOrCreateCA(ctx context.Context, kv KV, now time.Time) (*CA, error) {
	if kv == nil {
		return nil, ErrCAUnusable
	}
	kb, kerr := kv.Get(ctx, SecretCAKey)
	cb, cerr := kv.Get(ctx, SecretCACert)
	if kerr == nil && cerr == nil {
		k, err := ParseKey(kb)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCAUnusable, err)
		}
		c, err := ParseCert(cb)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCAUnusable, err)
		}
		return &CA{Cert: c, Key: k, PEM: cb}, nil
	}
	if kerr == nil || cerr == nil { // half a CA: never silently replace it
		return nil, fmt.Errorf("%w: incomplete CA in secret store", ErrCAUnusable)
	}
	ca, keyPEM, err := NewCA(now)
	if err != nil {
		return nil, err
	}
	if err := kv.Put(ctx, SecretCAKey, keyPEM); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCAUnusable, err)
	}
	if err := kv.Put(ctx, SecretCACert, ca.PEM); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCAUnusable, err)
	}
	return ca, nil
}

// Pool returns a cert pool holding only this CA.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// Fingerprint is the sha256 of the CA certificate (hex), shown to admins.
func (ca *CA) Fingerprint() string {
	h := sha256.Sum256(ca.Cert.Raw)
	return hex.EncodeToString(h[:])
}

// NodeURI is the identity URI SAN of a node certificate.
func NodeURI(nodeID int64, roles []string) string {
	return "bpanel://node/" + strconv.FormatInt(nodeID, 10) + "?roles=" + strings.Join(roles, ",")
}

// Identity is what a verified peer certificate says about the peer.
type Identity struct {
	Panel  bool
	NodeID int64
	Roles  []string
	Serial string
}

// IdentityOf extracts the BPANEL identity from a certificate's URI SANs.
func IdentityOf(c *x509.Certificate) (Identity, error) {
	id := Identity{Serial: SerialHex(c.SerialNumber)}
	for _, u := range c.URIs {
		if u.Scheme != "bpanel" {
			continue
		}
		if u.Host == "panel" {
			id.Panel = true
			return id, nil
		}
		if u.Host == "node" {
			n, err := strconv.ParseInt(strings.TrimPrefix(u.Path, "/"), 10, 64)
			if err != nil || n <= 0 {
				return id, errors.New("bad node id in certificate")
			}
			id.NodeID = n
			if r := u.Query().Get("roles"); r != "" {
				id.Roles = strings.Split(r, ",")
			}
			return id, nil
		}
	}
	return id, errors.New("certificate carries no BPANEL identity")
}

// SignNodeCSR signs a node CSR (PEM) and binds it to nodeID and roles. The
// CSR's own subject/SANs are ignored: identity comes only from the panel.
func (ca *CA) SignNodeCSR(csrPEM []byte, nodeID int64, roles []string, now time.Time) (*x509.Certificate, []byte, error) {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return nil, nil, ErrBadCSR
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, nil, ErrBadCSR
	}
	switch pk := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if pk.Curve != elliptic.P256() && pk.Curve != elliptic.P384() {
			return nil, nil, ErrBadCSR
		}
	case ed25519.PublicKey:
	default:
		return nil, nil, ErrBadCSR
	}
	u, _ := url.Parse(NodeURI(nodeID, roles))
	return ca.issue(csr.PublicKey, pkix.Name{CommonName: "bpanel-node-" + strconv.FormatInt(nodeID, 10)}, u, NodeCertValidity, now)
}

// IssuePanel issues the panel's own client certificate for a fresh key.
func (ca *CA) IssuePanel(now time.Time) (certPEM, keyPEM []byte, err error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	u, _ := url.Parse(PanelURI)
	_, certPEM, err = ca.issue(&k.PublicKey, pkix.Name{CommonName: "bpanel-panel"}, u, NodeCertValidity, now)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = encKey(k)
	return certPEM, keyPEM, err
}

func (ca *CA) issue(pub crypto.PublicKey, subj pkix.Name, u *url.URL, validity time.Duration, now time.Time) (*x509.Certificate, []byte, error) {
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	notAfter := now.Add(validity)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      subj,
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// NewNodeKeyAndCSR is used by `bpanel-agent join`: a fresh P-256 key and a CSR.
func NewNodeKeyAndCSR(hostname string) (keyPEM, csrPEM []byte, err error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hostname}}, k)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = encKey(k)
	if err != nil {
		return nil, nil, err
	}
	return keyPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}
