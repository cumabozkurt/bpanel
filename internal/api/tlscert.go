package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"sync"
	"time"
)

// certSource reloads the panel certificate from disk when it changes, so
// AutoSSL renewals of the hostname certificate apply without a restart.
type certSource struct {
	certFile, keyFile string
	mu                sync.Mutex
	cert              *tls.Certificate
	mod               time.Time
	fallback          *tls.Certificate
}

func loadOrSelfSign(certFile, keyFile, host string) (*certSource, error) {
	cs := &certSource{certFile: certFile, keyFile: keyFile}
	if host == "" {
		host, _ = os.Hostname()
	}
	fb, err := selfSigned(host)
	if err != nil {
		return nil, err
	}
	cs.fallback = fb
	return cs, nil
}

func (c *certSource) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := os.Stat(c.certFile)
	if err != nil {
		return c.fallback, nil
	}
	if c.cert == nil || st.ModTime().After(c.mod) {
		cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
		if err != nil {
			return c.fallback, nil
		}
		c.cert, c.mod = &cert, st.ModTime()
	}
	return c.cert, nil
}

func selfSigned(host string) (*tls.Certificate, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host, Organization: []string{"BOZKURT PANEL"}},
		DNSNames: []string{host, "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, nil
}
