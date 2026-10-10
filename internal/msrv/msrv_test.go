package msrv

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

func TestNormalizeRoles(t *testing.T) {
	r, err := NormalizeRoles([]string{"Web", "dns", "web", " "})
	if err != nil || len(r) != 2 || r[0] != "dns" || r[1] != "web" {
		t.Fatalf("%v %v", r, err)
	}
	for _, bad := range [][]string{nil, {""}, {"root"}, {"web", "shell"}} {
		if _, err := NormalizeRoles(bad); !errors.Is(err, ErrBadRoles) {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestSignNodeCSRBindsIdentity(t *testing.T) {
	ca, _, err := NewCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, csr, _ := NewNodeKeyAndCSR("evil-name-ignored")
	c, _, err := ca.SignNodeCSR(csr, 7, []string{"db", "web"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id, err := IdentityOf(c)
	if err != nil || id.NodeID != 7 || id.Panel || len(id.Roles) != 2 || id.Serial != SerialHex(c.SerialNumber) {
		t.Fatalf("%+v %v", id, err)
	}
	if c.IsCA || c.NotAfter.Sub(time.Now()) > NodeCertValidity+time.Hour {
		t.Fatal("node cert must be a short-lived leaf")
	}
	// ed25519 CSRs are accepted too
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	if _, _, err := ca.SignNodeCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 8, []string{"dns"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "junk", "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"} {
		if _, _, err := ca.SignNodeCSR([]byte(bad), 1, []string{"web"}, time.Now()); !errors.Is(err, ErrBadCSR) {
			t.Errorf("bad csr %q accepted", bad)
		}
	}
	p, _, err := ca.IssuePanel(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pc, _ := ParseCert(p)
	if id, _ := IdentityOf(pc); !id.Panel {
		t.Fatal("panel identity")
	}
}

func TestValidAddress(t *testing.T) {
	for _, a := range []string{"", "10.0.0.1:8445", "[2001:db8::1]:8445", "node.example.com:1"} {
		if !ValidAddress(a) {
			t.Errorf("%q refused", a)
		}
	}
	for _, a := range []string{"10.0.0.1", ":8445", "h:0", "h:70000", "a b:1"} {
		if ValidAddress(a) {
			t.Errorf("%q accepted", a)
		}
	}
}
