package agent

// `bpanel-agent join --panel https://panel.example:2083 --token bpj_...`
// (/msrv/join is served on the user-realm port 2083; there is no port 8443).
// generates this node's key (never leaves the node) and a CSR, posts the CSR
// with the one-time token to the panel's /msrv/join endpoint and stores the
// signed certificate and the panel CA under --dir (default /etc/bpanel/node).
// The panel's own HTTPS certificate is verified with the system roots, or a
// given --panel-ca file, or pinned with --panel-fingerprint (sha256 hex of
// the panel's TLS leaf certificate) for self-signed panels.

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cumabozkurt/bpanel/internal/msrv"
)

// JoinRequest is the body of POST /msrv/join.
type JoinRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
}

// RunJoin implements the join sub-command; returns the exit code.
func RunJoin(args []string) int {
	fs := flag.NewFlagSet("join", flag.ContinueOnError)
	panel := fs.String("panel", "", "panel base URL (https://host:port)")
	token := fs.String("token", "", "one-time join token from the panel (Servers page)")
	dir := fs.String("dir", defaultRemoteDir, "where node.key, node.crt and ca.crt are written")
	panelCA := fs.String("panel-ca", "", "PEM file to verify the panel's HTTPS certificate (optional)")
	fp := fs.String("panel-fingerprint", "", "sha256 hex of the panel's HTTPS certificate (pins a self-signed panel)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if tok := os.Getenv("BPANEL_JOIN_TOKEN"); *token == "" && tok != "" {
		*token = tok // keeps the token out of the process list
	}
	if err := Join(*panel, *token, *dir, *panelCA, *fp); err != nil {
		fmt.Fprintln(os.Stderr, "join failed:", err)
		return 1
	}
	fmt.Println("joined; certificate written to", *dir, "- set remote_listen in agent.json and restart bpanel-agent")
	return 0
}

// Join performs the enrolment (exported for tests).
func Join(panel, token, dir, panelCA, fingerprint string) error {
	u, err := url.Parse(panel)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("--panel must be an https:// URL")
	}
	if token == "" {
		return errors.New("--token is required")
	}
	tcfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if panelCA != "" {
		b, err := os.ReadFile(panelCA)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return errors.New("--panel-ca: no certificate")
		}
		tcfg.RootCAs = pool
	}
	if fingerprint != "" {
		want, err := hex.DecodeString(strings.ReplaceAll(strings.ToLower(fingerprint), ":", ""))
		if err != nil || len(want) != sha256.Size {
			return errors.New("--panel-fingerprint must be 64 hex characters")
		}
		tcfg.InsecureSkipVerify = true //nolint:gosec // replaced by the pin below
		tcfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no panel certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return errors.New("panel certificate fingerprint mismatch")
			}
			return nil
		}
	}
	host, _ := os.Hostname()
	keyPEM, csrPEM, err := msrv.NewNodeKeyAndCSR(host)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(JoinRequest{Token: token, CSR: string(csrPEM)})
	cl := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tcfg}}
	resp, err := cl.Post(strings.TrimRight(panel, "/")+"/msrv/join", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(rb, &e)
		return fmt.Errorf("panel answered %d %s", resp.StatusCode, e.Error)
	}
	var en msrv.Enrollment
	if err := json.Unmarshal(rb, &en); err != nil {
		return err
	}
	c, err := msrv.ParseCert([]byte(en.CertPEM))
	if err != nil {
		return err
	}
	if _, err := msrv.ParseCert([]byte(en.CAPEM)); err != nil {
		return err
	}
	if id, err := msrv.IdentityOf(c); err != nil || id.NodeID != en.NodeID {
		return errors.New("panel returned a certificate for another node")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for name, b := range map[string][]byte{"node.key": keyPEM, "node.crt": []byte(en.CertPEM), "ca.crt": []byte(en.CAPEM)} {
		tmp := filepath.Join(dir, "."+name+".tmp")
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}
