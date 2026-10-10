package agent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/http/webroot"
	"github.com/go-acme/lego/v5/registration"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/distro"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// AutoSSL: lego (embedded) with the HTTP-01 webroot challenge served from
// /var/lib/bpanel/acme by every vhost.

const acmeWebroot = "/var/lib/bpanel/acme"

type acmeUser struct {
	Email string                `json:"email"`
	Reg   *acme.ExtendedAccount `json:"registration"`
	key   crypto.Signer
}

func (u *acmeUser) GetEmail() string                       { return u.Email }
func (u *acmeUser) GetRegistration() *acme.ExtendedAccount { return u.Reg }
func (u *acmeUser) GetPrivateKey() crypto.Signer           { return u.key }

func (a *Agent) acmeAccount(ctx context.Context, email string, staging bool) (*lego.Client, error) {
	dir := filepath.Join(a.Cfg.ACMEDir, map[bool]string{true: "staging", false: "production"}[staging])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "account.key")
	u := &acmeUser{Email: email}
	if b, err := os.ReadFile(keyPath); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, errf("acme_key", "corrupt account key")
		}
		k, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		u.key = k
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		if err := writeAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600, -1, -1); err != nil {
			return nil, err
		}
		u.key = k
	}
	regPath := filepath.Join(dir, "account.json")
	if b, err := os.ReadFile(regPath); err == nil {
		var saved acmeUser
		if json.Unmarshal(b, &saved) == nil {
			u.Reg = saved.Reg
		}
	}
	cfg := lego.NewConfig(u)
	if staging {
		cfg.CADirURL = lego.DirectoryURLLetsEncryptStaging
	}
	if url := os.Getenv("BPANEL_ACME_DIRECTORY"); url != "" { // Pebble in CI
		cfg.CADirURL = url
	}
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	if u.Reg == nil {
		reg, err := client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, errf("acme_register", "%v", err)
		}
		u.Reg = reg
		b, err := json.Marshal(u)
		if err != nil {
			return nil, err
		}
		if err := writeAtomic(regPath, b, 0o600, -1, -1); err != nil {
			return nil, err
		}
	}
	return client, nil
}

func (a *Agent) sslIssue(ctx context.Context, p rpc.SSLIssue) (rpc.SSLInfo, error) {
	var info rpc.SSLInfo
	if err := validate.Domain(p.Domain); err != nil {
		return info, errf("invalid_domain", "%s", p.Domain)
	}
	domains := []string{p.Domain}
	for _, s := range p.SANs {
		if err := validate.Domain(s); err != nil {
			return info, errf("invalid_domain", "%s", s)
		}
		domains = append(domains, s)
	}
	// CODE-27: a tenant certificate only for the account's own names; an
	// owner-less request (installer: panel hostname) only for names no
	// account holds.
	for _, d := range domains {
		if p.User != "" {
			if err := a.ownsAny(d, p.User, kindWeb); err != nil {
				return info, err
			}
		} else if err := a.hostnameOrFree(d); err != nil {
			return info, err
		}
	}
	email := p.Email
	if email == "" {
		email = a.Cfg.ACMEEmail
	}
	if email != "" && validate.Email(email) != nil {
		return info, errf("invalid_email", "%s", email)
	}
	defer a.lock("acme")()
	client, err := a.acmeAccount(ctx, email, p.Staging || a.Cfg.ACMEStaging)
	if err != nil {
		return info, err
	}
	if err := os.MkdirAll(filepath.Join(a.acmeDir, ".well-known", "acme-challenge"), 0o755); err != nil {
		return info, err
	}
	prov, err := webroot.NewHTTPProvider(a.acmeDir)
	if err != nil {
		return info, err
	}
	if err := client.Challenge.SetHTTP01Provider(prov); err != nil {
		return info, err
	}
	res, err := client.Certificate.Obtain(ctx, certificate.ObtainRequest{Domains: domains, Bundle: true, KeyType: certcrypto.RSA2048})
	if err != nil {
		return info, errf("acme_failed", "%v", err)
	}
	if err := a.installCert(p.Domain, res.Certificate, res.PrivateKey); err != nil {
		return info, err
	}
	if err := a.reloadForCert(ctx, p.Domain); err != nil {
		return info, err
	}
	return a.sslInfo(ctx, rpc.DomainRef{Domain: p.Domain})
}

// hostnameOrFree is the owner-less (server) certificate rule: the panel
// hostname itself is the server's even when a tenant holds its parent
// domain (R2-WB-5: a tenant owning example.net blocked the certificate of
// panel.example.net forever); only an account holding the exact name
// conflicts. Any other name must be free of every account.
func (a *Agent) hostnameOrFree(d string) error {
	if a.Cfg.Hostname != "" && normName(d) == normName(a.Cfg.Hostname) {
		for _, k := range allKinds {
			if e, ok, err := a.readOwner(k, normName(d)); err != nil {
				return err
			} else if ok && e.Owner != "" {
				return errf("owned_by_another_account", "%s belongs to an account", d)
			}
		}
		return nil
	}
	return a.conflict(d, "")
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// reloadForCert makes a renewed certificate live (SYS-4): nginx only reads
// certificate files on reload. The panel hostname certificate is also copied
// to <ssl_dir>/panel, which bpanel-api reloads on change.
func (a *Agent) reloadForCert(ctx context.Context, domain string) error {
	if a.Cfg.Hostname != "" && domain == a.Cfg.Hostname {
		c, k := a.certPaths(domain)
		chain, err := os.ReadFile(c)
		if err != nil {
			return err
		}
		key, err := os.ReadFile(k)
		if err != nil {
			return err
		}
		if err := a.installCert("panel", chain, key); err != nil {
			return err
		}
		// bpanel-api runs unprivileged: give its group read access to the panel key
		if g, err := groupID("bpanel"); err == nil {
			dir := filepath.Join(a.Cfg.SSLDir, "panel")
			for _, f := range []string{dir, filepath.Join(dir, "privkey.pem"), filepath.Join(dir, "fullchain.pem")} {
				if err := os.Chown(f, 0, g); err != nil {
					return err
				}
			}
			if err := os.Chmod(dir, 0o750); err != nil {
				return err
			}
			if err := os.Chmod(filepath.Join(dir, "privkey.pem"), 0o640); err != nil {
				return err
			}
		}
		a.fanOutPanelCert(ctx, chain, key)
	}
	if _, err := os.Stat(filepath.Join(a.L.NginxVhosts, domain+".conf")); err != nil {
		return nil // no vhost uses it yet; the next vhost.apply picks it up
	}
	defer a.lock("web")()
	if err := a.configTest(ctx, a.L.NginxUnit); err != nil {
		return errf("nginx_config_invalid", "%v", err)
	}
	return a.systemctl(ctx, "reload", a.L.NginxUnit)
}

// FTPPEMPath is Pure-FTPd's combined key+certificate file per family.
func (a *Agent) ftpPEMPath() string {
	if a.L.Family == distro.RHEL {
		return "/etc/pki/pure-ftpd/pure-ftpd.pem"
	}
	return "/etc/ssl/private/pure-ftpd.pem"
}

// fanOutPanelCert makes a renewed hostname certificate live for the mail and
// FTP services of the install profile (handoff-installer H-9 / handoff-backend
// I-3): Postfix and Dovecot read /etc/bpanel/ssl/panel/*, Pure-FTPd needs its
// own key+chain PEM. Failures are logged, never fatal: the renewal itself
// succeeded and nginx/bpanel-api already use the new certificate.
func (a *Agent) fanOutPanelCert(ctx context.Context, chain, key []byte) {
	units := []string{}
	if a.Cfg.Profile != "minimal" {
		pem := append(append([]byte{}, key...), chain...)
		if err := os.MkdirAll(filepath.Dir(a.ftpPEMPath()), 0o700); err == nil {
			if err := writeAtomic(a.ftpPEMPath(), pem, 0o600, 0, 0); err != nil {
				a.Log.Warn("panel cert: pure-ftpd pem", "err", err)
			}
		}
		units = append(units, a.L.FTPUnit)
	}
	if a.Cfg.Profile == "full" || a.Cfg.Profile == "" {
		units = append(units, "postfix", "dovecot")
	}
	for _, u := range units {
		if err := a.systemctl(ctx, "try-reload-or-restart", u); err != nil {
			a.Log.Warn("panel cert: reload", "unit", u, "err", err)
		}
	}
}

func (a *Agent) installCert(domain string, chain, key []byte) error {
	dir := filepath.Join(a.Cfg.SSLDir, domain)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, "privkey.pem"), key, 0o600, -1, -1); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, "fullchain.pem"), chain, 0o644, -1, -1)
}

// SelfSigned generates a 1-year self-signed certificate (hostname fallback).
func SelfSigned(names []string) (chain, key []byte, err error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: names[0], Organization: []string{"BOZKURT PANEL self-signed"}},
		DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return nil, nil, err
	}
	kd, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), nil
}

func (a *Agent) sslSelfSigned(ctx context.Context, p rpc.SSLIssue) (rpc.SSLInfo, error) {
	if err := validate.Domain(p.Domain); err != nil {
		return rpc.SSLInfo{}, errf("invalid_domain", "%s", p.Domain)
	}
	for _, n := range p.SANs {
		if err := validate.Domain(n); err != nil {
			return rpc.SSLInfo{}, errf("invalid_domain", "%s", n)
		}
	}
	names := append([]string{p.Domain}, p.SANs...)
	// R2-WB-2: the same ownership rule as ssl.issue - a tenant only for its
	// own names, the owner-less call (installer) only for the panel hostname
	// or names nobody holds, and never over an existing certificate of a
	// name it does not own.
	for _, d := range names {
		if p.User != "" {
			if err := a.ownsAny(d, p.User, kindWeb); err != nil {
				return rpc.SSLInfo{}, err
			}
		} else if err := a.hostnameOrFree(d); err != nil {
			return rpc.SSLInfo{}, err
		}
	}
	if p.User == "" && p.Domain != a.Cfg.Hostname {
		if c, _ := a.certPaths(p.Domain); fileExists(c) {
			return rpc.SSLInfo{}, errf("refused", "%s already has a certificate", p.Domain)
		}
	}
	chain, key, err := SelfSigned(names)
	if err != nil {
		return rpc.SSLInfo{}, err
	}
	if err := a.installCert(p.Domain, chain, key); err != nil {
		return rpc.SSLInfo{}, err
	}
	return a.sslInfo(ctx, rpc.DomainRef{Domain: p.Domain})
}

// CertInfo parses a PEM chain file.
func CertInfo(path string) (rpc.SSLInfo, error) {
	var info rpc.SSLInfo
	b, err := os.ReadFile(path)
	if err != nil {
		return info, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return info, errf("bad_cert", "no PEM block")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return info, err
	}
	info.Present = true
	info.Issuer = c.Issuer.CommonName
	if len(c.Issuer.Organization) > 0 {
		info.Issuer = c.Issuer.Organization[0] + " " + c.Issuer.CommonName
	}
	info.NotAfter = c.NotAfter.UTC().Format(time.RFC3339)
	info.SANs = c.DNSNames
	info.SelfSigned = c.Issuer.String() == c.Subject.String()
	return info, nil
}

func (a *Agent) sslInfo(ctx context.Context, p rpc.DomainRef) (rpc.SSLInfo, error) {
	if err := validate.Domain(p.Domain); err != nil {
		return rpc.SSLInfo{}, errf("invalid_domain", "%s", p.Domain)
	}
	c, _ := a.certPaths(p.Domain)
	info, err := CertInfo(c)
	if err != nil {
		// no (readable) certificate yet is a normal state, not an error
		return rpc.SSLInfo{Domain: p.Domain}, nil //nolint:nilerr
	}
	info.Domain = p.Domain
	return info, nil
}
