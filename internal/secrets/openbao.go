package secrets

// OpenBao provider (v0.4). OpenBao (https://openbao.org, MPL-2.0) is the free,
// community-governed fork of HashiCorp Vault. BPANEL talks to it over its
// HTTP API only (no SDK dependency):
//
//   - named secrets live in a KV v2 mount:  <kv_mount>/data/<prefix>/<name>
//   - Seal/Open use the Transit engine (optional) with a derived key so the
//     caller's aad is bound as Transit "context"; without Transit Seal/Open
//     report not_configured (and a Legacy store, if set, still opens values
//     sealed by the local provider before migration).
//   - authentication is AppRole (role_id + secret_id read from a 0600 file);
//     the client token is renewed (auth/token/renew-self) before it expires
//     and re-obtained by a fresh login when renewal fails or a 403 comes back.
//   - TLS trusts ONLY the configured CA (pinning: the system pool is never
//     used), optionally also pinning the server certificate's SPKI sha256.
//   - every request has a timeout; network errors, 429 and 5xx are retried
//     with backoff; 4xx are not.
//   - tokens, secret_ids and values never appear in errors or logs.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cumabozkurt/bpanel/internal/redact"
)

// DefaultOpenBaoConfig is the provider config file (must be mode 0600).
const DefaultOpenBaoConfig = "/etc/bpanel/openbao.json"

// sealedTransitPrefix marks a Seal output produced by the OpenBao Transit engine.
const sealedTransitPrefix = SealedPrefix + "obt:"

// ErrUnavailable is returned when OpenBao cannot be reached or refuses us.
var ErrUnavailable = errors.New("secret_backend_unavailable")

// OpenBaoConfig is the content of /etc/bpanel/openbao.json.
type OpenBaoConfig struct {
	Addr         string `json:"addr"`                    // https://bao.example:8200
	CACertFile   string `json:"ca_cert_file,omitempty"`  // PEM; required for https
	PinSHA256    string `json:"pin_sha256,omitempty"`    // optional hex sha256 of server leaf SPKI
	RoleID       string `json:"role_id"`                 // AppRole
	SecretID     string `json:"secret_id"`               // AppRole (secret)
	AppRoleMount string `json:"approle_mount,omitempty"` // default "approle"
	KVMount      string `json:"kv_mount,omitempty"`      // default "secret"
	Prefix       string `json:"prefix,omitempty"`        // default "bpanel"
	TransitMount string `json:"transit_mount,omitempty"` // default "transit"
	TransitKey   string `json:"transit_key,omitempty"`   // "" = Seal/Open not configured
	Namespace    string `json:"namespace,omitempty"`
	TimeoutSec   int    `json:"timeout_sec,omitempty"` // per request, default 10
	Retries      int    `json:"retries,omitempty"`     // default 3
	// AllowInsecureHTTP permits http:// (tests / loopback dev servers only).
	AllowInsecureHTTP bool `json:"allow_insecure_http,omitempty"`
}

// LoadOpenBaoConfig reads the config file, refusing one readable by group/other.
func LoadOpenBaoConfig(path string) (OpenBaoConfig, error) {
	var c OpenBaoConfig
	if path == "" {
		path = DefaultOpenBaoConfig
	}
	fi, err := os.Stat(path)
	if err != nil {
		return c, fmt.Errorf("openbao config: %w", ErrNotConfigured)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return c, errors.New("openbao config must be mode 0600")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, errors.New("openbao config: invalid json")
	}
	return c, nil
}

// OpenBao is the OpenBao provider. The zero value is "not configured": every
// call returns ErrNotConfigured (never a fake success).
type OpenBao struct {
	Addr   string
	cfg    OpenBaoConfig
	hc     *http.Client
	Legacy SecretStore // optional: opens values sealed by the local provider
	now    func() time.Time
	sleep  func(time.Duration)

	mu       sync.Mutex
	token    string
	tokenExp time.Time
	ttl      time.Duration
	lastErr  string
}

// NewOpenBao validates cfg and builds the HTTP client. It does not contact
// the server; the first call logs in.
func NewOpenBao(cfg OpenBaoConfig) (*OpenBao, error) {
	u, err := url.Parse(cfg.Addr)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("openbao: invalid addr")
	}
	if u.Scheme == "http" && !cfg.AllowInsecureHTTP {
		return nil, errors.New("openbao: https required (set allow_insecure_http only for loopback tests)")
	}
	if cfg.RoleID == "" || cfg.SecretID == "" {
		return nil, errors.New("openbao: role_id and secret_id required")
	}
	def := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	def(&cfg.AppRoleMount, "approle")
	def(&cfg.KVMount, "secret")
	def(&cfg.Prefix, "bpanel")
	def(&cfg.TransitMount, "transit")
	for _, s := range []string{cfg.AppRoleMount, cfg.KVMount, cfg.TransitMount, cfg.Prefix, cfg.TransitKey} {
		if s != "" && !segOK(s) {
			return nil, errors.New("openbao: invalid mount/prefix/key name")
		}
	}
	if cfg.TimeoutSec <= 0 {
		cfg.TimeoutSec = 10
	}
	if cfg.Retries <= 0 {
		cfg.Retries = 3
	}
	tr := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: time.Duration(cfg.TimeoutSec) * time.Second, MaxIdleConnsPerHost: 4}
	if u.Scheme == "https" {
		tc := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CACertFile == "" {
			return nil, errors.New("openbao: ca_cert_file required for https (CA pinning)")
		}
		pem, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, errors.New("openbao: cannot read ca_cert_file")
		}
		pool := x509.NewCertPool() // only the pinned CA, never the system pool
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("openbao: ca_cert_file has no certificate")
		}
		tc.RootCAs = pool
		if cfg.PinSHA256 != "" {
			want := strings.ToLower(strings.ReplaceAll(cfg.PinSHA256, ":", ""))
			tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return errors.New("openbao: no server certificate")
				}
				c, err := x509.ParseCertificate(raw[0])
				if err != nil {
					return err
				}
				h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
				if hex.EncodeToString(h[:]) != want {
					return errors.New("openbao: server key pin mismatch")
				}
				return nil
			}
		}
		tr.TLSClientConfig = tc
	}
	return &OpenBao{
		Addr: strings.TrimRight(cfg.Addr, "/"), cfg: cfg,
		hc:  &http.Client{Transport: tr, Timeout: time.Duration(cfg.TimeoutSec) * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		now: time.Now, sleep: time.Sleep,
	}, nil
}

// baoName is validName plus no empty, "." or ".." path segments (names
// become URL paths on the OpenBao side).
func baoName(n string) bool { return validName(n) && segOK(strings.ReplaceAll(n, ":", "_")) }

func segOK(s string) bool {
	for _, p := range strings.Split(s, "/") {
		if p == "" || p == "." || p == ".." {
			return false
		}
		for _, c := range p {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
				return false
			}
		}
	}
	return true
}

func (o *OpenBao) configured() bool { return o != nil && o.hc != nil }

// escPath escapes each segment of a secret name (names may contain ':' and '/').
func escPath(name string) string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

type baoResp struct {
	status int
	body   []byte
}

// do performs one API call with retries. auth=false for the login call.
func (o *OpenBao) do(ctx context.Context, method, path string, in any, auth bool) (baoResp, error) {
	var payload []byte
	if in != nil {
		payload, _ = json.Marshal(in)
	}
	var last error
	relogged := false
	for attempt := 0; attempt < o.cfg.Retries; attempt++ {
		if attempt > 0 {
			o.sleep(time.Duration(attempt*attempt) * 200 * time.Millisecond)
		}
		var tok string
		if auth {
			t, err := o.ensureToken(ctx)
			if err != nil {
				return baoResp{}, err
			}
			tok = t
		}
		req, err := http.NewRequestWithContext(ctx, method, o.Addr+"/v1/"+path, bytes.NewReader(payload))
		if err != nil {
			return baoResp{}, ErrUnavailable
		}
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if tok != "" {
			req.Header.Set("X-Vault-Token", tok)
		}
		if o.cfg.Namespace != "" {
			req.Header.Set("X-Vault-Namespace", o.cfg.Namespace)
		}
		req.Header.Set("X-Vault-Request", "true")
		res, err := o.hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return baoResp{}, ctx.Err()
			}
			last = fmt.Errorf("%w: %s", ErrUnavailable, redact.String(scrubErr(err)))
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
		res.Body.Close()
		switch {
		case res.StatusCode == http.StatusForbidden && auth && !relogged:
			// token revoked/expired early: log in again once, then retry.
			relogged = true
			o.mu.Lock()
			o.token = ""
			o.mu.Unlock()
			attempt--
			continue
		case res.StatusCode == 429 || res.StatusCode >= 500:
			last = fmt.Errorf("%w: http %d %s", ErrUnavailable, res.StatusCode, apiErrText(body))
			continue
		}
		return baoResp{res.StatusCode, body}, nil
	}
	o.mu.Lock()
	if last != nil {
		o.lastErr = last.Error()
	}
	o.mu.Unlock()
	return baoResp{}, last
}

// scrubErr removes the URL (which never holds secrets, but may be long) noise.
func scrubErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Op + ": " + ue.Err.Error()
	}
	return err.Error()
}

// apiErrText extracts OpenBao's "errors" array (never echoes request data).
func apiErrText(body []byte) string {
	var e struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(body, &e) != nil || len(e.Errors) == 0 {
		return ""
	}
	s := strings.Join(e.Errors, "; ")
	if len(s) > 200 {
		s = s[:200]
	}
	return redact.String(s)
}

type authBlock struct {
	Auth *struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

// ensureToken returns a valid token, renewing or logging in as needed.
func (o *OpenBao) ensureToken(ctx context.Context) (string, error) {
	o.mu.Lock()
	tok, exp, ttl := o.token, o.tokenExp, o.ttl
	o.mu.Unlock()
	now := o.now()
	if tok != "" && (exp.IsZero() || now.Before(exp.Add(-ttl/3))) {
		return tok, nil
	}
	if tok != "" && now.Before(exp) {
		if err := o.renew(ctx, tok); err == nil {
			o.mu.Lock()
			t := o.token
			o.mu.Unlock()
			return t, nil
		}
	}
	return o.login(ctx)
}

func (o *OpenBao) setToken(a authBlock) (string, error) {
	if a.Auth == nil || a.Auth.ClientToken == "" {
		return "", fmt.Errorf("%w: no token in auth response", ErrUnavailable)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.token = a.Auth.ClientToken
	o.ttl = time.Duration(a.Auth.LeaseDuration) * time.Second
	if a.Auth.LeaseDuration > 0 {
		o.tokenExp = o.now().Add(o.ttl)
	} else {
		o.tokenExp = time.Time{} // non-expiring
	}
	return o.token, nil
}

func (o *OpenBao) login(ctx context.Context) (string, error) {
	r, err := o.do(ctx, http.MethodPost, "auth/"+o.cfg.AppRoleMount+"/login", map[string]string{"role_id": o.cfg.RoleID, "secret_id": o.cfg.SecretID}, false)
	if err != nil {
		return "", err
	}
	if r.status != 200 {
		return "", fmt.Errorf("%w: approle login http %d %s", ErrUnavailable, r.status, apiErrText(r.body))
	}
	var a authBlock
	if json.Unmarshal(r.body, &a) != nil {
		return "", fmt.Errorf("%w: bad login response", ErrUnavailable)
	}
	return o.setToken(a)
}

func (o *OpenBao) renew(ctx context.Context, tok string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.Addr+"/v1/auth/token/renew-self", strings.NewReader("{}"))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", tok)
	if o.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", o.cfg.Namespace)
	}
	res, err := o.hc.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	res.Body.Close()
	if res.StatusCode != 200 {
		return ErrUnavailable
	}
	var a authBlock
	if json.Unmarshal(body, &a) != nil {
		return ErrUnavailable
	}
	_, err = o.setToken(a)
	return err
}

// RenewNow forces a token renewal (or login). Used by tests and the status page.
func (o *OpenBao) RenewNow(ctx context.Context) error {
	if !o.configured() {
		return ErrNotConfigured
	}
	o.mu.Lock()
	tok := o.token
	o.mu.Unlock()
	if tok != "" && o.renew(ctx, tok) == nil {
		return nil
	}
	_, err := o.login(ctx)
	return err
}

func (o *OpenBao) kvData(name string) string {
	return o.cfg.KVMount + "/data/" + o.cfg.Prefix + "/" + escPath(name)
}
func (o *OpenBao) kvMeta(name string) string {
	return o.cfg.KVMount + "/metadata/" + o.cfg.Prefix + "/" + escPath(name)
}

func statusErr(op string, r baoResp) error {
	return fmt.Errorf("%w: %s http %d %s", ErrUnavailable, op, r.status, apiErrText(r.body))
}

// ---- SecretStore ------------------------------------------------------------

func (o *OpenBao) Put(ctx context.Context, name string, value []byte) error {
	if !o.configured() {
		return ErrNotConfigured
	}
	if !baoName(name) {
		return ErrBadName
	}
	r, err := o.do(ctx, http.MethodPost, o.kvData(name), map[string]any{"data": map[string]string{"value": base64.StdEncoding.EncodeToString(value)}}, true)
	if err != nil {
		return err
	}
	if r.status != 200 && r.status != 204 {
		return statusErr("kv put", r)
	}
	return nil
}

func (o *OpenBao) Get(ctx context.Context, name string) ([]byte, error) {
	if !o.configured() {
		return nil, ErrNotConfigured
	}
	if !baoName(name) {
		return nil, ErrBadName
	}
	r, err := o.do(ctx, http.MethodGet, o.kvData(name), nil, true)
	if err != nil {
		return nil, err
	}
	if r.status == 404 {
		return nil, ErrNotFound
	}
	if r.status != 200 {
		return nil, statusErr("kv get", r)
	}
	var v struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if json.Unmarshal(r.body, &v) != nil || v.Data.Data == nil {
		return nil, ErrCorrupt
	}
	s, ok := v.Data.Data["value"]
	if !ok {
		return nil, ErrCorrupt
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrCorrupt
	}
	return b, nil
}

func (o *OpenBao) Delete(ctx context.Context, name string) error {
	if !o.configured() {
		return ErrNotConfigured
	}
	if !baoName(name) {
		return ErrBadName
	}
	r, err := o.do(ctx, http.MethodGet, o.kvMeta(name), nil, true)
	if err != nil {
		return err
	}
	if r.status == 404 {
		return ErrNotFound
	}
	if r.status != 200 {
		return statusErr("kv metadata", r)
	}
	// metadata delete removes every version permanently.
	r, err = o.do(ctx, http.MethodDelete, o.kvMeta(name), nil, true)
	if err != nil {
		return err
	}
	if r.status != 204 && r.status != 200 {
		return statusErr("kv delete", r)
	}
	return nil
}

type kvMetaResp struct {
	Data struct {
		CreatedTime    string `json:"created_time"`
		UpdatedTime    string `json:"updated_time"`
		CurrentVersion int    `json:"current_version"`
	} `json:"data"`
}

func (o *OpenBao) listDir(ctx context.Context, dir string, out *[]string, depth int) error {
	if depth > 8 {
		return nil
	}
	p := o.cfg.KVMount + "/metadata/" + o.cfg.Prefix
	if dir != "" {
		p += "/" + escPath(strings.TrimSuffix(dir, "/"))
	}
	r, err := o.do(ctx, "LIST", p, nil, true)
	if err != nil {
		return err
	}
	if r.status == 404 {
		return nil
	}
	if r.status != 200 {
		return statusErr("kv list", r)
	}
	var v struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if json.Unmarshal(r.body, &v) != nil {
		return ErrCorrupt
	}
	for _, k := range v.Data.Keys {
		full := dir + k
		if strings.HasSuffix(k, "/") {
			if err := o.listDir(ctx, full, out, depth+1); err != nil {
				return err
			}
			continue
		}
		*out = append(*out, full)
	}
	return nil
}

func parseBaoTime(s string) int64 {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return 0
	}
	return t.Unix()
}

func (o *OpenBao) List(ctx context.Context) ([]Meta, error) {
	if !o.configured() {
		return nil, ErrNotConfigured
	}
	var names []string
	if err := o.listDir(ctx, "", &names, 0); err != nil {
		return nil, err
	}
	out := []Meta{}
	for _, n := range names {
		r, err := o.do(ctx, http.MethodGet, o.kvMeta(n), nil, true)
		if err != nil {
			return nil, err
		}
		if r.status != 200 {
			continue
		}
		var m kvMetaResp
		_ = json.Unmarshal(r.body, &m)
		meta := Meta{Name: n, KeyID: fmt.Sprintf("kv-v%d", m.Data.CurrentVersion), CreatedAt: parseBaoTime(m.Data.CreatedTime)}
		if m.Data.CurrentVersion > 1 {
			meta.RotatedAt = parseBaoTime(m.Data.UpdatedTime)
		}
		out = append(out, meta)
	}
	sortMeta(out)
	return out, nil
}

func sortMeta(m []Meta) {
	for i := 1; i < len(m); i++ {
		for j := i; j > 0 && m[j].Name < m[j-1].Name; j-- {
			m[j], m[j-1] = m[j-1], m[j]
		}
	}
}

// Rotate rotates the Transit key (new version for future Seal calls). KV data
// is protected by OpenBao's own barrier, whose rotation (sys/rotate) is an
// OpenBao operator task, so no rows are rewritten here: returns 0. Existing
// sealed values stay readable; Reseal rewraps one under the newest version.
func (o *OpenBao) Rotate(ctx context.Context) (int, error) {
	if !o.configured() {
		return 0, ErrNotConfigured
	}
	if o.cfg.TransitKey == "" {
		return 0, nil
	}
	r, err := o.do(ctx, http.MethodPost, o.cfg.TransitMount+"/keys/"+o.cfg.TransitKey+"/rotate", map[string]any{}, true)
	if err != nil {
		return 0, err
	}
	if r.status != 200 && r.status != 204 {
		return 0, statusErr("transit rotate", r)
	}
	return 0, nil
}

func b64ctx(aad string) string { return base64.StdEncoding.EncodeToString([]byte(aad)) }

func (o *OpenBao) Seal(ctx context.Context, plain []byte, aad string) (string, error) {
	if !o.configured() || o.cfg.TransitKey == "" {
		return "", ErrNotConfigured
	}
	r, err := o.do(ctx, http.MethodPost, o.cfg.TransitMount+"/encrypt/"+o.cfg.TransitKey,
		map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plain), "context": b64ctx(aad)}, true)
	if err != nil {
		return "", err
	}
	if r.status != 200 {
		return "", statusErr("transit encrypt", r)
	}
	var v struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if json.Unmarshal(r.body, &v) != nil || !strings.HasPrefix(v.Data.Ciphertext, "vault:v") {
		return "", ErrCorrupt
	}
	return sealedTransitPrefix + base64.RawURLEncoding.EncodeToString([]byte(v.Data.Ciphertext)), nil
}

func (o *OpenBao) Open(ctx context.Context, sealed, aad string) ([]byte, error) {
	if !o.configured() {
		return nil, ErrNotConfigured
	}
	if !strings.HasPrefix(sealed, sealedTransitPrefix) {
		if IsSealed(sealed) && o.Legacy != nil {
			return o.Legacy.Open(ctx, sealed, aad)
		}
		return nil, ErrCorrupt
	}
	if o.cfg.TransitKey == "" {
		return nil, ErrNotConfigured
	}
	ct, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, sealedTransitPrefix))
	if err != nil {
		return nil, ErrCorrupt
	}
	r, err := o.do(ctx, http.MethodPost, o.cfg.TransitMount+"/decrypt/"+o.cfg.TransitKey,
		map[string]string{"ciphertext": string(ct), "context": b64ctx(aad)}, true)
	if err != nil {
		return nil, err
	}
	if r.status == 400 {
		return nil, ErrCorrupt // wrong context (aad) or tampered ciphertext
	}
	if r.status != 200 {
		return nil, statusErr("transit decrypt", r)
	}
	var v struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if json.Unmarshal(r.body, &v) != nil {
		return nil, ErrCorrupt
	}
	p, err := base64.StdEncoding.DecodeString(v.Data.Plaintext)
	if err != nil {
		return nil, ErrCorrupt
	}
	return p, nil
}

// Reseal re-encrypts a sealed value under the newest Transit key version
// (also converts a legacy local-provider value when Legacy is set).
func (o *OpenBao) Reseal(ctx context.Context, sealed, aad string) (string, error) {
	p, err := o.Open(ctx, sealed, aad)
	if err != nil {
		return "", err
	}
	return o.Seal(ctx, p, aad)
}

// Ping checks reachability, unseal state and our AppRole login.
func (o *OpenBao) Ping(ctx context.Context) error {
	if !o.configured() {
		return ErrNotConfigured
	}
	r, err := o.do(ctx, http.MethodGet, "sys/health", nil, false)
	if err != nil {
		return err
	}
	if r.status != 200 && r.status != 429 && r.status != 473 {
		return fmt.Errorf("%w: health http %d (sealed or uninitialised)", ErrUnavailable, r.status)
	}
	_, err = o.ensureToken(ctx)
	return err
}

func (o *OpenBao) Status() map[string]any {
	if !o.configured() {
		return map[string]any{"provider": "openbao", "status": "not_configured", "reason": "OpenBao config file missing or invalid"}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	st := map[string]any{"provider": "openbao", "addr": o.Addr, "kv_mount": o.cfg.KVMount, "prefix": o.cfg.Prefix,
		"transit": o.cfg.TransitKey != "", "status": "ok", "authenticated": o.token != ""}
	if o.lastErr != "" {
		st["last_error"] = o.lastErr
	}
	if !o.tokenExp.IsZero() {
		st["token_expires_at"] = o.tokenExp.Unix()
	}
	return st
}

var _ SecretStore = (*OpenBao)(nil)
