// SPDX-License-Identifier: Apache-2.0

package agent

// v1.1 tenant tools: visitor statistics, Leech Protection scan, email
// routing, CalDAV/CardDAV logins (Radicale), GnuPG keys and SSH keys.
// Every method names its account (accountField) and checks that the domain
// or mailbox belongs to it; files below the home are handled through an
// os.Root that refuses symlinked components, and gpg runs as the account.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/logstat"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

var (
	// DavDir holds one JSON file of DAV logins per account; DavUsersFile is the
	// Radicale htpasswd file rendered from them.
	DavDir       = "/var/lib/bpanel/dav"
	DavUsersFile = "/etc/radicale/bpanel-users"
	DavConfig    = "/etc/radicale/config"
	// gpgBin / v11Have are variables for tests.
	gpgBin  = "gpg"
	v11Have = have

	reBcryptHash = regexp.MustCompile(`^\$2[aby]\$(0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}$`)
	reFpr        = regexp.MustCompile(`^[A-F0-9]{40}$|^[A-F0-9]{64}$`)
	reKeyName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	reGPGName    = regexp.MustCompile(`^[\p{L}\p{N} .,'_-]{1,64}$`)
)

func init() {
	for _, m := range []string{rpc.MLogStats, rpc.MWebxLeechScan, rpc.MMailRoutingSet, rpc.MDavSync, rpc.MGPGList, rpc.MGPGGenerate,
		rpc.MGPGImport, rpc.MGPGDelete, rpc.MGPGExport, rpc.MSSHKeyList, rpc.MSSHKeyImport, rpc.MSSHKeyGenerate, rpc.MSSHKeyAuthorize,
		rpc.MSSHKeyDelete} {
		accountField[m] = struct {
			key      string
			optional bool
		}{"user", false}
	}
}

func (a *Agent) v11UserRoutes() map[string]handler {
	return map[string]handler{
		rpc.MLogStats: bind(a.logStats), rpc.MWebxLeechScan: bind(a.leechScan), rpc.MMailRoutingSet: bind(a.mailRoutingSet),
		rpc.MDavSync: bind(a.davSync), rpc.MGPGList: bind(a.gpgList), rpc.MGPGGenerate: bind(a.gpgGenerate),
		rpc.MGPGImport: bind(a.gpgImport), rpc.MGPGDelete: bind(a.gpgDelete), rpc.MGPGExport: bind(a.gpgExport),
		rpc.MSSHKeyList: bind(a.sshKeyList), rpc.MSSHKeyImport: bind(a.sshKeyImport), rpc.MSSHKeyGenerate: bind(a.sshKeyGenerate),
		rpc.MSSHKeyAuthorize: bind(a.sshKeyAuthorize), rpc.MSSHKeyDelete: bind(a.sshKeyDelete),
	}
}

// ---- statistics ---------------------------------------------------------------

// ownsNoClaim is mustOwn for read-only methods: it never adopts an
// unregistered name, it only accepts the registered or vhost-inferred owner.
func (a *Agent) ownsNoClaim(kind, name, owner string) error {
	e, ok, err := a.readOwner(kind, name)
	if err != nil {
		return err
	}
	if ok && e.Owner == owner || !ok && owner != "" && a.inferOwner(name) == owner {
		return nil
	}
	return errf("owned_by_another_account", "%s is not served for this account", normName(name))
}

// openDomlogTail opens the access log of an own domain positioned at most
// max bytes before its end (at a line start).
func (a *Agent) openDomlogTail(user, domain string, max int64) (io.ReadCloser, bool, error) {
	d := strings.ToLower(domain)
	if validate.Domain(d) != nil || strings.ContainsAny(d, "/\\") {
		return nil, false, errf("invalid_domain", "%s", domain)
	}
	if err := a.ownsNoClaim(kindWeb, d, user); err != nil {
		return nil, false, err
	}
	f, err := os.OpenFile(filepath.Join(a.domlogDir, d+".access.log"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false, nil
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, false, nil
	}
	trunc := false
	if st.Size() > max {
		trunc = true
		if _, err := f.Seek(st.Size()-max, io.SeekStart); err != nil {
			f.Close()
			return nil, false, nil
		}
		// skip the partial first line
		var b [1]byte
		for {
			if n, err := f.Read(b[:]); n == 0 || err != nil || b[0] == '\n' {
				break
			}
		}
	}
	return f, trunc, nil
}

func (a *Agent) logStats(ctx context.Context, p rpc.LogStatsParams) (rpc.LogStatsResult, error) {
	max := p.MaxBytes
	if max <= 0 || max > 256<<20 {
		max = 32 << 20
	}
	f, trunc, err := a.openDomlogTail(p.User, p.Domain, max)
	if err != nil {
		return rpc.LogStatsResult{}, err
	}
	if f == nil {
		return rpc.LogStatsResult{Status: "no_log", Reason: "no access log yet for this domain", Days: []rpc.LogDay{}}, nil
	}
	defer f.Close()
	s := logstat.NewStats(strings.ToLower(p.Domain))
	s.Feed(io.LimitReader(f, max))
	res := s.Result()
	res.Truncated = trunc
	return res, nil
}

func (a *Agent) leechScan(ctx context.Context, p rpc.LeechScanParams) (rpc.LeechScanResult, error) {
	if len(p.Paths) == 0 || len(p.Paths) > 50 {
		return rpc.LeechScanResult{}, errf("bad_params", "1 to 50 paths")
	}
	for _, x := range p.Paths {
		if !strings.HasPrefix(x, "/") || !strings.HasSuffix(x, "/") || len(x) > 256 || strings.Contains(x, "..") {
			return rpc.LeechScanResult{}, errf("bad_params", "invalid path")
		}
	}
	if p.Window <= 0 || p.Window > 7*86400 {
		p.Window = 7200
	}
	f, _, err := a.openDomlogTail(p.User, p.Domain, 64<<20)
	if err != nil {
		return rpc.LeechScanResult{}, err
	}
	if f == nil {
		return rpc.LeechScanResult{Status: "no_log", Hits: []rpc.LeechHit{}}, nil
	}
	defer f.Close()
	return rpc.LeechScanResult{Status: "ok", Hits: logstat.Leech(f, p.Paths, time.Now().Add(-time.Duration(p.Window)*time.Second))}, nil
}

// ---- email routing ------------------------------------------------------------

func (a *Agent) routingFile() string { return filepath.Join(a.postfixDir(), "routing") }

// routingLines renders the transport entries of the remote/backup domains
// (appended to the managed transport map by writeTransport).
func (a *Agent) routingLines() string {
	m, _ := readMap(a.routingFile(), " ")
	var b strings.Builder
	for _, kv := range m {
		if validate.Domain(kv[0]) == nil && (kv[1] == "remote" || kv[1] == "backup") {
			// smtp: with no nexthop = deliver to the domain's MX hosts
			b.WriteString(kv[0] + " smtp:\n")
		}
	}
	return b.String()
}

func (a *Agent) mailRoutingSet(ctx context.Context, p rpc.MailRoutingParams) (rpc.MailRoutingResult, error) {
	d := strings.ToLower(p.Domain)
	if validate.Domain(d) != nil {
		return rpc.MailRoutingResult{}, errf("invalid_domain", "%s", p.Domain)
	}
	if p.Mode != "local" && p.Mode != "remote" && p.Mode != "backup" {
		return rpc.MailRoutingResult{}, errf("bad_params", "mode must be local, remote or backup")
	}
	if err := a.mustOwn(kindMail, d, p.User); err != nil {
		return rpc.MailRoutingResult{}, err
	}
	defer a.lock("mail")()
	path := a.routingFile()
	old, oldErr := os.ReadFile(path)
	fn := remove(func(k string) bool { return k == d })
	if p.Mode != "local" {
		fn = upsert(d, p.Mode)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return rpc.MailRoutingResult{}, errf("action_failed", "routing dir")
	}
	if err := editMap(path, " ", 0o644, fn); err != nil {
		return rpc.MailRoutingResult{}, errf("action_failed", "write routing")
	}
	if !dnsxHave("postmap") {
		return rpc.MailRoutingResult{Status: "not_installed", Reason: "Postfix is not installed; the routing is saved and applied once it is"}, nil
	}
	if err := a.writeTransport(ctx); err != nil {
		if oldErr == nil {
			_ = os.WriteFile(path, old, 0o644)
		} else {
			_ = os.Remove(path)
		}
		return rpc.MailRoutingResult{}, err
	}
	return rpc.MailRoutingResult{Status: "applied"}, nil
}

// ---- CalDAV / CardDAV (Radicale) -------------------------------------------------

func davMissing() string {
	if !v11Have("radicale") && !regularFile("/usr/bin/radicale") {
		return "Radicale is not installed (apt install radicale python3-bcrypt; RHEL: pip install radicale bcrypt)"
	}
	return ""
}

// renderDavUsers rebuilds the Radicale htpasswd file from every account's logins.
func renderDavUsers() ([]byte, int, error) {
	ents, err := os.ReadDir(DavDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, 0, err
	}
	var lines []string
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(DavDir, e.Name()))
		if err != nil {
			continue
		}
		var ls []rpc.DavLogin
		if json.Unmarshal(b, &ls) != nil {
			continue
		}
		for _, l := range ls {
			if davLoginOK(l) {
				lines = append(lines, l.Name+":"+l.Hash)
			}
		}
	}
	sort.Strings(lines)
	out := "# Managed by BOZKURT PANEL — CalDAV/CardDAV logins.\n"
	if len(lines) > 0 {
		out = strings.Join(lines, "\n") + "\n"
	}
	return []byte(out), len(lines), nil
}

func davLoginOK(l rpc.DavLogin) bool {
	_, dom, err := splitEmail(l.Name)
	return err == nil && strings.ToLower(l.Name) == l.Name && dom != "" && reBcryptHash.MatchString(l.Hash) && !strings.ContainsAny(l.Name, ":\n")
}

// DavConfigText is the Radicale configuration the panel installs.
const DavConfigText = `# Managed by BOZKURT PANEL — Radicale (CalDAV/CardDAV) behind the panel's /dav/ proxy.
[server]
hosts = 127.0.0.1:5232

[auth]
type = htpasswd
htpasswd_filename = /etc/radicale/bpanel-users
htpasswd_encryption = bcrypt
delay = 1

[rights]
type = owner_only

[storage]
filesystem_folder = /var/lib/radicale/collections

[web]
type = internal
`

func (a *Agent) davSync(ctx context.Context, p rpc.DavSyncParams) (rpc.DavStatusResult, error) {
	if len(p.Logins) > 1000 {
		return rpc.DavStatusResult{}, errf("bad_params", "too many logins")
	}
	for _, l := range p.Logins {
		if !davLoginOK(l) {
			return rpc.DavStatusResult{}, errf("bad_params", "invalid login %q", l.Name)
		}
		_, dom, _ := splitEmail(l.Name)
		if err := a.mustOwn(kindMail, dom, p.User); err != nil {
			return rpc.DavStatusResult{}, err
		}
	}
	defer a.lock("dav")()
	if err := os.MkdirAll(DavDir, 0o700); err != nil {
		return rpc.DavStatusResult{}, errf("action_failed", "dav dir")
	}
	own := filepath.Join(DavDir, p.User+".json")
	if len(p.Logins) == 0 {
		_ = os.Remove(own)
	} else if err := writeAtomic(own, mustJSONBytes(p.Logins), 0o600, -1, -1); err != nil {
		return rpc.DavStatusResult{}, errf("action_failed", "write dav logins")
	}
	return a.davRender(ctx)
}

func mustJSONBytes(v any) []byte { b, _ := json.Marshal(v); return b }

func (a *Agent) davRender(ctx context.Context) (rpc.DavStatusResult, error) {
	data, n, err := renderDavUsers()
	if err != nil {
		return rpc.DavStatusResult{}, errf("action_failed", "read dav logins")
	}
	if why := davMissing(); why != "" {
		return rpc.DavStatusResult{Status: "not_installed", Reason: why, Users: n}, nil
	}
	gid := 0
	if g, err := groupID("radicale"); err == nil {
		gid = g
	}
	uid := 0
	if os.Geteuid() != 0 {
		uid, gid = -1, -1
	}
	if err := writeAtomic(DavUsersFile, data, 0o640, uid, gid); err != nil {
		return rpc.DavStatusResult{}, errf("action_failed", "write %s", DavUsersFile)
	}
	if cur, err := os.ReadFile(DavConfig); err != nil || !bytes.Contains(cur, []byte("BOZKURT PANEL")) {
		if err := writeAtomic(DavConfig, []byte(DavConfigText), 0o644, -1, -1); err != nil {
			return rpc.DavStatusResult{}, errf("action_failed", "write %s", DavConfig)
		}
		if !a.Cfg.NoSystemd {
			_ = a.systemctl(ctx, "enable", "radicale")
			_ = a.systemctl(ctx, "restart", "radicale")
		}
	}
	return a.davStatusNow(ctx, n), nil
}

func (a *Agent) davStatusNow(ctx context.Context, n int) rpc.DavStatusResult {
	if why := davMissing(); why != "" {
		return rpc.DavStatusResult{Status: "not_installed", Reason: why, Users: n}
	}
	if a.Cfg.NoSystemd {
		return rpc.DavStatusResult{Status: "active", Users: n}
	}
	out, _ := run(ctx, nil, "systemctl", "is-active", "radicale")
	if strings.TrimSpace(out) == "active" {
		return rpc.DavStatusResult{Status: "active", Users: n}
	}
	return rpc.DavStatusResult{Status: "inactive", Reason: "radicale.service is " + strings.TrimSpace(out), Users: n}
}

func (a *Agent) davStatus(ctx context.Context, _ struct{}) (rpc.DavStatusResult, error) {
	_, n, _ := renderDavUsers()
	return a.davStatusNow(ctx, n), nil
}

// ---- GnuPG (runs as the account, keyring ~/.gnupg) ------------------------------

func (a *Agent) gpgRun(ctx context.Context, user string, stdin []byte, args ...string) (string, error) {
	e, err := a.home(user)
	if err != nil {
		return "", err
	}
	if !v11Have(gpgBin) {
		return "", errf("not_installed", "gpg (GnuPG) is not installed")
	}
	root, err := openHome(e)
	if err != nil {
		return "", err
	}
	if err := mkdirOwned(root, ".gnupg", 0o700, e.uid, e.gid, false); err != nil {
		root.Close()
		return "", err
	}
	root.Close()
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	argv := append([]string{gpgBin, "--homedir", filepath.Join(e.home, ".gnupg"), "--batch", "--no-tty", "--yes"}, args...)
	cmd := userCmd(cctx, e, argv...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	if v11Have("gpgconf") { // do not leave a gpg-agent running as the tenant
		k := userCmd(context.Background(), e, "gpgconf", "--homedir", filepath.Join(e.home, ".gnupg"), "--kill", "gpg-agent")
		_ = k.Run()
	}
	if err != nil {
		return out.String(), errf("gpg_failed", "%s", strings.TrimSpace(lastLines(errb.String(), 4)))
	}
	return out.String(), nil
}

// ParseGPGColons parses `gpg --with-colons --list-keys` output.
func ParseGPGColons(out string, secret bool) []rpc.GPGKey {
	var keys []rpc.GPGKey
	var cur *rpc.GPGKey
	algos := map[string]string{"1": "RSA", "16": "ElGamal", "17": "DSA", "18": "ECDH", "19": "ECDSA", "22": "EdDSA"}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Split(l, ":")
		if len(f) < 10 {
			continue
		}
		switch f[0] {
		case "pub", "sec":
			keys = append(keys, rpc.GPGKey{KeyID: f[4], Algo: algos[f[3]], UIDs: []string{}, Secret: secret})
			cur = &keys[len(keys)-1]
			cur.Bits, _ = strconv.Atoi(f[2])
			cur.Created, _ = strconv.ParseInt(f[5], 10, 64)
			cur.Expires, _ = strconv.ParseInt(f[6], 10, 64)
		case "fpr":
			if cur != nil && cur.Fingerprint == "" {
				cur.Fingerprint = f[9]
			}
		case "uid":
			if cur != nil {
				cur.UIDs = append(cur.UIDs, strings.ReplaceAll(f[9], `\x3a`, ":"))
			}
		case "sub", "ssb":
			cur = nil // the fingerprints after a subkey belong to it
		}
	}
	return keys
}

func (a *Agent) gpgList(ctx context.Context, p rpc.GPGListParams) (rpc.GPGListResult, error) {
	if !v11Have(gpgBin) {
		return rpc.GPGListResult{Status: "not_installed", Reason: "gpg (GnuPG) is not installed", Keys: []rpc.GPGKey{}}, nil
	}
	pub, err := a.gpgRun(ctx, p.User, nil, "--with-colons", "--fixed-list-mode", "--list-keys")
	if err != nil {
		return rpc.GPGListResult{}, err
	}
	sec, _ := a.gpgRun(ctx, p.User, nil, "--with-colons", "--fixed-list-mode", "--list-secret-keys")
	secret := map[string]bool{}
	for _, k := range ParseGPGColons(sec, true) {
		secret[k.Fingerprint] = true
	}
	keys := ParseGPGColons(pub, false)
	for i := range keys {
		keys[i].Secret = secret[keys[i].Fingerprint]
	}
	if keys == nil {
		keys = []rpc.GPGKey{}
	}
	return rpc.GPGListResult{Status: "ok", Keys: keys}, nil
}

func (a *Agent) gpgGenerate(ctx context.Context, p rpc.GPGGenerateParams) (rpc.GPGOutput, error) {
	if !reGPGName.MatchString(p.Name) || (p.Comment != "" && !reGPGName.MatchString(p.Comment)) {
		return rpc.GPGOutput{}, errf("bad_params", "invalid name or comment")
	}
	if _, _, err := splitEmail(p.Email); err != nil {
		return rpc.GPGOutput{}, err
	}
	algo := map[string]string{"ed25519": "ed25519", "rsa3072": "rsa3072", "rsa4096": "rsa4096", "": "ed25519"}[p.Algo]
	exp := map[string]string{"0": "never", "1y": "1y", "2y": "2y", "5y": "5y", "": "2y"}[p.Expire]
	if algo == "" || exp == "" {
		return rpc.GPGOutput{}, errf("bad_params", "unsupported algorithm or expiry")
	}
	if len(p.Passphrase) > 256 || strings.ContainsAny(p.Passphrase, "\r\n\x00") {
		return rpc.GPGOutput{}, errf("bad_params", "invalid passphrase")
	}
	uid := p.Name
	if p.Comment != "" {
		uid += " (" + p.Comment + ")"
	}
	uid += " <" + strings.ToLower(p.Email) + ">"
	args := []string{"--pinentry-mode", "loopback", "--passphrase-fd", "0", "--quick-gen-key", uid, algo, "default", exp}
	out, err := a.gpgRun(ctx, p.User, []byte(p.Passphrase+"\n"), args...)
	if err != nil {
		return rpc.GPGOutput{}, err
	}
	return rpc.GPGOutput{Status: "ok", Output: tail(out)}, nil
}

func (a *Agent) gpgImport(ctx context.Context, p rpc.GPGImportParams) (rpc.GPGOutput, error) {
	if len(p.Armored) > 256<<10 || !strings.Contains(p.Armored, "-----BEGIN PGP ") {
		return rpc.GPGOutput{}, errf("bad_params", "paste an ASCII-armored PGP key")
	}
	if _, err := a.gpgRun(ctx, p.User, []byte(p.Armored), "--import"); err != nil {
		return rpc.GPGOutput{}, err
	}
	return rpc.GPGOutput{Status: "ok"}, nil
}

func (a *Agent) gpgDelete(ctx context.Context, p rpc.GPGKeyRef) (rpc.GPGOutput, error) {
	if !reFpr.MatchString(p.Fingerprint) {
		return rpc.GPGOutput{}, errf("bad_params", "invalid fingerprint")
	}
	if _, err := a.gpgRun(ctx, p.User, nil, "--delete-secret-and-public-key", p.Fingerprint); err != nil {
		// a public-only key has no secret part: retry as public
		if _, err2 := a.gpgRun(ctx, p.User, nil, "--delete-keys", p.Fingerprint); err2 != nil {
			return rpc.GPGOutput{}, err
		}
	}
	return rpc.GPGOutput{Status: "ok"}, nil
}

func (a *Agent) gpgExport(ctx context.Context, p rpc.GPGKeyRef) (rpc.GPGOutput, error) {
	if !reFpr.MatchString(p.Fingerprint) {
		return rpc.GPGOutput{}, errf("bad_params", "invalid fingerprint")
	}
	out, err := a.gpgRun(ctx, p.User, nil, "--armor", "--export", p.Fingerprint)
	if err != nil {
		return rpc.GPGOutput{}, err
	}
	if !strings.Contains(out, "BEGIN PGP PUBLIC KEY BLOCK") {
		return rpc.GPGOutput{}, errf("not_found", "%s", p.Fingerprint)
	}
	return rpc.GPGOutput{Status: "ok", Armored: out}, nil
}

// ---- SSH keys (files below ~/.ssh, written as root through an os.Root) --------------

const sshAuth = ".ssh/authorized_keys"

func sshParse(pub string) (ssh.PublicKey, string, error) {
	k, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(pub)))
	if err != nil {
		return nil, "", errf("ssh_invalid_key", "not a valid OpenSSH public key")
	}
	switch k.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoRSA, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256:
	default:
		return nil, "", errf("ssh_invalid_key", "unsupported key type %s", k.Type())
	}
	if k.Type() == ssh.KeyAlgoRSA {
		if ck, ok := k.(ssh.CryptoPublicKey); ok {
			if rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok && rk.N.BitLen() < 2048 {
				return nil, "", errf("ssh_invalid_key", "RSA keys need at least 2048 bits")
			}
		}
	}
	return k, comment, nil
}

func keyBits(k ssh.PublicKey) int {
	if ck, ok := k.(ssh.CryptoPublicKey); ok {
		if rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok {
			return rk.N.BitLen()
		}
	}
	return 0
}

// sshHome opens the account home and makes sure ~/.ssh exists (0700, owned).
func (a *Agent) sshHome(user string) (passwdEntry, *os.Root, error) {
	e, err := a.home(user)
	if err != nil {
		return e, nil, err
	}
	root, err := openHome(e)
	if err != nil {
		return e, nil, err
	}
	if err := mkdirOwned(root, ".ssh", 0o700, e.uid, e.gid, false); err != nil {
		root.Close()
		return e, nil, err
	}
	return e, root, nil
}

func readSmall(root *os.Root, rel string) ([]byte, error) {
	if err := checkNoSymlinks(root, rel); err != nil {
		return nil, err
	}
	f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, errf("invalid_path", "%s is not a regular file", rel)
	}
	return io.ReadAll(io.LimitReader(f, 1<<20))
}

// replaceOwned atomically replaces rel with data (tmp + rename, owned by the account).
func replaceOwned(root *os.Root, rel string, data []byte, mode os.FileMode, uid, gid int) error {
	tmp := filepath.Join(filepath.Dir(rel), ".bpanel-"+filepath.Base(rel)+".tmp")
	_ = root.Remove(tmp)
	if err := createFileOwned(root, tmp, data, mode, uid, gid); err != nil {
		return err
	}
	if err := root.Rename(tmp, rel); err != nil {
		_ = root.Remove(tmp)
		return mapFSErr(err, rel)
	}
	return nil
}

func authorizedBlobs(root *os.Root) (map[string]bool, []string) {
	b, _ := readSmall(root, sshAuth)
	blobs := map[string]bool{}
	lines := strings.Split(string(b), "\n")
	for _, l := range lines {
		if k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l)); err == nil {
			blobs[string(k.Marshal())] = true
		}
	}
	return blobs, lines
}

func (a *Agent) sshKeyList(ctx context.Context, p rpc.SSHKeyListParams) (rpc.SSHKeyListResult, error) {
	_, root, err := a.sshHome(p.User)
	if err != nil {
		return rpc.SSHKeyListResult{}, err
	}
	defer root.Close()
	blobs, lines := authorizedBlobs(root)
	out := []rpc.SSHKey{}
	named := map[string]bool{}
	ents, _ := fs.ReadDir(root.FS(), ".ssh")
	for _, en := range ents {
		n := en.Name()
		if !strings.HasSuffix(n, ".pub") || !en.Type().IsRegular() || !reKeyName.MatchString(strings.TrimSuffix(n, ".pub")) {
			continue
		}
		b, err := readSmall(root, ".ssh/"+n)
		if err != nil {
			continue
		}
		k, comment, err := sshParse(string(b))
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(n, ".pub")
		_, perr := root.Lstat(".ssh/" + name)
		named[string(k.Marshal())] = true
		out = append(out, rpc.SSHKey{Name: name, Type: k.Type(), Bits: keyBits(k), Fingerprint: ssh.FingerprintSHA256(k), Comment: comment,
			Authorized: blobs[string(k.Marshal())], HasPrivate: perr == nil, PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))})
	}
	// authorized keys without a .pub file (added by hand)
	for i, l := range lines {
		k, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err != nil || named[string(k.Marshal())] {
			continue
		}
		named[string(k.Marshal())] = true
		out = append(out, rpc.SSHKey{Name: fmt.Sprintf("authorized_keys:%d", i+1), Type: k.Type(), Bits: keyBits(k), Fingerprint: ssh.FingerprintSHA256(k),
			Comment: comment, Authorized: true, PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return rpc.SSHKeyListResult{Keys: out}, nil
}

func (a *Agent) setAuthorized(root *os.Root, e passwdEntry, k ssh.PublicKey, comment string, on bool) error {
	blobs, lines := authorizedBlobs(root)
	if blobs[string(k.Marshal())] == on {
		return nil
	}
	var keep []string
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if kk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l)); err == nil && bytes.Equal(kk.Marshal(), k.Marshal()) {
			continue
		}
		keep = append(keep, l)
	}
	if on {
		line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
		if comment != "" {
			line += " " + comment
		}
		keep = append(keep, line)
	}
	data := ""
	if len(keep) > 0 {
		data = strings.Join(keep, "\n") + "\n"
	}
	return replaceOwned(root, sshAuth, []byte(data), 0o600, e.uid, e.gid)
}

func cleanComment(c string) string {
	c = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, c)
	if len(c) > 100 {
		c = c[:100]
	}
	return strings.TrimSpace(c)
}

func (a *Agent) sshKeyImport(ctx context.Context, p rpc.SSHKeyImportParams) (rpc.SSHKey, error) {
	if !reKeyName.MatchString(p.Name) || p.Name == "authorized_keys" || p.Name == "known_hosts" || p.Name == "config" {
		return rpc.SSHKey{}, errf("ssh_invalid_name", "invalid key name")
	}
	k, comment, err := sshParse(p.PublicKey)
	if err != nil {
		return rpc.SSHKey{}, err
	}
	comment = cleanComment(comment)
	if p.PrivateKey != "" {
		if len(p.PrivateKey) > 64<<10 || !strings.Contains(p.PrivateKey, "PRIVATE KEY-----") {
			return rpc.SSHKey{}, errf("ssh_invalid_key", "invalid private key")
		}
		if sk, err := ssh.ParsePrivateKey([]byte(p.PrivateKey)); err == nil && !bytes.Equal(sk.PublicKey().Marshal(), k.Marshal()) {
			return rpc.SSHKey{}, errf("ssh_invalid_key", "the private key does not match the public key")
		}
	}
	e, root, err := a.sshHome(p.User)
	if err != nil {
		return rpc.SSHKey{}, err
	}
	defer root.Close()
	defer a.lock("ssh-" + p.User)()
	if _, err := root.Lstat(".ssh/" + p.Name + ".pub"); err == nil {
		return rpc.SSHKey{}, errf("ssh_key_exists", "%s already exists", p.Name)
	}
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
	if comment != "" {
		pub += " " + comment
	}
	if err := createFileOwned(root, ".ssh/"+p.Name+".pub", []byte(pub+"\n"), 0o644, e.uid, e.gid); err != nil {
		return rpc.SSHKey{}, err
	}
	if p.PrivateKey != "" {
		if err := createFileOwned(root, ".ssh/"+p.Name, []byte(strings.TrimSpace(p.PrivateKey)+"\n"), 0o600, e.uid, e.gid); err != nil {
			_ = root.Remove(".ssh/" + p.Name + ".pub")
			return rpc.SSHKey{}, err
		}
	}
	if p.Authorize {
		if err := a.setAuthorized(root, e, k, comment, true); err != nil {
			return rpc.SSHKey{}, err
		}
	}
	return rpc.SSHKey{Name: p.Name, Type: k.Type(), Bits: keyBits(k), Fingerprint: ssh.FingerprintSHA256(k), Comment: comment,
		Authorized: p.Authorize, HasPrivate: p.PrivateKey != "", PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))}, nil
}

func (a *Agent) sshKeyGenerate(ctx context.Context, p rpc.SSHKeyGenerateParams) (rpc.SSHKeyGenerateResult, error) {
	if len(p.Passphrase) > 256 {
		return rpc.SSHKeyGenerateResult{}, errf("bad_params", "passphrase too long")
	}
	var signer any
	switch p.Type {
	case "", "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return rpc.SSHKeyGenerateResult{}, err
		}
		signer = priv
	case "rsa":
		bits := p.Bits
		if bits == 0 {
			bits = 4096
		}
		if bits != 2048 && bits != 3072 && bits != 4096 {
			return rpc.SSHKeyGenerateResult{}, errf("bad_params", "RSA size must be 2048, 3072 or 4096")
		}
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return rpc.SSHKeyGenerateResult{}, err
		}
		signer = k
	default:
		return rpc.SSHKeyGenerateResult{}, errf("bad_params", "type must be ed25519 or rsa")
	}
	comment := p.User + "@bpanel"
	var blk *pem.Block
	var err error
	if p.Passphrase != "" {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(signer, comment, []byte(p.Passphrase))
	} else {
		blk, err = ssh.MarshalPrivateKey(signer, comment)
	}
	if err != nil {
		return rpc.SSHKeyGenerateResult{}, err
	}
	s, err := ssh.NewSignerFromKey(signer)
	if err != nil {
		return rpc.SSHKeyGenerateResult{}, err
	}
	privPEM := string(pem.EncodeToMemory(blk))
	key, err := a.sshKeyImport(ctx, rpc.SSHKeyImportParams{User: p.User, Name: p.Name, Authorize: p.Authorize,
		PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))) + " " + comment, PrivateKey: privPEM})
	if err != nil {
		return rpc.SSHKeyGenerateResult{}, err
	}
	return rpc.SSHKeyGenerateResult{Key: key, PrivateKey: privPEM}, nil
}

// sshNamed loads the public key of a named key ("authorized_keys:N" = a line).
func sshNamed(root *os.Root, name string) (ssh.PublicKey, string, bool, error) {
	if strings.HasPrefix(name, "authorized_keys:") {
		n, err := strconv.Atoi(strings.TrimPrefix(name, "authorized_keys:"))
		_, lines := authorizedBlobs(root)
		if err != nil || n < 1 || n > len(lines) {
			return nil, "", false, errf("not_found", "%s", name)
		}
		k, c, _, _, err := ssh.ParseAuthorizedKey([]byte(lines[n-1]))
		if err != nil {
			return nil, "", false, errf("not_found", "%s", name)
		}
		return k, c, true, nil
	}
	if !reKeyName.MatchString(name) {
		return nil, "", false, errf("ssh_invalid_name", "invalid key name")
	}
	b, err := readSmall(root, ".ssh/"+name+".pub")
	if err != nil {
		return nil, "", false, errf("not_found", "%s", name)
	}
	k, c, err := sshParse(string(b))
	return k, c, false, err
}

func (a *Agent) sshKeyAuthorize(ctx context.Context, p rpc.SSHKeyRef) (rpc.Empty, error) {
	e, root, err := a.sshHome(p.User)
	if err != nil {
		return rpc.Empty{}, err
	}
	defer root.Close()
	defer a.lock("ssh-" + p.User)()
	k, c, _, err := sshNamed(root, p.Name)
	if err != nil {
		return rpc.Empty{}, err
	}
	return rpc.Empty{}, a.setAuthorized(root, e, k, cleanComment(c), p.Authorize)
}

func (a *Agent) sshKeyDelete(ctx context.Context, p rpc.SSHKeyRef) (rpc.Empty, error) {
	e, root, err := a.sshHome(p.User)
	if err != nil {
		return rpc.Empty{}, err
	}
	defer root.Close()
	defer a.lock("ssh-" + p.User)()
	k, c, line, err := sshNamed(root, p.Name)
	if err != nil {
		return rpc.Empty{}, err
	}
	if err := a.setAuthorized(root, e, k, c, false); err != nil {
		return rpc.Empty{}, err
	}
	if !line {
		_ = root.Remove(".ssh/" + p.Name + ".pub")
		_ = root.Remove(".ssh/" + p.Name)
	}
	return rpc.Empty{}, nil
}
