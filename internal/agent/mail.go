package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/distro"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// Mail layout (Postfix virtual domains -> LMTP -> Dovecot, Rspamd milter signs DKIM):
//   /etc/postfix/bpanel/vdomains   domain -> OK
//   /etc/postfix/bpanel/vmailbox   address -> domain/local/
//   /etc/postfix/bpanel/valias     address -> dest1,dest2  ("@domain" = catch-all)
//   /etc/dovecot/bpanel/passwd     address:{SSHA512}..:uid:gid::home::userdb_quota_rule=*:storage=NM
//   /var/lib/rspamd/dkim/<domain>.bpanel.key
// Mailboxes are Maildir under /home/<user>/mail/<domain>/<local>/ (same as the classic layout).

const DKIMSelector = "bpanel"

// DKIMDir holds the per-domain DKIM keys (a variable for tests).
var DKIMDir = "/var/lib/rspamd/dkim"

func (a *Agent) postfixDir() string    { return filepath.Join(a.L.PostfixDir, "bpanel") }
func (a *Agent) dovecotPasswd() string { return filepath.Join(a.L.DovecotDir, "bpanel", "passwd") }

func (a *Agent) mapType() string {
	if a.L.Family == distro.RHEL {
		return "lmdb"
	}
	return "hash"
}

// readMap reads a "key value" file preserving order.
func readMap(path, sep string) ([][2]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out [][2]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, _ := strings.Cut(line, sep)
		out = append(out, [2]string{k, v})
	}
	return out, sc.Err()
}

func writeMap(path, sep string, m [][2]string, mode os.FileMode) error {
	sort.SliceStable(m, func(i, j int) bool { return m[i][0] < m[j][0] })
	var b strings.Builder
	b.WriteString("# Managed by BOZKURT PANEL — changes are overwritten.\n")
	for _, kv := range m {
		b.WriteString(kv[0] + sep + kv[1] + "\n")
	}
	return writeAtomic(path, []byte(b.String()), mode, -1, -1)
}

// editMap applies fn to the entries of a map file and rewrites it.
func editMap(path, sep string, mode os.FileMode, fn func([][2]string) [][2]string) error {
	m, err := readMap(path, sep)
	if err != nil {
		return err
	}
	return writeMap(path, sep, fn(m), mode)
}

func upsert(key, val string) func([][2]string) [][2]string {
	return func(m [][2]string) [][2]string {
		for i := range m {
			if m[i][0] == key {
				m[i][1] = val
				return m
			}
		}
		return append(m, [2]string{key, val})
	}
}

func remove(pred func(k string) bool) func([][2]string) [][2]string {
	return func(m [][2]string) [][2]string {
		out := m[:0]
		for _, kv := range m {
			if !pred(kv[0]) {
				out = append(out, kv)
			}
		}
		return out
	}
}

func (a *Agent) postmap(ctx context.Context, name string) error {
	p := filepath.Join(a.postfixDir(), name)
	if !have("postmap") {
		return nil
	}
	_, err := run(ctx, nil, "postmap", a.mapType()+":"+p)
	return err
}

func (a *Agent) reloadPostfix(ctx context.Context) error {
	return a.systemctl(ctx, "reload", "postfix")
}

func splitEmail(e string) (local, domain string, err error) {
	e = strings.ToLower(strings.TrimSpace(e))
	if err := validate.Email(e); err != nil {
		return "", "", errf("invalid_email", "%s", e)
	}
	i := strings.LastIndex(e, "@")
	return e[:i], e[i+1:], nil
}

// HashSSHA512 returns a Dovecot {SSHA512} hash (base64(sha512(pw+salt)+salt)).
func HashSSHA512(pw string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err) // crypto/rand never fails on Linux
	}
	h := sha512.Sum512(append([]byte(pw), salt...))
	return "{SSHA512}" + base64.StdEncoding.EncodeToString(append(h[:], salt...))
}

func (a *Agent) mailDomainEnable(ctx context.Context, p rpc.MailDomain) (rpc.MailDomainResult, error) {
	var res rpc.MailDomainResult
	if err := validate.Domain(p.Domain); err != nil {
		return res, errf("invalid_domain", "%s", p.Domain)
	}
	e, err := a.home(p.User)
	if err != nil {
		return res, err
	}
	if err := a.claim(kindMail, p.Domain, p.User, ""); err != nil { // CODE-27
		return res, err
	}
	defer a.lock("mail")()
	if err := editMap(filepath.Join(a.postfixDir(), "vdomains"), " ", 0o644, upsert(p.Domain, "OK")); err != nil {
		return res, err
	}
	if err := a.postmap(ctx, "vdomains"); err != nil {
		return res, err
	}
	root, err := openHome(e)
	if err != nil {
		return res, err
	}
	err = mkdirOwned(root, "mail/"+p.Domain, 0o750, e.uid, e.gid, false)
	root.Close()
	if err != nil {
		return res, err
	}
	pub, err := ensureDKIM(p.Domain)
	if err != nil {
		return res, err
	}
	res.DKIMSelector = DKIMSelector
	res.DKIMRecord = "v=DKIM1; k=rsa; p=" + pub
	return res, a.reloadPostfix(ctx)
}

// ensureDKIM creates (or reads) the domain's RSA-2048 key and returns the base64 public key.
func ensureDKIM(domain string) (string, error) {
	path := filepath.Join(DKIMDir, domain+"."+DKIMSelector+".key")
	var key *rsa.PrivateKey
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk != nil {
			if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
				key, _ = k.(*rsa.PrivateKey)
			} else if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
				key = k
			}
		}
	}
	if key == nil {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", err
		}
		key = k
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return "", err
		}
		pemb := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.MkdirAll(DKIMDir, 0o750); err != nil {
			return "", err
		}
		uid, gid := -1, -1
		for _, n := range []string{"_rspamd", "rspamd"} {
			if u, err := lookupUser(n); err == nil {
				uid, gid = u.uid, u.gid
				break
			}
		}
		if err := writeAtomic(path, pemb, 0o640, uid, gid); err != nil {
			return "", err
		}
		if uid >= 0 {
			if err := os.Chown(DKIMDir, uid, gid); err != nil {
				return "", err
			}
		}
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

func (a *Agent) mailDomainDisable(ctx context.Context, p rpc.MailDomain) (rpc.Empty, error) {
	if err := validate.Domain(p.Domain); err != nil {
		return rpc.Empty{}, errf("invalid_domain", "%s", p.Domain)
	}
	if err := a.mustOwn(kindMail, p.Domain, p.User); err != nil { // CODE-27
		return rpc.Empty{}, err
	}
	defer func() {
		if err := a.release(kindMail, p.Domain, p.User); err != nil {
			a.Log.Warn("owner registry: release", "name", p.Domain, "err", err)
		}
	}()
	defer a.lock("mail")()
	suffix := "@" + p.Domain
	inDomain := func(k string) bool { return strings.HasSuffix(k, suffix) || k == p.Domain }
	pd := a.postfixDir()
	for _, n := range []string{"vdomains", "vmailbox", "valias"} {
		if err := editMap(filepath.Join(pd, n), " ", 0o644, remove(inDomain)); err != nil {
			return rpc.Empty{}, err
		}
		if err := a.postmap(ctx, n); err != nil {
			return rpc.Empty{}, err
		}
	}
	if err := editMap(a.dovecotPasswd(), ":", 0o640, remove(inDomain)); err != nil {
		return rpc.Empty{}, err
	}
	a.fixDovecotPerms()
	if err := a.editReject(ctx, remove(inDomain)); err != nil {
		return rpc.Empty{}, err
	}
	if err := os.Remove(filepath.Join(DKIMDir, p.Domain+"."+DKIMSelector+".key")); err != nil && !os.IsNotExist(err) {
		a.Log.Warn("dkim key removal", "domain", p.Domain, "err", err)
	}
	if e, err := a.home(p.User); err == nil {
		root, err := openHome(e)
		if err != nil {
			return rpc.Empty{}, err
		}
		err = removeAllIn(root, "mail/"+p.Domain)
		root.Close()
		if err != nil {
			return rpc.Empty{}, err
		}
	}
	return rpc.Empty{}, a.reloadPostfix(ctx)
}

func (a *Agent) fixDovecotPerms() {
	if g, err := groupID("dovecot"); err == nil {
		if err := os.Chown(a.dovecotPasswd(), 0, g); err != nil {
			a.Log.Warn("dovecot passwd owner", "err", err)
		}
	}
}

func passwdLine(hash string, e passwdEntry, home string, quotaMB int64, v24 bool) string {
	return fmt.Sprintf("%s:%d:%d::%s::%s", hash, e.uid, e.gid, home, quotaKV(quotaMB, v24))
}

// quotaKV is the passwd-file extra field for a mailbox quota: Dovecot 2.3
// reads userdb_quota_rule=*:storage=<N>M, Dovecot 2.4 ignores that and needs
// userdb_quota_storage_size=<N>M (verified with doveadm quota get).
func quotaKV(quotaMB int64, v24 bool) string {
	if quotaMB <= 0 {
		return ""
	}
	if v24 {
		return fmt.Sprintf("userdb_quota_storage_size=%dM", quotaMB)
	}
	return fmt.Sprintf("userdb_quota_rule=*:storage=%dM", quotaMB)
}

// capabilitiesFile is written by the installer (internal/installer.CapabilitiesFile).
var capabilitiesFile = "/etc/bpanel/capabilities.json"

// dovecotV24 reports whether the installed Dovecot uses the 2.4 settings
// syntax: agent.json dovecot_syntax, else capabilities.json, else
// `dovecot --version`. The answer is cached for the agent's lifetime.
func (a *Agent) dovecotV24() bool {
	a.dovecotOnce.Do(func() {
		syn := a.Cfg.DovecotSyntax
		if syn == "" {
			if b, err := os.ReadFile(capabilitiesFile); err == nil {
				var c struct {
					DovecotSyntax string `json:"dovecot_syntax"`
				}
				if json.Unmarshal(b, &c) == nil {
					syn = c.DovecotSyntax
				}
			}
		}
		if syn == "" {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if out, err := exec.CommandContext(ctx, "dovecot", "--version").Output(); err == nil {
				syn = string(out)
			}
		}
		a.dovecot24 = dovecotIs24(syn)
	})
	return a.dovecot24
}

// dovecotIs24 accepts "2.4", "2.4.1 (abc)" and later 2.x/3.x versions.
func dovecotIs24(v string) bool {
	v = strings.TrimSpace(v)
	var maj, min int
	if _, err := fmt.Sscanf(v, "%d.%d", &maj, &min); err != nil {
		return false
	}
	return maj > 2 || (maj == 2 && min >= 4)
}

func (a *Agent) mailboxCreate(ctx context.Context, p rpc.Mailbox) (rpc.Empty, error) {
	local, domain, err := splitEmail(p.Email)
	if err != nil {
		return rpc.Empty{}, err
	}
	if err := validate.Password(p.Password); err != nil {
		return rpc.Empty{}, errf(err.Error(), "password")
	}
	e, err := a.home(p.User)
	if err != nil {
		return rpc.Empty{}, err
	}
	if err := a.mustOwn(kindMail, domain, p.User); err != nil { // CODE-27
		return rpc.Empty{}, err
	}
	defer a.lock("mail")()
	vd, _ := readMap(filepath.Join(a.postfixDir(), "vdomains"), " ")
	found := false
	for _, kv := range vd {
		found = found || kv[0] == domain
	}
	if !found {
		return rpc.Empty{}, errf("mail_domain_disabled", "%s", domain)
	}
	box := filepath.Join(e.home, "mail", domain, local)
	root, err := openHome(e)
	if err != nil {
		return rpc.Empty{}, err
	}
	defer root.Close()
	if err := mkdirOwned(root, "mail/"+domain, 0o750, e.uid, e.gid, false); err != nil {
		return rpc.Empty{}, err
	}
	// bpanel-home is Dovecot's home (the Maildir root must not be the home:
	// Maildir++ mistakes .dovecot.lda-dupes for a folder; see DovecotConf)
	for _, d := range []string{"", "/cur", "/new", "/tmp", "/" + DovecotHomeDir} {
		if err := mkdirOwned(root, "mail/"+domain+"/"+local+d, 0o700, e.uid, e.gid, false); err != nil {
			return rpc.Empty{}, err
		}
	}
	addr := local + "@" + domain
	if err := editMap(a.dovecotPasswd(), ":", 0o640, upsert(addr, passwdLine(HashMailPassword(p.Password), e, box, p.QuotaMB, a.dovecotV24()))); err != nil {
		return rpc.Empty{}, err
	}
	a.fixDovecotPerms()
	if err := editMap(filepath.Join(a.postfixDir(), "vmailbox"), " ", 0o644, upsert(addr, domain+"/"+local+"/")); err != nil {
		return rpc.Empty{}, err
	}
	if err := a.postmap(ctx, "vmailbox"); err != nil {
		return rpc.Empty{}, err
	}
	// identity alias: keeps local delivery working when the domain has a
	// catch-all forwarder (Postfix applies "@domain" to every address otherwise)
	if err := a.ensureIdentityAlias(ctx, addr); err != nil {
		return rpc.Empty{}, err
	}
	return rpc.Empty{}, nil
}

func (a *Agent) mailboxDelete(ctx context.Context, p rpc.MailboxRef) (rpc.Empty, error) {
	local, domain, err := splitEmail(p.Email)
	if err != nil {
		return rpc.Empty{}, err
	}
	addr := local + "@" + domain
	if err := a.mustOwn(kindMail, domain, p.User); err != nil { // CODE-27
		return rpc.Empty{}, err
	}
	e, herr := a.home(p.User)
	defer a.lock("mail")()
	is := func(k string) bool { return k == addr }
	if err := editMap(a.dovecotPasswd(), ":", 0o640, remove(is)); err != nil {
		return rpc.Empty{}, err
	}
	a.fixDovecotPerms()
	if err := editMap(filepath.Join(a.postfixDir(), "vmailbox"), " ", 0o644, remove(is)); err != nil {
		return rpc.Empty{}, err
	}
	if err := a.postmap(ctx, "vmailbox"); err != nil {
		return rpc.Empty{}, err
	}
	if err := a.dropIdentityAlias(ctx, addr); err != nil {
		return rpc.Empty{}, err
	}
	if herr == nil {
		// never rm -rf through a tenant symlink (SEC-2): mail/<domain> -> / would be rm -rf /etc
		root, err := openHome(e)
		if err != nil {
			return rpc.Empty{}, err
		}
		err = removeAllIn(root, "mail/"+domain+"/"+local)
		root.Close()
		if err != nil {
			return rpc.Empty{}, err
		}
	}
	return rpc.Empty{}, nil
}

// ensureIdentityAlias adds "addr addr" to valias unless addr already has an
// alias entry (a forwarder that keeps a copy lists addr itself).
func (a *Agent) ensureIdentityAlias(ctx context.Context, addr string) error {
	path := filepath.Join(a.postfixDir(), "valias")
	changed := false
	err := editMap(path, " ", 0o644, func(m [][2]string) [][2]string {
		for _, kv := range m {
			if kv[0] == addr {
				return m
			}
		}
		changed = true
		return append(m, [2]string{addr, addr})
	})
	if err != nil || !changed {
		return err
	}
	return a.postmap(ctx, "valias")
}

// dropIdentityAlias removes addr from its own valias entry (or the entry if
// it was only the identity mapping).
func (a *Agent) dropIdentityAlias(ctx context.Context, addr string) error {
	path := filepath.Join(a.postfixDir(), "valias")
	err := editMap(path, " ", 0o644, func(m [][2]string) [][2]string {
		out := m[:0]
		for _, kv := range m {
			if kv[0] == addr {
				var keep []string
				for _, d := range strings.Split(kv[1], ",") {
					if d != addr {
						keep = append(keep, d)
					}
				}
				if len(keep) == 0 {
					continue
				}
				kv[1] = strings.Join(keep, ",")
			}
			out = append(out, kv)
		}
		return out
	})
	if err != nil {
		return err
	}
	return a.postmap(ctx, "valias")
}

// editReject edits the recipient reject map (":fail:" forwarders). Postfix
// has no ":fail:" alias target, so such addresses are rejected at RCPT time
// via check_recipient_access hash:/etc/postfix/bpanel/vreject.
func (a *Agent) editReject(ctx context.Context, fn func([][2]string) [][2]string) error {
	if err := editMap(filepath.Join(a.postfixDir(), "vreject"), " ", 0o644, fn); err != nil {
		return err
	}
	return a.postmap(ctx, "vreject")
}

// updatePasswd edits the fields of one passwd-file line. The value after
// the user name is pass:uid:gid:gecos:home:shell:extra; extra (the 7th
// field) runs to the end of the line and itself contains ':' (e.g.
// "userdb_quota_rule=*:storage=100M"), so it is split off with SplitN and
// never re-split (R2-E2E-7: a quota change used to corrupt it into
// "...:storage=200M:storage=100M").
func (a *Agent) updatePasswd(addr string, fn func(fields []string) []string) error {
	return editMap(a.dovecotPasswd(), ":", 0o640, func(m [][2]string) [][2]string {
		for i := range m {
			if m[i][0] == addr {
				f := strings.SplitN(m[i][1], ":", 7)
				for len(f) < 7 {
					f = append(f, "")
				}
				m[i][1] = strings.Join(fn(f), ":")
			}
		}
		return m
	})
}

// setQuotaExtra replaces the quota settings in a passwd-file extra field
// (space-separated key=value pairs; Dovecot 2.3 userdb_quota_rule and 2.4
// userdb_quota_storage_size), keeping every other pair.
func setQuotaExtra(extra string, quotaMB int64, v24 bool) string {
	var keep []string
	for _, kv := range strings.Fields(extra) {
		k, _, _ := strings.Cut(kv, "=")
		if k == "userdb_quota_rule" || k == "userdb_quota_storage_size" || strings.HasPrefix(kv, "storage=") {
			continue
		}
		keep = append(keep, kv)
	}
	if q := quotaKV(quotaMB, v24); q != "" {
		keep = append(keep, q)
	}
	return strings.Join(keep, " ")
}

func (a *Agent) mailboxPassword(ctx context.Context, p rpc.Mailbox) (rpc.Empty, error) {
	local, domain, err := splitEmail(p.Email)
	if err != nil {
		return rpc.Empty{}, err
	}
	stored := ""
	if p.CryptHash != "" {
		if stored = ImportedMailHash(p.CryptHash); stored == "" {
			return rpc.Empty{}, errf("invalid_password_hash", "unsupported or malformed crypt hash")
		}
	} else if err := validate.Password(p.Password); err != nil {
		return rpc.Empty{}, errf(err.Error(), "password")
	}
	if err := a.mustOwn(kindMail, domain, p.User); err != nil { // CODE-27
		return rpc.Empty{}, err
	}
	defer a.lock("mail")()
	if stored == "" {
		stored = HashMailPassword(p.Password)
	}
	err = a.updatePasswd(local+"@"+domain, func(f []string) []string { f[0] = stored; return f })
	a.fixDovecotPerms()
	return rpc.Empty{}, err
}

func (a *Agent) mailboxQuota(ctx context.Context, p rpc.Mailbox) (rpc.Empty, error) {
	local, domain, err := splitEmail(p.Email)
	if err != nil {
		return rpc.Empty{}, err
	}
	if err := a.mustOwn(kindMail, domain, p.User); err != nil { // CODE-27
		return rpc.Empty{}, err
	}
	defer a.lock("mail")()
	if p.QuotaMB < 0 {
		return rpc.Empty{}, errf("invalid_quota", "%d", p.QuotaMB)
	}
	err = a.updatePasswd(local+"@"+domain, func(f []string) []string {
		f[6] = setQuotaExtra(f[6], p.QuotaMB, a.dovecotV24())
		return f
	})
	a.fixDovecotPerms()
	return rpc.Empty{}, err
}

// mailForwardSet replaces the full destination list of one source address.
// ":blackhole:" maps to devnull@localhost; ":fail:" is written to the
// recipient reject map instead of valias (Postfix does not understand
// ":fail:" as an alias target).
func (a *Agent) mailForwardSet(ctx context.Context, p rpc.MailForward) (rpc.Empty, error) {
	src := strings.ToLower(strings.TrimSpace(p.Source))
	srcDomain := strings.TrimPrefix(src, "@")
	if strings.HasPrefix(src, "@") {
		if err := validate.Domain(src[1:]); err != nil {
			return rpc.Empty{}, errf("invalid_email", "%s", src)
		}
	} else if _, d, err := splitEmail(src); err != nil {
		return rpc.Empty{}, err
	} else {
		srcDomain = d
	}
	// CODE-27 / SEC-12: only the account holding the mail domain may set or
	// remove its forwarders.
	if err := a.mustOwn(kindMail, srcDomain, p.Owner); err != nil {
		return rpc.Empty{}, err
	}
	if len(p.Destinations) > 100 {
		return rpc.Empty{}, errf("invalid_forwarder", "too many destinations")
	}
	var dests []string
	reject := false
	seen := map[string]bool{}
	for _, d := range p.Destinations {
		d = strings.ToLower(strings.TrimSpace(d))
		switch {
		case d == "":
			continue
		case d == ":fail:":
			reject = true
			continue
		case d == ":blackhole:":
			d = "devnull@localhost"
		default:
			if err := validate.Email(d); err != nil {
				return rpc.Empty{}, errf("invalid_email", "%s", d)
			}
		}
		if !seen[d] {
			seen[d] = true
			dests = append(dests, d)
		}
	}
	defer a.lock("mail")()
	path := filepath.Join(a.postfixDir(), "valias")
	var err error
	if len(dests) == 0 || reject {
		err = editMap(path, " ", 0o644, remove(func(k string) bool { return k == src }))
	} else {
		err = editMap(path, " ", 0o644, upsert(src, strings.Join(dests, ",")))
	}
	if err != nil {
		return rpc.Empty{}, err
	}
	if err := a.postmap(ctx, "valias"); err != nil {
		return rpc.Empty{}, err
	}
	if reject {
		err = a.editReject(ctx, upsert(src, "REJECT No such recipient"))
	} else {
		err = a.editReject(ctx, remove(func(k string) bool { return k == src }))
	}
	if err != nil {
		return rpc.Empty{}, err
	}
	return rpc.Empty{}, a.reloadPostfix(ctx)
}

func (a *Agent) mailForwardDelete(ctx context.Context, p rpc.MailForwardRef) (rpc.Empty, error) {
	return a.mailForwardSet(ctx, rpc.MailForward{Owner: p.Owner, Source: p.Source})
}

func (a *Agent) mailUsage(ctx context.Context, p rpc.MailUsageReq) (rpc.MailUsage, error) {
	out := rpc.MailUsage{Bytes: map[string]int64{}}
	e, err := a.home(p.User)
	if err != nil {
		return out, err
	}
	root, err := openHome(e)
	if err != nil {
		return out, err
	}
	defer root.Close()
	for _, d := range p.Domains {
		if validate.Domain(d) != nil {
			continue
		}
		// R2-WB-3: through the home's os.Root, never following a symlink
		m, err := mailUsageIn(ctx, root, d)
		if err != nil {
			return out, err
		}
		for k, v := range m {
			out.Bytes[k] = v
		}
	}
	return out, nil
}
