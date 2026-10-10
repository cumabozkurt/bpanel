package agent

// Round-2 fixes (R2-WB-*, R2-E2E-*, R2-PERF-* agent side).
//   go test ./internal/agent -run 'TestR2' -v
//   go test -race ./internal/agent -run 'TestR2'

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

func r2dispatch(t *testing.T, a *Agent, m string, raw string) rpc.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return a.Dispatch(ctx, rpc.Request{V: rpc.Version, ID: 1, Method: m, Params: json.RawMessage(raw)})
}

func r2code(r rpc.Response) string {
	if r.Error == nil {
		return "ok"
	}
	return r.Error.Code
}

// addUbuntu adds the cloud image's sudo user (uid 1000, /home/ubuntu), which
// the panel did not create.
func addUbuntu(t *testing.T, e *testEnv) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(e.base, "home", "ubuntu"), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(passwdFile, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, "ubuntu:x:1000:1000::%s/home/ubuntu:/bin/bash\n", e.base)
	f.Close()
}

// R2-WB-1: every method is classified, and every tenant method refuses an
// account the panel did not create - before its handler runs.
func TestR2WB1EveryMethodClassified(t *testing.T) {
	e := newTestEnv(t)
	for m := range e.a.routes {
		_, tenant := accountField[m]
		_, exempt := gateExempt[m]
		if tenant == exempt {
			t.Errorf("method %s: tenant=%v exempt=%v (must be exactly one)", m, tenant, exempt)
		}
	}
	for m := range accountField {
		if _, ok := e.a.routes[m]; !ok {
			t.Errorf("accountField lists unknown method %s", m)
		}
	}
}

func TestR2WB1UnmanagedAccountRefusedEverywhere(t *testing.T) {
	e := newTestEnv(t)
	addUbuntu(t, e)
	for _, u := range []string{"ubuntu", "opsuser"} {
		for m, f := range accountField {
			p := map[string]any{f.key: u}
			b, _ := json.Marshal(p)
			r := r2dispatch(t, e.a, m, string(b))
			if c := r2code(r); c != "not_managed" {
				t.Errorf("%s as %s: %s (%v), want not_managed", m, u, c, r.Error)
			}
		}
	}
	// nothing was written for them
	if ents, _ := os.ReadDir(e.a.L.NginxVhosts); len(ents) != 0 {
		t.Fatalf("vhost files written: %d", len(ents))
	}
	// the managed tenant still passes the gate
	if r := r2dispatch(t, e.a, rpc.MDiskUsage, `{"user":"tenant"}`); r.Error != nil {
		t.Fatalf("managed tenant refused: %v", r.Error)
	}
	// a missing account name is refused, an optional one may be empty
	if c := r2code(r2dispatch(t, e.a, rpc.MCronSet, `{"entries":[]}`)); c != "owner_required" {
		t.Fatalf("cron.set without user: %s", c)
	}
	if c := r2code(r2dispatch(t, e.a, rpc.MSSLInfo, `{"domain":"x.example"}`)); c != "ok" {
		t.Fatalf("ssl.info without owner: %s", c)
	}
	// account.terminate keeps its own clear message for foreign accounts
	if r := r2dispatch(t, e.a, rpc.MAccountTerminate, `{"user":"ubuntu"}`); r2code(r) != "not_managed" {
		t.Fatalf("terminate ubuntu: %v", r.Error)
	}
}

// R2-WB-2: ssl.selfsigned checks ownership.
func TestR2WB2SelfSignedOwnership(t *testing.T) {
	e := newTestEnv(t)
	if r := r2dispatch(t, e.a, rpc.MVhostApply, `{"user":"tenant","domain":"victim.example","docroot":"public_html","mode":"nginx"}`); r.Error != nil {
		t.Fatal(r.Error)
	}
	key := filepath.Join(e.a.Cfg.SSLDir, "victim.example", "privkey.pem")
	_ = os.MkdirAll(filepath.Dir(key), 0o700)
	_ = os.WriteFile(key, []byte("REAL KEY"), 0o600)
	addUbuntu(t, e)
	// another (unmanaged) account: refused by the gate
	if c := r2code(r2dispatch(t, e.a, rpc.MSSLSelfSigned, `{"user":"ubuntu","domain":"victim.example"}`)); c == "ok" {
		t.Fatal("foreign account replaced the certificate")
	}
	// owner-less: refused for a tenant's name
	if c := r2code(r2dispatch(t, e.a, rpc.MSSLSelfSigned, `{"domain":"victim.example"}`)); c != "owned_by_another_account" {
		t.Fatalf("owner-less self-signed for a tenant name: %s", c)
	}
	if b, _ := os.ReadFile(key); string(b) != "REAL KEY" {
		t.Fatal("key replaced")
	}
	// the owner may
	if r := r2dispatch(t, e.a, rpc.MSSLSelfSigned, `{"user":"tenant","domain":"victim.example"}`); r.Error != nil {
		t.Fatalf("owner: %v", r.Error)
	}
	// the panel hostname (installer, no owner) may
	e.a.Cfg.Hostname = "panel.example.net"
	if r := r2dispatch(t, e.a, rpc.MSSLSelfSigned, `{"domain":"panel.example.net"}`); r.Error != nil {
		t.Fatalf("hostname: %v", r.Error)
	}
}

// R2-WB-3: mail.usage never follows a symlink out of the home.
func TestR2WB3MailUsageNoSymlink(t *testing.T) {
	e := newTestEnv(t)
	secret := filepath.Join(e.outside, "victim-mailboxes")
	for _, n := range []string{"ceo", "payroll"} {
		_ = os.MkdirAll(filepath.Join(secret, n, "cur"), 0o700)
		_ = os.WriteFile(filepath.Join(secret, n, "cur", "m1"), []byte(strings.Repeat("x", 5000)), 0o600)
	}
	_ = os.MkdirAll(filepath.Join(e.home, "mail", "own.example", "info", "cur"), 0o700)
	_ = os.WriteFile(filepath.Join(e.home, "mail", "own.example", "info", "cur", "m"), []byte("hello"), 0o600)
	if err := os.Symlink(secret, filepath.Join(e.home, "mail", "leak.example")); err != nil {
		t.Fatal(err)
	}
	// and a mailbox that is itself a symlink
	if err := os.Symlink(filepath.Join(secret, "ceo"), filepath.Join(e.home, "mail", "own.example", "ceo")); err != nil {
		t.Fatal(err)
	}
	r := r2dispatch(t, e.a, rpc.MMailUsage, `{"user":"tenant","domains":["leak.example","own.example"]}`)
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	if s := string(r.Result); strings.Contains(s, "payroll") || strings.Contains(s, "ceo@") {
		t.Fatalf("leaked: %s", s)
	}
	if !strings.Contains(string(r.Result), "info@own.example") {
		t.Fatalf("own mailbox missing: %s", r.Result)
	}
}

// R2-WB-4: public suffixes cannot be claimed and never act as a parent.
func TestR2WB4PublicSuffix(t *testing.T) {
	e := newTestEnv(t)
	for _, ps := range []string{"com.tr", "com", "github.io", "co.uk", "bel.tr"} {
		if err := e.a.claim(kindWeb, ps, "tenant", ""); code(err) != "public_suffix" {
			t.Errorf("claim %s: %v", ps, err)
		}
	}
	// a stale entry from before the fix does not block or adopt
	if err := e.a.writeOwner(kindWeb, "com.tr", ownerEntry{Owner: "tenant"}); err != nil {
		t.Fatal(err)
	}
	if err := e.a.claim(kindWeb, "victimshop.com.tr", "victim", ""); err != nil {
		t.Fatalf("victim blocked by a stale public-suffix entry: %v", err)
	}
	if err := e.a.ownsAny("anything.com.tr", "other", kindWeb); err != nil {
		t.Fatalf("ownsAny for a free name: %v", err)
	}
	if err := e.a.ownsAny("victimshop.com.tr", "tenant", kindWeb); code(err) != "owned_by_another_account" {
		t.Fatalf("tenant treated as owner of victimshop.com.tr: %v", err)
	}
	// ordinary registrable domains still work
	if err := e.a.claim(kindWeb, "shop.com.tr", "tenant", ""); err != nil {
		t.Fatal(err)
	}
}

// R2-WB-5: the hostname certificate is not blocked by a tenant's parent.
func TestR2WB5HostnameNotBlocked(t *testing.T) {
	e := newTestEnv(t)
	e.a.Cfg.Hostname = "panel.example.net"
	if err := e.a.claim(kindZone, "example.net", "tenant", ""); err != nil {
		t.Fatal(err)
	}
	if err := e.a.hostnameOrFree("panel.example.net"); err != nil {
		t.Fatalf("hostname blocked: %v", err)
	}
	// other names stay protected
	if err := e.a.hostnameOrFree("www.example.net"); code(err) != "owned_by_another_account" {
		t.Fatalf("owner-less cert for a tenant name: %v", err)
	}
	// the exact name held by an account still conflicts
	if err := e.a.writeOwner(kindWeb, "panel.example.net", ownerEntry{Owner: "tenant"}); err != nil {
		t.Fatal(err)
	}
	if err := e.a.hostnameOrFree("panel.example.net"); err == nil {
		t.Fatal("hostname held by an account accepted")
	}
}

// R2-WB-6: request buffering is bounded: many connections each sending a
// huge unterminated line no longer grow the heap by N x MaxLine.
func TestR2WB6AgentMemoryBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("memory heavy")
	}
	e := newTestEnv(t)
	e.a.Cfg.AllowedUIDs = []int{os.Getuid()}
	sock := filepath.Join(t.TempDir(), "a.sock")
	e.a.Cfg.Socket = sock
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	go func() { _ = e.a.Serve(ctx) }()
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("unix", sock); err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	const conns, per = 10, 24 << 20 // unbounded: ~240 MiB
	chunk := bytes.Repeat([]byte("a"), 1<<20)
	var wg sync.WaitGroup
	var cs []net.Conn
	var mu sync.Mutex
	for i := 0; i < conns; i++ {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		cs = append(cs, c)
		mu.Unlock()
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
			for w := 0; w < per; w += len(chunk) {
				if _, err := c.Write(chunk); err != nil {
					return // blocked: the agent stopped reading (no slot)
				}
			}
		}(c)
	}
	wg.Wait()
	time.Sleep(300 * time.Millisecond)
	var after runtime.MemStats
	runtime.GC() // live buffers only
	runtime.ReadMemStats(&after)
	grow := int64(after.HeapInuse) - int64(before.HeapInuse)
	t.Logf("%d connections x %d MiB: heap grew by %d MiB", conns, per>>20, grow>>20)
	for _, c := range cs {
		c.Close()
	}
	// at most bigLineSlots big lines (+ small buffers): well below 6 x 24 MiB
	if limit := int64(2*bigLineSlots*per + 2*conns*smallLine + 16<<20); grow > limit {
		t.Fatalf("heap grew by %d MiB (limit %d MiB)", grow>>20, limit>>20)
	}
	// and the agent still answers
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, `{"v":%d,"id":9,"method":"system.ping","params":{}}`+"\n", rpc.Version)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil || !bytes.Contains(line, []byte(`"result"`)) {
		t.Fatalf("ping after flood: %s %v", line, err)
	}
}

// R2-WB-7: the decoder refuses trailing data, case-variant and duplicate keys.
func TestR2WB7StrictDecoding(t *testing.T) {
	h := bind(func(_ context.Context, p rpc.AccountRef) (rpc.Empty, error) { return rpc.Empty{}, nil })
	for _, raw := range []string{
		`{"user":"alice","USER":"bob"}`,
		`{"user":"alice"} {"user":"root"}`,
		`{"user":"alice"} trailing`,
		`{"user":"alice","user":"bob"}`,
		`{"User":"alice"}`,
	} {
		if _, err := h(context.Background(), json.RawMessage(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	if _, err := h(context.Background(), json.RawMessage(` {"user":"alice"} `+"\n")); err != nil {
		t.Fatalf("valid params refused: %v", err)
	}
}

// R2-WB-12: INI values cannot carry Unicode line separators or controls.
func TestR2WB12INIValues(t *testing.T) {
	for _, v := range []string{"a\u2028b", "a\u2029b", "a\u0085b", "a\x7fb", "a\u200bb", "a\xffb", "${HOME}", "a\\b", "x'y", "a\tb"} {
		if iniValueOK(v) {
			t.Errorf("accepted %q", v)
		}
	}
	for _, v := range []string{"On", "Europe/Istanbul", "256M", "E_ALL & ~E_NOTICE", "/home/x/tmp", "çğü"} {
		if !iniValueOK(v) {
			t.Errorf("refused %q", v)
		}
	}
}

// R2-WB-13: mailbox hashes are SHA512-CRYPT and match glibc/openssl.
func TestR2WB13SHA512Crypt(t *testing.T) {
	for _, c := range []struct {
		pw, salt string
		rounds   int
		want     string
	}{
		{"Hello world!", "saltstring", 5000, "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"},
		{"Hello world!", "saltstringsaltstring", 10000, "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."},
	} {
		if got := sha512Crypt([]byte(c.pw), c.salt, c.rounds); got != c.want {
			t.Errorf("sha512Crypt(%q,%q,%d) = %s", c.pw, c.salt, c.rounds, got)
		}
	}
	h := HashMailPassword("Mailbox-Pass-2026")
	if !strings.HasPrefix(h, "{SHA512-CRYPT}$6$rounds=100000$") {
		t.Fatalf("scheme: %s", h)
	}
	if h == HashMailPassword("Mailbox-Pass-2026") {
		t.Fatal("salt not random")
	}
	// cross-check against openssl (libc-compatible) when available
	if _, err := exec.LookPath("openssl"); err == nil {
		out, err := exec.Command("openssl", "passwd", "-6", "-salt", "abcdEFGH12345678", "Long password with ümlauts and 40+ chars!!").Output()
		if err == nil {
			want := strings.TrimSpace(string(out))
			if got := sha512Crypt([]byte("Long password with ümlauts and 40+ chars!!"), "abcdEFGH12345678", 5000); got != want {
				t.Fatalf("openssl %s, got %s", want, got)
			}
		}
	}
}

// R2-WB-14: SSH and the panel cannot be stopped; extra units are filtered.
func TestR2WB14ServiceAllowlist(t *testing.T) {
	e := newTestEnv(t)
	e.a.Cfg.ExtraUnits = []string{"memcached", "systemd-journald", "dbus", "multi-user.target", "user@0", "redis-server"}
	for _, u := range []string{e.a.L.SSHUnit, "bpanel-api"} {
		if c := r2code(r2dispatch(t, e.a, rpc.MServiceAction, fmt.Sprintf(`{"unit":%q,"action":"stop"}`, u))); c != "refused" {
			t.Errorf("stop %s: %s", u, c)
		}
	}
	allowed := e.a.allowedUnits()
	for _, u := range []string{"systemd-journald", "dbus", "multi-user.target", "user@0"} {
		if _, ok := allowed[u]; ok {
			t.Errorf("extra unit %s allowed", u)
		}
	}
	for _, u := range []string{"memcached", "redis-server"} {
		if _, ok := allowed[u]; !ok {
			t.Errorf("extra unit %s dropped", u)
		}
	}
}

// R2-E2E-7: a quota change keeps the passwd line intact.
func TestR2E2E7MailboxQuotaParsing(t *testing.T) {
	for _, c := range []struct {
		in   string
		q    int64
		want string
	}{
		{"userdb_quota_rule=*:storage=100M", 200, "userdb_quota_rule=*:storage=200M"},
		{"", 50, "userdb_quota_rule=*:storage=50M"},
		{"userdb_quota_rule=*:storage=100M", 0, ""},
		{"userdb_mail=maildir:~/x userdb_quota_rule=*:storage=1M", 2, "userdb_mail=maildir:~/x userdb_quota_rule=*:storage=2M"},
		{"userdb_quota_storage_size=1M", 3, "userdb_quota_rule=*:storage=3M"},
	} {
		if got := setQuotaExtra(c.in, c.q, false); got != c.want {
			t.Errorf("setQuotaExtra(%q,%d) = %q, want %q", c.in, c.q, got, c.want)
		}
	}
	e := newTestEnv(t)
	if r := r2dispatch(t, e.a, rpc.MVhostApply, `{"user":"tenant","domain":"q.example","docroot":"public_html","mode":"nginx"}`); r.Error != nil {
		t.Fatal(r.Error)
	}
	pw := e.a.dovecotPasswd()
	_ = os.MkdirAll(filepath.Dir(pw), 0o755)
	line := "info@q.example:{SSHA512}abc:1001:1001::" + e.home + "/mail/q.example/info::userdb_quota_rule=*:storage=100M\n"
	if err := os.WriteFile(pw, []byte(line), 0o640); err != nil {
		t.Fatal(err)
	}
	for _, q := range []int64{200, 300} {
		if err := e.a.updatePasswd("info@q.example", func(f []string) []string { f[6] = setQuotaExtra(f[6], q, false); return f }); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(pw)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	got := lines[len(lines)-1]
	want := "info@q.example:{SSHA512}abc:1001:1001::" + e.home + "/mail/q.example/info::userdb_quota_rule=*:storage=300M"
	if got != want {
		t.Fatalf("passwd line:\n got %s\nwant %s", got, want)
	}
	if strings.Count(got, ":") != strings.Count(want, ":") {
		t.Fatal("field count changed")
	}
}

// R2-E2E-10: homes are 0710 group web; skeleton files lose group/other access.
func TestR2E2E10HomePermissions(t *testing.T) {
	e := newTestEnv(t)
	_ = os.Chmod(e.home, 0o711)
	_ = os.WriteFile(filepath.Join(e.home, ".bash_logout"), []byte("# skel"), 0o644)
	_ = os.WriteFile(filepath.Join(e.home, ".profile"), []byte("# skel"), 0o640)
	_ = os.Symlink("/etc/passwd", filepath.Join(e.home, "link"))
	ent, err := e.a.home("tenant")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.a.layoutHome(ent); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(e.home)
	if st.Mode().Perm() != 0o710 {
		t.Fatalf("home mode %o", st.Mode().Perm())
	}
	for _, f := range []string{".bash_logout", ".profile"} {
		st, _ := os.Stat(filepath.Join(e.home, f))
		if st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s mode %o", f, st.Mode().Perm())
		}
	}
	// the symlink target was not touched
	if st, _ := os.Stat("/etc/passwd"); st.Mode().Perm()&0o004 == 0 {
		t.Fatal("followed a symlink")
	}
	// public_html stays reachable for the web group
	pst, err := os.Stat(filepath.Join(e.home, "public_html"))
	if err != nil || pst.Mode().Perm() != 0o750 {
		t.Fatalf("public_html: %v %o", err, pst.Mode().Perm())
	}
	// migration of an old home
	_ = os.Chmod(e.home, 0o711)
	e.a.MigrateHomes()
	if st, _ := os.Stat(e.home); st.Mode().Perm() != 0o710 {
		t.Fatalf("migrated home mode %o", st.Mode().Perm())
	}
	// an unmanaged home is never migrated
	ops := filepath.Join(e.base, "home", "opsuser")
	_ = os.MkdirAll(ops, 0o755)
	e.a.MigrateHomes()
	if st, _ := os.Stat(ops); st.Mode().Perm() != 0o755 {
		t.Fatalf("unmanaged home changed: %o", st.Mode().Perm())
	}
}

// R2-E2E-9: an in-place directory restore swaps atomically and replaces
// read-only files.
func TestR2E2E9SwapRestore(t *testing.T) {
	e := newTestEnv(t)
	ent, _ := e.a.home("tenant")
	dest := filepath.Join(e.home, "mail", "x.example", "info")
	_ = os.MkdirAll(filepath.Join(dest, "cur"), 0o700)
	_ = os.WriteFile(filepath.Join(dest, "cur", "new-after-backup"), []byte("n"), 0o600)
	_ = os.WriteFile(filepath.Join(dest, "dovecot-uidvalidity.1"), []byte("old"), 0o444)
	snap := filepath.Join(e.base, "snap")
	_ = os.MkdirAll(filepath.Join(snap, "cur"), 0o700)
	_ = os.WriteFile(filepath.Join(snap, "cur", "restored"), []byte("r"), 0o600)
	_ = os.WriteFile(filepath.Join(snap, "dovecot-uidvalidity.1"), []byte("snap"), 0o444)
	if err := e.a.swapRestore(context.Background(), ent, snap, dest); err != nil {
		t.Fatal(err)
	}
	for f, want := range map[string]string{"cur/new-after-backup": "n", "cur/restored": "r", "dovecot-uidvalidity.1": "snap"} {
		if b, err := os.ReadFile(filepath.Join(dest, f)); err != nil || string(b) != want {
			t.Errorf("%s: %q %v", f, b, err)
		}
	}
	ents, _ := os.ReadDir(filepath.Dir(dest))
	for _, de := range ents {
		if strings.HasPrefix(de.Name(), ".bpanel-") {
			t.Errorf("leftover %s", de.Name())
		}
	}
}

// R2-PERF-9: limits for many accounts in one call; unmanaged items fail alone.
func TestR2PERF9QuotaBatch(t *testing.T) {
	e := newTestEnv(t)
	addUbuntu(t, e)
	r := r2dispatch(t, e.a, rpc.MAccountQuotaBatch, `{"items":[{"user":"tenant","quota_mb":100},{"user":"ubuntu","quota_mb":100}]}`)
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	var res rpc.AccountQuotaBatchResult
	_ = json.Unmarshal(r.Result, &res)
	if res.Failed["ubuntu"] != "not_managed" {
		t.Fatalf("ubuntu: %v", res.Failed)
	}
	if _, bad := res.Failed["tenant"]; bad {
		// quota tools are missing in the sandbox: only limits_failed is acceptable
		if res.Failed["tenant"] != "limits_failed" {
			t.Fatalf("tenant: %v", res.Failed)
		}
	}
}

// R2-PERF-15: an interrupted panel account is adopted only with Adopt and
// only when it carries the marker.
func TestR2PERF15Adopt(t *testing.T) {
	e := newTestEnv(t)
	addUbuntu(t, e)
	if _, err := e.a.accountCreate(context.Background(), rpc.AccountCreate{User: "ubuntu", Password: "Adopt-Pass-2026x", Adopt: true}); code(err) != "user_exists" {
		t.Fatalf("unmanaged adopted: %v", err)
	}
	if _, err := e.a.accountCreate(context.Background(), rpc.AccountCreate{User: "tenant", Password: "Adopt-Pass-2026x"}); code(err) != "user_exists" {
		t.Fatalf("managed without Adopt: %v", err)
	}
}

// R2-PERF-16: sysinfo is cached between calls.
func TestR2PERF16SysInfoCache(t *testing.T) {
	e := newTestEnv(t)
	start := time.Now()
	for i := 0; i < 5; i++ {
		if _, err := e.a.sysInfo(context.Background(), rpc.Empty{}); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("5 calls took %v", d)
	}
}

// R2-UX-13: the agent refuses private FTP directories itself.
func TestR2UX13FTPPrivateDir(t *testing.T) {
	e := newTestEnv(t)
	if r := r2dispatch(t, e.a, rpc.MVhostApply, `{"user":"tenant","domain":"f.example","docroot":"public_html","mode":"nginx"}`); r.Error != nil {
		t.Fatal(r.Error)
	}
	for _, d := range []string{"etc", "mail/x", "logs", "ssl", "backups", "tmp/a"} {
		r := r2dispatch(t, e.a, rpc.MFTPCreate, fmt.Sprintf(`{"user":"tenant","login":"a@f.example","password":"Ftp-Pass-2026x","dir":%q}`, d))
		if c := r2code(r); c != "private_dir" {
			t.Errorf("dir %s: %s", d, c)
		}
	}
}

// race: concurrent gated dispatches and quota batches.
func TestR2RaceDispatch(t *testing.T) {
	e := newTestEnv(t)
	addUbuntu(t, e)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := "tenant"
			if i%2 == 0 {
				u = "ubuntu"
			}
			_ = r2dispatch(t, e.a, rpc.MDiskUsage, fmt.Sprintf(`{"user":%q}`, u))
			_, _ = e.a.sysInfo(context.Background(), rpc.Empty{})
		}(i)
	}
	wg.Wait()
}

var _ = syscall.Getuid
