package agent

// Regression tests for the 2026-10-09 audit fixes (SEC-*, CODE-*, SYS-*).
// They run unprivileged: a fake passwd/group database maps the hosting
// account "tenant" to the uid running the tests, so root-only steps
// (chown to another uid) are the only thing not exercised here; the
// root/userns variants live in audit/poc (run_userns_poc.sh).

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/distro"
)

type testEnv struct {
	a       *Agent
	base    string
	home    string
	outside string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	base := t.TempDir()
	home := filepath.Join(base, "home", "tenant")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{home, outside, filepath.Join(base, "nginx"), filepath.Join(base, "apache"),
		filepath.Join(base, "postfix", "bpanel"), filepath.Join(base, "dovecot", "bpanel")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	uid, gid := os.Getuid(), os.Getgid()
	pw := filepath.Join(base, "passwd")
	gr := filepath.Join(base, "group")
	if err := os.WriteFile(pw, []byte(fmt.Sprintf("root:x:0:0::/root:/bin/bash\nopsuser:x:%d:%d::%s/home/opsuser:/bin/bash\ntenant:x:%d:%d::%s:/usr/sbin/nologin\n",
		uid, gid, base, uid, gid, home)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gr, []byte(fmt.Sprintf("root:x:0:\ntenant:x:%d:\nbpanel-users:x:4000:\n", gid)), 0o644); err != nil {
		t.Fatal(err)
	}
	oldP, oldG := passwdFile, groupFile
	passwdFile, groupFile = pw, gr
	t.Cleanup(func() { passwdFile, groupFile = oldP, oldG })

	l, err := distro.ForRelease(map[string]string{"ID": "ubuntu", "VERSION_ID": "24.04"})
	if err != nil {
		t.Fatal(err)
	}
	l.NginxVhosts = filepath.Join(base, "nginx")
	l.ApacheVhosts = filepath.Join(base, "apache")
	l.PostfixDir = filepath.Join(base, "postfix")
	l.DovecotDir = filepath.Join(base, "dovecot")
	cfg := DefaultConfig()
	cfg.HomeBase = filepath.Join(base, "home")
	cfg.NoSystemd = true
	cfg.AccountsDir = filepath.Join(base, "accounts")
	cfg.RestoreDir = filepath.Join(base, "restore")
	cfg.ResticPassDir = filepath.Join(base, "restic-pass")
	cfg.BackupRepo = filepath.Join(base, "repo")
	cfg.SSLDir = filepath.Join(base, "ssl")
	cfg.OwnersDir = filepath.Join(base, "owners")
	a := New(cfg, l, slog.New(slog.NewTextHandler(io.Discard, nil)))
	a.configTestFn = func(context.Context, string) error { return nil }
	a.domlogDir, a.acmeDir, a.resticCache = filepath.Join(base, "domlogs"), filepath.Join(base, "acme"), filepath.Join(base, "restic-cache")
	// "tenant" is a panel-created account (ownership marker); "opsuser" is
	// not (R2-WB-1)
	if err := writeAtomic(a.markerPath("tenant"), []byte("created-by=bpanel\n"), 0o600, -1, -1); err != nil {
		t.Fatal(err)
	}
	return &testEnv{a: a, base: base, home: home, outside: outside}
}

func code(err error) string {
	var re *rpc.Error
	if errors.As(err, &re) {
		return re.Code
	}
	if err == nil {
		return ""
	}
	return "?" + err.Error()
}

// SEC-1 / CODE-1: injected docroots never render, all paths are quoted.
func TestVhostRejectsDocrootInjection(t *testing.T) {
	e := newTestEnv(t)
	for _, dr := range []string{
		"public_html;\n}\nserver {", "public_html\n    CustomLog \"|/bin/sh -c id\" common\n#", "a b", `a"b`, "a{b}", "x:0:0",
		"../etc", ".ssh", "mail/x", "logs", "backups/restore-1", "a/$x", `a\b`, "",
	} {
		if _, _, err := e.a.RenderVhost(rpc.Vhost{User: "tenant", Domain: "t.test", DocRoot: dr, PHPVersion: "8.3"}, e.home); code(err) != "invalid_docroot" {
			t.Errorf("docroot %q: got %v, want invalid_docroot", dr, err)
		}
	}
	ng, ap, err := e.a.RenderVhost(rpc.Vhost{User: "tenant", Domain: "t.test", DocRoot: "sites/t.test", PHPVersion: "8.3", Mode: "nginx"}, e.home)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ng), `root "`+e.home+`/sites/t.test";`) {
		t.Errorf("nginx root not quoted:\n%s", ng)
	}
	if !strings.Contains(string(ap), `DocumentRoot "`+e.home+`/sites/t.test"`) {
		t.Errorf("apache DocumentRoot not quoted:\n%s", ap)
	}
}

// SEC-1 defence in depth: a redirect with config metacharacters is refused.
func TestVhostRejectsRedirectInjection(t *testing.T) {
	e := newTestEnv(t)
	for _, red := range []string{"https://x.test/;\n}", "https://x.test/ a", "https://x.test/$1", "https://x.test/#a", "ftp://x"} {
		_, _, err := e.a.RenderVhost(rpc.Vhost{User: "tenant", Domain: "t.test", DocRoot: "public_html", Redirect: red}, e.home)
		if code(err) != "invalid_redirect" {
			t.Errorf("redirect %q accepted: %v", red, err)
		}
	}
}

// SEC-4: symlink protection in both web servers.
func TestVhostSymlinkProtection(t *testing.T) {
	e := newTestEnv(t)
	ng, ap, err := e.a.RenderVhost(rpc.Vhost{User: "tenant", Domain: "t.test", DocRoot: "public_html", PHPVersion: "8.3"}, e.home)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ng), "disable_symlinks if_not_owner") {
		t.Error("nginx: no disable_symlinks")
	}
	if strings.Contains(string(ap), "AllowOverride All") || !strings.Contains(string(ap), "Options=Indexes,MultiViews,SymLinksIfOwnerMatch") {
		t.Errorf("apache AllowOverride too broad:\n%s", ap)
	}
}

// SEC-2 / CODE-3: vhostApply creates a missing docroot inside the home, but
// never through a symlink.
func TestVhostApplyDocrootSymlink(t *testing.T) {
	e := newTestEnv(t)
	if err := os.Symlink(e.outside, filepath.Join(e.home, "web")); err != nil {
		t.Fatal(err)
	}
	_, err := e.a.vhostApply(context.Background(), rpc.Vhost{User: "tenant", Domain: "t.test", DocRoot: "web/pwned", PHPVersion: "8.3", Mode: "nginx"})
	if code(err) != "symlink_in_path" {
		t.Fatalf("got %v, want symlink_in_path", err)
	}
	if _, err := os.Stat(filepath.Join(e.outside, "pwned")); err == nil {
		t.Fatal("docroot created outside the home")
	}
	// the normal case still works and writes the vhost
	if _, err := e.a.vhostApply(context.Background(), rpc.Vhost{User: "tenant", Domain: "t.test", DocRoot: "sites/t.test", PHPVersion: "8.3", Mode: "nginx"}); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(e.home, "sites", "t.test")); err != nil || !st.IsDir() {
		t.Fatalf("docroot not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.base, "nginx", "t.test.conf")); err != nil {
		t.Fatal("vhost not written")
	}
}

// SEC-2: mailbox create/delete never act through tenant symlinks.
func TestMailboxSymlinks(t *testing.T) {
	e := newTestEnv(t)
	if err := os.WriteFile(filepath.Join(e.a.postfixDir(), "vdomains"), []byte("x.test OK\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(e.home, "mail"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(e.outside, filepath.Join(e.home, "mail", "x.test")); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(e.outside, "etc", "shadow")
	if err := os.MkdirAll(filepath.Dir(sentinel), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sentinel, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.mailboxCreate(context.Background(), rpc.Mailbox{User: "tenant", Email: "box@x.test", Password: "Mail-Pass-2026"}); code(err) != "symlink_in_path" {
		t.Errorf("create: got %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.outside, "box")); err == nil {
		t.Error("maildir created outside the home")
	}
	if _, err := e.a.mailboxDelete(context.Background(), rpc.MailboxRef{User: "tenant", Email: "etc@x.test"}); code(err) != "symlink_in_path" {
		t.Errorf("delete: got %v", err)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatal("mailbox delete removed a file outside the home")
	}
}

// SEC-2 / SEC-9: FTP directory is strict and symlink-safe.
func TestFTPDir(t *testing.T) {
	e := newTestEnv(t)
	if err := os.Symlink(e.outside, filepath.Join(e.home, "link")); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"x\ny:z", "a:b", "../x", "a b"} {
		if _, err := e.a.ftpCreate(context.Background(), rpc.FTPAccount{User: "tenant", Login: "f@t.test", Password: "Ftp-Pass-2026", Dir: dir}); code(err) != "invalid_path" {
			t.Errorf("dir %q: %v", dir, err)
		}
	}
	if _, err := e.a.ftpCreate(context.Background(), rpc.FTPAccount{User: "tenant", Login: "f@t.test", Password: "Ftp-Pass-2026", Dir: "link/ftp"}); code(err) != "symlink_in_path" {
		t.Errorf("symlinked dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.outside, "ftp")); err == nil {
		t.Error("ftp dir created outside the home")
	}
}

// SEC-5 / CODE-2: an existing Linux account is never adopted.
func TestAccountCreateRefusesExistingUser(t *testing.T) {
	e := newTestEnv(t)
	for _, u := range []string{"root", "opsuser", "tenant"} {
		_, err := e.a.accountCreate(context.Background(), rpc.AccountCreate{User: u, Password: "Reseller-Pass-2026"})
		if code(err) != "user_exists" {
			t.Errorf("%s: got %v, want user_exists", u, err)
		}
	}
	// a name whose home directory already exists is refused as well
	if err := os.MkdirAll(filepath.Join(e.base, "home", "leftover"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.accountCreate(context.Background(), rpc.AccountCreate{User: "leftover", Password: "Reseller-Pass-2026"}); code(err) != "home_exists" {
		t.Errorf("leftover home: %v", err)
	}
}

// SEC-5 / CODE-2: terminate/password/suspend/quota need the ownership marker
// (or v0.1 bpanel-users membership); account.exists reports it.
func TestManagedAccounts(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if err := os.Remove(e.a.markerPath("tenant")); err != nil { // start unmarked
		t.Fatal(err)
	}
	if _, err := e.a.accountTerminate(ctx, rpc.AccountRef{User: "tenant"}); code(err) != "not_managed" {
		t.Fatalf("terminate of an unmarked account: %v", err)
	}
	if _, err := e.a.accountPassword(ctx, rpc.AccountPassword{User: "tenant", Password: "New-Pass-2026x"}); code(err) != "not_managed" {
		t.Fatalf("password of an unmarked account: %v", err)
	}
	ex, err := e.a.accountExists(ctx, rpc.AccountRef{User: "tenant"})
	if err != nil || !ex.Exists || ex.Managed {
		t.Fatalf("exists: %+v %v", ex, err)
	}
	if err := writeAtomic(e.a.markerPath("tenant"), []byte("x"), 0o600, -1, -1); err != nil {
		t.Fatal(err)
	}
	if ex, _ := e.a.accountExists(ctx, rpc.AccountRef{User: "tenant"}); !ex.Managed {
		t.Fatal("marker not recognised")
	}
	if err := os.Remove(e.a.markerPath("tenant")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(groupFile, []byte("bpanel-users:x:4000:other,tenant\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ex, _ := e.a.accountExists(ctx, rpc.AccountRef{User: "tenant"}); !ex.Managed {
		t.Fatal("v0.1 bpanel-users membership not recognised")
	}
	if ex, _ := e.a.accountExists(ctx, rpc.AccountRef{User: "nobodyhere"}); ex.Exists {
		t.Fatal("unknown user reported as existing")
	}
}

// layoutHome creates the standard tree and refuses symlinked entries.
func TestLayoutHome(t *testing.T) {
	e := newTestEnv(t)
	ent, err := e.a.home("tenant")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.a.layoutHome(ent); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"public_html", "logs", "tmp", "mail", ".bpanel", "etc", "backups"} {
		if st, err := os.Lstat(filepath.Join(e.home, d)); err != nil || !st.IsDir() {
			t.Errorf("%s missing", d)
		}
	}
	if _, err := os.Stat(filepath.Join(e.home, "public_html", "index.html")); err != nil {
		t.Error("index.html missing")
	}
	// idempotent, and a symlinked entry is refused instead of chmod/chown-ed
	if err := os.RemoveAll(filepath.Join(e.home, "logs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(e.outside, filepath.Join(e.home, "logs")); err != nil {
		t.Fatal(err)
	}
	if err := e.a.layoutHome(ent); code(err) != "symlink_in_path" {
		t.Fatalf("got %v", err)
	}
}

// removeAllIn / mkdirOwned primitives.
func TestSafeFSPrimitives(t *testing.T) {
	e := newTestEnv(t)
	ent, _ := e.a.home("tenant")
	root, err := openHome(ent)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Symlink("/", filepath.Join(e.home, "rootlink")); err != nil {
		t.Fatal(err)
	}
	if err := removeAllIn(root, "rootlink/etc"); code(err) != "symlink_in_path" {
		t.Errorf("removeAllIn through symlink: %v", err)
	}
	if err := removeAllIn(root, "rootlink"); err != nil { // removes the link itself
		t.Errorf("remove link: %v", err)
	}
	if _, err := os.Stat("/etc/passwd"); err != nil {
		t.Fatal("removed outside")
	}
	if err := removeAllIn(root, "."); code(err) != "refused" {
		t.Errorf("remove home: %v", err)
	}
	// ".." is cleaned inside the root, never above it
	if err := mkdirOwned(root, "../escaped", 0o755, os.Getuid(), os.Getgid(), false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(e.home), "escaped")); err == nil {
		t.Error("directory created above the home")
	}
}

// CODE-17: cron '%' is escaped when written (already escaped '%' stays as is).
func TestCronPercentEscaped(t *testing.T) {
	if got := cronLine([5]string{"0", "3", "*", "*", "*"}, `date +%F > /tmp/x-$(date +\%H)`); got != `0 3 * * * date +\%F > /tmp/x-$(date +\%H)` {
		t.Fatalf("cron line %q", got)
	}
}

// DNS: an existing zone is never deleted and re-created; Replace patches in place.
func TestDNSZoneCreateNoRecreate(t *testing.T) {
	e := newTestEnv(t)
	var calls []string
	exists := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == "GET" && exists:
			_ = json.NewEncoder(w).Encode(pdnsZone{Name: "z.test.", RRSets: []pdnsRRSet{
				{Name: "z.test.", Type: "SOA"}, {Name: "custom.z.test.", Type: "TXT"}, {Name: "z.test.", Type: "A"}}})
		case r.Method == "GET":
			w.WriteHeader(404)
		default:
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	e.a.Cfg.PDNSURL = srv.URL
	zone := rpc.DNSZone{Owner: "tenant", Zone: "z.test", Records: []rpc.DNSRecord{{Name: "z.test", Type: "A", Content: "192.0.2.1"}, {Name: "z.test", Type: "NS", Content: "ns1.s.test"}}}
	if _, err := e.a.dnsZoneCreate(context.Background(), zone); code(err) != "zone_exists" {
		t.Fatalf("existing zone: %v", err)
	}
	zone.Replace = true
	if _, err := e.a.dnsZoneCreate(context.Background(), zone); err != nil {
		t.Fatal(err)
	}
	for _, c := range calls {
		if strings.HasPrefix(c, "DELETE") || strings.HasPrefix(c, "POST") {
			t.Fatalf("zone was deleted/re-created: %v", calls)
		}
	}
	if calls[len(calls)-1] != "PATCH /api/v1/servers/localhost/zones/z.test." {
		t.Fatalf("no in-place patch: %v", calls)
	}
	exists = false
	calls = nil
	zone.Replace = false
	if _, err := e.a.dnsZoneCreate(context.Background(), zone); err != nil {
		t.Fatal(err)
	}
	if calls[len(calls)-1] != "POST /api/v1/servers/localhost/zones" {
		t.Fatalf("new zone not created: %v", calls)
	}
}

// SYS (forwarders): ":fail:" goes to the reject map, mailboxes keep an identity alias.
func TestForwarderMaps(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.a.mailForwardSet(ctx, rpc.MailForward{Owner: "tenant", Source: "old@x.test", Destinations: []string{":fail:"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.mailForwardSet(ctx, rpc.MailForward{Owner: "tenant", Source: "@x.test", Destinations: []string{"a@y.test", "a@y.test", ":blackhole:"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.a.ensureIdentityAlias(ctx, "info@x.test"); err != nil {
		t.Fatal(err)
	}
	va, _ := readMap(filepath.Join(e.a.postfixDir(), "valias"), " ")
	vr, _ := readMap(filepath.Join(e.a.postfixDir(), "vreject"), " ")
	got := map[string]string{}
	for _, kv := range va {
		got[kv[0]] = kv[1]
	}
	if got["@x.test"] != "a@y.test,devnull@localhost" || got["info@x.test"] != "info@x.test" || got["old@x.test"] != "" {
		t.Fatalf("valias: %v", got)
	}
	if len(vr) != 1 || vr[0][0] != "old@x.test" || !strings.HasPrefix(vr[0][1], "REJECT") {
		t.Fatalf("vreject: %v", vr)
	}
	if err := e.a.dropIdentityAlias(ctx, "info@x.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.mailForwardDelete(ctx, rpc.MailForwardRef{Owner: "tenant", Source: "old@x.test"}); err != nil {
		t.Fatal(err)
	}
	va, _ = readMap(filepath.Join(e.a.postfixDir(), "valias"), " ")
	vr, _ = readMap(filepath.Join(e.a.postfixDir(), "vreject"), " ")
	if len(va) != 1 || len(vr) != 0 {
		t.Fatalf("after delete: valias=%v vreject=%v", va, vr)
	}
}

// CODE-27: DB actions enforce the owner prefix when the API names the owner.
func TestDBOwnerPrefix(t *testing.T) {
	if err := checkOwned("alice", "bob_db", "db_prefix_required"); code(err) != "db_prefix_required" {
		t.Fatal(err)
	}
	if err := checkOwned("alice", "alice_db", "db_prefix_required"); err != nil {
		t.Fatal(err)
	}
	if err := checkOwned("", "bob_db", "x"); code(err) != "owner_required" {
		t.Fatal(err) // the owner is mandatory since v0.2
	}
	e := newTestEnv(t)
	if _, err := e.a.dbDrop(context.Background(), rpc.DBRef{Owner: "alice", Name: "bob_db"}); code(err) != "db_prefix_required" {
		t.Fatalf("dbDrop: %v", err)
	}
	if _, err := e.a.dbGrant(context.Background(), rpc.DBGrant{Owner: "alice", DB: "alice_db", User: "bob_u", Privileges: []string{"ALL"}}); code(err) != "invalid_db_user" {
		t.Fatalf("dbGrant: %v", err)
	}
}

// SEC-3 / CODE-3: restore goes through a root-owned staging dir and is
// copied into the home as the account. Uses the real restic binary when present.
func TestBackupRestoreStaging(t *testing.T) {
	restic, err := exec.LookPath("restic")
	if err != nil {
		t.Skip("restic not installed")
	}
	e := newTestEnv(t)
	e.a.Cfg.ResticBin = restic
	ctx := context.Background()
	if err := os.MkdirAll(filepath.Join(e.home, "public_html", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.home, "public_html", "sub", "a.txt"), []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := e.a.backupRun(ctx, rpc.BackupRun{User: "tenant"})
	if err != nil {
		t.Fatal(err)
	}
	snap := res.SnapshotIDs[0]
	if err := os.WriteFile(filepath.Join(e.home, "public_html", "sub", "a.txt"), []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	// glob characters and escapes are refused
	for _, p := range []string{"public_html/*", "a[b]", "x?"} {
		if _, err := e.a.backupRestore(ctx, rpc.BackupRestore{User: "tenant", Snapshot: snap, Path: p}); code(err) != "invalid_path" {
			t.Errorf("path %q: %v", p, err)
		}
	}
	out, err := e.a.backupRestore(ctx, rpc.BackupRestore{User: "tenant", Snapshot: snap, Path: "public_html/sub"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.RestoredTo, filepath.Join(e.home, "backups", "restore-")) {
		t.Fatalf("restored to %q", out.RestoredTo)
	}
	b, err := os.ReadFile(filepath.Join(out.RestoredTo, "sub", "a.txt"))
	if err != nil || string(b) != "v1" {
		t.Fatalf("restored content %q %v", b, err)
	}
	if _, err := e.a.backupRestore(ctx, rpc.BackupRestore{User: "tenant", Snapshot: snap, Path: "public_html/sub", InPlace: true}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(e.home, "public_html", "sub", "a.txt")); string(b) != "v1" {
		t.Fatalf("in-place content %q", b)
	}
	ents, _ := os.ReadDir(e.a.Cfg.RestoreDir)
	if len(ents) != 0 {
		t.Fatalf("staging not cleaned: %v", ents)
	}
}

// CODE-14: the agent cancels an action when the client hangs up, serves one
// request per connection and refuses oversized lines.
func TestHandleConnCancelOnClose(t *testing.T) {
	e := newTestEnv(t)
	started := make(chan struct{})
	cancelled := make(chan struct{})
	e.a.routes["test.block"] = func(ctx context.Context, _ json.RawMessage) (any, error) {
		close(started)
		select {
		case <-ctx.Done():
			close(cancelled)
			return nil, ctx.Err()
		case <-time.After(10 * time.Second):
			return nil, errors.New("not cancelled")
		}
	}
	e.a.Cfg.AllowedUIDs = []int{os.Getuid()}
	e.a.testExempt = map[string]bool{"test.block": true}
	sock := filepath.Join(t.TempDir(), "a.sock")
	e.a.Cfg.Socket = sock
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	go func() { _ = e.a.Serve(ctx) }()
	var c net.Conn
	var err error
	for i := 0; i < 100; i++ {
		if c, err = net.Dial("unix", sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte(`{"v":1,"id":1,"method":"test.block","params":{}}` + "\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("request not dispatched")
	}
	_ = c.Close()
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("action not cancelled after the client closed the connection")
	}
	// round trip through the real client
	cl := rpc.NewClient(sock)
	var pr rpc.PingResult
	if err := cl.Call(context.Background(), rpc.MPing, rpc.Empty{}, &pr); err != nil || pr.Version == "" {
		t.Fatalf("ping: %+v %v", pr, err)
	}
	if err := cl.Call(context.Background(), "no.such.method", rpc.Empty{}, nil); code(err) != "unknown_method" {
		t.Fatalf("unknown method: %v", err)
	}
}

// Every route rejects unknown fields (no smuggled input).
func TestAllRoutesRejectUnknownFields(t *testing.T) {
	a := New(DefaultConfig(), nil, nil)
	for m, h := range a.routes {
		if m == rpc.MPing || m == rpc.MSysInfo || m == rpc.MPHPVersions {
			continue // rpc.Empty params
		}
		if _, err := h(context.Background(), json.RawMessage(`{"zzz_unknown":1}`)); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Errorf("%s accepted an unknown field: %v", m, err)
		}
	}
}

func TestQuotaUnsupportedClassification(t *testing.T) {
	for _, s := range []string{"setquota: Cannot find mountpoint for device", "No filesystem with quota support found", "quotas are not enabled",
		// setquota 4.09 on overlayfs/fuse (containers):
		"setquota: Mountpoint (or device) / not found or has no quota enabled.\nsetquota: Not all specified mountpoints are using quota."} {
		if !quotaUnsupported(s) {
			t.Errorf("%q not classified", s)
		}
	}
	if quotaUnsupported("setquota: invalid user") {
		t.Error("real error classified as unsupported")
	}
}

func bufioReader(r io.Reader) *bufio.Reader { return bufio.NewReaderSize(r, 16) }

func TestReadLineLimit(t *testing.T) {
	r := strings.NewReader(strings.Repeat("x", 300) + "\n")
	if _, err := readLine(bufioReader(r), 100); err == nil {
		t.Fatal("oversized line accepted")
	}
	if l, err := readLine(bufioReader(strings.NewReader("abc\n")), 100); err != nil || string(l) != "abc\n" {
		t.Fatal(l, err)
	}
}

// H-5: nginx version parsing for the http2 directive.
func TestNginxHTTP2Version(t *testing.T) {
	for v, want := range map[string]bool{"nginx version: nginx/1.24.0": false, "nginx version: nginx/1.25.1": true,
		"nginx version: nginx/1.26.3 (Debian)": true, "nginx version: nginx/2.0": true, "garbage": false, "nginx version: nginx/1.25.0": false} {
		if got := nginxHTTP2On(v); got != want {
			t.Errorf("%q -> %v", v, got)
		}
	}
}

// SYS-5 / H-2: the minimal profile renders nginx-only vhosts and never tests Apache.
func TestMinimalProfileNginxOnly(t *testing.T) {
	e := newTestEnv(t)
	e.a.Cfg.Profile = "minimal"
	var tested []string
	e.a.configTestFn = func(_ context.Context, unit string) error { tested = append(tested, unit); return nil }
	if _, err := e.a.vhostApply(context.Background(), rpc.Vhost{User: "tenant", Domain: "m.test", DocRoot: "public_html", PHPVersion: "8.3", Mode: "nginx-apache"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.base, "apache", "m.test.conf")); err == nil {
		t.Fatal("apache vhost written on minimal")
	}
	for _, u := range tested {
		if u == e.a.L.ApacheUnit {
			t.Fatal("apache config tested on minimal")
		}
	}
	b, _ := os.ReadFile(filepath.Join(e.base, "nginx", "m.test.conf"))
	if strings.Contains(string(b), "8080") {
		t.Fatal("nginx proxies to apache on minimal")
	}
}
