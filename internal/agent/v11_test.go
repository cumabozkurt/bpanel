// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

func TestV11LogStatsAndLeech(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if err := e.a.claim(kindWeb, "stats.test", "tenant", ""); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format("02/Jan/2006:15:04:05 -0700")
	log := ""
	for i, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"} {
		log += ip + ` - alice [` + now + `] "GET /members/p` + string(rune('a'+i)) + `.html HTTP/1.1" 200 100 "-" "Mozilla/5.0 Firefox/130.0"` + "\n"
	}
	log += `198.51.100.1 - - [` + now + `] "GET / HTTP/1.1" 200 5000 "https://ref.example/x" "Mozilla/5.0 (Windows NT 10.0) Chrome/129.0 Safari/537.36"` + "\n"
	if err := os.MkdirAll(e.a.domlogDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.a.domlogDir, "stats.test.access.log"), []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := e.a.logStats(ctx, rpc.LogStatsParams{User: "tenant", Domain: "stats.test"})
	if err != nil || st.Status != "ok" || len(st.Days) != 1 || st.Days[0].Visitors != 5 || st.Days[0].Hits != 5 || len(st.Recent) != 5 {
		t.Fatalf("%+v %v", st, err)
	}
	// another account's domain and an unregistered one are refused (never adopted)
	if err := e.a.claim(kindWeb, "other.test", "someoneelse", ""); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"other.test", "unknown.test"} {
		if _, err := e.a.logStats(ctx, rpc.LogStatsParams{User: "tenant", Domain: d}); code(err) != "owned_by_another_account" {
			t.Errorf("%s: %v", d, err)
		}
	}
	if _, ok, _ := e.a.readOwner(kindWeb, "unknown.test"); ok {
		t.Fatal("read-only stats adopted an unregistered domain")
	}
	if _, err := e.a.logStats(ctx, rpc.LogStatsParams{User: "tenant", Domain: "../etc"}); code(err) != "invalid_domain" {
		t.Errorf("traversal: %v", err)
	}
	lr, err := e.a.leechScan(ctx, rpc.LeechScanParams{User: "tenant", Domain: "stats.test", Paths: []string{"/members/"}, Window: 7200})
	if err != nil || len(lr.Hits) != 1 || lr.Hits[0].IPs != 4 || lr.Hits[0].Login != "alice" {
		t.Fatalf("leech %+v %v", lr, err)
	}
	if _, err := e.a.leechScan(ctx, rpc.LeechScanParams{User: "tenant", Domain: "stats.test", Paths: []string{"/../"}}); code(err) != "bad_params" {
		t.Errorf("leech path: %v", err)
	}
	// missing log
	if err := e.a.claim(kindWeb, "nolog.test", "tenant", ""); err != nil {
		t.Fatal(err)
	}
	if st, err := e.a.logStats(ctx, rpc.LogStatsParams{User: "tenant", Domain: "nolog.test"}); err != nil || st.Status != "no_log" {
		t.Fatalf("no log: %+v %v", st, err)
	}
}

func TestV11SSHKeys(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	g, err := e.a.sshKeyGenerate(ctx, rpc.SSHKeyGenerateParams{User: "tenant", Name: "id_ed25519", Type: "ed25519", Authorize: true})
	if err != nil || !strings.Contains(g.PrivateKey, "OPENSSH PRIVATE KEY") || !g.Key.Authorized {
		t.Fatalf("%+v %v", g, err)
	}
	if fi, err := os.Stat(filepath.Join(e.home, ".ssh", "id_ed25519")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode: %v %v", fi, err)
	}
	if _, err := e.a.sshKeyGenerate(ctx, rpc.SSHKeyGenerateParams{User: "tenant", Name: "id_ed25519"}); code(err) != "ssh_key_exists" {
		t.Errorf("duplicate: %v", err)
	}
	for _, bad := range []string{"../x", ".hidden", "authorized_keys", "a b"} {
		if _, err := e.a.sshKeyImport(ctx, rpc.SSHKeyImportParams{User: "tenant", Name: bad, PublicKey: g.Key.PublicKey}); code(err) != "ssh_invalid_name" {
			t.Errorf("name %q: %v", bad, err)
		}
	}
	if _, err := e.a.sshKeyImport(ctx, rpc.SSHKeyImportParams{User: "tenant", Name: "junk", PublicKey: "ssh-rsa AAAA garbage"}); code(err) != "ssh_invalid_key" {
		t.Errorf("junk key: %v", err)
	}
	// a hand-added authorized key shows up as authorized_keys:N
	auth := filepath.Join(e.home, ".ssh", "authorized_keys")
	b, _ := os.ReadFile(auth)
	extra := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl hand@made\n"
	if err := os.WriteFile(auth, append(b, []byte(extra)...), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := e.a.sshKeyList(ctx, rpc.SSHKeyListParams{User: "tenant"})
	if err != nil || len(l.Keys) != 2 || l.Keys[0].Name != "authorized_keys:2" || !l.Keys[1].HasPrivate {
		t.Fatalf("list %+v %v", l, err)
	}
	if _, err := e.a.sshKeyAuthorize(ctx, rpc.SSHKeyRef{User: "tenant", Name: "id_ed25519", Authorize: false}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(auth)
	if strings.Contains(string(b), strings.Fields(g.Key.PublicKey)[1]) || !strings.Contains(string(b), "hand@made") {
		t.Fatalf("deauthorize left:\n%s", b)
	}
	if _, err := e.a.sshKeyDelete(ctx, rpc.SSHKeyRef{User: "tenant", Name: "id_ed25519"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.home, ".ssh", "id_ed25519")); !os.IsNotExist(err) {
		t.Fatal("private key not deleted")
	}
	// symlinked ~/.ssh is refused
	_ = os.RemoveAll(filepath.Join(e.home, ".ssh"))
	if err := os.Symlink(e.outside, filepath.Join(e.home, ".ssh")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.sshKeyGenerate(ctx, rpc.SSHKeyGenerateParams{User: "tenant", Name: "k2"}); err == nil {
		t.Fatal("wrote through a symlinked ~/.ssh")
	}
	if ents, _ := os.ReadDir(e.outside); len(ents) != 0 {
		t.Fatalf("files escaped: %v", ents)
	}
}

func TestV11ParsersAndValidation(t *testing.T) {
	total, msgs := ParsePostqueueJSON(`{"queue_name":"deferred","queue_id":"4F2A1C0B3D","arrival_time":1760000000,"message_size":1234,"sender":"a@x.test","recipients":[{"address":"b@y.test","delay_reason":"connect timed out"}]}
{"queue_name":"hold","queue_id":"BAD ID","arrival_time":1}
{"queue_name":"active","queue_id":"5A1B2C3D4E","arrival_time":1760000100,"message_size":10,"sender":"","recipients":[]}
not json`, 10)
	if total != 2 || len(msgs) != 2 || msgs[0].ID != "5A1B2C3D4E" || msgs[1].Recipients[0].Reason != "connect timed out" {
		t.Fatalf("%d %+v", total, msgs)
	}
	h := RewriteHosts("127.0.0.1 localhost\n127.0.1.1 old.example.com old\n# old.example.com\n", "old.example.com", "new.example.org")
	if !strings.Contains(h, "127.0.1.1 new.example.org new\n") || !strings.Contains(h, "# old.example.com") {
		t.Fatalf("hosts:\n%s", h)
	}
	if h := RewriteHosts("127.0.0.1 localhost\n", "", "panel.example.com"); !strings.HasSuffix(h, "127.0.1.1 panel.example.com panel\n") {
		t.Fatalf("hosts add:\n%s", h)
	}
	keys := ParseGPGColons(`tru::1:1760000000:0:3:1:5
pub:u:255:22:ABCDEF0123456789:1760000000:1823072000::u:::scESC:::::ed25519:::0:
fpr:::::::::0123456789ABCDEF0123456789ABCDEF01234567:
uid:u::::1760000000::HASH::Jane Doe <jane@x.test>::::::::::0:
sub:u:255:18:1111111111111111:1760000000::::::e:::::cv25519::
fpr:::::::::1111111111111111111111111111111111111111:
`, false)
	if len(keys) != 1 || keys[0].Fingerprint != "0123456789ABCDEF0123456789ABCDEF01234567" || keys[0].UIDs[0] != "Jane Doe <jane@x.test>" || keys[0].Algo != "EdDSA" {
		t.Fatalf("%+v", keys)
	}
	for _, bad := range []rpc.NetIPParams{{IP: "127.0.0.2", Prefix: 8, Dev: "eth0"}, {IP: "192.0.2.10", Prefix: 33, Dev: "eth0"},
		{IP: "192.0.2.10", Prefix: 24, Dev: "eth0;reboot"}, {IP: "fe80::1", Prefix: 64, Dev: "eth0"}, {IP: "192.0.2.10", Prefix: 24, Dev: "lo"}} {
		if _, err := ValidIPParams(bad); code(err) != "invalid_ip" {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if pf, err := ValidIPParams(rpc.NetIPParams{IP: "192.0.2.10", Prefix: 24, Dev: "eth0"}); err != nil || pf.String() != "192.0.2.10/24" {
		t.Fatalf("%v %v", pf, err)
	}
}

func TestV11MailQueueAndHostnameWithFakes(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	var calls [][]string
	oldCmd, oldHave := v11Cmd, v11Have
	t.Cleanup(func() { v11Cmd, v11Have = oldCmd, oldHave })
	v11Have = func(string) bool { return true }
	v11Cmd = func(_ context.Context, stdin []byte, argv ...string) (string, error) {
		calls = append(calls, append(append([]string{}, argv...), string(stdin)))
		if argv[0] == "postqueue" && argv[1] == "-j" {
			return `{"queue_name":"deferred","queue_id":"4F2A1C0B3D","arrival_time":1,"message_size":1,"sender":"a@x.test","recipients":[]}` + "\n", nil
		}
		if argv[0] == "postsuper" {
			return "postsuper: Deleted: 1 message\n", nil
		}
		return "", nil
	}
	l, err := e.a.mailQueueList(ctx, rpc.MailQueueListParams{})
	if err != nil || l.Total != 1 {
		t.Fatalf("%+v %v", l, err)
	}
	r, err := e.a.mailQueueAction(ctx, rpc.MailQueueActionParams{Action: "delete", IDs: []string{"4F2A1C0B3D"}})
	if err != nil || r.Affected != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	last := calls[len(calls)-1]
	if strings.Join(last[:3], " ") != "postsuper -d -" || last[3] != "4F2A1C0B3D\n" {
		t.Fatalf("argv %q", last)
	}
	for _, bad := range []rpc.MailQueueActionParams{{Action: "delete", IDs: []string{"-r ALL"}}, {Action: "rm", IDs: []string{"4F2A1C0B3D"}}, {Action: "delete"}} {
		if _, err := e.a.mailQueueAction(ctx, bad); code(err) != "bad_params" {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if _, err := e.a.mailQueueShow(ctx, rpc.MailQueueShowParams{ID: "../x"}); code(err) != "bad_params" {
		t.Errorf("show: %v", err)
	}
	// hostname without systemd: /etc/hostname + /etc/hosts + postconf
	dir := t.TempDir()
	oldH, oldN, oldS := hostsFile, hostnameFile, sethostname
	t.Cleanup(func() { hostsFile, hostnameFile, sethostname = oldH, oldN, oldS })
	hostsFile, hostnameFile = filepath.Join(dir, "hosts"), filepath.Join(dir, "hostname")
	oldAPI := APIConfigPath
	t.Cleanup(func() { APIConfigPath = oldAPI })
	APIConfigPath = filepath.Join(dir, "api.json")
	_ = os.WriteFile(APIConfigPath, []byte(`{"hostname":"old.example.com","user_port":2083}`), 0o640)
	sethostname = func(string) error { return nil }
	_ = os.WriteFile(hostsFile, []byte("127.0.0.1 localhost\n"), 0o644)
	if _, err := e.a.sysHostname(ctx, rpc.SysHostnameParams{Hostname: "bad_host"}); code(err) != "invalid_hostname" {
		t.Errorf("bad hostname: %v", err)
	}
	res, err := e.a.sysHostname(ctx, rpc.SysHostnameParams{Hostname: "Panel.Example.COM."})
	if err != nil || res.Hostname != "panel.example.com" {
		t.Fatalf("%+v %v", res, err)
	}
	if b, _ := os.ReadFile(hostnameFile); string(b) != "panel.example.com\n" {
		t.Fatalf("hostname file %q", b)
	}
	if b, _ := os.ReadFile(APIConfigPath); !strings.Contains(string(b), `"hostname": "panel.example.com"`) || !strings.Contains(string(b), `"user_port": 2083`) {
		t.Fatalf("api.json %s", b)
	}
	last = calls[len(calls)-1]
	if strings.Join(last[:3], " ") != "postconf -e myhostname=panel.example.com" {
		t.Fatalf("postconf argv %q", last)
	}
}

func TestV11MailRoutingAndDav(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	oldT, oldDir, oldUsers, oldConf, oldHave := MlmmjTransport, DavDir, DavUsersFile, DavConfig, v11Have
	t.Cleanup(func() {
		MlmmjTransport, DavDir, DavUsersFile, DavConfig, v11Have = oldT, oldDir, oldUsers, oldConf, oldHave
	})
	MlmmjTransport = filepath.Join(e.base, "postfix", "bpanel", "transport")
	if err := e.a.claim(kindMail, "mail.test", "tenant", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.mailRoutingSet(ctx, rpc.MailRoutingParams{User: "tenant", Domain: "mail.test", Mode: "sideways"}); code(err) != "bad_params" {
		t.Errorf("mode: %v", err)
	}
	if err := e.a.claim(kindMail, "theirs.test", "other", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.mailRoutingSet(ctx, rpc.MailRoutingParams{User: "tenant", Domain: "theirs.test", Mode: "remote"}); code(err) != "owned_by_another_account" {
		t.Errorf("foreign: %v", err)
	}
	if _, err := e.a.mailRoutingSet(ctx, rpc.MailRoutingParams{User: "tenant", Domain: "mail.test", Mode: "remote"}); err != nil {
		t.Fatal(err)
	}
	if got := e.a.routingLines(); got != "mail.test smtp:\n" {
		t.Fatalf("routing %q", got)
	}
	if _, err := e.a.mailRoutingSet(ctx, rpc.MailRoutingParams{User: "tenant", Domain: "mail.test", Mode: "local"}); err != nil {
		t.Fatal(err)
	}
	if got := e.a.routingLines(); got != "" {
		t.Fatalf("routing after local %q", got)
	}
	// DAV: logins of the account's own mail domains only; rendered htpasswd
	DavDir, DavUsersFile, DavConfig = filepath.Join(e.base, "dav"), filepath.Join(e.base, "radicale", "users"), filepath.Join(e.base, "radicale", "config")
	v11Have = func(b string) bool { return b == "radicale" }
	hash := "$2y$10$" + strings.Repeat("a", 53)
	if _, err := e.a.davSync(ctx, rpc.DavSyncParams{User: "tenant", Logins: []rpc.DavLogin{{Name: "x@theirs.test", Hash: hash}}}); code(err) != "owned_by_another_account" {
		t.Errorf("foreign dav: %v", err)
	}
	if _, err := e.a.davSync(ctx, rpc.DavSyncParams{User: "tenant", Logins: []rpc.DavLogin{{Name: "a@mail.test:x", Hash: hash}}}); code(err) != "bad_params" {
		t.Errorf("bad dav login: %v", err)
	}
	st, err := e.a.davSync(ctx, rpc.DavSyncParams{User: "tenant", Logins: []rpc.DavLogin{{Name: "a@mail.test", Hash: hash}}})
	if err != nil || st.Status != "active" || st.Users != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	if b, _ := os.ReadFile(DavUsersFile); string(b) != "a@mail.test:"+hash+"\n" {
		t.Fatalf("users %q", b)
	}
	if b, _ := os.ReadFile(DavConfig); !strings.Contains(string(b), "htpasswd_encryption = bcrypt") || !strings.Contains(string(b), "127.0.0.1:5232") {
		t.Fatalf("config %q", b)
	}
	if st, err := e.a.davSync(ctx, rpc.DavSyncParams{User: "tenant"}); err != nil || st.Users != 0 {
		t.Fatalf("%+v %v", st, err)
	}
}
