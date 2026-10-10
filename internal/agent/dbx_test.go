// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

type pgCall struct {
	name  string
	args  []string
	stdin string
}

func fakePG(t *testing.T, reply string) *[]pgCall {
	t.Helper()
	var calls []pgCall
	oe, of := pgExec, pgFind
	pgExec = func(ctx context.Context, name string, args []string, stdin string) (string, error) {
		calls = append(calls, pgCall{name, args, stdin})
		return reply, nil
	}
	pgFind = func(tool string) string { return "/usr/lib/postgresql/16/bin/" + tool }
	t.Cleanup(func() { pgExec, pgFind = oe, of })
	return &calls
}

func TestRemoteDBHostValidation(t *testing.T) {
	ok := map[string]string{
		"203.0.113.7": "203.0.113.7", "10.1.0.0/16": "10.1.0.0/255.255.0.0", "192.0.2.0/24": "192.0.2.0/255.255.255.0",
		"198.51.100.9/32": "198.51.100.9", "2001:db8::1": "2001:db8::1", "2001:db8::1/128": "2001:db8::1",
		" App.Example.COM ": "app.example.com", "::ffff:192.0.2.1": "192.0.2.1",
	}
	for in, want := range ok {
		got, err := validate.RemoteDBHost(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q %v want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "%", "10.0.0.%", "a_b.example.com", "localhost", "db.localhost", "127.0.0.1", "::1", "0.0.0.0",
		"0.0.0.0/0", "10.0.0.0/4", "10.0.0.1/24", "2001:db8::/64", "x'@'%", "host\n", "a b.com", "intranet", "-a.example.com",
		"1.2.3.999", "evil.com`", strings.Repeat("a", 58) + ".com", "fe80::1%eth0", "224.0.0.1"} {
		if got, err := validate.RemoteDBHost(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}

func TestDBXOwnershipChecks(t *testing.T) {
	a := &Agent{}
	ctx := context.Background()
	// all refused before any database connection is attempted
	cases := []rpc.DBXRemoteSync{
		{Owner: "", Hosts: nil},
		{Owner: "alice", Hosts: []string{"%"}},
		{Owner: "alice", Users: []rpc.DBXRemoteUser{{User: "bob_x"}}},
		{Owner: "alice", Users: []rpc.DBXRemoteUser{{User: "alice_x", Grants: []rpc.DBXGrant{{DB: "bob_db", Privileges: []string{"ALL"}}}}}},
		{Owner: "alice", Users: []rpc.DBXRemoteUser{{User: "alice_x", Grants: []rpc.DBXGrant{{DB: "alice_db", Privileges: []string{"SUPER"}}}}}},
		{Owner: "alice", Users: []rpc.DBXRemoteUser{{User: "alice_x`; DROP"}}},
		{Owner: "alice", MaxConn: -1},
		{Owner: "alice", Hosts: make([]string, 17)},
	}
	for i, c := range cases {
		if _, err := a.dbxRemoteSync(ctx, c); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if _, err := a.dbxKill(ctx, rpc.DBXKill{Owner: "alice", Engine: "mariadb", ID: 0}); err == nil {
		t.Error("kill id 0 accepted")
	}
	if _, err := a.dbxKill(ctx, rpc.DBXKill{Owner: "alice", Engine: "oracle", ID: 5}); err == nil {
		t.Error("unknown engine accepted")
	}
	if likePrefix("a_b") != `a\_b\_%` {
		t.Errorf("likePrefix: %s", likePrefix("a_b"))
	}
}

func TestPGCreateUsesVariablesNotInterpolation(t *testing.T) {
	calls := fakePG(t, "")
	a := &Agent{}
	ctx := context.Background()
	pw := "S3cret-pass'; DROP ROLE x; --"
	if _, err := a.pgCreate(ctx, rpc.PGDB{Owner: "alice", Name: "alice_app", Password: pw, MaxConn: 5}); err != nil {
		t.Fatal(err)
	}
	c := (*calls)[0]
	all := strings.Join(c.args, " ") + c.stdin
	if strings.Contains(all, pw) || strings.Contains(all, "S3cret") {
		t.Fatal("clear-text password reached psql")
	}
	if c.stdin != pgCreateScript || strings.Contains(c.stdin, "alice_app") {
		t.Fatalf("script is not the constant: %q", c.stdin)
	}
	want := []string{"-u", "postgres", "--", "/usr/lib/postgresql/16/bin/psql", "-X"}
	for i, w := range want {
		if c.args[i] != w {
			t.Fatalf("argv %v", c.args)
		}
	}
	joined := strings.Join(c.args, "\x00")
	for _, w := range []string{"ON_ERROR_STOP=1", "db=alice_app", "role=alice_app", "connlimit=5"} {
		if !strings.Contains(joined, w) {
			t.Errorf("missing %s in %v", w, c.args)
		}
	}
	if !strings.Contains(c.stdin, `REVOKE ALL ON DATABASE :"db" FROM PUBLIC`) || !strings.Contains(c.stdin, "NOSUPERUSER") {
		t.Error("least-privilege statements missing")
	}
	// injection / foreign names refused before psql runs
	n := len(*calls)
	for _, name := range []string{"bob_app", "alice_a\"b", "alice_A", "alice_" + strings.Repeat("x", 60), "alice"} {
		if _, err := a.pgCreate(ctx, rpc.PGDB{Owner: "alice", Name: name, Password: "Abcdefgh1"}); err == nil {
			t.Errorf("%q accepted", name)
		}
		if _, err := a.pgDrop(ctx, rpc.PGDB{Owner: "alice", Name: name}); err == nil {
			t.Errorf("drop %q accepted", name)
		}
	}
	if _, err := a.pgCreate(ctx, rpc.PGDB{Owner: "alice", Name: "alice_b", Password: "short"}); err == nil {
		t.Error("short password accepted")
	}
	if _, err := a.pgCreate(ctx, rpc.PGDB{Owner: "alice", Name: "alice_b", Password: "pässwörd-long"}); err == nil {
		t.Error("non-ascii password accepted")
	}
	if len(*calls) != n {
		t.Errorf("psql ran for refused input")
	}
}

func TestSCRAMVerifierFormat(t *testing.T) {
	v, err := scramVerifier("correct horse")
	if err != nil || !reVerifier.MatchString(v) {
		t.Fatalf("%q %v", v, err)
	}
	// recompute StoredKey from the salt: proves the RFC 5802 derivation
	parts := strings.Split(strings.TrimPrefix(v, "SCRAM-SHA-256$4096:"), "$")
	salt, _ := base64.StdEncoding.DecodeString(parts[0])
	keys := strings.Split(parts[1], ":")
	salted, _ := pbkdf2.Key(sha256.New, "correct horse", salt, 4096, 32)
	h := hmac.New(sha256.New, salted)
	h.Write([]byte("Client Key"))
	st := sha256.Sum256(h.Sum(nil))
	if base64.StdEncoding.EncodeToString(st[:]) != keys[0] {
		t.Error("stored key mismatch")
	}
}

func TestPGNotInstalledAndOwnFilters(t *testing.T) {
	of := pgFind
	pgFind = func(string) string { return "" }
	st, _ := (&Agent{}).pgStatus(context.Background(), rpc.Empty{})
	if st.Status != "not_installed" {
		t.Errorf("status %v", st)
	}
	pgFind = of
	// rows of other owners are dropped even if the server returned them
	fakePG(t, "1"+pgSep+"alice_app"+pgSep+""+pgSep+"alice_app"+pgSep+"active"+pgSep+""+pgSep+"42"+pgSep+"SELECT 1"+pgRec+
		"2"+pgSep+"bob_app"+pgSep+""+pgSep+"bob_app"+pgSep+"active"+pgSep+""+pgSep+"9"+pgSep+"SELECT 2"+pgRec)
	ps, s := pgProcs(context.Background(), "alice")
	if s.Status != "ok" || len(ps) != 1 || ps[0].User != "alice_app" || ps[0].Seconds != 42 {
		t.Errorf("procs %v %v", ps, s)
	}
	calls := fakePG(t, "alice_app"+pgSep+"8192"+pgRec+"bob_x"+pgSep+"1"+pgRec)
	sz, err := (&Agent{}).pgSizes(context.Background(), rpc.PGSizesReq{Owner: "alice"})
	if err != nil || len(sz.Sizes) != 1 || sz.Sizes["alice_app"] != 8192 {
		t.Errorf("sizes %v %v", sz, err)
	}
	if !strings.Contains(strings.Join((*calls)[0].args, " "), `pat=alice\_%`) {
		t.Errorf("pattern %v", (*calls)[0].args)
	}
	fakePG(t, "")
	if err := pgKill(context.Background(), "alice", 77); err == nil {
		t.Error("kill of a non-owned pid reported success")
	}
}
