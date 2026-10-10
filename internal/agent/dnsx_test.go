// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/distro"
)

type dnsxFake struct {
	calls [][]string
	fail  map[string]error
	out   map[string]string
}

func newDnsxEnv(t *testing.T, installed bool) (*Agent, *dnsxFake, string) {
	t.Helper()
	d := t.TempDir()
	f := &dnsxFake{fail: map[string]error{}, out: map[string]string{}}
	oh, or, os_, ot, orl := dnsxHave, dnsxRun, MlmmjSpool, MlmmjTransport, dnsxReloadPostfx
	t.Cleanup(func() { dnsxHave, dnsxRun, MlmmjSpool, MlmmjTransport, dnsxReloadPostfx = oh, or, os_, ot, orl })
	dnsxHave = func(string) bool { return installed }
	dnsxRun = func(ctx context.Context, _ []byte, argv ...string) (string, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Errorf("no timeout for %v", argv)
		}
		f.calls = append(f.calls, argv)
		key := argv[0] + " " + argv[1]
		return f.out[key], f.fail[key]
	}
	dnsxReloadPostfx = func(a *Agent, ctx context.Context) error { return f.fail["reload"] }
	MlmmjSpool = filepath.Join(d, "spool")
	MlmmjTransport = filepath.Join(d, "postfix", "bpanel_mlmmj_transport")
	a := New(Config{OwnersDir: filepath.Join(d, "owners"), NetsecDir: filepath.Join(d, "ns"), NoSystemd: true}, &distro.Layout{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return a, f, d
}

func TestDNSSECAgent(t *testing.T) {
	a, f, _ := newDnsxEnv(t, true)
	if err := a.claim(kindZone, "bob.test", "bob", ""); err != nil {
		t.Fatal(err)
	}
	f.out["pdnsutil show-zone"] = "keys:\nID = 1 (CSK), flags = 257, tag = 9, algo = 13\nDS = bob.test. IN DS 9 13 2 aa ; ( SHA256 digest )\n"
	st, err := a.dnssec(context.Background(), rpc.DNSSECReq{Owner: "bob", Zone: "bob.test", Action: "enable"})
	if err != nil || st.Status != "active" || len(st.DS) != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	if got := strings.Join(f.calls[0], " "); got != "pdnsutil secure-zone bob.test" {
		t.Errorf("argv %q", got)
	}
	// another account's zone is refused before any command runs
	n := len(f.calls)
	if _, err := a.dnssec(context.Background(), rpc.DNSSECReq{Owner: "mallory", Zone: "bob.test", Action: "enable"}); err == nil || !strings.Contains(err.Error(), "another account") {
		t.Errorf("foreign: %v", err)
	}
	if _, err := a.dnssec(context.Background(), rpc.DNSSECReq{Owner: "bob", Zone: "bob.test; rm -rf /", Action: "status"}); err == nil {
		t.Error("bad zone accepted")
	}
	if len(f.calls) != n {
		t.Error("command ran for refused request")
	}
	f.fail["pdnsutil secure-zone"] = errors.New("boom")
	if _, err := a.dnssec(context.Background(), rpc.DNSSECReq{Owner: "bob", Zone: "bob.test", Action: "enable"}); err == nil {
		t.Error("failure hidden")
	}
	a2, _, _ := newDnsxEnv(t, false)
	_ = a2.claim(kindZone, "bob.test", "bob", "")
	if st, err := a2.dnssec(context.Background(), rpc.DNSSECReq{Owner: "bob", Zone: "bob.test", Action: "status"}); err != nil || st.Status != "not_installed" {
		t.Errorf("not installed: %+v %v", st, err)
	}
}

func TestMailingListAgent(t *testing.T) {
	a, f, _ := newDnsxEnv(t, true)
	_ = a.claim(kindMail, "bob.test", "bob", "")
	ctx := context.Background()
	req := rpc.ListReq{User: "bob", Domain: "bob.test", Name: "news", Owner: "b@bob.test", Action: "create"}
	if _, err := a.listApply(ctx, req); err != nil {
		t.Fatal(err)
	}
	m, _ := os.ReadFile(MlmmjTransport)
	if !strings.Contains(string(m), "news@bob.test mlmmj:bob.test/news\n") {
		t.Errorf("map: %s", m)
	}
	if b, _ := os.ReadFile(filepath.Join(MlmmjSpool, "bob.test", "news", "control", "listaddress")); string(b) != "news@bob.test\n" {
		t.Errorf("listaddress %q", b)
	}
	if _, err := a.listApply(ctx, req); err == nil {
		t.Error("duplicate accepted")
	}
	// foreign domain / traversal refused
	if _, err := a.listApply(ctx, rpc.ListReq{User: "mallory", Domain: "bob.test", Name: "x", Owner: "m@m.test", Action: "create"}); err == nil {
		t.Error("foreign domain")
	}
	if _, err := a.listApply(ctx, rpc.ListReq{User: "bob", Domain: "bob.test", Name: "../../etc", Owner: "b@bob.test", Action: "create"}); err == nil {
		t.Error("traversal")
	}
	// rollback: reload failure restores the map and removes the new list
	f.fail["reload"] = errors.New("reload failed")
	if _, err := a.listApply(ctx, rpc.ListReq{User: "bob", Domain: "bob.test", Name: "two", Owner: "b@bob.test", Action: "create"}); err == nil {
		t.Error("reload failure hidden")
	}
	m2, _ := os.ReadFile(MlmmjTransport)
	if string(m2) != string(m) {
		t.Errorf("map not restored: %s", m2)
	}
	if _, err := os.Stat(filepath.Join(MlmmjSpool, "bob.test", "two")); err == nil {
		t.Error("list dir left behind")
	}
	delete(f.fail, "reload")
	// subscribers: argv only, address validated
	f.out["mlmmj-list -L"] = "fan@example.org\n"
	st, err := a.listSubs(ctx, rpc.ListSubsReq{User: "bob", Domain: "bob.test", Name: "news", Action: "add", Address: "fan@example.org"})
	if err != nil || len(st.Subscribers) != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	if _, err := a.listSubs(ctx, rpc.ListSubsReq{User: "bob", Domain: "bob.test", Name: "news", Action: "add", Address: "-x@y.z"}); err == nil {
		t.Error("option injection")
	}
	if _, err := a.listApply(ctx, rpc.ListReq{User: "bob", Domain: "bob.test", Name: "news", Action: "delete"}); err != nil {
		t.Fatal(err)
	}
	if m3, _ := os.ReadFile(MlmmjTransport); strings.Contains(string(m3), "news@") {
		t.Error("deleted list still mapped")
	}
	a2, _, _ := newDnsxEnv(t, false)
	_ = a2.claim(kindMail, "bob.test", "bob", "")
	if st, err := a2.listApply(ctx, req); err != nil || st.Status != "not_installed" {
		t.Errorf("not installed: %+v %v", st, err)
	}
}
