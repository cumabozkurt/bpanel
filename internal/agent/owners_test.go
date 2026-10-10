package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// fakePDNS answers every zone as existing (GET) and accepts changes.
func fakePDNS(t *testing.T, e *testEnv) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			if strings.Contains(r.URL.Path, "missing") {
				w.WriteHeader(404)
				return
			}
			_ = json.NewEncoder(w).Encode(pdnsZone{Name: "x.", RRSets: []pdnsRRSet{}})
		case "POST":
			w.WriteHeader(201)
		default:
			w.WriteHeader(204)
		}
	}))
	t.Cleanup(srv.Close)
	e.a.Cfg.PDNSURL = srv.URL
}

// addTenant adds a second managed account "other" to the fake passwd.
func addTenant(t *testing.T, e *testEnv, name string) string {
	t.Helper()
	home := filepath.Join(e.base, "home", name)
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(passwdFile, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(name + ":x:" + itoa(os.Getuid()) + ":" + itoa(os.Getgid()) + "::" + home + ":/usr/sbin/nologin\n"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(e.a.Cfg.AccountsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"tenant", name} {
		if err := os.WriteFile(e.a.markerPath(u), []byte(u+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

// CODE-27: the agent keeps its own domain/zone/mail-domain ownership
// registry and refuses cross-account actions even when the API asks.
func TestOwnerRegistry(t *testing.T) {
	e := newTestEnv(t)
	addTenant(t, e, "other")
	fakePDNS(t, e)
	oldDKIM := DKIMDir
	DKIMDir = filepath.Join(e.base, "dkim")
	t.Cleanup(func() { DKIMDir = oldDKIM })
	ctx := context.Background()

	// tenant creates site, zone and mail domain for t.test
	if _, err := e.a.vhostApply(ctx, rpc.Vhost{User: "tenant", Domain: "t.test", Aliases: []string{"alias.test"}, DocRoot: "public_html"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.dnsZoneCreate(ctx, rpc.DNSZone{Owner: "tenant", Zone: "missing-t.test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.mailDomainEnable(ctx, rpc.MailDomain{User: "tenant", Domain: "t.test"}); err != nil {
		t.Fatal(err)
	}

	deny := func(what string, err error) {
		t.Helper()
		if code(err) != "owned_by_another_account" {
			t.Errorf("%s: got %v, want owned_by_another_account", what, err)
		}
	}
	// another account (or an API bug passing the wrong owner) cannot touch them
	_, err := e.a.vhostApply(ctx, rpc.Vhost{User: "other", Domain: "t.test", DocRoot: "public_html"})
	deny("vhost takeover", err)
	_, err = e.a.vhostApply(ctx, rpc.Vhost{User: "other", Domain: "o.test", Aliases: []string{"alias.test"}, DocRoot: "public_html"})
	deny("alias takeover", err)
	_, err = e.a.vhostApply(ctx, rpc.Vhost{User: "other", Domain: "sub.t.test", DocRoot: "public_html"})
	deny("subdomain under another account's domain", err)
	_, err = e.a.vhostRemove(ctx, rpc.DomainRef{Owner: "other", Domain: "t.test"})
	deny("vhost remove", err)
	_, err = e.a.dnsRRSetReplace(ctx, rpc.RRSet{Owner: "other", Zone: "missing-t.test", Name: "www.missing-t.test", Type: "A", Records: []string{"192.0.2.9"}})
	deny("rrset replace", err)
	_, err = e.a.dnsRRSetDelete(ctx, rpc.RRSetRef{Owner: "other", Zone: "missing-t.test", Name: "www.missing-t.test", Type: "A"})
	deny("rrset delete", err)
	_, err = e.a.dnsZoneGet(ctx, rpc.ZoneRef{Owner: "other", Zone: "missing-t.test"})
	deny("zone get", err)
	_, err = e.a.dnsZoneDelete(ctx, rpc.ZoneRef{Owner: "other", Zone: "missing-t.test"})
	deny("zone delete", err)
	_, err = e.a.dnsZoneCreate(ctx, rpc.DNSZone{Owner: "other", Zone: "missing-t.test", Replace: true})
	deny("zone reset", err)
	_, err = e.a.mailDomainEnable(ctx, rpc.MailDomain{User: "other", Domain: "t.test"})
	deny("mail domain enable", err)
	_, err = e.a.mailDomainDisable(ctx, rpc.MailDomain{User: "other", Domain: "t.test"})
	deny("mail domain disable", err)
	_, err = e.a.mailboxCreate(ctx, rpc.Mailbox{User: "other", Email: "spy@t.test", Password: "Mail-Pass-2026"})
	deny("mailbox create", err)
	_, err = e.a.mailboxPassword(ctx, rpc.Mailbox{User: "other", Email: "info@t.test", Password: "Mail-Pass-2026"})
	deny("mailbox password", err)
	_, err = e.a.mailboxQuota(ctx, rpc.Mailbox{User: "other", Email: "info@t.test", QuotaMB: 1})
	deny("mailbox quota", err)
	_, err = e.a.mailboxDelete(ctx, rpc.MailboxRef{User: "other", Email: "info@t.test"})
	deny("mailbox delete", err)
	_, err = e.a.mailForwardSet(ctx, rpc.MailForward{Owner: "other", Source: "@t.test", Destinations: []string{"spy@evil.test"}})
	deny("catch-all forwarder", err)
	_, err = e.a.mailForwardDelete(ctx, rpc.MailForwardRef{Owner: "other", Source: "info@t.test"})
	deny("forwarder delete", err)
	_, err = e.a.ftpCreate(ctx, rpc.FTPAccount{User: "other", Login: "x@t.test", Password: "Ftp-Pass-2026"})
	deny("ftp create", err)
	_, err = e.a.ftpDelete(ctx, rpc.FTPRef{Owner: "other", Login: "x@t.test"})
	deny("ftp delete", err)
	_, err = e.a.ftpPassword(ctx, rpc.FTPAccount{User: "other", Login: "x@t.test", Password: "Ftp-Pass-2026"})
	deny("ftp password", err)
	_, err = e.a.logTail(ctx, rpc.LogTail{User: "other", Domain: "t.test"})
	deny("log tail", err)
	_, err = e.a.sslIssue(ctx, rpc.SSLIssue{User: "other", Domain: "t.test"})
	deny("ssl issue", err)
	_, err = e.a.sslIssue(ctx, rpc.SSLIssue{Domain: "t.test"}) // owner-less (installer) only for unowned names
	deny("owner-less ssl issue", err)

	// the owner is mandatory
	if _, err := e.a.dnsZoneDelete(ctx, rpc.ZoneRef{Zone: "missing-t.test"}); code(err) != "owner_required" {
		t.Errorf("owner-less zone delete: %v", err)
	}
	if _, err := e.a.mailForwardSet(ctx, rpc.MailForward{Source: "@t.test", Destinations: []string{"a@b.test"}}); code(err) != "owner_required" {
		t.Errorf("owner-less forwarder: %v", err)
	}

	// the owner itself still can, and www.t.test is covered by t.test
	if _, err := e.a.mailForwardSet(ctx, rpc.MailForward{Owner: "tenant", Source: "@t.test", Destinations: []string{"a@b.test"}}); err != nil {
		t.Errorf("owner forwarder: %v", err)
	}
	if err := e.a.ownsAny("www.t.test", "tenant", kindWeb); err != nil {
		t.Errorf("covered name: %v", err)
	}
	if _, ok, _ := e.a.readOwner(kindWeb, "www.t.test"); ok {
		t.Error("covered name must not get its own (stale) entry")
	}

	// dropping the alias from the vhost releases it; removing the vhost,
	// zone and mail domain releases t.test for the next owner
	if _, err := e.a.vhostApply(ctx, rpc.Vhost{User: "tenant", Domain: "t.test", DocRoot: "public_html"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := e.a.readOwner(kindWeb, "alias.test"); ok {
		t.Error("alias not released after it was dropped from the vhost")
	}
	if _, err := e.a.vhostRemove(ctx, rpc.DomainRef{Owner: "tenant", Domain: "t.test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.mailDomainDisable(ctx, rpc.MailDomain{User: "tenant", Domain: "t.test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.vhostApply(ctx, rpc.Vhost{User: "other", Domain: "t.test", DocRoot: "public_html"}); err != nil {
		t.Fatalf("released name not claimable: %v", err)
	}
	if _, err := e.a.dnsZoneDelete(ctx, rpc.ZoneRef{Owner: "tenant", Zone: "missing-t.test"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := e.a.readOwner(kindZone, "missing-t.test"); ok {
		t.Error("zone entry not released")
	}

	// terminate releases everything the account held
	if _, err := e.a.mailDomainEnable(ctx, rpc.MailDomain{User: "other", Domain: "o2.test"}); err != nil {
		t.Fatal(err)
	}
	e.a.releaseAll("other")
	for _, n := range []string{"t.test", "o2.test"} {
		for _, k := range allKinds {
			if _, ok, _ := e.a.readOwner(k, n); ok {
				t.Errorf("%s/%s still registered after releaseAll", k, n)
			}
		}
	}
}

// CODE-27 migration: a name created before the registry existed is
// attributed from the agent's own vhost file, never adopted by someone else.
func TestOwnerRegistryImportFromVhost(t *testing.T) {
	e := newTestEnv(t)
	addTenant(t, e, "other")
	fakePDNS(t, e)
	ctx := context.Background()
	if _, err := e.a.vhostApply(ctx, rpc.Vhost{User: "tenant", Domain: "legacy.test", DocRoot: "public_html"}); err != nil {
		t.Fatal(err)
	}
	// simulate a v0.1 install: vhost on disk, no registry
	if err := os.RemoveAll(e.a.ownersDir()); err != nil {
		t.Fatal(err)
	}
	if got := e.a.inferOwner("legacy.test"); got != "tenant" {
		t.Fatalf("inferOwner = %q", got)
	}
	if _, err := e.a.dnsZoneCreate(ctx, rpc.DNSZone{Owner: "other", Zone: "legacy.test", Replace: true}); code(err) != "owned_by_another_account" {
		t.Fatalf("other account adopted a legacy zone: %v", err)
	}
	if _, err := e.a.mailForwardSet(ctx, rpc.MailForward{Owner: "other", Source: "@legacy.test", Destinations: []string{"spy@evil.test"}}); code(err) != "owned_by_another_account" {
		t.Fatalf("other account set a legacy forwarder: %v", err)
	}
	if _, err := e.a.dnsZoneCreate(ctx, rpc.DNSZone{Owner: "tenant", Zone: "legacy.test", Replace: true}); err != nil {
		t.Fatalf("owner reset: %v", err)
	}
	if o, ok, _ := e.a.readOwner(kindZone, "legacy.test"); !ok || o.Owner != "tenant" {
		t.Fatalf("legacy zone not adopted for its owner: %+v %v", o, ok)
	}
}

// handoff-ui H-4: an empty privilege list no longer means ALL PRIVILEGES.
func TestGrantPrivileges(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
		code string
	}{
		{nil, "", "invalid_privilege"},
		{[]string{}, "", "invalid_privilege"},
		{[]string{"ALL"}, "ALL PRIVILEGES", ""},
		{[]string{"all"}, "ALL PRIVILEGES", ""},
		{[]string{"ALL", "SELECT"}, "", "invalid_privilege"},
		{[]string{"SELECT", "INSERT", "SELECT"}, "SELECT, INSERT", ""},
		{[]string{"SELECT; DROP"}, "", "invalid_privilege"},
		{[]string{"GRANT OPTION"}, "", "invalid_privilege"},
	} {
		got, err := grantPrivileges(tc.in)
		if code(err) != tc.code || got != tc.want {
			t.Errorf("%v: got %q %v", tc.in, got, err)
		}
	}
}
