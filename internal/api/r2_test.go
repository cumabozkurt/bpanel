package api

// Round-2 backend fixes (R2-PERF-*, R2-E2E-*, R2-UX-* server side).
//   go test ./internal/api -run 'TestR2' -v
//   go test -race ./internal/api -run 'TestR2'

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/auth"
	"github.com/cumabozkurt/bpanel/internal/store"
)

func adminLogin(t *testing.T, e *env) *sess {
	t.Helper()
	s, code := e.login(e.admin, "rootadmin", "Admin-Pass-123", "", "")
	if s == nil {
		t.Fatalf("admin login: %d", code)
	}
	return s
}

// ---- G1 ----------------------------------------------------------------------

func TestR2LimitJSON(t *testing.T) {
	var p PackageReq
	if err := json.Unmarshal([]byte(`{"name":"x","disk_mb":null,"max_ftp":0,"max_db":-1,"max_email":5}`), &p); err != nil {
		t.Fatal(err)
	}
	pk := p.asPackage()
	if pk.DiskMB != -1 || pk.MaxFTP != 0 || pk.MaxDB != -1 || pk.MaxEmail != 5 || pk.MaxDomains != -1 {
		t.Fatalf("%+v", pk)
	}
	if err := json.Unmarshal([]byte(`{"disk_mb":"10"}`), &p); err == nil {
		t.Fatal("string limit accepted")
	}
	if err := json.Unmarshal([]byte(`{"disk_mb":1.5}`), &p); err == nil {
		t.Fatal("fractional limit accepted")
	}
}

func TestR2G1Semantics(t *testing.T) {
	e := newEnv(t)
	s := adminLogin(t, e)
	// size limits refuse 0, counts accept it
	code, m := s.call("POST", "/api/v1/admin/packages", map[string]any{"name": "zero", "disk_mb": 0})
	if code != 400 || m["error"] != "invalid_limit" || m["field"] != "disk_mb" {
		t.Fatalf("disk 0: %d %v", code, m)
	}
	code, m = s.call("POST", "/api/v1/admin/packages", map[string]any{"name": "huge", "disk_mb": 9999999999999999})
	if code != 400 || m["field"] != "disk_mb" || m["max"] == nil {
		t.Fatalf("huge disk: %d %v", code, m)
	}
	code, m = s.call("POST", "/api/v1/admin/packages", map[string]any{"name": "noftp", "disk_mb": 1000, "max_ftp": 0, "max_db": nil})
	if code != 200 {
		t.Fatalf("create: %d %v", code, m)
	}
	pid := int64(m["id"].(float64))
	var ftp, db int64
	_ = e.srv.Store.DB.QueryRow(`SELECT max_ftp, max_db FROM packages WHERE id=?`, pid).Scan(&ftp, &db)
	if ftp != 0 || db != -1 {
		t.Fatalf("stored ftp=%d db=%d", ftp, db)
	}
	// 0 FTP accounts = FTP not allowed
	u, _, err := e.srv.CreateAccount(context.Background(), &e.root, CreateAccountReq{Username: "noftp", Domain: "noftp.test", Password: tPW, PackageID: pid})
	if err != nil {
		t.Fatal(err)
	}
	us := mustLogin(t, e, e.user, u.Username, "")
	code, m = us.call("POST", "/api/v1/user/ftp", map[string]any{"login": "a", "domain": "noftp.test", "password": tPW})
	if code != 409 || m["error"] != "limit_reached" {
		t.Fatalf("ftp with max_ftp=0: %d %v", code, m)
	}
	// -1 databases = unlimited
	for i := 0; i < 3; i++ {
		if code, m := us.call("POST", "/api/v1/user/databases", map[string]any{"name": fmt.Sprintf("d%d", i)}); code != 200 {
			t.Fatalf("db %d: %d %v", i, code, m)
		}
	}
	// summary reports -1 for unlimited
	_, sm := us.call("GET", "/api/v1/user/summary", nil)
	b, _ := json.Marshal(sm)
	if !strings.Contains(string(b), `"databases"`) {
		t.Fatalf("summary: %s", b)
	}
	// mailbox quota 0 refused, -1 accepted, capped by the package disk
	code, m = us.call("POST", "/api/v1/user/email/accounts", map[string]any{"local": "a", "domain": "noftp.test", "password": tPW, "quota_mb": 0})
	if code != 400 || m["field"] != "quota_mb" {
		t.Fatalf("mailbox quota 0: %d %v", code, m)
	}
	code, m = us.call("POST", "/api/v1/user/email/accounts", map[string]any{"local": "b", "domain": "noftp.test", "password": tPW, "quota_mb": 5000})
	if code != 400 || m["error"] != "invalid_limit" {
		t.Fatalf("mailbox quota above disk: %d %v", code, m)
	}
	if code, m := us.call("POST", "/api/v1/user/email/accounts", map[string]any{"local": "c", "domain": "noftp.test", "password": tPW, "quota_mb": -1}); code != 200 {
		t.Fatalf("unlimited mailbox: %d %v", code, m)
	}
	// the agent still gets 0 for "no limit"
	for _, c := range e.ag.find(rpc.MMailboxCreate) {
		if strings.Contains(string(c.Params), `"c@noftp.test"`) && !strings.Contains(string(c.Params), `"quota_mb":0`) {
			t.Fatalf("agent quota: %s", c.Params)
		}
	}
}

// ---- R2-UX-02/03 ---------------------------------------------------------------

func TestR2ResellerScope(t *testing.T) {
	e := newEnv(t)
	_, _, err := e.srv.CreateAccount(context.Background(), &e.root, CreateAccountReq{Username: "rsell", Domain: "rsell.test", Password: tPW,
		PackageID: e.pkg(), Role: "reseller", MaxAccounts: LimitOf(5)})
	if err != nil {
		t.Fatal(err)
	}
	r := mustLogin(t, e, e.admin, "rsell", "")
	full := map[string]any{"name": "own", "disk_mb": 10, "max_domains": 1, "max_subdomains": 1, "max_aliases": 1, "max_email": 1,
		"max_db": 1, "max_ftp": 1, "cpu_percent": 10, "memory_mb": 64, "max_tasks": 10}
	if code, m := r.call("POST", "/api/v1/admin/packages", full); code != 200 || m["prefixed"] != true {
		t.Fatalf("own package: %d %v", code, m)
	}
	w := e.do(e.admin, req{method: "GET", path: "/api/v1/admin/packages"}, r)
	var pk []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &pk)
	if len(pk) != 1 || pk[0]["name"] != "rsell_own" {
		t.Fatalf("reseller sees: %s", w.Body.String())
	}
	code, m := r.call("POST", "/api/v1/admin/accounts", map[string]any{"username": "rx", "domain": "rx.test", "password": tPW, "package_id": e.pkg(), "role": "reseller"})
	if code != 403 || m["error"] != "reseller_cannot_create_reseller" || m["field"] != "role" {
		t.Fatalf("reseller creating reseller: %d %v", code, m)
	}
	_, sm := r.call("GET", "/api/v1/admin/summary", nil)
	if _, ok := sm["resellers"]; ok || sm["packages"].(float64) != 1 {
		t.Fatalf("reseller summary: %v", sm)
	}
}

// ---- R2-UX-10 / UX-40: over-length values ------------------------------------------

func TestR2OverLengthRejected(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	a := adminLogin(t, e)
	s := mustLogin(t, e, e.user, "alice", "")
	cases := []struct {
		s           *sess
		method, url string
		body        map[string]any
		field       string
	}{
		{a, "POST", "/api/v1/admin/packages", map[string]any{"name": strings.Repeat("p", 65)}, "name"},
		{a, "POST", "/api/v1/admin/accounts", map[string]any{"username": strings.Repeat("u", 17), "domain": "x.test", "password": tPW, "package_id": e.pkg()}, "username"},
		{a, "POST", "/api/v1/admin/accounts/1/suspend", map[string]any{"reason": strings.Repeat("r", 501)}, "reason"},
		{s, "POST", "/api/v1/user/email/accounts", map[string]any{"local": strings.Repeat("l", 64), "domain": "alice.test", "password": tPW}, "local"},
		{s, "POST", "/api/v1/user/ftp", map[string]any{"login": strings.Repeat("f", 33), "domain": "alice.test", "password": tPW}, "login"},
		{s, "POST", "/api/v1/user/databases", map[string]any{"name": strings.Repeat("d", 70)}, "name"},
		{s, "POST", "/api/v1/user/cron", map[string]any{"minute": "*", "hour": "*", "dom": "*", "month": "*", "dow": "*", "command": strings.Repeat("c", 1001)}, "command"},
		{s, "POST", "/api/v1/user/domains", map[string]any{"kind": "addon", "name": "x.test", "docroot": strings.Repeat("d", 129)}, "docroot"},
	}
	for _, c := range cases {
		code, m := c.s.call(c.method, c.url, c.body)
		if code != 400 || m["error"] != "too_long" || m["field"] != c.field || m["max"] == nil {
			t.Errorf("%s %s: %d %v", c.method, c.url, code, m)
		}
	}
	if n := e.srv.count(`SELECT COUNT(*) FROM packages WHERE name LIKE 'ppp%'`); n != 0 {
		t.Fatal("a truncated package was stored")
	}
	// password over 256 bytes
	code, m := s.call("POST", "/api/v1/user/email/accounts", map[string]any{"local": "x", "domain": "alice.test", "password": strings.Repeat("Aa1", 100)})
	if code != 400 || m["error"] != "password_too_long" || m["max"] != float64(256) {
		t.Fatalf("long password: %d %v", code, m)
	}
}

// ---- R2-UX-11/12/13/16/18: names and paths ---------------------------------------

func TestR2NamesAndPaths(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	s := mustLogin(t, e, e.user, "alice", "")
	for name, want := range map[string]string{"😀.test": "invalid_idn", "com.tr": "public_suffix", "http://x.test": "invalid_domain"} {
		code, m := s.call("POST", "/api/v1/user/domains", map[string]any{"kind": "addon", "name": name})
		if code != 400 || m["error"] != want || m["field"] != "name" {
			t.Errorf("domain %q: %d %v", name, code, m)
		}
	}
	// trailing dot and IDN are normalised
	code, m := s.call("POST", "/api/v1/user/domains", map[string]any{"kind": "addon", "name": "Çiçek.Test."})
	if code != 200 || m["name"] != "xn--iek-1lab.test" {
		t.Fatalf("idn addon: %d %v", code, m)
	}
	// a 200+ character domain gets a shortened docroot
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + ".test"
	code, m = s.call("POST", "/api/v1/user/domains", map[string]any{"kind": "addon", "name": long})
	if code != 200 || len(m["docroot"].(string)) > 128 {
		t.Fatalf("long domain: %d %v", code, m)
	}
	// FTP private dirs
	for _, d := range []string{"etc", "mail", "logs/x", "ssl", "backups", "tmp"} {
		code, m := s.call("POST", "/api/v1/user/ftp", map[string]any{"login": "f", "domain": "alice.test", "password": tPW, "dir": d})
		if code != 400 || m["error"] != "private_dir" || m["field"] != "dir" {
			t.Errorf("ftp dir %s: %d %v", d, code, m)
		}
	}
	// 300-character file name
	code, m = s.call("POST", "/api/v1/user/files", map[string]any{"op": "touch", "path": "public_html/" + strings.Repeat("n", 300)})
	if code != 400 || m["error"] != "invalid_filename" {
		t.Fatalf("long file name: %d %v", code, m)
	}
	code, m = s.call("POST", "/api/v1/user/files", map[string]any{"op": "rename", "path": "public_html", "dest": ".."})
	if code != 400 || m["error"] != "invalid_filename" || m["field"] != "dest" {
		t.Fatalf("rename to ..: %d %v", code, m)
	}
}

func TestR2RecordName(t *testing.T) {
	for in, want := range map[string]string{
		"":                  "alice.test",
		"@":                 "alice.test",
		"alice.test.":       "alice.test",
		"www":               "www.alice.test",
		"www.alice.test":    "www.alice.test",
		"www.alice.test.":   "www.alice.test",
		"evil.example.org.": "evil.example.org",
		"evil.example.org":  "evil.example.org.alice.test",
		"_dmarc":            "_dmarc.alice.test",
		"*.shop":            "*.shop.alice.test",
		"çiçek":             "xn--iek-1lab.alice.test",
	} {
		if got := recordName("alice.test", in); got != want {
			t.Errorf("recordName(%q) = %q, want %q", in, got, want)
		}
	}
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	s := mustLogin(t, e, e.user, "alice", "")
	code, m := s.call("PUT", "/api/v1/user/dns/alice.test/rrset", map[string]any{"name": "evil.example.org.", "type": "A", "ttl": 300, "records": []string{"192.0.2.1"}})
	if code != 400 || m["error"] != "record_outside_zone" {
		t.Fatalf("FQDN outside the zone: %d %v", code, m)
	}
	code, m = s.call("PUT", "/api/v1/user/dns/alice.test/rrset", map[string]any{"name": "www.alice.test.", "type": "A", "ttl": 300, "records": []string{"192.0.2.1"}})
	if code != 200 {
		t.Fatalf("FQDN inside the zone: %d %v", code, m)
	}
}

// ---- R2-UX-22/23 --------------------------------------------------------------------

func TestR2WrongCurrentPasswordAndTOTPSpaces(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	s := mustLogin(t, e, e.user, "alice", "")
	code, m := s.call("POST", "/api/v1/account/password", map[string]any{"current": "Wrong-Pass-123", "new": "New-Pass-2026x"})
	if code != 400 || m["error"] != "wrong_current_password" || m["field"] != "current" {
		t.Fatalf("wrong current: %d %v", code, m)
	}
	for in, want := range map[string]string{"123 456": "123456", " 123456 ": "123456", "123-456": "123456", "123\u00a0456": "123456"} {
		if got := normTOTP(in); got != want {
			t.Errorf("normTOTP(%q) = %q", in, got)
		}
	}
	// end to end: enable TOTP and log in with a spaced code
	_, setup := s.call("POST", "/api/v1/account/totp/setup", nil)
	secret, _ := setup["secret"].(string)
	if secret == "" {
		t.Skipf("totp setup: %v", setup)
	}
	c := auth.TOTPCode(secret, time.Now())
	spaced := c[:3] + " " + c[3:]
	if code, m := s.call("POST", "/api/v1/account/totp/enable", map[string]any{"code": spaced}); code != 200 {
		t.Fatalf("enable with spaced code: %d %v", code, m)
	}
}

// ---- R2-E2E-6: DNS reset keeps subdomain and addon records -------------------------

func TestR2ZoneResetKeepsSubdomains(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	s := mustLogin(t, e, e.user, "alice", "")
	var mainID int64
	_ = e.srv.Store.DB.QueryRow(`SELECT id FROM domains WHERE name='alice.test'`).Scan(&mainID)
	if code, m := s.call("POST", "/api/v1/user/domains", map[string]any{"kind": "sub", "name": "blog", "parent_id": mainID}); code != 200 {
		t.Fatalf("sub: %d %v", code, m)
	}
	e.ag.reset()
	if code, m := s.call("POST", "/api/v1/user/dns/alice.test/reset", nil); code != 200 {
		t.Fatalf("reset: %d %v", code, m)
	}
	zc := e.ag.find(rpc.MDNSZoneCreate)
	if len(zc) != 1 {
		t.Fatalf("zone calls: %d", len(zc))
	}
	var z rpc.DNSZone
	_ = json.Unmarshal(zc[0].Params, &z)
	found := false
	for _, r := range z.Records {
		if r.Name == "blog.alice.test" && r.Type == "A" {
			found = true
		}
	}
	if !found || !z.Replace {
		t.Fatalf("subdomain record dropped by the reset: %+v", z.Records)
	}
}

// ---- R2-PERF-8: server-side paging ------------------------------------------------

func TestR2Paging(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 7; i++ {
		e.tenant(fmt.Sprintf("pg%d", i), fmt.Sprintf("pg%d.test", i))
	}
	a := adminLogin(t, e)
	w := e.do(e.admin, req{method: "GET", path: "/api/v1/admin/accounts?limit=3&offset=2"}, a)
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || len(rows) != 3 || rows[0]["username"] != "pg2" {
		t.Fatalf("page: %s", w.Body.String())
	}
	if w.Header().Get("X-Total-Count") != "7" {
		t.Fatalf("total %q", w.Header().Get("X-Total-Count"))
	}
	w = e.do(e.admin, req{method: "GET", path: "/api/v1/admin/accounts?q=PG5"}, a)
	_ = json.Unmarshal(w.Body.Bytes(), &rows)
	if len(rows) != 1 || w.Header().Get("X-Total-Count") != "1" {
		t.Fatalf("q: %s", w.Body.String())
	}
	w = e.do(e.admin, req{method: "GET", path: "/api/v1/admin/accounts?status=suspended"}, a)
	_ = json.Unmarshal(w.Body.Bytes(), &rows)
	if len(rows) != 0 {
		t.Fatalf("status filter: %s", w.Body.String())
	}
	// no limit: the whole array, as before
	w = e.do(e.admin, req{method: "GET", path: "/api/v1/admin/accounts"}, a)
	_ = json.Unmarshal(w.Body.Bytes(), &rows)
	if len(rows) != 7 {
		t.Fatalf("unpaged: %d", len(rows))
	}
}

// ---- R2-PERF-2: audit search via FTS -----------------------------------------------

func TestR2AuditSearch(t *testing.T) {
	e := newEnv(t)
	a := adminLogin(t, e)
	// the audit row is written by the HTTP handler, not by CreateAccount
	// itself, so the account is created through the API (v0.3 test fix)
	if code, m := a.call("POST", "/api/v1/admin/accounts", map[string]any{"username": "alice", "domain": "alice.test", "password": tPW, "package_id": e.pkg()}); code != 200 {
		t.Fatalf("create: %d %v", code, m)
	}
	for _, q := range []string{"alice", "ccount.cre", "al"} {
		w := e.do(e.admin, req{method: "GET", path: "/api/v1/admin/audit?q=" + q}, a)
		var rows []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || len(rows) == 0 {
			t.Errorf("q=%s: %d %s", q, w.Code, w.Body.String())
		}
	}
	w := e.do(e.admin, req{method: "GET", path: `/api/v1/admin/audit?q=%22%29%20OR%20*`}, a)
	if w.Code != 200 {
		t.Fatalf("FTS syntax in q: %d %s", w.Code, w.Body.String())
	}
}

// ---- R2-PERF-15: optimistic locking -----------------------------------------------

func TestR2PackageVersionConflict(t *testing.T) {
	e := newEnv(t)
	a := adminLogin(t, e)
	pid := e.pkg()
	body := map[string]any{"name": "default", "disk_mb": 2000}
	w := e.do(e.admin, req{method: "PUT", path: fmt.Sprintf("/api/v1/admin/packages/%d", pid), body: body, headers: map[string]string{"If-Match": `"1"`}}, a)
	if w.Code != 200 || w.Header().Get("ETag") != `"2"` {
		t.Fatalf("first edit: %d %s %q", w.Code, w.Body.String(), w.Header().Get("ETag"))
	}
	w = e.do(e.admin, req{method: "PUT", path: fmt.Sprintf("/api/v1/admin/packages/%d", pid), body: body, headers: map[string]string{"If-Match": `"1"`}}, a)
	if w.Code != 412 || !strings.Contains(w.Body.String(), "version_conflict") || w.Header().Get("ETag") != `"2"` {
		t.Fatalf("stale edit: %d %s", w.Code, w.Body.String())
	}
	body["version"] = 2
	if code, m := a.call("PUT", fmt.Sprintf("/api/v1/admin/packages/%d", pid), body); code != 200 || m["version"] != float64(3) {
		t.Fatalf("version in body: %d %v", code, m)
	}
	// without a version: unconditional, as before
	delete(body, "version")
	if code, _ := a.call("PUT", fmt.Sprintf("/api/v1/admin/packages/%d", pid), body); code != 200 {
		t.Fatal("unconditional edit refused")
	}
}

// ---- R2-PERF-9: one quota batch per package edit ---------------------------------

func TestR2QuotaBatch(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 5; i++ {
		e.tenant(fmt.Sprintf("qb%d", i), fmt.Sprintf("qb%d.test", i))
	}
	a := adminLogin(t, e)
	e.ag.reset()
	if code, m := a.call("PUT", fmt.Sprintf("/api/v1/admin/packages/%d", e.pkg()), map[string]any{"name": "default", "disk_mb": 3000}); code != 200 {
		t.Fatalf("edit: %d %v", code, m)
	}
	if n := len(e.ag.find(rpc.MAccountQuota)); n != 0 {
		t.Fatalf("%d per-account quota calls", n)
	}
	b := e.ag.find(rpc.MAccountQuotaBatch)
	if len(b) != 1 || strings.Count(string(b[0].Params), `"user"`) != 5 {
		t.Fatalf("batch: %v", b)
	}
	// an older agent: per-account fallback
	e.ag.fail[rpc.MAccountQuotaBatch] = &rpc.Error{Code: "unknown_method"}
	e.ag.reset()
	if code, _ := a.call("PUT", fmt.Sprintf("/api/v1/admin/packages/%d", e.pkg()), map[string]any{"name": "default", "disk_mb": 4000}); code != 200 {
		t.Fatal("edit with old agent")
	}
	if n := len(e.ag.find(rpc.MAccountQuota)); n != 5 {
		t.Fatalf("fallback calls: %d", n)
	}
}

// ---- R2-PERF-1: bounded argon2 --------------------------------------------------

func TestR2HashGate(t *testing.T) {
	g := newGate(2)
	r1, ok1 := g.acquire(context.Background(), 0)
	r2, ok2 := g.acquire(context.Background(), 0)
	if !ok1 || !ok2 {
		t.Fatal("slots")
	}
	start := time.Now()
	if _, ok := g.acquire(context.Background(), 50*time.Millisecond); ok {
		t.Fatal("third slot granted")
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Fatal("did not wait")
	}
	r1()
	if r3, ok := g.acquire(context.Background(), time.Second); !ok {
		t.Fatal("freed slot not granted")
	} else {
		r3()
	}
	r2()
	// a full gate answers 503 server_busy with Retry-After
	e := newEnv(t)
	e.srv.hashGate = newGate(1)
	rel, _ := e.srv.hashGate.acquire(context.Background(), 0)
	defer rel()
	w := e.do(e.user, req{method: "POST", path: "/api/v1/auth/login", body: map[string]string{"username": "x", "password": "y"}}, nil)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "server_busy") || w.Header().Get("Retry-After") == "" {
		t.Fatalf("busy login: %d %s %v", w.Code, w.Body.String(), w.Header())
	}
}

func TestR2ConcurrentLoginsRace(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := e.do(e.user, req{method: "POST", path: "/api/v1/auth/login", body: map[string]string{"username": "alice", "password": tPW}, ip: fmt.Sprintf("198.51.100.%d", i+10)}, nil)
			mu.Lock()
			codes[w.Code]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	for c := range codes {
		if c != 200 && c != 503 {
			t.Fatalf("codes: %v", codes)
		}
	}
}

// ---- R2-PERF-3: upload slots -----------------------------------------------------

func TestR2UploadGate(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	s := mustLogin(t, e, e.user, "alice", "")
	e.srv.uploadGate = newGate(1)
	rel, _ := e.srv.uploadGate.acquire(context.Background(), 0)
	var body bytes.Buffer
	body.WriteString("--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\nhello\r\n--b--\r\n")
	w := e.do(e.user, req{method: "POST", path: "/api/v1/user/files/upload?path=public_html", raw: &body, ctype: "multipart/form-data; boundary=b"}, s)
	if w.Code != 503 {
		t.Fatalf("upload with no slot: %d %s", w.Code, w.Body.String())
	}
	rel()
	p := getChunk(1 << 20)
	if len(*p) != 1<<20 {
		t.Fatal("chunk size")
	}
	putChunk(p)
}

// ---- R2-PERF-5: stale provisioning rows rolled back at start --------------------

func TestR2StartupReconcile(t *testing.T) {
	e := newEnv(t)
	u := e.tenant("stale", "stale.test")
	if _, err := e.srv.Store.DB.Exec(`UPDATE users SET status='provisioning', created_at=? WHERE id=?`, time.Now().Add(-time.Minute).Unix(), u.ID); err != nil {
		t.Fatal(err)
	}
	e.srv.startedAt = time.Now()
	e.srv.reconcileStartup(context.Background())
	if n := e.srv.count(`SELECT COUNT(*) FROM users WHERE username='stale'`); n != 0 {
		t.Fatal("stale provisioning row survived the startup reconcile")
	}
	// a row created by this process is left alone
	u2 := e.tenant("fresh", "fresh.test")
	if _, err := e.srv.Store.DB.Exec(`UPDATE users SET status='provisioning', created_at=? WHERE id=?`, time.Now().Add(time.Second).Unix(), u2.ID); err != nil {
		t.Fatal(err)
	}
	e.srv.reconcileStartup(context.Background())
	if n := e.srv.count(`SELECT COUNT(*) FROM users WHERE username='fresh'`); n != 1 {
		t.Fatal("in-flight row removed")
	}
}

// ---- R2-PERF-7: gzip -------------------------------------------------------------

func TestR2Gzip(t *testing.T) {
	e := newEnv(t)
	a := adminLogin(t, e)
	w := e.do(e.admin, req{method: "GET", path: "/api/v1/admin/packages", headers: map[string]string{"Accept-Encoding": "gzip, br"}}, a)
	if w.Header().Get("Content-Encoding") != "gzip" || !strings.Contains(w.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatalf("headers: %v", w.Header())
	}
	zr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(zr)
	if !strings.Contains(string(b), `"default"`) {
		t.Fatalf("body: %s", b)
	}
	w = e.do(e.admin, req{method: "GET", path: "/api/v1/admin/packages", headers: map[string]string{"Accept-Encoding": "gzip;q=0"}}, a)
	if w.Header().Get("Content-Encoding") != "" {
		t.Fatal("gzip despite q=0")
	}
}

// ---- R2-PERF-11: log sampling -------------------------------------------------------

func TestR2Sampler(t *testing.T) {
	sm := newSampler(10 * time.Second)
	now := time.Unix(0, 0)
	sm.now = func() time.Time { return now }
	if ok, _ := sm.allow("k"); !ok {
		t.Fatal("first")
	}
	for i := 0; i < 100; i++ {
		if ok, _ := sm.allow("k"); ok {
			t.Fatal("not sampled")
		}
	}
	now = now.Add(11 * time.Second)
	if ok, n := sm.allow("k"); !ok || n != 100 {
		t.Fatalf("after window: %v %d", ok, n)
	}
}

// ---- R2-PERF-13 / R2-PERF-4: error mapping ---------------------------------------

func TestR2ErrorMapping(t *testing.T) {
	if agentStatus("disk_full") != 507 || agentStatus("quota_exceeded") != 507 || agentStatus("snapshot_kind_mismatch") != 422 || agentStatus("private_dir") != 400 {
		t.Fatal("status mapping")
	}
}

// ---- R2-PERF-16: sysinfo cache ------------------------------------------------------

func TestR2SysInfoCache(t *testing.T) {
	e := newEnv(t)
	a := adminLogin(t, e)
	e.ag.reset()
	for i := 0; i < 5; i++ {
		a.call("GET", "/api/v1/admin/summary", nil)
	}
	if n := len(e.ag.find(rpc.MSysInfo)); n != 1 {
		t.Fatalf("sysinfo calls: %d", n)
	}
}

// ---- terminate retry after the Linux account is gone --------------------------------

func TestR2TerminateIgnoresGoneUser(t *testing.T) {
	e := newEnv(t)
	u := e.tenant("gone", "gone.test")
	us := mustLogin(t, e, e.user, "gone", "")
	if code, _ := us.call("POST", "/api/v1/user/databases", map[string]any{"name": "x"}); code != 200 {
		t.Fatal("db")
	}
	e.ag.fail[rpc.MDBDrop] = &rpc.Error{Code: "no_such_user"}
	if err := e.srv.TerminateAccount(context.Background(), &u); err != nil {
		t.Fatalf("terminate: %v", err)
	}
	if n := e.srv.count(`SELECT COUNT(*) FROM users WHERE username='gone'`); n != 0 {
		t.Fatal("row left")
	}
}

var _ = store.IsBusy
var _ http.Handler
