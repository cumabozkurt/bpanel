package api

// Regression tests for the 2026-10-09 audit (SEC-*, CODE-*): the PoCs from
// audit/poc/api plus the provisioning saga, limits, status codes, streaming
// file transfer, CSRF/XFF hardening and OpenAPI drift.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/auth"
	"github.com/cumabozkurt/bpanel/internal/fileops"
	"github.com/cumabozkurt/bpanel/internal/store"
)

const tPW = "Tenant-Pass-2026"

type call struct {
	Method string
	Params json.RawMessage
}

// fakeAgent records calls, can fail chosen methods and runs file operations
// against a temp directory with the real fileops code.
type fakeAgent struct {
	mu     sync.Mutex
	calls  []call
	fail   map[string]error
	exists map[string]bool
	homes  string
}

func (a *fakeAgent) Call(ctx context.Context, method string, params any, result any) error {
	b, _ := json.Marshal(params)
	a.mu.Lock()
	a.calls = append(a.calls, call{method, b})
	err := a.fail[method]
	a.mu.Unlock()
	if err != nil {
		return err
	}
	var out any
	if o, ok := fakeIsolation(method, b); ok { // isolation_test.go
		out = o
	}
	if o, ok, ferr := fakeShield(a, method, b); ok { // shield_test.go
		if ferr != nil {
			return ferr
		}
		out = o
	}
	if o, ok, ferr := fakeNetsec(method, b); ok { // netsec_test.go
		if ferr != nil {
			return ferr
		}
		out = o
	}
	if o, ok := fakeUsagex(method, b); ok { // usagex_test.go
		out = o
	}
	if o, ok := fakeBackupVerify(method, b); ok { // backup_verify_test.go
		out = o
	}
	if o, ok, ferr := fakeXfer(method, b); ok { // xfer_test.go
		if ferr != nil {
			return ferr
		}
		out = o
	}
	if o, ok := fakeDbx(method, b); ok { // dbx_test.go
		out = o
	}
	if o, ok, ferr := fakeDnsx(a, method, b); ok { // dnsx_test.go
		if ferr != nil {
			return ferr
		}
		out = o
	}
	switch method {
	case rpc.MAccountExists:
		var p rpc.AccountRef
		_ = json.Unmarshal(b, &p)
		out = rpc.AccountExistsResult{Exists: a.exists[p.User]}
	case rpc.MAccountCreate:
		var p rpc.AccountCreate
		_ = json.Unmarshal(b, &p)
		out = rpc.AccountCreateResult{UID: 1001, GID: 1001, Home: "/home/" + p.User, Created: true}
	case rpc.MSSLIssue:
		out = rpc.SSLInfo{Present: true, NotAfter: time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339)}
	case rpc.MFiles:
		var p rpc.FileOp
		_ = json.Unmarshal(b, &p)
		dir := filepath.Join(a.homes, p.User)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			return err
		}
		defer root.Close()
		r, err := fileops.Exec(root, p)
		if err != nil {
			return &rpc.Error{Code: err.Error(), Message: p.Path}
		}
		out = r
	}
	if out != nil && result != nil {
		ob, _ := json.Marshal(out)
		return json.Unmarshal(ob, result)
	}
	return nil
}

func (a *fakeAgent) methods() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var m []string
	for _, c := range a.calls {
		m = append(m, c.Method)
	}
	return m
}

func (a *fakeAgent) find(method string) []call {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []call
	for _, c := range a.calls {
		if c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

func (a *fakeAgent) reset() {
	a.mu.Lock()
	a.calls = nil
	a.mu.Unlock()
}

type env struct {
	t     *testing.T
	srv   *Server
	ag    *fakeAgent
	user  http.Handler
	admin http.Handler
	root  store.User
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := Bootstrap(st); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Hostname = "server.example.com"
	cfg.PlainHTTP = true
	ag := &fakeAgent{fail: map[string]error{}, exists: map[string]bool{}, homes: t.TempDir()}
	srv := New(cfg, st, ag, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	id, err := EnsureAdmin(context.Background(), st, "rootadmin", "Admin-Pass-123", "")
	if err != nil {
		t.Fatal(err)
	}
	root, err := srv.userByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	softDelay = func(int) {}
	return &env{t: t, srv: srv, ag: ag, user: srv.Handler(RealmUser), admin: srv.Handler(RealmAdmin), root: root}
}

func (e *env) pkg() int64 {
	var id int64
	if err := e.srv.Store.DB.QueryRow(`SELECT id FROM packages WHERE name='default'`).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *env) tenant(user, domain string) store.User {
	e.t.Helper()
	u, _, err := e.srv.CreateAccount(context.Background(), &e.root, CreateAccountReq{Username: user, Domain: domain, Password: tPW, PackageID: e.pkg()})
	if err != nil {
		e.t.Fatalf("create %s: %v", user, err)
	}
	return *u
}

type sess struct {
	e      *env
	h      http.Handler
	cookie *http.Cookie
	csrf   string
	ip     string
}

type req struct {
	method, path string
	body         any
	raw          io.Reader
	ctype        string
	headers      map[string]string
	ip           string
}

func (e *env) do(h http.Handler, r req, s *sess) *httptest.ResponseRecorder {
	var rd io.Reader = r.raw
	if r.body != nil {
		b, _ := json.Marshal(r.body)
		rd = bytes.NewReader(b)
	}
	hr := httptest.NewRequest(r.method, r.path, rd)
	ct := r.ctype
	if ct == "" {
		ct = "application/json"
	}
	hr.Header.Set("Content-Type", ct)
	for k, v := range r.headers {
		hr.Header.Set(k, v)
	}
	ip := r.ip
	if s != nil {
		hr.AddCookie(s.cookie)
		hr.Header.Set("X-CSRF-Token", s.csrf)
		if ip == "" {
			ip = s.ip
		}
	}
	if ip == "" {
		ip = "198.51.100.7"
	}
	hr.RemoteAddr = ip + ":40000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, hr)
	return w
}

func (e *env) login(h http.Handler, user, pw, totp, ip string) (*sess, int) {
	body := map[string]string{"username": user, "password": pw}
	if totp != "" {
		body["totp"] = totp
	}
	w := e.do(h, req{method: "POST", path: "/api/v1/auth/login", body: body, ip: ip}, nil)
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	if w.Code != 200 || m["csrf"] == nil {
		return nil, w.Code
	}
	for _, c := range w.Result().Cookies() {
		if strings.HasSuffix(c.Name, "_session") {
			if ip == "" {
				ip = "198.51.100.7"
			}
			return &sess{e: e, h: h, cookie: c, csrf: m["csrf"].(string), ip: ip}, 200
		}
	}
	return nil, w.Code
}

func (s *sess) call(method, path string, body any) (int, map[string]any) {
	w := s.e.do(s.h, req{method: method, path: path, body: body}, s)
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w.Code, m
}

func mustLogin(t *testing.T, e *env, h http.Handler, user, ip string) *sess {
	t.Helper()
	s, code := e.login(h, user, tPW, "", ip)
	if s == nil {
		t.Fatalf("login %s: %d", user, code)
	}
	return s
}

// ---- PoC regressions ---------------------------------------------------------

// SEC-1: docroots with config metacharacters are refused before the agent.
func TestSEC1DocrootRejected(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	s := mustLogin(t, e, e.user, "alice", "")
	var id int64
	_ = e.srv.Store.DB.QueryRow(`SELECT id FROM domains WHERE name='alice.test'`).Scan(&id)
	e.ag.reset()
	for _, dr := range []string{"public_html;\n}\nserver {", "a b", "mail", "logs/x", "x:y", `a"b`} {
		code, m := s.call("PUT", fmt.Sprintf("/api/v1/user/domains/%d", id), map[string]any{"docroot": dr})
		if code != 400 || (m["error"] != "invalid_docroot" && m["error"] != "private_dir") {
			t.Errorf("docroot %q: %d %v", dr, code, m)
		}
		code, _ = s.call("POST", "/api/v1/user/domains", map[string]any{"name": "new.test", "kind": "addon", "docroot": dr})
		if code != 400 {
			t.Errorf("create docroot %q: %d", dr, code)
		}
	}
	if n := len(e.ag.find(rpc.MVhostApply)); n != 0 {
		t.Fatalf("agent received %d vhost.apply calls", n)
	}
}

// SEC-6 / CODE-4: ownership of names across accounts and server names.
func TestSEC6DomainClaims(t *testing.T) {
	e := newEnv(t)
	e.tenant("victim", "victim.test")
	e.tenant("mallory", "mallory.test")
	s := mustLogin(t, e, e.user, "mallory", "")
	for _, name := range []string{"mail.victim.test", "a.b.victim.test", "server.example.com", "x.server.example.com",
		"ns1.example.com", "example.com"} {
		code, m := s.call("POST", "/api/v1/user/domains", map[string]any{"name": name, "kind": "addon"})
		if code == 200 {
			t.Errorf("mallory claimed %s", name)
		} else if code != 403 && code != 409 {
			t.Errorf("%s: unexpected %d %v", name, code, m)
		}
	}
	// a parent of another account's domain is refused too
	if _, _, err := e.srv.CreateAccount(context.Background(), &e.root, CreateAccountReq{Username: "sub", Domain: "shop.parent.test", Password: tPW, PackageID: e.pkg()}); err != nil {
		t.Fatal(err)
	}
	if code, _ := s.call("POST", "/api/v1/user/domains", map[string]any{"name": "parent.test", "kind": "addon"}); code != 409 {
		t.Errorf("parent of another account's domain: %d", code)
	}
	// own sub-names stay possible
	if code, m := s.call("POST", "/api/v1/user/domains", map[string]any{"name": "shop.mallory.test", "kind": "addon"}); code != 200 {
		t.Errorf("own addon: %d %v", code, m)
	}
	// resellers cannot create accounts on server names either
	if _, _, err := e.srv.CreateAccount(context.Background(), &e.root, CreateAccountReq{Username: "hostx", Domain: "server.example.com", Password: tPW, PackageID: e.pkg()}); err == nil {
		t.Error("account on the panel hostname")
	}
}

// SEC-12: forwarders die with their domain and never leak to the next owner.
func TestSEC12ForwardersRemovedWithDomain(t *testing.T) {
	e := newEnv(t)
	e.tenant("mallory", "mallory.test")
	e.tenant("bob", "bob.test")
	ms := mustLogin(t, e, e.user, "mallory", "")
	code, m := ms.call("POST", "/api/v1/user/domains", map[string]any{"name": "shared.test", "kind": "addon"})
	if code != 200 {
		t.Fatalf("addon: %d %v", code, m)
	}
	id := int64(m["id"].(float64))
	if code, m := ms.call("POST", "/api/v1/user/email/forwarders", map[string]any{"source": "info", "domain": "shared.test", "destination": "spy@evil.test"}); code != 200 {
		t.Fatalf("fwd: %d %v", code, m)
	}
	if code, m := ms.call("DELETE", fmt.Sprintf("/api/v1/user/domains/%d", id), nil); code != 200 {
		t.Fatalf("delete: %d %v", code, m)
	}
	if n := e.srv.count(`SELECT COUNT(*) FROM forwarders WHERE source LIKE '%@shared.test'`); n != 0 {
		t.Fatalf("%d stale forwarders", n)
	}
	if len(e.ag.find(rpc.MMailForwardDel)) == 0 {
		t.Fatal("forwarder not removed from Postfix")
	}
	bs := mustLogin(t, e, e.user, "bob", "198.51.100.8")
	if code, _ := bs.call("POST", "/api/v1/user/domains", map[string]any{"name": "shared.test", "kind": "addon"}); code != 200 {
		t.Fatal("bob addon")
	}
	if code, _ := bs.call("POST", "/api/v1/user/email/forwarders", map[string]any{"source": "info", "domain": "shared.test", "destination": "bob@bob.test"}); code != 200 {
		t.Fatal("bob fwd")
	}
	calls := e.ag.find(rpc.MMailForwardSet)
	var last rpc.MailForward
	_ = json.Unmarshal(calls[len(calls)-1].Params, &last)
	if !slices.Equal(last.Destinations, []string{"bob@bob.test"}) {
		t.Fatalf("destinations %v", last.Destinations)
	}
}

// SEC-17: TOTP codes are single use (login, enable and disable).
func TestSEC17TOTPReplay(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	sec := auth.NewTOTPSecret()
	if _, err := e.srv.Store.DB.Exec(`UPDATE users SET totp_secret=?, totp_enabled=1 WHERE username='alice'`, sec); err != nil {
		t.Fatal(err)
	}
	c := auth.TOTPCode(sec, time.Now())
	if s, code := e.login(e.user, "alice", tPW, c, "198.51.100.20"); s == nil {
		t.Fatalf("first login: %d", code)
	}
	if s, code := e.login(e.user, "alice", tPW, c, "198.51.100.21"); s != nil || code != 401 {
		t.Fatalf("replayed code: %d", code)
	}
}

// SEC-18: failures from many IPs never lock out the right password from a
// clean IP; per IP+account the hard lock still applies.
func TestSEC18Lockout(t *testing.T) {
	e := newEnv(t)
	var logBuf bytes.Buffer
	var logMu sync.Mutex
	e.srv.Log = slog.New(slog.NewTextHandler(&lockedWriter{w: &logBuf, mu: &logMu}, nil))
	if _, err := EnsureAdmin(context.Background(), e.srv.Store, "bossadmin", "Admin-Pass-123", ""); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		e.login(e.admin, "bossadmin", "wrong", "", fmt.Sprintf("203.0.113.%d", i+1))
	}
	if s, code := e.login(e.admin, "bossadmin", "Admin-Pass-123", "", "192.0.2.50"); s == nil {
		t.Fatalf("admin locked out: %d", code)
	}
	for i := 0; i < maxFailuresPerUserIP; i++ {
		e.login(e.admin, "bossadmin", "wrong", "", "192.0.2.99")
	}
	if _, code := e.login(e.admin, "bossadmin", "Admin-Pass-123", "", "192.0.2.99"); code != 429 {
		t.Fatalf("per account+IP lock not applied: %d", code)
	}
	// H-1: fail2ban-readable line, real client IP, no password
	logMu.Lock()
	out := logBuf.String()
	logMu.Unlock()
	if !strings.Contains(out, `msg="auth failure"`) || !strings.Contains(out, "ip=203.0.113.1 ") || strings.Contains(out, "wrong") && strings.Contains(out, "password=") {
		t.Fatalf("auth failure log:\n%s", out)
	}
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// ---- provisioning saga (CODE-5 / SEC-5) -------------------------------------------

func TestCreateAccountRefusesExistingSystemUser(t *testing.T) {
	e := newEnv(t)
	e.ag.exists["devops"] = true
	_, _, err := e.srv.CreateAccount(context.Background(), &e.root, CreateAccountReq{Username: "devops", Domain: "d.test", Password: tPW, PackageID: e.pkg()})
	if ae, ok := err.(*apiError); !ok || ae.Status != 409 {
		t.Fatalf("got %v", err)
	}
	if slices.Contains(e.ag.methods(), rpc.MAccountCreate) || slices.Contains(e.ag.methods(), rpc.MAccountTerminate) {
		t.Fatal("agent touched an existing system user")
	}
}

func TestCreateAccountRollbackAtEveryStep(t *testing.T) {
	steps := []string{rpc.MAccountCreate, rpc.MPHPPoolApply, rpc.MVhostApply, rpc.MMailDomainOn, rpc.MDNSZoneCreate}
	for k, failAt := range steps {
		t.Run(failAt, func(t *testing.T) {
			e := newEnv(t)
			e.ag.fail[failAt] = &rpc.Error{Code: "boom"}
			_, _, err := e.srv.CreateAccount(context.Background(), &e.root, CreateAccountReq{Username: "alice", Domain: "alice.test", Password: tPW, PackageID: e.pkg()})
			if err == nil {
				t.Fatal("no error")
			}
			if n := e.srv.count(`SELECT COUNT(*) FROM users WHERE username='alice'`); n != 0 {
				t.Fatal("user row left behind")
			}
			if n := e.srv.count(`SELECT COUNT(*) FROM domains`) + e.srv.count(`SELECT COUNT(*) FROM provision_steps`); n != 0 {
				t.Fatal("domain/step rows left behind")
			}
			ms := e.ag.methods()
			has := func(m string) bool { return slices.Contains(ms, m) }
			// compensations exactly for the steps that ran (failing step excluded: definitive error)
			want := map[string]bool{
				rpc.MAccountTerminate: k > 0,
				rpc.MPHPPoolRemove:    k > 1,
				rpc.MVhostRemove:      k > 2,
				rpc.MMailDomainOff:    k > 3,
				rpc.MDNSZoneDelete:    false,
			}
			for m, w := range want {
				if has(m) != w {
					t.Errorf("fail at %s: compensation %s called=%v want %v (calls %v)", failAt, m, has(m), w, ms)
				}
			}
			// reverse order: account.terminate is the last compensation
			if k > 1 && ms[len(ms)-1] != rpc.MAccountTerminate {
				t.Errorf("compensations not in reverse order: %v", ms)
			}
		})
	}
}

// An agent timeout leaves the outcome unknown: the step is compensated anyway.
func TestCreateAccountUnknownOutcomeCompensated(t *testing.T) {
	e := newEnv(t)
	e.ag.fail[rpc.MDNSZoneCreate] = &rpc.Error{Code: "agent_timeout"}
	if _, _, err := e.srv.CreateAccount(context.Background(), &e.root, CreateAccountReq{Username: "alice", Domain: "alice.test", Password: tPW, PackageID: e.pkg()}); err == nil {
		t.Fatal("no error")
	}
	if len(e.ag.find(rpc.MDNSZoneDelete)) != 1 {
		t.Fatal("zone of unknown outcome not compensated")
	}
}

// Crash recovery: a stale 'provisioning' row is compensated at startup.
func TestReconcileProvisioning(t *testing.T) {
	e := newEnv(t)
	u := e.tenant("alice", "alice.test")
	if _, err := e.srv.Store.DB.Exec(`UPDATE users SET status='provisioning', created_at=1 WHERE id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.Store.DB.Exec(`INSERT INTO provision_steps(user_id,seq,step,arg,done_at) VALUES(?,1,'account','alice',1),(?,2,'pool','8.3',1)`, u.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	e.ag.reset()
	e.srv.reconcileProvisioning(context.Background(), time.Minute)
	if n := e.srv.count(`SELECT COUNT(*) FROM users WHERE id=?`, u.ID); n != 0 {
		t.Fatal("stale provisioning account not rolled back")
	}
	if ms := e.ag.methods(); !slices.Equal(ms, []string{rpc.MPHPPoolRemove, rpc.MAccountTerminate}) {
		t.Fatalf("compensations %v", ms)
	}
}

// CODE-16: terminate removes everything incl. the phpMyAdmin user; a failure
// keeps the row in 'terminating' and a retry finishes.
func TestTerminateAccount(t *testing.T) {
	e := newEnv(t)
	u := e.tenant("alice", "alice.test")
	e.ag.fail[rpc.MDNSZoneDelete] = &rpc.Error{Code: "pdns_unreachable"}
	if err := e.srv.TerminateAccount(context.Background(), &u); err == nil {
		t.Fatal("partial failure hidden")
	}
	var st string
	_ = e.srv.Store.DB.QueryRow(`SELECT status FROM users WHERE id=?`, u.ID).Scan(&st)
	if st != "terminating" || slices.Contains(e.ag.methods(), rpc.MAccountTerminate) {
		t.Fatalf("status %q / account terminated before cleanup finished", st)
	}
	delete(e.ag.fail, rpc.MDNSZoneDelete)
	e.ag.reset()
	e.srv.reconcileProvisioning(context.Background(), time.Hour)
	if n := e.srv.count(`SELECT COUNT(*) FROM users WHERE id=?`, u.ID); n != 0 {
		t.Fatal("retry did not finish")
	}
	var pma bool
	for _, c := range e.ag.find(rpc.MDBUserDrop) {
		pma = pma || strings.Contains(string(c.Params), `"alice_pma"`)
	}
	if !pma || len(e.ag.find(rpc.MPHPPoolRemove)) < 5 {
		t.Fatal("pma user or php pools not cleaned")
	}
}

// ---- limits (CODE-9 / CODE-13) ---------------------------------------------------

func TestParallelQuota(t *testing.T) {
	e := newEnv(t)
	if _, err := e.srv.Store.DB.Exec(`UPDATE packages SET max_db=2`); err != nil {
		t.Fatal(err)
	}
	e.tenant("alice", "alice.test")
	s := mustLogin(t, e, e.user, "alice", "")
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			code, _ := s.call("POST", "/api/v1/user/databases", map[string]any{"name": fmt.Sprintf("db%d", i)})
			if code == 200 {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if ok != 2 || e.srv.count(`SELECT COUNT(*) FROM databases`) != 2 {
		t.Fatalf("%d databases created with max_db=2", ok)
	}
	// agent failure removes the row again
	e.ag.fail[rpc.MDBCreate] = &rpc.Error{Code: "mariadb_unreachable"}
	if _, err := e.srv.Store.DB.Exec(`UPDATE packages SET max_db=-1`); err != nil { // G1: -1 = unlimited
		t.Fatal(err)
	}
	if code, _ := s.call("POST", "/api/v1/user/databases", map[string]any{"name": "zz"}); code != 502 {
		t.Fatalf("got %d", code)
	}
	if e.srv.count(`SELECT COUNT(*) FROM databases WHERE name='alice_zz'`) != 0 {
		t.Fatal("orphan row")
	}
}

func TestResellerLimits(t *testing.T) {
	e := newEnv(t)
	rs, _, err := e.srv.CreateAccount(context.Background(), &e.root, CreateAccountReq{Username: "rsell", Domain: "rsell.test", Password: tPW,
		PackageID: e.pkg(), Role: "reseller", MaxAccounts: LimitOf(2), ResellerDiskMB: LimitOf(3000)})
	if err != nil {
		t.Fatal(err)
	}
	// the global "default" package belongs to the admin: not for resellers (R2-UX-03)
	if _, _, err := e.srv.CreateAccount(context.Background(), rs, CreateAccountReq{Username: "c1", Domain: "c1.test", Password: tPW, PackageID: e.pkg()}); err == nil {
		t.Fatal("reseller used a package with unlimited limits")
	}
	s := mustLogin(t, e, e.admin, "rsell", "")
	full := map[string]any{"name": "small", "disk_mb": 1000, "max_domains": 1, "max_subdomains": 1, "max_aliases": 1, "max_email": 1,
		"max_db": 1, "max_ftp": 1, "cpu_percent": 50, "memory_mb": 256, "max_tasks": 50}
	unl := map[string]any{"name": "big"}
	for k, v := range full {
		unl[k] = v
	}
	unl["name"], unl["max_email"] = "big", -1 // G1: -1 = unlimited
	if code, _ := s.call("POST", "/api/v1/admin/packages", unl); code != 403 {
		t.Fatalf("unlimited reseller package: %d", code)
	}
	code, m := s.call("POST", "/api/v1/admin/packages", full)
	if code != 200 {
		t.Fatalf("package: %d %v", code, m)
	}
	pid := int64(m["id"].(float64))
	rs2, _ := e.srv.userByID(context.Background(), rs.ID)
	for i, want := range []bool{true, true, false} { // MaxAccounts=2
		_, _, err := e.srv.CreateAccount(context.Background(), &rs2, CreateAccountReq{Username: fmt.Sprintf("cust%d", i), Domain: fmt.Sprintf("cust%d.test", i), Password: tPW, PackageID: pid})
		if (err == nil) != want {
			t.Fatalf("account %d: %v", i, err)
		}
	}
	// disk pool: 2x1000 used of 3000, growing the package to 2000 would need 4000
	full["disk_mb"] = 2000
	if code, _ := s.call("PUT", fmt.Sprintf("/api/v1/admin/packages/%d", pid), full); code != 409 {
		t.Fatalf("disk pool overrun accepted: %d", code)
	}
}

// ---- status codes and errors (CODE-10 / CODE-11) ------------------------------------

func TestAgentStatusMapping(t *testing.T) {
	for c, want := range map[string]int{"not_found": 404, "already_exists": 409, "zone_exists": 409, "permission_denied": 403,
		"file_too_large": 413, "invalid_path": 400, "is_directory": 422, "quota_exceeded": 507, "agent_unreachable": 503,
		"agent_timeout": 504, "action_failed": 502, "not_managed": 403} {
		if got := agentStatus(c); got != want {
			t.Errorf("%s -> %d, want %d", c, got, want)
		}
	}
}

func TestNoInternalErrorText(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	s := mustLogin(t, e, e.user, "alice", "")
	e.ag.fail[rpc.MDNSZoneGet] = &rpc.Error{Code: "pdns_error", Message: "GET /zones: 500 secret internals /etc/powerdns"}
	w := e.do(e.user, req{method: "GET", path: "/api/v1/user/dns/alice.test"}, s)
	if w.Code != 502 || strings.Contains(w.Body.String(), "secret") || w.Header().Get("X-Request-ID") == "" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	// file manager errors map to real codes
	code, m := s.call("POST", "/api/v1/user/files", map[string]any{"op": "read", "path": "nope.txt"})
	if code != 404 || m["error"] != "not_found" {
		t.Fatalf("missing file: %d %v", code, m)
	}
	// JSON 405
	w = e.do(e.user, req{method: "PATCH", path: "/api/v1/user/domains"}, s)
	if w.Code != 405 || !strings.Contains(w.Header().Get("Content-Type"), "json") {
		t.Fatalf("405: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	// deleting an unknown cron id is a 404, not a panic
	if code, _ := s.call("DELETE", "/api/v1/user/cron/999", nil); code != 404 {
		t.Fatalf("cron: %d", code)
	}
}

func TestRecoverer(t *testing.T) {
	e := newEnv(t)
	h := e.srv.requestIDs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 500 || strings.Contains(w.Body.String(), "boom") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

// ---- CSRF / client IP (login CSRF, CODE-20) ------------------------------------------

func TestLoginCSRF(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	body := `{"username":"alice","password":"` + tPW + `"}=`
	w := e.do(e.user, req{method: "POST", path: "/api/v1/auth/login", raw: strings.NewReader(body), ctype: "text/plain"}, nil)
	if w.Code != 415 {
		t.Fatalf("text/plain login: %d", w.Code)
	}
	w = e.do(e.user, req{method: "POST", path: "/api/v1/auth/login", body: map[string]string{"username": "alice", "password": tPW},
		headers: map[string]string{"Sec-Fetch-Site": "cross-site"}}, nil)
	if w.Code != 403 {
		t.Fatalf("cross-site login: %d", w.Code)
	}
	w = e.do(e.user, req{method: "POST", path: "/api/v1/auth/login", body: map[string]string{"username": "alice", "password": tPW},
		headers: map[string]string{"Origin": "https://evil.test"}}, nil)
	if w.Code != 403 {
		t.Fatalf("bad origin: %d", w.Code)
	}
}

func TestClientIPXFF(t *testing.T) {
	s := New(Config{TrustedProxies: []string{"10.0.0.1", "10.1.0.0/16"}}, nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "t")
	mk := func(remote, xff string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote + ":1"
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	for _, c := range []struct{ remote, xff, want string }{
		{"203.0.113.9", "1.2.3.4", "203.0.113.9"},                       // untrusted peer: header ignored
		{"10.0.0.1", "6.6.6.6, 198.51.100.1", "198.51.100.1"},           // right-most untrusted hop
		{"10.0.0.1", "6.6.6.6, 198.51.100.1, 10.1.2.3", "198.51.100.1"}, // skip trusted chain
		{"10.0.0.1", "garbage", "10.0.0.1"},
	} {
		if got := s.clientIP(mk(c.remote, c.xff)); got != c.want {
			t.Errorf("%s %q -> %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
}

// CODE-12: the CSP is computed once.
func TestCSPConcurrent(t *testing.T) {
	e := newEnv(t)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = e.srv.csp() }()
	}
	wg.Wait()
	if !strings.Contains(e.srv.csp(), "default-src 'self'") {
		t.Fatal(e.srv.csp())
	}
}

// ---- files (CODE-7) --------------------------------------------------------------------

func TestStreamingUploadDownload(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	s := mustLogin(t, e, e.user, "alice", "")
	if err := os.MkdirAll(filepath.Join(e.ag.homes, "alice", "public_html"), 0o755); err != nil {
		t.Fatal(err)
	}
	size := 3*fileops.MaxChunkBytes + 12345 // several chunks
	data := bytes.Repeat([]byte("bpanel!"), size/7+1)[:size]
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("path", "public_html")
	fw, _ := mw.CreateFormFile("file", "big file.bin")
	_, _ = fw.Write(data)
	_ = mw.Close()
	w := e.do(e.user, req{method: "POST", path: "/api/v1/user/files/upload", raw: &body, ctype: mw.FormDataContentType()}, s)
	if w.Code != 200 {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
	got, err := os.ReadFile(filepath.Join(e.ag.homes, "alice", "public_html", "big file.bin"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("uploaded content mismatch (%d bytes, %v)", len(got), err)
	}
	for _, c := range e.ag.find(rpc.MFiles) {
		if len(c.Params) > 2*fileops.MaxChunkBytes {
			t.Fatalf("agent message of %d bytes", len(c.Params))
		}
	}
	ents, _ := os.ReadDir(filepath.Join(e.ag.homes, "alice", "public_html"))
	for _, en := range ents {
		if strings.HasPrefix(en.Name(), ".bpanel-upload-") {
			t.Fatal("temporary upload left behind")
		}
	}
	w = e.do(e.user, req{method: "GET", path: "/api/v1/user/files/download?path=public_html/big%20file.bin"}, s)
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), data) || w.Header().Get("Content-Length") != fmt.Sprint(size) {
		t.Fatalf("download: %d len=%d", w.Code, w.Body.Len())
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, `filename="big file.bin"`) {
		t.Fatalf("disposition %q", cd)
	}
	w = e.do(e.user, req{method: "GET", path: "/api/v1/user/files/download?path=missing.bin"}, s)
	if w.Code != 404 {
		t.Fatalf("missing download: %d", w.Code)
	}
}

// ---- phpMyAdmin SSO cleanup -------------------------------------------------------------

func TestPMACleanup(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	s := mustLogin(t, e, e.user, "alice", "")
	if code, _ := s.call("POST", "/api/v1/user/db-users", map[string]any{"name": "pma", "password": "Db-Pass-20261"}); code != 400 {
		t.Fatalf("reserved pma user: %d", code)
	}
	if code, _ := s.call("POST", "/api/v1/user/phpmyadmin", nil); code != 200 {
		t.Fatal("sso")
	}
	ms := e.ag.methods()
	if i := slices.Index(ms, rpc.MDBUserDrop); i < 0 || i > slices.Index(ms, rpc.MDBUserCreate) {
		t.Fatalf("pma user not re-created from scratch: %v", ms)
	}
	if e.srv.count(`SELECT COUNT(*) FROM pma_users WHERE db_user='alice_pma'`) != 1 {
		t.Fatal("pma user not recorded")
	}
	e.srv.Now = func() time.Time { return time.Now().Add(pmaUserTTL + time.Minute) }
	e.ag.reset()
	e.srv.prunePMAUsers(context.Background(), pmaUserTTL)
	if len(e.ag.find(rpc.MDBUserDrop)) != 1 || e.srv.count(`SELECT COUNT(*) FROM pma_users`) != 0 {
		t.Fatal("expired pma user not dropped")
	}
}

// ---- AutoSSL renewal (CODE-6 / SYS-4) ---------------------------------------------------

func TestAutoSSLRenewal(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	soon := time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	later := time.Now().Add(80 * 24 * time.Hour).UTC().Format(time.RFC3339)
	e.tenant("bob", "bob.test")
	if _, err := e.srv.Store.DB.Exec(`UPDATE domains SET ssl_status='active', ssl_expires=? WHERE name='alice.test'`, soon); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.Store.DB.Exec(`UPDATE domains SET ssl_status='active', ssl_expires=? WHERE name='bob.test'`, later); err != nil {
		t.Fatal(err)
	}
	e.ag.reset()
	e.srv.autoSSLRun(context.Background())
	var issued, host []call
	for _, c := range e.ag.find(rpc.MSSLIssue) {
		if strings.Contains(string(c.Params), `"domain":"server.example.com"`) {
			host = append(host, c) // R2-WB-5: the hostname certificate is renewed too
		} else {
			issued = append(issued, c)
		}
	}
	if len(issued) != 1 || !strings.Contains(string(issued[0].Params), `"alice.test"`) {
		t.Fatalf("renewals: %d", len(issued))
	}
	if len(host) != 1 {
		t.Fatalf("hostname certificate renewals: %d", len(host))
	}
	if len(e.ag.find(rpc.MVhostApply)) == 0 {
		t.Fatal("vhost not re-applied after renewal")
	}
	var exp string
	_ = e.srv.Store.DB.QueryRow(`SELECT ssl_expires FROM domains WHERE name='alice.test'`).Scan(&exp)
	if exp == soon {
		t.Fatal("expiry not updated")
	}
	// a failure keeps the old certificate active and is not retried immediately
	if _, err := e.srv.Store.DB.Exec(`UPDATE domains SET ssl_expires=?, ssl_attempt_at=0 WHERE name='alice.test'`, soon); err != nil {
		t.Fatal(err)
	}
	e.ag.fail[rpc.MSSLIssue] = &rpc.Error{Code: "acme_failed"}
	e.srv.autoSSLRun(context.Background())
	e.ag.reset()
	e.srv.autoSSLRun(context.Background())
	if len(e.ag.find(rpc.MSSLIssue)) != 0 {
		t.Fatal("failed renewal retried immediately")
	}
	var st string
	_ = e.srv.Store.DB.QueryRow(`SELECT ssl_status FROM domains WHERE name='alice.test'`).Scan(&st)
	if st != "active" {
		t.Fatalf("status %q", st)
	}
}

// ---- misc ---------------------------------------------------------------------------------

func TestLoginAsUsesConfiguredHostname(t *testing.T) {
	e := newEnv(t)
	u := e.tenant("alice", "alice.test")
	s, _ := e.login(e.admin, "rootadmin", "Admin-Pass-123", "", "")
	w := e.do(e.admin, req{method: "POST", path: fmt.Sprintf("/api/v1/admin/accounts/%d/login", u.ID), headers: map[string]string{"Host": "evil.test"}}, s)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "server.example.com:2083") || strings.Contains(w.Body.String(), "evil") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestCronValidationAPI(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	s := mustLogin(t, e, e.user, "alice", "")
	if code, _ := s.call("POST", "/api/v1/user/cron", map[string]any{"minute": "61", "hour": "*", "dom": "*", "month": "*", "dow": "*", "command": "x"}); code != 400 {
		t.Fatalf("minute 61: %d", code)
	}
	if code, _ := s.call("POST", "/api/v1/user/cron", map[string]any{"minute": "0", "hour": "3", "dom": "*", "month": "*", "dow": "*", "command": "date +%F"}); code != 200 {
		t.Fatalf("percent command: %d", code)
	}
}

func TestMetaExportsLimits(t *testing.T) {
	e := newEnv(t)
	w := e.do(e.user, req{method: "GET", path: "/api/v1/meta"}, nil)
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	if m["limits"] == nil {
		t.Fatal("no limits in /meta")
	}
}

// CODE-22: the checked-in docs/openapi.json matches the router, and every
// operation documents its real error codes.
func TestOpenAPIDrift(t *testing.T) {
	e := newEnv(t)
	spec := e.srv.OpenAPI()
	b, err := os.ReadFile("../../docs/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	ops := func(m map[string]any) []string {
		var out []string
		for p, item := range m["paths"].(map[string]any) {
			for meth := range item.(map[string]any) {
				if meth != "servers" {
					out = append(out, strings.ToUpper(meth)+" "+p)
				}
			}
		}
		slices.Sort(out)
		return out
	}
	gb, _ := json.Marshal(spec)
	var gen map[string]any
	_ = json.Unmarshal(gb, &gen)
	if !slices.Equal(ops(gen), ops(doc)) {
		t.Fatalf("docs/openapi.json is stale: run `make openapi`")
	}
	for p, item := range gen["paths"].(map[string]any) {
		for meth, op := range item.(map[string]any) {
			if meth == "servers" {
				continue
			}
			rs := op.(map[string]any)["responses"].(map[string]any)
			if strings.Contains(p, "{id}") && rs["404"] == nil {
				t.Errorf("%s %s lacks 404", meth, p)
			}
			if strings.HasPrefix(p, "/api/v1/user/") && rs["502"] == nil && rs["401"] == nil {
				t.Errorf("%s %s lacks error codes", meth, p)
			}
		}
	}
}
