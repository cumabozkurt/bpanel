package api

// v0.2 integration tests: SEC-8, handoff-ui H-1..H-10, CODE-27 wiring and an
// adversarial pass over the changed provisioning/auth code.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/auth"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

func pmaExchange(e *env, tok, remote string, xff string) (int, map[string]string) {
	r := httptest.NewRequest("GET", "/internal/pma-token/"+tok, nil)
	r.RemoteAddr = remote + ":5555"
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	w := httptest.NewRecorder()
	e.user.ServeHTTP(w, r)
	var m map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w.Code, m
}

// SEC-8: the phpMyAdmin SSO password is never stored in clear, the token is
// single use and loopback only, and the SSO user goes with the account.
func TestSEC8PMAPasswordNotStored(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	s := mustLogin(t, e, e.user, "alice", "")
	e.ag.reset()
	code, m := s.call("POST", "/api/v1/user/phpmyadmin", nil)
	if code != 200 {
		t.Fatalf("sso: %d %v", code, m)
	}
	tok := strings.TrimPrefix(m["url"].(string), "/3rdparty/phpMyAdmin/bpanel-signon.php?token=")
	var created rpc.DBUser
	cs := e.ag.find(rpc.MDBUserCreate)
	if len(cs) != 1 {
		t.Fatalf("db user create calls: %d", len(cs))
	}
	_ = json.Unmarshal(cs[0].Params, &created)
	var stored string
	if err := e.srv.Store.DB.QueryRow(`SELECT password FROM pma_tokens`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == created.Password || strings.Contains(stored, created.Password) || !strings.HasPrefix(stored, "v1:") {
		t.Fatalf("pma password stored in clear: %q", stored)
	}
	for _, g := range e.ag.find(rpc.MDBGrant) {
		if !strings.Contains(string(g.Params), `"privileges":["ALL"]`) {
			t.Errorf("SSO grant without explicit ALL: %s", g.Params)
		}
	}
	if c, _ := pmaExchange(e, tok, "198.51.100.7", ""); c != 403 {
		t.Fatalf("non-loopback exchange: %d", c)
	}
	if c, _ := pmaExchange(e, tok, "127.0.0.1", "203.0.113.5"); c != 403 {
		t.Fatalf("forwarded exchange: %d", c)
	}
	if c, _ := pmaExchange(e, tok+"x", "127.0.0.1", ""); c != 404 {
		t.Fatalf("wrong token: %d", c)
	}
	c, got := pmaExchange(e, tok, "127.0.0.1", "")
	if c != 200 || got["password"] != created.Password || got["user"] != "alice_pma" {
		t.Fatalf("exchange: %d %v", c, got)
	}
	if c, _ := pmaExchange(e, tok, "127.0.0.1", ""); c != 404 {
		t.Fatalf("token reused: %d", c)
	}
	// a stored value with the right hash but tampered ciphertext is refused
	tok2 := "tok2-for-test"
	if _, err := e.srv.Store.DB.Exec(`INSERT INTO pma_tokens(hash,db_user,password,expires_at) VALUES(?,?,?,?)`,
		auth.SHA256Hex(tok2), "alice_pma", "plaintext-from-v01", 1<<40); err != nil {
		t.Fatal(err)
	}
	if c, _ := pmaExchange(e, tok2, "127.0.0.1", ""); c != 404 {
		t.Fatalf("unsealed v0.1 row accepted: %d", c)
	}
	// terminate drops the SSO MariaDB user too
	var id int64
	_ = e.srv.Store.DB.QueryRow(`SELECT id FROM users WHERE username='alice'`).Scan(&id)
	a := mustLoginAdmin(t, e)
	e.ag.reset()
	if code, m := a.call("DELETE", fmt.Sprintf("/api/v1/admin/accounts/%d", id), nil); code != 200 {
		t.Fatalf("terminate: %d %v", code, m)
	}
	found := false
	for _, c := range e.ag.find(rpc.MDBUserDrop) {
		found = found || strings.Contains(string(c.Params), `"alice_pma"`)
	}
	if !found {
		t.Fatal("phpMyAdmin SSO user not dropped on termination")
	}
}

func mustLoginAdmin(t *testing.T, e *env) *sess {
	t.Helper()
	s, code := e.login(e.admin, "rootadmin", "Admin-Pass-123", "", "192.0.2.10")
	if s == nil {
		t.Fatalf("admin login: %d", code)
	}
	return s
}

// handoff-ui H-4: [] no longer means ALL PRIVILEGES.
func TestGrantPrivilegesAPI(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	s := mustLogin(t, e, e.user, "alice", "")
	_, db := s.call("POST", "/api/v1/user/databases", map[string]any{"name": "wp"})
	_, du := s.call("POST", "/api/v1/user/db-users", map[string]any{"name": "wpu", "password": "Db-Pass-20261"})
	dbID, uID := db["id"], du["id"]
	for _, tc := range []struct {
		body map[string]any
		code int
		sent string
	}{
		{map[string]any{"privileges": []string{}}, 400, ""},
		{map[string]any{}, 400, ""},
		{map[string]any{"privileges": []string{"SELECT", "SUPER"}}, 400, ""},
		{map[string]any{"privileges": []string{"SELECT; DROP DATABASE x"}}, 400, ""},
		{map[string]any{"all": true, "privileges": []string{"SELECT"}}, 400, ""},
		{map[string]any{"privileges": []string{"ALL"}}, 200, `["ALL"]`},
		{map[string]any{"all": true}, 200, `["ALL"]`},
		{map[string]any{"privileges": []string{"select", "INSERT", "SELECT"}}, 200, `["SELECT","INSERT"]`},
	} {
		e.ag.reset()
		tc.body["db_id"], tc.body["user_id"] = dbID, uID
		code, m := s.call("POST", "/api/v1/user/db-grants", tc.body)
		if code != tc.code {
			t.Errorf("%v: %d %v", tc.body, code, m)
			continue
		}
		g := e.ag.find(rpc.MDBGrant)
		if tc.code != 200 {
			if len(g) != 0 || m["error"] != "invalid_privilege" {
				t.Errorf("%v reached the agent or wrong code: %v", tc.body, m)
			}
			continue
		}
		if len(g) != 1 || !strings.Contains(string(g[0].Params), `"privileges":`+tc.sent) {
			t.Errorf("%v: agent got %v", tc.body, g)
		}
	}
}

// handoff-ui H-2: server-side Database Wizard with rollback.
func TestDBWizard(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	s := mustLogin(t, e, e.user, "alice", "")
	body := map[string]any{"name": "shop", "user": "shopu", "password": "Db-Pass-20261", "privileges": []string{"SELECT", "INSERT"}}
	code, m := s.call("POST", "/api/v1/user/db-wizard", body)
	if code != 200 || m["db"].(map[string]any)["name"] != "alice_shop" {
		t.Fatalf("wizard: %d %v", code, m)
	}
	if e.srv.count(`SELECT COUNT(*) FROM db_grants`) != 1 {
		t.Fatal("grant row missing")
	}
	rows := func() int64 {
		return e.srv.count(`SELECT COUNT(*) FROM databases`) + e.srv.count(`SELECT COUNT(*) FROM db_users`)
	}
	base := rows()
	// failure at step 2: the database is dropped again
	e.ag.reset()
	e.ag.fail[rpc.MDBUserCreate] = &rpc.Error{Code: "db_error"}
	body["name"], body["user"] = "two", "twou"
	if code, _ := s.call("POST", "/api/v1/user/db-wizard", body); code < 400 {
		t.Fatal("wizard succeeded with a failing step")
	}
	if rows() != base || len(e.ag.find(rpc.MDBDrop)) != 1 {
		t.Fatalf("step-2 rollback: rows %d->%d, drops %d", base, rows(), len(e.ag.find(rpc.MDBDrop)))
	}
	delete(e.ag.fail, rpc.MDBUserCreate)
	// failure at step 3: user and database are dropped, in reverse order
	e.ag.reset()
	e.ag.fail[rpc.MDBGrant] = &rpc.Error{Code: "db_error"}
	body["name"], body["user"] = "three", "threeu"
	if code, _ := s.call("POST", "/api/v1/user/db-wizard", body); code < 400 {
		t.Fatal("wizard succeeded with a failing grant")
	}
	ms := e.ag.methods()
	if rows() != base || strings.Join(ms[len(ms)-2:], ",") != rpc.MDBUserDrop+","+rpc.MDBDrop {
		t.Fatalf("step-3 rollback: rows %d->%d, calls %v", base, rows(), ms)
	}
	// rollback itself fails: 500 rollback_incomplete, no detail in the body
	e.ag.fail[rpc.MDBDrop] = &rpc.Error{Code: "db_error", Message: "secret /var/lib/mysql detail"}
	body["name"], body["user"] = "four", "fouru"
	code, m = s.call("POST", "/api/v1/user/db-wizard", body)
	if code != 500 || m["error"] != "rollback_incomplete" || strings.Contains(fmt.Sprint(m), "mysql") {
		t.Fatalf("failed rollback: %d %v", code, m)
	}
	e.ag.fail = map[string]error{}
	// validation happens before any side effect
	e.ag.reset()
	for _, b := range []map[string]any{
		{"name": "x", "user": "pma", "password": "Db-Pass-20261", "all": true},
		{"name": "x", "user": "u", "password": "short", "all": true},
		{"name": "bad name", "user": "u", "password": "Db-Pass-20261", "all": true},
		{"name": "x", "user": "u", "password": "Db-Pass-20261", "privileges": []string{}},
	} {
		if code, _ := s.call("POST", "/api/v1/user/db-wizard", b); code != 400 {
			t.Errorf("%v: %d", b, code)
		}
	}
	if len(e.ag.calls) != 0 {
		t.Fatalf("invalid wizard input reached the agent: %v", e.ag.methods())
	}
	for b, step := range map[string]string{"db": "bad name", "user": "pma", "grant": ""} {
		body := map[string]any{"name": "ok", "user": "u", "password": "Db-Pass-20261", "all": true}
		switch b {
		case "db":
			body["name"] = step
		case "user":
			body["user"] = step
		case "grant":
			delete(body, "all")
		}
		if _, m := s.call("POST", "/api/v1/user/db-wizard", body); m["step"] != b {
			t.Errorf("failing step %s not reported: %v", b, m)
		}
	}
}

// handoff-ui H-1: user-side activity feed.
func TestActivityFeed(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	e.tenant("bob", "bob.test")
	rs, _, err := e.srv.CreateAccount(context.Background(), &e.root, CreateAccountReq{Username: "rsell", Domain: "rsell.test", Password: tPW,
		PackageID: e.pkg(), Role: "reseller", MaxAccounts: LimitOf(5)})
	if err != nil {
		t.Fatal(err)
	}
	_ = rs
	alice := mustLogin(t, e, e.user, "alice", "")
	bob := mustLogin(t, e, e.user, "bob", "")
	alice.call("POST", "/api/v1/user/databases", map[string]any{"name": "a1"})
	bob.call("POST", "/api/v1/user/databases", map[string]any{"name": "b1"})
	e.login(e.user, "alice", "wrong-password-1", "", "203.0.113.77") // failed login against alice
	code, m := alice.call("GET", "/api/v1/account/activity?limit=50", nil)
	if code != 200 {
		t.Fatalf("activity: %d %v", code, m)
	}
	items := m["items"].([]any)
	sawFail, sawOwn := false, false
	for _, it := range items {
		row := it.(map[string]any)
		if strings.Contains(fmt.Sprint(row), "bob") {
			t.Errorf("alice sees bob's row: %v", row)
		}
		if _, ok := row["detail"]; ok {
			t.Error("detail column leaked")
		}
		sawOwn = sawOwn || row["action"] == "db.create" && row["target"] == "alice_a1"
		sawFail = sawFail || row["action"] == "auth.login" && row["ok"] == false
	}
	if !sawOwn || !sawFail {
		t.Fatalf("own=%v failedLogin=%v: %v", sawOwn, sawFail, items)
	}
	top := int64(items[0].(map[string]any)["id"].(float64))
	_, m = alice.call("GET", fmt.Sprintf("/api/v1/account/activity?since_id=%d", top), nil)
	if len(m["items"].([]any)) != 0 || m["unread"].(float64) != 0 {
		t.Fatalf("since_id: %v", m)
	}
	// reseller sees rows of its own accounts only
	rsC, _ := e.srv.userByID(context.Background(), rs.ID)
	if _, _, err := e.srv.CreateAccount(context.Background(), &rsC, CreateAccountReq{Username: "cust", Domain: "cust.test", Password: tPW, PackageID: resellerPkg(t, e, rs.ID)}); err != nil {
		t.Fatal(err)
	}
	cust := mustLogin(t, e, e.user, "cust", "")
	cust.call("POST", "/api/v1/user/databases", map[string]any{"name": "c1"})
	r := mustLogin(t, e, e.admin, "rsell", "")
	_, m = r.call("GET", "/api/v1/account/activity?limit=100", nil)
	txt := fmt.Sprint(m["items"])
	if !strings.Contains(txt, "cust_c1") || strings.Contains(txt, "alice_a1") || strings.Contains(txt, "bob_b1") {
		t.Fatalf("reseller feed: %s", txt)
	}
}

func resellerPkg(t *testing.T, e *env, owner int64) int64 {
	t.Helper()
	res, err := e.srv.Store.DB.Exec(`INSERT INTO packages(name,owner_id,disk_mb,bandwidth_mb,max_domains,max_subdomains,max_aliases,max_email,max_db,max_ftp,mail_quota_mb,cpu_percent,memory_mb,max_tasks,php_version,created_at)
		VALUES('rsell_p',?,100,0,1,1,1,1,1,1,0,50,256,50,'',0)`, owner)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

// handoff-ui H-3: favorites stored on the server.
func TestFavorites(t *testing.T) {
	e := newEnv(t)
	a := mustLoginAdmin(t, e)
	_, m := a.call("GET", "/api/v1/auth/me", nil)
	if m["favorites"] != nil {
		t.Fatalf("fresh user favorites: %v", m["favorites"])
	}
	if code, m := a.call("PUT", "/api/v1/account/preferences", map[string]any{"favorites": []string{"create_account", "list_accounts"}}); code != 200 {
		t.Fatalf("save: %d %v", code, m)
	}
	_, m = a.call("GET", "/api/v1/auth/me", nil)
	if fmt.Sprint(m["favorites"]) != "[create_account list_accounts]" {
		t.Fatalf("favorites: %v", m["favorites"])
	}
	many := make([]string, validate.MaxFavorites+1)
	for i := range many {
		many[i] = fmt.Sprintf("t%d", i)
	}
	for _, bad := range [][]string{many, {"<script>"}, {"a", "a"}, {strings.Repeat("x", 41)}} {
		if code, m := a.call("PUT", "/api/v1/account/preferences", map[string]any{"favorites": bad}); code != 400 || m["error"] != "invalid_favorites" {
			t.Errorf("%v: %d %v", bad, code, m)
		}
	}
	if code, _ := a.call("PUT", "/api/v1/account/preferences", map[string]any{"favorites": []string{}}); code != 200 {
		t.Fatal("clear favorites")
	}
	_, m = a.call("GET", "/api/v1/auth/me", nil)
	if fmt.Sprint(m["favorites"]) != "[]" {
		t.Fatalf("cleared favorites: %v", m["favorites"])
	}
}

// handoff-ui H-5 / H-10: one FTP login rule everywhere, request size exported.
func TestMetaLimitsV02(t *testing.T) {
	e := newEnv(t)
	w := e.do(e.user, req{method: "GET", path: "/api/v1/meta"}, nil)
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	lim := m["limits"].(map[string]any)
	pat := lim["ftp_login"].(map[string]any)["pattern"].(string)
	re := regexp.MustCompile(pat)
	if !re.MatchString(strings.Repeat("a", 32)) || re.MatchString(strings.Repeat("a", 33)) {
		t.Fatalf("ftp_login pattern %s is not 32 characters", pat)
	}
	agentLocal := strings.TrimSuffix(strings.Split(validate.FTPLoginPattern.String(), "@")[0], "") + "$"
	if pat != agentLocal {
		t.Fatalf("/meta %s != agent %s", pat, agentLocal)
	}
	if lim["upload_max_request"].(float64) != float64(validate.UploadMaxRequest) || lim["upload_max_file"].(float64) != float64(validate.UploadMaxFile) {
		t.Fatalf("upload limits: %v", lim)
	}
	e.tenant("alice", "alice.test")
	s := mustLogin(t, e, e.user, "alice", "")
	for login, want := range map[string]int{strings.Repeat("a", 32): 200, strings.Repeat("a", 33): 400, "a+b": 400, "a..b": 400, ".a": 400} {
		code, mm := s.call("POST", "/api/v1/user/ftp", map[string]any{"login": login, "domain": "alice.test", "password": "Ftp-Pass-20261"})
		if code != want {
			t.Errorf("ftp login %q: %d %v", login, code, mm)
		}
	}
}

// handoff-ui H-6: warnings are structured codes.
func TestStructuredWarnings(t *testing.T) {
	e := newEnv(t)
	e.tenant("alice", "alice.test")
	s := mustLogin(t, e, e.user, "alice", "")
	e.ag.fail[rpc.MMailDomainOn] = &rpc.Error{Code: "postfix_error"}
	e.ag.fail[rpc.MDNSZoneCreate] = &rpc.Error{Code: "pdns_error"}
	code, m := s.call("POST", "/api/v1/user/domains", map[string]any{"name": "shop.test", "kind": "addon"})
	if code != 200 {
		t.Fatalf("create: %d %v", code, m)
	}
	ws := m["warnings"].([]any)
	if len(ws) != 2 {
		t.Fatalf("warnings: %v", ws)
	}
	w0, w1 := ws[0].(map[string]any), ws[1].(map[string]any)
	if w0["code"] != WarnMailSetupFailed || w0["area"] != "mail" || w0["detail"] != "postfix_error" || w1["code"] != WarnDNSSetupFailed {
		t.Fatalf("warnings: %v", ws)
	}
	a := mustLoginAdmin(t, e)
	_, m = a.call("PUT", "/api/v1/admin/settings", map[string]any{"server_ip": "192.0.2.44"})
	if ws := m["warnings"].([]any); len(ws) != 1 || ws[0].(map[string]any)["code"] != WarnExistingNotUpdated {
		t.Fatalf("settings warnings: %v", m)
	}
}

// CODE-27: every tenant-scoped agent call names its owner.
func TestAgentCallsCarryOwner(t *testing.T) {
	e := newEnv(t)
	e.ag.reset()
	e.tenant("alice", "alice.test")
	s := mustLogin(t, e, e.user, "alice", "")
	s.call("POST", "/api/v1/user/domains", map[string]any{"name": "shop.test", "kind": "addon"})
	s.call("POST", "/api/v1/user/domains", map[string]any{"name": "blog.alice.test", "kind": "sub"})
	s.call("POST", "/api/v1/user/email/forwarders", map[string]any{"source": "info@alice.test", "destination": "x@example.org"})
	s.call("POST", "/api/v1/user/ftp", map[string]any{"login": "up", "domain": "alice.test", "password": "Ftp-Pass-20261"})
	_, z := s.call("GET", "/api/v1/user/dns/alice.test", nil)
	_ = z
	s.call("POST", "/api/v1/user/dns/alice.test/reset", nil)
	var id int64
	_ = e.srv.Store.DB.QueryRow(`SELECT id FROM domains WHERE name='shop.test'`).Scan(&id)
	s.call("DELETE", fmt.Sprintf("/api/v1/user/domains/%d", id), nil)
	scoped := map[string]bool{rpc.MDNSZoneCreate: true, rpc.MDNSZoneDelete: true, rpc.MDNSZoneGet: true, rpc.MDNSRRSetReplace: true,
		rpc.MDNSRRSetDelete: true, rpc.MMailForwardSet: true, rpc.MMailForwardDel: true, rpc.MFTPDelete: true, rpc.MVhostRemove: true,
		rpc.MMailDomainOn: true, rpc.MMailDomainOff: true, rpc.MFTPCreate: true, rpc.MVhostApply: true, rpc.MDBGrant: true}
	seen := 0
	for _, c := range e.ag.calls {
		if !scoped[c.Method] {
			continue
		}
		seen++
		var p map[string]any
		_ = json.Unmarshal(c.Params, &p)
		if p["owner"] != "alice" && p["user"] != "alice" {
			t.Errorf("%s without owner: %s", c.Method, c.Params)
		}
	}
	if seen < 8 {
		t.Fatalf("only %d scoped calls recorded: %v", seen, e.ag.methods())
	}
}

// Adversarial pass (medium items): spoofed X-Forwarded-For cannot pick the
// lockout bucket, a burst of wrong passwords cannot lock the admin out, and
// resellers cannot create, widen or borrow unlimited/global packages.
func TestAdversarialV02(t *testing.T) {
	e := newEnv(t)
	// XFF from an untrusted peer is ignored: the attacker's failures land on
	// its own IP, so rotating XFF values does not escape the per-IP lock...
	for i := 0; i < maxFailuresPerIP; i++ {
		e.do(e.admin, req{method: "POST", path: "/api/v1/auth/login", body: map[string]string{"username": "rootadmin", "password": "nope"},
			ip: "203.0.113.200", headers: map[string]string{"X-Forwarded-For": fmt.Sprintf("10.9.9.%d", i)}}, nil)
	}
	w := e.do(e.admin, req{method: "POST", path: "/api/v1/auth/login", body: map[string]string{"username": "rootadmin", "password": "Admin-Pass-123"},
		ip: "203.0.113.200", headers: map[string]string{"X-Forwarded-For": "10.9.9.250"}}, nil)
	if w.Code != 429 {
		t.Fatalf("spoofed XFF escaped the per-IP lock: %d", w.Code)
	}
	if n := e.srv.count(`SELECT COUNT(*) FROM login_failures WHERE ip LIKE '10.9.9.%'`); n != 0 {
		t.Fatalf("spoofed XFF recorded as client IP %d times", n)
	}
	// ...and cannot frame the admin's own IP either
	if s, code := e.login(e.admin, "rootadmin", "Admin-Pass-123", "", "192.0.2.10"); s == nil {
		t.Fatalf("admin locked out by someone else's failures: %d", code)
	}
	// 8 (and 30) wrong passwords from rotating IPs: no lockout for the owner
	for i := 0; i < 30; i++ {
		e.login(e.admin, "rootadmin", "wrong", "", fmt.Sprintf("198.18.0.%d", i+1))
	}
	if s, code := e.login(e.admin, "rootadmin", "Admin-Pass-123", "", "192.0.2.11"); s == nil {
		t.Fatalf("admin locked out after distributed failures: %d", code)
	}
	// resellers and packages
	rs, _, err := e.srv.CreateAccount(context.Background(), &e.root, CreateAccountReq{Username: "rsell", Domain: "rsell.test", Password: tPW,
		PackageID: e.pkg(), Role: "reseller", MaxAccounts: LimitOf(3)})
	if err != nil {
		t.Fatal(err)
	}
	r := mustLogin(t, e, e.admin, "rsell", "")
	full := map[string]any{"name": "global", "disk_mb": 10, "max_domains": 1, "max_subdomains": 1, "max_aliases": 1, "max_email": 1,
		"max_db": 1, "max_ftp": 1, "cpu_percent": 10, "memory_mb": 64, "max_tasks": 10}
	code, m := r.call("POST", "/api/v1/admin/packages", full)
	if code != 200 || !strings.HasPrefix(m["name"].(string), "rsell_") {
		t.Fatalf("reseller package not namespaced: %d %v", code, m)
	}
	var owner *int64
	_ = e.srv.Store.DB.QueryRow(`SELECT owner_id FROM packages WHERE id=?`, int64(m["id"].(float64))).Scan(&owner)
	if owner == nil || *owner != rs.ID {
		t.Fatal("reseller package created as a global package")
	}
	for _, f := range []string{"disk_mb", "max_db", "cpu_percent", "memory_mb", "max_tasks"} {
		b := map[string]any{}
		for k, v := range full {
			b[k] = v
		}
		b["name"], b[f] = "u"+f, -1 // G1: -1 = unlimited
		if code, _ := r.call("POST", "/api/v1/admin/packages", b); code != 403 {
			t.Errorf("unlimited %s accepted: %d", f, code)
		}
		b[f] = nil // null = unlimited too
		if code, _ := r.call("POST", "/api/v1/admin/packages", b); code != 403 {
			t.Errorf("null (unlimited) %s accepted: %d", f, code)
		}
		b[f] = -2
		if code, _ := r.call("POST", "/api/v1/admin/packages", b); code != 400 {
			t.Errorf("negative %s accepted: %d", f, code)
		}
	}
	if code, _ := r.call("PUT", fmt.Sprintf("/api/v1/admin/packages/%d", e.pkg()), full); code != 403 {
		t.Fatalf("reseller edited the global package: %d", code)
	}
	if code, _ := r.call("DELETE", fmt.Sprintf("/api/v1/admin/packages/%d", e.pkg()), nil); code != 403 {
		t.Fatalf("reseller deleted the global package: %d", code)
	}
	// an admin's global package is off-limits for resellers (R2-UX-03)
	code, m = r.call("POST", "/api/v1/admin/accounts", map[string]any{"username": "cx", "domain": "cx.test", "password": tPW, "package_id": e.pkg()})
	if code != 403 || m["error"] != "package_not_owned" || m["field"] != "package_id" {
		t.Fatalf("reseller used the unlimited global package: %d %v", code, m)
	}
	code, _ = r.call("POST", "/api/v1/admin/accounts", map[string]any{"username": "cy", "domain": "cy.test", "password": tPW, "package_id": e.pkg(), "role": "reseller"})
	if code < 400 {
		t.Fatal("reseller created a reseller")
	}
	// login CSRF: form-encoded and cross-site posts never create a session
	for _, h := range []map[string]string{{"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"}, {"Origin": "null"}} {
		w := e.do(e.user, req{method: "POST", path: "/api/v1/auth/login", body: map[string]string{"username": "rsell", "password": tPW}, headers: h}, nil)
		if w.Code != 403 || len(w.Result().Cookies()) != 0 {
			t.Errorf("login CSRF %v: %d", h, w.Code)
		}
	}
	for _, ct := range []string{"application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "text/plain;charset=UTF-8"} {
		w := e.do(e.user, req{method: "POST", path: "/api/v1/auth/login", raw: strings.NewReader(`{"username":"rsell","password":"` + tPW + `"}`), ctype: ct}, nil)
		if w.Code != 415 {
			t.Errorf("login with %s: %d", ct, w.Code)
		}
	}
	_ = http.StatusOK
}
