package api

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/store"
)

func (e *env) resellerPkg(owner int64, name string, bw int64) int64 {
	e.t.Helper()
	res, err := e.srv.Store.DB.Exec(`INSERT INTO packages(name,owner_id,disk_mb,bandwidth_mb,max_domains,max_subdomains,max_aliases,max_email,max_db,max_ftp,mail_quota_mb,cpu_percent,memory_mb,max_tasks,created_at)
		VALUES(?,?,100,?,1,1,1,1,1,1,100,100,512,100,1)`, name, owner, bw)
	if err != nil {
		e.t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

func (e *env) userRow(id int64) store.User {
	u, err := e.srv.userByID(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

func TestAdminxEditResellerEnforcedOnCreate(t *testing.T) {
	e := newEnv(t)
	rid := e.reseller("rsa")
	pa, pb := e.resellerPkg(rid, "rsa_small", 1000), e.resellerPkg(rid, "rsa_other", 1000)
	admin := mustLoginAdmin(t, e)
	if c, m := admin.call("PUT", fmt.Sprintf("/api/v1/admin/resellers/%d/limits", rid), map[string]any{"max_accounts": 1, "bandwidth_mb": 1500, "allowed_packages": []int64{pa}, "acl": []string{"accounts.read", "accounts.create"}}); c != 200 {
		t.Fatalf("edit reseller: %d %v", c, m)
	}
	if c, m := admin.call("PUT", fmt.Sprintf("/api/v1/admin/resellers/%d/limits", rid), map[string]any{"acl": []string{"server.write"}}); c != 400 || m["error"] != "invalid_acl" {
		t.Fatalf("acl beyond role: %d %v", c, m)
	}
	if c, m := admin.call("GET", fmt.Sprintf("/api/v1/admin/resellers/%d/limits", rid), nil); c != 200 || m["limits"].(map[string]any)["max_accounts"].(float64) != 1 {
		t.Fatalf("get: %d %v", c, m)
	}
	rs := e.userRow(rid)
	ctx := context.Background()
	// package not in allowed list
	if _, _, err := e.srv.CreateAccount(ctx, &rs, CreateAccountReq{Username: "cb1", Domain: "cb1.test", Password: tPW, PackageID: pb}); err == nil || err.(*apiError).Code != "package_not_allowed" || err.(*apiError).Status != 403 {
		t.Fatalf("allowed packages: %v", err)
	}
	if _, _, err := e.srv.CreateAccount(ctx, &rs, CreateAccountReq{Username: "ca1", Domain: "ca1.test", Password: tPW, PackageID: pa}); err != nil {
		t.Fatalf("first: %v", err)
	}
	// over max_accounts via HTTP → 409
	rsess := mustLogin(t, e, e.admin, "rsa", "192.0.2.31")
	c, m := rsess.call("POST", "/api/v1/admin/accounts", map[string]any{"username": "ca2", "domain": "ca2.test", "password": tPW, "package_id": pa})
	if c != 409 || m["error"] != "limit_reached" {
		t.Fatalf("over limit: %d %v", c, m)
	}
	// raise accounts: bandwidth pool (1500, 1000 used) refuses the next one
	admin.call("PUT", fmt.Sprintf("/api/v1/admin/resellers/%d/limits", rid), map[string]any{"max_accounts": 5})
	c, m = rsess.call("POST", "/api/v1/admin/accounts", map[string]any{"username": "ca3", "domain": "ca3.test", "password": tPW, "package_id": pa})
	if c != 409 || m["message"] != "reseller_bandwidth" {
		t.Fatalf("bandwidth: %d %v", c, m)
	}
	// ACL: accounts.write not granted → suspend refused; reads still work
	var ca1 int64
	e.srv.Store.DB.QueryRow(`SELECT id FROM users WHERE username='ca1'`).Scan(&ca1)
	if c, m := rsess.call("POST", fmt.Sprintf("/api/v1/admin/accounts/%d/suspend", ca1), map[string]any{}); c != 403 || m["error"] != "permission_denied" {
		t.Fatalf("acl suspend: %d %v", c, m)
	}
	if c, _ := rsess.call("GET", "/api/v1/admin/accounts", nil); c != 200 {
		t.Fatalf("acl read: %d", c)
	}
	// a reseller can never edit reseller limits
	if c, _ := rsess.call("PUT", fmt.Sprintf("/api/v1/admin/resellers/%d/limits", rid), map[string]any{"max_accounts": 99}); c != 403 {
		t.Fatalf("reseller edits itself: %d", c)
	}
}

func TestAdminxModifyAccountOwnership(t *testing.T) {
	e := newEnv(t)
	r1, r2 := e.reseller("rsone"), e.reseller("rstwo")
	p1 := e.resellerPkg(r1, "p_one", 100)
	c1 := e.tenant("cone", "cone.test")
	c2 := e.tenant("ctwo", "ctwo.test")
	db := e.srv.Store.DB
	db.Exec(`UPDATE users SET owner_id=?, package_id=? WHERE id=?`, r1, p1, c1.ID)
	db.Exec(`UPDATE users SET owner_id=? WHERE id=?`, r2, c2.ID)
	s1 := mustLogin(t, e, e.admin, "rsone", "192.0.2.41")
	// foreign account: 404
	if c, _ := s1.call("PUT", fmt.Sprintf("/api/v1/admin/accounts/%d/modify", c2.ID), map[string]any{"shell_access": true}); c != 404 {
		t.Fatalf("foreign: %d", c)
	}
	// reseller cannot move owners
	if c, m := s1.call("PUT", fmt.Sprintf("/api/v1/admin/accounts/%d/modify", c1.ID), map[string]any{"owner_id": r2}); c != 403 {
		t.Fatalf("owner by reseller: %d %v", c, m)
	}
	// rename refused honestly
	if c, m := s1.call("PUT", fmt.Sprintf("/api/v1/admin/accounts/%d/modify", c1.ID), map[string]any{"primary_domain": "new.test"}); c != 422 || m["error"] != "rename_unsupported" {
		t.Fatalf("rename: %d %v", c, m)
	}
	// own account: shell + overrides + email
	e.ag.mu.Lock()
	e.ag.calls = nil
	e.ag.mu.Unlock()
	c, m := s1.call("PUT", fmt.Sprintf("/api/v1/admin/accounts/%d/modify", c1.ID), map[string]any{"shell_access": true, "max_addon_domains": 7, "max_subdomains": -1, "email": "ops@cone.test"})
	if c != 200 {
		t.Fatalf("modify: %d %v", c, m)
	}
	u := e.userRow(c1.ID)
	if u.Email != "ops@cone.test" {
		t.Fatal(u.Email)
	}
	p := e.srv.packageOf(context.Background(), &u)
	if p.MaxDomains != 7 || p.MaxSubdomains != -1 {
		t.Fatalf("overrides not applied: %d %d", p.MaxDomains, p.MaxSubdomains)
	}
	var jail rpc.IsolationSSHApply
	found := false
	e.ag.mu.Lock()
	for _, cl := range e.ag.calls {
		if cl.Method == rpc.MIsolationSSHApply {
			found = true
			_ = json.Unmarshal(cl.Params, &jail)
		}
	}
	e.ag.mu.Unlock()
	if !found {
		t.Fatal("ssh jail not re-rendered")
	}
	for _, n := range jail.Users {
		if n == "cone" {
			t.Fatalf("shell-enabled account still jailed: %v", jail.Users)
		}
	}
	if c, m := s1.call("PUT", fmt.Sprintf("/api/v1/admin/accounts/%d/modify", c1.ID), map[string]any{"email": "not-an-email"}); c != 400 || m["error"] != "invalid_email" {
		t.Fatalf("bad email: %d %v", c, m)
	}
	// admin moves c2 to r1: the package is not r1's → 403
	admin := mustLoginAdmin(t, e)
	if c, m := admin.call("PUT", fmt.Sprintf("/api/v1/admin/accounts/%d/modify", c2.ID), map[string]any{"owner_id": r1}); c != 403 || m["error"] != "package_not_owned" {
		t.Fatalf("move w/o package: %d %v", c, m)
	}
	if c, m := admin.call("PUT", fmt.Sprintf("/api/v1/admin/accounts/%d/modify", c2.ID), map[string]any{"owner_id": r1, "package_id": p1}); c != 200 {
		t.Fatalf("move: %d %v", c, m)
	}
	if u := e.userRow(c2.ID); u.OwnerID == nil || *u.OwnerID != r1 {
		t.Fatal("owner not moved")
	}
	if c, m := admin.call("PUT", fmt.Sprintf("/api/v1/admin/accounts/%d/modify", c2.ID), map[string]any{"owner_id": c1.ID}); c != 400 || m["error"] != "invalid_owner" {
		t.Fatalf("owner must be reseller/admin: %d %v", c, m)
	}
}

func TestAdminxContactEmailAndUserManager(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("alice", "alice.test")
	b := e.tenant("bob", "bob.test")
	db := e.srv.Store.DB
	var da, dbb int64
	db.QueryRow(`SELECT id FROM domains WHERE user_id=?`, a.ID).Scan(&da)
	db.QueryRow(`SELECT id FROM domains WHERE user_id=?`, b.ID).Scan(&dbb)
	db.Exec(`INSERT INTO mailboxes(user_id,domain_id,email,quota_mb,created_at) VALUES(?,?,?,?,1)`, a.ID, da, "info@alice.test", 100)
	db.Exec(`INSERT INTO mailboxes(user_id,domain_id,email,quota_mb,created_at) VALUES(?,?,?,?,1)`, b.ID, dbb, "info@bob.test", 100)
	db.Exec(`INSERT INTO ftp_accounts(user_id,login,dir,quota_mb,created_at) VALUES(?,?,?,?,1)`, a.ID, "alice_up", "public_html", 0)
	us := mustLogin(t, e, e.user, "alice", "192.0.2.51")
	if c, m := us.call("PUT", "/api/v1/user/contact-email", map[string]any{"email": "bad@"}); c != 400 || m["error"] != "invalid_email" {
		t.Fatalf("invalid: %d %v", c, m)
	}
	if c, m := us.call("PUT", "/api/v1/user/contact-email", map[string]any{"email": "me@example.org"}); c != 200 || m["old_notified"] != false {
		t.Fatalf("set: %d %v", c, m)
	}
	if u := e.userRow(a.ID); u.Email != "me@example.org" {
		t.Fatal(u.Email)
	}
	c, m := us.call("GET", "/api/v1/user/user-manager", nil)
	if c != 200 {
		t.Fatalf("um: %d %v", c, m)
	}
	list := m["users"].([]any)
	if len(list) != 2 {
		t.Fatalf("expected own mailbox+ftp only: %v", list)
	}
	for _, x := range list {
		if x.(map[string]any)["login"] == "info@bob.test" {
			t.Fatal("foreign mailbox leaked")
		}
	}
}

func TestAdminxUpdatePrefs(t *testing.T) {
	e := newEnv(t)
	admin := mustLoginAdmin(t, e)
	if c, m := admin.call("PUT", "/api/v1/admin/updates/prefs", map[string]any{"policy": "sometimes", "auto_reboot": "never"}); c != 400 || m["error"] != "invalid_update_policy" {
		t.Fatalf("invalid: %d %v", c, m)
	}
	if c, m := admin.call("PUT", "/api/v1/admin/updates/prefs", map[string]any{"policy": "security", "auto_reboot": "when_required"}); c != 200 {
		t.Fatalf("set: %d %v", c, m)
	}
	if c, m := admin.call("GET", "/api/v1/admin/updates/prefs", nil); c != 200 || m["prefs"].(map[string]any)["policy"] != "security" {
		t.Fatalf("get: %d %v", c, m)
	}
	if c, m := admin.call("GET", "/api/v1/admin/updates/status", nil); c != 200 || m["status"] == "" {
		t.Fatalf("status: %d %v", c, m)
	}
	c, m := admin.call("POST", "/api/v1/admin/updates/apply", nil)
	if c != 200 || m["job_id"] == nil {
		t.Fatalf("apply: %d %v", c, m)
	}
	for e.srv.Jobs().RunOnce(context.Background()) {
	}
	found := false
	e.ag.mu.Lock()
	for _, cl := range e.ag.calls {
		if cl.Method == rpc.MUpdatesApply {
			var p rpc.UpdatesApply
			_ = json.Unmarshal(cl.Params, &p)
			found = p.SecurityOnly && p.AutoReboot
		}
	}
	e.ag.mu.Unlock()
	if !found {
		t.Fatal("apply job did not call the agent with the stored policy")
	}
	rid := e.reseller("rsu")
	_ = rid
	rs := mustLogin(t, e, e.admin, "rsu", "192.0.2.61")
	if c, _ := rs.call("GET", "/api/v1/admin/updates/prefs", nil); c != 403 {
		t.Fatalf("reseller prefs: %d", c)
	}
	if c, _ := rs.call("POST", "/api/v1/admin/updates/apply", nil); c != 403 {
		t.Fatalf("reseller apply: %d", c)
	}
}
