package api

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

func fakeBackupVerify(method string, b []byte) (any, bool) {
	switch method {
	case rpc.MBackupVerify:
		var p rpc.BackupVerify
		_ = json.Unmarshal(b, &p)
		return rpc.BackupVerification{User: p.User, SnapshotID: "0123456789abcdef", FilesChecked: 7, CheckOK: true, Status: "ok"}, true
	case rpc.MBackupDelete:
		return struct{}{}, true
	case rpc.MBackupCredsExport: // backup_partb_test.go
		var p rpc.AccountRef
		_ = json.Unmarshal(b, &p)
		fakeLegacyMu.Lock()
		defer fakeLegacyMu.Unlock()
		if pw, ok := fakeLegacyPW[p.User]; ok {
			return rpc.BackupCredsExport{Found: true, Password: pw}, true
		}
		return rpc.BackupCredsExport{}, true
	case rpc.MBackupForget:
		return rpc.BackupForgetResult{Kept: 3, Removed: 2}, true
	}
	return nil, false
}

func TestBackupVerifyAPI(t *testing.T) {
	e := newEnv(t)
	r1 := e.reseller("rsbk")
	c1, c2 := e.tenant("bkone", "bkone.test"), e.tenant("bktwo", "bktwo.test")
	e.srv.Store.DB.Exec(`UPDATE users SET owner_id=? WHERE id=?`, r1, c1.ID)
	admin := mustLoginAdmin(t, e)

	code, m := admin.call("POST", fmt.Sprintf("/api/v1/admin/accounts/%d/backups/verify", c1.ID), nil)
	if code != 200 || m["status"] != "ok" || m["files_checked"].(float64) != 7 || m["trigger"] != "manual" {
		t.Fatalf("verify now: %d %v", code, m)
	}
	code, m = admin.call("GET", "/api/v1/admin/backups/verifications", nil)
	if code != 200 || len(m["verifications"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, m)
	}
	// reseller: no backups.verify / backups.delete permission
	rs := mustLogin(t, e, e.admin, "rsbk", "")
	if code, _ := rs.call("POST", fmt.Sprintf("/api/v1/admin/accounts/%d/backups/verify", c1.ID), nil); code != 403 {
		t.Fatalf("reseller verify: %d", code)
	}
	if code, _ := rs.call("DELETE", fmt.Sprintf("/api/v1/admin/accounts/%d/backups/0123456789abcdef", c1.ID), nil); code != 403 {
		t.Fatalf("reseller delete: %d", code)
	}
	// account user: cannot reach admin realm, but sees own last result (without error detail)
	u := mustLogin(t, e, e.user, "bkone", "")
	code, m = u.call("GET", "/api/v1/user/backups/verification", nil)
	if code != 200 || m["verification"] == nil || m["verification"].(map[string]any)["status"] != "ok" {
		t.Fatalf("own verification: %d %v", code, m)
	}
	u2 := mustLogin(t, e, e.user, "bktwo", "")
	if code, m := u2.call("GET", "/api/v1/user/backups/verification", nil); code != 200 || m["verification"] != nil {
		t.Fatalf("other account sees result: %d %v", code, m)
	}
	// admin delete: validated snapshot id, reaches the agent
	if code, _ := admin.call("DELETE", fmt.Sprintf("/api/v1/admin/accounts/%d/backups/NOTHEX", c2.ID), nil); code != 400 {
		t.Fatalf("bad snapshot id: %d", code)
	}
	if code, m := admin.call("DELETE", fmt.Sprintf("/api/v1/admin/accounts/%d/backups/0123456789abcdef", c2.ID), nil); code != 200 {
		t.Fatalf("admin delete: %d %v", code, m)
	}
	// scheduled tick verifies exactly one stale account per run
	e.srv.backupVerifyTick(context.Background())
	var n int
	e.srv.Store.DB.QueryRow(`SELECT COUNT(*) FROM backup_verifications WHERE trigger='scheduled'`).Scan(&n)
	if n != 1 {
		t.Fatalf("scheduled verifications: %d", n)
	}
}
