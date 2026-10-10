package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/rbac"
)

var (
	fakeLegacyMu sync.Mutex
	fakeLegacyPW = map[string]string{}
)

func withSecrets(t *testing.T, e *env) {
	t.Helper()
	e.srv.Cfg.SecretKeyFile = filepath.Join(t.TempDir(), "secret.key")
	if _, ok := e.srv.secretsUsable(); !ok {
		t.Fatal("secret store unavailable")
	}
}

// Retention runs automatically after every successful scheduled backup, with
// the configured keep-* policy; a failed backup never prunes; retention
// errors are recorded without failing the backup.
func TestBackupRetentionAfterScheduledBackup(t *testing.T) {
	e := newEnv(t)
	withSecrets(t, e)
	c := e.tenant("rtone", "rtone.test")
	e.srv.Store.Set("backup_keep_daily", "9")
	e.srv.Store.Set("backup_keep_weekly", "0")
	e.srv.Store.Set("backup_keep_monthly", "0")

	e.ag.reset()
	e.srv.backupScheduleTick(context.Background()) // backup_auto defaults to 0
	if len(e.ag.find(rpc.MBackupRun)) != 0 {
		t.Fatal("scheduled backup ran while disabled")
	}
	e.srv.Store.Set("backup_auto", "1")
	e.srv.backupScheduleTick(context.Background())
	ms := strings.Join(e.ag.methods(), " ")
	if !strings.Contains(ms, rpc.MBackupRun) || !strings.Contains(ms, rpc.MBackupForget) ||
		strings.Index(ms, rpc.MBackupRun) > strings.LastIndex(ms, rpc.MBackupForget) {
		t.Fatalf("expected backup.run then backup.forget, got %s", ms)
	}
	if !strings.Contains(ms[:strings.Index(ms, rpc.MBackupRun)], rpc.MBackupCredsLoad) {
		t.Fatalf("creds not pushed before backup.run: %s", ms)
	}
	var fp rpc.BackupForget
	_ = json.Unmarshal(e.ag.find(rpc.MBackupForget)[0].Params, &fp)
	if fp.User != "rtone" || fp.Policy.Daily != 9 || fp.Policy.Weekly != 0 {
		t.Fatalf("policy: %+v", fp)
	}
	var st, rs string
	var removed int
	e.srv.Store.DB.QueryRow(`SELECT status, retention_status, removed FROM backup_runs WHERE account_id=?`, c.ID).Scan(&st, &rs, &removed)
	if st != "ok" || rs != "ok" || removed != 2 {
		t.Fatalf("run row: %s %s %d", st, rs, removed)
	}
	// not due again within the interval
	e.ag.reset()
	e.srv.backupScheduleTick(context.Background())
	if len(e.ag.find(rpc.MBackupRun)) != 0 {
		t.Fatal("ran again before the interval")
	}

	// retention failure is recorded, backup stays ok
	e.srv.Store.DB.Exec(`DELETE FROM backup_runs`)
	e.ag.fail[rpc.MBackupForget] = &rpc.Error{Code: "retention_failed", Message: "x"}
	e.srv.backupScheduleTick(context.Background())
	e.srv.Store.DB.QueryRow(`SELECT status, retention_status FROM backup_runs WHERE account_id=?`, c.ID).Scan(&st, &rs)
	if st != "ok" || rs != "failed" {
		t.Fatalf("retention failure: %s %s", st, rs)
	}
	// failed backup: no forget
	delete(e.ag.fail, rpc.MBackupForget)
	e.ag.fail[rpc.MBackupRun] = &rpc.Error{Code: "backup_failed", Message: "x"}
	e.srv.Store.DB.Exec(`DELETE FROM backup_runs`)
	e.ag.reset()
	e.srv.backupScheduleTick(context.Background())
	if len(e.ag.find(rpc.MBackupForget)) != 0 {
		t.Fatal("pruned after a failed backup")
	}
	e.srv.Store.DB.QueryRow(`SELECT status, retention_status FROM backup_runs WHERE account_id=?`, c.ID).Scan(&st, &rs)
	if st != "failed" || rs != "skipped" {
		t.Fatalf("failed backup row: %s %s", st, rs)
	}
	// policy API: keeps-nothing refused; overview lists the account
	admin := mustLoginAdmin(t, e)
	if code, m := admin.call("PUT", "/api/v1/admin/backups/policy", map[string]any{"auto": true, "interval_hours": 24}); code != 400 || m["error"] != "invalid_retention" {
		t.Fatalf("keep-nothing policy: %d %v", code, m)
	}
	if code, m := admin.call("PUT", "/api/v1/admin/backups/policy", map[string]any{"auto": true, "interval_hours": 12, "keep_daily": 5}); code != 200 || m["keep_daily"].(float64) != 5 {
		t.Fatalf("policy put: %d %v", code, m)
	}
	code, m := admin.call("GET", "/api/v1/admin/backups/overview", nil)
	if code != 200 || len(m["accounts"].([]any)) != 1 {
		t.Fatalf("overview: %d %v", code, m)
	}
}

// One-time migration of the legacy repository password into the secret
// store: idempotent, value stored exactly, legacy file retired, never logged.
func TestBackupPasswordMigrationIdempotent(t *testing.T) {
	e := newEnv(t)
	withSecrets(t, e)
	var logs bytes.Buffer
	e.srv.Log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e.tenant("mgone", "mgone.test")
	e.tenant("mgtwo", "mgtwo.test")
	const legacy = "4f1d0c9a7b3e5f60718293a4b5c6d7e8f9011223"
	fakeLegacyMu.Lock()
	fakeLegacyPW["mgone"] = legacy
	fakeLegacyMu.Unlock()
	t.Cleanup(func() { fakeLegacyMu.Lock(); delete(fakeLegacyPW, "mgone"); fakeLegacyMu.Unlock() })

	e.ag.reset()
	if n := e.srv.migrateBackupSecrets(context.Background()); n != 2 {
		t.Fatalf("first migration moved %d", n)
	}
	ctx := context.Background()
	got, err := e.srv.Secrets().Get(ctx, backupRepoSecret("mgone"))
	if err != nil || string(got) != legacy {
		t.Fatalf("migrated value mismatch: %v", err)
	}
	gen, err := e.srv.Secrets().Get(ctx, backupRepoSecret("mgtwo"))
	if err != nil || len(gen) != 64 {
		t.Fatalf("generated password: %v len=%d", err, len(gen))
	}
	var retired bool
	for _, c := range e.ag.find(rpc.MBackupCredsLoad) {
		var p rpc.BackupCredsLoad
		_ = json.Unmarshal(c.Params, &p)
		if p.User == "mgone" && p.Retire && p.Password == legacy {
			retired = true
		}
	}
	if !retired {
		t.Fatal("legacy file not retired via backup.creds.load")
	}
	exports := len(e.ag.find(rpc.MBackupCredsExport))
	// second run (restart): nothing moved, no new export, same value
	if n := e.srv.migrateBackupSecrets(ctx); n != 0 {
		t.Fatalf("second migration moved %d", n)
	}
	if len(e.ag.find(rpc.MBackupCredsExport)) != exports {
		t.Fatal("second migration exported again")
	}
	if again, _ := e.srv.Secrets().Get(ctx, backupRepoSecret("mgone")); string(again) != legacy {
		t.Fatal("value changed on second run")
	}
	// a user backup call pushes creds first
	u := mustLogin(t, e, e.user, "mgone", "")
	e.ag.reset()
	if code, _ := u.call("GET", "/api/v1/user/backups", nil); code != 200 {
		t.Fatalf("list backups: %d", code)
	}
	if ms := e.ag.methods(); len(ms) < 2 || ms[0] != rpc.MBackupCredsLoad {
		t.Fatalf("creds not loaded before backup.list: %v", ms)
	}
	// never in logs, audit or the DB in clear
	if strings.Contains(logs.String(), legacy) || strings.Contains(logs.String(), string(gen)) {
		t.Fatal("password leaked into logs")
	}
	var n int
	e.srv.Store.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE detail LIKE ? OR target LIKE ?`, "%"+legacy+"%", "%"+legacy+"%").Scan(&n)
	if n != 0 {
		t.Fatal("password in audit log")
	}
	e.srv.Store.DB.QueryRow(`SELECT COUNT(*) FROM secrets WHERE CAST(ciphertext AS TEXT) LIKE ?`, "%"+legacy+"%").Scan(&n)
	if n != 0 {
		t.Fatal("password stored in clear")
	}
	if s := (rpc.BackupCredsLoad{Password: legacy}).String(); strings.Contains(s, legacy) {
		t.Fatal("BackupCredsLoad String leaks")
	}
}

// Without a usable secret store backups keep working on the legacy file.
func TestBackupCredsSecretStoreUnavailable(t *testing.T) {
	e := newEnv(t)
	e.srv.Cfg.SecretKeyFile = "/proc/nonexistent/secret.key"
	if err := e.srv.loadBackupCreds(context.Background(), "nobody"); err != nil {
		t.Fatalf("unavailable store must fall back: %v", err)
	}
	if len(e.ag.find(rpc.MBackupCredsLoad)) != 0 {
		t.Fatal("loaded creds without a store")
	}
}

func TestSecretsRotateAuth(t *testing.T) {
	e := newEnv(t)
	withSecrets(t, e)
	ctx := context.Background()
	if err := e.srv.Secrets().Put(ctx, "backup/repo/x", []byte("value-123456789012")); err != nil {
		t.Fatal(err)
	}
	before, _ := e.srv.Secrets().Status()["key_id"].(string)
	for _, role := range []string{rbac.ServerAdmin, rbac.SecurityAdmin, rbac.Auditor} {
		name := "rot" + strings.ReplaceAll(role, "_", "")
		staff(t, e, name, role)
		s := mustLogin(t, e, e.admin, name, "")
		if code, m := s.call("POST", "/api/v1/admin/secrets/rotate", nil); code != 403 {
			t.Fatalf("%s rotate: %d %v", role, code, m)
		}
	}
	// stale session → reauth_required
	s, code := e.login(e.admin, "rootadmin", "Admin-Pass-123", "", "")
	if s == nil {
		t.Fatalf("login %d", code)
	}
	e.srv.Store.DB.Exec(`UPDATE sessions SET created_at=?, reauth_at=0`, time.Now().Add(-time.Hour).Unix())
	if code, m := s.call("POST", "/api/v1/admin/secrets/rotate", nil); code != 403 || m["error"] != "reauth_required" {
		t.Fatalf("stale rotate: %d %v", code, m)
	}
	if code, _ := s.call("POST", "/api/v1/account/reauth", map[string]any{"password": "Admin-Pass-123"}); code != 200 {
		t.Fatalf("reauth %d", code)
	}
	code, m := s.call("POST", "/api/v1/admin/secrets/rotate", nil)
	if code != 200 || m["key_id"] == "" || m["key_id"] == before || m["previous_key_id"] != before || m["reencrypted"].(float64) < 1 {
		t.Fatalf("rotate: %d %v", code, m)
	}
	if v, err := e.srv.Secrets().Get(ctx, "backup/repo/x"); err != nil || string(v) != "value-123456789012" {
		t.Fatalf("value after rotate: %v", err)
	}
	var n int
	e.srv.Store.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='secrets.rotate' AND ok=1`).Scan(&n)
	if n != 1 {
		t.Fatalf("audit rows %d", n)
	}
	_ = errors.New
}
