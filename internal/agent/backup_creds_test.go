package agent

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// fakeRestic records argv and whether a password reached it via the env.
func fakeRestic(t *testing.T, dir string) (bin, log string) {
	t.Helper()
	bin, log = filepath.Join(dir, "restic"), filepath.Join(dir, "restic.log")
	script := "#!/bin/sh\n" +
		"echo \"ARGS $* PWENV=${RESTIC_PASSWORD:+set} PWFILE=${RESTIC_PASSWORD_FILE:-none}\" >> " + log + "\n" +
		"case \"$1\" in\n" +
		" forget) echo '[{\"keep\":[{\"id\":\"a\"},{\"id\":\"b\"}],\"remove\":[{\"id\":\"c\"}]}]' ;;\n" +
		" backup) echo '{\"message_type\":\"summary\",\"snapshot_id\":\"0123456789abcdef\"}' ;;\n" +
		"esac\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, log
}

func TestBackupCredsLoadForgetRetire(t *testing.T) {
	te := newTestEnv(t)
	a := te.a
	var logs bytes.Buffer
	a.Log = slog.New(slog.NewTextHandler(&logs, nil))
	bin, logf := fakeRestic(t, t.TempDir())
	a.Cfg.ResticBin = bin
	ctx := context.Background()
	t.Cleanup(func() { credsMu.Lock(); delete(credsMem, "tenant"); credsMu.Unlock() })

	// legacy file exists (pre-v0.4 install) and a repository exists
	if _, err := a.resticEnv("tenant"); err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(a.Cfg.BackupRepo, "tenant"), 0o700))
	must(os.WriteFile(filepath.Join(a.Cfg.BackupRepo, "tenant", "config"), []byte("x"), 0o600))

	ex, err := a.backupCredsExport(ctx, rpc.AccountRef{User: "tenant"})
	if err != nil || !ex.Found || len(ex.Password) < 16 {
		t.Fatalf("export: %v %+v", err, ex.Found)
	}
	// wrong value: file kept; right value: retired
	must2 := func(p rpc.BackupCredsLoad) {
		if _, err := a.backupCredsLoad(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	must2(rpc.BackupCredsLoad{User: "tenant", Password: "ffffffffffffffffffffffff", Retire: true})
	if _, err := os.Stat(a.legacyPassFile("tenant")); err != nil {
		t.Fatal("legacy file removed although values differ")
	}
	must2(rpc.BackupCredsLoad{User: "tenant", Password: ex.Password, Retire: true})
	if _, err := os.Stat(a.legacyPassFile("tenant")); !os.IsNotExist(err) {
		t.Fatal("legacy file not retired")
	}
	// second load is a no-op (idempotent)
	must2(rpc.BackupCredsLoad{User: "tenant", Password: ex.Password, Retire: true})

	res, err := a.backupForget(ctx, rpc.BackupForget{User: "tenant", Policy: rpc.RetentionPolicy{Daily: 7, Weekly: 4}})
	if err != nil || res.Kept != 2 || res.Removed != 1 {
		t.Fatalf("forget: %v %+v", err, res)
	}
	b, _ := os.ReadFile(logf)
	got := string(b)
	if !strings.Contains(got, "forget --prune --group-by host,paths --keep-daily 7 --keep-weekly 4 --json") {
		t.Fatalf("forget argv: %s", got)
	}
	if !strings.Contains(got, "PWENV=set PWFILE=none") {
		t.Fatalf("password not passed via env only: %s", got)
	}
	if strings.Contains(logs.String(), ex.Password) || strings.Contains(got, ex.Password) {
		t.Fatal("password leaked")
	}
	// keeps-nothing policy refused
	if _, err := a.backupForget(ctx, rpc.BackupForget{User: "tenant"}); code(err) != "invalid_retention" {
		t.Fatalf("empty policy: %v", err)
	}
	// password forgotten (agent restart) + legacy file gone + repo exists: never re-key
	credsMu.Lock()
	delete(credsMem, "tenant")
	credsMu.Unlock()
	if _, err := a.resticEnv("tenant"); code(err) != "backup_creds_missing" {
		t.Fatalf("re-key guard: %v", err)
	}
	if _, err := a.backupCredsLoad(ctx, rpc.BackupCredsLoad{User: "tenant", Password: "short"}); code(err) != "invalid_backup_password" {
		t.Fatalf("short password: %v", err)
	}
}
