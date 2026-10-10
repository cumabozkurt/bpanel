package agent

// v0.4 backup part B: repository passwords and target credentials are owned by
// the panel secret store (internal/secrets). The panel pushes them with
// backup.creds.load before every backup operation; the agent keeps them in
// memory only and passes them to restic via RESTIC_PASSWORD in the child env.
// The legacy <ResticPassDir>/<user>.pass file is exported once
// (backup.creds.export) and removed by a load with Retire=true once the panel
// has stored the same value. Secrets are never logged or put into errors.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/backup"
)

type memCreds struct {
	password string
	target   backup.Creds
}

var (
	credsMu  sync.RWMutex
	credsMem = map[string]memCreds{} // per account; one agent per process
)

// BackupForgetTimeout bounds one retention run.
const BackupForgetTimeout = 30 * time.Minute

func memPassword(user string) (memCreds, bool) {
	credsMu.RLock()
	defer credsMu.RUnlock()
	c, ok := credsMem[user]
	return c, ok && c.password != ""
}

func (a *Agent) legacyPassFile(user string) string {
	return filepath.Join(a.Cfg.ResticPassDir, user+".pass")
}

func (a *Agent) backupCredsExport(_ context.Context, p rpc.AccountRef) (rpc.BackupCredsExport, error) {
	var res rpc.BackupCredsExport
	if _, err := a.home(p.User); err != nil {
		return res, err
	}
	f := a.legacyPassFile(p.User)
	if err := backup.CheckSecretFile(f, os.Geteuid()); err != nil {
		if os.IsNotExist(err) {
			return res, nil
		}
		return res, errf("backup_creds_insecure", "legacy password file failed the 0600/root check")
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return res, errf("backup_creds_unreadable", "legacy password file unreadable")
	}
	res.Found, res.Password = true, strings.TrimRight(string(b), "\r\n")
	if a.Cfg.BackupCredsFile != "" {
		if c, err := backup.LoadCreds(a.Cfg.BackupCredsFile, os.Geteuid()); err == nil {
			res.TargetCreds = map[string]string{"s3_access_key": c.S3AccessKey, "s3_secret_key": c.S3SecretKey}
		}
	}
	return res, nil
}

func (a *Agent) backupCredsLoad(_ context.Context, p rpc.BackupCredsLoad) (struct{}, error) {
	if _, err := a.home(p.User); err != nil {
		return struct{}{}, err
	}
	if len(p.Password) < 16 || strings.ContainsAny(p.Password, "\x00\n\r") {
		return struct{}{}, errf("invalid_backup_password", "repository password rejected")
	}
	credsMu.Lock()
	credsMem[p.User] = memCreds{password: p.Password, target: backup.Creds{S3AccessKey: p.TargetCreds["s3_access_key"], S3SecretKey: p.TargetCreds["s3_secret_key"]}}
	credsMu.Unlock()
	if p.Retire {
		f := a.legacyPassFile(p.User)
		if b, err := os.ReadFile(f); err == nil && strings.TrimRight(string(b), "\r\n") == p.Password {
			if err := os.Remove(f); err == nil {
				a.Log.Info("backup legacy password file retired", "user", p.User)
			}
		}
	}
	return struct{}{}, nil
}

func (a *Agent) backupForget(ctx context.Context, p rpc.BackupForget) (rpc.BackupForgetResult, error) {
	var res rpc.BackupForgetResult
	if _, err := a.home(p.User); err != nil {
		return res, err
	}
	pol := backup.Retention{Last: p.Policy.Last, Daily: p.Policy.Daily, Weekly: p.Policy.Weekly, Monthly: p.Policy.Monthly, Yearly: p.Policy.Yearly}
	if _, err := pol.ForgetArgs(); err != nil {
		return res, errf("invalid_retention", "%v", err)
	}
	if _, err := os.Stat(filepath.Join(a.Cfg.BackupRepo, p.User, "config")); err != nil {
		return res, nil // no repository yet: nothing to prune
	}
	eng, err := a.backupEngine(p.User)
	if err != nil {
		return res, err
	}
	eng.Timeout = BackupForgetTimeout
	defer a.lock("backup-" + p.User)()
	out, err := eng.Forget(ctx, p.User, pol)
	if err != nil {
		return res, errf("retention_failed", "%v", err)
	}
	res.Kept, res.Removed = backup.ForgetCounts(out)
	return res, nil
}

// resticPasswordEnv returns "RESTIC_PASSWORD=..." when the panel pushed the
// account's secret-store password, else "" (caller falls back to the legacy
// file, which is only created for an account without a repository).
func (a *Agent) resticPasswordEnv(user string) string {
	if c, ok := memPassword(user); ok {
		return "RESTIC_PASSWORD=" + c.password
	}
	return ""
}
