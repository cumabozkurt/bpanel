package agent

// v0.4 backup module: restore verification + admin-only snapshot deletion,
// built on internal/backup. Repository passwords stay in Cfg.ResticPassDir
// (root, 0600, checked before every call); manifests live in
// <BackupRepo>/.manifests (root 0700) and are never readable by accounts.

import (
	"context"
	"os"
	"path/filepath"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/backup"
)

func (a *Agent) backupEngine(user string) (*backup.Engine, error) {
	if _, err := a.resticEnv(user); err != nil { // creates the 0600 password file when missing
		return nil, err
	}
	mc, _ := memPassword(user)
	return &backup.Engine{
		Password:     mc.password, // v0.4 part B: secret store (memory), else legacy file
		Creds:        mc.target,
		Bin:          a.Cfg.ResticBin,
		Target:       backup.Target{Kind: backup.KindLocal, Path: a.Cfg.BackupRepo},
		PasswordFile: filepath.Join(a.Cfg.ResticPassDir, user+".pass"),
		CacheDir:     a.resticCache,
		ManifestDir:  filepath.Join(a.Cfg.BackupRepo, ".manifests"),
		SecretUID:    os.Geteuid(), // root in production
	}, nil
}

// recordManifest stores the backup-time manifest for a files snapshot.
// Failure is logged by the caller but does not fail the backup itself.
func (a *Agent) recordManifest(user string, m *backup.Manifest, snap string) error {
	if m == nil || snap == "" {
		return nil
	}
	eng, err := a.backupEngine(user)
	if err != nil {
		return err
	}
	m.DropChanged()
	m.SnapshotID = snap
	return eng.SaveManifest(user, m)
}

func (a *Agent) backupVerify(ctx context.Context, p rpc.BackupVerify) (rpc.BackupVerification, error) {
	var res rpc.BackupVerification
	if _, err := a.home(p.User); err != nil {
		return res, err
	}
	if _, err := os.Stat(filepath.Join(a.Cfg.BackupRepo, p.User, "config")); err != nil {
		res.User, res.Status, res.Error = p.User, "no_snapshot", "no backup repository"
		return res, nil
	}
	eng, err := a.backupEngine(p.User)
	if err != nil {
		return res, err
	}
	if err := os.MkdirAll(a.Cfg.RestoreDir, 0o700); err != nil {
		return res, err
	}
	defer a.lock("backup-" + p.User)()
	v := eng.VerifyRestore(ctx, p.User, backup.VerifyOptions{ReadDataSubset: p.Subset, TempDir: a.Cfg.RestoreDir})
	return rpc.BackupVerification{User: p.User, SnapshotID: v.SnapshotID, Started: v.Started.Format(time.RFC3339),
		Finished: v.Finished.Format(time.RFC3339), FilesChecked: v.FilesChecked, Mismatches: v.Mismatches,
		CheckOK: v.CheckOK, Status: v.Status, Error: v.Error, Samples: v.Samples}, nil
}

func (a *Agent) backupDelete(ctx context.Context, p rpc.BackupDelete) (struct{}, error) {
	if _, err := a.home(p.User); err != nil {
		return struct{}{}, err
	}
	eng, err := a.backupEngine(p.User)
	if err != nil {
		return struct{}{}, err
	}
	defer a.lock("backup-" + p.User)()
	if err := eng.ForgetSnapshot(ctx, p.User, p.Snapshot); err != nil {
		return struct{}{}, errf("backup_failed", "%v", err)
	}
	_ = os.Remove(filepath.Join(a.Cfg.BackupRepo, ".manifests", p.User, p.Snapshot+".json"))
	return struct{}{}, nil
}
