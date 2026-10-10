package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/backup"
	"github.com/cumabozkurt/bpanel/internal/fileops"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// ---- FTP (Pure-FTPd virtual users mapped to the account uid) ----------------

var reFTPLogin = validate.FTPLoginPattern // same local-part rule as the API and /meta (H-5)

func (a *Agent) pureArgs(args ...string) []string {
	return append(append([]string{"pure-pw"}, args...), "-f", a.L.FTPPasswd, "-F", a.L.FTPPDB, "-m")
}

func (a *Agent) ftpCreate(ctx context.Context, p rpc.FTPAccount) (rpc.Empty, error) {
	if !reFTPLogin.MatchString(p.Login) {
		return rpc.Empty{}, errf("invalid_ftp_login", "%s", p.Login)
	}
	if err := validate.Password(p.Password); err != nil {
		return rpc.Empty{}, errf(err.Error(), "password")
	}
	e, err := a.home(p.User)
	if err != nil {
		return rpc.Empty{}, err
	}
	// CODE-27: an FTP login lives on one of the account's own domains
	if err := a.ownsAny(ftpDomain(p.Login), p.User, kindWeb); err != nil {
		return rpc.Empty{}, err
	}
	// Strict grammar: the directory is written into Pure-FTPd's colon-separated
	// passwd file, so ':' or a newline would inject fields/accounts (SEC-9).
	dir, err := validate.FTPDir(p.Dir)
	if err != nil {
		return rpc.Empty{}, errf(err.Error(), "%q", p.Dir)
	}
	if p.QuotaMB < 0 {
		return rpc.Empty{}, errf("invalid_quota", "%d", p.QuotaMB)
	}
	abs := filepath.Join(e.home, dir)
	if dir != "" {
		root, err := openHome(e)
		if err != nil {
			return rpc.Empty{}, err
		}
		err = mkdirOwned(root, dir, 0o755, e.uid, e.gid, false)
		root.Close()
		if err != nil {
			return rpc.Empty{}, err
		}
	}
	if !validate.ConfigSafe(abs) || strings.Contains(abs, ":") {
		return rpc.Empty{}, errf("invalid_path", "%q", p.Dir)
	}
	defer a.lock("ftp")()
	args := []string{"useradd", p.Login, "-u", strconv.Itoa(e.uid), "-g", strconv.Itoa(e.gid), "-d", abs}
	if p.QuotaMB > 0 {
		args = append(args, "-N", strconv.FormatInt(p.QuotaMB, 10))
	}
	pw := []byte(p.Password + "\n" + p.Password + "\n")
	_, err = run(ctx, pw, a.pureArgs(args...)...)
	return rpc.Empty{}, err
}

func ftpDomain(login string) string {
	_, d, _ := strings.Cut(login, "@")
	return d
}

func (a *Agent) ftpDelete(ctx context.Context, p rpc.FTPRef) (rpc.Empty, error) {
	if !reFTPLogin.MatchString(p.Login) {
		return rpc.Empty{}, errf("invalid_ftp_login", "%s", p.Login)
	}
	if err := a.ownsAny(ftpDomain(p.Login), p.Owner, kindWeb); err != nil { // CODE-27
		return rpc.Empty{}, err
	}
	defer a.lock("ftp")()
	out, err := run(ctx, nil, a.pureArgs("userdel", p.Login)...)
	if err != nil && strings.Contains(out, "doesn't exist") {
		err = nil
	}
	return rpc.Empty{}, err
}

func (a *Agent) ftpPassword(ctx context.Context, p rpc.FTPAccount) (rpc.Empty, error) {
	if !reFTPLogin.MatchString(p.Login) {
		return rpc.Empty{}, errf("invalid_ftp_login", "%s", p.Login)
	}
	if err := validate.Password(p.Password); err != nil {
		return rpc.Empty{}, errf(err.Error(), "password")
	}
	if err := a.ownsAny(ftpDomain(p.Login), p.User, kindWeb); err != nil { // CODE-27
		return rpc.Empty{}, err
	}
	defer a.lock("ftp")()
	_, err := run(ctx, []byte(p.Password+"\n"+p.Password+"\n"), a.pureArgs("passwd", p.Login)...)
	return rpc.Empty{}, err
}

// ---- cron -------------------------------------------------------------------

func (a *Agent) cronSet(ctx context.Context, p rpc.CronSet) (rpc.Empty, error) {
	ent, err := a.home(p.User)
	if err != nil {
		return rpc.Empty{}, err
	}
	if len(p.Entries) > 500 {
		return rpc.Empty{}, errf("invalid_cron", "too many jobs")
	}
	var b strings.Builder
	b.WriteString("# Managed by BOZKURT PANEL — edit cron jobs in the panel.\nSHELL=/bin/bash\n")
	b.WriteString("TMPDIR=" + ent.home + "/tmp\n") // per-tenant tmp (H-6)
	if p.Email != "" {
		if err := validate.Email(p.Email); err != nil {
			return rpc.Empty{}, errf("invalid_email", "%s", p.Email)
		}
		b.WriteString("MAILTO=" + p.Email + "\n")
	} else {
		b.WriteString("MAILTO=\"\"\n")
	}
	for _, e := range p.Entries {
		if err := validate.CronSchedule(e.Schedule[:]); err != nil {
			return rpc.Empty{}, errf("invalid_cron", "%v", e.Schedule)
		}
		if err := validate.CronCommand(e.Command); err != nil {
			return rpc.Empty{}, errf("invalid_cron_command", "")
		}
		b.WriteString(cronLine(e.Schedule, e.Command) + "\n")
	}
	_, err = run(ctx, []byte(b.String()), "crontab", "-u", p.User, "-")
	return rpc.Empty{}, err
}

// cronLine formats one crontab entry. A bare '%' would end the command and
// feed the rest to stdin, so it is escaped (CODE-17).
func cronLine(schedule [5]string, command string) string {
	return strings.Join(schedule[:], " ") + " " + validate.EscapeCronPercent(command)
}

// ---- files: helper process with the account's credentials --------------------

type helperReq struct {
	Home string     `json:"home"`
	Op   rpc.FileOp `json:"op"`
}

type helperResp struct {
	Result rpc.FileResult `json:"result"`
	Error  string         `json:"error,omitempty"`
}

func (a *Agent) files(ctx context.Context, p rpc.FileOp) (rpc.FileResult, error) {
	var res rpc.FileResult
	e, err := a.home(p.User)
	if err != nil {
		return res, err
	}
	self, err := os.Executable()
	if err != nil {
		return res, err
	}
	in, err := json.Marshal(helperReq{Home: e.home, Op: p})
	if err != nil {
		return res, err
	}
	cmd := exec.CommandContext(ctx, self, "files-helper")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + e.home}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(e.uid), Gid: uint32(e.gid), Groups: []uint32{}}}
	cmd.Stdin = bytes.NewReader(in)
	var out, serr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &serr
	if err := cmd.Run(); err != nil && out.Len() == 0 {
		return res, errf("files_helper", "%v: %s", err, serr.String())
	}
	var hr helperResp
	if err := json.Unmarshal(out.Bytes(), &hr); err != nil {
		return res, errf("files_helper", "bad helper response")
	}
	if hr.Error != "" {
		return res, errf(hr.Error, "%s", p.Path)
	}
	return hr.Result, nil
}

// RunFileHelper is the entry point of `bpanel-agent files-helper` (already running as the user).
func RunFileHelper() int {
	var req helperReq
	enc := json.NewEncoder(os.Stdout)
	reply := func(r helperResp, code int) int {
		if err := enc.Encode(r); err != nil {
			return 1
		}
		return code
	}
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		return reply(helperResp{Error: "bad_request"}, 1)
	}
	if os.Geteuid() == 0 {
		return reply(helperResp{Error: "helper_must_not_run_as_root"}, 1)
	}
	syscall.Umask(0o022)
	root, err := os.OpenRoot(req.Home)
	if err != nil {
		return reply(helperResp{Error: "home_unavailable"}, 1)
	}
	defer root.Close()
	res, err := fileops.Exec(root, req.Op)
	if err != nil {
		return reply(helperResp{Error: err.Error()}, 0)
	}
	return reply(helperResp{Result: res}, 0)
}

// ---- backups (restic) -------------------------------------------------------

func (a *Agent) resticEnv(user string) ([]string, error) {
	pwDir := a.Cfg.ResticPassDir
	if err := os.MkdirAll(pwDir, 0o700); err != nil {
		return nil, err
	}
	repoDir := filepath.Join(a.Cfg.BackupRepo, user)
	if pe := a.resticPasswordEnv(user); pe != "" { // v0.4: secret-store password, memory → child env only
		return []string{"RESTIC_REPOSITORY=" + repoDir, pe, "RESTIC_CACHE_DIR=" + a.resticCache,
			"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/root"}, nil
	}
	pwFile := filepath.Join(pwDir, user+".pass")
	if _, err := os.Stat(pwFile); os.IsNotExist(err) {
		if _, rerr := os.Stat(filepath.Join(repoDir, "config")); rerr == nil {
			return nil, errf("backup_creds_missing", "repository password not loaded") // never re-key an existing repo
		}
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		if err := writeAtomic(pwFile, []byte(fmt.Sprintf("%x\n", b)), 0o600, -1, -1); err != nil {
			return nil, err
		}
	}
	repo := filepath.Join(a.Cfg.BackupRepo, user)
	return []string{"RESTIC_REPOSITORY=" + repo, "RESTIC_PASSWORD_FILE=" + pwFile, "RESTIC_CACHE_DIR=" + a.resticCache,
		"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/root"}, nil
}

func (a *Agent) restic(ctx context.Context, env []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, a.Cfg.ResticBin, args...)
	cmd.Env = env
	var out, serr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &serr
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("restic %s: %v: %s", args[0], err, lastLines(serr.String(), 5))
	}
	return out.String(), nil
}

func (a *Agent) ensureRepo(ctx context.Context, env []string, user string) error {
	if _, err := os.Stat(filepath.Join(a.Cfg.BackupRepo, user, "config")); err == nil {
		return nil
	}
	if err := os.MkdirAll(a.Cfg.BackupRepo, 0o700); err != nil {
		return err
	}
	_, err := a.restic(ctx, env, "init")
	return err
}

func (a *Agent) backupRun(ctx context.Context, p rpc.BackupRun) (rpc.BackupRunResult, error) {
	var res rpc.BackupRunResult
	e, err := a.home(p.User)
	if err != nil {
		return res, err
	}
	env, err := a.resticEnv(p.User)
	if err != nil {
		return res, err
	}
	defer a.lock("backup-" + p.User)()
	if err := a.ensureRepo(ctx, env, p.User); err != nil {
		return res, err
	}
	// v0.4: independent manifest (sha256 per file) for restore verification
	man, merr := backup.BuildManifest(e.home, []string{filepath.Join(e.home, "backups")})
	out, err := a.restic(ctx, env, "backup", "--json", "--tag", "files", "--exclude", filepath.Join(e.home, "backups"), e.home)
	if err != nil {
		return res, err
	}
	res.SnapshotIDs = append(res.SnapshotIDs, snapshotFromJSON(out))
	if merr == nil {
		if err := a.recordManifest(p.User, man, snapshotFromJSON(out)); err != nil {
			a.Log.Warn("backup manifest", "user", p.User, "err", err)
		}
	}
	for _, db := range p.Databases {
		if err := checkDBName(db); err != nil || !strings.HasPrefix(db, p.User+"_") {
			return res, errf("invalid_db_name", "%s", db)
		}
		dump := exec.CommandContext(ctx, "mariadb-dump", "--single-transaction", "--routines", "--triggers", "--databases", db)
		dump.Env = []string{"PATH=/usr/bin:/bin", "HOME=/root"}
		bk := exec.CommandContext(ctx, a.Cfg.ResticBin, "backup", "--json", "--tag", "db,"+db, "--stdin", "--stdin-filename", db+".sql")
		bk.Env = env
		pipe, err := dump.StdoutPipe()
		if err != nil {
			return res, err
		}
		bk.Stdin = pipe
		var bout, berr, derr bytes.Buffer
		bk.Stdout, bk.Stderr, dump.Stderr = &bout, &berr, &derr
		if err := bk.Start(); err != nil {
			return res, err
		}
		if err := dump.Run(); err != nil {
			_ = bk.Process.Kill()
			_ = bk.Wait()
			return res, errf("dump_failed", "%s: %v %s", db, err, lastLines(derr.String(), 5))
		}
		if err := bk.Wait(); err != nil {
			return res, errf("backup_failed", "%s: %v %s", db, err, berr.String())
		}
		res.SnapshotIDs = append(res.SnapshotIDs, snapshotFromJSON(bout.String()))
	}
	if len(p.Databases) > 0 { // v0.4 dbx pg.go: databases requested -> PostgreSQL ones too (no-op without PostgreSQL)
		if err := a.pgBackup(ctx, env, p.User, &res); err != nil {
			return res, err
		}
	}
	return res, nil
}

func snapshotFromJSON(out string) string {
	for _, line := range strings.Split(out, "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["message_type"] == "summary" {
			if s, ok := m["snapshot_id"].(string); ok {
				return s
			}
		}
	}
	return ""
}

func (a *Agent) backupList(ctx context.Context, p rpc.AccountRef) (rpc.BackupList, error) {
	var res rpc.BackupList
	if _, err := a.home(p.User); err != nil {
		return res, err
	}
	env, err := a.resticEnv(p.User)
	if err != nil {
		return res, err
	}
	if _, err := os.Stat(filepath.Join(a.Cfg.BackupRepo, p.User, "config")); err != nil {
		return res, nil
	}
	out, err := a.restic(ctx, env, "snapshots", "--json")
	if err != nil {
		return res, err
	}
	var snaps []struct {
		ID      string   `json:"id"`
		ShortID string   `json:"short_id"`
		Time    string   `json:"time"`
		Paths   []string `json:"paths"`
		Tags    []string `json:"tags"`
	}
	if err := json.Unmarshal([]byte(out), &snaps); err != nil {
		return res, err
	}
	for i := len(snaps) - 1; i >= 0; i-- {
		s := snaps[i]
		res.Snapshots = append(res.Snapshots, rpc.BackupSnapshot{ID: s.ID, ShortID: s.ShortID, Time: s.Time, Paths: s.Paths, Tags: s.Tags})
	}
	return res, nil
}

// backupRestore restores a database or files from the account's restic repo.
//
// Files are never written into the home as root (SEC-3 / CODE-3): restic
// restores into a fresh root-owned staging directory outside /home, the tree
// is handed to the account, and the copy into the home runs as the account's
// uid. A tenant symlink in the home (or a pre-created restore-* symlink) can
// therefore only redirect writes to places the tenant could write anyway.
func (a *Agent) backupRestore(ctx context.Context, p rpc.BackupRestore) (rpc.BackupRestoreResult, error) {
	var res rpc.BackupRestoreResult
	if err := validate.Snapshot(p.Snapshot); err != nil {
		return res, errf("invalid_snapshot", "%s", p.Snapshot)
	}
	e, err := a.home(p.User)
	if err != nil {
		return res, err
	}
	env, err := a.resticEnv(p.User)
	if err != nil {
		return res, err
	}
	defer a.lock("backup-" + p.User)()
	if db, ok := strings.CutPrefix(p.Path, "db:"); ok {
		return a.restoreDB(ctx, env, p, db)
	}
	if db, ok := strings.CutPrefix(p.Path, "pg:"); ok { // v0.4 dbx pg.go
		return a.restorePG(ctx, env, p, db)
	}
	relp, err := validate.FilePath(p.Path)
	if err != nil || strings.ContainsAny(relp, "*?[]\\") {
		return res, errf("invalid_path", "%q", p.Path)
	}
	if err := a.checkRestoreDir(); err != nil {
		return res, err
	}
	staging, err := os.MkdirTemp(a.Cfg.RestoreDir, p.User+"-")
	if err != nil {
		return res, err
	}
	// The staging directory itself stays root-owned (0711): the account can
	// traverse it to copy its files but can never rename, replace or plant
	// entries at the top level while root still works in it (SEC-3).
	if err := os.Chmod(staging, 0o711); err != nil {
		return res, err
	}
	defer func() {
		// os.RemoveAll never follows symlinks (openat + O_NOFOLLOW)
		if err := os.RemoveAll(staging); err != nil {
			a.Log.Warn("restore: staging cleanup", "dir", staging, "err", err)
		}
	}()
	args := []string{"restore", p.Snapshot, "--target", staging}
	src := e.home
	if relp != "" {
		src = filepath.Join(e.home, relp)
		args = append(args, "--include", src)
	}
	if _, err := a.restic(ctx, env, args...); err != nil {
		return res, err
	}
	restored := filepath.Join(staging, src)
	st, err := os.Lstat(restored)
	if err != nil {
		return res, errf("not_found", "%s is not in snapshot %s", p.Path, p.Snapshot)
	}
	// Hand the restored tree (below the root-owned staging dir) to the
	// account. -h/-R with the default -P never follow a symlink, and
	// chown clears setuid/setgid bits on regular files.
	ents, err := os.ReadDir(staging)
	if err != nil {
		return res, err
	}
	for _, de := range ents {
		if _, err := run(ctx, nil, "chown", "-R", "-h", "-P", fmt.Sprintf("%d:%d", e.uid, e.gid), "--", filepath.Join(staging, de.Name())); err != nil {
			return res, err
		}
	}
	var dest string
	if p.InPlace {
		dest = src
	} else {
		target := filepath.Join(e.home, "backups", "restore-"+time.Now().Format("20060102-150405"))
		if _, err := runAs(ctx, e, "mkdir", "-p", "--", target); err != nil {
			return res, err
		}
		dest = filepath.Join(target, filepath.Base(src))
		if relp == "" {
			dest = target
		}
		res.RestoredTo = target
	}
	switch {
	case st.IsDir() && p.InPlace && relp != "":
		err = a.swapRestore(ctx, e, restored, dest)
	case st.IsDir():
		if _, err := runAs(ctx, e, "mkdir", "-p", "--", dest); err != nil {
			return res, err
		}
		// --remove-destination: read-only files (Dovecot's 0444
		// dovecot-uidvalidity.*) are replaced instead of failing (R2-E2E-9)
		_, err = runAs(ctx, e, "cp", "-a", "--no-preserve=ownership", "--remove-destination", "--", restored+"/.", dest+"/")
	default:
		_, err = runAs(ctx, e, "cp", "-a", "--no-preserve=ownership", "--remove-destination", "--", restored, dest)
	}
	if err != nil {
		return res, errf("restore_failed", "%v", err)
	}
	if res.RestoredTo == "" {
		res.RestoredTo = dest
	}
	return res, nil
}

// swapRestore restores a directory in place atomically (R2-E2E-9): the
// current tree and the snapshot are merged into a temporary sibling (as
// the account, files of the snapshot win), which then replaces the
// directory with two renames. A failure at any point leaves the original
// untouched; mail delivered meanwhile stays in the merged copy only if it
// arrived before the copy, so the window is the copy time, not the restore.
func (a *Agent) swapRestore(ctx context.Context, e passwdEntry, restored, dest string) error {
	parent := filepath.Dir(dest)
	tag := fmt.Sprintf("%d", time.Now().UnixNano())
	tmp := filepath.Join(parent, ".bpanel-restore-"+tag)
	old := filepath.Join(parent, ".bpanel-old-"+tag)
	cleanup := func(p string) {
		if _, err := runAs(context.WithoutCancel(ctx), e, "rm", "-rf", "--", p); err != nil {
			a.Log.Warn("restore: cleanup", "path", p, "err", err)
		}
	}
	if _, err := runAs(ctx, e, "mkdir", "-p", "--", tmp); err != nil {
		return err
	}
	if _, err := os.Lstat(dest); err == nil {
		if _, err := runAs(ctx, e, "cp", "-a", "--", dest+"/.", tmp+"/"); err != nil {
			cleanup(tmp)
			return err
		}
	}
	if _, err := runAs(ctx, e, "cp", "-a", "--no-preserve=ownership", "--remove-destination", "--", restored+"/.", tmp+"/"); err != nil {
		cleanup(tmp)
		return err
	}
	hadDest := false
	if _, err := os.Lstat(dest); err == nil {
		hadDest = true
		if _, err := runAs(ctx, e, "mv", "-T", "--", dest, old); err != nil {
			cleanup(tmp)
			return err
		}
	}
	if _, err := runAs(ctx, e, "mv", "-T", "--", tmp, dest); err != nil {
		if hadDest {
			if _, rerr := runAs(context.WithoutCancel(ctx), e, "mv", "-T", "--", old, dest); rerr != nil {
				a.Log.Error("restore: could not put the original back", "dest", dest, "err", rerr)
			}
		}
		cleanup(tmp)
		return err
	}
	if hadDest {
		cleanup(old)
	}
	return nil
}

// checkRestoreDir makes sure the restic staging area is a real directory
// (not a symlink) owned by root with mode 0711, creating it if missing. A
// symlinked or foreign-owned restore_dir would let root write and chown
// restored files somewhere else (SEC-3).
func (a *Agent) checkRestoreDir() error {
	dir := a.Cfg.RestoreDir
	if !filepath.IsAbs(dir) {
		return errf("restore_dir_unsafe", "%s is not absolute", dir)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o711); err != nil && !os.IsExist(err) {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return errf("restore_dir_unsafe", "%s is not a directory", dir)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 && sys.Uid != 0 {
		return errf("restore_dir_unsafe", "%s is not owned by root", dir)
	}
	return os.Chmod(dir, 0o711)
}

// restoreDB streams one database dump into MariaDB. --one-database makes the
// client ignore every statement for any other database, so a tampered dump
// cannot touch another tenant's data.
func (a *Agent) restoreDB(ctx context.Context, env []string, p rpc.BackupRestore, db string) (rpc.BackupRestoreResult, error) {
	var res rpc.BackupRestoreResult
	if err := checkDBName(db); err != nil || !strings.HasPrefix(db, p.User+"_") {
		return res, errf("invalid_db_name", "%s", db)
	}
	// R2-E2E-9: a files snapshot holds no dump: say so (422) instead of a
	// restic error (502)
	if out, err := a.restic(ctx, env, "ls", "--json", p.Snapshot, "/"+db+".sql"); err != nil || !strings.Contains(out, `"/`+db+`.sql"`) {
		return res, errf("snapshot_kind_mismatch", "snapshot %s holds no dump of %s", p.Snapshot, db)
	}
	// R2-WB-8: the dump is replayed by a temporary MariaDB user that can
	// only touch this database, by a client running as nobody, with
	// --sandbox (no \! shell escapes) where the client supports it.
	user, pw, dropUser, err := a.restoreUser(ctx, db)
	if err != nil {
		return res, errf("restore_failed", "temporary user: %v", err)
	}
	defer dropUser()
	cnf, rmCnf, err := clientDefaults(user, pw)
	if err != nil {
		return res, err
	}
	defer rmCnf()
	args := []string{"--defaults-extra-file=" + cnf, "--one-database", "--binary-mode"}
	if clientHasSandbox(ctx) {
		args = append(args, "--sandbox")
	}
	if a.L != nil && a.L.MySQLSocket != "" {
		args = append(args, "--socket="+a.L.MySQLSocket)
	}
	args = append(args, db)
	dump := exec.CommandContext(ctx, a.Cfg.ResticBin, "dump", p.Snapshot, "/"+db+".sql")
	dump.Env = env
	imp := exec.CommandContext(ctx, "mariadb", args...)
	imp.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	if os.Geteuid() == 0 {
		if nb, err := lookupUser("nobody"); err == nil {
			if err := os.Chown(cnf, nb.uid, nb.gid); err != nil {
				return res, err
			}
			imp.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(nb.uid), Gid: uint32(nb.gid), Groups: []uint32{}}}
		}
	}
	pipe, err := dump.StdoutPipe()
	if err != nil {
		return res, err
	}
	imp.Stdin = pipe
	var ierr, derr bytes.Buffer
	imp.Stderr = &ierr
	dump.Stderr = &derr
	if err := imp.Start(); err != nil {
		return res, err
	}
	if err := dump.Run(); err != nil {
		_ = imp.Process.Kill()
		_ = imp.Wait()
		return res, errf("restore_failed", "%v %s", err, lastLines(derr.String(), 3))
	}
	if err := imp.Wait(); err != nil {
		return res, errf("restore_failed", "%v %s", err, lastLines(ierr.String(), 3))
	}
	res.RestoredTo = "database " + db
	return res, nil
}
