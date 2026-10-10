package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// ---- R2-PERF-9: limits for many accounts, one daemon-reload -------------------

func (a *Agent) accountQuotaBatch(ctx context.Context, p rpc.AccountQuotaBatch) (rpc.AccountQuotaBatchResult, error) {
	res := rpc.AccountQuotaBatchResult{Failed: map[string]string{}}
	if len(p.Items) > 10000 {
		return res, errf("bad_params", "too many accounts")
	}
	reload := false
	for _, q := range p.Items {
		e, err := a.managedHome(q.User) // R2-WB-1: every item
		if err == nil {
			err = a.applyLimitsNoReload(ctx, e, q)
			reload = true
		}
		if err != nil {
			var re *rpc.Error
			code := "limits_failed"
			if errors.As(err, &re) {
				code = re.Code
			}
			res.Failed[q.User] = code
			a.Log.Warn("quota batch", "user", q.User, "err", err)
		}
	}
	if reload && !a.Cfg.NoSystemd {
		if _, err := run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
			return res, errf("limits_failed", "daemon-reload: %v", err)
		}
	}
	return res, nil
}

// ---- R2-PERF-14: stale restic locks after a crash ---------------------------------

// UnlockRepos removes stale restic locks of every account repository once at
// start (a backup killed with -9 left its lock, and every later backup of
// that account failed). `restic unlock` only removes locks whose process is
// gone, so a backup running elsewhere is not affected.
func (a *Agent) UnlockRepos(ctx context.Context) {
	ents, err := os.ReadDir(a.Cfg.BackupRepo)
	if err != nil {
		return
	}
	for _, de := range ents {
		if ctx.Err() != nil {
			return
		}
		if !de.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(a.Cfg.BackupRepo, de.Name(), "config")); err != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(a.Cfg.ResticPassDir, de.Name()+".pass")); err != nil {
			continue
		}
		env, err := a.resticEnv(de.Name())
		if err != nil {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		if _, err := a.restic(cctx, env, "unlock"); err != nil {
			a.Log.Warn("restic unlock at start", "repo", de.Name(), "err", err)
		}
		cancel()
	}
}

// ---- R2-E2E-10: home permissions -------------------------------------------------

// homeMode is the mode of an account's home: the owner has everything, the
// web server group may only traverse (to reach public_html), nobody else
// may even enter. 0711 let every tenant read world-readable files at the top
// of every other home (/home/ct2/.bash_logout).
const homeMode = 0o710

// secureHome sets the home to user:<web group> 0710 and removes group/other
// access from the regular files at its top level (the skeleton dotfiles
// useradd copies with 0644). It never follows symlinks.
func (a *Agent) secureHome(e passwdEntry) error {
	webGID, err := groupID(a.L.WebGroup)
	if err != nil {
		webGID = e.gid
	}
	st, err := os.Lstat(e.home)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errf("home_unavailable", "%s", e.home)
	}
	if os.Geteuid() == 0 {
		if err := os.Lchown(e.home, e.uid, webGID); err != nil {
			return err
		}
	}
	if err := os.Chmod(e.home, homeMode); err != nil {
		return err
	}
	root, err := openHome(e)
	if err != nil {
		return err
	}
	defer root.Close()
	ents, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return err
	}
	for _, de := range ents {
		if !de.Type().IsRegular() {
			continue
		}
		f, err := root.OpenFile(de.Name(), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			continue
		}
		if fi, err := f.Stat(); err == nil && fi.Mode().IsRegular() {
			if sys, ok := fi.Sys().(*syscall.Stat_t); ok && int(sys.Uid) == e.uid && fi.Mode().Perm()&0o077 != 0 {
				_ = f.Chmod(fi.Mode().Perm() &^ 0o077) // skel files: 0644 -> 0600
			}
		}
		f.Close()
	}
	return nil
}

// MigrateHomes applies secureHome to every managed account once at start,
// so homes created by v0.1/v0.2 (0711, 0644 dotfiles) are fixed on upgrade.
func (a *Agent) MigrateHomes() {
	ents, err := readPasswd()
	if err != nil {
		return
	}
	n := 0
	for _, e := range ents {
		if !strings.HasPrefix(e.home, a.Cfg.HomeBase+"/") || e.uid < 1000 || e.uid >= 60000 || !a.isManaged(e) {
			continue
		}
		st, err := os.Lstat(e.home)
		if err != nil || !st.IsDir() {
			continue
		}
		if st.Mode().Perm() == homeMode {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				if g, err := groupID(a.L.WebGroup); err != nil || int(sys.Gid) == g {
					continue
				}
			}
		}
		if err := a.secureHome(e); err != nil {
			a.Log.Warn("home permissions migration", "user", e.name, "err", err)
			continue
		}
		n++
	}
	if n > 0 {
		a.Log.Info("home permissions migrated (0710, group web)", "accounts", n)
	}
}

// ---- R2-WB-3: mail usage without following tenant symlinks ---------------------

// mailUsageIn sums each mailbox directory of one domain through an os.Root
// opened on the home: a tenant symlink (~/mail/<domain> -> another tenant's
// mail, or /root) can no longer make root list or size directories outside
// the home.
func mailUsageIn(ctx context.Context, root *os.Root, domain string) (map[string]int64, error) {
	out := map[string]int64{}
	dir := "mail/" + domain
	if err := checkNoSymlinks(root, dir); err != nil {
		return out, nil // a symlinked mail dir is ignored, never followed
	}
	ents, err := fs.ReadDir(root.FS(), dir)
	if err != nil {
		return out, nil // no mail directory yet
	}
	for _, de := range ents {
		if !de.IsDir() || de.Type()&fs.ModeSymlink != 0 {
			continue
		}
		var total int64
		err := fs.WalkDir(root.FS(), dir+"/"+de.Name(), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			info, ierr := d.Info()
			if ierr != nil {
				return nil
			}
			sz := info.Size()
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				sz = st.Blocks * 512
			}
			total += sz
			return nil
		})
		if err != nil {
			return out, err
		}
		out[de.Name()+"@"+domain] = total
	}
	return out, nil
}

// ---- R2-WB-8: database restore as a restricted MariaDB user ------------------------

// restoreUser creates a short-lived MariaDB account that can only touch db,
// so a crafted dump (other databases, GRANT, user tables, FILE/SUPER
// statements) fails instead of running as root. It returns the account,
// its password and a cleanup function.
func (a *Agent) restoreUser(ctx context.Context, db string) (string, string, func(), error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", "", nil, err
	}
	user := "bprst_" + hex.EncodeToString(b)
	pwb := make([]byte, 24)
	if _, err := rand.Read(pwb); err != nil {
		return "", "", nil, err
	}
	pw := hex.EncodeToString(pwb)
	conn, err := a.mysql(ctx)
	if err != nil {
		return "", "", nil, err
	}
	if _, err := conn.ExecContext(ctx, "CREATE USER "+sqlString(user)+"@'localhost' IDENTIFIED BY "+sqlString(pw)); err != nil {
		conn.Close()
		return "", "", nil, err
	}
	drop := func() {
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		if _, err := conn.ExecContext(dctx, "DROP USER IF EXISTS "+sqlString(user)+"@'localhost'"); err != nil {
			a.Log.Warn("restore: drop temporary user", "user", user, "err", err)
		}
		conn.Close()
	}
	// everything a dump needs on this one database, nothing global
	if _, err := conn.ExecContext(ctx, "GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE, CREATE VIEW, SHOW VIEW, CREATE ROUTINE, ALTER ROUTINE, EVENT, TRIGGER, REFERENCES ON "+ident(db)+".* TO "+sqlString(user)+"@'localhost'"); err != nil {
		drop()
		return "", "", nil, err
	}
	return user, pw, drop, nil
}

func sqlString(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

// clientDefaults writes a 0600 option file for the mariadb client so the
// password never appears in argv or the environment.
func clientDefaults(user, pw string) (string, func(), error) {
	f, err := os.CreateTemp("", "bpanel-restore-*.cnf")
	if err != nil {
		return "", nil, err
	}
	name := f.Name()
	cleanup := func() { _ = os.Remove(name) }
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		cleanup()
		return "", nil, err
	}
	_, err = fmt.Fprintf(f, "[client]\nuser=%s\npassword=%s\n", user, pw)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		cleanup()
		return "", nil, err
	}
	return name, cleanup, nil
}

// clientHasSandbox reports whether the mariadb client knows --sandbox
// (MariaDB >= 10.5.25 / 10.6.18 / 10.11.8 / 11.x): it refuses \! and other
// client commands that a dump could use to run shell commands as root.
func clientHasSandbox(ctx context.Context) bool {
	out, err := run(ctx, nil, "mariadb", "--help")
	return err == nil && strings.Contains(out, "--sandbox")
}
