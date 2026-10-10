package agent

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

// Symlink-safe file operations inside a tenant's home (SEC-2 / CODE-3).
//
// The agent runs as root, and everything below /home/<user> is controlled by
// the tenant (PHP, SFTP, cron can create symlinks there). Every root-run
// operation on a path inside a home therefore goes through an os.Root opened
// on the home directory (openat-based, so a path can never resolve outside
// it), and additionally refuses symlinked path components, so the agent never
// chowns, creates or removes something the tenant pointed it at.

// openHome opens an os.Root on a managed account's home, refusing a home that
// is itself a symlink.
func openHome(e passwdEntry) (*os.Root, error) {
	st, err := os.Lstat(e.home)
	if err != nil {
		return nil, errf("home_unavailable", "%s: %v", e.name, err)
	}
	if st.Mode()&fs.ModeSymlink != 0 || !st.IsDir() {
		return nil, errf("home_unavailable", "home of %s is not a directory", e.name)
	}
	r, err := os.OpenRoot(e.home)
	if err != nil {
		return nil, errf("home_unavailable", "%s: %v", e.name, err)
	}
	return r, nil
}

// cleanRel validates a home-relative path for internal use (no escapes).
func cleanRel(rel string) (string, error) {
	c := path.Clean("/" + rel)
	if c == "/" {
		return ".", nil
	}
	c = strings.TrimPrefix(c, "/")
	for _, seg := range strings.Split(c, "/") {
		if seg == ".." {
			return "", errf("invalid_path", "%s", rel)
		}
	}
	return c, nil
}

// checkNoSymlinks makes sure no existing component of rel (inside root) is a
// symlink. Missing components are fine.
func checkNoSymlinks(root *os.Root, rel string) error {
	cur := ""
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || seg == "." {
			continue
		}
		cur = path.Join(cur, seg)
		st, err := root.Lstat(cur)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return mapFSErr(err, rel)
		}
		if st.Mode()&fs.ModeSymlink != 0 {
			return errf("symlink_in_path", "%s: %s is a symbolic link", rel, cur)
		}
	}
	return nil
}

// mkdirOwned creates rel (and missing parents) inside root, never following
// symlinks. Newly created directories get mode and uid:gid. With fixExisting
// the last component's mode and owner are enforced even if it already existed.
func mkdirOwned(root *os.Root, rel string, mode os.FileMode, uid, gid int, fixExisting bool) error {
	rel, err := cleanRel(rel)
	if err != nil {
		return err
	}
	if rel == "." {
		return errf("invalid_path", "refusing to modify the home itself")
	}
	segs := strings.Split(rel, "/")
	cur := ""
	for i, seg := range segs {
		cur = path.Join(cur, seg)
		last := i == len(segs)-1
		st, err := root.Lstat(cur)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := root.Mkdir(cur, mode); err != nil && !errors.Is(err, fs.ErrExist) {
				return mapFSErr(err, rel)
			}
			// re-check: the tenant may have raced us with a symlink
			if st, err = root.Lstat(cur); err != nil || !st.IsDir() || st.Mode()&fs.ModeSymlink != 0 {
				return errf("symlink_in_path", "%s: %s changed while creating it", rel, cur)
			}
			if err := root.Lchown(cur, uid, gid); err != nil {
				return mapFSErr(err, rel)
			}
			if err := root.Chmod(cur, mode); err != nil {
				return mapFSErr(err, rel)
			}
		case err != nil:
			return mapFSErr(err, rel)
		case st.Mode()&fs.ModeSymlink != 0:
			return errf("symlink_in_path", "%s: %s is a symbolic link", rel, cur)
		case !st.IsDir():
			return errf("not_a_directory", "%s: %s is not a directory", rel, cur)
		case last && fixExisting:
			if err := root.Lchown(cur, uid, gid); err != nil {
				return mapFSErr(err, rel)
			}
			if err := root.Chmod(cur, mode); err != nil {
				return mapFSErr(err, rel)
			}
		}
	}
	return nil
}

// removeAllIn removes rel inside root (rm -rf) after making sure none of its
// parent components is a symlink. A symlink as the final component is
// removed itself, never its target.
func removeAllIn(root *os.Root, rel string) error {
	rel, err := cleanRel(rel)
	if err != nil {
		return err
	}
	if rel == "." {
		return errf("refused", "refusing to remove the home itself")
	}
	if err := checkNoSymlinks(root, path.Dir(rel)); err != nil {
		return err
	}
	if err := root.RemoveAll(rel); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return mapFSErr(err, rel)
	}
	return nil
}

// createFileOwned creates a new file (O_EXCL: never overwrites, never follows
// a symlink) inside root and hands it to uid:gid via fchown.
func createFileOwned(root *os.Root, rel string, data []byte, mode os.FileMode, uid, gid int) error {
	rel, err := cleanRel(rel)
	if err != nil {
		return err
	}
	if err := checkNoSymlinks(root, path.Dir(rel)); err != nil {
		return err
	}
	f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return mapFSErr(err, rel)
	}
	if err := f.Chown(uid, gid); err != nil {
		f.Close()
		return mapFSErr(err, rel)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return mapFSErr(err, rel)
	}
	return f.Close()
}

func mapFSErr(err error, p string) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return errf("not_found", "%s", p)
	case errors.Is(err, fs.ErrExist):
		return errf("already_exists", "%s", p)
	case errors.Is(err, fs.ErrPermission):
		return errf("permission_denied", "%s", p)
	case errors.Is(err, syscall.ENOTDIR):
		return errf("not_a_directory", "%s", p)
	case errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
		return errf("quota_exceeded", "%s", p)
	case strings.Contains(err.Error(), "escapes from parent") || strings.Contains(err.Error(), "path escapes"):
		return errf("symlink_in_path", "%s leaves the home directory", p)
	}
	return errf("io_error", "%s: %v", p, err)
}

// userCmd builds a command that runs with the account's uid/gid (no
// supplementary groups) when the agent is root. Used for everything that
// writes tenant-controlled data into a home, so a symlink planted by the
// tenant can only ever reach files the tenant could write anyway.
func userCmd(ctx context.Context, e passwdEntry, argv ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "HOME=" + e.home}
	cmd.Dir = "/"
	if os.Geteuid() == 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(e.uid), Gid: uint32(e.gid), Groups: []uint32{}}}
	}
	return cmd
}

// runAs runs argv as the account and returns combined output.
func runAs(ctx context.Context, e passwdEntry, argv ...string) (string, error) {
	cmd := userCmd(ctx, e, argv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), errf("action_failed", "%s: %v: %s", filepath.Base(argv[0]), err, strings.TrimSpace(lastLines(string(out), 5)))
	}
	return string(out), nil
}
