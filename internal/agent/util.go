package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// run executes argv (never through a shell) and returns combined output.
func run(ctx context.Context, stdin []byte, argv ...string) (string, error) {
	if len(argv) == 0 {
		return "", errors.New("empty argv")
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "DEBIAN_FRONTEND=noninteractive", "HOME=/root"}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	s := out.String()
	if err != nil {
		return s, fmt.Errorf("%s: %v: %s", argv[0], err, strings.TrimSpace(lastLines(s, 8)))
	}
	return s, nil
}

func lastLines(s string, n int) string {
	ls := strings.Split(strings.TrimSpace(s), "\n")
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	return strings.Join(ls, "\n")
}

func have(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// writeAtomic writes via a temp file + rename, keeping a .bpanel-bak of the old content.
func writeAtomic(path string, data []byte, mode os.FileMode, uid, gid int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".bpanel-*")
	if err != nil {
		return err
	}
	cleanup := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return cleanup(err)
	}
	if err := tmp.Chmod(mode); err != nil {
		return cleanup(err)
	}
	if uid >= 0 {
		if err := tmp.Chown(uid, gid); err != nil {
			return cleanup(err)
		}
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return nil
}

// transaction tracks file writes so a failed config test can roll them back.
type transaction struct {
	backups map[string][]byte // nil value = file did not exist
}

func newTx() *transaction { return &transaction{backups: map[string][]byte{}} }

func (t *transaction) write(path string, data []byte, mode os.FileMode) error {
	if _, seen := t.backups[path]; !seen {
		old, err := os.ReadFile(path)
		if err != nil {
			old = nil
		}
		t.backups[path] = old
	}
	return writeAtomic(path, data, mode, -1, -1)
}

func (t *transaction) remove(path string) error {
	if _, seen := t.backups[path]; !seen {
		old, err := os.ReadFile(path)
		if err != nil {
			return nil // nothing to remove
		}
		t.backups[path] = old
	}
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (t *transaction) rollback() {
	for p, old := range t.backups {
		var err error
		if old == nil {
			err = os.Remove(p)
			if os.IsNotExist(err) {
				err = nil
			}
		} else {
			err = writeAtomic(p, old, 0o644, -1, -1)
		}
		if err != nil {
			slogDefault().Error("rollback of managed file failed", "path", p, "err", err)
		}
	}
}

// systemctl wraps service management; in NoSystemd (test) mode it is a no-op.
func (a *Agent) systemctl(ctx context.Context, action, unit string) error {
	if a.Cfg.NoSystemd {
		a.Log.Info("no_systemd: skipped", "action", action, "unit", unit)
		return nil
	}
	_, err := run(ctx, nil, "systemctl", action, unit)
	return err
}

type passwdEntry struct {
	name     string
	uid, gid int
	home     string
	shell    string
}

// passwdFile and groupFile are variables so tests can use fake databases.
var (
	passwdFile = "/etc/passwd"
	groupFile  = "/etc/group"
)

func readPasswd() ([]passwdEntry, error) {
	f, err := os.Open(passwdFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []passwdEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) < 7 {
			continue
		}
		uid, uerr := strconv.Atoi(p[2])
		gid, gerr := strconv.Atoi(p[3])
		if uerr != nil || gerr != nil {
			continue
		}
		out = append(out, passwdEntry{p[0], uid, gid, p[5], p[6]})
	}
	return out, sc.Err()
}

func lookupUser(name string) (passwdEntry, error) {
	ents, err := readPasswd()
	if err != nil {
		return passwdEntry{}, err
	}
	for _, e := range ents {
		if e.name == name {
			return e, nil
		}
	}
	return passwdEntry{}, errf("no_such_user", "system user %s not found", name)
}

func lookupUID(uid int) (passwdEntry, error) {
	ents, err := readPasswd()
	if err != nil {
		return passwdEntry{}, err
	}
	for _, e := range ents {
		if e.uid == uid {
			return e, nil
		}
	}
	return passwdEntry{}, fmt.Errorf("uid %d not found", uid)
}

func groupID(name string) (int, error) {
	b, err := os.ReadFile(groupFile)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		p := strings.Split(line, ":")
		if len(p) >= 3 && p[0] == name {
			return strconv.Atoi(p[2])
		}
	}
	return 0, fmt.Errorf("group %s not found", name)
}

// groupMembers returns the explicit members of a group in /etc/group.
func groupMembers(name string) map[string]bool {
	out := map[string]bool{}
	b, err := os.ReadFile(groupFile)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		p := strings.Split(line, ":")
		if len(p) >= 4 && p[0] == name {
			for _, m := range strings.Split(p[3], ",") {
				if m = strings.TrimSpace(m); m != "" {
					out[m] = true
				}
			}
		}
	}
	return out
}

// markerPath is the root-owned stamp that proves the panel created an account.
func (a *Agent) markerPath(user string) string { return filepath.Join(a.Cfg.AccountsDir, user) }

// isManaged reports whether a Linux account was created by the panel: it has
// the panel's ownership marker, or (accounts created by v0.1, before markers
// existed) it is a member of the bpanel-users group. Pre-existing system and
// operator accounts (ubuntu, the admin's own login, ...) are neither.
func (a *Agent) isManaged(e passwdEntry) bool {
	if st, err := os.Lstat(a.markerPath(e.name)); err == nil && st.Mode().IsRegular() {
		return true
	}
	return groupMembers("bpanel-users")[e.name]
}

// managedHome is homeAny() plus the ownership check (panel marker or
// bpanel-users membership). Since R2-WB-1 every tenant action goes through
// it: home() is managedHome(), and Dispatch checks the account named by the
// request before the handler runs (gate.go).
func (a *Agent) managedHome(user string) (passwdEntry, error) {
	e, err := a.homeAny(user)
	if err != nil {
		return e, err
	}
	if !a.isManaged(e) {
		return e, errf("not_managed", "user %s was not created by the panel", user)
	}
	return e, nil
}

// home returns the home of a panel-managed hosting account (R2-WB-1).
func (a *Agent) home(user string) (passwdEntry, error) { return a.managedHome(user) }

// homeAny returns the home directory of a hosting-like account (uid range,
// home below HomeBase), whether or not the panel created it. Only
// accountTerminate (which reports not_managed itself) uses it directly.
func (a *Agent) homeAny(user string) (passwdEntry, error) {
	e, err := lookupUser(user)
	if err != nil {
		return e, err
	}
	if !strings.HasPrefix(e.home, a.Cfg.HomeBase+"/") || e.uid < 1000 || e.uid >= 60000 || filepath.Clean(e.home) != e.home {
		return e, errf("not_managed", "user %s is not a hosting account", user)
	}
	return e, nil
}

func slogDefault() *slog.Logger { return slog.Default() }
