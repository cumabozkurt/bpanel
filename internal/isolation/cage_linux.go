// SPDX-License-Identifier: Apache-2.0

//go:build linux

package isolation

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// CageArgs are the parsed arguments of `bpanel-agent cage-exec`.
type CageArgs struct {
	Cgroup   string
	UID, GID int
	Chdir    string
	Argv     []string
}

// ParseCageArgs parses: --cgroup DIR --uid N --gid N [--chdir DIR] -- ARGV...
// The cgroup must be an account slice directory under /sys/fs/cgroup (or the
// given root), uid/gid >= 1000, and argv non-empty.
func ParseCageArgs(args []string, cgroupRoot string) (CageArgs, error) {
	var c CageArgs
	c.UID, c.GID = -1, -1
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			c.Argv = args[i+1:]
			break
		}
		if i+1 >= len(args) {
			return c, fmt.Errorf("missing value for %s", a)
		}
		v := args[i+1]
		i++
		switch a {
		case "--cgroup":
			c.Cgroup = v
		case "--chdir":
			c.Chdir = v
		case "--uid", "--gid":
			n, err := strconv.Atoi(v)
			if err != nil {
				return c, fmt.Errorf("%s: %v", a, err)
			}
			if a == "--uid" {
				c.UID = n
			} else {
				c.GID = n
			}
		default:
			return c, fmt.Errorf("unknown flag %s", a)
		}
	}
	if len(c.Argv) == 0 {
		return c, fmt.Errorf("no command")
	}
	if c.UID < 1000 || c.GID < 1000 {
		return c, fmt.Errorf("refusing uid/gid %d/%d (< 1000)", c.UID, c.GID)
	}
	clean := filepath.Clean(c.Cgroup)
	prefix := filepath.Join(cgroupRoot, "bpanel.slice", "bpanel-u.slice") + "/bpanel-u-"
	if clean != c.Cgroup || !strings.HasPrefix(clean, prefix) || !strings.HasSuffix(clean, ".slice") ||
		!UserRe.MatchString(strings.TrimSuffix(strings.TrimPrefix(clean, prefix), ".slice")) {
		return c, fmt.Errorf("cgroup %q is not an account slice", c.Cgroup)
	}
	return c, nil
}

// CageExec moves the current process into c.Cgroup (created if missing,
// mode 0755 root), drops supplementary groups, gid, uid, sets no_new_privs
// and execs c.Argv. It never returns on success. Must run as root.
func CageExec(c CageArgs) error {
	if err := os.MkdirAll(c.Cgroup, 0o755); err != nil {
		return fmt.Errorf("cgroup: %w", err)
	}
	if err := os.WriteFile(filepath.Join(c.Cgroup, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		return fmt.Errorf("join cgroup: %w", err)
	}
	if c.Chdir != "" {
		if err := os.Chdir(c.Chdir); err != nil {
			return err
		}
	}
	// Go applies setgroups/setgid/setuid to every thread (Go >= 1.16).
	if err := syscall.Setgroups([]int{c.GID}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(c.GID); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(c.UID); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	if _, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, 38 /* PR_SET_NO_NEW_PRIVS */, 1, 0, 0, 0, 0); e != 0 {
		err := error(e)
		return fmt.Errorf("no_new_privs: %w", err)
	}
	bin := c.Argv[0]
	if !filepath.IsAbs(bin) {
		return fmt.Errorf("command must be an absolute path")
	}
	env := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"}
	if c.Chdir != "" {
		env = append(env, "HOME="+c.Chdir)
	}
	return syscall.Exec(bin, c.Argv, env)
}

// CageExecMain is the `bpanel-agent cage-exec` entry point.
func CageExecMain(args []string) int {
	c, err := ParseCageArgs(args, "/sys/fs/cgroup")
	if err == nil {
		err = CageExec(c)
	}
	fmt.Fprintln(os.Stderr, "bpanel cage-exec:", err)
	return 126
}
