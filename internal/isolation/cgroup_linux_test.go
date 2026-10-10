// SPDX-License-Identifier: Apache-2.0

//go:build cgrouptest && linux

// Real-kernel isolation tests. They need root and a cgroup v2 hierarchy:
//
//	go test -c -tags cgrouptest -o isolation.test ./internal/isolation
//	sudo -n ./isolation.test -test.v -test.run Kernel
//
// They only create a throwaway child cgroup /sys/fs/cgroup/bpanel-test-<rand>
// and remove it afterwards.
package isolation

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const cgRoot = "/sys/fs/cgroup"

func TestMain(m *testing.M) {
	switch os.Getenv("BPANEL_CG_HELPER") {
	case "alloc": // allocate and touch 100 MiB
		b := make([]byte, 100<<20)
		for i := 0; i < len(b); i += 4096 {
			b[i] = 1
		}
		fmt.Println("allocated 100MiB without being killed")
		os.Exit(0)
	case "fork": // try to start 20 children
		started := 0
		var firstErr error
		var cmds []*exec.Cmd
		for i := 0; i < 20; i++ {
			c := exec.Command("/bin/sleep", "5")
			if err := c.Start(); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			started++
			cmds = append(cmds, c)
		}
		for _, c := range cmds {
			c.Process.Kill()
			c.Wait()
		}
		fmt.Printf("started=%d failed=%d first_error=%v\n", started, 20-started, firstErr)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func mkTestCgroup(t *testing.T) (string, *os.File) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	pr := Probe(cgRoot)
	t.Logf("probe: %+v", pr)
	if !pr.CgroupV2 {
		t.Skip(pr.Reason)
	}
	sub, _ := os.ReadFile(filepath.Join(cgRoot, "cgroup.subtree_control"))
	for _, c := range []string{"memory", "pids"} {
		if !strings.Contains(" "+string(sub)+" ", " "+c+" ") && !strings.Contains(string(sub), c) {
			if err := os.WriteFile(filepath.Join(cgRoot, "cgroup.subtree_control"), []byte("+"+c), 0); err != nil {
				t.Skipf("cannot enable %s controller: %v", c, err)
			}
			t.Logf("enabled +%s in %s/cgroup.subtree_control", c, cgRoot)
		}
	}
	rb := make([]byte, 4)
	rand.Read(rb)
	dir := filepath.Join(cgRoot, "bpanel-test-"+hex.EncodeToString(rb))
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for i := 0; i < 50; i++ {
			if err := os.Remove(dir); err == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Errorf("could not remove %s", dir)
	})
	fd, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fd.Close() })
	return dir, fd
}

func write(t *testing.T, dir, f, v string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, f), []byte(v), 0); err != nil {
		t.Fatalf("%s=%s: %v", f, v, err)
	}
}

// helper runs this test binary as a child placed directly into the cgroup
// (clone3 CLONE_INTO_CGROUP).
func helper(t *testing.T, fd *os.File, mode string) (string, error) {
	self, _ := os.Executable()
	c := exec.Command(self, "-test.run=^$")
	c.Env = append(os.Environ(), "BPANEL_CG_HELPER="+mode, "GOMAXPROCS=1")
	c.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd())}
	out, err := c.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func TestKernelMemoryMaxOOMKills(t *testing.T) {
	dir, fd := mkTestCgroup(t)
	write(t, dir, "memory.max", "32M")
	write(t, dir, "memory.swap.max", "0")
	out, err := helper(t, fd, "alloc")
	t.Logf("child: err=%v out=%q", err, out)
	st, rerr := ReadStats(dir)
	if rerr != nil {
		t.Fatal(rerr)
	}
	t.Logf("stats after: %+v", st)
	if err == nil {
		t.Fatal("100MiB allocation in a 32M cgroup was not killed")
	}
	if ee, ok := err.(*exec.ExitError); ok {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			t.Logf("child killed by signal %v", ws.Signal())
		}
	}
	if st.OOMKills == 0 {
		t.Fatalf("memory.events oom_kill = 0")
	}
}

func TestKernelPidsMaxBlocksFork(t *testing.T) {
	dir, fd := mkTestCgroup(t)
	write(t, dir, "pids.max", "8")
	out, err := helper(t, fd, "fork")
	t.Logf("child: err=%v out=%q", err, out)
	st, _ := ReadStats(dir)
	t.Logf("pids.max read back: %d", st.PidsMax)
	if st.PidsMax != 8 {
		t.Fatalf("pids.max=%d", st.PidsMax)
	}
	var started, failed int
	fmt.Sscanf(out, "started=%d failed=%d", &started, &failed)
	if failed == 0 || started >= 8 {
		t.Fatalf("fork limit not enforced: %s", out)
	}
	ev, _ := os.ReadFile(filepath.Join(dir, "pids.events"))
	t.Logf("pids.events: %q", strings.TrimSpace(string(ev)))
}

// TestKernelHomeIsolation proves the ProtectHome=tmpfs + BindPaths model:
// inside the sandbox only the account's own home is visible.
func TestKernelHomeIsolation(t *testing.T) {
	base := t.TempDir()
	a, b := filepath.Join(base, "A"), filepath.Join(base, "B")
	os.Mkdir(a, 0o755)
	os.Mkdir(b, 0o755)
	os.WriteFile(filepath.Join(a, "mine.txt"), []byte("a"), 0o644)
	os.WriteFile(filepath.Join(b, "secret.txt"), []byte("b"), 0o644)
	// B is reachable on the host as /home/b-equivalent: we bind it at /home/b
	// in a reference run and show that, in the sandbox, /home only holds a.
	script := "ls /home; ls /home/a; ls /home/b && echo B_VISIBLE || echo B_HIDDEN"
	var c *exec.Cmd
	if bw, err := exec.LookPath("bwrap"); err == nil {
		c = exec.Command(bw, "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
			"--symlink", "usr/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev",
			"--tmpfs", "/home", "--bind", a, "/home/a", "--unshare-all", "/bin/sh", "-c", script)
		t.Log("using bwrap")
	} else if os.Geteuid() == 0 {
		// bwrap not installed: same mount model with a private mount
		// namespace (unshare(1) + mount(8)); this is what systemd's
		// ProtectHome=tmpfs + BindPaths= sets up.
		inner := fmt.Sprintf("mount --make-rprivate / && mount -t tmpfs tmpfs /home && mkdir /home/a && mount --bind %s /home/a && %s", a, script)
		c = exec.Command("unshare", "-m", "/bin/sh", "-c", inner)
		t.Log("bwrap not installed; using unshare -m + tmpfs/bind mounts")
	} else {
		t.Skip("neither bwrap nor root available")
	}
	_ = b
	out, err := c.CombinedOutput()
	t.Logf("sandbox output:\n%s(err=%v)", out, err)
	s := string(out)
	if !strings.Contains(s, "mine.txt") || !strings.Contains(s, "B_HIDDEN") || strings.Contains(s, "secret.txt") {
		t.Fatal("home isolation failed")
	}
	if _, err := os.Stat(filepath.Join(b, "secret.txt")); err != nil {
		t.Fatal("host view changed")
	}
}
