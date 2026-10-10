package installer

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// install.sh must verify release signatures (SEC-10): runs the shell test
// suite when minisign and openssl are available.
func TestInstallShSignatures(t *testing.T) {
	for _, b := range []string{"bash", "minisign", "openssl"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("%s not installed", b)
		}
	}
	out, err := exec.Command("bash", filepath.Join("..", "..", "installer", "test", "test-install-sh.sh")).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestInstallShSyntax(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	for _, f := range []string{"install.sh", "test/test-install-sh.sh", "test/validate-configs.sh"} {
		if out, err := exec.Command("bash", "-n", filepath.Join("..", "..", "installer", f)).CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", f, err, out)
		}
	}
}

// The generated configs checked with the real tools (nginx -t, apache2ctl,
// php-fpm -t, postfix check, sshd -t, fail2ban, logrotate, systemd-analyze).
// It changes /etc (and restores it), so it only runs when asked:
//
//	sudo BPANEL_VALIDATE_CONFIGS=/path/to/bpanel-installer go test ./internal/installer -run TestValidateConfigsWithRealTools
func TestValidateConfigsWithRealTools(t *testing.T) {
	bin := os.Getenv("BPANEL_VALIDATE_CONFIGS")
	if bin == "" || os.Geteuid() != 0 {
		t.Skip("set BPANEL_VALIDATE_CONFIGS=<bpanel-installer binary> and run as root on a scratch machine")
	}
	out, err := exec.Command("bash", filepath.Join("..", "..", "installer", "test", "validate-configs.sh"), bin).CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatal(err)
	}
}

// lockHeld must see an fcntl lock held by another process (what apt/dpkg use).
func TestLockHeld(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	f := filepath.Join(t.TempDir(), "lock-frontend")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if lockHeld(f) {
		t.Fatal("unlocked file reported as locked")
	}
	cmd := exec.Command(py, "-c", `import fcntl,sys,time
f=open(sys.argv[1],"r+"); fcntl.lockf(f, fcntl.LOCK_EX); print("locked", flush=True); time.sleep(30)`, f)
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	buf := make([]byte, 6)
	if _, err := out.Read(buf); err != nil {
		t.Fatal(err)
	}
	if !lockHeld(f) {
		t.Fatal("lock held by another process not detected")
	}
	if lockHeld(filepath.Join(t.TempDir(), "missing")) {
		t.Fatal("missing file reported as locked")
	}
}
