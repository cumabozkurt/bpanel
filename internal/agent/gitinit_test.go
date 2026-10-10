package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A push to the checked-out branch of a repository set up like gitInit must
// be accepted and update the work tree.
func TestGitInitAcceptsPushToCheckedOutBranch(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	repo, work := filepath.Join(dir, "repo"), filepath.Join(dir, "work")
	run := func(cwd string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = cwd
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run(dir, "-c", "init.defaultBranch=main", "init", "--quiet", "--", "repo")
	run(repo, gitInitConfig...)
	run(dir, "-c", "init.defaultBranch=main", "init", "--quiet", "--", "work")
	if err := os.WriteFile(filepath.Join(work, "index.html"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(work, "add", ".")
	run(work, "commit", "-qm", "init")
	run(work, "push", "-q", repo, "HEAD:main")
	if b, err := os.ReadFile(filepath.Join(repo, "index.html")); err != nil || string(b) != "hi" {
		t.Fatalf("work tree not updated: %q %v", b, err)
	}
}
