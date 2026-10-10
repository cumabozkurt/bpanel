// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// devxEnv runs caged commands directly as the test user (the cage itself is
// covered by internal/isolation) and records every argv.
func devxEnv(t *testing.T) (*testEnv, *[][]string) {
	e := newTestEnv(t)
	var seen [][]string
	var mu sync.Mutex // exportHEAD cages git and tar concurrently
	oc, or := devxCage, devxResolver
	devxCage = func(_ passwdEntry, _ string, argv ...string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, argv)
		return argv, nil
	}
	devxResolver = func(_ context.Context, h string) ([]net.IP, error) {
		if h == "internal.example" {
			return []net.IP{net.ParseIP("10.0.0.5")}, nil
		}
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	t.Cleanup(func() { devxCage, devxResolver = oc, or })
	return e, &seen
}

func TestDevxGitCloneRejects(t *testing.T) {
	e, seen := devxEnv(t)
	ctx := context.Background()
	for url, want := range map[string]string{
		"file:///etc":                     "git_url_scheme",
		"/home/other/repo":                "git_url_scheme",
		"ext::sh -c id":                   "git_url_invalid",
		"https://internal.example/a.git":  "target_blocked",
		"https://127.0.0.1/a.git":         "target_blocked",
		"https://[::1]/a.git":             "target_blocked",
		"ssh://git@169.254.169.254/a.git": "target_blocked",
	} {
		if _, err := e.a.gitClone(ctx, rpc.GitClone{User: "tenant", Path: "repositories/x", URL: url}); code(err) != want {
			t.Errorf("%s: %v want %s", url, err, want)
		}
	}
	for _, p := range []string{"../outside", "/etc", ".ssh/x", "a/.git"} {
		if _, err := e.a.gitClone(ctx, rpc.GitClone{User: "tenant", Path: p, URL: "https://example.com/a.git"}); code(err) != "git_path_invalid" {
			t.Errorf("path %s: %v", p, err)
		}
	}
	if _, err := e.a.gitClone(ctx, rpc.GitClone{User: "opsuser", Path: "r", URL: "https://example.com/a.git"}); err == nil {
		t.Error("unmanaged account accepted")
	}
	if len(*seen) != 0 {
		t.Fatalf("git ran for rejected input: %v", *seen)
	}
	// symlinked parent
	if err := os.Symlink(e.outside, filepath.Join(e.home, "evil")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.gitInit(ctx, rpc.GitRepoRef{User: "tenant", Path: "evil/r"}); code(err) != "symlink_in_path" {
		t.Errorf("symlink: %v", err)
	}
}

func TestDevxGitInitInfoDeploy(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	e, seen := devxEnv(t)
	ctx := context.Background()
	info, err := e.a.gitInit(ctx, rpc.GitRepoRef{User: "tenant", Path: "repositories/site"})
	if err != nil {
		t.Fatal(err)
	}
	if info.Branch != "main" || info.Last != nil {
		t.Fatalf("init info %+v", info)
	}
	for _, a := range *seen {
		j := strings.Join(a, " ")
		if !strings.Contains(j, "GIT_TERMINAL_PROMPT=0") || !strings.Contains(j, "protocol.file.allow=never") {
			t.Fatalf("unsafe argv %s", j)
		}
	}
	repo := filepath.Join(e.home, "repositories/site")
	os.WriteFile(filepath.Join(repo, "index.html"), []byte("<h1>v1</h1>"), 0o644)
	for _, args := range [][]string{{"add", "index.html"}, {"-c", "user.name=T", "-c", "user.email=t@x", "commit", "-qm", "first"}} {
		c := exec.Command("git", args...)
		c.Dir = repo
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
	}
	info, err = e.a.gitInfo(ctx, rpc.GitRepoRef{User: "tenant", Path: "repositories/site"})
	if err != nil || info.Last == nil || info.Last.Subject != "first" || len(info.Branches) != 1 || info.Branches[0].Name != "main" {
		t.Fatalf("info %+v %v", info, err)
	}
	if _, err := e.a.gitInit(ctx, rpc.GitRepoRef{User: "tenant", Path: "repositories/site"}); code(err) != "git_path_exists" {
		t.Fatalf("re-init: %v", err)
	}
	os.MkdirAll(filepath.Join(e.home, "public_html"), 0o755)
	if _, err := exec.LookPath("tar"); err == nil {
		r, err := e.a.gitDeploy(ctx, rpc.GitDeploy{User: "tenant", Path: "repositories/site", DeployPath: "public_html"})
		if err != nil || !r.Deployed {
			t.Fatalf("deploy %+v %v", r, err)
		}
		if b, _ := os.ReadFile(filepath.Join(e.home, "public_html/index.html")); string(b) != "<h1>v1</h1>" {
			t.Fatalf("deployed %q", b)
		}
		if _, err := os.Stat(filepath.Join(e.home, "public_html/.git")); err == nil {
			t.Fatal(".git exported")
		}
	}
	if _, err := e.a.gitDeploy(ctx, rpc.GitDeploy{User: "tenant", Path: "repositories/site", DeployPath: "repositories/site/sub"}); code(err) == "" {
		t.Fatal("overlapping deploy accepted")
	}
	// pull without remote, and with a file:// remote smuggled into the config
	if _, err := e.a.gitDeploy(ctx, rpc.GitDeploy{User: "tenant", Path: "repositories/site", Pull: true}); code(err) != "git_no_remote" {
		t.Fatalf("pull no remote: %v", err)
	}
	c := exec.Command("git", "remote", "add", "origin", "file://"+e.outside)
	c.Dir = repo
	c.Run()
	if _, err := e.a.gitDeploy(ctx, rpc.GitDeploy{User: "tenant", Path: "repositories/site", Pull: true}); code(err) != "git_url_scheme" {
		t.Fatalf("pull file remote: %v", err)
	}
	if _, err := e.a.gitRemove(ctx, rpc.GitRepoRef{User: "tenant", Path: "public_html"}); code(err) != "git_not_a_repo" {
		t.Fatalf("remove non-repo: %v", err)
	}
	if _, err := e.a.gitRemove(ctx, rpc.GitRepoRef{User: "tenant", Path: "repositories/site"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(repo); err == nil {
		t.Fatal("not removed")
	}
}

func TestDevxTraceRouteValidation(t *testing.T) {
	e, _ := devxEnv(t)
	for _, h := range []string{"-n", "a;id", "", "localhost"} {
		if _, err := e.a.traceRoute(context.Background(), rpc.TraceRoute{Host: h}); code(err) != "invalid_host" {
			t.Errorf("%q: %v", h, err)
		}
	}
	old := traceTools
	traceTools = []string{"bpanel-no-such-traceroute"}
	defer func() { traceTools = old }()
	r, err := e.a.traceRoute(context.Background(), rpc.TraceRoute{Host: "example.com"})
	if err != nil || r.Status != "not_installed" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestDevxTerminal(t *testing.T) {
	e, _ := devxEnv(t)
	ctx := context.Background()
	if _, err := e.a.termOpen(ctx, rpc.TermOpen{User: "tenant"}); code(err) != "shell_disabled" {
		t.Fatalf("nologin shell: %v", err)
	}
	if _, err := e.a.termOpen(ctx, rpc.TermOpen{User: "opsuser"}); err == nil {
		t.Fatal("unmanaged account got a terminal")
	}
	// give the tenant /bin/sh
	pw := filepath.Join(e.base, "passwd2")
	os.WriteFile(pw, []byte(fmt.Sprintf("tenant:x:%d:%d::%s:/bin/sh\n", os.Getuid(), os.Getgid(), e.home)), 0o644)
	old := passwdFile
	passwdFile = pw
	defer func() { passwdFile = old }()
	o, err := e.a.termOpen(ctx, rpc.TermOpen{User: "tenant", Cols: 100, Rows: 30})
	if code(err) == "terminal_unsupported" {
		t.Skip("no pty in this environment")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer e.a.termClose(ctx, rpc.TermIO{User: "tenant", ID: o.ID})
	if _, err := e.a.termRead(ctx, rpc.TermIO{User: "other", ID: o.ID}); code(err) != "terminal_not_found" {
		t.Fatalf("cross-account read: %v", err)
	}
	if _, err := e.a.termWrite(ctx, rpc.TermIO{User: "tenant", ID: o.ID, Data: []byte("echo devx-$((40+2))\n")}); err != nil {
		t.Fatal(err)
	}
	var got strings.Builder
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(got.String(), "devx-42") {
		r, err := e.a.termRead(ctx, rpc.TermIO{User: "tenant", ID: o.ID, WaitMS: 500})
		if err != nil {
			t.Fatal(err)
		}
		got.Write(r.Data)
	}
	if !strings.Contains(got.String(), "devx-42") {
		t.Fatalf("output %q", got.String())
	}
	if _, err := e.a.termResize(ctx, rpc.TermIO{User: "tenant", ID: o.ID, Cols: 120, Rows: 40}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.termClose(ctx, rpc.TermIO{User: "tenant", ID: o.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.termWrite(ctx, rpc.TermIO{User: "tenant", ID: o.ID, Data: []byte("x")}); code(err) != "terminal_not_found" {
		t.Fatalf("closed session: %v", err)
	}
}
