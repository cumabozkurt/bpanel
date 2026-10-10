// SPDX-License-Identifier: Apache-2.0

package agent

// v0.4 devx: Git Version Control, browser terminal (PTY sessions) and
// traceroute for Track DNS. Git and the shell always run as the account's
// uid inside its cage (`bpanel-agent cage-exec`: account cgroup slice,
// setgroups/setgid/setuid, no_new_privs) - root never touches a
// user-controlled repository (hooks, fsmonitor, config). git, traceroute and
// tracepath are GPL programs invoked as separate processes (argv only).

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/devx"
	"github.com/cumabozkurt/bpanel/internal/isolation"
)

// Overridable in tests.
var (
	gitBin        = "/usr/bin/git"
	devxResolver  = devx.DefaultResolver
	devxBlockedIP = devx.BlockedIP
	// devxCage wraps argv so it runs as e's uid inside its slice.
	devxCage = func(e passwdEntry, chdir string, argv ...string) ([]string, error) {
		if _, err := os.Stat(isolation.CageExecBin); err != nil {
			return nil, errf("cage_unavailable", "%s is missing", isolation.CageExecBin)
		}
		return append([]string{isolation.CageExecBin, "cage-exec", "--cgroup", isolation.CgroupDir(isolationCgroupRoot, e.name),
			"--uid", strconv.Itoa(e.uid), "--gid", strconv.Itoa(e.gid), "--chdir", chdir, "--"}, argv...), nil
	}
	traceTools = []string{"traceroute", "tracepath"}
)

const (
	gitCloneTimeout = 5 * time.Minute
	gitPullTimeout  = 2 * time.Minute
	gitInfoTimeout  = 20 * time.Second
	traceTimeout    = 60 * time.Second
	devxMaxOutput   = 64 << 10
)

func init() {
	for _, m := range []string{rpc.MGitClone, rpc.MGitInit, rpc.MGitInfo, rpc.MGitDeploy, rpc.MGitRemove,
		rpc.MTermOpen, rpc.MTermWrite, rpc.MTermRead, rpc.MTermResize, rpc.MTermClose} {
		accountField[m] = struct {
			key      string
			optional bool
		}{"user", false}
	}
	gateExempt[rpc.MTraceRoute] = "server (traceroute/tracepath; host validated, argv only)"
}

func (a *Agent) devxRoutes() map[string]handler {
	return map[string]handler{
		rpc.MGitClone:   bind(a.gitClone),
		rpc.MGitInit:    bind(a.gitInit),
		rpc.MGitInfo:    bind(a.gitInfo),
		rpc.MGitDeploy:  bind(a.gitDeploy),
		rpc.MGitRemove:  bind(a.gitRemove),
		rpc.MTraceRoute: bind(a.traceRoute),
		rpc.MTermOpen:   bind(a.termOpen),
		rpc.MTermWrite:  bind(a.termWrite),
		rpc.MTermRead:   bind(a.termRead),
		rpc.MTermResize: bind(a.termResize),
		rpc.MTermClose:  bind(a.termClose),
	}
}

// capWriter keeps at most devxMaxOutput bytes.
type capWriter struct{ b bytes.Buffer }

func (w *capWriter) Write(p []byte) (int, error) {
	if room := devxMaxOutput - w.b.Len(); room > 0 {
		if len(p) > room {
			w.b.Write(p[:room])
		} else {
			w.b.Write(p)
		}
	}
	return len(p), nil
}

// runCaged runs argv as the account inside its cage with a timeout.
func runCaged(ctx context.Context, timeout time.Duration, e passwdEntry, chdir string, stdin io.Reader, stdout io.Writer, argv ...string) (string, error) {
	full, err := devxCage(e, chdir, argv...)
	if err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, full[0], full[1:]...)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"}
	cmd.Dir = chdir
	cmd.Stdin = stdin
	var out capWriter
	if stdout != nil {
		cmd.Stdout = stdout
	} else {
		cmd.Stdout = &out
	}
	cmd.Stderr = &out
	cmd.WaitDelay = 5 * time.Second
	err = cmd.Run()
	s := out.b.String()
	if cctx.Err() == context.DeadlineExceeded {
		return s, errf("git_timeout", "timed out after %s", timeout)
	}
	if err != nil {
		return s, errf("git_failed", "%s", strings.TrimSpace(lastLines(s, 6)))
	}
	return s, nil
}

func gitArgs(args ...string) []string { return devx.GitEnvArgv(gitBin, args...) }

func devxErr(err error) error {
	if c := devx.Code(err); c != "" {
		return errf(c, "%s", c)
	}
	return err
}

// repoDir validates rel and returns the absolute repository directory
// (existing, no symlinked components, containing .git when wantRepo).
func (a *Agent) repoDir(user, rel string, wantRepo bool) (passwdEntry, string, string, error) {
	if err := isolationUser(a, user); err != nil {
		return passwdEntry{}, "", "", err
	}
	e, err := a.managedHome(user)
	if err != nil {
		return e, "", "", err
	}
	c, err := devx.CleanRel(rel)
	if err != nil {
		return e, "", "", devxErr(err)
	}
	root, err := openHome(e)
	if err != nil {
		return e, "", "", err
	}
	defer root.Close()
	if err := checkNoSymlinks(root, c); err != nil {
		return e, "", "", err
	}
	if wantRepo {
		st, err := root.Lstat(c + "/.git")
		if err != nil || !st.IsDir() {
			return e, "", "", errf("git_not_a_repo", "%s", c)
		}
	}
	return e, c, filepath.Join(e.home, c), nil
}

func (a *Agent) checkRemote(ctx context.Context, raw string, allowPrivate bool) (devx.CloneURL, error) {
	u, err := devx.ParseCloneURL(raw)
	if err != nil {
		return u, devxErr(err)
	}
	if !allowPrivate {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := devx.CheckHost(c, u.Host, devxResolver, devxBlockedIP); err != nil {
			return u, devxErr(err)
		}
	}
	return u, nil
}

func (a *Agent) gitClone(ctx context.Context, p rpc.GitClone) (rpc.GitInfo, error) {
	e, rel, _, err := a.repoDir(p.User, p.Path, false)
	if err != nil {
		return rpc.GitInfo{}, err
	}
	if !devx.ValidBranch(p.Branch) {
		return rpc.GitInfo{}, errf("git_branch_invalid", "%s", p.Branch)
	}
	u, err := a.checkRemote(ctx, p.URL, p.AllowPrivate)
	if err != nil {
		return rpc.GitInfo{}, err
	}
	if err := a.prepareRepoParent(e, rel); err != nil {
		return rpc.GitInfo{}, err
	}
	args := []string{"clone", "--no-recurse-submodules", "--quiet"}
	if p.Branch != "" {
		args = append(args, "--branch", p.Branch)
	}
	args = append(args, "--", u.Normalized, rel)
	if _, err := runCaged(ctx, gitCloneTimeout, e, e.home, nil, nil, gitArgs(args...)...); err != nil {
		return rpc.GitInfo{}, err
	}
	a.Log.Info("git.clone", "user", e.name, "path", rel, "host", u.Host)
	return a.readGitInfo(ctx, e, filepath.Join(e.home, rel))
}

// prepareRepoParent refuses an existing target and creates missing parents
// owned by the account.
func (a *Agent) prepareRepoParent(e passwdEntry, rel string) error {
	root, err := openHome(e)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Lstat(rel); err == nil {
		return errf("git_path_exists", "%s", rel)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return mapFSErr(err, rel)
	}
	if d := path.Dir(rel); d != "." {
		return mkdirOwned(root, d, 0o755, e.uid, e.gid, false)
	}
	return nil
}

func (a *Agent) gitInit(ctx context.Context, p rpc.GitRepoRef) (rpc.GitInfo, error) {
	e, rel, abs, err := a.repoDir(p.User, p.Path, false)
	if err != nil {
		return rpc.GitInfo{}, err
	}
	if err := a.prepareRepoParent(e, rel); err != nil {
		return rpc.GitInfo{}, err
	}
	if _, err := runCaged(ctx, gitInfoTimeout, e, e.home, nil, nil, gitArgs("-c", "init.defaultBranch=main", "init", "--quiet", "--", rel)...); err != nil {
		return rpc.GitInfo{}, err
	}
	a.Log.Info("git.init", "user", e.name, "path", rel)
	return a.readGitInfo(ctx, e, abs)
}

func (a *Agent) gitInfo(ctx context.Context, p rpc.GitRepoRef) (rpc.GitInfo, error) {
	e, _, abs, err := a.repoDir(p.User, p.Path, true)
	if err != nil {
		return rpc.GitInfo{}, err
	}
	return a.readGitInfo(ctx, e, abs)
}

func (a *Agent) readGitInfo(ctx context.Context, e passwdEntry, abs string) (rpc.GitInfo, error) {
	info := rpc.GitInfo{Branches: []rpc.GitBranch{}}
	if out, err := runCaged(ctx, gitInfoTimeout, e, abs, nil, nil, gitArgs("symbolic-ref", "--short", "-q", "HEAD")...); err == nil {
		info.Branch = strings.TrimSpace(out)
	}
	out, err := runCaged(ctx, gitInfoTimeout, e, abs, nil, nil, gitArgs("for-each-ref", "--count=200", "--format=%(refname)%09%(objectname:short)", "refs/heads", "refs/remotes")...)
	if err != nil {
		return info, err
	}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.SplitN(l, "\t", 2)
		if len(f) != 2 || strings.HasSuffix(f[0], "/HEAD") {
			continue
		}
		b := rpc.GitBranch{Commit: f[1]}
		switch {
		case strings.HasPrefix(f[0], "refs/heads/"):
			b.Name = strings.TrimPrefix(f[0], "refs/heads/")
		case strings.HasPrefix(f[0], "refs/remotes/"):
			b.Name, b.Remote = strings.TrimPrefix(f[0], "refs/remotes/"), true
		default:
			continue
		}
		info.Branches = append(info.Branches, b)
	}
	if out, err := runCaged(ctx, gitInfoTimeout, e, abs, nil, nil, gitArgs("log", "-1", "--format=%H%x09%an%x09%at%x09%s")...); err == nil {
		if f := strings.SplitN(strings.TrimSpace(out), "\t", 4); len(f) == 4 {
			n, _ := strconv.ParseInt(f[2], 10, 64)
			info.Last = &rpc.GitCommit{Hash: f[0], Author: f[1], Unix: n, Subject: f[3]}
		}
	}
	return info, nil
}

func (a *Agent) gitDeploy(ctx context.Context, p rpc.GitDeploy) (rpc.GitDeployResult, error) {
	var res rpc.GitDeployResult
	e, rel, abs, err := a.repoDir(p.User, p.Path, true)
	if err != nil {
		return res, err
	}
	var dst string
	if p.DeployPath != "" {
		_, drel, dabs, err := a.repoDir(p.User, p.DeployPath, false)
		if err != nil {
			return res, err
		}
		if st, err := os.Lstat(dabs); err != nil || !st.IsDir() {
			return res, errf("git_deploy_path_invalid", "%s is not an existing directory", drel)
		}
		if drel == rel || strings.HasPrefix(drel+"/", rel+"/") || strings.HasPrefix(rel+"/", drel+"/") {
			return res, errf("git_deploy_path_invalid", "deploy path overlaps the repository")
		}
		dst = dabs
	}
	if p.Pull {
		origin, err := runCaged(ctx, gitInfoTimeout, e, abs, nil, nil, gitArgs("config", "--get", "remote.origin.url")...)
		if err != nil || strings.TrimSpace(origin) == "" {
			return res, errf("git_no_remote", "repository has no origin remote")
		}
		if _, err := a.checkRemote(ctx, strings.TrimSpace(origin), p.AllowPrivate); err != nil {
			return res, err
		}
		out, err := runCaged(ctx, gitPullTimeout, e, abs, nil, nil, gitArgs("pull", "--ff-only", "--no-rebase", "--no-recurse-submodules")...)
		res.Output = lastLines(out, 20)
		if err != nil {
			return res, err
		}
		res.Pulled = true
	}
	if dst != "" {
		if err := exportHEAD(ctx, e, abs, dst); err != nil {
			return res, err
		}
		res.Deployed = true
	}
	a.Log.Info("git.deploy", "user", e.name, "path", rel, "pulled", res.Pulled, "deployed", res.Deployed)
	res.Info, err = a.readGitInfo(ctx, e, abs)
	return res, err
}

// exportHEAD streams `git archive HEAD` into `tar -x` in dst, both caged as
// the account (tracked files only; .git never reaches the docroot).
func exportHEAD(ctx context.Context, e passwdEntry, repo, dst string) error {
	pr, pw := io.Pipe()
	errc := make(chan error, 1)
	go func() {
		_, err := runCaged(ctx, gitPullTimeout, e, repo, nil, pw, gitArgs("archive", "--format=tar", "HEAD")...)
		pw.CloseWithError(err)
		errc <- err
	}()
	_, terr := runCaged(ctx, gitPullTimeout, e, dst, pr, nil, "/usr/bin/env", "tar", "-x", "--no-same-owner", "--no-same-permissions", "-f", "-")
	pr.Close()
	if gerr := <-errc; gerr != nil {
		return gerr
	}
	if terr != nil {
		return errf("git_deploy_failed", "%v", terr)
	}
	return nil
}

func (a *Agent) gitRemove(ctx context.Context, p rpc.GitRepoRef) (rpc.Empty, error) {
	e, rel, _, err := a.repoDir(p.User, p.Path, true)
	if err != nil {
		return rpc.Empty{}, err
	}
	root, err := openHome(e)
	if err != nil {
		return rpc.Empty{}, err
	}
	defer root.Close()
	if err := removeAllIn(root, rel); err != nil {
		return rpc.Empty{}, err
	}
	a.Log.Info("git.remove", "user", e.name, "path", rel)
	return rpc.Empty{}, nil
}

// ---- traceroute --------------------------------------------------------------------

func (a *Agent) traceRoute(ctx context.Context, p rpc.TraceRoute) (rpc.TraceRouteResult, error) {
	h := strings.TrimSuffix(strings.TrimSpace(p.Host), ".")
	if !devx.ValidHost(h) {
		return rpc.TraceRouteResult{}, errf("invalid_host", "%s", p.Host)
	}
	for _, t := range traceTools {
		bin, err := exec.LookPath(t)
		if err != nil {
			continue
		}
		argv := []string{bin, "-n", "-w", "2", "-q", "1", "-m", "20", h}
		if t == "tracepath" {
			argv = []string{bin, "-n", "-m", "20", h}
		}
		cctx, cancel := context.WithTimeout(ctx, traceTimeout)
		cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
		var out capWriter
		cmd.Stdout, cmd.Stderr = &out, &out
		err = cmd.Run()
		cancel()
		if err != nil && out.b.Len() == 0 {
			return rpc.TraceRouteResult{}, errf("traceroute_failed", "%v", err)
		}
		a.Log.Info("net.traceroute", "host", h, "tool", t)
		return rpc.TraceRouteResult{Status: "ok", Tool: t, Output: out.b.String()}, nil
	}
	return rpc.TraceRouteResult{Status: "not_installed"}, nil
}

// ---- terminal ----------------------------------------------------------------------

const (
	termIdle       = 15 * time.Minute
	termMaxAge     = 8 * time.Hour
	termPerUser    = 3
	termMax        = 64
	termBufMax     = 1 << 20
	termReadChunk  = 64 << 10
	termWriteChunk = 64 << 10
)

// termShells are login shells a terminal may start (anything else, notably
// nologin/false, means shell access is disabled at the OS level too).
var termShells = map[string]bool{"/bin/bash": true, "/usr/bin/bash": true, "/bin/sh": true, "/usr/bin/sh": true,
	"/bin/dash": true, "/usr/bin/dash": true, "/bin/zsh": true, "/usr/bin/zsh": true, "/usr/local/bin/bpanel-cage-shell": true}

type termSess struct {
	id, user string
	m        *os.File
	cmd      *exec.Cmd
	mu       sync.Mutex
	buf      bytes.Buffer
	notify   chan struct{}
	exited   bool
	started  time.Time
	last     time.Time
}

var terms = struct {
	sync.Mutex
	m       map[string]*termSess
	reaping bool
}{m: map[string]*termSess{}}

func (s *termSess) kill() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
		_ = s.cmd.Process.Kill()
	}
	_ = s.m.Close()
}

func (a *Agent) termReaper() {
	for {
		time.Sleep(30 * time.Second)
		now := time.Now()
		terms.Lock()
		for id, s := range terms.m {
			s.mu.Lock()
			dead := s.exited && now.Sub(s.last) > time.Minute
			stale := now.Sub(s.last) > termIdle || now.Sub(s.started) > termMaxAge
			s.mu.Unlock()
			if dead || stale {
				s.kill()
				delete(terms.m, id)
				a.Log.Info("term.reap", "user", s.user, "id", id)
			}
		}
		terms.Unlock()
	}
}

func (a *Agent) termOpen(_ context.Context, p rpc.TermOpen) (rpc.TermOpenResult, error) {
	if err := isolationUser(a, p.User); err != nil {
		return rpc.TermOpenResult{}, err
	}
	e, err := a.managedHome(p.User)
	if err != nil {
		return rpc.TermOpenResult{}, err
	}
	if !termShells[e.shell] {
		return rpc.TermOpenResult{}, errf("shell_disabled", "login shell %s is not allowed", e.shell)
	}
	terms.Lock()
	n := 0
	for _, s := range terms.m {
		if s.user == p.User {
			n++
		}
	}
	if n >= termPerUser || len(terms.m) >= termMax {
		terms.Unlock()
		return rpc.TermOpenResult{}, errf("terminal_limit", "too many terminal sessions")
	}
	if !terms.reaping {
		terms.reaping = true
		go a.termReaper()
	}
	terms.Unlock()
	argv, err := devxCage(e, e.home, "/usr/bin/env", "TERM=xterm-256color", "USER="+e.name, "LOGNAME="+e.name, "SHELL="+e.shell, e.shell, "-l")
	if err != nil {
		return rpc.TermOpenResult{}, err
	}
	m, sl, err := devx.OpenPTY()
	if err != nil {
		return rpc.TermOpenResult{}, errf("terminal_unsupported", "pty: %v", err)
	}
	_ = devx.SetWinsize(m, p.Cols, p.Rows)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"}
	cmd.Dir = e.home
	cmd.Stdin, cmd.Stdout, cmd.Stderr = sl, sl, sl
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		m.Close()
		sl.Close()
		return rpc.TermOpenResult{}, errf("terminal_failed", "%v", err)
	}
	sl.Close()
	idb := make([]byte, 16)
	_, _ = rand.Read(idb)
	now := time.Now()
	s := &termSess{id: hex.EncodeToString(idb), user: p.User, m: m, cmd: cmd, notify: make(chan struct{}, 1), started: now, last: now}
	go func() {
		b := make([]byte, 8192)
		for {
			n, err := m.Read(b)
			s.mu.Lock()
			if n > 0 {
				s.buf.Write(b[:n])
				if over := s.buf.Len() - termBufMax; over > 0 {
					s.buf.Next(over)
				}
			}
			if err != nil {
				s.exited = true
			}
			s.mu.Unlock()
			select {
			case s.notify <- struct{}{}:
			default:
			}
			if err != nil {
				_ = cmd.Wait()
				return
			}
		}
	}()
	terms.Lock()
	terms.m[s.id] = s
	terms.Unlock()
	a.Log.Info("term.open", "user", e.name, "id", s.id)
	return rpc.TermOpenResult{ID: s.id}, nil
}

func termGet(user, id string) (*termSess, error) {
	terms.Lock()
	defer terms.Unlock()
	s, ok := terms.m[id]
	if !ok || s.user != user { // sessions are bound to their account
		return nil, errf("terminal_not_found", "no such session")
	}
	return s, nil
}

func (a *Agent) termWrite(_ context.Context, p rpc.TermIO) (rpc.Empty, error) {
	s, err := termGet(p.User, p.ID)
	if err != nil {
		return rpc.Empty{}, err
	}
	if len(p.Data) > termWriteChunk {
		return rpc.Empty{}, errf("bad_params", "input too large")
	}
	s.mu.Lock()
	s.last = time.Now()
	ex := s.exited
	s.mu.Unlock()
	if ex {
		return rpc.Empty{}, errf("terminal_exited", "session ended")
	}
	if _, err := s.m.Write(p.Data); err != nil {
		return rpc.Empty{}, errf("terminal_exited", "session ended")
	}
	return rpc.Empty{}, nil
}

func (a *Agent) termRead(ctx context.Context, p rpc.TermIO) (rpc.TermReadResult, error) {
	s, err := termGet(p.User, p.ID)
	if err != nil {
		return rpc.TermReadResult{}, err
	}
	wait := time.Duration(min(max(p.WaitMS, 0), 5000)) * time.Millisecond
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		s.mu.Lock()
		if s.buf.Len() > 0 || s.exited {
			out := rpc.TermReadResult{Data: append([]byte(nil), s.buf.Next(termReadChunk)...), Exited: s.exited && s.buf.Len() == 0}
			s.last = time.Now()
			s.mu.Unlock()
			return out, nil
		}
		s.mu.Unlock()
		select {
		case <-s.notify:
		case <-deadline.C:
			return rpc.TermReadResult{}, nil
		case <-ctx.Done():
			return rpc.TermReadResult{}, nil
		}
	}
}

func (a *Agent) termResize(_ context.Context, p rpc.TermIO) (rpc.Empty, error) {
	s, err := termGet(p.User, p.ID)
	if err != nil {
		return rpc.Empty{}, err
	}
	_ = devx.SetWinsize(s.m, p.Cols, p.Rows)
	return rpc.Empty{}, nil
}

func (a *Agent) termClose(_ context.Context, p rpc.TermIO) (rpc.Empty, error) {
	s, err := termGet(p.User, p.ID)
	if err != nil {
		return rpc.Empty{}, err
	}
	terms.Lock()
	delete(terms.m, p.ID)
	terms.Unlock()
	s.kill()
	a.Log.Info("term.close", "user", s.user, "id", s.id, "seconds", int(time.Since(s.started).Seconds()))
	return rpc.Empty{}, nil
}
