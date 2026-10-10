//go:build dev

// SPDX-License-Identifier: Apache-2.0

package mockagent

// Dev-mode answers for the devx agent actions. Input is validated like the
// real agent does; git repositories are plain directories under the mock
// base (no git runs), traceroute reports not_installed, and the terminal is
// honestly unsupported (the mock agent has no PTY and no account uid).

import (
	"os"
	"path/filepath"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/devx"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

func (m *Mock) mockDevx(method string, params any) (any, error) {
	switch method {
	case rpc.MTraceRoute:
		var p rpc.TraceRoute
		if conv(params, &p) != nil || !devx.ValidHost(p.Host) {
			return nil, &rpc.Error{Code: "invalid_host"}
		}
		return rpc.TraceRouteResult{Status: "not_installed"}, nil
	case rpc.MTermOpen, rpc.MTermWrite, rpc.MTermRead, rpc.MTermResize, rpc.MTermClose:
		return nil, &rpc.Error{Code: "terminal_unsupported", Message: "the mock agent has no PTY"}
	}
	var p rpc.GitClone // superset of GitRepoRef / GitDeploy fields used here
	if conv(params, &p) != nil || validate.Username(p.User) != nil {
		return nil, &rpc.Error{Code: "bad_params"}
	}
	rel, err := devx.CleanRel(p.Path)
	if err != nil {
		return nil, &rpc.Error{Code: "git_path_invalid"}
	}
	dir := filepath.Join(m.home(p.User), rel)
	info := rpc.GitInfo{Branch: "main", Branches: []rpc.GitBranch{{Name: "main", Commit: "0000000"}},
		Last: &rpc.GitCommit{Hash: "0000000000000000000000000000000000000000", Author: "mock", Unix: time.Now().Unix(), Subject: "mock agent: no git ran"}}
	switch method {
	case rpc.MGitClone, rpc.MGitInit:
		if method == rpc.MGitClone {
			if _, err := devx.ParseCloneURL(p.URL); err != nil {
				return nil, &rpc.Error{Code: devx.Code(err)}
			}
		}
		if _, err := os.Stat(dir); err == nil {
			return nil, &rpc.Error{Code: "git_path_exists"}
		}
		if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
			return nil, &rpc.Error{Code: "action_failed"}
		}
		return info, nil
	case rpc.MGitInfo:
		if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
			return nil, &rpc.Error{Code: "git_not_a_repo"}
		}
		return info, nil
	case rpc.MGitDeploy:
		var d rpc.GitDeploy
		_ = conv(params, &d)
		return rpc.GitDeployResult{Pulled: d.Pull, Deployed: d.DeployPath != "", Output: "mock agent: nothing pulled or copied", Info: info}, nil
	case rpc.MGitRemove:
		_ = os.RemoveAll(dir)
		return rpc.Empty{}, nil
	}
	return nil, &rpc.Error{Code: "unknown_method"}
}
