// SPDX-License-Identifier: Apache-2.0

package agentrpc

// v0.4 devx: Git Version Control, browser terminal, Track DNS (traceroute).
// Every git/terminal action runs as the account's uid inside its cage
// (cgroup slice, no_new_privs) - never as root on user-controlled repos.
const (
	MGitClone  = "git.clone"  // clone a remote (https/ssh) into a path under the home
	MGitInit   = "git.init"   // create an empty repository under the home
	MGitInfo   = "git.info"   // branches + last commit
	MGitDeploy = "git.deploy" // git pull --ff-only (+ optional export of HEAD into a docroot)
	MGitRemove = "git.remove" // delete a repository directory under the home

	MTraceRoute = "net.traceroute" // traceroute/tracepath to a validated host

	MTermOpen   = "term.open"   // start a PTY session running the account's shell in its cage
	MTermWrite  = "term.write"  // send input
	MTermRead   = "term.read"   // read buffered output (waits up to WaitMS)
	MTermResize = "term.resize" // window size
	MTermClose  = "term.close"  // end the session
)

// GitRepoRef names a repository directory (Path relative to the home).
type GitRepoRef struct {
	User string `json:"user"`
	Path string `json:"path"`
}

// GitClone: URL already validated by the API (scheme, host, SSRF); the agent
// re-validates it and re-checks the resolved addresses unless AllowPrivate.
type GitClone struct {
	User         string `json:"user"`
	Path         string `json:"path"`
	URL          string `json:"url"`
	Branch       string `json:"branch,omitempty"`
	AllowPrivate bool   `json:"allow_private,omitempty"`
}

type GitBranch struct {
	Name   string `json:"name"`
	Commit string `json:"commit"`
	Remote bool   `json:"remote"`
}

type GitCommit struct {
	Hash    string `json:"hash"`
	Author  string `json:"author"`
	Unix    int64  `json:"unix"`
	Subject string `json:"subject"`
}

type GitInfo struct {
	Branch   string      `json:"branch"`
	Branches []GitBranch `json:"branches"`
	Last     *GitCommit  `json:"last,omitempty"`
}

// GitDeploy pulls (Pull) and/or exports HEAD into DeployPath (relative to the
// home, an existing directory) when non-empty.
type GitDeploy struct {
	User         string `json:"user"`
	Path         string `json:"path"`
	Pull         bool   `json:"pull"`
	DeployPath   string `json:"deploy_path,omitempty"`
	AllowPrivate bool   `json:"allow_private,omitempty"`
}

type GitDeployResult struct {
	Pulled   bool    `json:"pulled"`
	Deployed bool    `json:"deployed"`
	Output   string  `json:"output,omitempty"`
	Info     GitInfo `json:"info"`
}

type TraceRoute struct {
	Host string `json:"host"`
}

type TraceRouteResult struct {
	Status string `json:"status"` // ok | not_installed
	Tool   string `json:"tool,omitempty"`
	Output string `json:"output,omitempty"`
}

type TermOpen struct {
	User string `json:"user"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

type TermOpenResult struct {
	ID string `json:"id"`
}

type TermIO struct {
	User   string `json:"user"`
	ID     string `json:"id"`
	Data   []byte `json:"data,omitempty"` // base64 on the wire
	WaitMS int    `json:"wait_ms,omitempty"`
	Cols   int    `json:"cols,omitempty"`
	Rows   int    `json:"rows,omitempty"`
}

type TermReadResult struct {
	Data   []byte `json:"data,omitempty"`
	Exited bool   `json:"exited"`
}
