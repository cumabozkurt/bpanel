// SPDX-License-Identifier: Apache-2.0

package agentrpc

const (
	MIsolationHidepidStatus = "isolation.hidepid.status" // live /proc mount options + fstab state
	MIsolationSSHApply      = "isolation.ssh.apply"      // write sshd Match blocks for jailed accounts (sshd -t, rollback)
)

type HidepidStatus struct {
	Status          string `json:"status"` // active | configured_reboot_pending | not_configured | unsupported
	Hidepid         string `json:"hidepid"`
	GID             int    `json:"gid"`
	Group           string `json:"group"`
	GroupGID        int    `json:"group_gid"`
	FstabConfigured bool   `json:"fstab_configured"`
	Reason          string `json:"reason,omitempty"`
}

type IsolationSSHApply struct {
	Users []string `json:"users"` // all jailed accounts (full set; the file is replaced)
	Mode  string   `json:"mode"`  // "cage" | "sftp"
	// Shell lists the accounts WITH shell access (v1.1): their login shell is
	// set to a real shell, jailed accounts get nologin back. Without this the
	// "shell access" switch changed only sshd and the terminal still refused.
	Shell []string `json:"shell,omitempty"`
}

type IsolationSSHResult struct {
	Status string `json:"status"` // applied | applied_unvalidated
	File   string `json:"file"`
	Users  int    `json:"users"`
	Reason string `json:"reason,omitempty"`
}
