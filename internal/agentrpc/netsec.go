// SPDX-License-Identifier: Apache-2.0

package agentrpc

import (
	"time"

	"github.com/cumabozkurt/bpanel/internal/netsec"
)

// v0.4 network security (part A): host firewall in table inet bpanel.
// All methods are server-level (no tenant account).
const (
	MNetsecFwApply   = "netsec.fw.apply"   // apply with confirm timer + automatic rollback
	MNetsecFwConfirm = "netsec.fw.confirm" // confirm a pending apply by token
	MNetsecFwStatus  = "netsec.fw.status"  // support probe + pending change
	MNetsecFwBlock   = "netsec.fw.block"   // temporary block (element timeout)
	MNetsecFwUnblock = "netsec.fw.unblock"
	MNetsecFwList    = "netsec.fw.list" // current temporary blocks from the kernel
)

// NetsecFwApplyParams: the ruleset to apply. ConfirmSeconds defaults to 60
// (10..600). The API must call netsec.fw.confirm with the token in time or
// the previous table is restored.
type NetsecFwApplyParams struct {
	Ruleset        netsec.Ruleset `json:"ruleset"`
	ConfirmSeconds int            `json:"confirm_seconds,omitempty"`
}

// NetsecFwApplyResult: Status is "pending" (applied, waiting for confirm),
// or "unsupported" (nft not installed: nothing applied; Script and
// SyntaxOK report the Go-side check, Reason says why).
type NetsecFwApplyResult struct {
	Status   string    `json:"status"`
	Reason   string    `json:"reason,omitempty"`
	Token    string    `json:"token,omitempty"`
	Deadline time.Time `json:"deadline,omitempty"`
	Script   string    `json:"script"`
	SyntaxOK bool      `json:"syntax_ok"`
}

type NetsecFwConfirmParams struct {
	Token string `json:"token"`
}

type NetsecFwConfirmResult struct {
	Status string `json:"status"` // confirmed
}

type NetsecFwStatusParams struct{}

type NetsecFwStatusResult struct {
	Supported bool      `json:"supported"`
	Reason    string    `json:"reason,omitempty"`
	Pending   bool      `json:"pending"`
	Deadline  time.Time `json:"deadline,omitempty"`
	// LastRollback is set when the previous pending change was rolled back
	// ("timeout" or "agent_restart").
	LastRollback string `json:"last_rollback,omitempty"`
}

type NetsecFwBlockParams struct {
	IP             string `json:"ip"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	AdminIP        string `json:"admin_ip,omitempty"`
}

type NetsecFwUnblockParams struct {
	IP string `json:"ip"`
}

type NetsecFwBlockResult struct {
	Status string `json:"status"` // ok | unsupported
	Reason string `json:"reason,omitempty"`
}

type NetsecFwListParams struct{}

type NetsecFwListResult struct {
	Status string         `json:"status"` // ok | unsupported
	Reason string         `json:"reason,omitempty"`
	Blocks []netsec.Block `json:"blocks"`
}
