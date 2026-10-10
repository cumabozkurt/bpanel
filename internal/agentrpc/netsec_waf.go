// SPDX-License-Identifier: Apache-2.0

package agentrpc

import "github.com/cumabozkurt/bpanel/internal/netsec"

// v0.4 network security (part B): per-domain WAF includes.
const (
	MNetsecWafApply  = "netsec.waf.apply"  // write the include, config test, roll back on failure
	MNetsecWafStatus = "netsec.waf.status" // provider probe (fixed paths), never faked
)

// NetsecWafApplyParams applies one domain's WAF config at Version.
type NetsecWafApplyParams struct {
	Config  netsec.WAFConfig `json:"config"`
	Version int64            `json:"version"`
	// Vhost, when set (Domain must equal Config.Domain), is re-applied through
	// the vhost apply path so the vhost includes/drops the WAF snippet.
	Vhost *Vhost `json:"vhost,omitempty"`
}

// NetsecWafApplyResult: Status applied | not_installed. Wired reports
// whether the domain's vhost already includes the WAF snippet.
type NetsecWafApplyResult struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	Server string `json:"server,omitempty"` // nginx | apache
	Wired  bool   `json:"wired"`
}

type NetsecWafStatusParams struct{}

// NetsecWafStatusResult: Status installed | not_installed.
type NetsecWafStatusResult struct {
	Status  string          `json:"status"`
	Reason  string          `json:"reason,omitempty"`
	Server  string          `json:"server,omitempty"`
	Module  string          `json:"module,omitempty"`
	Paths   netsec.WAFPaths `json:"paths"`
	Missing []string        `json:"missing,omitempty"`
}
