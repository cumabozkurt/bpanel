// SPDX-License-Identifier: Apache-2.0

package agentrpc

// v0.4 adminx: server update status / apply (Update Preferences).
const (
	MUpdatesStatus = "system.updates.status" // read-only: upgradable packages + reboot-required
	MUpdatesApply  = "system.updates.apply"  // run the package manager upgrade (security-only or all)
)

type UpdatesStatusReq struct {
	SecurityOnly bool `json:"security_only"`
}

type UpdatesStatus struct {
	Status         string   `json:"status"`            // ok | not_installed | unsupported | error
	Manager        string   `json:"manager,omitempty"` // apt | dnf
	Upgradable     int      `json:"upgradable"`
	Security       int      `json:"security"`
	Packages       []string `json:"packages,omitempty"` // at most 200 names
	RebootRequired bool     `json:"reboot_required"`
	RebootKnown    bool     `json:"reboot_known"` // false when no probe was available
	Reason         string   `json:"reason,omitempty"`
	CheckedAt      int64    `json:"checked_at"`
}

type UpdatesApply struct {
	SecurityOnly bool `json:"security_only"`
	AutoReboot   bool `json:"auto_reboot"` // only honoured when a reboot is required afterwards
}

type UpdatesApplyResult struct {
	Status         string `json:"status"` // applied | not_installed | unsupported
	Manager        string `json:"manager,omitempty"`
	RebootRequired bool   `json:"reboot_required"`
	RebootStarted  bool   `json:"reboot_started"`
	Reason         string `json:"reason,omitempty"`
}
