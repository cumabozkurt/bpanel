// SPDX-License-Identifier: Apache-2.0

package agentrpc

import "github.com/cumabozkurt/bpanel/internal/webx"

// v0.4 webx: per-domain web extras (directory privacy, hotlink protection,
// custom error pages, MIME types, IP blocker).
const MWebxApply = "webx.apply" // store state, re-apply the vhost (config test + rollback)

// WebxApplyParams replaces one domain's web extras. User names the account
// (R2-WB-1 gate); Vhost (Domain = Config.Domain, User = User) is re-applied
// through the normal vhost path so the include is (re)written or dropped.
type WebxApplyParams struct {
	User   string      `json:"user"`
	Config webx.Config `json:"config"`
	Vhost  Vhost       `json:"vhost"`
}

// WebxApplyResult: Status "applied".
type WebxApplyResult struct {
	Status string `json:"status"`
	Wired  bool   `json:"wired"` // the vhost now includes the snippet (false when nothing to render)
}
