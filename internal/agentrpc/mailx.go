// SPDX-License-Identifier: Apache-2.0

package agentrpc

import "github.com/cumabozkurt/bpanel/internal/mailx"

// v0.4 user mail tools (autoresponders, filters, spam filters, track delivery).
const (
	MMailSieveApply = "mail.sieve.apply" // write + compile + activate the managed Sieve script of one mailbox
	MMailSpamApply  = "mail.spam.apply"  // render the account's Rspamd settings rules and reload rspamd
	MMailLogSearch  = "mail.log.search"  // search the Postfix log for the account's mail domains
)

// MailSieveReq replaces the managed script of one mailbox (nil Vacation and
// no Rules = remove it).
type MailSieveReq struct {
	User     string          `json:"user"`
	Email    string          `json:"email"`
	Vacation *mailx.Vacation `json:"vacation,omitempty"`
	Rules    []mailx.Rule    `json:"rules"`
}

// MailxStatus: active | inactive (nothing configured) | not_installed.
type MailxStatus struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type MailSpamReq struct {
	User    string     `json:"user"`
	Domains []string   `json:"domains"`
	Policy  mailx.Spam `json:"policy"`
}

type MailLogReq struct {
	User    string   `json:"user"`
	Domains []string `json:"domains"`
	Query   string   `json:"query,omitempty"`
	Limit   int      `json:"limit,omitempty"`
}

type MailLogResult struct {
	Status  string           `json:"status"` // ok | not_installed
	Reason  string           `json:"reason,omitempty"`
	Source  string           `json:"source,omitempty"`
	Scanned int              `json:"scanned"`
	Entries []mailx.Delivery `json:"entries"`
}
