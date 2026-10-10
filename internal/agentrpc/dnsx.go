// SPDX-License-Identifier: Apache-2.0

package agentrpc

// v0.4 dnsx: DNSSEC through pdnsutil and mlmmj mailing lists.
const (
	MDNSSEC    = "dns.dnssec"  // status | enable | disable one zone (pdnsutil)
	MListApply = "mlist.apply" // create | delete one mlmmj list (+ Postfix transport map)
	MListSubs  = "mlist.subs"  // list | add | remove subscribers of one list
)

type DNSSECReq struct {
	Owner  string `json:"owner"`
	Zone   string `json:"zone"`
	Action string `json:"action"` // status | enable | disable
}

// DNSSECStatus: active | inactive | not_installed.
type DNSSECStatus struct {
	Status string   `json:"status"`
	Reason string   `json:"reason,omitempty"`
	DS     []string `json:"ds"`
	DNSKEY []string `json:"dnskey"`
}

type ListReq struct {
	User   string `json:"user"`
	Domain string `json:"domain"`
	Name   string `json:"name"`
	Owner  string `json:"owner,omitempty"` // list owner address (create)
	Action string `json:"action"`          // create | delete
}

type ListSubsReq struct {
	User    string `json:"user"`
	Domain  string `json:"domain"`
	Name    string `json:"name"`
	Action  string `json:"action"` // list | add | remove
	Address string `json:"address,omitempty"`
}

// ListStatus: ok | not_installed.
type ListStatus struct {
	Status      string   `json:"status"`
	Reason      string   `json:"reason,omitempty"`
	Subscribers []string `json:"subscribers"`
}
