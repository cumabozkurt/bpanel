//go:build dev

// SPDX-License-Identifier: Apache-2.0

package mockagent

import (
	"sort"
	"strings"
	"sync"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/dnsx"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// mockDnsx keeps DNSSEC and mailing-list state in memory for the dev/test
// mock agent. It validates like the real agent; every answer carries
// Reason "simulated by the mock agent" so nothing looks like a real system.

type dnsxState struct {
	secured map[string]bool
	lists   map[string]map[string]bool // addr -> subscribers
}

var (
	dnsxMu  sync.Mutex
	dnsxSt  = map[*Mock]*dnsxState{}
	mockWhy = "simulated by the mock agent"
)

func (m *Mock) dnsxState() *dnsxState {
	s := dnsxSt[m]
	if s == nil {
		s = &dnsxState{secured: map[string]bool{}, lists: map[string]map[string]bool{}}
		dnsxSt[m] = s
	}
	return s
}

func (m *Mock) mockDnsx(method string, params any) (any, error) {
	dnsxMu.Lock()
	defer dnsxMu.Unlock()
	st := m.dnsxState()
	switch method {
	case rpc.MDNSSEC:
		var p rpc.DNSSECReq
		conv(params, &p)
		if p.Owner == "" {
			return nil, &rpc.Error{Code: "owner_required"}
		}
		if _, ok := m.zones[p.Zone]; !ok {
			return nil, &rpc.Error{Code: "pdns_error", Message: "zone not found"}
		}
		switch p.Action {
		case "enable":
			st.secured[p.Zone] = true
		case "disable":
			delete(st.secured, p.Zone)
		case "status":
		default:
			return nil, &rpc.Error{Code: "invalid_action"}
		}
		r := rpc.DNSSECStatus{Status: "inactive", Reason: mockWhy, DS: []string{}, DNSKEY: []string{}}
		if st.secured[p.Zone] {
			r.Status = "active"
			r.DS = []string{p.Zone + ". IN DS 0 13 2 00 ; mock"}
		}
		return r, nil
	case rpc.MListApply:
		var p rpc.ListReq
		conv(params, &p)
		if p.User == "" || validate.Domain(p.Domain) != nil {
			return nil, &rpc.Error{Code: "invalid_domain"}
		}
		if err := dnsx.ListName(p.Name); err != nil {
			return nil, &rpc.Error{Code: err.Error()}
		}
		addr := p.Name + "@" + p.Domain
		switch p.Action {
		case "create":
			if validate.Email(p.Owner) != nil {
				return nil, &rpc.Error{Code: "invalid_email"}
			}
			if st.lists[addr] != nil {
				return nil, &rpc.Error{Code: "already_exists"}
			}
			st.lists[addr] = map[string]bool{}
		case "delete":
			if st.lists[addr] == nil {
				return nil, &rpc.Error{Code: "not_found"}
			}
			delete(st.lists, addr)
		default:
			return nil, &rpc.Error{Code: "invalid_action"}
		}
		return rpc.ListStatus{Status: "ok", Reason: mockWhy, Subscribers: []string{}}, nil
	case rpc.MListSubs:
		var p rpc.ListSubsReq
		conv(params, &p)
		subs := st.lists[p.Name+"@"+p.Domain]
		if subs == nil {
			return nil, &rpc.Error{Code: "not_found"}
		}
		switch p.Action {
		case "list":
		case "add", "remove":
			if validate.Email(p.Address) != nil {
				return nil, &rpc.Error{Code: "invalid_email"}
			}
			if p.Action == "add" {
				subs[strings.ToLower(p.Address)] = true
			} else {
				delete(subs, strings.ToLower(p.Address))
			}
		default:
			return nil, &rpc.Error{Code: "invalid_action"}
		}
		r := rpc.ListStatus{Status: "ok", Reason: mockWhy, Subscribers: []string{}}
		for a := range subs {
			r.Subscribers = append(r.Subscribers, a)
		}
		sort.Strings(r.Subscribers)
		return r, nil
	}
	return nil, &rpc.Error{Code: "unknown_method"}
}
