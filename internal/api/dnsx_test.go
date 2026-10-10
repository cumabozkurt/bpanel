// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/dnsx"
)

// fakeDnsx gives a fakeAgent a stateful zone store, DNSSEC and mailing
// lists, only for agents a dnsx test switched on (other tests keep the
// stateless behaviour).
type fakeDnsxState struct {
	zones      map[string][]rpc.DNSRecord
	secured    map[string]bool
	lists      map[string]map[string]bool
	notInstall bool
}

var (
	fakeDnsxMu sync.Mutex
	fakeDnsxOn = map[*fakeAgent]*fakeDnsxState{}
)

func dnsxOn(a *fakeAgent) *fakeDnsxState {
	fakeDnsxMu.Lock()
	defer fakeDnsxMu.Unlock()
	st := &fakeDnsxState{zones: map[string][]rpc.DNSRecord{}, secured: map[string]bool{}, lists: map[string]map[string]bool{}}
	fakeDnsxOn[a] = st
	return st
}

func fakeDnsx(a *fakeAgent, method string, b []byte) (any, bool, error) {
	fakeDnsxMu.Lock()
	defer fakeDnsxMu.Unlock()
	st := fakeDnsxOn[a]
	if st == nil {
		return nil, false, nil
	}
	switch method {
	case rpc.MDNSZoneCreate:
		var p rpc.DNSZone
		_ = json.Unmarshal(b, &p)
		recs := []rpc.DNSRecord{{Name: p.Zone, Type: "SOA", TTL: 3600, Content: "ns1." + p.Zone + ". h." + p.Zone + ". 1 2 3 4 5"}}
		for _, r := range p.Records {
			r.Content = dnsx.Normalize(r.Type, r.Content)
			recs = append(recs, r)
		}
		st.zones[p.Zone] = recs
		return struct{}{}, true, nil
	case rpc.MDNSZoneGet:
		var p rpc.ZoneRef
		_ = json.Unmarshal(b, &p)
		return rpc.DNSZone{Zone: p.Zone, Records: append([]rpc.DNSRecord(nil), st.zones[p.Zone]...), Serial: 1}, true, nil
	case rpc.MDNSRRSetReplace, rpc.MDNSRRSetDelete:
		var p rpc.RRSet
		_ = json.Unmarshal(b, &p)
		var keep []rpc.DNSRecord
		for _, r := range st.zones[p.Zone] {
			if !(r.Name == p.Name && r.Type == p.Type) {
				keep = append(keep, r)
			}
		}
		if method == rpc.MDNSRRSetReplace {
			for _, c := range p.Records {
				keep = append(keep, rpc.DNSRecord{Name: p.Name, Type: p.Type, TTL: p.TTL, Content: dnsx.Normalize(p.Type, c)})
			}
		}
		st.zones[p.Zone] = keep
		return struct{}{}, true, nil
	case rpc.MDNSSEC:
		var p rpc.DNSSECReq
		_ = json.Unmarshal(b, &p)
		if st.notInstall {
			return rpc.DNSSECStatus{Status: "not_installed", Reason: "pdnsutil not found"}, true, nil
		}
		switch p.Action {
		case "enable":
			st.secured[p.Zone] = true
		case "disable":
			delete(st.secured, p.Zone)
		}
		r := rpc.DNSSECStatus{Status: "inactive", DS: []string{}}
		if st.secured[p.Zone] {
			r.Status, r.DS = "active", []string{p.Zone + ". IN DS 1 13 2 ab"}
		}
		return r, true, nil
	case rpc.MListApply:
		var p rpc.ListReq
		_ = json.Unmarshal(b, &p)
		if st.notInstall {
			return rpc.ListStatus{Status: "not_installed", Reason: "mlmmj-receive not found"}, true, nil
		}
		k := p.User + ":" + p.Name + "@" + p.Domain
		if p.Action == "create" {
			st.lists[k] = map[string]bool{}
		} else {
			delete(st.lists, k)
		}
		return rpc.ListStatus{Status: "ok"}, true, nil
	case rpc.MListSubs:
		var p rpc.ListSubsReq
		_ = json.Unmarshal(b, &p)
		subs := st.lists[p.User+":"+p.Name+"@"+p.Domain]
		if subs == nil {
			return nil, true, &rpc.Error{Code: "not_found"}
		}
		if p.Action == "add" {
			subs[p.Address] = true
		} else if p.Action == "remove" {
			delete(subs, p.Address)
		}
		r := rpc.ListStatus{Status: "ok", Subscribers: []string{}}
		for s := range subs {
			r.Subscribers = append(r.Subscribers, s)
		}
		return r, true, nil
	}
	return nil, false, nil
}

func TestDnsxOwnershipHistoryRevert(t *testing.T) {
	e := newEnv(t)
	st := dnsxOn(e.ag)
	e.tenant("bob", "bob.test")
	e.tenant("mallory", "mallory.test")
	bs := mustLogin(t, e, e.user, "bob", "")
	ms := mustLogin(t, e, e.user, "mallory", "")
	// another tenant's zone is invisible on every dnsx endpoint
	imp := map[string]any{"text": "a A 192.0.2.1"}
	for _, c := range []struct {
		m, p string
		b    any
	}{{"GET", "dnssec", nil}, {"POST", "dnssec", map[string]any{"enabled": true}}, {"GET", "export", nil}, {"POST", "import/preview", imp},
		{"POST", "import/apply", imp}, {"GET", "check", nil}, {"GET", "history", nil}, {"POST", "history/1/revert", map[string]any{}}} {
		if code, _ := ms.call(c.m, "/api/v1/user/dnsx/bob.test/"+c.p, c.b); code != 404 {
			t.Errorf("mallory %s %s: %d", c.m, c.p, code)
		}
	}
	// history: a change is recorded and can be reverted
	if code, m := bs.call("PUT", "/api/v1/user/dns/bob.test/rrset", map[string]any{"name": "api", "type": "A", "ttl": 300, "records": []string{"192.0.2.7"}}); code != 200 {
		t.Fatalf("put: %d %v", code, m)
	}
	code, m := bs.call("GET", "/api/v1/user/dnsx/bob.test/history", nil)
	items, _ := m["items"].([]any)
	if code != 200 || len(items) == 0 {
		t.Fatalf("history: %d %v", code, m)
	}
	top := items[0].(map[string]any)
	if top["name"] != "api.bob.test" || top["before"] != nil || top["actor"] != "bob" {
		t.Errorf("history item: %v", top)
	}
	id := strconv.Itoa(int(top["id"].(float64)))
	// mallory cannot revert bob's change through her own zone either
	if code, _ := ms.call("POST", "/api/v1/user/dnsx/mallory.test/history/"+id+"/revert", nil); code != 404 {
		t.Errorf("foreign revert: %d", code)
	}
	if code, m := bs.call("POST", "/api/v1/user/dnsx/bob.test/history/"+id+"/revert", nil); code != 200 {
		t.Fatalf("revert: %d %v", code, m)
	}
	for _, r := range st.zones["bob.test"] {
		if r.Name == "api.bob.test" {
			t.Errorf("revert left %v", r)
		}
	}
	// reverting again conflicts (zone no longer matches the change)
	if code, _ := bs.call("POST", "/api/v1/user/dnsx/bob.test/history/"+id+"/revert", nil); code != 409 {
		t.Errorf("second revert: %d", code)
	}
	// export -> import round trip is a no-op
	code, m = bs.call("GET", "/api/v1/user/dnsx/bob.test/export", nil)
	txt, _ := m["text"].(string)
	if code != 200 || !strings.Contains(txt, "$ORIGIN bob.test.") {
		t.Fatalf("export: %d %v", code, m)
	}
	code, m = bs.call("POST", "/api/v1/user/dnsx/bob.test/import/preview", map[string]any{"text": txt, "mode": "replace"})
	if ch, _ := m["changes"].([]any); code != 200 || len(ch) != 0 {
		t.Errorf("round trip: %d %v", code, m)
	}
	// malformed input: preview lists errors, apply refuses
	bad := "www A 999.0.0.1\n$INCLUDE /etc/shadow\nx.evil.org. A 192.0.2.1\n"
	code, m = bs.call("POST", "/api/v1/user/dnsx/bob.test/import/preview", map[string]any{"text": bad})
	if errs, _ := m["errors"].([]any); code != 200 || len(errs) != 3 {
		t.Errorf("preview bad: %d %v", code, m)
	}
	if code, _ := bs.call("POST", "/api/v1/user/dnsx/bob.test/import/apply", map[string]any{"text": bad}); code != 400 {
		t.Errorf("apply bad: %d", code)
	}
	if code, _ := bs.call("POST", "/api/v1/user/dnsx/bob.test/import/apply", map[string]any{"text": "a A 192.0.2.1", "mode": "evil"}); code != 400 {
		t.Errorf("bad mode: %d", code)
	}
	// consistency errors block apply unless forced
	cn := "@ CNAME other.example.\n"
	if code, _ := bs.call("POST", "/api/v1/user/dnsx/bob.test/import/apply", map[string]any{"text": cn}); code != 409 {
		t.Errorf("apex cname: %d", code)
	}
	good := "shop 600 IN A 192.0.2.10\nshop TXT \"hello\"\n"
	code, m = bs.call("POST", "/api/v1/user/dnsx/bob.test/import/apply", map[string]any{"text": good})
	if code != 200 || m["applied"].(float64) != 2 {
		t.Errorf("apply: %d %v", code, m)
	}
	if code, m := bs.call("GET", "/api/v1/user/dnsx/bob.test/check", nil); code != 200 || m["findings"] == nil {
		t.Errorf("check: %d %v", code, m)
	}
	// DNSSEC
	if code, m := bs.call("POST", "/api/v1/user/dnsx/bob.test/dnssec", map[string]any{"enabled": true}); code != 200 || m["status"] != "active" {
		t.Errorf("dnssec: %d %v", code, m)
	}
	st.notInstall = true
	if code, m := bs.call("POST", "/api/v1/user/dnsx/bob.test/dnssec", map[string]any{"enabled": true}); code != 409 || m["error"] != "dnssec_not_installed" {
		t.Errorf("dnssec not installed: %d %v", code, m)
	}
	if code, m := bs.call("POST", "/api/v1/user/lists", map[string]any{"name": "news", "domain": "bob.test", "owner": "bob@bob.test"}); code != 409 || m["error"] != "mlist_not_installed" {
		t.Errorf("list not installed: %d %v", code, m)
	}
	st.notInstall = false
	// the agent only ever hears about the caller's own zone
	e.ag.mu.Lock()
	for _, c := range e.ag.calls {
		if c.Method == rpc.MDNSSEC && strings.Contains(string(c.Params), "mallory") {
			t.Errorf("leak: %s", c.Params)
		}
	}
	e.ag.mu.Unlock()
}

func TestMailingLists(t *testing.T) {
	e := newEnv(t)
	dnsxOn(e.ag)
	e.tenant("bob", "bob.test")
	e.tenant("mallory", "mallory.test")
	bs := mustLogin(t, e, e.user, "bob", "")
	ms := mustLogin(t, e, e.user, "mallory", "")
	if code, _ := ms.call("POST", "/api/v1/user/lists", map[string]any{"name": "news", "domain": "bob.test", "owner": "m@mallory.test"}); code != 404 {
		t.Errorf("foreign domain: %d", code)
	}
	for _, b := range []map[string]any{{"name": "postmaster", "domain": "bob.test", "owner": "b@bob.test"},
		{"name": "../x", "domain": "bob.test", "owner": "b@bob.test"}, {"name": "news", "domain": "bob.test", "owner": "nope"}} {
		if code, _ := bs.call("POST", "/api/v1/user/lists", b); code != 400 {
			t.Errorf("bad %v: %d", b, code)
		}
	}
	code, m := bs.call("POST", "/api/v1/user/lists", map[string]any{"name": "news", "domain": "bob.test", "owner": "b@bob.test"})
	if code != 200 || m["address"] != "news@bob.test" {
		t.Fatalf("create: %d %v", code, m)
	}
	id := strconv.Itoa(int(m["id"].(float64)))
	if code, _ := bs.call("POST", "/api/v1/user/lists", map[string]any{"name": "news", "domain": "bob.test", "owner": "b@bob.test"}); code != 409 {
		t.Errorf("dup: %d", code)
	}
	base := "/api/v1/user/lists/" + id
	for _, c := range [][2]string{{"GET", "/subscribers"}, {"POST", "/subscribers"}, {"DELETE", "/subscribers?address=a@b.test"}, {"DELETE", ""}} {
		if code, _ := ms.call(c[0], base+c[1], map[string]any{"address": "x@y.test"}); code != 404 {
			t.Errorf("mallory %v: %d", c, code)
		}
	}
	if code, _ := bs.call("POST", base+"/subscribers", map[string]any{"address": "bad"}); code != 400 {
		t.Errorf("bad sub: %d", code)
	}
	code, m = bs.call("POST", base+"/subscribers", map[string]any{"address": "Fan@Example.org"})
	if subs, _ := m["subscribers"].([]any); code != 200 || len(subs) != 1 || subs[0] != "fan@example.org" {
		t.Errorf("add: %d %v", code, m)
	}
	code, m = bs.call("DELETE", base+"/subscribers?address=fan@example.org", nil)
	if subs, _ := m["subscribers"].([]any); code != 200 || len(subs) != 0 {
		t.Errorf("remove: %d %v", code, m)
	}
	if code, m := ms.call("GET", "/api/v1/user/lists", nil); code != 200 || len(m["lists"].([]any)) != 0 {
		t.Errorf("mallory sees lists: %v", m)
	}
	if code, _ := bs.call("DELETE", base, nil); code != 200 {
		t.Errorf("delete: %d", code)
	}
}
