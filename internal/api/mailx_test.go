// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

func mxFirstBox(t *testing.T, s *sess) int64 {
	t.Helper()
	code, m := s.call("GET", "/api/v1/user/email/autoresponders", nil)
	if code != 200 {
		t.Fatalf("list: %d %v", code, m)
	}
	bs, _ := m["mailboxes"].([]any)
	if len(bs) == 0 {
		t.Fatalf("no mailboxes: %v", m)
	}
	return int64(bs[0].(map[string]any)["id"].(float64))
}

func TestMailxOwnershipAndValidation(t *testing.T) {
	e := newEnv(t)
	e.tenant("mallory", "mallory.test")
	e.tenant("bob", "bob.test")
	bs := mustLogin(t, e, e.user, "bob", "")
	ms := mustLogin(t, e, e.user, "mallory", "")
	dom := map[*sess]string{bs: "bob.test", ms: "mallory.test"}
	for s, d := range dom {
		if code, m := s.call("POST", "/api/v1/user/email/accounts", map[string]any{"local": "info", "domain": d, "password": tPW, "quota_mb": 100}); code != 200 {
			t.Fatalf("mailbox %s: %d %v", d, code, m)
		}
	}
	bobBox := mxFirstBox(t, bs)
	malBox := mxFirstBox(t, ms)
	ar := map[string]any{"subject": "Away", "body": "Back soon", "interval_days": 2}
	// another tenant's mailbox is invisible
	if code, _ := ms.call("PUT", "/api/v1/user/email/autoresponders/"+strconv.FormatInt(bobBox, 10), ar); code != 404 {
		t.Errorf("foreign autoresponder: %d", code)
	}
	if code, _ := ms.call("POST", "/api/v1/user/email/filters", map[string]any{"mailbox_id": bobBox, "name": "x", "field": "from", "op": "is", "value": "v", "action": "discard"}); code != 404 {
		t.Errorf("foreign filter: %d", code)
	}
	// own: ok
	if code, m := ms.call("PUT", "/api/v1/user/email/autoresponders/"+strconv.FormatInt(malBox, 10), ar); code != 200 {
		t.Errorf("own autoresponder: %d %v", code, m)
	}
	// injection attempts are refused before the agent is called
	for _, bad := range []map[string]any{
		{"subject": "a\"\r\ndiscard;", "body": "b", "interval_days": 1},
		{"subject": "s", "body": "b", "interval_days": 0},
		{"subject": "s", "body": "b", "interval_days": 1, "from": "info@bob.test"},
	} {
		if code, _ := ms.call("PUT", "/api/v1/user/email/autoresponders/"+strconv.FormatInt(malBox, 10), bad); code != 400 {
			t.Errorf("bad autoresponder %v: %d", bad, code)
		}
	}
	code, m := ms.call("POST", "/api/v1/user/email/filters", map[string]any{"mailbox_id": malBox, "name": "news", "field": "header", "header": "X-Evil\"", "op": "is", "value": "v", "action": "discard"})
	if code != 400 || m["error"] != "invalid_filter_header" {
		t.Errorf("bad header: %d %v", code, m)
	}
	code, m = ms.call("POST", "/api/v1/user/email/filters", map[string]any{"mailbox_id": malBox, "name": "news", "field": "from", "op": "contains", "value": "news@", "action": "move", "target": "News"})
	if code != 200 {
		t.Fatalf("filter: %d %v", code, m)
	}
	fid := int64(m["id"].(float64))
	if code, _ := bs.call("DELETE", "/api/v1/user/email/filters/"+strconv.FormatInt(fid, 10), nil); code != 404 {
		t.Errorf("foreign filter delete: %d", code)
	}
	if code, m := ms.call("PUT", "/api/v1/user/email/spam", map[string]any{"enabled": true, "required_score": 5, "allow": []string{"friend@x.com"}, "deny": []string{"a\"b"}}); code != 400 {
		t.Errorf("bad spam entry: %d %v", code, m)
	}
	if code, m := ms.call("PUT", "/api/v1/user/email/spam", map[string]any{"enabled": true, "required_score": 5, "allow": []string{"friend@x.com"}}); code != 200 {
		t.Errorf("spam: %d %v", code, m)
	}
	if code, m := ms.call("GET", "/api/v1/user/email/track?q=info", nil); code != 200 {
		t.Errorf("track: %d %v", code, m)
	}
	// the agent only ever hears about the caller's own domains / mailboxes
	ag := e.ag
	ag.mu.Lock()
	defer ag.mu.Unlock()
	seen := map[string]bool{}
	for _, c := range ag.calls {
		switch c.Method {
		case rpc.MMailSieveApply, rpc.MMailSpamApply, rpc.MMailLogSearch:
			seen[c.Method] = true
			var p map[string]any
			_ = json.Unmarshal(c.Params, &p)
			if p["user"] != "mallory" || strings.Contains(string(c.Params), "bob.test") {
				t.Errorf("%s leaked: %s", c.Method, c.Params)
			}
		}
	}
	if len(seen) != 3 {
		t.Errorf("agent methods called: %v", seen)
	}
}
