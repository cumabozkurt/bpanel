// SPDX-License-Identifier: Apache-2.0

package mailx

import (
	"regexp"
	"strings"
)

// Delivery is one delivery attempt (or SMTP reject) from the Postfix log.
type Delivery struct {
	Time    string `json:"time"`
	QueueID string `json:"queue_id"`
	From    string `json:"from"`
	To      string `json:"to"`
	Status  string `json:"status"` // sent | deferred | bounced | expired | rejected | ...
	Relay   string `json:"relay,omitempty"`
	DSN     string `json:"dsn,omitempty"`
	Delay   string `json:"delay,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

const MaxDetail = 240

// syslog "Oct 10 12:00:01 host prog[pid]: msg" or ISO "2026-10-10T12:00:01.1+03:00 host prog[pid]: msg"
var reLine = regexp.MustCompile(`^((?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)|\d{4}-\d\d-\d\dT\S+)\s+\S+\s+(postfix[^\s\[:]*)\[\d+\]:\s+([0-9A-Za-z]{5,20}):\s+(.*)$`)

// kv extracts key=value fields ("to=<a@b>, relay=x[1.2.3.4]:25, status=sent (250 ok)").
func kv(s string) map[string]string {
	m := map[string]string{}
	for _, k := range []string{"from", "to", "orig_to", "relay", "delay", "dsn", "status"} {
		i := strings.Index(s, k+"=")
		for i > 0 && s[i-1] != ' ' && s[i-1] != ',' && s[i-1] != ';' {
			j := strings.Index(s[i+1:], k+"=")
			if j < 0 {
				i = -1
				break
			}
			i += 1 + j
		}
		if i < 0 {
			continue
		}
		v := s[i+len(k)+1:]
		if strings.HasPrefix(v, "<") {
			if e := strings.IndexByte(v, '>'); e >= 0 {
				m[k] = v[1:e]
				continue
			}
		}
		if e := strings.IndexAny(v, ", "); e >= 0 {
			v = v[:e]
		}
		m[k] = v
	}
	if i := strings.Index(s, "status="); i >= 0 {
		rest := s[i+7:]
		if o := strings.Index(rest, " ("); o >= 0 && strings.HasSuffix(rest, ")") {
			m["detail"] = rest[o+2 : len(rest)-1]
		}
	}
	return m
}

func trunc(s string) string {
	if len(s) > MaxDetail {
		s = s[:MaxDetail]
		for len(s) > 0 && s[len(s)-1]&0xC0 == 0x80 { // do not cut a UTF-8 sequence
			s = s[:len(s)-1]
		}
		s += "…"
	}
	return s
}

func domainOf(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i >= 0 {
		return strings.ToLower(addr[i+1:])
	}
	return ""
}

// ParseLog turns Postfix log lines into deliveries whose sender or recipient
// domain is in owned (the ownership filter: other tenants' mail is never
// returned). query, when set, must be a substring of the sender or recipient.
// The newest limit entries are returned, newest first.
func ParseLog(lines []string, owned map[string]bool, query string, limit int) []Delivery {
	query = strings.ToLower(query)
	from := map[string]string{}
	var out []Delivery
	for _, ln := range lines {
		m := reLine.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		ts, prog, qid, msg := m[1], m[2], m[3], m[4]
		f := kv(msg)
		var d Delivery
		switch {
		case qid == "NOQUEUE" && strings.HasPrefix(msg, "reject:"):
			detail := strings.TrimPrefix(msg, "reject: ")
			if i := strings.Index(detail, "; from=<"); i >= 0 {
				detail = detail[:i]
			}
			d = Delivery{Time: ts, QueueID: qid, From: f["from"], To: f["to"], Status: "rejected", Detail: trunc(detail)}
		case strings.HasPrefix(msg, "from=<") && !strings.Contains(msg, "status="):
			from[qid] = f["from"]
			continue
		case f["to"] != "" && f["status"] != "":
			d = Delivery{Time: ts, QueueID: qid, From: from[qid], To: f["to"], Status: f["status"], Relay: f["relay"],
				DSN: f["dsn"], Delay: f["delay"], Detail: trunc(f["detail"])}
		default:
			continue
		}
		_ = prog
		if !owned[domainOf(d.To)] && !owned[domainOf(d.From)] {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(d.From), query) && !strings.Contains(strings.ToLower(d.To), query) {
			continue
		}
		out = append(out, d)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
