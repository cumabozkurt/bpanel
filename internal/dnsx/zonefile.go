// SPDX-License-Identifier: Apache-2.0

// Package dnsx holds the pure logic of the v0.4 DNS extras: BIND zone file
// export and a strict import parser, rrset diffing, zone consistency checks,
// pdnsutil output parsing (DNSSEC) and mlmmj mailing-list helpers. Nothing in
// here touches the system; the agent and the API call into it.
package dnsx

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// ImportTypes are the record types an import may carry. NS only for a
// delegation below the apex (the apex NS set belongs to the server).
var ImportTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "TXT": true, "SRV": true, "CAA": true, "NS": true}

// skipped types: accepted in a pasted file but never imported (server managed).
var skipTypes = map[string]bool{"SOA": true, "DNSKEY": true, "RRSIG": true, "NSEC": true, "NSEC3": true, "NSEC3PARAM": true, "DS": true, "CDS": true, "CDNSKEY": true}

const (
	MaxImportBytes   = 256 << 10
	MaxImportRecords = 2000
	MaxLineBytes     = 8192
	MinTTL           = 60
	MaxTTL           = 604800
	maxErrors        = 50
)

// RRSet is one name+type with its records (content in PowerDNS presentation:
// absolute targets end in a dot, TXT is quoted).
type RRSet struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Records []string `json:"records"`
}

func (r RRSet) Key() string { return r.Name + "/" + r.Type }

// Equal compares content order-independently.
func (r RRSet) Equal(o RRSet) bool {
	if r.Name != o.Name || r.Type != o.Type || r.TTL != o.TTL || len(r.Records) != len(o.Records) {
		return false
	}
	a, b := append([]string(nil), r.Records...), append([]string(nil), o.Records...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ParseError is one problem of an import, with its 1-based line.
type ParseError struct {
	Line   int    `json:"line"`
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

func (e ParseError) Error() string { return fmt.Sprintf("line %d: %s %s", e.Line, e.Code, e.Detail) }

// Note is an informational message (a line that was skipped on purpose).
type Note struct {
	Line int    `json:"line"`
	Code string `json:"code"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

// Group turns flat records into rrsets (sorted by name, type). The TTL of a
// set is its first record's.
func Group(recs []rpc.DNSRecord) []RRSet {
	idx := map[string]int{}
	var out []RRSet
	for _, r := range recs {
		if r.Disabled {
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(r.Name), ".")
		k := name + "/" + r.Type
		i, ok := idx[k]
		if !ok {
			idx[k] = len(out)
			out = append(out, RRSet{Name: name, Type: r.Type, TTL: r.TTL})
			i = len(out) - 1
		}
		out[i].Records = append(out[i].Records, Normalize(r.Type, r.Content))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func fqdn(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "." || strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// Normalize mirrors agent.NormalizeContent so imported content compares
// equal to what PowerDNS returns.
func Normalize(t, c string) string {
	c = strings.TrimSpace(c)
	switch t {
	case "CNAME", "NS":
		return fqdn(c)
	case "MX":
		if f := strings.Fields(c); len(f) == 2 {
			return f[0] + " " + fqdn(f[1])
		}
	case "SRV":
		if f := strings.Fields(c); len(f) == 4 {
			return f[0] + " " + f[1] + " " + f[2] + " " + fqdn(f[3])
		}
	case "TXT":
		if strings.HasPrefix(c, `"`) {
			return c
		}
		c = strings.ReplaceAll(c, `"`, `\"`)
		var parts []string
		for len(c) > 255 {
			parts = append(parts, `"`+c[:255]+`"`)
			c = c[255:]
		}
		return strings.Join(append(parts, `"`+c+`"`), " ")
	}
	return c
}

func rel(zone, name string) string {
	if name == zone {
		return "@"
	}
	if strings.HasSuffix(name, "."+zone) {
		return strings.TrimSuffix(name, "."+zone)
	}
	return name + "."
}

// Export renders a BIND zone file. SOA is written as a comment (the server
// owns it); every other rrset is written with absolute-or-@ owner names.
func Export(zone string, recs []rpc.DNSRecord, serial int64) string {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	var b strings.Builder
	fmt.Fprintf(&b, "; Zone %s exported by BOZKURT PANEL (serial %d)\n", zone, serial)
	fmt.Fprintf(&b, "$ORIGIN %s.\n$TTL 3600\n", zone)
	for _, s := range Group(recs) {
		for _, c := range s.Records {
			line := fmt.Sprintf("%-24s %-6d IN %-6s %s\n", rel(zone, s.Name), s.TTL, s.Type, c)
			if s.Type == "SOA" {
				line = "; " + line
			}
			b.WriteString(line)
		}
	}
	return b.String()
}

// stripComment removes a ';' comment outside quotes and reports open
// quotes.
func stripComment(s string) (string, bool) {
	inQ, esc := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case esc:
			esc = false
		case c == '\\':
			esc = true
		case c == '"':
			inQ = !inQ
		case c == ';' && !inQ:
			return s[:i], true
		}
	}
	return s, !inQ
}

// tokenize splits on blanks, keeping quoted strings (with quotes) whole.
func tokenize(s string) ([]string, bool) {
	var out []string
	var cur strings.Builder
	inQ, esc, have := false, false, false
	flush := func() {
		if have {
			out = append(out, cur.String())
			cur.Reset()
			have = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if esc {
			cur.WriteByte(c)
			esc = false
			continue
		}
		switch {
		case c == '\\':
			cur.WriteByte(c)
			esc, have = true, true
		case c == '"':
			cur.WriteByte(c)
			have = true
			if inQ {
				inQ = false
				flush()
			} else {
				inQ = true
			}
		case !inQ && (c == ' ' || c == '\t'):
			flush()
		default:
			cur.WriteByte(c)
			have = true
		}
	}
	if inQ {
		return nil, false
	}
	flush()
	return out, true
}

// ParseTTL accepts seconds or BIND units (1h30m, 1d, 2w).
func ParseTTL(s string) (int, bool) {
	s = strings.ToLower(s)
	if s == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n, n >= 0
	}
	total, num := 0, ""
	for _, c := range s {
		if c >= '0' && c <= '9' {
			num += string(c)
			continue
		}
		mult := map[rune]int{'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}[c]
		if mult == 0 || num == "" {
			return 0, false
		}
		n, err := strconv.Atoi(num)
		if err != nil || n > 10000000 {
			return 0, false
		}
		total += n * mult
		num = ""
	}
	if num != "" {
		return 0, false
	}
	return total, true
}

func isType(s string) bool {
	return ImportTypes[s] || skipTypes[s] || s == "PTR" || s == "HINFO" || s == "SPF" || s == "DNAME" || s == "ALIAS"
}

// Result is a parsed import.
type Result struct {
	RRSets []RRSet      `json:"rrsets"`
	Errors []ParseError `json:"errors"`
	Notes  []Note       `json:"notes"`
	Warn   []Finding    `json:"warnings"`
	Count  int          `json:"count"`
}

// Parse is the strict BIND zone-text parser. It never panics and returns
// every problem it finds (up to 50) with its line. Supported: $ORIGIN (must
// be the zone), $TTL, parentheses, comments, blank owner (= previous),
// "@", relative and absolute names, optional TTL and class IN in either
// order. Types: ImportTypes; SOA/DNSSEC types are skipped with a note;
// anything else ($INCLUDE, $GENERATE, other types/classes) is an error.
func Parse(zone, text string) Result {
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	res := Result{RRSets: []RRSet{}, Errors: []ParseError{}, Notes: []Note{}, Warn: []Finding{}}
	fail := func(line int, code, detail string) {
		if len(res.Errors) < maxErrors {
			if len(detail) > 80 {
				detail = detail[:80]
			}
			res.Errors = append(res.Errors, ParseError{Line: line, Code: code, Detail: detail})
		}
	}
	if len(text) > MaxImportBytes {
		fail(0, "dnsx_import_too_large", "")
		return res
	}
	if strings.ContainsRune(text, 0) {
		fail(0, "dnsx_import_binary", "")
		return res
	}
	// Defence in depth (qa fuzz FuzzParse): callers pass a stored, validated
	// domain, but never build owner names from a malformed zone.
	if validate.Domain(zone) != nil || !validate.ConfigSafe(zone) {
		fail(0, "dnsx_origin_mismatch", "")
		return res
	}
	defTTL := 3600
	prev := ""
	idx := map[string]int{}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		lineNo := i + 1
		raw := lines[i]
		if len(raw) > MaxLineBytes {
			fail(lineNo, "dnsx_line_too_long", "")
			continue
		}
		body, ok := stripComment(raw)
		if !ok {
			fail(lineNo, "dnsx_unterminated_quote", "")
			continue
		}
		// parentheses: join continuation lines
		if strings.Count(body, "(") > strings.Count(body, ")") {
			for strings.Count(body, "(") > strings.Count(body, ")") && i+1 < len(lines) && i-lineNo < 50 {
				i++
				nb, _ := stripComment(lines[i])
				body += " " + nb
			}
			if strings.Count(body, "(") != strings.Count(body, ")") {
				fail(lineNo, "dnsx_unbalanced_parens", "")
				continue
			}
		}
		if strings.Count(body, ")") > strings.Count(body, "(") {
			fail(lineNo, "dnsx_unbalanced_parens", "")
			continue
		}
		body = strings.NewReplacer("(", " ", ")", " ").Replace(body)
		for _, c := range body {
			if c < 0x20 && c != '\t' {
				fail(lineNo, "dnsx_control_char", "")
				body = ""
				break
			}
		}
		if strings.TrimSpace(body) == "" {
			continue
		}
		blankOwner := body[0] == ' ' || body[0] == '\t'
		tok, ok := tokenize(body)
		if !ok {
			fail(lineNo, "dnsx_unterminated_quote", "")
			continue
		}
		if len(tok) == 0 {
			continue
		}
		if strings.HasPrefix(tok[0], "$") && !blankOwner {
			switch strings.ToUpper(tok[0]) {
			case "$ORIGIN":
				if len(tok) != 2 || strings.TrimSuffix(strings.ToLower(tok[1]), ".") != zone || !strings.HasSuffix(tok[1], ".") {
					fail(lineNo, "dnsx_origin_mismatch", strings.Join(tok[1:], " "))
				}
			case "$TTL":
				t, ok := ParseTTL(strings.Join(tok[1:], ""))
				if len(tok) != 2 || !ok || t < MinTTL || t > MaxTTL {
					fail(lineNo, "dnsx_invalid_ttl", strings.Join(tok[1:], " "))
				} else {
					defTTL = t
				}
			default:
				fail(lineNo, "dnsx_directive_unsupported", tok[0])
			}
			continue
		}
		var owner string
		if blankOwner {
			if prev == "" {
				fail(lineNo, "dnsx_missing_owner", "")
				continue
			}
			owner = prev
		} else {
			n, code := ownerName(zone, tok[0])
			if code != "" {
				fail(lineNo, code, tok[0])
				prev = ""
				continue
			}
			owner, tok = n, tok[1:]
			prev = owner
		}
		ttl, ttlSet := defTTL, false
		// [ttl] [class] type  or  [class] [ttl] type
		for k := 0; k < 2 && len(tok) > 0; k++ {
			u := strings.ToUpper(tok[0])
			if isType(u) {
				break
			}
			if u == "IN" {
				tok = tok[1:]
				continue
			}
			if u == "CH" || u == "HS" || u == "CS" || u == "ANY" {
				fail(lineNo, "dnsx_class_unsupported", tok[0])
				tok = nil
				break
			}
			if t, ok := ParseTTL(tok[0]); ok && !ttlSet {
				ttl, ttlSet = t, true
				tok = tok[1:]
				continue
			}
			break
		}
		if tok == nil {
			continue
		}
		if len(tok) == 0 {
			fail(lineNo, "dnsx_missing_type", "")
			continue
		}
		typ := strings.ToUpper(tok[0])
		rdata := tok[1:]
		if skipTypes[typ] {
			res.Notes = append(res.Notes, Note{Line: lineNo, Code: "dnsx_skipped_managed", Name: owner, Type: typ})
			continue
		}
		if !ImportTypes[typ] {
			fail(lineNo, "dnsx_type_unsupported", tok[0])
			continue
		}
		if ttl < MinTTL || ttl > MaxTTL {
			fail(lineNo, "dnsx_invalid_ttl", strconv.Itoa(ttl))
			continue
		}
		if typ == "NS" && owner == zone {
			res.Notes = append(res.Notes, Note{Line: lineNo, Code: "dnsx_skipped_apex_ns", Name: owner, Type: typ})
			continue
		}
		content, code := rdataFor(zone, typ, rdata)
		if code != "" {
			fail(lineNo, code, strings.Join(rdata, " "))
			continue
		}
		res.Count++
		if res.Count > MaxImportRecords {
			fail(lineNo, "dnsx_too_many_records", "")
			break
		}
		k := owner + "/" + typ
		j, ok := idx[k]
		if !ok {
			idx[k] = len(res.RRSets)
			res.RRSets = append(res.RRSets, RRSet{Name: owner, Type: typ, TTL: ttl})
			j = len(res.RRSets) - 1
		} else if res.RRSets[j].TTL != ttl {
			res.Warn = append(res.Warn, Finding{Level: "warn", Code: "ttl_mismatch", Name: owner, Type: typ})
			if ttl < res.RRSets[j].TTL {
				res.RRSets[j].TTL = ttl
			}
		}
		dup := false
		for _, c := range res.RRSets[j].Records {
			dup = dup || c == content
		}
		if !dup {
			res.RRSets[j].Records = append(res.RRSets[j].Records, content)
		}
		if len(res.RRSets[j].Records) > 100 {
			fail(lineNo, "dnsx_rrset_too_large", owner+" "+typ)
		}
	}
	sort.Slice(res.RRSets, func(i, j int) bool {
		if res.RRSets[i].Name != res.RRSets[j].Name {
			return res.RRSets[i].Name < res.RRSets[j].Name
		}
		return res.RRSets[i].Type < res.RRSets[j].Type
	})
	return res
}

// ownerName resolves an owner token to a lowercase FQDN without the dot.
func ownerName(zone, tok string) (string, string) {
	t := strings.ToLower(tok)
	var name string
	switch {
	case t == "@":
		name = zone
	case strings.HasSuffix(t, "."):
		name = strings.TrimSuffix(t, ".")
	default:
		name = t + "." + zone
	}
	if strings.ContainsAny(name, `\"/ `) {
		return "", "dnsx_invalid_name"
	}
	if err := validate.RecordName(zone, name); err != nil {
		if err.Error() == "record_outside_zone" {
			return "", "dnsx_name_outside_zone"
		}
		return "", "dnsx_invalid_name"
	}
	return name, ""
}

// target resolves a domain-name rdata field to an absolute name with dot.
func target(zone, tok string) (string, bool) {
	t := strings.ToLower(tok)
	if t == "." {
		return ".", true
	}
	if t == "@" {
		return zone + ".", true
	}
	if !strings.HasSuffix(t, ".") {
		t = t + "." + zone + "."
	}
	h := strings.TrimSuffix(t, ".")
	if len(h) > 253 || h == "" {
		return "", false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 {
			return "", false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '*') {
				return "", false
			}
		}
	}
	return t, true
}

func u16(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 0 && n <= 65535 && s == strconv.Itoa(n)
}

// rdataFor validates the rdata tokens of one record and returns its content
// in PowerDNS presentation format.
func rdataFor(zone, typ string, f []string) (string, string) {
	switch typ {
	case "A":
		if len(f) != 1 {
			return "", "dnsx_bad_rdata"
		}
		if ip := net.ParseIP(f[0]); ip == nil || ip.To4() == nil || strings.Contains(f[0], ":") {
			return "", "invalid_ipv4"
		}
		return net.ParseIP(f[0]).To4().String(), ""
	case "AAAA":
		if len(f) != 1 {
			return "", "dnsx_bad_rdata"
		}
		if ip := net.ParseIP(f[0]); ip == nil || !strings.Contains(f[0], ":") {
			return "", "invalid_ipv6"
		}
		return net.ParseIP(f[0]).String(), ""
	case "CNAME", "NS":
		if len(f) != 1 {
			return "", "dnsx_bad_rdata"
		}
		t, ok := target(zone, f[0])
		if !ok || t == "." {
			return "", "dnsx_bad_target"
		}
		return t, ""
	case "MX":
		if len(f) != 2 || !u16(f[0]) {
			return "", "dnsx_bad_rdata"
		}
		t, ok := target(zone, f[1])
		if !ok {
			return "", "dnsx_bad_target"
		}
		return f[0] + " " + t, ""
	case "SRV":
		if len(f) != 4 || !u16(f[0]) || !u16(f[1]) || !u16(f[2]) {
			return "", "dnsx_bad_rdata"
		}
		t, ok := target(zone, f[3])
		if !ok {
			return "", "dnsx_bad_target"
		}
		return f[0] + " " + f[1] + " " + f[2] + " " + t, ""
	case "TXT":
		if len(f) == 0 {
			return "", "dnsx_bad_rdata"
		}
		parts := make([]string, 0, len(f))
		total := 0
		for _, p := range f {
			if !strings.HasPrefix(p, `"`) {
				// unquoted single word: quote it
				if strings.ContainsAny(p, `"\`) {
					return "", "dnsx_bad_txt"
				}
				p = `"` + p + `"`
			}
			if len(p) < 2 || !strings.HasSuffix(p, `"`) || len(p)-2 > 255+strings.Count(p, `\`) {
				return "", "dnsx_bad_txt"
			}
			total += len(p)
			parts = append(parts, p)
		}
		if total > 4000 {
			return "", "dnsx_bad_txt"
		}
		return strings.Join(parts, " "), ""
	case "CAA":
		if len(f) != 3 {
			return "", "dnsx_bad_rdata"
		}
		fl, err := strconv.Atoi(f[0])
		tag := strings.ToLower(f[1])
		if err != nil || fl < 0 || fl > 255 || (tag != "issue" && tag != "issuewild" && tag != "iodef") {
			return "", "dnsx_bad_caa"
		}
		v := f[2]
		if !strings.HasPrefix(v, `"`) {
			v = `"` + v + `"`
		}
		if strings.Count(v, `"`) != 2 || len(v) > 512 {
			return "", "dnsx_bad_caa"
		}
		return strconv.Itoa(fl) + " " + tag + " " + v, ""
	}
	return "", "dnsx_type_unsupported"
}
