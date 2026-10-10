// SPDX-License-Identifier: Apache-2.0

// Package mailx holds the pure (no I/O) parts of the v0.4 user mail tools:
// the Sieve generator for autoresponders and filters (Dovecot Pigeonhole),
// the Rspamd settings renderer for per-account spam filters and the Postfix
// mail log parser for "Track Delivery". Everything a tenant types is
// validated here and escaped again on output, so no input can break out of
// a quoted string and add Sieve or UCL commands.
package mailx

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Error is a validation error with a stable API error code.
type Error struct{ Code, Field string }

func (e *Error) Error() string { return e.Code + ": " + e.Field }

func bad(code, field string) error { return &Error{Code: code, Field: field} }

// Vacation is one mailbox autoresponder (Sieve "vacation", RFC 5230).
type Vacation struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
	Start   string `json:"start,omitempty"` // YYYY-MM-DD, inclusive; empty = now
	End     string `json:"end,omitempty"`   // YYYY-MM-DD, inclusive; empty = open-ended
	Days    int    `json:"interval_days"`   // 1..30: one reply per sender per N days
	From    string `json:"from,omitempty"`  // reply sender; empty = the mailbox
}

// Rule is one simple mail filter: <field> <op> <value> -> <action> [target].
type Rule struct {
	Name   string `json:"name"`
	Field  string `json:"field"`            // from | to | subject | header
	Header string `json:"header,omitempty"` // header name when Field == header
	Op     string `json:"op"`               // contains | is | begins
	Value  string `json:"value"`
	Action string `json:"action"`           // move | discard | redirect
	Target string `json:"target,omitempty"` // folder (move) or address (redirect)
}

const (
	MaxRules       = 50
	MaxSubjectLen  = 200
	MaxBodyLen     = 8000
	MaxValueLen    = 200
	MaxFolderLen   = 100
	MaxRuleNameLen = 80
)

var (
	reDate   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	reHeader = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`)
	reFolder = regexp.MustCompile(`^[\p{L}\p{N} _.\-/]+$`)
	reEmail  = regexp.MustCompile(`^[a-z0-9!#$%&'*+/=?^_{|}~.-]{1,64}@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	reDomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// hasCtl reports control characters (newline included).
func hasCtl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// IsEmail is a strict lowercase address check (no quoted local parts).
func IsEmail(s string) bool { return len(s) <= 254 && reEmail.MatchString(s) }

// IsDomain is a strict lowercase hostname check.
func IsDomain(s string) bool { return len(s) <= 253 && reDomain.MatchString(s) }

// Normalize trims and validates a vacation; it returns a copy.
func (v Vacation) Normalize() (Vacation, error) {
	v.Subject = strings.TrimSpace(v.Subject)
	v.Body = strings.ReplaceAll(strings.ReplaceAll(v.Body, "\r\n", "\n"), "\r", "\n")
	v.From = strings.ToLower(strings.TrimSpace(v.From))
	switch {
	case v.Subject == "" || utf8.RuneCountInString(v.Subject) > MaxSubjectLen || hasCtl(v.Subject) || !utf8.ValidString(v.Subject):
		return v, bad("invalid_autoresponder_subject", "subject")
	case strings.TrimSpace(v.Body) == "" || len(v.Body) > MaxBodyLen || !utf8.ValidString(v.Body) || strings.ContainsAny(strings.ReplaceAll(v.Body, "\n", ""), "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x7f"):
		return v, bad("invalid_autoresponder_body", "body")
	case v.Days < 1 || v.Days > 30:
		return v, bad("invalid_autoresponder_interval", "interval_days")
	case v.From != "" && !IsEmail(v.From):
		return v, bad("invalid_email", "from")
	}
	var st, en time.Time
	for _, f := range []struct {
		s     string
		t     *time.Time
		field string
	}{{v.Start, &st, "start"}, {v.End, &en, "end"}} {
		if f.s == "" {
			continue
		}
		t, err := time.Parse("2006-01-02", f.s)
		if !reDate.MatchString(f.s) || err != nil {
			return v, bad("invalid_autoresponder_dates", f.field)
		}
		*f.t = t
	}
	if !st.IsZero() && !en.IsZero() && en.Before(st) {
		return v, bad("invalid_autoresponder_dates", "end")
	}
	return v, nil
}

// Normalize trims and validates a rule; it returns a copy.
func (r Rule) Normalize() (Rule, error) {
	r.Name = strings.TrimSpace(r.Name)
	r.Field = strings.ToLower(strings.TrimSpace(r.Field))
	r.Header = strings.TrimSpace(r.Header)
	r.Op = strings.ToLower(strings.TrimSpace(r.Op))
	r.Action = strings.ToLower(strings.TrimSpace(r.Action))
	r.Target = strings.TrimSpace(r.Target)
	if r.Name == "" || utf8.RuneCountInString(r.Name) > MaxRuleNameLen || hasCtl(r.Name) || !utf8.ValidString(r.Name) {
		return r, bad("invalid_filter_name", "name")
	}
	switch r.Field {
	case "from", "to", "subject":
		r.Header = ""
	case "header":
		if !reHeader.MatchString(r.Header) {
			return r, bad("invalid_filter_header", "header")
		}
	default:
		return r, bad("invalid_filter_field", "field")
	}
	if r.Op != "contains" && r.Op != "is" && r.Op != "begins" {
		return r, bad("invalid_filter_op", "op")
	}
	if r.Value == "" || utf8.RuneCountInString(r.Value) > MaxValueLen || hasCtl(r.Value) || !utf8.ValidString(r.Value) {
		return r, bad("invalid_filter_value", "value")
	}
	switch r.Action {
	case "discard":
		r.Target = ""
	case "move":
		if r.Target == "" || utf8.RuneCountInString(r.Target) > MaxFolderLen || !reFolder.MatchString(r.Target) ||
			strings.HasPrefix(r.Target, "/") || strings.HasSuffix(r.Target, "/") || strings.Contains(r.Target, "..") || strings.Contains(r.Target, "//") {
			return r, bad("invalid_filter_folder", "target")
		}
	case "redirect":
		r.Target = strings.ToLower(r.Target)
		if !IsEmail(r.Target) {
			return r, bad("invalid_email", "target")
		}
	default:
		return r, bad("invalid_filter_action", "action")
	}
	return r, nil
}

// Quote renders s as a Sieve quoted-string (RFC 5228 §2.4.2): only '"' and
// '\' are special inside it, so escaping both keeps every input inside the
// string. Bare CR/LF are normalised to CRLF (allowed inside quoted-strings).
func Quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString("\r\n")
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// comment makes a single-line Sieve "#" comment from text (no line breaks).
func comment(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// Generate builds the managed Sieve script of one mailbox. vac may be nil;
// rules may be empty. It returns "" when there is nothing to do.
func Generate(mailbox string, vac *Vacation, rules []Rule) (string, error) {
	if !IsEmail(mailbox) {
		return "", bad("invalid_email", "email")
	}
	if len(rules) > MaxRules {
		return "", bad("too_many_filters", "rules")
	}
	var nv *Vacation
	if vac != nil {
		v, err := vac.Normalize()
		if err != nil {
			return "", err
		}
		nv = &v
	}
	nr := make([]Rule, 0, len(rules))
	for _, r := range rules {
		x, err := r.Normalize()
		if err != nil {
			return "", err
		}
		nr = append(nr, x)
	}
	if nv == nil && len(nr) == 0 {
		return "", nil
	}
	req := map[string]bool{}
	var body strings.Builder
	if nv != nil {
		req["vacation"] = true
		conds := []string{`not header :contains ["X-Spam", "X-Spam-Flag"] ["Yes", "YES", "yes"]`}
		if nv.Start != "" {
			req["date"], req["relational"] = true, true
			conds = append(conds, `currentdate :value "ge" "date" `+Quote(nv.Start))
		}
		if nv.End != "" {
			req["date"], req["relational"] = true, true
			conds = append(conds, `currentdate :value "le" "date" `+Quote(nv.End))
		}
		from := ""
		if nv.From != "" {
			from = " :from " + Quote(nv.From)
		}
		body.WriteString("# autoresponder\n")
		fmt.Fprintf(&body, "if allof(%s) {\n  vacation :days %s :addresses [%s]%s :subject %s\n    %s;\n}\n",
			strings.Join(conds, ",\n         "), strconv.Itoa(nv.Days), Quote(mailbox), from, Quote(nv.Subject), Quote(nv.Body))
	}
	for i, r := range nr {
		match := map[string]string{"contains": ":contains", "is": ":is", "begins": ":matches"}[r.Op]
		val := r.Value
		if r.Op == "begins" {
			// :matches treats * and ? as wildcards: escape them, then append *
			val = strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`).Replace(val) + "*"
		}
		var test string
		switch r.Field {
		case "from", "to":
			test = fmt.Sprintf("address %s :all %s %s", match, Quote(r.Field), Quote(val))
			if r.Field == "to" {
				test = fmt.Sprintf("address %s :all [\"to\", \"cc\"] %s", match, Quote(val))
			}
		case "subject":
			test = fmt.Sprintf("header %s \"subject\" %s", match, Quote(val))
		default:
			test = fmt.Sprintf("header %s %s %s", match, Quote(r.Header), Quote(val))
		}
		var act string
		switch r.Action {
		case "move":
			req["fileinto"], req["mailbox"] = true, true
			act = "fileinto :create " + Quote(strings.ReplaceAll(r.Target, "/", ".")) + ";"
		case "discard":
			act = "discard;"
		case "redirect":
			act = "redirect " + Quote(r.Target) + ";"
		}
		fmt.Fprintf(&body, "# filter %d: %s\nif %s {\n  %s\n  stop;\n}\n", i+1, comment(r.Name), test, act)
	}
	var b strings.Builder
	b.WriteString("# Managed by BOZKURT PANEL (autoresponder + filters for " + comment(mailbox) + ").\n# Changes made here are overwritten.\n")
	var names []string
	for _, n := range []string{"date", "fileinto", "mailbox", "relational", "vacation"} {
		if req[n] {
			names = append(names, Quote(n))
		}
	}
	b.WriteString("require [" + strings.Join(names, ", ") + "];\n\n")
	b.WriteString(body.String())
	return b.String(), nil
}
