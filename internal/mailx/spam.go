// SPDX-License-Identifier: Apache-2.0

package mailx

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Spam is one hosting account's spam filter policy, applied by Rspamd's
// settings module to mail addressed to the account's mail domains.
type Spam struct {
	Enabled       bool     `json:"enabled"`
	RequiredScore float64  `json:"required_score"` // "add header" (mark as spam) threshold, 1..30
	Allow         []string `json:"allow"`          // sender address or @domain: never marked
	Deny          []string `json:"deny"`           // sender address or @domain: always rejected
}

const MaxListEntries = 200

var reAccount = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// NormalizeEntry turns "user@x.y", "@x.y" or "x.y" into "user@x.y" / "@x.y".
func NormalizeEntry(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(s, "@") {
		return s, IsDomain(s[1:])
	}
	if strings.Contains(s, "@") {
		return s, IsEmail(s)
	}
	return "@" + s, IsDomain(s)
}

// Normalize validates and de-duplicates the policy.
func (p Spam) Normalize() (Spam, error) {
	if p.RequiredScore == 0 {
		p.RequiredScore = 6
	}
	if p.RequiredScore < 1 || p.RequiredScore > 30 {
		return p, bad("invalid_spam_score", "required_score")
	}
	var err error
	if p.Allow, err = normList(p.Allow, "allow"); err != nil {
		return p, err
	}
	if p.Deny, err = normList(p.Deny, "deny"); err != nil {
		return p, err
	}
	return p, nil
}

func normList(in []string, field string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if strings.TrimSpace(s) == "" {
			continue
		}
		e, ok := NormalizeEntry(s)
		if !ok {
			return nil, bad("invalid_spam_entry", field)
		}
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	if len(out) > MaxListEntries {
		return nil, bad("too_many_spam_entries", field)
	}
	sort.Strings(out)
	return out, nil
}

// uclList renders a UCL array of already-validated strings (quoted, escaped).
func uclList(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = strconv.Quote(x) // validated charset never needs escaping; Quote is defence in depth
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// RenderRspamd renders the settings-module rules of one account. It returns
// "" when the account has no mail domain (nothing to apply).
func RenderRspamd(account string, domains []string, p Spam) (string, error) {
	if !reAccount.MatchString(account) {
		return "", bad("invalid_username", "user")
	}
	p, err := p.Normalize()
	if err != nil {
		return "", err
	}
	var rcpt []string
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if !IsDomain(d) {
			return "", bad("invalid_domain", "domains")
		}
		rcpt = append(rcpt, "@"+d)
	}
	if len(rcpt) == 0 {
		return "", nil
	}
	sort.Strings(rcpt)
	id := strings.ReplaceAll(account, "-", "_")
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by BOZKURT PANEL: spam filter of account %s. Changes are overwritten.\n", account)
	if len(p.Deny) > 0 {
		fmt.Fprintf(&b, "bpanel_%s_deny {\n  priority = high;\n  rcpt = %s;\n  from = %s;\n  apply {\n    actions {\n      reject = 0.01;\n    }\n  }\n}\n",
			id, uclList(rcpt), uclList(p.Deny))
	}
	if len(p.Allow) > 0 {
		fmt.Fprintf(&b, "bpanel_%s_allow {\n  priority = medium;\n  rcpt = %s;\n  from = %s;\n  want_spam = yes;\n}\n", id, uclList(rcpt), uclList(p.Allow))
	}
	if !p.Enabled {
		fmt.Fprintf(&b, "bpanel_%s {\n  priority = low;\n  rcpt = %s;\n  want_spam = yes;\n}\n", id, uclList(rcpt))
	} else {
		sc := strconv.FormatFloat(p.RequiredScore, 'f', 1, 64)
		rj := strconv.FormatFloat(max(p.RequiredScore+9, 15), 'f', 1, 64)
		fmt.Fprintf(&b, "bpanel_%s {\n  priority = low;\n  rcpt = %s;\n  apply {\n    actions {\n      \"add header\" = %s;\n      \"rewrite subject\" = null;\n      greylist = null;\n      reject = %s;\n    }\n  }\n}\n",
			id, uclList(rcpt), sc, rj)
	}
	return b.String(), nil
}
