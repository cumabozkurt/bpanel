// SPDX-License-Identifier: Apache-2.0

package mailx

import (
	"errors"
	"strings"
	"testing"
)

// sieveStrings returns the script with every quoted-string removed, i.e. the
// command skeleton. Injection succeeds only if tenant text shows up here.
func sieveSkeleton(t *testing.T, s string) string {
	t.Helper()
	var b strings.Builder
	in, esc := false, false
	for _, r := range s {
		switch {
		case in && esc:
			esc = false
		case in && r == '\\':
			esc = true
		case in && r == '"':
			in = false
		case in:
		case r == '"':
			in = true
			b.WriteString(`""`)
		default:
			b.WriteRune(r)
		}
	}
	if in {
		t.Fatalf("unterminated quoted string in:\n%s", s)
	}
	return b.String()
}

func dropComments(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func TestGenerateVacationAndFilters(t *testing.T) {
	s, err := Generate("info@example.com", &Vacation{Subject: "Away", Body: "Back on Monday.\n.\nBye", Start: "2026-10-01", End: "2026-10-20", Days: 3},
		[]Rule{{Name: "news", Field: "from", Op: "contains", Value: "news@", Action: "move", Target: "Newsletters/Weekly"},
			{Name: "junk", Field: "header", Header: "X-Mailer", Op: "begins", Value: "Bulk*", Action: "discard"},
			{Name: "boss", Field: "subject", Op: "is", Value: "urgent", Action: "redirect", Target: "Me@Other.org"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`require ["date", "fileinto", "mailbox", "relational", "vacation"];`, `vacation :days 3 :addresses ["info@example.com"] :subject "Away"`,
		`currentdate :value "ge" "date" "2026-10-01"`, `fileinto :create "Newsletters.Weekly";`, `header :matches "X-Mailer" "Bulk\\**"`,
		`redirect "me@other.org";`, `address :contains :all "from" "news@"`, "discard;", "stop;"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	if s2, _ := Generate("info@example.com", nil, nil); s2 != "" {
		t.Fatalf("empty config should give empty script, got %q", s2)
	}
}

func TestSieveInjection(t *testing.T) {
	evil := []string{"\"; discard; #", "x\"\r\nredirect \"evil@x.com\";", "a\\\"; keep;", "\\", "\"", "}\nif true { discard; }"}
	for _, e := range evil {
		// subject/value/name reject control characters outright
		if _, err := Generate("a@b.com", &Vacation{Subject: e, Body: "x", Days: 1}, nil); strings.ContainsAny(e, "\r\n") && err == nil {
			t.Errorf("subject with newline accepted: %q", e)
		}
		if _, err := Generate("a@b.com", nil, []Rule{{Name: "n", Field: "subject", Op: "is", Value: e, Action: "discard"}}); strings.ContainsAny(e, "\r\n") && err == nil {
			t.Errorf("value with newline accepted: %q", e)
		}
		// body may contain newlines: it must still stay inside one string
		s, err := Generate("a@b.com", &Vacation{Subject: "s", Body: e, Days: 1}, nil)
		if err != nil {
			t.Fatalf("body %q: %v", e, err)
		}
		sk := dropComments(sieveSkeleton(t, s))
		for _, bad := range []string{"redirect", "keep", "if true", "discard"} {
			if strings.Contains(sk, bad) {
				t.Errorf("body %q leaked %q into commands:\n%s", e, bad, s)
			}
		}
		if !strings.Contains(e, "\n") {
			s, err = Generate("a@b.com", &Vacation{Subject: e, Body: "b", Days: 1}, []Rule{{Name: e, Field: "subject", Op: "contains", Value: e, Action: "discard"}})
			if err != nil {
				t.Fatalf("%q: %v", e, err)
			}
			sk = dropComments(sieveSkeleton(t, s))
			for _, bad := range []string{"redirect", "keep", "if true"} {
				if strings.Contains(sk, bad) {
					t.Errorf("%q leaked %q:\n%s", e, bad, s)
				}
			}
			if strings.Count(sk, "discard;") != 1 {
				t.Errorf("%q: expected exactly one discard:\n%s", e, sk)
			}
		}
	}
	// rule names go into comments: a newline there must not be possible
	if _, err := Generate("a@b.com", nil, []Rule{{Name: "x\ndiscard;", Field: "subject", Op: "is", Value: "v", Action: "discard"}}); err == nil {
		t.Error("name with newline accepted")
	}
}

func TestRuleValidation(t *testing.T) {
	cases := []struct {
		r    Rule
		code string
	}{
		{Rule{Name: "n", Field: "body", Op: "is", Value: "v", Action: "discard"}, "invalid_filter_field"},
		{Rule{Name: "n", Field: "header", Header: "X Bad", Op: "is", Value: "v", Action: "discard"}, "invalid_filter_header"},
		{Rule{Name: "n", Field: "header", Header: "X\"", Op: "is", Value: "v", Action: "discard"}, "invalid_filter_header"},
		{Rule{Name: "n", Field: "from", Op: "regex", Value: "v", Action: "discard"}, "invalid_filter_op"},
		{Rule{Name: "n", Field: "from", Op: "is", Value: "v", Action: "move", Target: "../etc"}, "invalid_filter_folder"},
		{Rule{Name: "n", Field: "from", Op: "is", Value: "v", Action: "move", Target: "a\"b"}, "invalid_filter_folder"},
		{Rule{Name: "n", Field: "from", Op: "is", Value: "v", Action: "move", Target: "/abs"}, "invalid_filter_folder"},
		{Rule{Name: "n", Field: "from", Op: "is", Value: "v", Action: "redirect", Target: "x\"@y.com"}, "invalid_email"},
		{Rule{Name: "n", Field: "from", Op: "is", Value: "v", Action: "vacation"}, "invalid_filter_action"},
		{Rule{Name: "n", Field: "from", Op: "is", Value: "", Action: "discard"}, "invalid_filter_value"},
	}
	for _, c := range cases {
		_, err := c.r.Normalize()
		var me *Error
		if !errors.As(err, &me) || me.Code != c.code {
			t.Errorf("%+v: got %v want %s", c.r, err, c.code)
		}
	}
	for _, v := range []Vacation{{Subject: "s", Body: "b", Days: 0}, {Subject: "s", Body: "b", Days: 31}, {Subject: "s", Body: "b", Days: 1, Start: "2026-13-01"},
		{Subject: "s", Body: "b", Days: 1, Start: "2026-10-10", End: "2026-10-01"}, {Subject: "", Body: "b", Days: 1}, {Subject: "s", Body: " ", Days: 1}} {
		if _, err := v.Normalize(); err == nil {
			t.Errorf("accepted %+v", v)
		}
	}
}

func TestRenderRspamd(t *testing.T) {
	s, err := RenderRspamd("alice", []string{"example.com", "b.org"}, Spam{Enabled: true, RequiredScore: 5, Allow: []string{"Friend@x.com", "trusted.net"}, Deny: []string{"@spam.biz"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`rcpt = ["@b.org", "@example.com"];`, `from = ["@trusted.net", "friend@x.com"];`, `from = ["@spam.biz"];`, `"add header" = 5.0;`, "reject = 15.0;", "want_spam = yes;", "priority = high;"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	off, _ := RenderRspamd("alice", []string{"example.com"}, Spam{Enabled: false})
	if !strings.Contains(off, "want_spam = yes;") || strings.Contains(off, "add header") {
		t.Errorf("disabled:\n%s", off)
	}
	for _, e := range []string{`a"b@x.com`, "x.com\n}", "x.com; reject=0", "@", "a b.com"} {
		if _, err := RenderRspamd("alice", []string{"example.com"}, Spam{Enabled: true, Allow: []string{e}}); err == nil {
			t.Errorf("entry %q accepted", e)
		}
	}
	if _, err := RenderRspamd("Alice;", []string{"example.com"}, Spam{}); err == nil {
		t.Error("bad account accepted")
	}
	if _, err := RenderRspamd("alice", []string{"example.com"}, Spam{RequiredScore: 99}); err == nil {
		t.Error("bad score accepted")
	}
	if s, _ := RenderRspamd("alice", nil, Spam{Enabled: true}); s != "" {
		t.Error("no domains should render nothing")
	}
}

var sampleLog = strings.Split(`Oct 10 12:00:01 mx postfix/smtpd[100]: 4A1B2C3D4E: client=mail.other.net[203.0.113.5]
Oct 10 12:00:01 mx postfix/cleanup[101]: 4A1B2C3D4E: message-id=<abc@other.net>
Oct 10 12:00:01 mx postfix/qmgr[102]: 4A1B2C3D4E: from=<bob@other.net>, size=1234, nrcpt=2 (queue active)
Oct 10 12:00:02 mx postfix/lmtp[103]: 4A1B2C3D4E: to=<info@example.com>, relay=mx[private/dovecot-lmtp], delay=0.4, delays=0.1/0/0/0.3, dsn=2.0.0, status=sent (250 2.0.0 <info@example.com> Saved)
Oct 10 12:00:02 mx postfix/lmtp[103]: 4A1B2C3D4E: to=<carol@tenant2.com>, relay=mx[private/dovecot-lmtp], delay=0.4, dsn=2.0.0, status=sent (250 2.0.0 Saved)
2026-10-10T12:05:00.123456+03:00 mx postfix/qmgr[102]: 5B2C3D4E5F: from=<sales@example.com>, size=900, nrcpt=1 (queue active)
2026-10-10T12:05:03.000001+03:00 mx postfix/smtp[104]: 5B2C3D4E5F: to=<x@gmail.com>, orig_to=<alias@example.com>, relay=gmail-smtp-in.l.google.com[142.250.1.1]:25, delay=3, dsn=4.7.1, status=deferred (host gmail-smtp-in.l.google.com said: 421-4.7.1 try again later)
Oct 10 12:06:00 mx postfix/smtpd[105]: NOQUEUE: reject: RCPT from unknown[198.51.100.7]: 554 5.7.1 Service unavailable; Client host blocked; from=<spam@bad.biz> to=<info@example.com> proto=ESMTP helo=<x>
Oct 10 12:06:30 mx postfix/smtpd[105]: NOQUEUE: reject: RCPT from unknown[198.51.100.7]: 550 5.1.1 User unknown; from=<spam@bad.biz> to=<dave@tenant2.com> proto=ESMTP helo=<x>
Oct 10 12:07:00 mx postfix/bounce[106]: 6C3D4E5F6A: sender non-delivery notification: 7D4E5F6A7B
Oct 10 12:07:00 mx dovecot: lmtp(info@example.com): msgid=<abc@other.net>: saved mail to INBOX
garbage line`, "\n")

func TestParseLogOwnership(t *testing.T) {
	got := ParseLog(sampleLog, map[string]bool{"example.com": true}, "", 100)
	if len(got) != 3 {
		t.Fatalf("got %d entries: %+v", len(got), got)
	}
	// newest first
	if got[0].Status != "rejected" || got[0].From != "spam@bad.biz" || got[0].To != "info@example.com" || !strings.Contains(got[0].Detail, "Client host blocked") {
		t.Errorf("reject: %+v", got[0])
	}
	if got[1].Status != "deferred" || got[1].From != "sales@example.com" || got[1].To != "x@gmail.com" || got[1].DSN != "4.7.1" ||
		got[1].Relay != "gmail-smtp-in.l.google.com[142.250.1.1]:25" || !strings.HasPrefix(got[1].Time, "2026-10-10T12:05:03") {
		t.Errorf("deferred: %+v", got[1])
	}
	if got[2].Status != "sent" || got[2].From != "bob@other.net" || got[2].To != "info@example.com" || got[2].QueueID != "4A1B2C3D4E" || got[2].Delay != "0.4" {
		t.Errorf("sent: %+v", got[2])
	}
	for _, d := range got {
		if strings.Contains(d.To, "tenant2") || strings.Contains(d.From, "tenant2") {
			t.Errorf("other tenant leaked: %+v", d)
		}
	}
	if q := ParseLog(sampleLog, map[string]bool{"example.com": true}, "gmail", 100); len(q) != 1 {
		t.Errorf("query filter: %+v", q)
	}
	if l := ParseLog(sampleLog, map[string]bool{"example.com": true}, "", 1); len(l) != 1 || l[0].Status != "rejected" {
		t.Errorf("limit: %+v", l)
	}
	if n := ParseLog(sampleLog, map[string]bool{}, "", 100); len(n) != 0 {
		t.Errorf("no domains must give nothing: %+v", n)
	}
}
