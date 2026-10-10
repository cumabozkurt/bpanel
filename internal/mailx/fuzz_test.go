// SPDX-License-Identifier: Apache-2.0

package mailx

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// unquote decodes a Sieve quoted-string produced by Quote.
func unquote(t *testing.T, q string) string {
	if len(q) < 2 || q[0] != '"' || q[len(q)-1] != '"' {
		t.Fatalf("not quoted: %q", q)
	}
	var b strings.Builder
	in := q[1 : len(q)-1]
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c == '\\' {
			i++
			if i >= len(in) {
				t.Fatalf("dangling backslash in %q", q)
			}
			b.WriteByte(in[i])
			continue
		}
		if c == '"' {
			t.Fatalf("unescaped quote inside %q", q)
		}
		b.WriteByte(c)
	}
	return b.String()
}

func FuzzQuote(f *testing.F) {
	for _, s := range []string{"", "a", `"`, `\`, "a\r\nb", "\r", `\"; discard;`, "ü\u2028"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		q := Quote(s)
		if !utf8.ValidString(q) {
			t.Fatalf("Quote produced invalid UTF-8 for %q", s)
		}
		if !utf8.ValidString(s) {
			return // API input is JSON (valid UTF-8); invalid bytes become U+FFFD
		}
		got := unquote(t, q)
		want := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n"), "\n", "\r\n")
		if got != want {
			t.Fatalf("roundtrip: %q -> %q", want, got)
		}
	})
}

// skeleton replaces every quoted-string, multi-line text: literal and
// comment of a Sieve script with a placeholder, leaving only the commands.
func skeleton(t *testing.T, s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '"':
			j := i + 1
			for ; j < len(s); j++ {
				if s[j] == '\\' {
					j++
					continue
				}
				if s[j] == '"' {
					break
				}
			}
			if j >= len(s) {
				t.Fatalf("unterminated string in script:\n%s", s)
			}
			b.WriteString("<S>")
			i = j
		case s[i] == '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			b.WriteString("<C>\n")
		case strings.HasPrefix(s[i:], "text:"):
			end := strings.Index(s[i:], "\r\n.\r\n")
			if end < 0 {
				t.Fatalf("unterminated text: in script:\n%s", s)
			}
			b.WriteString("<T>")
			i += end + 4
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// FuzzGenerate: whatever the user puts in subject/body/value/name/target, the
// command structure of the script must equal the one produced for benign
// values (i.e. no Sieve injection).
func FuzzGenerate(f *testing.F) {
	f.Add("Away", "I am away.\nBack soon", "spam", "rule 1", "Junk", "subject", "contains", "move", "")
	f.Add(`"; discard; "`, "x\r\n.\r\nredirect \"a@b.cc\";", `\"`, "#\n", "a/b", "header", "is", "redirect", "X-Spam")
	f.Fuzz(func(t *testing.T, subj, body, value, name, target, field, op, action, header string) {
		mk := func(subj, body, value, name, target string) (string, error) {
			vac := &Vacation{Subject: subj, Body: body, Days: 7}
			rule := Rule{Name: name, Field: field, Header: header, Op: op, Value: value, Action: action, Target: target}
			return Generate("user@example.test", vac, []Rule{rule})
		}
		got, err := mk(subj, body, value, name, target)
		if err != nil {
			return
		}
		benTarget := "Folder"
		if action == "redirect" {
			benTarget = "a@example.test"
		}
		if action == "discard" {
			benTarget = target
		}
		ben, err := mk("s", "b", "v", "n", benTarget)
		if err != nil {
			return
		}
		if sk, bk := skeleton(t, got), skeleton(t, ben); sk != bk {
			t.Fatalf("script structure changed by user input:\n--- got\n%s\n--- benign\n%s", sk, bk)
		}
	})
}

func FuzzParseLog(f *testing.F) {
	f.Add("Oct 10 12:00:01 host postfix/smtp[123]: ABCDE12345: to=<a@example.test>, relay=x[1.2.3.4]:25, delay=1, dsn=2.0.0, status=sent (250 ok)", "")
	f.Add("2026-10-10T12:00:00+03:00 h postfix/qmgr[1]: 0123456789: from=<b@c.de>, size=1", "c.de")
	f.Fuzz(func(t *testing.T, line, q string) {
		out := ParseLog(strings.Split(line, "\n"), map[string]bool{"example.test": true, "c.de": true}, q, 100)
		for _, d := range out {
			if len(d.Detail) > MaxDetail+8 {
				t.Fatalf("detail not truncated: %d", len(d.Detail))
			}
		}
	})
}
