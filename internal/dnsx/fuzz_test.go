// SPDX-License-Identifier: Apache-2.0

package dnsx

import (
	"strings"
	"testing"
)

// FuzzParse: the BIND importer must never panic, must cap its error list,
// and must never emit a record/name containing a line break (it is later
// rendered into a zone file and into PowerDNS calls).
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"$ORIGIN example.test.\n$TTL 3600\n@ IN A 192.0.2.1\nwww 300 IN CNAME @\n",
		"@ IN MX 10 mail\n@ IN TXT \"v=spf1 -all\" ( \"x\" )\n; c\n",
		"@ IN SOA ns1 host ( 1 2 3 4 5 )\n_srv._tcp IN SRV 0 5 5060 sip.example.test.\n",
		"$INCLUDE /etc/passwd\n", "( ( (\n\"unterminated", "a\\\nb IN A 1.2.3.4",
		"@ IN CAA 0 issue \"letsencrypt.org\"\n", "@ 1w2d IN AAAA 2001:db8::1\n",
	} {
		f.Add("example.test", s)
	}
	f.Fuzz(func(t *testing.T, zone, text string) {
		if len(text) > 64<<10 {
			return
		}
		res := Parse(zone, text)
		if len(res.Errors) > maxErrors {
			t.Fatalf("too many errors: %d", len(res.Errors))
		}
		for _, s := range res.RRSets {
			if strings.ContainsAny(s.Name, "\r\n\x00") || strings.ContainsAny(s.Type, "\r\n\x00 ") {
				t.Fatalf("bad rrset name/type %q %q", s.Name, s.Type)
			}
			for _, r := range s.Records {
				if strings.ContainsAny(r, "\r\n\x00") {
					t.Fatalf("record with line break: %q", r)
				}
			}
		}
		_ = Check(zone, res.RRSets)
	})
}

func FuzzParseTTL(f *testing.F) {
	for _, s := range []string{"3600", "1h", "1w2d3h4m5s", "", "99999999999999999999", "1H30M"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if v, ok := ParseTTL(s); ok && v < 0 {
			t.Fatalf("negative ttl %d for %q", v, s)
		}
	})
}
