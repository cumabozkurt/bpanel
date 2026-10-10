// SPDX-License-Identifier: Apache-2.0

package dnsx

import (
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

const good = `; comment
$ORIGIN example.com.
$TTL 1h
@   IN SOA ns1.example.com. host.example.com. ( 2024010101 ; serial
        10800 3600 604800 3600 )
@        IN NS   ns1.example.com.
@   300  IN A    192.0.2.1
         IN AAAA 2001:db8::1
www  CNAME @
@  MX 10 mail
mail 3600 IN A 192.0.2.2
@ TXT "v=spf1 mx -all" ; spf
_dmarc TXT "v=DMARC1; p=none"
_sip._tcp SRV 10 5 5060 sip.example.com.
sip A 192.0.2.3
@ CAA 0 issue "letsencrypt.org"
sub NS ns.other.net.
@ DNSKEY 257 3 13 abc
`

func TestParseGood(t *testing.T) {
	r := Parse("example.com", good)
	if len(r.Errors) != 0 {
		t.Fatalf("errors: %v", r.Errors)
	}
	want := map[string]string{
		"example.com/A":             "192.0.2.1",
		"example.com/AAAA":          "2001:db8::1",
		"www.example.com/CNAME":     "example.com.",
		"example.com/MX":            "10 mail.example.com.",
		"example.com/TXT":           `"v=spf1 mx -all"`,
		"_dmarc.example.com/TXT":    `"v=DMARC1; p=none"`,
		"_sip._tcp.example.com/SRV": "10 5 5060 sip.example.com.",
		"example.com/CAA":           `0 issue "letsencrypt.org"`,
		"sub.example.com/NS":        "ns.other.net.",
	}
	got := map[string]RRSet{}
	for _, s := range r.RRSets {
		got[s.Key()] = s
	}
	for k, v := range want {
		if s, ok := got[k]; !ok || len(s.Records) != 1 || s.Records[0] != v {
			t.Errorf("%s = %+v, want %q", k, got[k], v)
		}
	}
	if got["example.com/A"].TTL != 300 || got["example.com/MX"].TTL != 3600 {
		t.Errorf("ttl: %+v", r.RRSets)
	}
	if _, ok := got["example.com/NS"]; ok {
		t.Error("apex NS imported")
	}
	if len(r.Notes) != 3 { // SOA, apex NS, DNSKEY
		t.Errorf("notes: %+v", r.Notes)
	}
	if f := Check("example.com", r.RRSets); HasErrors(f) {
		t.Errorf("findings: %+v", f)
	}
}

func TestParseMalformed(t *testing.T) {
	cases := map[string]string{
		"www A 999.1.1.1":               "invalid_ipv4",
		"www A 192.0.2.1 extra":         "dnsx_bad_rdata",
		"www AAAA 192.0.2.1":            "invalid_ipv6",
		"evil.example.org. A 192.0.2.1": "dnsx_name_outside_zone",
		"$ORIGIN other.com.":            "dnsx_origin_mismatch",
		"$INCLUDE /etc/passwd":          "dnsx_directive_unsupported",
		"$GENERATE 1-10 h$ A 1.1.1.$":   "dnsx_directive_unsupported",
		"www CH A 192.0.2.1":            "dnsx_class_unsupported",
		"www PTR foo":                   "dnsx_type_unsupported",
		"www 10 A 192.0.2.1":            "dnsx_invalid_ttl",
		"www 99999999 A 192.0.2.1":      "dnsx_invalid_ttl",
		"$TTL 5":                        "dnsx_invalid_ttl",
		`www TXT "unterminated`:         "dnsx_unterminated_quote",
		"www MX ten mail":               "dnsx_bad_rdata",
		"www MX 10 bad..name":           "dnsx_bad_target",
		"www CNAME a b":                 "dnsx_bad_rdata",
		"www SRV 1 2 70000 x":           "dnsx_bad_rdata",
		`www CAA 0 evil "x"`:            "dnsx_bad_caa",
		"www A ( 192.0.2.1":             "dnsx_unbalanced_parens",
		"www A 192.0.2.1 )":             "dnsx_unbalanced_parens",
		"  A 192.0.2.1":                 "dnsx_missing_owner",
		"www":                           "dnsx_missing_type",
		"bad_name! A 192.0.2.1":         "dnsx_invalid_name",
		"www CNAME a\x01b":              "dnsx_control_char",
		"www TXT \"" + strings.Repeat("x", 300) + "\"": "dnsx_bad_txt",
	}
	for in, code := range cases {
		r := Parse("example.com", in)
		if len(r.Errors) == 0 || r.Errors[0].Code != code {
			t.Errorf("%q: %+v, want %s", in, r.Errors, code)
		}
		if len(r.Errors) > 0 && r.Errors[0].Line != 1 && code != "dnsx_import_too_large" {
			t.Errorf("%q: line %d", in, r.Errors[0].Line)
		}
	}
	if r := Parse("example.com", strings.Repeat("a", MaxImportBytes+1)); len(r.Errors) == 0 || r.Errors[0].Code != "dnsx_import_too_large" {
		t.Error("size limit")
	}
	if r := Parse("example.com", "a A 1.1.1.1\x00"); len(r.Errors) == 0 {
		t.Error("nul")
	}
	// many errors are capped
	if r := Parse("example.com", strings.Repeat("x PTR y\n", 500)); len(r.Errors) != maxErrors {
		t.Errorf("cap: %d", len(r.Errors))
	}
}

func TestExportRoundTrip(t *testing.T) {
	recs := []rpc.DNSRecord{
		{Name: "example.com", Type: "SOA", TTL: 3600, Content: "ns1.example.com. h.example.com. 1 2 3 4 5"},
		{Name: "example.com", Type: "A", TTL: 3600, Content: "192.0.2.1"},
		{Name: "www.example.com", Type: "CNAME", TTL: 3600, Content: "example.com."},
		{Name: "example.com", Type: "MX", TTL: 3600, Content: "10 mail.example.com."},
		{Name: "mail.example.com", Type: "A", TTL: 3600, Content: "192.0.2.2"},
		{Name: "example.com", Type: "TXT", TTL: 3600, Content: `"v=spf1 mx -all"`},
	}
	txt := Export("example.com", recs, 7)
	r := Parse("example.com", txt)
	if len(r.Errors) != 0 {
		t.Fatalf("%s\n%v", txt, r.Errors)
	}
	cur := Group(recs)
	if d := Diff("example.com", cur, r.RRSets, "replace"); len(d) != 0 {
		t.Errorf("round trip diff: %+v", d)
	}
}

func TestDiffAndChecks(t *testing.T) {
	cur := []RRSet{{Name: "example.com", Type: "A", TTL: 3600, Records: []string{"192.0.2.1"}},
		{Name: "old.example.com", Type: "A", TTL: 3600, Records: []string{"192.0.2.9"}},
		{Name: "example.com", Type: "NS", TTL: 3600, Records: []string{"ns1.example.com."}},
		{Name: "example.com", Type: "SOA", TTL: 3600, Records: []string{"x"}}}
	des := []RRSet{{Name: "example.com", Type: "A", TTL: 300, Records: []string{"192.0.2.1"}},
		{Name: "new.example.com", Type: "A", TTL: 3600, Records: []string{"192.0.2.5"}}}
	if d := Diff("example.com", cur, des, "merge"); len(d) != 2 || d[0].Action != "replace" || d[1].Action != "add" {
		t.Errorf("merge: %+v", d)
	}
	d := Diff("example.com", cur, des, "replace")
	if len(d) != 3 || d[2].Action != "delete" || d[2].Name != "old.example.com" {
		t.Errorf("replace: %+v", d)
	}
	bad := []RRSet{
		{Name: "example.com", Type: "CNAME", TTL: 3600, Records: []string{"x.net."}},
		{Name: "example.com", Type: "MX", TTL: 3600, Records: []string{"10 mx.example.com."}},
		{Name: "mx.example.com", Type: "CNAME", TTL: 30, Records: []string{"y.net."}},
		{Name: "mx.example.com", Type: "TXT", TTL: 3600, Records: []string{`"a"`}},
		{Name: "example.com", Type: "TXT", TTL: 3600, Records: []string{`"v=spf1 -all"`, `"v=spf1 mx -all"`}},
	}
	codes := map[string]bool{}
	for _, f := range Check("example.com", bad) {
		codes[f.Code] = true
	}
	for _, c := range []string{"cname_at_apex", "cname_with_other", "mx_to_cname", "ttl_low", "spf_multiple", "dmarc_missing"} {
		if !codes[c] {
			t.Errorf("missing %s in %v", c, codes)
		}
	}
	if !codes["spf_multiple"] || codes["spf_missing"] {
		t.Error("spf")
	}
}

func TestShowZone(t *testing.T) {
	out := `This is a Native zone
Metadata items: None
Zone has NSEC semantics
keys:
ID = 1 (CSK), flags = 257, tag = 31337, algo = 13, bits = 256	  Active	 Published  ( ECDSAP256SHA256 )
CSK DNSKEY = example.com. IN DNSKEY 257 3 13 abcd ; ( ECDSAP256SHA256 )
DS = example.com. IN DS 31337 13 2 deadbeef ; ( SHA256 digest )
DS = example.com. IN DS 31337 13 4 cafe ; ( SHA-384 digest )
`
	i := ParseShowZone(out)
	if !i.Secured || len(i.DS) != 2 || i.DS[0] != "example.com. IN DS 31337 13 2 deadbeef" || len(i.DNSKEY) != 1 {
		t.Errorf("%+v", i)
	}
	if ParseShowZone("Zone is not actively secured\n").Secured {
		t.Error("unsecured")
	}
}

func TestLists(t *testing.T) {
	for _, n := range []string{"news", "team-a", "a.b_c"} {
		if ListName(n) != nil {
			t.Errorf("%s rejected", n)
		}
	}
	for _, n := range []string{"", "-x", "a/b", "../x", "postmaster", "A", "a+b", "x.", "a..b"} {
		if ListName(n) == nil {
			t.Errorf("%q accepted", n)
		}
	}
	if _, err := ListDir("/var/spool/mlmmj", "../etc", "x"); err == nil {
		t.Error("traversal")
	}
	if p, _ := ListDir("/var/spool/mlmmj", "example.com", "news"); p != "/var/spool/mlmmj/example.com/news" {
		t.Error(p)
	}
	m := TransportMap([]ListRef{{"b.com", "z"}, {"a.com", "news"}})
	if !strings.Contains(m, "news@a.com mlmmj:a.com/news\nz@b.com mlmmj:b.com/z\n") {
		t.Error(m)
	}
}
