// SPDX-License-Identifier: Apache-2.0

package netsec

import (
	"strings"
	"testing"
	"time"
)

func base() Ruleset {
	return Ruleset{SSHPort: 22, PanelPorts: []int{8443}, AdminIP: "203.0.113.7"}
}

func TestParseCIDR(t *testing.T) {
	ok := map[string]string{
		"1.2.3.4": "1.2.3.4", "1.2.3.9/24": "1.2.3.0/24", "2001:db8::1": "2001:db8::1",
		"2001:db8::5/32": "2001:db8::/32", "::ffff:10.0.0.1": "10.0.0.1",
	}
	for in, want := range ok {
		p, err := ParseCIDR(in)
		if err != nil || fmtPrefix(p) != want {
			t.Errorf("%s: got %v %v want %s", in, fmtPrefix(p), err, want)
		}
	}
	for _, bad := range []string{"", "1.2.3", "1.2.3.4/33", "fe80::1%eth0", "a;b", "1.2.3.4 }"} {
		if _, err := ParseCIDR(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRenderStructure(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rs := base()
	rs.Rules = []Rule{
		{Action: ActionDeny, CIDR: "198.51.100.0/24", Comment: "scanner"},
		{Action: ActionDeny, CIDR: "2001:db8:bad::/48"},
		{Action: ActionDeny, CIDR: "192.0.2.5", ExpiresAt: now.Add(time.Hour), Source: SourceAuto},
		{Action: ActionDeny, CIDR: "192.0.2.6", ExpiresAt: now.Add(-time.Hour)}, // expired: dropped
		{Action: ActionAllow, CIDR: "10.0.0.0/8"},
		{Action: ActionAllow, CIDR: "192.0.2.0/28", Ports: []int{3306, 3306}},
		{Action: ActionRateLimit, Ports: []int{25}, RatePerMin: 60},
	}
	s, err := Render(rs, now)
	if err != nil {
		t.Fatal(err)
	}
	must := []string{
		"table inet bpanel {}\ndelete table inet bpanel\ntable inet bpanel {",
		"flags interval,timeout",
		"elements = { 192.0.2.5 timeout 3600s, 198.51.100.0/24 }",
		"elements = { 2001:db8:bad::/48 }",
		"elements = { 10.0.0.0/8 }",
		"ip saddr 192.0.2.0/28 tcp dport 3306 accept",
		`ip saddr 203.0.113.7 tcp dport { 22, 8443 } accept comment "bpanel admin guard"`,
		"tcp dport 25 ct state new add @rl_r6_4 { ip saddr limit rate over 60/minute } drop",
		"add @rl_r6_6 { ip6 saddr limit rate over 60/minute } drop",
		"jump guard_rl",
		"rate over 30/minute",
	}
	for _, m := range must {
		if !strings.Contains(s, m) {
			t.Errorf("missing %q in\n%s", m, s)
		}
	}
	if strings.Contains(s, "192.0.2.6") {
		t.Error("expired rule rendered")
	}
	// ordering: established, lo, admin guard before every drop
	iEst := strings.Index(s, "ct state established,related accept")
	iLo := strings.Index(s, `iif "lo" accept`)
	iAdm := strings.Index(s, "bpanel admin guard")
	iDrop := strings.Index(s, " drop")
	if !(iEst > 0 && iEst < iLo && iLo < iAdm && iAdm < iDrop) {
		t.Errorf("safety rules not first: est=%d lo=%d admin=%d drop=%d", iEst, iLo, iAdm, iDrop)
	}
	if err := SyntaxCheck(s); err != nil {
		t.Fatalf("own output fails syntax check: %v", err)
	}
	if strings.Contains(s, "flush ruleset") {
		t.Fatal("must never flush the ruleset")
	}
}

func TestRenderIPv6Admin(t *testing.T) {
	rs := base()
	rs.AdminIP = "2001:db8::42"
	rs.SSHRatePerMin = -1
	s, err := Render(rs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "ip6 saddr 2001:db8::42 tcp dport { 22, 8443 } accept") || strings.Contains(s, "guard_rl") {
		t.Fatal(s)
	}
}

func TestLockoutGuard(t *testing.T) {
	cases := []Rule{
		{Action: ActionDeny, CIDR: "203.0.113.0/24"},
		{Action: ActionDeny, CIDR: "203.0.113.7", Ports: []int{22}},
		{Action: ActionDeny, CIDR: "0.0.0.0/0", Ports: []int{8443}},
		{Action: ActionRateLimit, Ports: []int{22}, RatePerMin: 5},
	}
	for i, r := range cases {
		rs := base()
		rs.Rules = []Rule{r}
		if _, err := Render(rs, time.Now()); !IsCode(err, CodeLockout) {
			t.Errorf("case %d: want lockout, got %v", i, err)
		}
	}
	// deny on an unrelated port / other family is fine
	rs := base()
	rs.Rules = []Rule{{Action: ActionDeny, CIDR: "203.0.113.0/24", Ports: []int{80}}, {Action: ActionDeny, CIDR: "2001:db8::/32"}}
	if _, err := Render(rs, time.Now()); err != nil {
		t.Fatal(err)
	}
	rs = base()
	rs.AdminIP = ""
	if _, err := Render(rs, time.Now()); !IsCode(err, CodeLockout) {
		t.Fatalf("missing admin ip must be refused, got %v", err)
	}
}

func TestValidationErrors(t *testing.T) {
	bad := []Rule{
		{Action: "reject", CIDR: "1.2.3.4"},
		{Action: ActionDeny},
		{Action: ActionDeny, CIDR: "1.2.3.4", Family: FamilyIP6},
		{Action: ActionDeny, CIDR: "1.2.3.4", Ports: []int{0}},
		{Action: ActionDeny, CIDR: "1.2.3.4", Proto: "icmp", Ports: []int{1}},
		{Action: ActionDeny, CIDR: "1.2.3.4", Comment: `x" ; flush ruleset`},
		{Action: ActionRateLimit, Ports: []int{80}},
		{Action: ActionDeny, CIDR: "1.2.3.4", Ports: []int{80}, ExpiresAt: time.Now().Add(time.Hour)},
		{Action: ActionDeny, CIDR: "1.2.3.4", Source: "evil"},
	}
	for i, r := range bad {
		rs := base()
		rs.Rules = []Rule{r}
		if _, err := Render(rs, time.Now()); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	rs := base()
	rs.Rules = []Rule{{Action: ActionDeny, CIDR: "198.51.100.0/24"}, {Action: ActionDeny, CIDR: "198.51.100.9"}}
	if _, err := Render(rs, time.Now()); !IsCode(err, "fw_overlap") {
		t.Fatalf("overlap: %v", err)
	}
}

func TestSyntaxCheckRejectsForeign(t *testing.T) {
	for _, s := range []string{
		"table inet filter { }",
		"table inet bpanel { ",
		"flush ruleset\ntable inet bpanel {}",
		"include \"/etc/x\"\ntable inet bpanel {}",
		"",
	} {
		if SyntaxCheck(s) == nil {
			t.Errorf("accepted %q", s)
		}
	}
	if SyntaxCheck(RestoreScript("table inet bpanel {\n}\n")) != nil || SyntaxCheck(EmptyScript) != nil {
		t.Fatal("restore scripts must pass")
	}
}

func TestBlocks(t *testing.T) {
	set, el, err := BlockElement("192.0.2.50", time.Hour, "203.0.113.7")
	if err != nil || set != "block4" || el != "192.0.2.50 timeout 3600s" {
		t.Fatal(set, el, err)
	}
	set, el, err = BlockElement("2001:db8::/64", time.Minute, "")
	if err != nil || set != "block6" || el != "2001:db8::/64 timeout 60s" {
		t.Fatal(set, el, err)
	}
	if _, _, err := BlockElement("203.0.113.0/24", time.Hour, "203.0.113.7"); !IsCode(err, CodeLockout) {
		t.Fatal("admin block allowed", err)
	}
	for _, c := range []struct {
		ip  string
		ttl time.Duration
	}{{"1.2.3.4", 0}, {"1.2.3.4", 31 * 24 * time.Hour}, {"0.0.0.0/0", time.Hour}, {"x", time.Hour}} {
		if _, _, err := BlockElement(c.ip, c.ttl, ""); err == nil {
			t.Errorf("%v accepted", c)
		}
	}
	now := time.Unix(1_700_000_000, 0)
	db := []Block{{IP: "192.0.2.1", ExpiresAt: now.Add(time.Hour)}, {IP: "192.0.2.2", ExpiresAt: now.Add(-time.Minute)}, {IP: "192.0.2.3/32", ExpiresAt: now.Add(time.Hour)}}
	kernel := []Block{{IP: "192.0.2.3"}, {IP: "192.0.2.99"}}
	add, exp, orph := SyncBlocks(db, kernel, now)
	if len(add) != 1 || add[0].IP != "192.0.2.1" || len(exp) != 1 || exp[0].IP != "192.0.2.2" || len(orph) != 1 || orph[0].IP != "192.0.2.99" {
		t.Fatalf("sync: add=%v exp=%v orph=%v", add, exp, orph)
	}
}

func TestParseSetJSON(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	js := `{"nftables":[{"metainfo":{"version":"1.0.9"}},{"set":{"family":"inet","name":"block4","table":"bpanel","type":"ipv4_addr","flags":["interval","timeout"],
	"elem":["10.0.0.1",{"prefix":{"addr":"10.1.0.0","len":16}},{"elem":{"val":"192.0.2.50","timeout":3600,"expires":3500}},{"elem":{"val":{"prefix":{"addr":"198.51.100.0","len":24}},"timeout":60,"expires":30}}]}}]}`
	bs, err := ParseSetJSON([]byte(js), now)
	if err != nil || len(bs) != 4 {
		t.Fatal(bs, err)
	}
	if bs[1].IP != "10.1.0.0/16" || bs[2].IP != "192.0.2.50" || !bs[2].ExpiresAt.Equal(now.Add(3500*time.Second)) || bs[3].IP != "198.51.100.0/24" {
		t.Fatalf("%+v", bs)
	}
}
