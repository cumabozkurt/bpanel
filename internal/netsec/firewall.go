// SPDX-License-Identifier: Apache-2.0

// Package netsec models BPANEL's host firewall (v0.4 network security, part A)
// and renders it as a complete nftables script for ONE dedicated table,
// `inet bpanel`. The script never flushes the ruleset and never references
// another table, so firewalld/ufw/docker tables stay untouched.
//
// The base chain has policy accept: BPANEL adds allow/deny/rate-limit
// decisions on top of whatever else the host runs. Before any drop it always
// accepts established/related traffic, loopback, and the SSH + panel ports
// from the administrator's current IP (lockout guard).
package netsec

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Table is the only nftables table BPANEL ever writes.
const (
	TableFamily = "inet"
	TableName   = "bpanel"
)

// Rule actions, families, sources.
const (
	ActionAllow     = "allow"
	ActionDeny      = "deny"
	ActionRateLimit = "ratelimit"

	FamilyIP   = "ip"
	FamilyIP6  = "ip6"
	FamilyInet = "inet"

	SourceManual = "manual"
	SourceAuto   = "auto"
)

// Rule is one firewall rule. A rule without ports goes into an allow/deny
// set (interval + timeout flags, so ExpiresAt becomes an element timeout);
// a rule with ports becomes a chain statement.
type Rule struct {
	ID         int64     `json:"id,omitempty"`
	Action     string    `json:"action"`
	Family     string    `json:"family,omitempty"` // derived from CIDR when empty
	CIDR       string    `json:"cidr,omitempty"`   // empty only for ratelimit (= any source)
	Proto      string    `json:"proto,omitempty"`  // tcp|udp, default tcp when ports are set
	Ports      []int     `json:"ports,omitempty"`
	RatePerMin int       `json:"rate_per_min,omitempty"` // ratelimit only
	Comment    string    `json:"comment,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"` // temporary rule; zero = permanent
	Source     string    `json:"source,omitempty"`     // manual|auto
}

// Ruleset is everything Render needs.
type Ruleset struct {
	Rules      []Rule `json:"rules"`
	SSHPort    int    `json:"ssh_port"`
	PanelPorts []int  `json:"panel_ports"`
	// AdminIP is the administrator's current address (from the API request).
	// It is always accepted on SSH + panel ports before any drop.
	AdminIP string `json:"admin_ip"`
	// SSHRatePerMin limits NEW connections per source to SSH and panel
	// ports; 0 = DefaultSSHRate, negative = no rate limit.
	SSHRatePerMin int `json:"ssh_rate_per_min,omitempty"`
}

// DefaultSSHRate is the per-source new-connection rate for SSH/panel ports.
const DefaultSSHRate = 30

// Limits.
const (
	MaxRules   = 4096
	MaxPorts   = 32
	maxComment = 64
	MaxTimeout = 30 * 24 * time.Hour
	MinTimeout = time.Second
)

// Error is a validation failure with a machine code.
type Error struct{ Code, Msg string }

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func errc(code, f string, a ...any) error { return &Error{Code: code, Msg: fmt.Sprintf(f, a...)} }

// ErrLockout is returned when a ruleset would cut the admin off.
const CodeLockout = "fw_lockout"

var commentRe = regexp.MustCompile(`^[A-Za-z0-9 ._:@/-]*$`)

// ParseCIDR accepts "1.2.3.4", "1.2.3.0/24", "2001:db8::1", "2001:db8::/32"
// and returns the masked prefix (host bits cleared, IPv4-mapped unmapped).
func ParseCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, errc("fw_bad_cidr", "empty address")
	}
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, errc("fw_bad_cidr", "invalid address %q", s)
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, errc("fw_bad_cidr", "invalid prefix %q", s)
	}
	if p.Addr().Is4In6() {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}

// fmtPrefix prints a host prefix as a bare address (nft style).
func fmtPrefix(p netip.Prefix) string {
	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String()
	}
	return p.String()
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

// Normalize validates one rule and fills derived fields.
func (r *Rule) Normalize() error {
	switch r.Action {
	case ActionAllow, ActionDeny, ActionRateLimit:
	default:
		return errc("fw_bad_action", "action must be allow, deny or ratelimit")
	}
	if r.Source == "" {
		r.Source = SourceManual
	}
	if r.Source != SourceManual && r.Source != SourceAuto {
		return errc("fw_bad_source", "source must be manual or auto")
	}
	if len(r.Comment) > maxComment || !commentRe.MatchString(r.Comment) {
		return errc("fw_bad_comment", "comment: up to %d chars of letters, digits, space . _ : @ / -", maxComment)
	}
	var fam string
	if r.CIDR != "" {
		p, err := ParseCIDR(r.CIDR)
		if err != nil {
			return err
		}
		r.CIDR = fmtPrefix(p)
		fam = FamilyIP6
		if p.Addr().Is4() {
			fam = FamilyIP
		}
	} else if r.Action != ActionRateLimit {
		return errc("fw_bad_cidr", "cidr is required for %s", r.Action)
	}
	switch r.Family {
	case "":
		if fam == "" {
			fam = FamilyInet
		}
		r.Family = fam
	case FamilyInet:
		if fam != "" {
			r.Family = fam // a concrete address decides
		}
	case FamilyIP, FamilyIP6:
		if fam != "" && fam != r.Family {
			return errc("fw_bad_family", "family %s does not match address %s", r.Family, r.CIDR)
		}
	default:
		return errc("fw_bad_family", "family must be ip, ip6 or inet")
	}
	if len(r.Ports) > MaxPorts {
		return errc("fw_bad_port", "at most %d ports per rule", MaxPorts)
	}
	seen := map[int]bool{}
	ports := r.Ports[:0:0]
	for _, p := range r.Ports {
		if !validPort(p) {
			return errc("fw_bad_port", "port %d out of range", p)
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)
	r.Ports = ports
	switch r.Proto {
	case "":
		if len(r.Ports) > 0 {
			r.Proto = "tcp"
		}
	case "tcp", "udp":
		if len(r.Ports) == 0 {
			return errc("fw_bad_proto", "proto needs ports")
		}
	default:
		return errc("fw_bad_proto", "proto must be tcp or udp")
	}
	if r.Action == ActionRateLimit {
		if len(r.Ports) == 0 {
			return errc("fw_bad_port", "ratelimit needs ports")
		}
		if r.RatePerMin < 1 || r.RatePerMin > 100000 {
			return errc("fw_bad_rate", "rate_per_min must be 1..100000")
		}
	} else if r.RatePerMin != 0 {
		return errc("fw_bad_rate", "rate_per_min is only for ratelimit")
	}
	if !r.ExpiresAt.IsZero() && len(r.Ports) > 0 {
		return errc("fw_bad_expiry", "temporary rules cannot have ports (use a set rule)")
	}
	return nil
}

// Validate normalises the whole ruleset and runs the lockout guard.
func (rs *Ruleset) Validate() error {
	if !validPort(rs.SSHPort) {
		return errc("fw_bad_port", "ssh_port is required")
	}
	if len(rs.PanelPorts) == 0 || len(rs.PanelPorts) > 8 {
		return errc("fw_bad_port", "1..8 panel ports required")
	}
	for _, p := range rs.PanelPorts {
		if !validPort(p) {
			return errc("fw_bad_port", "panel port %d out of range", p)
		}
	}
	a, err := netip.ParseAddr(strings.TrimSpace(rs.AdminIP))
	if err != nil || a.Zone() != "" {
		return errc(CodeLockout, "admin_ip is required so the admin cannot be locked out")
	}
	rs.AdminIP = a.Unmap().String()
	if len(rs.Rules) > MaxRules {
		return errc("fw_too_many", "at most %d rules", MaxRules)
	}
	for i := range rs.Rules {
		if err := rs.Rules[i].Normalize(); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	}
	return rs.LockoutCheck()
}

// guardedPorts are SSH + panel ports, sorted, unique.
func (rs *Ruleset) guardedPorts() []int {
	m := map[int]bool{rs.SSHPort: true}
	for _, p := range rs.PanelPorts {
		m[p] = true
	}
	out := make([]int, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// LockoutCheck refuses a ruleset with a deny or ratelimit rule that matches
// the admin IP on an SSH/panel port. The rendered script accepts the admin
// first anyway; this check makes the operator's intent explicit instead of
// silently overriding it.
func (rs *Ruleset) LockoutCheck() error {
	admin, err := netip.ParseAddr(rs.AdminIP)
	if err != nil {
		return errc(CodeLockout, "admin_ip missing")
	}
	admin = admin.Unmap()
	guard := map[int]bool{}
	for _, p := range rs.guardedPorts() {
		guard[p] = true
	}
	for i, r := range rs.Rules {
		if r.Action == ActionAllow {
			continue
		}
		if r.CIDR != "" {
			p, err := ParseCIDR(r.CIDR)
			if err != nil || !p.Contains(admin) {
				continue
			}
		} else if r.Family == FamilyIP && !admin.Is4() || r.Family == FamilyIP6 && admin.Is4() {
			continue
		}
		hits := len(r.Ports) == 0
		for _, p := range r.Ports {
			if guard[p] && (r.Proto == "" || r.Proto == "tcp") {
				hits = true
			}
		}
		if hits {
			return errc(CodeLockout, "rule %d (%s %s) would block the admin address %s on SSH/panel ports", i, r.Action, r.CIDR, rs.AdminIP)
		}
	}
	return nil
}

// ---- rendering -------------------------------------------------------------

type elem struct {
	p   netip.Prefix
	ttl time.Duration // 0 = permanent
}

func setDecl(b *strings.Builder, name, typ string, elems []elem) {
	fmt.Fprintf(b, "\tset %s {\n\t\ttype %s\n\t\tflags interval,timeout\n", name, typ)
	if len(elems) > 0 {
		parts := make([]string, 0, len(elems))
		for _, e := range elems {
			s := fmtPrefix(e.p)
			if e.ttl > 0 {
				s += " timeout " + strconv.FormatInt(int64(e.ttl/time.Second), 10) + "s"
			}
			parts = append(parts, s)
		}
		fmt.Fprintf(b, "\t\telements = { %s }\n", strings.Join(parts, ", "))
	}
	b.WriteString("\t}\n")
}

func meterDecl(b *strings.Builder, name, typ string) {
	fmt.Fprintf(b, "\tset %s {\n\t\ttype %s\n\t\tsize 65535\n\t\tflags dynamic,timeout\n\t\ttimeout 1m\n\t}\n", name, typ)
}

func portList(ps []int) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = strconv.Itoa(p)
	}
	if len(s) == 1 {
		return s[0]
	}
	return "{ " + strings.Join(s, ", ") + " }"
}

func saddr(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "ip saddr " + fmtPrefix(p)
	}
	return "ip6 saddr " + fmtPrefix(p)
}

func comment(c string) string {
	if c == "" {
		return ""
	}
	return ` comment "` + c + `"`
}

// checkOverlap refuses overlapping prefixes in one interval set (the kernel
// would reject them; auto-merge does not work with per-element timeouts).
func checkOverlap(set string, es []elem) error {
	sort.Slice(es, func(i, j int) bool { return es[i].p.Addr().Less(es[j].p.Addr()) })
	for i := 0; i < len(es); i++ {
		for j := i + 1; j < len(es); j++ {
			if es[i].p.Overlaps(es[j].p) {
				return errc("fw_overlap", "%s: %s overlaps %s", set, fmtPrefix(es[i].p), fmtPrefix(es[j].p))
			}
		}
	}
	return nil
}

// Render validates rs and returns the complete nftables script for table
// inet bpanel. Rules whose ExpiresAt is not after now are dropped.
// The script first creates (no-op if present) and deletes the table, then
// re-creates it, so `nft -f` replaces exactly this table atomically.
func Render(rs Ruleset, now time.Time) (string, error) {
	if err := rs.Validate(); err != nil {
		return "", err
	}
	sets := map[string][]elem{}
	var allowStmts, denyStmts, rlStmts []string
	var rlMeters []string
	for i, r := range rs.Rules {
		var ttl time.Duration
		if !r.ExpiresAt.IsZero() {
			ttl = r.ExpiresAt.Sub(now).Truncate(time.Second)
			if ttl < MinTimeout {
				continue // expired
			}
			if ttl > MaxTimeout {
				return "", errc("fw_bad_expiry", "rule %d expires more than 30 days ahead", i)
			}
		}
		var p netip.Prefix
		if r.CIDR != "" {
			p, _ = ParseCIDR(r.CIDR)
		}
		switch {
		case r.Action == ActionRateLimit:
			match := r.Proto + " dport " + portList(r.Ports) + " ct state new"
			pre := ""
			if r.CIDR != "" {
				pre = saddr(p) + " "
			}
			for _, v := range []struct{ fam, typ, key string }{{"4", "ipv4_addr", "ip saddr"}, {"6", "ipv6_addr", "ip6 saddr"}} {
				if r.CIDR != "" && (p.Addr().Is4() != (v.fam == "4")) || r.Family == FamilyIP && v.fam == "6" || r.Family == FamilyIP6 && v.fam == "4" {
					continue
				}
				m := fmt.Sprintf("rl_r%d_%s", i, v.fam)
				rlMeters = append(rlMeters, m+" "+v.typ)
				rlStmts = append(rlStmts, fmt.Sprintf("%s%s add @%s { %s limit rate over %d/minute } drop%s", pre, match, m, v.key, r.RatePerMin, comment(r.Comment)))
			}
		case len(r.Ports) > 0:
			verdict := "accept"
			if r.Action == ActionDeny {
				verdict = "drop"
			}
			st := fmt.Sprintf("%s %s dport %s %s%s", saddr(p), r.Proto, portList(r.Ports), verdict, comment(r.Comment))
			if r.Action == ActionAllow {
				allowStmts = append(allowStmts, st)
			} else {
				denyStmts = append(denyStmts, st)
			}
		default:
			name := r.Action + "4"
			if !p.Addr().Is4() {
				name = r.Action + "6"
			}
			sets[name] = append(sets[name], elem{p, ttl})
		}
	}
	for n, es := range sets {
		if err := checkOverlap(n, es); err != nil {
			return "", err
		}
	}
	admin, _ := netip.ParseAddr(rs.AdminIP)
	adminP := netip.PrefixFrom(admin, admin.BitLen())
	guard := portList(rs.guardedPorts())

	var b strings.Builder
	b.WriteString("# Generated by BPANEL - only table inet bpanel is managed here.\n")
	b.WriteString("table inet bpanel {}\ndelete table inet bpanel\n")
	b.WriteString("table inet bpanel {\n")
	setDecl(&b, "allow4", "ipv4_addr", sets["allow4"])
	setDecl(&b, "allow6", "ipv6_addr", sets["allow6"])
	setDecl(&b, "deny4", "ipv4_addr", sets["deny4"])
	setDecl(&b, "deny6", "ipv6_addr", sets["deny6"])
	setDecl(&b, "block4", "ipv4_addr", nil) // temporary blocks (netsec.fw.block)
	setDecl(&b, "block6", "ipv6_addr", nil)
	rate := rs.SSHRatePerMin
	if rate == 0 {
		rate = DefaultSSHRate
	}
	if rate > 0 {
		meterDecl(&b, "rl_guard4", "ipv4_addr")
		meterDecl(&b, "rl_guard6", "ipv6_addr")
	}
	for _, m := range rlMeters {
		f := strings.Fields(m)
		meterDecl(&b, f[0], f[1])
	}
	b.WriteString("\tchain input {\n\t\ttype filter hook input priority 0; policy accept;\n")
	b.WriteString("\t\tct state established,related accept\n")
	b.WriteString("\t\tiif \"lo\" accept\n")
	fmt.Fprintf(&b, "\t\t%s tcp dport %s accept comment \"bpanel admin guard\"\n", saddr(adminP), guard)
	b.WriteString("\t\tip saddr @allow4 accept\n\t\tip6 saddr @allow6 accept\n")
	for _, s := range allowStmts {
		b.WriteString("\t\t" + s + "\n")
	}
	b.WriteString("\t\tip saddr @deny4 drop\n\t\tip6 saddr @deny6 drop\n")
	b.WriteString("\t\tip saddr @block4 drop\n\t\tip6 saddr @block6 drop\n")
	for _, s := range denyStmts {
		b.WriteString("\t\t" + s + "\n")
	}
	if rate > 0 {
		fmt.Fprintf(&b, "\t\ttcp dport %s ct state new jump guard_rl\n", guard)
	}
	for _, s := range rlStmts {
		b.WriteString("\t\t" + s + "\n")
	}
	b.WriteString("\t}\n")
	if rate > 0 {
		b.WriteString("\tchain guard_rl {\n")
		fmt.Fprintf(&b, "\t\tadd @rl_guard4 { ip saddr limit rate over %d/minute burst 10 packets } drop\n", rate)
		fmt.Fprintf(&b, "\t\tadd @rl_guard6 { ip6 saddr limit rate over %d/minute burst 10 packets } drop\n", rate)
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String(), nil
}

// EmptyScript removes table inet bpanel (rollback target when no table existed).
const EmptyScript = "table inet bpanel {}\ndelete table inet bpanel\n"

// RestoreScript turns a `nft list table inet bpanel` snapshot back into a
// script that replaces the current table with the snapshot.
func RestoreScript(snapshot string) string {
	s := strings.TrimSpace(snapshot)
	if s == "" {
		return EmptyScript
	}
	return EmptyScript + s + "\n"
}

var (
	tableRef  = regexp.MustCompile(`(?m)^\s*(?:add\s+|delete\s+|flush\s+)?table\s+(\S+)\s+(\S+)`)
	forbidden = regexp.MustCompile(`(?mi)\b(flush\s+ruleset|include\s+)`)
)

// SyntaxCheck is the Go-side check used when nft is not installed: balanced
// braces and quotes, no `flush ruleset` / `include`, and every table
// reference is `inet bpanel`. It cannot prove kernel acceptance.
func SyntaxCheck(script string) error {
	depth, inQ := 0, false
	for _, c := range script {
		switch {
		case c == '"':
			inQ = !inQ
		case inQ:
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth < 0 {
				return errc("fw_syntax", "unbalanced }")
			}
		}
	}
	if depth != 0 || inQ {
		return errc("fw_syntax", "unbalanced braces or quotes")
	}
	if forbidden.MatchString(script) {
		return errc("fw_syntax", "flush ruleset / include are not allowed")
	}
	refs := tableRef.FindAllStringSubmatch(script, -1)
	if len(refs) == 0 {
		return errc("fw_syntax", "no table inet bpanel")
	}
	for _, m := range refs {
		if m[1] != TableFamily || strings.TrimSuffix(m[2], "{") != TableName {
			return errc("fw_syntax", "foreign table %s %s", m[1], m[2])
		}
	}
	return nil
}

// ---- temporary blocks -----------------------------------------------------

// Block is a temporary block (set element in block4/block6 with a timeout).
type Block struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason,omitempty"`
	Source    string    `json:"source,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// BlockElement validates a block request and returns the set name and the
// nft element text ("1.2.3.4 timeout 3600s").
func BlockElement(ip string, ttl time.Duration, adminIP string) (set, element string, err error) {
	p, err := ParseCIDR(ip)
	if err != nil {
		return "", "", err
	}
	if ttl < MinTimeout || ttl > MaxTimeout {
		return "", "", errc("fw_bad_expiry", "timeout must be 1s..30d")
	}
	if adminIP != "" {
		if a, e := netip.ParseAddr(adminIP); e == nil && p.Contains(a.Unmap()) {
			return "", "", errc(CodeLockout, "refusing to block the admin address")
		}
	}
	if p.Bits() < 8 && p.Addr().Is4() || p.Bits() < 16 && !p.Addr().Is4() {
		return "", "", errc("fw_bad_cidr", "prefix too wide for a block")
	}
	set = "block4"
	if !p.Addr().Is4() {
		set = "block6"
	}
	return set, fmtPrefix(p) + " timeout " + strconv.FormatInt(int64(ttl/time.Second), 10) + "s", nil
}

// UnblockElement returns the set and element (address only) to delete.
func UnblockElement(ip string) (set, element string, err error) {
	p, err := ParseCIDR(ip)
	if err != nil {
		return "", "", err
	}
	set = "block4"
	if !p.Addr().Is4() {
		set = "block6"
	}
	return set, fmtPrefix(p), nil
}

// SyncBlocks reconciles DB rows with what the kernel set holds:
// toKernel = unexpired DB rows missing from the kernel (re-add after a
// reboot or rollback, with the remaining TTL); expired = DB rows whose time
// passed or that the kernel no longer has although they should have expired
// (delete from DB). Kernel-only elements are returned as orphans.
func SyncBlocks(db []Block, kernel []Block, now time.Time) (toKernel, expired, orphans []Block) {
	k := map[string]bool{}
	for _, b := range kernel {
		k[norm(b.IP)] = true
	}
	d := map[string]bool{}
	for _, b := range db {
		key := norm(b.IP)
		d[key] = true
		switch {
		case !b.ExpiresAt.IsZero() && !b.ExpiresAt.After(now.Add(MinTimeout)):
			expired = append(expired, b)
		case !k[key]:
			toKernel = append(toKernel, b)
		}
	}
	for _, b := range kernel {
		if !d[norm(b.IP)] {
			orphans = append(orphans, b)
		}
	}
	return
}

func norm(ip string) string {
	if p, err := ParseCIDR(ip); err == nil {
		return fmtPrefix(p)
	}
	return ip
}

// IsCode reports whether err carries the netsec code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}
