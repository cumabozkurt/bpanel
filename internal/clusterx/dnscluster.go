// SPDX-License-Identifier: Apache-2.0

// Package clusterx holds the pure logic of two v0.4 admin tools: the DNS
// cluster (PowerDNS native primary/secondary replication: AXFR + NOTIFY,
// all free software) and the plugin system (signed, declarative plugins:
// static web assets + webhook subscriptions, no arbitrary root code).
// Everything here is side-effect free apart from the SOA query, so the API,
// the agent and the mock agent share the same validation.
package clusterx

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Error carries a stable API error code (see internal/api/errcodes.go).
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func errf(code, format string, a ...any) error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// MaxSecondaries bounds the also-notify / allow-axfr-ips lists.
const MaxSecondaries = 32

// ValidateSecondaryIP accepts one unicast IPv4/IPv6 address that can be a
// real secondary: loopback, unspecified, multicast, link-local and the IPv4
// broadcast address are rejected (they would either be meaningless or open
// AXFR to the local host). Private ranges are allowed (secondaries often sit
// on a private network). The canonical text form is returned.
func ValidateSecondaryIP(s string) (string, error) {
	s = strings.TrimSpace(s)
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return "", errf("cluster_invalid_ip", "not an IP address: %q", s)
	}
	a = a.Unmap()
	switch {
	case a.IsLoopback(), a.IsUnspecified(), a.IsMulticast(), a.IsInterfaceLocalMulticast(),
		a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
		return "", errf("cluster_invalid_ip", "%s cannot be a secondary nameserver", s)
	case a.Is4() && a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return "", errf("cluster_invalid_ip", "broadcast address")
	}
	return a.String(), nil
}

// NormalizeIPs validates, de-duplicates and sorts a list of secondaries.
func NormalizeIPs(in []string) ([]string, error) {
	if len(in) > MaxSecondaries {
		return nil, errf("cluster_invalid_ip", "at most %d secondaries", MaxSecondaries)
	}
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		ip, err := ValidateSecondaryIP(s)
		if err != nil {
			return nil, err
		}
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	sort.Strings(out)
	return out, nil
}

// RenderPdnsConf renders the include file the agent drops into
// /etc/powerdns/pdns.d/. With no secondaries it returns "" (the file is then
// removed). "primary" is the PowerDNS >= 4.5 name of the old "master" switch.
func RenderPdnsConf(ips []string) (string, error) {
	ips, err := NormalizeIPs(ips)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", nil
	}
	var b strings.Builder
	b.WriteString("# Managed by BPanel (DNS cluster). Do not edit: changes are overwritten.\n")
	b.WriteString("primary=yes\n")
	b.WriteString("allow-axfr-ips=" + strings.Join(ips, ",") + "\n")
	b.WriteString("also-notify=" + strings.Join(ips, ",") + "\n")
	return b.String(), nil
}

// Sync states of one zone on one secondary.
const (
	StateInSync      = "in_sync"
	StateBehind      = "behind"
	StateAhead       = "ahead" // secondary has a newer serial than the primary (misconfiguration)
	StateUnreachable = "unreachable"
	StateMissing     = "missing" // secondary answered but has no SOA for the zone
	StateUnknown     = "unknown" // primary itself could not be read
)

// SerialCompare compares two SOA serials with RFC 1982 serial-number
// arithmetic: -1 if a < b, 0 if equal, 1 if a > b. (Values exactly 2^31
// apart are undefined by the RFC; they are reported as a > b.)
func SerialCompare(a, b uint32) int {
	if a == b {
		return 0
	}
	if (a < b && b-a < 1<<31) || (a > b && a-b > 1<<31) {
		return -1
	}
	return 1
}

// SOAResult is one SOA lookup.
type SOAResult struct {
	Serial uint32
	Found  bool  // the server answered with a SOA for the zone
	Err    error // network / timeout / refused
}

// CompareSOA turns the primary and secondary lookups into a sync state.
func CompareSOA(primary, secondary SOAResult) string {
	switch {
	case primary.Err != nil || !primary.Found:
		return StateUnknown
	case secondary.Err != nil:
		return StateUnreachable
	case !secondary.Found:
		return StateMissing
	}
	switch SerialCompare(secondary.Serial, primary.Serial) {
	case 0:
		return StateInSync
	case -1:
		return StateBehind
	}
	return StateAhead
}

// QuerySOA asks server (ip or ip:port) for the SOA of zone, non-recursive,
// UDP with a TCP retry on truncation, bounded by timeout.
func QuerySOA(ctx context.Context, server, zone string, timeout time.Duration) SOAResult {
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(strings.ToLower(zone)), dns.TypeSOA)
	m.RecursionDesired = false
	c := &dns.Client{Timeout: timeout}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	r, _, err := c.ExchangeContext(cctx, m, server)
	if err == nil && r != nil && r.Truncated {
		c.Net = "tcp"
		r, _, err = c.ExchangeContext(cctx, m, server)
	}
	if err != nil {
		return SOAResult{Err: err}
	}
	if r.Rcode == dns.RcodeRefused || r.Rcode == dns.RcodeServerFailure {
		return SOAResult{}
	}
	for _, rr := range r.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return SOAResult{Serial: soa.Serial, Found: true}
		}
	}
	return SOAResult{}
}
