// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"errors"
	"net"
	"net/netip"
	"strings"
)

// RemoteDBHost validates one allowed remote MySQL host as a user types it
// (single IP, IPv4 CIDR /8../32, or a DNS hostname) and returns its MariaDB
// account-host form: the IP, "net/netmask" for a CIDR (the only subnet form
// MariaDB accepts), or the lower-cased hostname. Wildcards (%, _), loopback
// and unspecified addresses, IPv6 prefixes other than /128 and anything with
// quoting characters are refused.
func RemoteDBHost(in string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(in))
	bad := errors.New("invalid_remote_host")
	if s == "" || len(s) > 60 || strings.ContainsAny(s, "%_'\"`\\ \t\r\n*") {
		return "", bad
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || p != p.Masked() {
			return "", bad
		}
		if p.Addr().Is6() && !p.Addr().Is4In6() {
			if p.Bits() != 128 {
				return "", bad
			}
			return ipHost(p.Addr())
		}
		if p.Bits() < 8 || p.Bits() > 32 {
			return "", bad
		}
		if p.Bits() == 32 {
			return ipHost(p.Addr())
		}
		if p.Addr().IsLoopback() || p.Addr().IsUnspecified() {
			return "", bad
		}
		m := net.CIDRMask(p.Bits(), 32)
		return p.Addr().String() + "/" + net.IP(m).String(), nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return ipHost(a)
	}
	if s == "localhost" || strings.HasSuffix(s, ".localhost") || !strings.Contains(s, ".") {
		return "", bad
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", bad
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", bad
			}
		}
	}
	// an all-numeric last label is a malformed IP, not a hostname
	last := s[strings.LastIndex(s, ".")+1:]
	if strings.Trim(last, "0123456789") == "" {
		return "", bad
	}
	return s, nil
}

func ipHost(a netip.Addr) (string, error) {
	a = a.Unmap()
	if a.IsLoopback() || a.IsUnspecified() || a.Zone() != "" || a.IsMulticast() {
		return "", errors.New("invalid_remote_host")
	}
	return a.String(), nil
}
