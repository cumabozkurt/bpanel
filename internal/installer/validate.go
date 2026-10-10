package installer

import (
	"fmt"
	"net/mail"
	"strings"
)

// ValidHostname checks an RFC 1123 host name (R2-WB-15): the hostname ends
// up in nginx, Postfix, Dovecot, PowerDNS and certificate configuration, so
// anything else (spaces, ';', '{', newlines, quotes) is refused before a
// single file is written. Single-label names are allowed (with a warning
// later), IP addresses and trailing dots are not.
func ValidHostname(h string) error {
	if h == "" || len(h) > 253 {
		return fmt.Errorf("invalid hostname %q: 1 to 253 characters", h)
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return fmt.Errorf("invalid hostname %q: empty or too long label", h)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("invalid hostname %q: a label cannot start or end with '-'", h)
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("invalid hostname %q: only letters, digits, '-' and '.' are allowed", h)
			}
		}
	}
	allDigits := true
	for _, c := range labels[len(labels)-1] {
		if c < '0' || c > '9' {
			allDigits = false
		}
	}
	if allDigits {
		return fmt.Errorf("invalid hostname %q: an IP address is not a hostname", h)
	}
	return nil
}

// ValidEmail checks the administrator / Let's Encrypt contact address
// (R2-WB-15). It is written to /etc/aliases, api/agent configuration and
// Roundcube, so it must be a single plain addr-spec on one line.
func ValidEmail(e string) error {
	if e == "" {
		return nil // optional
	}
	if len(e) > 254 || strings.ContainsAny(e, "\r\n\t \"'`\\,;:<>()[]{}|$") {
		return fmt.Errorf("invalid email %q", e)
	}
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e || a.Name != "" {
		return fmt.Errorf("invalid email %q", e)
	}
	at := strings.LastIndexByte(e, '@')
	if at < 1 || ValidHostname(e[at+1:]) != nil || !strings.Contains(e[at+1:], ".") {
		return fmt.Errorf("invalid email %q: the domain must be a host name like example.com", e)
	}
	return nil
}

// ValidateOptions checks the operator-supplied values used in generated files.
func ValidateOptions(o Options) error {
	if o.Hostname != "" {
		if err := ValidHostname(o.Hostname); err != nil {
			return err
		}
	}
	if err := ValidEmail(o.Email); err != nil {
		return err
	}
	if o.AdminUser != "" {
		for _, c := range o.AdminUser {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
				return fmt.Errorf("invalid administrator name %q: use a-z, 0-9, '.', '_' and '-'", o.AdminUser)
			}
		}
	}
	for _, v := range o.ExtraPHP {
		if !phpVersionRE.MatchString(v) {
			return fmt.Errorf("invalid PHP version %q (use e.g. 8.2)", v)
		}
	}
	return nil
}
