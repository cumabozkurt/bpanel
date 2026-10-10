package validate

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// MaxDomain is the longest domain name (RFC 1035, without the trailing dot).
const MaxDomain = 253

// MaxDocRootSegment is the longest single docroot path segment (rePathSeg).
const MaxDocRootSegment = 128

// NormalizeDomain turns user input into the stored form of a domain name:
// trimmed, lower-case, one trailing dot (FQDN form) removed, IDN converted
// to punycode. It refuses schemes and paths ("http://x.com", "x.com/a")
// instead of silently stripping them, and labels with symbols or emoji,
// which are not valid IDNA2008 (registries refuse them) although the UTS-46
// mapping alone accepts them (R2-UX-11). Errors: too_long, invalid_idn,
// invalid_domain, public_suffix.
func NormalizeDomain(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	if s == "" || strings.ContainsAny(s, "/:@?# \t") {
		return "", errors.New("invalid_domain")
	}
	if len(s) > 4*MaxDomain {
		return "", errors.New("too_long")
	}
	ascii := s
	if !isASCII(s) || strings.Contains(s, "xn--") {
		a, err := idna.Registration.ToASCII(s)
		if err != nil {
			return "", errors.New("invalid_domain")
		}
		u, err := idna.Registration.ToUnicode(a)
		if err != nil {
			return "", errors.New("invalid_domain")
		}
		for _, label := range strings.Split(u, ".") {
			if isASCII(label) {
				continue
			}
			for _, r := range label {
				if !(unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.In(r, unicode.Mn, unicode.Mc) || r == '-') {
					return "", errors.New("invalid_idn")
				}
			}
		}
		ascii = a
	}
	if len(ascii) > MaxDomain {
		return "", errors.New("too_long")
	}
	if err := Domain(ascii); err != nil {
		return "", err
	}
	if IsPublicSuffix(ascii) {
		return "", errors.New("public_suffix")
	}
	return ascii, nil
}

// IsPublicSuffix reports whether name is itself a public suffix ("com",
// "com.tr", "github.io"), which no tenant may own (R2-WB-4): owning
// "com.tr" would make an account the parent of every *.com.tr domain.
func IsPublicSuffix(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return false
	}
	ps, icann := publicsuffix.PublicSuffix(name)
	if ps != name {
		return false
	}
	// For names not on the list PublicSuffix returns the last label with
	// icann=false ("*" rule): a bare unknown TLD. A multi-label name with
	// no explicit rule is an ordinary domain.
	return icann || !strings.Contains(name, ".") || isListedPrivate(name)
}

// isListedPrivate reports a PRIVATE-section rule ("github.io"): EffectiveTLDPlusOne
// of such a name fails because the name is the suffix itself.
func isListedPrivate(name string) bool {
	_, err := publicsuffix.EffectiveTLDPlusOne(name)
	return err != nil
}

// NormalizeLabel is NormalizeDomain for one label (subdomain names, DNS
// record labels): IDN labels become punycode.
func NormalizeLabel(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || strings.Contains(s, ".") {
		return "", errors.New("invalid_label")
	}
	if !isASCII(s) {
		a, err := idna.Registration.ToASCII(s)
		if err != nil {
			return "", errors.New("invalid_label")
		}
		for _, r := range s {
			if !(unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.In(r, unicode.Mn, unicode.Mc) || r == '-') {
				return "", errors.New("invalid_idn")
			}
		}
		s = a
	}
	if err := Label(s); err != nil {
		return "", err
	}
	return s, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// DefaultDocRoot derives the document root of a new addon domain or
// subdomain from its name. Names longer than one docroot segment (a valid
// 253-character domain) get a shortened, still unique directory name
// instead of failing with invalid_docroot (R2-UX-12).
func DefaultDocRoot(domain string) string {
	if len(domain) <= MaxDocRootSegment {
		return domain
	}
	h := uint32(2166136261)
	for i := 0; i < len(domain); i++ {
		h ^= uint32(domain[i])
		h *= 16777619
	}
	return strings.TrimRight(domain[:100], ".-") + "-" + fmt.Sprintf("%08x", h)
}
