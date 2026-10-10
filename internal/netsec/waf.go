// SPDX-License-Identifier: Apache-2.0

package netsec

// v0.4 network security, part B: WAF management for the web server BPANEL
// already runs (nginx + libmodsecurity v3 connector, or Apache mod_security2).
// BPANEL does NOT link a WAF engine (Coraza is not a dependency); it renders
// ModSecurity-compatible per-domain includes that load the OWASP CRS from the
// distribution package. Coraza accepts the same SecLang directives.

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// WAF modes.
const (
	WAFAudit = "audit" // SecRuleEngine DetectionOnly (default)
	WAFBlock = "block" // SecRuleEngine On
	WAFOff   = "off"   // SecRuleEngine Off
)

// MaxWAFExclusions bounds the exclusion list per domain.
const MaxWAFExclusions = 256

var reWAFDomain = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// WAFConfig is the per-domain WAF state.
type WAFConfig struct {
	Domain     string `json:"domain"`
	Mode       string `json:"mode"`
	Exclusions []int  `json:"exclusions"` // rule IDs removed with SecRuleRemoveById
}

// WAFPaths are the files a WAF config needs on the host.
type WAFPaths struct {
	// ModSecConf is the engine base config (recommended settings).
	ModSecConf string `json:"modsec_conf"`
	// CRSSetup is crs-setup.conf; CRSRules is a glob of the CRS rule files.
	CRSSetup string `json:"crs_setup"`
	CRSRules string `json:"crs_rules"`
}

// ValidWAFMode reports whether m is audit|block|off.
func ValidWAFMode(m string) bool { return m == WAFAudit || m == WAFBlock || m == WAFOff }

// ValidWAFDomain reports whether d is a plain lowercase-able host name (no
// path characters; it becomes a file name).
func ValidWAFDomain(d string) bool { return len(d) <= 253 && reWAFDomain.MatchString(d) }

// ParseWAFExclusions validates exclusion IDs given as strings: numeric only,
// 1..9999999, deduplicated and sorted.
func ParseWAFExclusions(in []string) ([]int, error) {
	if len(in) > MaxWAFExclusions {
		return nil, errc("waf_invalid", "at most %d exclusions", MaxWAFExclusions)
	}
	seen := map[int]bool{}
	out := []int{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return nil, errc("waf_invalid", "exclusion %q: rule IDs are numeric only", s)
			}
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 9999999 {
			return nil, errc("waf_invalid", "exclusion %q: rule ID out of range", s)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out, nil
}

// Normalize validates c in place.
func (c *WAFConfig) Normalize() error {
	c.Domain = strings.ToLower(strings.TrimSpace(c.Domain))
	if !ValidWAFDomain(c.Domain) {
		return errc("waf_invalid", "invalid domain")
	}
	if c.Mode == "" {
		c.Mode = WAFAudit
	}
	if !ValidWAFMode(c.Mode) {
		return errc("waf_invalid", "mode must be audit, block or off")
	}
	ss := make([]string, len(c.Exclusions))
	for i, n := range c.Exclusions {
		ss[i] = strconv.Itoa(n)
	}
	ex, err := ParseWAFExclusions(ss)
	if err != nil {
		return err
	}
	c.Exclusions = ex
	return nil
}

func engine(mode string) string {
	switch mode {
	case WAFBlock:
		return "On"
	case WAFOff:
		return "Off"
	}
	return "DetectionOnly"
}

// RenderModSec renders the per-domain ModSecurity rules file.
func RenderModSec(c WAFConfig, p WAFPaths, version int64) (string, error) {
	if err := c.Normalize(); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by BOZKURT PANEL — WAF for %s (version %d). Do not edit.\n", c.Domain, version)
	if c.Mode != WAFOff {
		if p.ModSecConf != "" {
			fmt.Fprintf(&b, "Include %s\n", p.ModSecConf)
		}
	}
	fmt.Fprintf(&b, "SecRuleEngine %s\n", engine(c.Mode))
	if c.Mode != WAFOff {
		b.WriteString("SecAuditEngine RelevantOnly\n")
		if p.CRSSetup != "" {
			fmt.Fprintf(&b, "Include %s\n", p.CRSSetup)
		}
		if p.CRSRules != "" {
			fmt.Fprintf(&b, "Include %s\n", p.CRSRules)
		}
		for _, id := range c.Exclusions {
			fmt.Fprintf(&b, "SecRuleRemoveById %d\n", id)
		}
	}
	return b.String(), nil
}

// RenderNginxSnippet is the server-level nginx include for a domain.
func RenderNginxSnippet(domain, rulesFile string, mode string) string {
	if mode == WAFOff {
		return "# Managed by BOZKURT PANEL — WAF off for " + domain + "\nmodsecurity off;\n"
	}
	return fmt.Sprintf("# Managed by BOZKURT PANEL — WAF for %s\nmodsecurity on;\nmodsecurity_rules_file %s;\n", domain, rulesFile)
}

// RenderApacheSnippet is the VirtualHost-level Apache include for a domain.
func RenderApacheSnippet(domain, rulesFile string, mode string) string {
	if mode == WAFOff {
		return "# Managed by BOZKURT PANEL — WAF off for " + domain + "\n<IfModule security2_module>\n    SecRuleEngine Off\n</IfModule>\n"
	}
	return fmt.Sprintf("# Managed by BOZKURT PANEL — WAF for %s\n<IfModule security2_module>\n    Include %s\n</IfModule>\n", domain, rulesFile)
}
