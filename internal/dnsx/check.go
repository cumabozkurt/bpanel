// SPDX-License-Identifier: Apache-2.0

package dnsx

import (
	"errors"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Finding is one consistency-check result. Level: error (apply refused
// unless forced), warn, info (hint).
type Finding struct {
	Level string `json:"level"`
	Code  string `json:"code"`
	Name  string `json:"name,omitempty"`
	Type  string `json:"type,omitempty"`
}

func inZone(zone, t string) (string, bool) {
	h := strings.TrimSuffix(t, ".")
	return h, h == zone || strings.HasSuffix(h, "."+zone)
}

// Check runs the zone consistency checks on a full set of rrsets.
func Check(zone string, sets []RRSet) []Finding {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	out := []Finding{}
	add := func(level, code, name, typ string) {
		out = append(out, Finding{Level: level, Code: code, Name: name, Type: typ})
	}
	types := map[string]map[string]RRSet{}
	for _, s := range sets {
		if types[s.Name] == nil {
			types[s.Name] = map[string]RRSet{}
		}
		types[s.Name][s.Type] = s
	}
	for _, s := range sets {
		switch s.Type {
		case "CNAME":
			if s.Name == zone {
				add("error", "cname_at_apex", s.Name, s.Type)
			}
			if len(s.Records) > 1 {
				add("error", "cname_multiple", s.Name, s.Type)
			}
			for t := range types[s.Name] {
				if t != "CNAME" && t != "RRSIG" && t != "NSEC" && t != "NSEC3" {
					add("error", "cname_with_other", s.Name, t)
				}
			}
			for _, c := range s.Records {
				if h, ok := inZone(zone, c); ok && h == s.Name {
					add("error", "cname_loop", s.Name, s.Type)
				}
			}
		case "MX":
			for _, c := range s.Records {
				f := strings.Fields(c)
				if len(f) != 2 || f[1] == "." {
					continue
				}
				if h, ok := inZone(zone, f[1]); ok {
					if _, cn := types[h]["CNAME"]; cn {
						add("error", "mx_to_cname", s.Name, s.Type)
					} else if types[h]["A"].Name == "" && types[h]["AAAA"].Name == "" {
						add("warn", "mx_target_missing", s.Name, s.Type)
					}
				}
			}
		case "NS":
			if s.Name != zone {
				for _, c := range s.Records {
					if h, ok := inZone(zone, c); ok {
						if _, cn := types[h]["CNAME"]; cn {
							add("error", "ns_to_cname", s.Name, s.Type)
						}
					}
				}
			}
		case "TXT":
			if s.Name == zone {
				n := 0
				for _, c := range s.Records {
					if strings.HasPrefix(strings.ToLower(strings.Trim(c, `"`)), "v=spf1") {
						n++
					}
				}
				if n > 1 {
					add("error", "spf_multiple", s.Name, s.Type)
				}
			}
		}
		if s.Type != "SOA" {
			if s.TTL > 0 && s.TTL < 300 {
				add("warn", "ttl_low", s.Name, s.Type)
			} else if s.TTL > 86400 {
				add("warn", "ttl_high", s.Name, s.Type)
			}
		}
	}
	// below a delegation (sub NS) nothing else may live except glue
	for name, ts := range types {
		if _, ok := ts["NS"]; ok && name != zone {
			for other := range types {
				if strings.HasSuffix(other, "."+name) {
					for t := range types[other] {
						if t != "A" && t != "AAAA" {
							add("warn", "below_delegation", other, t)
						}
					}
				}
			}
			for t := range ts {
				if t != "NS" && t != "DS" && t != "A" && t != "AAAA" {
					add("warn", "delegation_with_other", name, t)
				}
			}
		}
	}
	if _, mx := types[zone]["MX"]; mx {
		spf := false
		for _, c := range types[zone]["TXT"].Records {
			spf = spf || strings.HasPrefix(strings.ToLower(strings.Trim(c, `"`)), "v=spf1")
		}
		if !spf {
			add("info", "spf_missing", zone, "TXT")
		}
		dm := false
		for _, c := range types["_dmarc."+zone]["TXT"].Records {
			dm = dm || strings.HasPrefix(strings.ToLower(strings.Trim(c, `"`)), "v=dmarc1")
		}
		if !dm {
			add("info", "dmarc_missing", "_dmarc."+zone, "TXT")
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		lv := map[string]int{"error": 0, "warn": 1, "info": 2}
		if lv[out[i].Level] != lv[out[j].Level] {
			return lv[out[i].Level] < lv[out[j].Level]
		}
		return out[i].Name+out[i].Type+out[i].Code < out[j].Name+out[j].Type+out[j].Code
	})
	// dedupe
	var dd []Finding
	seen := map[Finding]bool{}
	for _, f := range out {
		if !seen[f] {
			seen[f] = true
			dd = append(dd, f)
		}
	}
	if dd == nil {
		dd = []Finding{}
	}
	return dd
}

// HasErrors reports an error-level finding.
func HasErrors(fs []Finding) bool {
	for _, f := range fs {
		if f.Level == "error" {
			return true
		}
	}
	return false
}

// Change is one rrset-level change of an import.
type Change struct {
	Action string `json:"action"` // add | replace | delete
	Name   string `json:"name"`
	Type   string `json:"type"`
	Before *RRSet `json:"before,omitempty"`
	After  *RRSet `json:"after,omitempty"`
}

// Protected reports rrsets an import never deletes: SOA, the apex NS and
// anything outside ImportTypes (DNSSEC records).
func Protected(zone string, s RRSet) bool {
	return s.Type == "SOA" || !ImportTypes[s.Type] || (s.Type == "NS" && s.Name == zone)
}

// Diff computes the changes that make current look like desired. mode
// "merge" only adds/replaces the imported sets; "replace" also deletes the
// unprotected sets the import does not carry.
func Diff(zone string, current, desired []RRSet, mode string) []Change {
	cur := map[string]RRSet{}
	for _, s := range current {
		cur[s.Key()] = s
	}
	out := []Change{}
	want := map[string]bool{}
	for _, d := range desired {
		d := d
		want[d.Key()] = true
		c, ok := cur[d.Key()]
		switch {
		case !ok:
			out = append(out, Change{Action: "add", Name: d.Name, Type: d.Type, After: &d})
		case !c.Equal(d):
			c := c
			out = append(out, Change{Action: "replace", Name: d.Name, Type: d.Type, Before: &c, After: &d})
		}
	}
	if mode == "replace" {
		for _, c := range current {
			c := c
			if !want[c.Key()] && !Protected(zone, c) {
				out = append(out, Change{Action: "delete", Name: c.Name, Type: c.Type, Before: &c})
			}
		}
	}
	return out
}

// Apply returns current with the given rrset replaced (after == nil deletes).
func Apply(current []RRSet, name, typ string, after *RRSet) []RRSet {
	var out []RRSet
	for _, s := range current {
		if s.Name == name && s.Type == typ {
			continue
		}
		out = append(out, s)
	}
	if after != nil && len(after.Records) > 0 {
		out = append(out, *after)
	}
	return out
}

// Find returns the rrset name/type of sets (nil = absent).
func Find(sets []RRSet, name, typ string) *RRSet {
	for _, s := range sets {
		if s.Name == name && s.Type == typ {
			s := s
			return &s
		}
	}
	return nil
}

// ---- DNSSEC (pdnsutil output) ---------------------------------------------

// DNSSECInfo is what pdnsutil show-zone tells about a zone.
type DNSSECInfo struct {
	Secured bool     `json:"secured"`
	DS      []string `json:"ds"`
	DNSKEY  []string `json:"dnskey"`
	Keys    []string `json:"keys"`
}

// ParseShowZone parses `pdnsutil show-zone ZONE`.
func ParseShowZone(out string) DNSSECInfo {
	info := DNSSECInfo{DS: []string{}, DNSKEY: []string{}, Keys: []string{}}
	notSecured := strings.Contains(out, "not actively secured")
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "DS = "):
			v := strings.TrimSpace(strings.TrimPrefix(l, "DS = "))
			if i := strings.Index(v, ";"); i > 0 {
				v = strings.TrimSpace(v[:i])
			}
			info.DS = append(info.DS, v)
		case strings.Contains(l, "DNSKEY = "):
			v := l[strings.Index(l, "DNSKEY = ")+9:]
			if i := strings.Index(v, ";"); i > 0 {
				v = strings.TrimSpace(v[:i])
			}
			info.DNSKEY = append(info.DNSKEY, v)
		case strings.HasPrefix(l, "ID = "):
			info.Keys = append(info.Keys, l)
		}
	}
	info.Secured = !notSecured && (len(info.Keys) > 0 || len(info.DS) > 0)
	return info
}

// ---- mlmmj mailing lists --------------------------------------------------

var reListName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,47}$`)

var reservedLists = map[string]bool{"postmaster": true, "abuse": true, "root": true, "mailer-daemon": true, "hostmaster": true,
	"webmaster": true, "noreply": true, "no-reply": true, "admin": true, "security": true}

// ListName validates a list's local part.
func ListName(s string) error {
	if !reListName.MatchString(s) || strings.Contains(s, "..") || strings.HasSuffix(s, ".") || reservedLists[s] {
		return errors.New("dnsx_invalid_list_name")
	}
	return nil
}

// ListDir is the mlmmj list directory <spool>/<domain>/<name>.
func ListDir(spool, domain, name string) (string, error) {
	if err := ListName(name); err != nil {
		return "", err
	}
	if domain == "" || strings.ContainsAny(domain, "/\\ ") || strings.HasPrefix(domain, ".") || strings.Contains(domain, "..") {
		return "", errors.New("invalid_domain")
	}
	p := filepath.Join(spool, domain, name)
	if !strings.HasPrefix(p, filepath.Clean(spool)+"/") {
		return "", errors.New("invalid_domain")
	}
	return p, nil
}

// ListRef is one list in the transport map.
type ListRef struct{ Domain, Name string }

// TransportMap renders the Postfix transport map for the lists:
//
//	name@domain  mlmmj:domain/name
//
// master.cf carries "mlmmj unix - n n - - pipe flags=ORhu user=mlmmj
// argv=/usr/bin/mlmmj-receive -F -L /var/spool/mlmmj/$nexthop".
// list+command@ addresses resolve through recipient_delimiter=+.
func TransportMap(lists []ListRef) string {
	sort.Slice(lists, func(i, j int) bool {
		return lists[i].Domain+"/"+lists[i].Name < lists[j].Domain+"/"+lists[j].Name
	})
	var b strings.Builder
	b.WriteString("# Managed by BOZKURT PANEL (mailing lists, mlmmj). Do not edit.\n")
	for _, l := range lists {
		b.WriteString(l.Name + "@" + l.Domain + " mlmmj:" + l.Domain + "/" + l.Name + "\n")
	}
	return b.String()
}
