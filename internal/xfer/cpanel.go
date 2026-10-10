// SPDX-License-Identifier: Apache-2.0

package xfer

import (
	"bufio"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// cPanel account backups (cpmove-USER.tar.gz, backup-DATE_USER.tar.gz) are
// parsed from their publicly documented layout only:
//   cp/USER                 KEY=VALUE account file (DNS=, DNSn=, PLAN=, CONTACTEMAIL=)
//   userdata/main           YAML: main_domain, addon_domains, parked_domains, sub_domains
//   userdata/<domain>       YAML: documentroot
//   homedir/                the home directory
//   mysql/<db>.sql          per-database dumps (mysql.sql = grants, not imported)
//   dnszones/<domain>.db    BIND zone files
//   va/<domain>             mail forwarders "local@domain: target, target"
//   etc/<domain>/passwd|shadow|quota   mailboxes, their crypt hashes and quotas
// Nothing is executed; every other part is listed in Unsupported.

var cpTop = regexp.MustCompile(`^(cpmove-[a-z0-9_]+|backup-[0-9._-]+_[a-z0-9_]+)$`)

func isCPanel(s *scan) bool {
	top := ""
	for _, n := range s.names {
		first := n
		if i := strings.IndexByte(n, '/'); i >= 0 {
			first = n[:i]
		}
		if cpTop.MatchString(first) {
			top = first
			break
		}
	}
	s.topDir = top
	pre := ""
	if top != "" {
		pre = top + "/"
	}
	for n := range s.meta {
		if strings.HasPrefix(n, pre+"cp/") || n == pre+"userdata/main" {
			return true
		}
	}
	return false
}

func parseKV(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// parseYAMLish reads the flat YAML of cPanel userdata files: top-level
// scalars, lists ("  - x") and one-level maps ("  k: v").
func parseYAMLish(b []byte) (scalars map[string]string, lists map[string][]string, maps map[string]map[string]string) {
	scalars, lists, maps = map[string]string{}, map[string][]string{}, map[string]map[string]string{}
	cur := ""
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \r")
		if line == "" || line == "---" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		unq := func(s string) string { return strings.Trim(strings.TrimSpace(s), `'"`) }
		if line[0] != ' ' && line[0] != '-' {
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			cur = strings.TrimSpace(k)
			if v = strings.TrimSpace(v); v != "" && v != "{}" && v != "[]" {
				scalars[cur] = unq(v)
			}
			continue
		}
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "- ") {
			lists[cur] = append(lists[cur], unq(t[2:]))
		} else if k, v, ok := strings.Cut(t, ":"); ok && cur != "" {
			if maps[cur] == nil {
				maps[cur] = map[string]string{}
			}
			maps[cur][unq(k)] = unq(v)
		}
	}
	return
}

var domainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

func okDomain(d string) bool { return len(d) <= 253 && domainRe.MatchString(d) }

func analyseCPanel(s *scan) (*Model, error) {
	m := &Model{Format: FormatCPanel, Root: s.topDir, Home: HomeInfo{Prefix: "homedir"}}
	get := func(rel string) []byte { return s.meta[m.Member(rel)] }
	user := ""
	if s.topDir != "" {
		user = s.topDir[strings.LastIndexAny(s.topDir, "-_")+1:]
	}
	var kv map[string]string
	for n, b := range s.meta {
		if strings.HasPrefix(n, m.Member("cp/")) {
			kv = parseKV(b)
			if user == "" {
				user = path.Base(n)
			}
			break
		}
	}
	if kv == nil {
		kv = map[string]string{}
	}
	if u := strings.ToLower(kv["USER"]); u != "" {
		user = u
	}
	m.Account = Account{Username: user, Email: kv["CONTACTEMAIL"], Plan: kv["PLAN"], MainDomain: strings.ToLower(kv["DNS"])}

	seen := map[string]bool{}
	add := func(name, kind string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || seen[name] {
			return
		}
		if !okDomain(name) {
			m.Warnings = append(m.Warnings, "skipped invalid domain "+trunc(name))
			return
		}
		seen[name] = true
		d := Domain{Name: name, Kind: kind}
		if b := get("userdata/" + name); b != nil {
			sc, _, _ := parseYAMLish(b)
			d.DocRoot = sc["documentroot"]
		}
		m.Domains = append(m.Domains, d)
	}
	if b := get("userdata/main"); b != nil {
		sc, ls, mp := parseYAMLish(b)
		if sc["main_domain"] != "" {
			m.Account.MainDomain = strings.ToLower(sc["main_domain"])
		}
		add(m.Account.MainDomain, "main")
		addonSubs := map[string]bool{}
		keys := make([]string, 0, len(mp["addon_domains"]))
		for k, v := range mp["addon_domains"] {
			keys = append(keys, k)
			addonSubs[strings.ToLower(v)] = true
		}
		sort.Strings(keys)
		for _, k := range keys {
			add(k, "addon")
		}
		for _, p := range ls["parked_domains"] {
			add(p, "parked")
		}
		for _, sd := range ls["sub_domains"] {
			if !addonSubs[strings.ToLower(sd)] { // addon helper subdomains are internal
				add(sd, "sub")
			}
		}
	} else {
		add(m.Account.MainDomain, "main")
		for i := 1; i < 1000; i++ {
			v, ok := kv["DNS"+strconv.Itoa(i)]
			if !ok {
				break
			}
			add(v, "addon")
		}
	}

	pre := m.Member("")
	if m.Root != "" {
		pre = m.Root + "/"
	}
	parts := map[string]bool{}
	for _, n := range s.names {
		rel := strings.TrimPrefix(n, pre)
		top, rest, _ := strings.Cut(rel, "/")
		switch top {
		case "mysql":
			if strings.HasSuffix(rest, ".sql") && !strings.Contains(rest, "/") {
				db := strings.TrimSuffix(rest, ".sql")
				if db == "" {
					continue
				}
				m.Databases = append(m.Databases, Database{Name: db, Dump: "mysql/" + rest, Bytes: s.sizes[n]})
			} else if rel == "mysql.sql" {
				parts["mysql.sql"] = true
			}
		case "mysql.sql":
			parts["mysql.sql"] = true
		case "dnszones":
			if strings.HasSuffix(rest, ".db") && !strings.Contains(rest, "/") {
				d := strings.ToLower(strings.TrimSuffix(rest, ".db"))
				if okDomain(d) {
					m.Zones = append(m.Zones, Zone{Domain: d, Member: "dnszones/" + rest, Text: string(s.meta[n])})
				}
			}
		case "va":
			if rest != "" && !strings.Contains(rest, "/") {
				m.Forwarders = append(m.Forwarders, parseVA(strings.ToLower(rest), s.meta[n])...)
			}
		case "etc":
			dom, file, _ := strings.Cut(rest, "/")
			if file == "passwd" && okDomain(dom) {
				m.Mailboxes = append(m.Mailboxes, parseMailboxes(dom, s.meta[n], get("etc/"+dom+"/shadow"), get("etc/"+dom+"/quota"))...)
			}
		case "sslcerts", "sslkeys", "ssl":
			parts["ssl"] = true
		case "cron", "vf", "vfilters", "fp", "proftpdpasswd", "psql", "logs", "bandwidth", "mm", "mma", "suspended", "suspendinfo", "homedir.tar", "pgsql", "apache_tls", "authnames", "ips", "resellerconfig", "resellerfeatures", "resellerpackages", "nobodyfiles", "locale", "sds", "sds2", "shells", "counters", "domainkeys", "httpfiles", "interchange", "meta", "my.cnf", "quota", "shadow", "ssldomain", "team":
			parts[top] = true
		}
	}
	reasons := map[string]string{
		"mysql.sql":     "MySQL users and grants are not imported; database users are re-created on BPanel with new passwords",
		"ssl":           "cPanel certificates are not imported; BPanel issues free Let's Encrypt certificates once DNS points here",
		"cron":          "cron jobs are listed but never imported automatically (they could run arbitrary commands)",
		"vf":            "mail filters (Exim filter syntax) are not converted",
		"vfilters":      "mail filters (Exim filter syntax) are not converted",
		"fp":            "FTP accounts are not imported; re-create them",
		"proftpdpasswd": "FTP accounts are not imported; re-create them",
		"psql":          "PostgreSQL dumps are not imported automatically",
		"pgsql":         "PostgreSQL dumps are not imported automatically",
		"mm":            "Mailman lists are not imported",
		"mma":           "Mailman list archives are not imported",
		"homedir.tar":   "nested homedir.tar (legacy layout) is not extracted; re-export with a current cPanel",
		"domainkeys":    "DKIM keys are not imported; BPanel generates new keys (publish the new DNS record)",
		"team":          "cPanel team users are not imported",
	}
	keys := make([]string, 0, len(parts))
	for k := range parts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r, ok := reasons[k]
		if !ok {
			r = "cPanel-specific data, not used by BPanel"
		}
		m.Unsupported = append(m.Unsupported, ReportItem{Part: k, Reason: r})
	}
	if m.Account.Username == "" || m.Account.MainDomain == "" {
		return nil, errf(ErrFormat, "cPanel archive without account user or main domain")
	}
	homeStats(m, s)
	return m.normalise(), nil
}

func parseVA(domain string, b []byte) []Forwarder {
	var out []Forwarder
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		from, to, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		from = strings.ToLower(strings.TrimSpace(from))
		if from == "*" {
			continue // default address: listed via catch-all is not imported
		}
		if !strings.Contains(from, "@") {
			from += "@" + domain
		}
		var tos []string
		for _, t := range strings.Split(to, ",") {
			t = strings.Trim(strings.TrimSpace(t), `"`)
			// only plain addresses; pipes (|cmd), files (/path) and :fail: are never imported
			if t != "" && strings.Contains(t, "@") && !strings.ContainsAny(t, "|/: \t") {
				tos = append(tos, strings.ToLower(t))
			}
		}
		if len(tos) > 0 {
			out = append(out, Forwarder{From: from, To: tos})
		}
	}
	return out
}

func parseMailboxes(domain string, passwd, shadow, quota []byte) []Mailbox {
	hashes := map[string]string{}
	for _, l := range strings.Split(string(shadow), "\n") {
		f := strings.Split(l, ":")
		if len(f) >= 2 && strings.HasPrefix(f[1], "$") {
			hashes[f[0]] = f[1]
		}
	}
	quotas := map[string]int64{}
	for _, l := range strings.Split(string(quota), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				quotas[k] = n / (1 << 20)
			}
		}
	}
	var out []Mailbox
	for _, l := range strings.Split(string(passwd), "\n") {
		local, _, ok := strings.Cut(l, ":")
		local = strings.ToLower(strings.TrimSpace(local))
		if !ok || local == "" || strings.ContainsAny(local, "@/ ") {
			continue
		}
		h := hashes[local]
		out = append(out, Mailbox{Address: local + "@" + domain, QuotaMB: quotas[local], Hash: h, HasHash: h != ""})
	}
	return out
}

// ---- HestiaCP -----------------------------------------------------------------

func isHestia(s *scan) bool {
	if s.meta["hestia/user.conf"] != nil {
		return true
	}
	for _, n := range s.names {
		if n == "pam/passwd" || strings.HasPrefix(n, "hestia/") || strings.HasPrefix(n, "vesta/") {
			return true
		}
	}
	return false
}

// analyseHestia recognises a HestiaCP backup but does not import it yet:
// its per-domain payloads are nested tar.zst archives (follow-up).
func analyseHestia(s *scan) (*Model, error) {
	return nil, errf(ErrUnsupported, "HestiaCP backups are recognised but not importable yet (planned follow-up)")
}
