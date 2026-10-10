// SPDX-License-Identifier: Apache-2.0

package providers

import "context"

// Builtin is a provider whose state comes from the agent's providers.detect
// probe of the same name (internal/agent/providers.go probeSpecs).
type Builtin struct {
	ID    string
	Name_ string
	K     Kind
	Lic   License
	Caps  []string
	Reqs  []string
}

func (b *Builtin) Name() string           { return b.ID }
func (b *Builtin) Title() string          { return b.Name_ }
func (b *Builtin) Kind() Kind             { return b.K }
func (b *Builtin) License() License       { return b.Lic }
func (b *Builtin) Capabilities() []string { return b.Caps }
func (b *Builtin) Requirements() []string { return b.Reqs }

// Detect maps the agent probe; it never claims success without one.
func (b *Builtin) Detect(ctx context.Context, env *Env) Status {
	if env == nil {
		return FromProbe(nil, errNoAgent)
	}
	p, err := env.Probe(ctx, b.ID)
	st := FromProbe(p, err)
	if b.Lic.Class == CommercialOptional && st.State == NotConfigured {
		// BPANEL keeps no own config for commercial agents: present = installed.
		st.State, st.Reason = Installed, ""
	}
	return st
}

func oss(spdx, url string) License { return License{Class: OpenSource, SPDX: spdx, Upstream: url} }

// Builtins returns the components BPANEL drives directly (fresh values).
// nftables, ClamAV and cgroups register from their own packages.
func Builtins() []Provider {
	linux := []string{"Linux (Debian/Ubuntu or RHEL family)"}
	return []Provider{
		&Builtin{ID: "nginx", Name_: "Nginx", K: WebServer, Lic: oss("BSD-2-Clause", "https://nginx.org"),
			Caps: []string{"vhosts", "tls", "config_test", "reload"}, Reqs: linux},
		&Builtin{ID: "apache", Name_: "Apache HTTP Server", K: WebServer, Lic: oss("Apache-2.0", "https://httpd.apache.org"),
			Caps: []string{"vhosts", "htaccess", "config_test", "reload"}, Reqs: linux},
		&Builtin{ID: "php-fpm", Name_: "PHP-FPM", K: PHP, Lic: oss("PHP-3.01", "https://www.php.net"),
			Caps: []string{"multi_version", "per_account_pools", "ini_overrides"}, Reqs: linux},
		&Builtin{ID: "mariadb", Name_: "MariaDB", K: Database, Lic: oss("GPL-2.0-only", "https://mariadb.org"),
			Caps: []string{"databases", "users", "grants", "dump"}, Reqs: linux},
		&Builtin{ID: "powerdns", Name_: "PowerDNS Authoritative", K: DNS, Lic: oss("GPL-2.0-only", "https://www.powerdns.com"),
			Caps: []string{"zones", "records", "http_api", "dnssec"}, Reqs: []string{"PowerDNS HTTP API key in agent.json"}},
		&Builtin{ID: "postfix", Name_: "Postfix", K: Mail, Lic: oss("IPL-1.0 OR EPL-2.0", "https://www.postfix.org"),
			Caps: []string{"virtual_domains", "forwarders", "smtp_auth"}, Reqs: linux},
		&Builtin{ID: "dovecot", Name_: "Dovecot", K: Mail, Lic: oss("MIT AND LGPL-2.1-only", "https://www.dovecot.org"),
			Caps: []string{"imap", "pop3", "quota", "sasl"}, Reqs: linux},
		&Builtin{ID: "rspamd", Name_: "Rspamd", K: Mail, Lic: oss("Apache-2.0", "https://rspamd.com"),
			Caps: []string{"spam_filter", "dkim_signing"}, Reqs: linux},
		&Builtin{ID: "fail2ban", Name_: "Fail2ban", K: Firewall, Lic: oss("GPL-2.0-or-later", "https://github.com/fail2ban/fail2ban"),
			Caps: []string{"brute_force_bans", "jail_status"}, Reqs: linux},
		&Builtin{ID: "restic", Name_: "restic", K: Backup, Lic: oss("BSD-2-Clause", "https://restic.net"),
			Caps: []string{"snapshots", "restore", "encryption", "dedup"}, Reqs: []string{"Backup repository configured"}},
		&Builtin{ID: "lego", Name_: "lego (ACME)", K: Certificate,
			Lic:  License{Class: OpenSource, SPDX: "MIT", Upstream: "https://go-acme.github.io/lego/", Bundled: true},
			Caps: []string{"acme_http01", "acme_dns01", "auto_renew"}, Reqs: []string{"Public DNS pointing at this server"}},
		&Builtin{ID: "imunify360", Name_: "Imunify360", K: MalwareScanner,
			Lic:  License{Class: CommercialOptional, SPDX: "proprietary", Upstream: "https://www.imunify360.com"},
			Caps: []string{"detect"}, Reqs: []string{"Separate Imunify360 license from CloudLinux"}},
		&Builtin{ID: "monarx", Name_: "Monarx", K: MalwareScanner,
			Lic:  License{Class: CommercialOptional, SPDX: "proprietary", Upstream: "https://www.monarx.com"},
			Caps: []string{"detect"}, Reqs: []string{"Separate Monarx license"}},
	}
}

func init() {
	for _, p := range Builtins() {
		Register(p)
	}
}
