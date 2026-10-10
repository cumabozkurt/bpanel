package installer

// Pure configuration generators. Everything the installer writes is rendered
// here from explicit inputs so that tests (and `bpanel-installer render`) can
// produce the exact files and check them with the real tools (nginx -t,
// apache2ctl configtest, php-fpm -t, postfix check, sshd -t, fail2ban-client -t,
// logrotate -d, systemd-analyze verify/security).

import (
	"fmt"
	"github.com/cumabozkurt/bpanel/internal/agent"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cumabozkurt/bpanel/internal/distro"
)

// ---------------------------------------------------------------- nginx ----

// NginxHTTPDirectives are the http-level settings the panel wants. Each one is
// only emitted when the stock configuration does not already set it, because
// nginx refuses duplicate directives ("gzip" directive is duplicate) and
// Ubuntu's nginx.conf already contains `gzip on;` (SYS-1).
var NginxHTTPDirectives = []struct{ Name, Line string }{
	{"server_tokens", "server_tokens off;"},
	{"client_max_body_size", "client_max_body_size 256m;"},
	{"server_names_hash_bucket_size", "server_names_hash_bucket_size 128;"},
	{"gzip", "gzip on;"},
	{"gzip_vary", "gzip_vary on;"},
	{"gzip_types", "gzip_types text/css application/javascript application/json image/svg+xml text/plain application/xml;"},
}

var nginxComment = regexp.MustCompile(`(?m)#.*$`)

// nginxDirectives returns the set of directive names used anywhere in conf
// (comments removed). Context is ignored on purpose: a directive the stock
// file sets at any level is left to the stock file.
func nginxDirectives(conf string) map[string]bool {
	out := map[string]bool{}
	conf = nginxComment.ReplaceAllString(conf, "")
	for _, stmt := range strings.FieldsFunc(conf, func(r rune) bool { return r == ';' || r == '{' || r == '}' }) {
		f := strings.Fields(stmt)
		if len(f) > 0 {
			out[f[0]] = true
		}
	}
	return out
}

// NginxVersion parses the output of `nginx -v` ("nginx version: nginx/1.24.0").
func NginxVersion(out string) (major, minor, patch int, ok bool) {
	m := regexp.MustCompile(`nginx/(\d+)\.(\d+)\.(\d+)`).FindStringSubmatch(out)
	if m == nil {
		return 0, 0, 0, false
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	c, _ := strconv.Atoi(m[3])
	return a, b, c, true
}

// NginxHTTP2On reports whether nginx understands the `http2 on;` directive
// (1.25.1+). Older builds (Ubuntu 24.04 ships 1.24.0) only know
// `listen ... ssl http2`, and 1.25.1+ warns that that form is deprecated.
func NginxHTTP2On(versionOutput string) bool {
	a, b, c, ok := NginxVersion(versionOutput)
	if !ok {
		return false
	}
	return a > 1 || (a == 1 && (b > 25 || (b == 25 && c >= 1)))
}

// NginxBaseOpts are the inputs of the main panel snippet (conf.d/bpanel.conf).
type NginxBaseOpts struct {
	Hostname  string
	VhostsDir string
	Stock     string // concatenated nginx.conf + other conf.d/*.conf
}

// NginxBase renders /etc/nginx/conf.d/bpanel.conf.
func NginxBase(o NginxBaseOpts) string {
	have := nginxDirectives(o.Stock)
	var b strings.Builder
	b.WriteString("# Managed by BOZKURT PANEL\n")
	for _, d := range NginxHTTPDirectives {
		if have[d.Name] {
			fmt.Fprintf(&b, "# %s: set by the distribution configuration\n", d.Name)
			continue
		}
		b.WriteString(d.Line + "\n")
	}
	fmt.Fprintf(&b, `log_format bpanel '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"';

# Hostname / catch-all: answers ACME challenges for the panel certificate.
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name %[1]s _;
    location ^~ /.well-known/acme-challenge/ { root /var/lib/bpanel/acme; default_type text/plain; }
    location / { return 302 https://%[1]s:2083/; }
}

include %[2]s/*.conf;
include /etc/nginx/bpanel-apps.d/*.conf;
`, o.Hostname, o.VhostsDir)
	return b.String()
}

// AppsNginxOpts are the inputs of bpanel-apps.d/apps.conf.
type AppsNginxOpts struct {
	Socket, PMADir, RCDir, Cert, Key string
	Webmail                          bool // full profile: Roundcube on 2095/2096
	HTTP2On                          bool // nginx >= 1.25.1
}

// AppsNginx renders the internal phpMyAdmin server and the webmail servers.
func AppsNginx(o AppsNginxOpts) string {
	s := fmt.Sprintf(`# Managed by BOZKURT PANEL — internal phpMyAdmin (proxied by the user panel on 2083)
server {
    listen 127.0.0.1:2090;
    server_name _;
    location ^~ /3rdparty/phpMyAdmin/ {
        alias %[2]s/;
        index index.php;
        location ~ ^/3rdparty/phpMyAdmin/(libraries|setup|templates|vendor|sql)/ { deny all; }
        location ~ \.php$ {
            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $request_filename;
            fastcgi_param HTTPS on;
            fastcgi_param SERVER_PORT 2083;
            fastcgi_pass unix:%[1]s;
        }
    }
}
`, o.Socket, o.PMADir)
	if !o.Webmail {
		return s
	}
	listen, h2 := "listen 2096 ssl http2;\n    listen [::]:2096 ssl http2;", ""
	if o.HTTP2On {
		listen, h2 = "listen 2096 ssl;\n    listen [::]:2096 ssl;", "\n    http2 on;"
	}
	return s + fmt.Sprintf(`
# Webmail (Roundcube): HTTPS 2096, HTTP 2095 redirects
server {
    listen 2095;
    listen [::]:2095;
    server_name _;
    return 301 https://$host:2096$request_uri;
}
server {
    %[5]s%[6]s
    server_name _;
    ssl_certificate %[3]s;
    ssl_certificate_key %[4]s;
    ssl_protocols TLSv1.2 TLSv1.3;
    root %[2]s;
    index index.php;
    client_max_body_size 64m;
    add_header Strict-Transport-Security "max-age=31536000" always;
    location ~ ^/(config|temp|logs|bin|SQL|installer|vendor)/ { deny all; }
    location ~ /\. { deny all; }
    location ~ \.php$ {
        try_files $uri =404;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param HTTPS on;
        fastcgi_pass unix:%[1]s;
    }
}
`, o.Socket, o.RCDir, o.Cert, o.Key, listen, h2)
}

// --------------------------------------------------------------- apache ----

// ApachePortsDebian replaces /etc/apache2/ports.conf: Apache is only a backend.
const ApachePortsDebian = "# Managed by BOZKURT PANEL: Apache is the backend behind Nginx\nListen 127.0.0.1:8080\n"

// ApacheBase is conf-available/bpanel.conf (Debian) or conf.d/bpanel.conf (RHEL).
func ApacheBase(vhostsDir string) string {
	return `# Managed by BOZKURT PANEL
ServerTokens Prod
ServerSignature Off
<IfModule remoteip_module>
    RemoteIPHeader X-Real-IP
    RemoteIPInternalProxy 127.0.0.1
</IfModule>
IncludeOptional ` + vhostsDir + `/*.conf
`
}

// ApacheListenRHEL rewrites the Listen line of the stock httpd.conf.
func ApacheListenRHEL(httpdConf string) string {
	re := regexp.MustCompile(`(?m)^Listen\s+(?:0\.0\.0\.0:|\[::\]:)?80\s*$`)
	return re.ReplaceAllString(httpdConf, "Listen 127.0.0.1:8080")
}

// ------------------------------------------------------------------ php ----

// PHPPackages returns the packages for one PHP version. It corrects the
// distro list for PHP 8.5+, where OPcache is part of the core and neither
// Sury (php8.5-opcache) nor Remi (php85-php-opcache) ship a separate package,
// so asking for it aborts the whole apt/dnf transaction.
func PHPPackages(l *distro.Layout, v string) []string {
	in := l.PHPPackages(v)
	if !phpAtLeast(v, 8, 5) {
		return in
	}
	out := make([]string, 0, len(in))
	for _, p := range in {
		if strings.HasSuffix(p, "-opcache") {
			continue
		}
		out = append(out, p)
	}
	return out
}

func phpAtLeast(v string, maj, min int) bool {
	a, b, ok := strings.Cut(v, ".")
	if !ok {
		return false
	}
	x, err1 := strconv.Atoi(a)
	y, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return x > maj || (x == maj && y >= min)
}

// PHPFPMDropIn gives every PHP-FPM master its own /tmp, separate from the
// host and from other services. Per-account isolation inside FPM comes from
// the pool's TMPDIR/upload_tmp_dir/session.save_path (= ~/tmp, mode 0700).
const PHPFPMDropIn = `# Managed by BOZKURT PANEL
[Service]
PrivateTmp=yes
Slice=bpanel-php.slice
`

// UnitPHPSlice groups every PHP-FPM master: PHP of all tenants together can
// never starve the panel, SSH or the database (handoff-backend I-4b).
// Per-tenant FPM cgroups would need one FPM master per account (deferred).
const UnitPHPSlice = `# Managed by BOZKURT PANEL
[Unit]
Description=BOZKURT PANEL: PHP-FPM of all hosting accounts
Before=slices.target

[Slice]
CPUWeight=50
IOWeight=50
MemoryHigh=85%
MemoryMax=92%
TasksMax=80%
`

// --------------------------------------------------------------- systemd ---

// ResolvedDropIn frees port 53 for PowerDNS (SYS-2).
const ResolvedDropIn = "# Managed by BOZKURT PANEL: PowerDNS answers on port 53\n[Resolve]\nDNSStubListener=no\n"

// Tmpfiles creates the root-only download cache used instead of /tmp and
// the agent's restic cache (R2-SYS-6: never the path of a file).
const Tmpfiles = "# Managed by BOZKURT PANEL\nd /var/cache/bpanel 0700 root root -\nd /var/cache/bpanel/restic-cache 0700 root root -\n"

// JournaldDropIn caps the journal.
const JournaldDropIn = "[Journal]\nSystemMaxUse=500M\n"

// ------------------------------------------------------------------ ssh ----

// SSHDSnippet jails hosting accounts to SFTP.
const SSHDSnippet = `# Managed by BOZKURT PANEL: hosting accounts get SFTP only, jailed to /home
Match Group bpanel-sftp
    ChrootDirectory /home
    ForceCommand internal-sftp -d /%u
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitTTY no
`

// SSHPortsFrom extracts the ports sshd really listens on, from `sshd -T`
// ("port 22" lines) and, on Ubuntu 24.04 where sshd is socket-activated, from
// `systemctl show -p Listen ssh.socket` ("Listen=[::]:22 (Stream)").
func SSHPortsFrom(sshdT, socketShow string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, l := range strings.Split(sshdT, "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "port" {
			add(f[1])
		}
	}
	for _, m := range regexp.MustCompile(`:(\d+)\s*\(Stream\)`).FindAllStringSubmatch(socketShow, -1) {
		add(m[1])
	}
	if len(out) == 0 {
		out = []string{"22"}
	}
	sort.Slice(out, func(i, j int) bool { a, _ := strconv.Atoi(out[i]); b, _ := strconv.Atoi(out[j]); return a < b })
	return out
}

// -------------------------------------------------------------- postfix ----

// PostfixSettings returns the `postconf -e` settings.
func PostfixSettings(hostname, mapType, mapDir, cert, key string) []string {
	return []string{
		"myhostname=" + hostname,
		// local delivery (root, postmaster) goes through /etc/aliases
		"mydestination=$myhostname, localhost.localdomain, localhost",
		"alias_maps=" + mapType + ":/etc/aliases", "alias_database=" + mapType + ":/etc/aliases",
		"inet_interfaces=all", "inet_protocols=all",
		"virtual_mailbox_domains=" + mapType + ":" + mapDir + "/vdomains",
		"virtual_mailbox_maps=" + mapType + ":" + mapDir + "/vmailbox",
		"virtual_alias_maps=" + mapType + ":" + mapDir + "/valias",
		"virtual_transport=lmtp:unix:private/dovecot-lmtp",
		"smtpd_sasl_type=dovecot", "smtpd_sasl_path=private/auth", "smtpd_sasl_auth_enable=yes",
		"smtpd_tls_cert_file=" + cert, "smtpd_tls_key_file=" + key,
		"smtpd_tls_security_level=may", "smtp_tls_security_level=may", "smtpd_tls_auth_only=yes",
		// ":fail:" forwarders are rejected at RCPT time, before any permit
		// (handoff-backend I-2): the agent writes <mapDir>/vreject
		"smtpd_recipient_restrictions=check_recipient_access " + mapType + ":" + mapDir + "/vreject,permit_mynetworks,permit_sasl_authenticated,reject_unauth_destination",
		"smtpd_milters=inet:127.0.0.1:11332", "non_smtpd_milters=inet:127.0.0.1:11332",
		"milter_default_action=accept", "milter_protocol=6",
		"message_size_limit=52428800", "mailbox_size_limit=0", "recipient_delimiter=+",
		"disable_vrfy_command=yes", "smtpd_helo_required=yes",
	}
}

// AliasesWithRoot returns /etc/aliases with root's mail forwarded to email.
// Existing aliases are kept; only the root line is replaced or added.
func AliasesWithRoot(orig, email string) string { return agent.AliasesWithRoot(orig, email) }

// ------------------------------------------------------------- fail2ban ----

// Fail2banPanelFilter matches the API's failed-login log line in the journal:
//
//	level=WARN msg="auth failure" realm=admin user=bob ip=203.0.113.9 reason="bad credentials"
//
// The API must emit this line (see audit/handoff-installer.md).
const Fail2banPanelFilter = `# Managed by BOZKURT PANEL: failed panel logins (bpanel-api journal)
[INCLUDES]
before = common.conf

[Definition]
# R2-WB-20: anchored on the field order of the API's log line
#   msg="auth failure" realm=<r> user=<u> ip=<ip> ...
# slog quotes any value with a space, '=' or '"' and escapes quotes in it, so
# a crafted username ("x ip=203.0.113.9") stays inside user="..." and can
# never supply the ip field.
failregex = (?:^|\s)msg="auth failure" realm=(?:"(?:[^"\\]|\\.)*"|[^\s"]*) user=(?:"(?:[^"\\]|\\.)*"|[^\s"]*) ip=<HOST>(?:\s|$)
ignoreregex =
journalmatch = _SYSTEMD_UNIT=bpanel-api.service
`

// Fail2banJail renders /etc/fail2ban/jail.d/bpanel.local (panel=false after
// uninstall: SSH and mail jails stay, the panel jail goes).
func Fail2banJail(sshPorts []string, full, panel bool) string {
	s := fmt.Sprintf(`# Managed by BOZKURT PANEL
[DEFAULT]
banaction = nftables-multiport
banaction_allports = nftables-allports
bantime = 1h
findtime = 10m
maxretry = 6
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
backend = systemd
port = %s
journalmatch = _SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service + _COMM=sshd + _COMM=sshd-session
`, strings.Join(sshPorts, ","))
	if panel {
		s += `
[bpanel]
enabled = true
backend = systemd
filter = bpanel
port = 2082,2083,2086,2087,2095,2096
maxretry = 8
`
	}
	if full {
		s += `
[roundcube-auth]
enabled = true
backend = systemd
port = 2095,2096

[dovecot]
enabled = true
backend = systemd
port = pop3,pop3s,imap,imaps,submission,465,sieve

[postfix-sasl]
enabled = true
backend = systemd
filter = postfix[mode=auth]
port = smtp,465,submission,imap,imaps,pop3,pop3s
`
	}
	return s
}

// ------------------------------------------------------------ logrotate ----

// Logrotate renders /etc/logrotate.d/bpanel. /var/log/bpanel is root-owned
// (root:bpanel 0750), so no `su` is needed; domain logs are written by the
// root nginx/Apache masters, which reopen them on USR1 / graceful reload.
func Logrotate(apacheUnit string) string {
	reload := "        [ ! -s /run/nginx.pid ] || kill -USR1 \"$(cat /run/nginx.pid)\" 2>/dev/null || true\n"
	if apacheUnit != "" {
		reload += "        systemctl try-reload-or-restart " + apacheUnit + " >/dev/null 2>&1 || true\n"
	}
	return `# Managed by BOZKURT PANEL
/var/log/bpanel/install.log {
    monthly
    rotate 3
    missingok
    notifempty
    compress
    nocreate
}

/var/log/bpanel/domlogs/*.log {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    create 0640 root bpanel
    postrotate
` + reload + `    endscript
}
`
}

// -------------------------------------------------------------- selinux ----

// FContext is one `semanage fcontext` rule.
type FContext struct{ Type, Spec string }

// SELinuxPlan is everything the installer changes in the SELinux policy on
// AlmaLinux/Rocky (SYS-7). Booleans are recorded with their previous value so
// uninstall can restore them.
type SELinuxPlan struct {
	Booleans  []string
	FContexts []FContext
	Ports     []string // tcp ports labelled http_port_t
	Relabel   []string // restorecon -R targets
}

// SELinux returns the policy changes for a profile.
func SELinux(full, web bool) SELinuxPlan {
	p := SELinuxPlan{
		Booleans: []string{
			"httpd_can_network_connect",    // nginx -> 127.0.0.1:8080 (Apache), :2083 (pma signon)
			"httpd_can_network_connect_db", // PHP -> MariaDB over TCP
			"httpd_enable_homedirs",        // docroots live in /home/<user>
			"httpd_read_user_content",
			"httpd_setrlimit",
		},
		FContexts: []FContext{
			{"httpd_sys_content_t", "/var/lib/bpanel/acme(/.*)?"},
			{"httpd_sys_content_t", "/usr/share/bpanel(/.*)?"},
			{"httpd_sys_rw_content_t", "/var/lib/bpanel/apps(/.*)?"},
			{"httpd_log_t", "/var/log/bpanel/domlogs(/.*)?"},
			{"cert_t", "/etc/bpanel/ssl(/.*)?"},
			{"httpd_user_rw_content_t", "/home/[^/]+/public_html(/.*)?"},
			{"httpd_user_rw_content_t", "/home/[^/]+/tmp(/.*)?"},
		},
		Ports:   []string{"2090", "8080"},
		Relabel: []string{"/var/lib/bpanel", "/usr/share/bpanel", "/var/log/bpanel", "/etc/bpanel/ssl", "/home"},
	}
	if web {
		p.Booleans = append(p.Booleans, "ftpd_full_access") // Pure-FTPd virtual users write into /home/<user>
	}
	if full {
		p.Booleans = append(p.Booleans, "httpd_can_sendmail")
		p.FContexts = append(p.FContexts, FContext{"mail_home_rw_t", "/home/[^/]+/mail(/.*)?"})
		p.Ports = append(p.Ports, "2095", "2096")
	}
	return p
}

// ------------------------------------------------------------- firewall ----

// FirewallPorts lists the TCP ports the ruleset opens for a profile.
func FirewallPorts(sshPorts []string, full, web, panel bool) []string {
	tcp := append([]string{}, sshPorts...)
	tcp = append(tcp, "80", "443")
	if panel {
		tcp = append(tcp, "2082", "2083", "2086", "2087")
	}
	if web {
		tcp = append(tcp, "21", "53", "30000-30100")
	}
	if full {
		// 2095/2096 is Roundcube (served by nginx), so it stays open without the panel too
		tcp = append(tcp, "25", "465", "587", "993", "995", "110", "143", "2095", "2096")
	}
	return tcp
}

// FirewallRules renders the nftables ruleset (exported for tests).
func FirewallRules(sshPorts []string, full, web bool) string {
	return firewallRules(FirewallPorts(sshPorts, full, web, true), web)
}

func firewallRules(tcp []string, web bool) string {
	udp := ""
	if web {
		udp = "        udp dport 53 accept\n"
	}
	return fmt.Sprintf(`#!/usr/sbin/nft -f
# Managed by BOZKURT PANEL
table inet bpanel
delete table inet bpanel
table inet bpanel {
    set blocklist4 { type ipv4_addr; flags interval; }
    set blocklist6 { type ipv6_addr; flags interval; }
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        ct state established,related accept
        ct state invalid drop
        ip saddr @blocklist4 drop
        ip6 saddr @blocklist6 drop
        meta l4proto { icmp, ipv6-icmp } accept
        tcp dport { %s } accept
%s    }
}
`, strings.Join(tcp, ", "), udp)
}

// RequiredPorts are the ports that must be free before a first install.
// Port 53 is not listed when systemd-resolved is the only listener (it is
// handled by turning its stub listener off, SYS-2).
func RequiredPorts(profile string) []int {
	p := []int{80, 443, 2082, 2083, 2086, 2087, 3306}
	if profile != "minimal" {
		p = append(p, 21, 53)
	}
	if profile == "full" {
		p = append(p, 25, 465, 587, 993, 995, 110, 143, 2095, 2096)
	}
	return p
}

// RenderOpts are the inputs of Render.
type RenderOpts struct {
	Profile     string
	Hostname    string
	Email       string
	NginxStock  string // contents of the distribution nginx.conf (+ conf.d)
	NginxHTTP2  bool   // nginx >= 1.25.1
	SSHPorts    []string
	AppsSocket  string
	AliasesOrig string
}

// Render returns every static file the installer writes for a profile,
// keyed by target path (`bpanel-installer render` and the config tests use
// it to check the files with the real tools).
func Render(l *distro.Layout, o RenderOpts) map[string]string {
	full, web := o.Profile == "full", o.Profile != "minimal"
	if len(o.SSHPorts) == 0 {
		o.SSHPorts = []string{"22"}
	}
	if o.AppsSocket == "" {
		o.AppsSocket = "/run/php/bpanel-apps.sock"
		if l.Family == distro.RHEL {
			o.AppsSocket = "/run/php-fpm/bpanel-apps.sock"
		}
	}
	apache := ""
	if web {
		apache = l.ApacheUnit
	}
	ph := l.PHPFor(l.DefaultPHP)
	m := map[string]string{
		"/etc/nginx/conf.d/bpanel.conf":                             NginxBase(NginxBaseOpts{Hostname: o.Hostname, VhostsDir: l.NginxVhosts, Stock: o.NginxStock}),
		"/etc/nginx/bpanel-apps.d/apps.conf":                        AppsNginx(AppsNginxOpts{Socket: o.AppsSocket, PMADir: pmaDir, RCDir: rcDir, Cert: panelCert, Key: panelKey, Webmail: full, HTTP2On: o.NginxHTTP2}),
		ph.PoolDir + "/bpanel-apps.conf":                            AppsPool(o.AppsSocket),
		"/etc/systemd/system/" + ph.Unit + ".service.d/bpanel.conf": PHPFPMDropIn,
		"/etc/systemd/system/bpanel-php.slice":                      UnitPHPSlice,
		"/etc/ssh/sshd_config.d/50-bpanel.conf":                     SSHDSnippet,
		"/etc/bpanel/nftables.conf":                                 FirewallRules(o.SSHPorts, full, web),
		"/etc/fail2ban/jail.d/bpanel.local":                         Fail2banJail(o.SSHPorts, full, true),
		"/etc/fail2ban/filter.d/bpanel.conf":                        Fail2banPanelFilter,
		"/etc/logrotate.d/bpanel":                                   Logrotate(apache),
		"/etc/tmpfiles.d/bpanel.conf":                               Tmpfiles,
		"/etc/systemd/journald.conf.d/50-bpanel.conf":               JournaldDropIn,
		"/etc/systemd/system/bpanel-agent.service":                  UnitAgent,
		"/etc/systemd/system/bpanel-api.service":                    UnitAPI,
		"/etc/systemd/system/bpanel-firewall.service":               UnitFirewall,
	}
	if web {
		m["/etc/systemd/resolved.conf.d/bpanel.conf"] = ResolvedDropIn
		if l.Family == distro.Debian {
			m["/etc/apache2/ports.conf"] = ApachePortsDebian
			m["/etc/apache2/conf-available/bpanel.conf"] = ApacheBase(l.ApacheVhosts)
		} else {
			m["/etc/httpd/conf.d/bpanel.conf"] = ApacheBase(l.ApacheVhosts)
		}
	}
	if full && o.Email != "" {
		m["/etc/aliases"] = AliasesWithRoot(o.AliasesOrig, o.Email)
	}
	return m
}

// PostfixMapType is the lookup table type for a distribution family.
func PostfixMapType(l *distro.Layout) string {
	if l.Family == distro.RHEL {
		return "lmdb"
	}
	return "hash"
}

// -------------------------------------------------------------- dovecot ----

// DovecotVersion24 reports whether `dovecot --version` output is Dovecot
// 2.4 or newer, whose configuration syntax differs from 2.3 (R2-E2E-3).
// Unknown output counts as 2.3 (Ubuntu 24.04 and AlmaLinux 9 ship 2.3).
func DovecotVersion24(versionOutput string) bool {
	f := strings.Fields(versionOutput)
	if len(f) == 0 {
		return false
	}
	var maj, min int
	if n, _ := fmt.Sscanf(f[0], "%d.%d", &maj, &min); n < 2 {
		return false
	}
	return maj > 2 || (maj == 2 && min >= 4)
}

// DovecotConf renders conf.d/99-bpanel.conf: virtual users from a
// passwd-file (written by the agent), Maildir in the mailbox home, LMTP and
// SASL sockets for Postfix, quota and Sieve.
//
// The per-mailbox quota comes from the passwd-file extra field: 2.3 reads
// userdb_quota_rule=*:storage=<N>M, 2.4 reads userdb_quota_storage_size=<N>M
// (2.4 silently ignores quota_rule: verified with doveadm quota get).
// DovecotHomeDir is Dovecot's home inside a mailbox directory (see the
// userdb blocks below and agent.DovecotHomeDir).
const DovecotHomeDir = "bpanel-home"

func DovecotConf(v24 bool, cert, key, passwd, hostname string) string {
	if !v24 {
		return fmt.Sprintf(`# Managed by BOZKURT PANEL (Dovecot 2.3 syntax)
protocols = imap pop3 lmtp
mail_location = maildir:~
first_valid_uid = 1000
ssl = required
ssl_cert = <%[1]s
ssl_key = <%[2]s
ssl_min_protocol = TLSv1.2
auth_mechanisms = plain login
disable_plaintext_auth = yes
mail_plugins = $mail_plugins quota

passdb {
  driver = passwd-file
  args = scheme=SSHA512 username_format=%%u %[3]s
}
userdb {
  driver = passwd-file
  args = username_format=%%u %[3]s
  # The passwd-file home is the Maildir root; Dovecot's own home (duplicate
  # DB, locks) lives in a non-dot subdirectory so Maildir++ never lists it
  # as a folder. mail and sieve are expanded before home is replaced.
  override_fields = mail=maildir:%%{userdb:home} sieve=file:%%{userdb:home}/sieve;active=%%{userdb:home}/dovecot.sieve home=%%{userdb:home}/`+DovecotHomeDir+`
}
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
protocol lmtp {
  mail_plugins = $mail_plugins sieve
  postmaster_address = postmaster@%[4]s
}
protocol imap {
  mail_plugins = $mail_plugins imap_quota
}
plugin {
  quota = maildir:User quota
  sieve = file:~/sieve;active=~/dovecot.sieve
}
`, cert, key, passwd, hostname)
	}
	return fmt.Sprintf(`# Managed by BOZKURT PANEL (Dovecot 2.4 syntax)
protocols = imap pop3 lmtp
mail_driver = maildir
mail_path = %%{home}
# Debian's 10-mail.conf sets mail_home and mail_inbox_path for system
# users; virtual mailboxes keep everything in the passwd-file home.
mail_home =
mail_inbox_path = %%{home}
first_valid_uid = 1000
ssl = required
ssl_server_cert_file = %[1]s
ssl_server_key_file = %[2]s
ssl_min_protocol = TLSv1.2
auth_mechanisms = plain login
auth_allow_cleartext = no
mail_plugins {
  quota = yes
}

passdb passwd-file {
  passwd_file_path = %[3]s
}
userdb passwd-file {
  passwd_file_path = %[3]s
  # The passwd-file home is the Maildir root; Dovecot's own home (duplicate
  # DB, locks) lives in a non-dot subdirectory so Maildir++ never lists it
  # as a folder. The mail and sieve paths keep the original home.
  fields {
    mail_path = %%{userdb:home}
    mail_inbox_path = %%{userdb:home}
    sieve_script/personal/sieve_script_path = %%{userdb:home}/sieve
    sieve_script/personal/sieve_script_active_path = %%{userdb:home}/dovecot.sieve
    home = %%{userdb:home}/`+DovecotHomeDir+`
  }
}
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
protocol lmtp {
  # mailbox names are full addresses (Debian's 20-lmtp.conf strips the domain)
  auth_username_format = %%{user | lower}
  mail_plugins {
    sieve = yes
  }
  postmaster_address = postmaster@%[4]s
}
protocol imap {
  mail_plugins {
    imap_quota = yes
  }
}
quota "User quota" {
  driver = maildir
}
sieve_script personal {
  driver = file
  path = ~/sieve
  active_path = ~/dovecot.sieve
}
`, cert, key, passwd, hostname)
}
