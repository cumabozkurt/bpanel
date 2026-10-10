package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cumabozkurt/bpanel/internal/distro"
)

func ubuntu(t *testing.T) *distro.Layout {
	t.Helper()
	l, err := distro.ForRelease(map[string]string{"ID": "ubuntu", "VERSION_ID": "24.04"})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func alma(t *testing.T) *distro.Layout {
	t.Helper()
	l, err := distro.ForRelease(map[string]string{"ID": "almalinux", "VERSION_ID": "9.6"})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// packagedFiles maps packaging/<name> to what the installer writes.
func packagedFiles() map[string]string {
	return map[string]string{
		"systemd/bpanel-agent.service":           UnitAgent,
		"systemd/bpanel-api.service":             UnitAPI,
		"systemd/bpanel-firewall.service":        UnitFirewall,
		"systemd/php-fpm.service.d/bpanel.conf":  PHPFPMDropIn,
		"systemd/bpanel-php.slice":               UnitPHPSlice,
		"systemd/resolved.conf.d/bpanel.conf":    ResolvedDropIn,
		"systemd/journald.conf.d/50-bpanel.conf": JournaldDropIn,
		"tmpfiles.d/bpanel.conf":                 Tmpfiles,
		"logrotate/bpanel":                       Logrotate("apache2"),
		"logrotate/bpanel.minimal":               Logrotate(""),
		"fail2ban/filter.d/bpanel.conf":          Fail2banPanelFilter,
		"fail2ban/jail.d/bpanel.local":           Fail2banJail([]string{"22"}, true, true),
		"apache/ports.conf":                      ApachePortsDebian,
		"apache/bpanel.conf.debian":              ApacheBase("/etc/apache2/bpanel.d"),
		"apache/bpanel.conf.rhel":                ApacheBase("/etc/httpd/bpanel.d"),
		"ssh/50-bpanel.conf":                     SSHDSnippet,
	}
}

// The files shipped in packaging/ must match what the installer writes.
func TestPackagedFilesMatchInstaller(t *testing.T) {
	for name, want := range packagedFiles() {
		b, err := os.ReadFile(filepath.Join("..", "..", "packaging", name))
		if err != nil {
			t.Fatalf("%s: %v (regenerate with BPANEL_WRITE_PACKAGING=1 go test -run TestWritePackaging)", name, err)
		}
		if string(b) != want {
			t.Errorf("packaging/%s differs from the installer's copy", name)
		}
	}
}

func TestRequiredPortsPerProfile(t *testing.T) {
	has := func(l []int, p int) bool {
		for _, x := range l {
			if x == p {
				return true
			}
		}
		return false
	}
	for _, prof := range []string{"minimal", "web", "full"} {
		ports := RequiredPorts(prof)
		if has(ports, 8443) {
			t.Fatal("8443 must not be used")
		}
		for _, p := range []int{80, 443, 2082, 2083, 2086, 2087} {
			if !has(ports, p) {
				t.Errorf("%s: port %d missing", prof, p)
			}
		}
	}
	if has(RequiredPorts("minimal"), 53) || has(RequiredPorts("minimal"), 25) || has(RequiredPorts("minimal"), 2096) {
		t.Error("minimal must not require DNS/mail/webmail ports")
	}
	if !has(RequiredPorts("full"), 2095) || !has(RequiredPorts("full"), 2096) || !has(RequiredPorts("web"), 53) {
		t.Error("full needs 2095/2096, web needs 53")
	}
}

const ubuntuNginx = `user www-data;
worker_processes auto;
http {
	sendfile on;
	# server_tokens off;
	# server_names_hash_bucket_size 64;
	include /etc/nginx/mime.types;
	gzip on;
	# gzip_vary on;
	# gzip_types text/plain text/css application/json;
	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}
`

const almaNginx = `user nginx;
http {
    log_format  main  '$remote_addr';
    sendfile            on;
    include             /etc/nginx/mime.types;
    include /etc/nginx/conf.d/*.conf;
    server {
        listen       80;
        server_name  _;
    }
}
`

// SYS-1: Ubuntu's nginx.conf already has `gzip on;`; repeating it fails nginx -t.
func TestNginxBaseDoesNotDuplicateStockDirectives(t *testing.T) {
	u := NginxBase(NginxBaseOpts{Hostname: "panel.example.com", VhostsDir: "/etc/nginx/bpanel.d", Stock: ubuntuNginx})
	if strings.Contains(u, "\ngzip on;") {
		t.Errorf("gzip duplicated on Ubuntu:\n%s", u)
	}
	for _, want := range []string{"server_tokens off;", "gzip_types ", "gzip_vary on;", "server_names_hash_bucket_size 128;", "client_max_body_size 256m;"} {
		if !strings.Contains(u, want) {
			t.Errorf("Ubuntu: %q missing (only commented out in stock)", want)
		}
	}
	a := NginxBase(NginxBaseOpts{Hostname: "panel.example.com", VhostsDir: "/etc/nginx/bpanel.d", Stock: almaNginx})
	if !strings.Contains(a, "\ngzip on;") {
		t.Error("AlmaLinux stock has no gzip: the panel must enable it")
	}
}

func TestNginxHTTP2(t *testing.T) {
	for out, want := range map[string]bool{
		"nginx version: nginx/1.24.0":                 false, // Ubuntu 24.04
		"nginx version: nginx/1.25.0":                 false,
		"nginx version: nginx/1.25.1":                 true,
		"nginx version: nginx/1.26.3":                 true, // Debian 13, AlmaLinux 9 module
		"nginx version: nginx/2.0.0 (Ubuntu)":         true,
		"garbage":                                     false,
		"nginx version: nginx/1.26.2\nbuilt with ...": true,
	} {
		if got := NginxHTTP2On(out); got != want {
			t.Errorf("%q: got %v want %v", out, got, want)
		}
	}
	on := AppsNginx(AppsNginxOpts{Socket: "/run/s", PMADir: "/p", RCDir: "/r", Cert: "/c", Key: "/k", Webmail: true, HTTP2On: true})
	if strings.Contains(on, "ssl http2") || !strings.Contains(on, "http2 on;") {
		t.Errorf("nginx >= 1.25.1 must use `http2 on;`:\n%s", on)
	}
	off := AppsNginx(AppsNginxOpts{Socket: "/run/s", PMADir: "/p", RCDir: "/r", Cert: "/c", Key: "/k", Webmail: true})
	if strings.Contains(off, "http2 on;") || !strings.Contains(off, "listen 2096 ssl http2;") {
		t.Errorf("nginx 1.24 must use `listen ... ssl http2`:\n%s", off)
	}
	min := AppsNginx(AppsNginxOpts{Socket: "/run/s", PMADir: "/p"})
	if strings.Contains(min, "2096") {
		t.Error("webmail server rendered without the full profile")
	}
	// the deny rule must win over the PHP location (nginx uses the first matching regex)
	if strings.Index(on, "(libraries|setup") > strings.Index(on, `location ~ \.php$`) {
		t.Error("phpMyAdmin deny location must come before the PHP location")
	}
}

func TestPHPPackages(t *testing.T) {
	for _, l := range []*distro.Layout{ubuntu(t), alma(t)} {
		for _, v := range []string{"8.5", "8.6"} {
			for _, p := range PHPPackages(l, v) {
				if strings.HasSuffix(p, "-opcache") {
					t.Errorf("%s PHP %s: %s does not exist (OPcache is built in)", l.Family, v, p)
				}
			}
		}
		found := false
		for _, p := range PHPPackages(l, "8.3") {
			found = found || strings.HasSuffix(p, "-opcache")
		}
		if !found {
			t.Errorf("%s PHP 8.3 must still install opcache", l.Family)
		}
	}
	if got := PHPPackages(ubuntu(t), "8.5"); got[0] != "php8.5-fpm" {
		t.Errorf("unexpected list %v", got)
	}
}

func TestPackageListFail2ban(t *testing.T) {
	join := func(l []string) string { return " " + strings.Join(l, " ") + " " }
	d := join(PackageList(ubuntu(t), "minimal", nil))
	if !strings.Contains(d, " fail2ban ") || !strings.Contains(d, " python3-systemd ") || strings.Contains(d, " apache2 ") {
		t.Errorf("debian minimal: %s", d)
	}
	r := join(PackageList(alma(t), "full", []string{"8.5"}))
	if strings.Contains(r, " fail2ban ") || !strings.Contains(r, " fail2ban-systemd ") || strings.Contains(r, "php85-php-opcache") {
		t.Errorf("rhel full: %s", r)
	}
}

func TestSSHPortsFrom(t *testing.T) {
	got := SSHPortsFrom("port 22\nport 2222\naddressfamily any\n", "Listen=[::]:22 (Stream)\nListen=0.0.0.0:4422 (Stream)\n")
	if strings.Join(got, ",") != "22,2222,4422" {
		t.Errorf("got %v", got)
	}
	if strings.Join(SSHPortsFrom("", ""), ",") != "22" {
		t.Error("default must be 22")
	}
}

func TestAliasesWithRoot(t *testing.T) {
	orig := "# See man 5 aliases for format\npostmaster:    root\nroot: someone@old\n"
	a := AliasesWithRoot(orig, "admin@example.com")
	if strings.Count(a, "root:") != 1 || !strings.Contains(a, "root: admin@example.com") || !strings.Contains(a, "postmaster:    root") {
		t.Errorf("aliases:\n%s", a)
	}
	if AliasesWithRoot(a, "admin@example.com") != a {
		t.Error("not idempotent")
	}
	if !strings.Contains(AliasesWithRoot("", "x@y.z"), "postmaster: root") {
		t.Error("postmaster alias must exist")
	}
}

func TestFail2banJail(t *testing.T) {
	j := Fail2banJail([]string{"22", "2222"}, false, true)
	for _, want := range []string{"[sshd]", "port = 22,2222", "[bpanel]", "sshd-session", "nftables-multiport"} {
		if !strings.Contains(j, want) {
			t.Errorf("%q missing", want)
		}
	}
	if strings.Contains(j, "[dovecot]") {
		t.Error("mail jails without the full profile")
	}
	if strings.Contains(Fail2banJail([]string{"22"}, true, false), "[bpanel]") {
		t.Error("panel jail kept after uninstall")
	}
}

// SYS-3: /var/lib/bpanel is traversable but not listable, and root-owned.
func TestDirs(t *testing.T) {
	m := map[string]Dir{}
	for _, d := range Dirs(ubuntu(t), "full") {
		m[d.Path] = d
	}
	if d := m["/var/lib/bpanel"]; d.Mode != 0o751 || d.Owner != "root:bpanel" {
		t.Errorf("/var/lib/bpanel = %o %s", d.Mode, d.Owner)
	}
	if d := m["/var/lib/bpanel/acme/.well-known/acme-challenge"]; d.Mode&0o005 != 0o005 {
		t.Error("acme challenges must be readable by the web server")
	}
	if d := m["/var/lib/bpanel/apps"]; d.Owner != "bpanel-apps:bpanel-apps" {
		t.Error("apps dir must belong to the apps pool user")
	}
	if d := m["/var/lib/bpanel/db"]; d.Owner != "bpanel:bpanel" || d.Mode != 0o700 {
		t.Error("db dir must be private to the API user")
	}
	if d := m["/var/log/bpanel"]; !strings.HasPrefix(d.Owner, "root:") {
		t.Error("/var/log/bpanel must be root-owned (install.log is written by root)")
	}
	for _, d := range Dirs(ubuntu(t), "minimal") {
		if strings.HasPrefix(d.Path, "/etc/apache2") {
			t.Error("minimal profile must not create Apache directories (SYS-5)")
		}
	}
}

func TestSELinuxPlan(t *testing.T) {
	p := SELinux(true, true)
	specs := map[string]string{}
	for _, f := range p.FContexts {
		specs[f.Spec] = f.Type
	}
	if specs["/var/lib/bpanel/acme(/.*)?"] != "httpd_sys_content_t" || specs["/var/lib/bpanel/apps(/.*)?"] != "httpd_sys_rw_content_t" ||
		specs["/home/[^/]+/mail(/.*)?"] != "mail_home_rw_t" {
		t.Errorf("fcontexts %v", specs)
	}
	joined := strings.Join(p.Booleans, " ")
	for _, b := range []string{"httpd_can_network_connect", "httpd_enable_homedirs", "ftpd_full_access", "httpd_can_sendmail"} {
		if !strings.Contains(joined, b) {
			t.Errorf("boolean %s missing", b)
		}
	}
	if strings.Contains(joined, "httpd_unified") {
		t.Error("httpd_unified is too broad")
	}
	if m := SELinux(false, false); strings.Contains(strings.Join(m.Ports, " "), "2096") {
		t.Error("webmail port labelled on minimal")
	}
}

func TestFirewall(t *testing.T) {
	min := FirewallRules([]string{"22"}, false, false)
	if strings.Contains(min, " 53") || strings.Contains(min, "21,") || strings.Contains(min, "2096") {
		t.Errorf("minimal ruleset opens DNS/FTP/webmail:\n%s", min)
	}
	full := FirewallRules([]string{"22", "2222"}, true, true)
	for _, p := range []string{"2222", "2083", "2087", "2096", "25", "udp dport 53"} {
		if !strings.Contains(full, p) {
			t.Errorf("%s missing", p)
		}
	}
	after := strings.Join(FirewallPorts([]string{"22"}, true, true, false), ",")
	if strings.Contains(after, "2083") || strings.Contains(after, "2087") || !strings.Contains(after, "443") || !strings.Contains(after, "2096") {
		t.Errorf("uninstall ports: %s", after)
	}
}

func TestProcAddr(t *testing.T) {
	for in, want := range map[string]string{
		"3500007F":                         "127.0.0.53",
		"00000000":                         "0.0.0.0",
		"0100007F":                         "127.0.0.1",
		"00000000000000000000000000000000": "::",
		"00000000000000000000000001000000": "::1",
	} {
		if got := procAddr(in); got != want {
			t.Errorf("%s: %s want %s", in, got, want)
		}
	}
}

func TestApacheListenRHEL(t *testing.T) {
	got := ApacheListenRHEL("ServerRoot \"/etc/httpd\"\n#Listen 12.34.56.78:80\nListen 80\nInclude conf.modules.d/*.conf\n")
	if !strings.Contains(got, "\nListen 127.0.0.1:8080\n") || strings.Contains(got, "\nListen 80\n") || !strings.Contains(got, "#Listen 12.34.56.78:80") {
		t.Errorf("got:\n%s", got)
	}
}

func TestRenderProfiles(t *testing.T) {
	for _, prof := range []string{"minimal", "web", "full"} {
		m := Render(ubuntu(t), RenderOpts{Profile: prof, Hostname: "panel.example.com", Email: "a@example.com"})
		_, apache := m["/etc/apache2/ports.conf"]
		if apache != (prof != "minimal") {
			t.Errorf("%s: apache files rendered=%v", prof, apache)
		}
		_, resolved := m["/etc/systemd/resolved.conf.d/bpanel.conf"]
		if resolved != (prof != "minimal") {
			t.Errorf("%s: resolved drop-in rendered=%v", prof, resolved)
		}
		for p, c := range m {
			if !strings.Contains(c, "BOZKURT PANEL") && !strings.HasPrefix(p, "/etc/systemd/journald") && !strings.HasPrefix(p, "/etc/systemd/system/bpanel") {
				t.Errorf("%s has no 'Managed by BOZKURT PANEL' marker", p)
			}
		}
	}
}

func TestAgentUnitHardening(t *testing.T) {
	for _, want := range []string{"CapabilityBoundingSet=", "CAP_SYS_ADMIN", "CAP_CHOWN", "CAP_NET_ADMIN", "ProtectKernelModules=yes",
		"SystemCallFilter=~@clock", "PrivateTmp=yes", "RestrictNamespaces=~user"} {
		if !strings.Contains(UnitAgent, want) {
			t.Errorf("agent unit: %q missing", want)
		}
	}
	for _, never := range []string{"CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_PTRACE", "CAP_SYS_TIME", "CAP_SYS_BOOT", "ProtectSystem=strict", "NoNewPrivileges=yes"} {
		if strings.Contains(UnitAgent, never) {
			t.Errorf("agent unit must not contain %q", never)
		}
	}
}

func TestUninstallKeepsPanelPortsOut(t *testing.T) {
	if strings.Contains(Fail2banJail([]string{"22"}, false, false), "2083") {
		t.Error("panel ports in the post-uninstall jail")
	}
}
