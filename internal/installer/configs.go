package installer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cumabozkurt/bpanel/internal/agent"
	"github.com/cumabozkurt/bpanel/internal/distro"
)

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on Linux
	}
	return hex.EncodeToString(b)
}

// secretDir holds generated service secrets (root only).
var secretDir = "/etc/bpanel/secrets"

// secret returns a value stored in /etc/bpanel/secrets/<name>, creating it once.
func secret(name string) (string, error) {
	p := filepath.Join(secretDir, name)
	if b, err := os.ReadFile(p); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			return v, nil
		}
	}
	if err := os.MkdirAll(secretDir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(secretDir, 0o700); err != nil {
		return "", err
	}
	v := randHex(24)
	if err := os.WriteFile(p+".new", []byte(v+"\n"), 0o600); err != nil {
		return "", err
	}
	return v, os.Rename(p+".new", p)
}

func (in *Installer) full() bool { return in.O.Profile == "full" }
func (in *Installer) web() bool  { return in.O.Profile != "minimal" }

func (in *Installer) configs(ctx context.Context) error {
	steps := []struct {
		name string
		fn   func(context.Context) error
		when bool
	}{
		{"panel-cert", in.cfgPanelCert, true},
		{"nginx", in.cfgNginx, true},
		{"apache", in.cfgApache, in.web()}, // minimal = nginx-only (SYS-5)
		{"php", in.cfgPHP, true},
		{"mariadb", in.cfgMariaDB, true},
		{"powerdns", in.cfgPowerDNS, in.web()},
		{"postfix", in.cfgPostfix, in.full()},
		{"dovecot", in.cfgDovecot, in.full()},
		{"rspamd", in.cfgRspamd, in.full()},
		{"pure-ftpd", in.cfgPureFTPd, in.web()},
		{"sftp", in.cfgSFTP, true},
		{"apps", in.cfgApps, true},
		{"firewall", in.cfgFirewall, true},
		{"fail2ban", in.cfgFail2ban, true},
		{"v04", in.cfgV04, true}, // v0.4 instx: dirs, bpanel-app@, mlmmj transport, chrony, crowdsec
		{"base-services", in.cfgBaseServices, true},
	}
	for _, s := range steps {
		if !s.when {
			continue
		}
		in.logf("configure %s", s.name)
		if err := s.fn(ctx); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}
	return nil
}

const panelCert = "/etc/bpanel/ssl/panel/fullchain.pem"
const panelKey = "/etc/bpanel/ssl/panel/privkey.pem"

// cfgPanelCert creates a self-signed certificate used until AutoSSL replaces it.
func (in *Installer) cfgPanelCert(ctx context.Context) error {
	dir := filepath.Dir(panelCert)
	if _, err := os.Stat(panelCert); err == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	chain, key, err := agent.SelfSigned([]string{in.O.Hostname})
	if err != nil {
		return err
	}
	if err := os.WriteFile(panelKey, key, 0o640); err != nil {
		return err
	}
	if err := os.WriteFile(panelCert, chain, 0o644); err != nil {
		return err
	}
	return in.sh(ctx, "chown", "root:bpanel", panelKey, panelCert)
}

// nginxStock returns the distribution's nginx configuration (everything the
// panel does not own) so the panel snippet can avoid duplicate directives.
func nginxStock() string {
	var b strings.Builder
	if c, err := os.ReadFile("/etc/nginx/nginx.conf"); err == nil {
		b.Write(c)
	}
	files, _ := filepath.Glob("/etc/nginx/conf.d/*.conf")
	for _, f := range files {
		if filepath.Base(f) == "bpanel.conf" {
			continue
		}
		if c, err := os.ReadFile(f); err == nil {
			b.WriteString("\n")
			b.Write(c)
		}
	}
	return b.String()
}

func (in *Installer) nginxHTTP2On(ctx context.Context) bool {
	out, _ := in.shOut(ctx, nil, "nginx", "-v")
	return NginxHTTP2On(out)
}

func (in *Installer) cfgNginx(ctx context.Context) error {
	if in.L.Family == distro.Debian {
		if err := in.disable("/etc/nginx/sites-enabled/default"); err != nil {
			return err
		}
	} else if b, err := os.ReadFile("/etc/nginx/nginx.conf"); err == nil && strings.Contains(string(b), "listen       80;") {
		// AlmaLinux ships a default server inside nginx.conf; move it off port 80.
		s := strings.ReplaceAll(string(b), "listen       80;", "listen       127.0.0.1:8999;")
		s = strings.ReplaceAll(s, "listen       [::]:80;", "")
		if err := in.writeFile("/etc/nginx/nginx.conf", s, 0o644); err != nil {
			return err
		}
	}
	conf := NginxBase(NginxBaseOpts{Hostname: in.O.Hostname, VhostsDir: in.L.NginxVhosts, Stock: nginxStock()})
	if err := in.writeFile("/etc/nginx/conf.d/bpanel.conf", conf, 0o644); err != nil {
		return err
	}
	if err := os.MkdirAll("/etc/nginx/bpanel-apps.d", 0o755); err != nil {
		return err
	}
	if err := in.sh(ctx, "nginx", "-t"); err != nil {
		return err
	}
	if err := in.systemctl(ctx, "enable", "--now", "nginx"); err != nil {
		return err
	}
	return in.systemctl(ctx, "reload", "nginx")
}

func (in *Installer) cfgApache(ctx context.Context) error {
	if in.L.Family == distro.Debian {
		if err := in.writeFile("/etc/apache2/ports.conf", ApachePortsDebian, 0o644); err != nil {
			return err
		}
		if err := in.writeFile("/etc/apache2/conf-available/bpanel.conf", ApacheBase(in.L.ApacheVhosts), 0o644); err != nil {
			return err
		}
		_ = in.sh(ctx, "a2dissite", "-q", "000-default")
		_ = in.sh(ctx, "a2dismod", "-q", "-f", "mpm_prefork")
		for _, c := range [][]string{
			{"a2enmod", "-q", "mpm_event", "proxy", "proxy_fcgi", "setenvif", "rewrite", "headers", "remoteip", "expires"},
			{"a2enconf", "-q", "bpanel"},
		} {
			if err := in.sh(ctx, c...); err != nil {
				return err
			}
		}
		if err := in.sh(ctx, "apache2ctl", "configtest"); err != nil {
			return err
		}
	} else {
		if b, err := os.ReadFile("/etc/httpd/conf/httpd.conf"); err == nil {
			if err := in.writeFile("/etc/httpd/conf/httpd.conf", ApacheListenRHEL(string(b)), 0o644); err != nil {
				return err
			}
		}
		for _, f := range []string{"/etc/httpd/conf.d/ssl.conf", "/etc/httpd/conf.d/welcome.conf", "/etc/httpd/conf.d/userdir.conf"} {
			if err := in.disable(f); err != nil {
				return err
			}
		}
		if err := in.writeFile("/etc/httpd/conf.d/bpanel.conf", ApacheBase(in.L.ApacheVhosts), 0o644); err != nil {
			return err
		}
		if err := in.sh(ctx, "apachectl", "configtest"); err != nil {
			return err
		}
	}
	return in.systemctl(ctx, "enable", "--now", in.L.ApacheUnit)
}

func (in *Installer) cfgPHP(ctx context.Context) error {
	versions := appendUnique([]string{in.L.DefaultPHP}, in.O.ExtraPHP...)
	for _, v := range versions {
		ph := in.L.PHPFor(v)
		if _, err := os.Stat(ph.Binary); err != nil {
			in.warn("PHP " + v + " is not installed; skipped")
			continue
		}
		if err := agent.EnsurePHPBase(in.L, v); err != nil {
			return err
		}
		if err := in.sh(ctx, ph.Binary, "-t"); err != nil {
			return err
		}
		// Each FPM master gets a private /tmp (accounts use ~/tmp via the pool)
		// and runs in bpanel-php.slice.
		if err := in.writeFile("/etc/systemd/system/bpanel-php.slice", UnitPHPSlice, 0o644); err != nil {
			return err
		}
		if err := in.writeFile("/etc/systemd/system/"+ph.Unit+".service.d/bpanel.conf", PHPFPMDropIn, 0o644); err != nil {
			return err
		}
		if err := in.systemctl(ctx, "daemon-reload"); err != nil {
			return err
		}
		if err := in.systemctl(ctx, "enable", ph.Unit); err != nil {
			return err
		}
		if err := in.systemctl(ctx, "restart", ph.Unit); err != nil {
			return err
		}
	}
	return nil
}

func (in *Installer) cfgMariaDB(ctx context.Context) error {
	path := "/etc/my.cnf.d/bpanel.cnf"
	if in.L.Family == distro.Debian {
		path = "/etc/mysql/mariadb.conf.d/99-bpanel.cnf"
	}
	si := memMB()
	pool := 128
	if si > 3000 {
		pool = si / 4
	} else if si > 1500 {
		pool = 256
	}
	if err := in.writeFile(path, fmt.Sprintf(`# Managed by BOZKURT PANEL
[mysqld]
bind-address = 127.0.0.1
# No skip-name-resolve (R2-SYS-15): MariaDB only listens on loopback, so the
# only lookup is 127.0.0.1 -> localhost from /etc/hosts, and accounts created
# as 'user'@'localhost' work over TCP (host 127.0.0.1) as well as the socket.
max_connections = 200
innodb_buffer_pool_size = %dM
innodb_file_per_table = 1
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
`, pool), 0o644); err != nil {
		return err
	}
	if err := in.systemctl(ctx, "enable", in.L.MariaDBUnit); err != nil {
		return err
	}
	return in.systemctl(ctx, "restart", in.L.MariaDBUnit)
}

func memMB() int {
	b, _ := os.ReadFile("/proc/meminfo")
	var kb int
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "MemTotal:") {
			if _, err := fmt.Sscanf(strings.TrimPrefix(l, "MemTotal:"), "%d", &kb); err != nil {
				return 0
			}
		}
	}
	return kb / 1024
}

func (in *Installer) pdnsConfDir() string {
	if in.L.Family == distro.Debian {
		return "/etc/powerdns"
	}
	return "/etc/pdns"
}

const resolvConf = "/etc/resolv.conf"
const resolvedUpstream = "/run/systemd/resolve/resolv.conf"

// freePort53 turns off the systemd-resolved stub listener (127.0.0.53:53 and
// 127.0.0.54:53) so PowerDNS can bind port 53, and points /etc/resolv.conf at
// resolved's upstream list, because the stub file would name a listener that
// no longer exists (SYS-2). The previous resolv.conf is recorded for uninstall.
func (in *Installer) freePort53(ctx context.Context) error {
	if _, err := os.Stat("/run/systemd/resolve"); err != nil {
		return nil // systemd-resolved is not running
	}
	if err := in.writeFile("/etc/systemd/resolved.conf.d/bpanel.conf", ResolvedDropIn, 0o644); err != nil {
		return err
	}
	if _, ok := in.S.Prev["resolv.conf"]; !ok {
		if fi, err := os.Lstat(resolvConf); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				t, err := os.Readlink(resolvConf)
				if err != nil {
					return err
				}
				if t != resolvedUpstream {
					in.S.Prev["resolv.conf"] = "link:" + t
				}
			} else if b, err := os.ReadFile(resolvConf); err == nil && strings.Contains(string(b), "127.0.0.53") {
				in.S.Prev["resolv.conf"] = "file"
				if err := in.disable(resolvConf); err != nil {
					return err
				}
			}
		}
		in.save()
	}
	if err := in.systemctl(ctx, "restart", "systemd-resolved"); err != nil {
		return err
	}
	if _, ok := in.S.Prev["resolv.conf"]; ok {
		if _, err := os.Stat(resolvedUpstream); err == nil {
			tmp := resolvConf + ".bpanel-new"
			_ = os.Remove(tmp)
			if err := os.Symlink(resolvedUpstream, tmp); err != nil {
				return err
			}
			if err := os.Rename(tmp, resolvConf); err != nil {
				return err
			}
		}
	}
	if in.O.NoSystemd {
		return nil
	}
	return waitFor(ctx, func() bool { return len(stubListeners()) == 0 }, 15*time.Second)
}

func (in *Installer) cfgPowerDNS(ctx context.Context) error {
	if err := in.freePort53(ctx); err != nil {
		return fmt.Errorf("systemd-resolved stub listener: %w", err)
	}
	db := "/var/lib/powerdns/pdns.sqlite3"
	if err := os.MkdirAll(filepath.Dir(db), 0o750); err != nil {
		return err
	}
	if _, err := os.Stat(db); os.IsNotExist(err) {
		schemas, _ := filepath.Glob("/usr/share/doc/pdns-backend-sqlite*/schema.sqlite3.sql")
		more, _ := filepath.Glob("/usr/share/doc/pdns*/schema.sqlite3.sql")
		schemas = append(schemas, more...)
		if len(schemas) == 0 {
			return fmt.Errorf("PowerDNS sqlite schema not found")
		}
		sql, err := os.ReadFile(schemas[0])
		if err != nil {
			return err
		}
		if _, err := in.shOut(ctx, sql, "sqlite3", db+".new"); err != nil {
			return err
		}
		if err := os.Rename(db+".new", db); err != nil {
			return err
		}
	}
	if err := in.sh(ctx, "chown", "-R", "pdns:pdns", filepath.Dir(db)); err != nil {
		return err
	}
	key, err := secret("pdns-api-key")
	if err != nil {
		return err
	}
	ns := "ns1." + parentDomain(in.O.Hostname)
	conf := fmt.Sprintf(`# Managed by BOZKURT PANEL
launch=gsqlite3
gsqlite3-database=%s
gsqlite3-dnssec=yes
local-address=0.0.0.0, ::
api=yes
api-key=%s
webserver=yes
webserver-address=127.0.0.1
webserver-port=8081
webserver-allow-from=127.0.0.1,::1
default-soa-content=%s hostmaster.@ 0 10800 3600 604800 3600
default-ttl=3600
disable-axfr=yes
`, db, key, ns)
	// The Debian package launches the bind backend from pdns.d/bind.conf.
	if err := in.disable(in.pdnsConfDir() + "/pdns.d/bind.conf"); err != nil {
		return err
	}
	if err := in.writeFile(in.pdnsConfDir()+"/pdns.conf", conf, 0o640); err != nil {
		return err
	}
	if err := in.sh(ctx, "chown", "root:pdns", in.pdnsConfDir()+"/pdns.conf"); err != nil {
		return err
	}
	if err := in.systemctl(ctx, "enable", in.L.PDNSUnit); err != nil {
		return err
	}
	return in.systemctl(ctx, "restart", in.L.PDNSUnit)
}

func parentDomain(h string) string {
	if strings.Count(h, ".") >= 2 {
		return h[strings.Index(h, ".")+1:]
	}
	return h
}

func (in *Installer) postfixMapType() string { return PostfixMapType(in.L) }

func (in *Installer) cfgPostfix(ctx context.Context) error {
	pd := in.L.PostfixDir + "/bpanel"
	mt := in.postfixMapType()
	if err := os.MkdirAll(pd, 0o755); err != nil {
		return err
	}
	// postmap and newaliases read main.cf; a fresh Postfix has no usable
	// myhostname yet when the system hostname is not a FQDN (R2-E2E-5).
	if err := in.sh(ctx, "postconf", "-e", "myhostname="+in.O.Hostname); err != nil {
		return err
	}
	for _, n := range []string{"vdomains", "vmailbox", "valias", "vreject"} {
		p := pd + "/" + n
		if _, err := os.Stat(p); os.IsNotExist(err) {
			if err := os.WriteFile(p, []byte("# Managed by BOZKURT PANEL — changes are overwritten.\n"), 0o644); err != nil {
				return err
			}
		}
		if err := in.sh(ctx, "postmap", mt+":"+p); err != nil {
			return err
		}
	}
	// root's mail (cron, logwatch, fail2ban, unattended-upgrades) reaches the admin.
	if in.O.Email != "" {
		orig, _ := os.ReadFile("/etc/aliases")
		if err := in.writeFile("/etc/aliases", AliasesWithRoot(string(orig), in.O.Email), 0o644); err != nil {
			return err
		}
	} else {
		in.warn("no --email given: mail for root stays on this server (set it later in /etc/aliases and run newaliases)")
	}
	if err := in.sh(ctx, append([]string{"postconf", "-e"}, PostfixSettings(in.O.Hostname, mt, pd, panelCert, panelKey)...)...); err != nil {
		return err
	}
	if err := in.sh(ctx, "newaliases"); err != nil {
		return err
	}
	for _, svc := range []string{"submission", "smtps"} {
		if err := in.sh(ctx, "postconf", "-M", svc+"/inet="+svc+" inet n - y - - smtpd"); err != nil {
			return err
		}
		args := []string{"syslog_name=postfix/" + svc, "smtpd_sasl_auth_enable=yes", "smtpd_client_restrictions=permit_sasl_authenticated,reject",
			"smtpd_recipient_restrictions=permit_sasl_authenticated,reject"}
		if svc == "submission" {
			args = append(args, "smtpd_tls_security_level=encrypt")
		} else {
			args = append(args, "smtpd_tls_wrappermode=yes")
		}
		for _, a := range args {
			if err := in.sh(ctx, "postconf", "-P", svc+"/inet/"+a); err != nil {
				return err
			}
		}
	}
	if err := in.sh(ctx, "postfix", "check"); err != nil {
		return err
	}
	if err := in.systemctl(ctx, "enable", "postfix"); err != nil {
		return err
	}
	return in.systemctl(ctx, "restart", "postfix")
}

func (in *Installer) cfgDovecot(ctx context.Context) error {
	dd := in.L.DovecotDir
	passwd := dd + "/bpanel/passwd"
	if err := os.MkdirAll(filepath.Dir(passwd), 0o750); err != nil {
		return err
	}
	if _, err := os.Stat(passwd); os.IsNotExist(err) {
		if err := os.WriteFile(passwd, []byte(""), 0o640); err != nil {
			return err
		}
	}
	if err := in.sh(ctx, "chown", "root:dovecot", passwd); err != nil {
		return err
	}
	// System (PAM) logins are not mail accounts.
	if b, err := os.ReadFile(dd + "/conf.d/10-auth.conf"); err == nil {
		s := strings.Replace(string(b), "\n!include auth-system.conf.ext", "\n#!include auth-system.conf.ext", 1)
		if err := in.writeFile(dd+"/conf.d/10-auth.conf", s, 0o644); err != nil {
			return err
		}
	}
	conf := DovecotConf(DovecotVersion24(in.dovecotVersion(ctx)), panelCert, panelKey, passwd, in.O.Hostname)
	if err := in.writeFile(dd+"/conf.d/99-bpanel.conf", conf, 0o644); err != nil {
		return err
	}
	migrateSieveActive("/home")
	if err := in.sh(ctx, "doveconf", "-n"); err != nil {
		return err
	}
	if err := in.systemctl(ctx, "enable", "dovecot"); err != nil {
		return err
	}
	return in.systemctl(ctx, "restart", "dovecot")
}

func (in *Installer) cfgRspamd(ctx context.Context) error {
	if err := os.MkdirAll(agent.DKIMDir, 0o750); err != nil {
		return err
	}
	for _, u := range []string{"_rspamd", "rspamd"} {
		if userExists(u) {
			if err := in.sh(ctx, "chown", u+":"+u, agent.DKIMDir); err != nil {
				return err
			}
			break
		}
	}
	ctl, err := secret("rspamd-controller")
	if err != nil {
		return err
	}
	files := map[string]string{
		"/etc/rspamd/local.d/dkim_signing.conf": fmt.Sprintf(`# Managed by BOZKURT PANEL
enabled = true;
path = "%s/$domain.$selector.key";
selector = "%s";
allow_username_mismatch = true;
use_domain = "header";
sign_authenticated = true;
sign_local = true;
`, agent.DKIMDir, agent.DKIMSelector),
		"/etc/rspamd/local.d/redis.conf":            "servers = \"127.0.0.1\";\n",
		"/etc/rspamd/local.d/milter_headers.conf":   "use = [\"x-spamd-bar\", \"x-spam-level\", \"authentication-results\"];\n",
		"/etc/rspamd/local.d/actions.conf":          "reject = 15;\nadd_header = 6;\ngreylist = 4;\n",
		"/etc/rspamd/local.d/worker-controller.inc": "password = \"" + ctl + "\";\nbind_socket = \"127.0.0.1:11334\";\n",
		// numeric loopback, never "localhost", which needs /etc/hosts (R2-SYS-13)
		"/etc/rspamd/local.d/worker-normal.inc": "bind_socket = \"127.0.0.1:11333\";\n",
		"/etc/rspamd/local.d/worker-proxy.inc":  "bind_socket = \"127.0.0.1:11332\";\nupstream \"local\" {\n  default = yes;\n  hosts = \"127.0.0.1:11333\";\n}\n",
		"/etc/rspamd/local.d/worker-fuzzy.inc":  "bind_socket = \"127.0.0.1:11335\";\n",
	}
	for p, c := range files {
		mode := os.FileMode(0o644)
		if strings.HasSuffix(p, "worker-controller.inc") {
			mode = 0o640
		}
		if err := in.writeFile(p, c, mode); err != nil {
			return err
		}
	}
	for _, g := range []string{"_rspamd", "rspamd"} {
		if groupExists(g) {
			_ = in.sh(ctx, "chown", "root:"+g, "/etc/rspamd/local.d/worker-controller.inc")
			break
		}
	}
	if have("rspamadm") {
		if err := in.sh(ctx, "rspamadm", "configtest"); err != nil {
			return err
		}
	}
	if err := in.systemctl(ctx, "enable", "--now", in.L.RedisUnit); err != nil {
		return err
	}
	if err := in.systemctl(ctx, "enable", in.L.RspamdUnit); err != nil {
		return err
	}
	return in.systemctl(ctx, "restart", in.L.RspamdUnit)
}

func (in *Installer) ftpCertPath() string {
	if in.L.Family == distro.Debian {
		return "/etc/ssl/private/pure-ftpd.pem"
	}
	return "/etc/pki/pure-ftpd/pure-ftpd.pem"
}

// writeFTPCert concatenates key + chain for Pure-FTPd.
func (in *Installer) writeFTPCert() error {
	k, err := os.ReadFile(panelKey)
	if err != nil {
		return err
	}
	c, err := os.ReadFile(panelCert)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(in.ftpCertPath()), 0o700); err != nil {
		return err
	}
	return os.WriteFile(in.ftpCertPath(), append(k, c...), 0o600)
}

func (in *Installer) cfgPureFTPd(ctx context.Context) error {
	if err := in.writeFTPCert(); err != nil {
		return err
	}
	if _, err := os.Stat(in.L.FTPPasswd); os.IsNotExist(err) {
		if err := os.WriteFile(in.L.FTPPasswd, nil, 0o600); err != nil {
			return err
		}
	}
	if err := in.sh(ctx, "pure-pw", "mkdb", in.L.FTPPDB, "-f", in.L.FTPPasswd); err != nil {
		return err
	}
	if in.L.Family == distro.Debian {
		opts := map[string]string{
			"PureDB": in.L.FTPPDB, "TLS": "2", "ChrootEveryone": "yes", "NoAnonymous": "yes", "MinUID": "1000",
			"PassivePortRange": "30000 30100", "UnixAuthentication": "no", "PAMAuthentication": "no", "DontResolve": "yes",
		}
		for k, v := range opts {
			if err := in.writeFile("/etc/pure-ftpd/conf/"+k, v+"\n", 0o644); err != nil {
				return err
			}
		}
		if err := os.MkdirAll("/etc/pure-ftpd/auth", 0o755); err != nil {
			return err
		}
		for _, f := range []string{"/etc/pure-ftpd/auth/70pam", "/etc/pure-ftpd/auth/65unix"} {
			if err := in.disable(f); err != nil {
				return err
			}
		}
		if t, err := os.Readlink("/etc/pure-ftpd/auth/50pure"); err != nil || t != "../conf/PureDB" {
			_ = os.Remove("/etc/pure-ftpd/auth/50pure")
			if err := os.Symlink("../conf/PureDB", "/etc/pure-ftpd/auth/50pure"); err != nil {
				return err
			}
		}
	} else {
		b, err := os.ReadFile("/etc/pure-ftpd/pure-ftpd.conf")
		if err != nil {
			return err
		}
		set := map[string]string{"PureDB": in.L.FTPPDB, "TLS": "2", "ChrootEveryone": "yes", "NoAnonymous": "yes", "MinUID": "1000",
			"PassivePortRange": "30000 30100", "PAMAuthentication": "no", "UnixAuthentication": "no", "CertFile": in.ftpCertPath(), "DontResolve": "yes"}
		lines := strings.Split(string(b), "\n")
		seen := map[string]bool{}
		for i, l := range lines {
			t := strings.TrimLeft(strings.TrimSpace(l), "# ")
			for k, v := range set {
				if strings.HasPrefix(t, k+" ") || t == k {
					lines[i] = k + "  " + v
					seen[k] = true
				}
			}
		}
		for k, v := range set {
			if !seen[k] {
				lines = append(lines, k+"  "+v)
			}
		}
		if err := in.writeFile("/etc/pure-ftpd/pure-ftpd.conf", strings.Join(lines, "\n"), 0o644); err != nil {
			return err
		}
	}
	if err := in.systemctl(ctx, "enable", in.L.FTPUnit); err != nil {
		return err
	}
	return in.systemctl(ctx, "restart", in.L.FTPUnit)
}

func (in *Installer) cfgSFTP(ctx context.Context) error {
	const p = "/etc/ssh/sshd_config.d/50-bpanel.conf"
	if !have("sshd") {
		return fmt.Errorf("sshd is not installed (package openssh-server)")
	}
	// A freshly installed sshd has no host keys on EL9 until
	// sshd-keygen@.service runs (R2-SYS-3), and Ubuntu 24.04 creates
	// /run/sshd only when ssh.service starts (R2-SYS-4); `sshd -t` needs both.
	if err := in.sh(ctx, "ssh-keygen", "-A"); err != nil {
		return err
	}
	if err := os.MkdirAll("/run/sshd", 0o755); err != nil {
		return err
	}
	if err := os.Chmod("/run/sshd", 0o755); err != nil {
		return err
	}
	if err := in.writeFile(p, SSHDSnippet, 0o644); err != nil {
		return err
	}
	if err := in.sh(ctx, "sshd", "-t"); err != nil {
		_ = os.Remove(p)
		return err
	}
	// sshd must run (SFTP for the accounts): R2-SYS-9. Ubuntu starts it on
	// demand through ssh.socket; elsewhere the service itself runs.
	unit := in.L.SSHUnit
	if in.socketActivatedSSH(ctx) {
		unit = "ssh.socket"
	}
	if err := in.systemctl(ctx, "enable", "--now", unit); err != nil {
		return err
	}
	return in.reloadSSH(ctx)
}

// cronUnit is the cron daemon of the distribution family.
func (in *Installer) cronUnit() string {
	if in.L.Family == distro.RHEL {
		return "crond"
	}
	return "cron"
}

// cfgBaseServices enables and starts the distribution services the panel
// relies on. On Debian/Ubuntu the package stage's policy-rc.d kept them from
// starting, and nothing else started cron until a reboot (R2-SYS-8).
func (in *Installer) cfgBaseServices(ctx context.Context) error {
	return in.systemctl(ctx, "enable", "--now", in.cronUnit())
}

// dovecotVersion returns the output of `dovecot --version` ("2.3.21 (47349e2482)").
func (in *Installer) dovecotVersion(ctx context.Context) string {
	if !have("dovecot") {
		return ""
	}
	out, err := in.shOut(ctx, nil, "dovecot", "--version")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// reloadSSH applies sshd configuration changes. Ubuntu 24.04 starts sshd
// through ssh.socket, so ssh.service may legitimately be inactive: a plain
// `systemctl reload ssh` fails then. try-reload-or-restart reloads a running
// sshd and does nothing otherwise (the next connection reads the new file).
// A changed Port needs the socket regenerated, which daemon-reload does.
func (in *Installer) reloadSSH(ctx context.Context) error {
	if in.socketActivatedSSH(ctx) {
		if err := in.systemctl(ctx, "daemon-reload"); err != nil {
			return err
		}
	}
	return in.systemctl(ctx, "try-reload-or-restart", in.L.SSHUnit)
}

func (in *Installer) socketActivatedSSH(ctx context.Context) bool {
	if in.O.NoSystemd || in.L.Family != distro.Debian {
		return false
	}
	out, err := in.shOut(ctx, nil, "systemctl", "is-enabled", "ssh.socket")
	return err == nil && strings.TrimSpace(out) == "enabled"
}

// sshPorts returns every port sshd listens on (sshd -T plus ssh.socket).
func (in *Installer) sshPorts(ctx context.Context) []string {
	t, _ := in.shOut(ctx, nil, "sshd", "-T")
	sock := ""
	if in.socketActivatedSSH(ctx) {
		sock, _ = in.shOut(ctx, nil, "systemctl", "show", "-p", "Listen", "ssh.socket")
	}
	return SSHPortsFrom(t, sock)
}

func (in *Installer) cfgFirewall(ctx context.Context) error {
	rules := FirewallRules(in.sshPorts(ctx), in.full(), in.web())
	if err := in.writeFile("/etc/bpanel/nftables.conf", rules, 0o600); err != nil {
		return err
	}
	if err := in.writeFile("/etc/systemd/system/bpanel-firewall.service", UnitFirewall, 0o644); err != nil {
		return err
	}
	if err := in.sh(ctx, "nft", "-c", "-f", "/etc/bpanel/nftables.conf"); err != nil {
		if !in.O.NoSystemd || !strings.Contains(err.Error(), "Netlink") {
			return err
		}
		in.warn("firewall: ruleset not checked (no nf_tables netlink in this test container)")
	}
	// Remember the firewall that was active so uninstall can bring it back.
	if _, ok := in.S.Prev["firewall"]; !ok {
		prev := "none"
		if !in.O.NoSystemd {
			if out, err := in.shOut(ctx, nil, "systemctl", "is-active", "firewalld"); err == nil && strings.TrimSpace(out) == "active" {
				prev = "firewalld"
			} else if have("ufw") {
				if out, err := in.shOut(ctx, nil, "ufw", "status"); err == nil && strings.Contains(out, "Status: active") {
					prev = "ufw"
				}
			}
		}
		in.S.Prev["firewall"] = prev
		in.save()
	}
	switch in.S.Prev["firewall"] {
	case "firewalld":
		if err := in.systemctl(ctx, "disable", "--now", "firewalld"); err != nil {
			return err
		}
	case "ufw":
		if err := in.sh(ctx, "ufw", "--force", "disable"); err != nil {
			return err
		}
	}
	if err := in.systemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	if err := in.systemctl(ctx, "enable", "bpanel-firewall"); err != nil {
		return err
	}
	return in.systemctl(ctx, "reload-or-restart", "bpanel-firewall")
}

const (
	fail2banJailPath   = "/etc/fail2ban/jail.d/bpanel.local"
	fail2banFilterPath = "/etc/fail2ban/filter.d/bpanel.conf"
)

// cfgFail2ban bans brute-force sources on SSH, the panel ports and (full
// profile) webmail, IMAP/POP3 and SMTP AUTH, using nftables.
func (in *Installer) cfgFail2ban(ctx context.Context) error {
	if !have("fail2ban-client") {
		in.warn("fail2ban is not installed; brute-force protection is off")
		return nil
	}
	if err := in.writeFile(fail2banFilterPath, Fail2banPanelFilter, 0o644); err != nil {
		return err
	}
	if err := in.writeFile(fail2banJailPath, Fail2banJail(in.sshPorts(ctx), in.full(), true), 0o644); err != nil {
		return err
	}
	if err := in.sh(ctx, "fail2ban-client", "--test"); err != nil {
		return err
	}
	if err := in.systemctl(ctx, "enable", "fail2ban"); err != nil {
		return err
	}
	return in.systemctl(ctx, "restart", "fail2ban")
}

// migrateSieveActive moves the active Sieve link of every mailbox from
// ~/.dovecot.sieve to ~/dovecot.sieve (v1.1). The mailbox home is also the
// Maildir++ root, where a dot-prefixed entry is taken for a folder: a
// fileinto into a new folder (BoxTrapper) then failed with a temporary
// error. Only plain directories are walked (no symlinks are followed) and
// the link itself is renamed, never its target.
// migrateDovecotHome creates <box>/bpanel-home (owned like the box) and moves
// Dovecot's duplicate DB out of the Maildir root, where Maildir++ listed it
// as the folders "dovecot", "dovecot.lda-dupes" and "dovecot.lda-dupes.locks".
func migrateDovecotHome(box string) {
	fi, err := os.Lstat(box)
	if err != nil || !fi.IsDir() {
		return
	}
	home := filepath.Join(box, DovecotHomeDir)
	if hi, err := os.Lstat(home); err == nil && !hi.IsDir() {
		return // something else is there: leave it alone
	} else if err != nil {
		if os.Mkdir(home, 0o700) != nil {
			return
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			_ = os.Lchown(home, int(st.Uid), int(st.Gid))
		}
	}
	for _, n := range []string{".dovecot.lda-dupes", ".dovecot.lda-dupes.locks"} {
		p := filepath.Join(box, n)
		pi, err := os.Lstat(p)
		if err != nil || pi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if _, err := os.Lstat(filepath.Join(home, n)); err == nil {
			_ = os.RemoveAll(p)
			continue
		}
		_ = os.Rename(p, filepath.Join(home, n))
	}
}

func migrateSieveActive(homeRoot string) int {
	n := 0
	isDir := func(p string) bool {
		fi, err := os.Lstat(p)
		return err == nil && fi.IsDir()
	}
	users, _ := os.ReadDir(homeRoot)
	for _, u := range users {
		mail := filepath.Join(homeRoot, u.Name(), "mail")
		if !isDir(filepath.Join(homeRoot, u.Name())) || !isDir(mail) {
			continue
		}
		doms, _ := os.ReadDir(mail)
		for _, d := range doms {
			if !isDir(filepath.Join(mail, d.Name())) {
				continue
			}
			boxes, _ := os.ReadDir(filepath.Join(mail, d.Name()))
			for _, b := range boxes {
				box := filepath.Join(mail, d.Name(), b.Name())
				if !isDir(box) {
					continue
				}
				migrateDovecotHome(box)
				old, nw := filepath.Join(box, ".dovecot.sieve"), filepath.Join(box, "dovecot.sieve")
				fi, err := os.Lstat(old)
				if err != nil || (fi.Mode()&os.ModeSymlink == 0 && !fi.Mode().IsRegular()) {
					continue
				}
				if _, err := os.Lstat(nw); err == nil {
					continue
				}
				if os.Rename(old, nw) == nil {
					_ = os.Remove(filepath.Join(box, ".dovecot.svbin"))
					n++
				}
			}
		}
	}
	return n
}
