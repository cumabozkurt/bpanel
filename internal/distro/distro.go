// Package distro captures the file-system and service-name differences
// between the supported platforms (Ubuntu 24.04 and AlmaLinux 9).
package distro

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Family string

const (
	Debian Family = "debian" // Ubuntu 24.04 (and Debian for development)
	RHEL   Family = "rhel"   // AlmaLinux 9 / Rocky 9
)

// Layout lists every path and unit name that differs between families.
type Layout struct {
	Family       Family
	ID           string
	VersionID    string
	Pretty       string
	DefaultPHP   string
	NginxUnit    string
	NginxVhosts  string // directory included by our nginx snippet
	ApacheUnit   string
	ApacheVhosts string
	ApacheUser   string
	WebGroup     string // group nginx/apache run as
	MariaDBUnit  string
	MySQLSocket  string
	PDNSUnit     string
	PostfixDir   string
	DovecotDir   string
	RspamdUnit   string
	RedisUnit    string
	FTPUnit      string
	FTPPasswd    string
	FTPPDB       string
	SSHUnit      string
	CronDir      string
}

// OSRelease parses /etc/os-release.
func OSRelease(root string) (map[string]string, error) {
	f, err := os.Open(filepath.Join(root, "/etc/os-release"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		m[k] = strings.Trim(v, `"'`)
	}
	return m, sc.Err()
}

// Detect returns the layout for the running system.
func Detect() (*Layout, error) {
	m, err := OSRelease("/")
	if err != nil {
		return nil, err
	}
	return ForRelease(m)
}

// ForRelease maps os-release values to a layout.
func ForRelease(m map[string]string) (*Layout, error) {
	id := m["ID"]
	like := " " + m["ID_LIKE"] + " "
	var l *Layout
	switch {
	case id == "ubuntu" || id == "debian" || strings.Contains(like, " debian "):
		l = &Layout{Family: Debian, DefaultPHP: "8.3", NginxUnit: "nginx", NginxVhosts: "/etc/nginx/bpanel.d",
			ApacheUnit: "apache2", ApacheVhosts: "/etc/apache2/bpanel.d", ApacheUser: "www-data", WebGroup: "bpanel-web",
			MariaDBUnit: "mariadb", MySQLSocket: "/run/mysqld/mysqld.sock", PDNSUnit: "pdns", PostfixDir: "/etc/postfix",
			DovecotDir: "/etc/dovecot", RspamdUnit: "rspamd", RedisUnit: "redis-server", FTPUnit: "pure-ftpd",
			FTPPasswd: "/etc/pure-ftpd/pureftpd.passwd", FTPPDB: "/etc/pure-ftpd/pureftpd.pdb", SSHUnit: "ssh",
			CronDir: "/var/spool/cron/crontabs"}
		if id == "debian" {
			l.DefaultPHP = "8.4"
		}
	case id == "almalinux" || id == "rocky" || id == "rhel" || strings.Contains(like, " rhel "):
		l = &Layout{Family: RHEL, DefaultPHP: "8.3", NginxUnit: "nginx", NginxVhosts: "/etc/nginx/bpanel.d",
			ApacheUnit: "httpd", ApacheVhosts: "/etc/httpd/bpanel.d", ApacheUser: "apache", WebGroup: "bpanel-web",
			MariaDBUnit: "mariadb", MySQLSocket: "/var/lib/mysql/mysql.sock", PDNSUnit: "pdns", PostfixDir: "/etc/postfix",
			DovecotDir: "/etc/dovecot", RspamdUnit: "rspamd", RedisUnit: "redis", FTPUnit: "pure-ftpd",
			FTPPasswd: "/etc/pure-ftpd/pureftpd.passwd", FTPPDB: "/etc/pure-ftpd/pureftpd.pdb", SSHUnit: "sshd",
			CronDir: "/var/spool/cron"}
	default:
		return nil, fmt.Errorf("unsupported distribution %q", id)
	}
	l.ID, l.VersionID, l.Pretty = id, m["VERSION_ID"], m["PRETTY_NAME"]
	return l, nil
}

// Supported reports whether the release is an officially supported target.
func (l *Layout) Supported() bool {
	switch l.ID {
	case "ubuntu":
		return l.VersionID == "24.04"
	case "almalinux", "rocky":
		return strings.HasPrefix(l.VersionID, "9")
	}
	return false
}

// PHP describes where a given PHP-FPM version lives.
type PHP struct {
	Version string
	Unit    string
	Binary  string
	PoolDir string
	Socket  func(user string) string
}

func nodot(v string) string { return strings.ReplaceAll(v, ".", "") }

// PHPFor returns the FPM layout for a version. On Ubuntu every version
// (distro or ondrej PPA) uses /etc/php/X.Y. On AlmaLinux the module default
// is /etc/php-fpm.d and Remi SCL versions live in /etc/opt/remi/phpXY.
func (l *Layout) PHPFor(v string) PHP {
	if l.Family == Debian {
		return PHP{Version: v, Unit: "php" + v + "-fpm", Binary: "/usr/sbin/php-fpm" + v,
			PoolDir: "/etc/php/" + v + "/fpm/pool.d",
			Socket:  func(u string) string { return "/run/php/bpanel-" + u + "-" + nodot(v) + ".sock" }}
	}
	if v == l.DefaultPHP {
		return PHP{Version: v, Unit: "php-fpm", Binary: "/usr/sbin/php-fpm", PoolDir: "/etc/php-fpm.d",
			Socket: func(u string) string { return "/run/php-fpm/bpanel-" + u + "-" + nodot(v) + ".sock" }}
	}
	n := nodot(v)
	return PHP{Version: v, Unit: "php" + n + "-php-fpm", Binary: "/opt/remi/php" + n + "/root/usr/sbin/php-fpm",
		PoolDir: "/etc/opt/remi/php" + n + "/php-fpm.d",
		Socket:  func(u string) string { return "/var/opt/remi/php" + n + "/run/php-fpm/bpanel-" + u + ".sock" }}
}

// PHPPackages returns the packages that install one FPM version.
// PHP 8.5+ has OPcache built in: neither Sury (php8.5-opcache) nor Remi
// (php85-php-opcache) ship that package, and apt/dnf abort the whole
// transaction on a missing name (SYS: PHP install), so it is left out.
func (l *Layout) PHPPackages(v string) []string {
	opcache := !phpAtLeast(v, 8, 5)
	keep := func(exts []string) []string {
		out := exts[:0:0]
		for _, e := range exts {
			if e == "opcache" && !opcache {
				continue
			}
			out = append(out, e)
		}
		return out
	}
	exts := keep([]string{"fpm", "cli", "mysql", "curl", "gd", "mbstring", "xml", "zip", "intl", "bcmath", "opcache", "soap", "imagick"})
	var out []string
	if l.Family == Debian {
		for _, e := range exts {
			out = append(out, "php"+v+"-"+e)
		}
		return out
	}
	if v == l.DefaultPHP {
		for _, e := range keep([]string{"fpm", "cli", "mysqlnd", "gd", "mbstring", "xml", "intl", "bcmath", "opcache", "soap", "pecl-zip"}) {
			out = append(out, "php-"+e)
		}
		return out
	}
	n := nodot(v)
	for _, e := range keep([]string{"fpm", "cli", "mysqlnd", "gd", "mbstring", "xml", "intl", "bcmath", "opcache", "soap", "pecl-zip", "pecl-imagick"}) {
		out = append(out, "php"+n+"-php-"+e)
	}
	return out
}

// phpAtLeast reports whether version "X.Y" is >= maj.min.
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
	return x > maj || x == maj && y >= min
}

// ProfileUnits are the core service units an install profile ships
// (minimal: nginx + PHP + MariaDB; web: + Apache, PowerDNS, Pure-FTPd;
// full: + Postfix, Dovecot, Rspamd, Redis).
func (l *Layout) ProfileUnits(profile string) []string {
	u := []string{l.NginxUnit, l.MariaDBUnit, l.PHPFor(l.DefaultPHP).Unit, l.SSHUnit, "bpanel-api"}
	if profile != "minimal" {
		u = append(u, l.ApacheUnit, l.PDNSUnit, l.FTPUnit)
	}
	if profile == "full" || profile == "" {
		u = append(u, "postfix", "dovecot", l.RspamdUnit, l.RedisUnit)
	}
	return u
}

// UnitsNotInProfile are the optional units a profile does not install.
func (l *Layout) UnitsNotInProfile(profile string) []string {
	switch profile {
	case "minimal":
		return []string{l.ApacheUnit, l.PDNSUnit, l.FTPUnit, "postfix", "dovecot", l.RspamdUnit, l.RedisUnit}
	case "web":
		return []string{"postfix", "dovecot", l.RspamdUnit, l.RedisUnit}
	}
	return nil
}

// KnownPHP is the set of versions the panel offers to manage.
var KnownPHP = []string{"8.1", "8.2", "8.3", "8.4", "8.5"}
