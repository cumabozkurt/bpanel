package installer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cumabozkurt/bpanel/internal/distro"
)

const (
	appsDir   = "/usr/share/bpanel"
	rcDir     = appsDir + "/roundcube"
	pmaDir    = appsDir + "/phpmyadmin"
	appsState = "/var/lib/bpanel/apps"
)

// AppsDirs are the writable directories of the bundled PHP apps. They live
// under /var/lib/bpanel (0751) and belong to bpanel-apps, the user of the
// apps PHP-FPM pool (SYS-3).
var AppsDirs = []struct {
	Path string
	Mode os.FileMode
}{
	{appsState, 0o750},
	{appsState + "/sessions", 0o700},
	{appsState + "/pma-tmp", 0o700},
	{appsState + "/roundcube", 0o700},
}

func (in *Installer) appsSocket() string {
	if in.L.Family == distro.Debian {
		return "/run/php/bpanel-apps.sock"
	}
	return "/run/php-fpm/bpanel-apps.sock"
}

// extract downloads (checksum-verified, into the root-only cache) and unpacks
// an app archive. Files end up root-owned and read-only for the pool user.
func (in *Installer) extract(ctx context.Context, url, sha, dest string) error {
	if _, err := os.Stat(dest + "/index.php"); err == nil {
		return nil
	}
	tmp := filepath.Join(CacheDir, filepath.Base(url))
	if err := download(ctx, url, tmp, sha); err != nil {
		return err
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	return in.sh(ctx, "tar", "-xzf", tmp, "-C", dest, "--strip-components=1", "--no-same-owner", "--no-same-permissions")
}

// AppsPool renders the PHP-FPM pool for Roundcube and phpMyAdmin.
func AppsPool(socket string) string {
	return fmt.Sprintf(`; Managed by BOZKURT PANEL — pool for Roundcube and phpMyAdmin
[bpanel-apps]
user = bpanel-apps
group = bpanel-apps
listen = %[1]s
listen.owner = bpanel-apps
listen.group = bpanel-web
listen.mode = 0660
pm = ondemand
pm.max_children = 10
pm.process_idle_timeout = 30s
env[TMPDIR] = %[2]s/pma-tmp
php_admin_value[upload_max_filesize] = 64M
php_admin_value[post_max_size] = 64M
php_admin_value[session.save_path] = %[2]s/sessions
php_admin_value[session.gc_probability] = 1
php_admin_value[upload_tmp_dir] = %[2]s/pma-tmp
php_admin_value[sys_temp_dir] = %[2]s/pma-tmp
php_admin_value[open_basedir] = %[3]s:%[2]s:/usr/share/php
`, socket, appsState, appsDir)
}

// cfgApps installs Roundcube (webmail, HTTPS 2096) and phpMyAdmin (served
// internally on 127.0.0.1:2090 and reached through the user panel with SSO).
func (in *Installer) cfgApps(ctx context.Context) error {
	ph := in.L.PHPFor(in.L.DefaultPHP)
	for _, d := range AppsDirs {
		if err := os.MkdirAll(d.Path, d.Mode); err != nil {
			return err
		}
		if err := os.Chmod(d.Path, d.Mode); err != nil {
			return err
		}
	}
	if err := in.writeFile(filepath.Join(ph.PoolDir, "bpanel-apps.conf"), AppsPool(in.appsSocket()), 0o644); err != nil {
		return err
	}
	nginx := AppsNginx(AppsNginxOpts{Socket: in.appsSocket(), PMADir: pmaDir, RCDir: rcDir, Cert: panelCert, Key: panelKey,
		Webmail: in.full(), HTTP2On: in.nginxHTTP2On(ctx)})

	if err := in.extract(ctx, PMAURL, PMASHA, pmaDir); err != nil {
		return fmt.Errorf("phpMyAdmin: %w", err)
	}
	blowfish, err := secret("pma-blowfish")
	if err != nil {
		return err
	}
	if err := in.writeFile(pmaDir+"/config.inc.php", fmt.Sprintf(`<?php
// Managed by BOZKURT PANEL — single sign-on from the user panel.
$cfg['blowfish_secret'] = '%s';
$i = 1;
$cfg['Servers'][$i]['auth_type'] = 'signon';
$cfg['Servers'][$i]['SignonSession'] = 'BPPMA';
$cfg['Servers'][$i]['SignonURL'] = '/3rdparty/phpMyAdmin/bpanel-signon.php';
$cfg['Servers'][$i]['LogoutURL'] = '/';
$cfg['Servers'][$i]['host'] = 'localhost';
$cfg['Servers'][$i]['AllowNoPassword'] = false;
$cfg['TempDir'] = '%s/pma-tmp';
$cfg['VersionCheck'] = false;
$cfg['ShowDatabasesNavigationAsTree'] = true;
`, blowfish[:32], appsState), 0o640); err != nil {
		return err
	}
	// R2-E2E-8: the token endpoint is on the configured user-panel port.
	userPort := apiConfig().UserPort
	if userPort <= 0 || userPort > 65535 {
		userPort = 2083
	}
	if err := in.writeFile(pmaDir+"/bpanel-signon.php", strings.Replace(`<?php
// Managed by BOZKURT PANEL: exchanges a one-time panel token for DB credentials.
$t = isset($_GET['token']) ? $_GET['token'] : '';
if (!preg_match('/^[a-f0-9]{48}$/', $t)) { http_response_code(400); exit('Invalid token'); }
$ctx = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false], 'http' => ['timeout' => 5]]);
$r = @file_get_contents('https://127.0.0.1:@@PORT@@/internal/pma-token/' . $t, false, $ctx);
$d = json_decode((string)$r, true);
if (!is_array($d) || empty($d['user'])) { http_response_code(403); exit('This link has expired. Open phpMyAdmin again from the panel.'); }
session_set_cookie_params(['path' => '/3rdparty/phpMyAdmin/', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
session_name('BPPMA');
session_start();
$_SESSION['PMA_single_signon_user'] = $d['user'];
$_SESSION['PMA_single_signon_password'] = $d['password'];
$_SESSION['PMA_single_signon_host'] = 'localhost';
session_write_close();
header('Location: index.php');
`, "@@PORT@@", strconv.Itoa(userPort), 1), 0o644); err != nil {
		return err
	}
	if err := in.sh(ctx, "chown", "root:bpanel-apps", pmaDir+"/config.inc.php"); err != nil {
		return err
	}

	if in.full() {
		if err := in.extract(ctx, RoundcubeURL, RoundcubeSHA, rcDir); err != nil {
			return fmt.Errorf("roundcube: %w", err)
		}
		des, err := secret("roundcube-des")
		if err != nil {
			return err
		}
		lang := "en_US"
		if in.O.Lang == "tr" {
			lang = "tr_TR"
		}
		if err := in.writeFile(rcDir+"/config/config.inc.php", fmt.Sprintf(`<?php
// Managed by BOZKURT PANEL
$config = [];
$config['db_dsnw'] = 'sqlite:///%[1]s/roundcube/roundcube.db?mode=0640';
$config['imap_host'] = 'localhost:143';
$config['smtp_host'] = 'tls://localhost:587';
$config['smtp_user'] = '%%u';
$config['smtp_pass'] = '%%p';
$config['smtp_conn_options'] = ['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]];
$config['support_url'] = '';
$config['product_name'] = 'BOZKURT PANEL Webmail';
$config['des_key'] = '%[2]s';
$config['plugins'] = ['archive', 'zipdownload', 'managesieve', 'markasjunk'];
$config['managesieve_host'] = 'localhost';
$config['language'] = '%[3]s';
$config['skin'] = 'elastic';
$config['temp_dir'] = '%[1]s/roundcube/';
// Logs go to the journal (SYSLOG_IDENTIFIER=roundcube) where the
// fail2ban roundcube-auth jail reads failed logins.
$config['log_driver'] = 'syslog';
$config['syslog_id'] = 'roundcube';
$config['log_logins'] = true;
$config['enable_installer'] = false;
$config['use_https'] = true;
`, appsState, des[:24], lang), 0o640); err != nil {
			return err
		}
		if err := in.sh(ctx, "chown", "root:bpanel-apps", rcDir+"/config/config.inc.php"); err != nil {
			return err
		}
		if err := os.RemoveAll(rcDir + "/installer"); err != nil {
			return err
		}
		if err := in.sh(ctx, "chown", "-R", "bpanel-apps:bpanel-apps", appsState); err != nil {
			return err
		}
		if err := in.roundcubeSchema(ctx); err != nil {
			in.warn("Roundcube database init: " + err.Error())
		}
	}
	if err := in.sh(ctx, "chown", "-R", "bpanel-apps:bpanel-apps", appsState); err != nil {
		return err
	}
	if err := in.writeFile("/etc/nginx/bpanel-apps.d/apps.conf", nginx, 0o644); err != nil {
		return err
	}
	if err := in.sh(ctx, ph.Binary, "-t"); err != nil {
		return err
	}
	if err := in.systemctl(ctx, "restart", ph.Unit); err != nil {
		return err
	}
	if err := in.sh(ctx, "nginx", "-t"); err != nil {
		return err
	}
	return in.systemctl(ctx, "reload", "nginx")
}

// rcDB is Roundcube's SQLite database.
const rcDB = appsState + "/roundcube/roundcube.db"

// rcSchemaReady reports whether Roundcube's schema exists (its users table).
func (in *Installer) rcSchemaReady(ctx context.Context) bool {
	if _, err := os.Stat(rcDB); err != nil {
		return false
	}
	out, err := in.shOut(ctx, nil, "sqlite3", rcDB, "SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
	return err == nil && strings.TrimSpace(out) == "users"
}

// roundcubeSchema creates the Roundcube schema once (R2-SYS-12 / R2-E2E-5).
// Roundcube's SQLite driver creates the schema itself when it first opens a
// new database file, so initdb.sh then fails with "table users already
// exists [FAILED]" although everything is in place. The step is skipped when
// the schema is present, and an initdb.sh error only counts when the schema
// is still missing afterwards.
func (in *Installer) roundcubeSchema(ctx context.Context) error {
	if in.rcSchemaReady(ctx) {
		return nil
	}
	php := "php"
	if in.L.Family == distro.Debian {
		php = "php" + in.L.DefaultPHP
	}
	_, err := in.shOut(ctx, nil, "runuser", "-u", "bpanel-apps", "--", php, rcDir+"/bin/initdb.sh", "--dir="+rcDir+"/SQL")
	if in.rcSchemaReady(ctx) {
		return nil
	}
	if err == nil {
		err = fmt.Errorf("schema not found in %s after initdb.sh", rcDB)
	}
	return err
}
