//go:build dev

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cumabozkurt/bpanel/internal/api"
	"github.com/cumabozkurt/bpanel/internal/store"
)

// DevAdminPassword is the password of the demo administrator in dev builds
// only (go build -tags dev). Override with BPANEL_DEV_PASSWORD.
var DevAdminPassword = func() string {
	if p := os.Getenv("BPANEL_DEV_PASSWORD"); p != "" {
		return p
	}
	return "Demo-Pass-2026"
}()

// seedDemo fills an empty development database with realistic demo data.
func seedDemo(srv *api.Server, devDir string) error {
	ctx := context.Background()
	st := srv.Store
	id, err := api.EnsureAdmin(ctx, st, "bpadmin", DevAdminPassword, "admin@example.com")
	if err != nil {
		return err
	}
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE role<>'admin'`).Scan(&n)
	if n > 0 {
		return nil
	}
	st.Set("contact_email", "admin@example.com")
	admin, _ := store.One[store.User](ctx, st.DB, `SELECT *, '' AS package_name, '' AS owner_name FROM users WHERE id=?`, id)
	st.DB.Exec(`INSERT INTO packages(name,disk_mb,bandwidth_mb,max_domains,max_subdomains,max_aliases,max_email,max_db,max_ftp,mail_quota_mb,cpu_percent,memory_mb,max_tasks,php_version,created_at)
		VALUES('starter',2048,20480,1,5,2,10,2,2,512,50,512,100,'',?),('business',51200,-1,-1,-1,-1,-1,-1,-1,4096,200,2048,400,'8.3',?)`, time.Now().Unix(), time.Now().Unix())
	var pkg int64
	st.DB.QueryRow(`SELECT id FROM packages WHERE name='default'`).Scan(&pkg)
	accounts := []api.CreateAccountReq{
		{Username: "demo", Domain: "ornek.com.tr", Password: "Demo-User-2026", Email: "demo@ornek.com.tr", PackageID: pkg},
		{Username: "kurtajans", Domain: "kurtajans.com", Password: "Demo-User-2026", Email: "info@kurtajans.com", PackageID: pkg, Role: "reseller", MaxAccounts: api.LimitOf(25)},
		{Username: "anadolu", Domain: "anadolukahve.com", Password: "Demo-User-2026", Email: "hello@anadolukahve.com", PackageID: pkg},
	}
	for _, a := range accounts {
		if _, _, err := srv.CreateAccount(ctx, &admin, a); err != nil {
			return fmt.Errorf("seed %s: %w", a.Username, err)
		}
	}
	st.DB.Exec(`UPDATE users SET status='suspended', suspend_reason='Unpaid invoice' WHERE username='anadolu'`)
	var uid, mainID int64
	st.DB.QueryRow(`SELECT id FROM users WHERE username='demo'`).Scan(&uid)
	st.DB.QueryRow(`SELECT id FROM domains WHERE name='ornek.com.tr'`).Scan(&mainID)
	now := time.Now().Unix()
	st.DB.Exec(`INSERT INTO domains(user_id,name,kind,parent_id,docroot,php_version,ssl_status,created_at) VALUES
		(?, 'blog.ornek.com.tr', 'sub', ?, 'blog.ornek.com.tr', '8.4', 'active', ?),
		(?, 'magaza.com.tr', 'addon', NULL, 'magaza.com.tr', '', 'none', ?),
		(?, 'ornek.net', 'alias', ?, 'public_html', '', 'none', ?)`, uid, mainID, now, uid, now, uid, mainID, now)
	st.DB.Exec(`UPDATE domains SET ssl_status='active', ssl_expires=? WHERE id=?`, time.Now().AddDate(0, 0, 74).UTC().Format(time.RFC3339), mainID)
	var magaza int64
	st.DB.QueryRow(`SELECT id FROM domains WHERE name='magaza.com.tr'`).Scan(&magaza)
	for _, m := range []struct {
		email string
		dom   int64
		q     int64
	}{{"info@ornek.com.tr", mainID, 1024}, {"cuma@ornek.com.tr", mainID, 2048}, {"destek@ornek.com.tr", mainID, 512}, {"siparis@magaza.com.tr", magaza, 1024}} {
		st.DB.Exec(`INSERT INTO mailboxes(user_id,domain_id,email,quota_mb,created_at) VALUES(?,?,?,?,?)`, uid, m.dom, m.email, m.q, now)
	}
	st.DB.Exec(`INSERT INTO forwarders(user_id,source,destination,created_at) VALUES(?, 'satis@ornek.com.tr','cuma@ornek.com.tr',?),(?, '@magaza.com.tr','siparis@magaza.com.tr',?)`, uid, now, uid, now)
	st.DB.Exec(`INSERT INTO databases(user_id,name,created_at) VALUES(?, 'demo_wp',?),(?, 'demo_shop',?)`, uid, now, uid, now)
	st.DB.Exec(`INSERT INTO db_users(user_id,name,created_at) VALUES(?, 'demo_wpuser',?)`, uid, now)
	st.DB.Exec(`INSERT INTO db_grants(db_id,dbuser_id,privileges) SELECT d.id, u.id, 'ALL' FROM databases d, db_users u WHERE d.name='demo_wp' AND u.name='demo_wpuser'`)
	st.DB.Exec(`INSERT INTO ftp_accounts(user_id,login,dir,quota_mb,created_at) VALUES(?, 'tasarim@ornek.com.tr','public_html/tema',-1,?)`, uid, now)
	st.DB.Exec(`INSERT INTO cron_jobs(user_id,minute,hour,dom,month,dow,command,created_at) VALUES(?, '*/15','*','*','*','*','/usr/bin/php /home/demo/public_html/wp-cron.php >/dev/null 2>&1',?),(?, '0','3','*','*','0','/home/demo/bin/yedek.sh',?)`, uid, now, uid, now)
	// demo files
	home := filepath.Join(devDir, "homes", "demo")
	files := map[string]string{
		"public_html/index.php":                           "<?php\n// Örnek Ltd. — ana sayfa\nrequire __DIR__ . '/wp-blog-header.php';\n",
		"public_html/.htaccess":                           "# BEGIN WordPress\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . /index.php [L]\n# END WordPress\n",
		"public_html/wp-config.php":                       "<?php\ndefine('DB_NAME', 'demo_wp');\ndefine('DB_USER', 'demo_wpuser');\ndefine('DB_HOST', 'localhost');\n",
		"public_html/robots.txt":                          "User-agent: *\nDisallow: /wp-admin/\n",
		"public_html/wp-content/themes/ornek/style.css":   "/* Theme Name: Örnek */\nbody{font-family:sans-serif}\n",
		"public_html/wp-content/uploads/2026/10/logo.svg": "<svg xmlns='http://www.w3.org/2000/svg'/>",
		"public_html/tema/README.md":                      "Tema dosyaları\n",
		"blog.ornek.com.tr/index.html":                    "<h1>Blog</h1>\n",
		"magaza.com.tr/index.php":                         "<?php echo 'Mağaza';\n",
		"logs/php-error.log":                              "[09-Oct-2026 01:12:44 UTC] PHP Warning:  Undefined variable $x in /home/demo/public_html/index.php on line 3\n",
		"bin/yedek.sh":                                    "#!/bin/bash\necho yedek\n",
	}
	for p, c := range files {
		full := filepath.Join(home, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, []byte(c), 0o644)
	}
	os.WriteFile(filepath.Join(home, "public_html", "wp-content", "uploads", "2026", "10", "kapak.jpg"), make([]byte, 734003), 0o644)
	os.WriteFile(filepath.Join(home, "backups", "site-2026-10-01.zip"), make([]byte, 5<<20), 0o644)
	fmt.Fprintf(os.Stderr, "\n  DEV MODE — demo logins:\n    admin panel  : bpadmin / %s\n    user panel   : demo / Demo-User-2026\n\n", DevAdminPassword)
	return nil
}
