package api

import (
	"context"
	"time"

	"github.com/cumabozkurt/bpanel/internal/auth"
	"github.com/cumabozkurt/bpanel/internal/store"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// Bootstrap makes sure the database has a default package and settings.
func Bootstrap(st *store.Store) error {
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM packages`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := st.DB.Exec(`INSERT INTO packages(name,disk_mb,bandwidth_mb,max_domains,max_subdomains,max_aliases,max_email,max_db,max_ftp,mail_quota_mb,cpu_percent,memory_mb,max_tasks,php_version,created_at)
			VALUES('default',10240,102400,10,20,10,50,10,10,1024,100,1024,200,'',?)`, time.Now().Unix()); err != nil {
			return err
		}
	}
	if st.Get("default_lang", "") == "" {
		if err := st.Set("default_lang", "en"); err != nil {
			return err
		}
	}
	return nil
}

// EnsureAdmin creates (or resets the password of) a panel administrator that
// is not a system account. Used by the installer and `bpanel admin`.
func EnsureAdmin(ctx context.Context, st *store.Store, username, password, email string) (int64, error) {
	if err := validate.Password(password); err != nil {
		return 0, err
	}
	h, err := auth.HashPassword(password)
	if err != nil {
		return 0, err
	}
	var id int64
	err = st.DB.QueryRowContext(ctx, `SELECT id FROM users WHERE username=?`, username).Scan(&id)
	if err == nil {
		_, err = st.DB.ExecContext(ctx, `UPDATE users SET password_hash=?, role='admin', status='active' WHERE id=?`, h, id)
		return id, err
	}
	res, err := st.DB.ExecContext(ctx, `INSERT INTO users(username,role,email,password_hash,status,created_at) VALUES(?,?,?,?,'active',?)`,
		username, "admin", email, h, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}
