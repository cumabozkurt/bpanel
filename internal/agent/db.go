package agent

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// MariaDB is managed over the local unix socket as root (unix_socket auth),
// with client-side parameter interpolation for every value.

func (a *Agent) mysql(ctx context.Context) (*sql.DB, error) {
	cfg := mysql.NewConfig()
	cfg.User = "root"
	cfg.Net = "unix"
	cfg.Addr = a.L.MySQLSocket
	cfg.InterpolateParams = true
	cfg.Timeout = 5 * time.Second
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, errf("mariadb_unreachable", "%v", err)
	}
	return db, nil
}

func ident(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }

// grantIdent escapes LIKE wildcards: in GRANT ... ON db.* an underscore matches any char.
func grantIdent(s string) string { return ident(strings.ReplaceAll(s, "_", `\_`)) }

func checkDBName(name string) error {
	owner, _, ok := strings.Cut(name, "_")
	if !ok {
		return errf("invalid_db_name", "%s", name)
	}
	if err := validateDB(owner, name); err != nil {
		return err
	}
	return nil
}

func validateDB(owner, name string) error {
	if len(name) > 64 || len(owner) == 0 {
		return errf("invalid_db_name", "%s", name)
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return errf("invalid_db_name", "%s", name)
		}
	}
	return nil
}

// checkOwned enforces the "<owner>_" prefix of the owning account, so the
// agent does not blindly trust the API for tenancy (CODE-27). The owner is
// mandatory since v0.2.
func checkOwned(owner, name, code string) error {
	if owner == "" {
		return errf("owner_required", "%s: no owning account given", name)
	}
	if err := validate.Username(owner); err != nil && err.Error() == "invalid_username" {
		return errf("invalid_username", "%s", owner)
	}
	if !strings.HasPrefix(name, owner+"_") {
		return errf(code, "%s does not belong to %s", name, owner)
	}
	return nil
}

func dbHost(h string) (string, error) {
	if h == "" {
		return "localhost", nil
	}
	if len(h) > 60 || strings.ContainsAny(h, "'\"`\\ \n") {
		return "", errf("invalid_host", "%s", h)
	}
	return h, nil
}

// dbHosts is every account name a database user gets (R2-SYS-15): MariaDB
// treats 'u'@'localhost' (socket) and a TCP login from 127.0.0.1 or ::1 as
// different accounts, so apps configured with DB host 127.0.0.1 were refused
// (1130). A local user is therefore mirrored to 'u'@'127.0.0.1' and
// 'u'@'::1' with the same password and grants; every change is applied to all.
func dbHosts(h string) ([]string, error) {
	host, err := dbHost(h)
	if err != nil {
		return nil, err
	}
	if host == "localhost" {
		return []string{"localhost", "127.0.0.1", "::1"}, nil
	}
	return []string{host}, nil
}

func (a *Agent) dbCreate(ctx context.Context, p rpc.DBRef) (rpc.Empty, error) {
	if err := checkDBName(p.Name); err != nil {
		return rpc.Empty{}, err
	}
	if err := checkOwned(p.Owner, p.Name, "db_prefix_required"); err != nil {
		return rpc.Empty{}, err
	}
	db, err := a.mysql(ctx)
	if err != nil {
		return rpc.Empty{}, err
	}
	defer db.Close()
	_, err = db.ExecContext(ctx, "CREATE DATABASE IF NOT EXISTS "+ident(p.Name)+" CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
	return rpc.Empty{}, err
}

func (a *Agent) dbDrop(ctx context.Context, p rpc.DBRef) (rpc.Empty, error) {
	if err := checkDBName(p.Name); err != nil {
		return rpc.Empty{}, err
	}
	if err := checkOwned(p.Owner, p.Name, "db_prefix_required"); err != nil {
		return rpc.Empty{}, err
	}
	db, err := a.mysql(ctx)
	if err != nil {
		return rpc.Empty{}, err
	}
	defer db.Close()
	_, err = db.ExecContext(ctx, "DROP DATABASE IF EXISTS "+ident(p.Name))
	return rpc.Empty{}, err
}

func (a *Agent) dbUserCreate(ctx context.Context, p rpc.DBUser) (rpc.Empty, error) {
	if err := checkDBName(p.User); err != nil || len(p.User) > 32 {
		return rpc.Empty{}, errf("invalid_db_user", "%s", p.User)
	}
	if err := checkOwned(p.Owner, p.User, "invalid_db_user"); err != nil {
		return rpc.Empty{}, err
	}
	hosts, err := dbHosts(p.Host)
	if err != nil {
		return rpc.Empty{}, err
	}
	if len(p.Password) < 8 {
		return rpc.Empty{}, errf("password_too_short", "")
	}
	db, err := a.mysql(ctx)
	if err != nil {
		return rpc.Empty{}, err
	}
	defer db.Close()
	for _, host := range hosts {
		if _, err := db.ExecContext(ctx, "CREATE USER IF NOT EXISTS ?@? IDENTIFIED BY ?", p.User, host, p.Password); err != nil {
			return rpc.Empty{}, err
		}
		if _, err := db.ExecContext(ctx, "ALTER USER ?@? IDENTIFIED BY ?", p.User, host, p.Password); err != nil {
			return rpc.Empty{}, err
		}
	}
	return rpc.Empty{}, nil
}

func (a *Agent) dbUserPassword(ctx context.Context, p rpc.DBUser) (rpc.Empty, error) {
	if err := checkDBName(p.User); err != nil || len(p.User) > 32 {
		return rpc.Empty{}, errf("invalid_db_user", "%s", p.User)
	}
	if len(p.Password) < 8 {
		return rpc.Empty{}, errf("password_too_short", "")
	}
	if err := checkOwned(p.Owner, p.User, "invalid_db_user"); err != nil {
		return rpc.Empty{}, err
	}
	hosts, err := dbHosts(p.Host)
	if err != nil {
		return rpc.Empty{}, err
	}
	db, err := a.mysql(ctx)
	if err != nil {
		return rpc.Empty{}, err
	}
	defer db.Close()
	for _, host := range hosts {
		// CREATE first: users made before v0.3 have no 127.0.0.1/::1 twin yet
		if _, err := db.ExecContext(ctx, "CREATE USER IF NOT EXISTS ?@? IDENTIFIED BY ?", p.User, host, p.Password); err != nil {
			return rpc.Empty{}, err
		}
		if _, err := db.ExecContext(ctx, "ALTER USER ?@? IDENTIFIED BY ?", p.User, host, p.Password); err != nil {
			return rpc.Empty{}, err
		}
	}
	return rpc.Empty{}, nil
}

func (a *Agent) dbUserDrop(ctx context.Context, p rpc.DBUserRef) (rpc.Empty, error) {
	if err := checkDBName(p.User); err != nil {
		return rpc.Empty{}, errf("invalid_db_user", "%s", p.User)
	}
	if err := checkOwned(p.Owner, p.User, "invalid_db_user"); err != nil {
		return rpc.Empty{}, err
	}
	hosts, err := dbHosts(p.Host)
	if err != nil {
		return rpc.Empty{}, err
	}
	db, err := a.mysql(ctx)
	if err != nil {
		return rpc.Empty{}, err
	}
	defer db.Close()
	for _, host := range hosts {
		if _, err := db.ExecContext(ctx, "DROP USER IF EXISTS ?@?", p.User, host); err != nil {
			return rpc.Empty{}, err
		}
	}
	return rpc.Empty{}, nil
}

var allowedPrivs = validate.DBPrivileges

// grantPrivileges validates a privilege list: ["ALL"] alone, or a non-empty
// subset of allowedPrivs.
func grantPrivileges(list []string) (string, error) {
	if len(list) == 0 {
		return "", errf("invalid_privilege", "no privileges given (use [\"ALL\"] for all privileges)")
	}
	if len(list) == 1 && strings.EqualFold(list[0], "ALL") {
		return "ALL PRIVILEGES", nil
	}
	seen := map[string]bool{}
	var out []string
	for _, pr := range list {
		if !allowedPrivs[pr] {
			return "", errf("invalid_privilege", "%s", pr)
		}
		if !seen[pr] {
			seen[pr] = true
			out = append(out, pr)
		}
	}
	return strings.Join(out, ", "), nil
}

func (a *Agent) dbGrant(ctx context.Context, p rpc.DBGrant) (rpc.Empty, error) {
	if err := checkDBName(p.DB); err != nil {
		return rpc.Empty{}, err
	}
	if err := checkDBName(p.User); err != nil {
		return rpc.Empty{}, errf("invalid_db_user", "%s", p.User)
	}
	if err := checkOwned(p.Owner, p.DB, "db_prefix_required"); err != nil {
		return rpc.Empty{}, err
	}
	if err := checkOwned(p.Owner, p.User, "invalid_db_user"); err != nil {
		return rpc.Empty{}, err
	}
	host, err := dbHost(p.Host)
	if err != nil {
		return rpc.Empty{}, err
	}
	// An empty list used to mean ALL PRIVILEGES, so a client that forgot to
	// fill it granted everything (UX-02 / handoff-ui H-4). Full rights must
	// now be asked for explicitly with ["ALL"].
	privs, err := grantPrivileges(p.Privileges)
	if err != nil {
		return rpc.Empty{}, err
	}
	db, err := a.mysql(ctx)
	if err != nil {
		return rpc.Empty{}, err
	}
	defer db.Close()
	// a missing previous grant (error 1141) is expected here
	if _, err := db.ExecContext(ctx, "REVOKE ALL PRIVILEGES ON "+grantIdent(p.DB)+".* FROM ?@?", p.User, host); err != nil &&
		!strings.Contains(err.Error(), "1141") {
		return rpc.Empty{}, err
	}
	if _, err = db.ExecContext(ctx, "GRANT "+privs+" ON "+grantIdent(p.DB)+".* TO ?@?", p.User, host); err != nil {
		return rpc.Empty{}, err
	}
	// mirror accounts (R2-SYS-15); a twin missing on a pre-v0.3 user is skipped (1133)
	if hosts, _ := dbHosts(p.Host); len(hosts) > 1 {
		for _, h := range hosts[1:] {
			if _, err := db.ExecContext(ctx, "REVOKE ALL PRIVILEGES ON "+grantIdent(p.DB)+".* FROM ?@?", p.User, h); err != nil &&
				!strings.Contains(err.Error(), "1141") && !strings.Contains(err.Error(), "1133") {
				return rpc.Empty{}, err
			}
			if _, err := db.ExecContext(ctx, "GRANT "+privs+" ON "+grantIdent(p.DB)+".* TO ?@?", p.User, h); err != nil &&
				!strings.Contains(err.Error(), "1133") {
				return rpc.Empty{}, err
			}
		}
	}
	return rpc.Empty{}, nil
}

func (a *Agent) dbRevoke(ctx context.Context, p rpc.DBGrant) (rpc.Empty, error) {
	if err := checkDBName(p.DB); err != nil {
		return rpc.Empty{}, err
	}
	if err := checkDBName(p.User); err != nil {
		return rpc.Empty{}, errf("invalid_db_user", "%s", p.User)
	}
	if err := checkOwned(p.Owner, p.DB, "db_prefix_required"); err != nil {
		return rpc.Empty{}, err
	}
	if err := checkOwned(p.Owner, p.User, "invalid_db_user"); err != nil {
		return rpc.Empty{}, err
	}
	host, err := dbHost(p.Host)
	if err != nil {
		return rpc.Empty{}, err
	}
	db, err := a.mysql(ctx)
	if err != nil {
		return rpc.Empty{}, err
	}
	defer db.Close()
	hosts := []string{host}
	if hs, _ := dbHosts(p.Host); len(hs) > 1 {
		hosts = hs // mirror accounts (R2-SYS-15)
	}
	for _, h := range hosts {
		_, err = db.ExecContext(ctx, "REVOKE ALL PRIVILEGES ON "+grantIdent(p.DB)+".* FROM ?@?", p.User, h)
		if err != nil && !strings.Contains(err.Error(), "1141") && !strings.Contains(err.Error(), "1133") { // no such grant / user
			return rpc.Empty{}, err
		}
	}
	return rpc.Empty{}, nil
}

func (a *Agent) dbSizes(ctx context.Context, p rpc.DBSizesReq) (rpc.DBSizes, error) {
	out := rpc.DBSizes{Sizes: map[string]int64{}}
	if err := validateDB(p.Prefix, p.Prefix); err != nil {
		return out, err
	}
	db, err := a.mysql(ctx)
	if err != nil {
		return out, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT table_schema, COALESCE(SUM(data_length+index_length),0)
		FROM information_schema.tables WHERE table_schema LIKE ? GROUP BY table_schema`, p.Prefix+`\_%`)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		var s int64
		if err := rows.Scan(&n, &s); err != nil {
			return out, err
		}
		out.Sizes[n] = s
	}
	return out, rows.Err()
}
