// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/rbac"
	"github.com/cumabozkurt/bpanel/internal/store"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// v0.4 dbx (spec §13): Remote MySQL (per-account allowed hosts mirrored as
// 'user'@'host' accounts), per-account MAX_USER_CONNECTIONS, process list
// and kill of the account's own queries, optional PostgreSQL engine.
// Every endpoint works on the caller's own account only; the agent re-checks
// the <owner>_ prefix of every name.

const dbxMaxHosts = 16

var dbxMu sync.Mutex // serialises remote syncs (DB state -> agent)

type RemoteHostReq struct {
	Host string `json:"host"`
	Note string `json:"note"`
}

type DBXKillReq struct {
	Engine string `json:"engine"`
	ID     int64  `json:"id"`
}

type DBXSettingsReq struct {
	RemoteEnabled bool `json:"remote_enabled"`
}

type DBXLimitReq struct {
	MaxUserConnections int `json:"max_user_connections"`
}

type PGCreateReq struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type PGPasswordReq struct {
	Password string `json:"password"`
}

func (s *Server) mountDbx(r chi.Router) {
	s.op(r, "GET", "/user/databases/remote", "databases", "Remote MySQL: allowed hosts of the own account", nil, s.h(s.listRemoteHosts))
	s.op(r, "POST", "/user/databases/remote", "databases", "Remote MySQL: allow a host (IP, IPv4 CIDR or hostname)", RemoteHostReq{}, s.h(s.addRemoteHost))
	s.op(r, "DELETE", "/user/databases/remote/{id}", "databases", "Remote MySQL: remove an allowed host", nil, s.h(s.deleteRemoteHost))
	s.op(r, "GET", "/user/databases/processes", "databases", "Running queries of the own database users (MariaDB + PostgreSQL)", nil, s.h(s.listDBProcesses))
	s.op(r, "POST", "/user/databases/processes/kill", "databases", "Cancel one running query of the own database users", DBXKillReq{}, s.h(s.killDBProcess))
	s.op(r, "GET", "/user/postgresql", "databases", "PostgreSQL status and own databases", nil, s.h(s.listPG))
	s.op(r, "POST", "/user/postgresql", "databases", "Create a PostgreSQL database with its login role (name prefixed with the username)", PGCreateReq{}, s.h(s.createPG))
	s.op(r, "DELETE", "/user/postgresql/{id}", "databases", "Delete a PostgreSQL database and its role", nil, s.h(s.deletePG))
	s.op(r, "PUT", "/user/postgresql/{id}/password", "databases", "Change the password of a PostgreSQL role", PGPasswordReq{}, s.h(s.passwordPG))
}

func (s *Server) mountDbxAdmin(r chi.Router) {
	s.opPerm(r, rbac.ServerRead, "GET", "/admin/dbx/settings", "databases", "Database engine settings (remote MySQL switch, PostgreSQL status)", nil, s.h(s.getDBXSettings))
	s.opPerm(r, rbac.ServerWrite, "PUT", "/admin/dbx/settings", "databases", "Allow or forbid remote MySQL server-wide (port 3306 is opened separately by a firewall rule)", DBXSettingsReq{}, s.h(s.putDBXSettings))
	s.opPerm(r, rbac.AccountsRead, "GET", "/admin/accounts/{id}/db-limits", "databases", "Database connection limit of an account", nil, s.h(s.getDBXLimit))
	s.opPerm(r, rbac.AccountsWrite, "PUT", "/admin/accounts/{id}/db-limits", "databases", "Set MAX_USER_CONNECTIONS (MariaDB) / CONNECTION LIMIT (PostgreSQL) of an account (0 = unlimited)", DBXLimitReq{}, s.h(s.putDBXLimit))
}

func (s *Server) remoteEnabled() bool { return s.Store.Get("dbx_remote_enabled", "0") == "1" }

// ---- remote MySQL ------------------------------------------------------------------

type remoteHostRow struct {
	ID        int64  `json:"id"`
	Host      string `json:"host"`
	MySQLHost string `json:"mysql_host"`
	Note      string `json:"note"`
	CreatedAt int64  `json:"created_at"`
}

func (s *Server) remoteHosts(ctx context.Context, uid int64) ([]remoteHostRow, error) {
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT id, host, note, created_at FROM dbx_remote_hosts WHERE user_id=? ORDER BY id`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []remoteHostRow{}
	for rows.Next() {
		var x remoteHostRow
		if err := rows.Scan(&x.ID, &x.Host, &x.Note, &x.CreatedAt); err != nil {
			return nil, err
		}
		x.MySQLHost, _ = validate.RemoteDBHost(x.Host)
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Server) dbxMaxConn(ctx context.Context, uid int64) int {
	var n int
	_ = s.Store.DB.QueryRowContext(ctx, `SELECT max_user_connections FROM dbx_limits WHERE user_id=?`, uid).Scan(&n)
	return n
}

// dbxSync pushes the account's complete remote/limit state to the agent.
func (s *Server) dbxSync(r *http.Request, u *store.User) error {
	dbxMu.Lock()
	defer dbxMu.Unlock()
	ctx := r.Context()
	hs, err := s.remoteHosts(ctx, u.ID)
	if err != nil {
		return err
	}
	p := rpc.DBXRemoteSync{Owner: u.Username, Hosts: []string{}, Users: []rpc.DBXRemoteUser{}, MaxConn: s.dbxMaxConn(ctx, u.ID)}
	if s.remoteEnabled() { // switched off server-wide: every remote account is dropped
		for _, h := range hs {
			p.Hosts = append(p.Hosts, h.Host)
		}
	}
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT du.name, COALESCE(d.name,''), COALESCE(g.privileges,'')
		FROM db_users du LEFT JOIN db_grants g ON g.dbuser_id=du.id LEFT JOIN databases d ON d.id=g.db_id
		WHERE du.user_id=? ORDER BY du.name, d.name`, u.ID)
	if err != nil {
		return err
	}
	idx := map[string]int{}
	for rows.Next() {
		var user, db, privs string
		if err := rows.Scan(&user, &db, &privs); err != nil {
			rows.Close()
			return err
		}
		if user == pmaUserName(u.Username) { // phpMyAdmin SSO user stays local-only
			continue
		}
		i, ok := idx[user]
		if !ok {
			i = len(p.Users)
			idx[user] = i
			p.Users = append(p.Users, rpc.DBXRemoteUser{User: user, Grants: []rpc.DBXGrant{}})
		}
		if db != "" && privs != "" {
			p.Users[i].Grants = append(p.Users[i].Grants, rpc.DBXGrant{DB: db, Privileges: strings.Split(privs, ",")})
		}
	}
	rows.Close()
	var res rpc.DBXRemoteResult
	return s.Agent.Call(ctx, rpc.MDBXRemoteSync, p, &res)
}

// dbxAfterDBChange re-syncs remote mirrors / limits after a MariaDB user or
// grant changed, when the account uses either (hooked from audit/agentCall).
func (s *Server) dbxAfterDBChange(r *http.Request, action string) {
	switch action {
	case "db.user_create", "db.grant", "db.revoke", "db.wizard", rpc.MDBUserPassword:
	default:
		return
	}
	if r == nil {
		return
	}
	u := userOf(r)
	if u == nil || u.Role != "user" {
		return
	}
	var n int
	if err := s.Store.DB.QueryRowContext(r.Context(), `SELECT (SELECT COUNT(*) FROM dbx_remote_hosts WHERE user_id=?) + (SELECT COUNT(*) FROM dbx_limits WHERE user_id=? AND max_user_connections>0)`, u.ID, u.ID).Scan(&n); err != nil || n == 0 {
		return
	}
	if err := s.dbxSync(r, u); err != nil {
		s.Log.Warn("dbx resync", "user", u.Username, "err", err)
	}
}

func (s *Server) listRemoteHosts(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	hs, err := s.remoteHosts(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"enabled": s.remoteEnabled(), "hosts": hs, "max_hosts": dbxMaxHosts, "port": 3306,
		"max_user_connections": s.dbxMaxConn(r.Context(), u.ID)}, nil
}

func (s *Server) addRemoteHost(w http.ResponseWriter, r *http.Request) (any, error) {
	var in RemoteHostReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	if !s.remoteEnabled() {
		return nil, conflict("remote_db_disabled")
	}
	host := strings.ToLower(strings.TrimSpace(in.Host))
	if _, err := validate.RemoteDBHost(host); err != nil {
		return nil, badField("invalid_remote_host", "host")
	}
	if len(in.Note) > 100 || strings.ContainsAny(in.Note, "\r\n\x00") {
		return nil, badField("invalid_note", "note")
	}
	var n int
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM dbx_remote_hosts WHERE user_id=?`, u.ID).Scan(&n)
	if n >= dbxMaxHosts {
		return nil, conflict("too_many_remote_hosts")
	}
	res, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO dbx_remote_hosts(user_id,host,note,created_at) VALUES(?,?,?,?)`, u.ID, host, in.Note, s.Now().Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if err := s.dbxSync(r, u); err != nil {
		s.deleteRow(r.Context(), "dbx_remote_hosts", id)
		return nil, err
	}
	s.audit(r, "dbx.remote_add", host, "", true)
	return map[string]any{"id": id, "host": host}, nil
}

func (s *Server) deleteRemoteHost(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	var host string
	if err := s.Store.DB.QueryRowContext(r.Context(), `SELECT host FROM dbx_remote_hosts WHERE id=? AND user_id=?`, idParam(r, "id"), u.ID).Scan(&host); err != nil {
		return nil, notFound()
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM dbx_remote_hosts WHERE id=? AND user_id=?`, idParam(r, "id"), u.ID); err != nil {
		return nil, err
	}
	if err := s.dbxSync(r, u); err != nil {
		return nil, err
	}
	s.audit(r, "dbx.remote_delete", host, "", true)
	return nil, nil
}

// ---- process list ---------------------------------------------------------------------

func (s *Server) listDBProcesses(w http.ResponseWriter, r *http.Request) (any, error) {
	var out rpc.DBXProcList
	if err := s.agentCall(r, rpc.MDBXProcessList, rpc.DBXProcReq{Owner: userOf(r).Username}, &out); err != nil {
		return nil, err
	}
	if out.Processes == nil {
		out.Processes = []rpc.DBXProcess{}
	}
	return out, nil
}

func (s *Server) killDBProcess(w http.ResponseWriter, r *http.Request) (any, error) {
	var in DBXKillReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if in.Engine != "mariadb" && in.Engine != "postgresql" {
		return nil, badField("invalid_engine", "engine")
	}
	if in.ID <= 0 {
		return nil, badField("invalid_process_id", "id")
	}
	u := userOf(r)
	if err := s.agentCall(r, rpc.MDBXKill, rpc.DBXKill{Owner: u.Username, Engine: in.Engine, ID: in.ID}, nil); err != nil {
		return nil, err
	}
	s.audit(r, "dbx.kill", in.Engine, "", true)
	return nil, nil
}

// ---- PostgreSQL ------------------------------------------------------------------------

type pgRow struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	SizeBytes int64  `json:"size_bytes"`
	CreatedAt int64  `json:"created_at"`
}

func (s *Server) pgStatus(r *http.Request) rpc.PGStatus {
	var st rpc.PGStatus
	if err := s.agentCall(r, rpc.MPGStatus, rpc.Empty{}, &st); err != nil {
		return rpc.PGStatus{Status: "unreachable", Reason: "agent"}
	}
	return st
}

func (s *Server) requirePG(r *http.Request) error {
	switch st := s.pgStatus(r); st.Status {
	case "ok":
		return nil
	case "not_installed":
		return &apiError{Status: 422, Code: "pg_not_installed", Message: st.Reason}
	default:
		return &apiError{Status: 503, Code: "pg_unreachable"}
	}
}

func (s *Server) listPG(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	st := s.pgStatus(r)
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT id, name, created_at FROM pg_databases WHERE user_id=? ORDER BY name`, u.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	dbs := []pgRow{}
	for rows.Next() {
		var x pgRow
		if err := rows.Scan(&x.ID, &x.Name, &x.CreatedAt); err != nil {
			return nil, err
		}
		x.Role = x.Name
		dbs = append(dbs, x)
	}
	if st.Status == "ok" && len(dbs) > 0 {
		var sz rpc.DBSizes
		if err := s.agentCall(r, rpc.MPGSizes, rpc.PGSizesReq{Owner: u.Username}, &sz); err == nil {
			for i := range dbs {
				dbs[i].SizeBytes = sz.Sizes[dbs[i].Name]
			}
		}
	}
	return map[string]any{"status": st, "databases": dbs, "prefix": u.Username + "_", "port": 5432}, nil
}

func (s *Server) ownPG(r *http.Request) (int64, string, error) {
	var name string
	id := idParam(r, "id")
	if err := s.Store.DB.QueryRowContext(r.Context(), `SELECT name FROM pg_databases WHERE id=? AND user_id=?`, id, userOf(r).ID).Scan(&name); err != nil {
		return 0, "", notFound()
	}
	return id, name, nil
}

func (s *Server) createPG(w http.ResponseWriter, r *http.Request) (any, error) {
	var in PGCreateReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	name := s.prefixed(u, in.Name)
	if len(name) > 63 {
		return nil, tooLong("name", 63-len(u.Username)-1)
	}
	if err := validate.DBName(u.Username, name); err != nil {
		return nil, badField(err.Error(), "name")
	}
	if err := passwordErr(in.Password, "password"); err != nil {
		return nil, err
	}
	if err := s.requirePG(r); err != nil {
		return nil, err
	}
	res, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO pg_databases(user_id,name,created_at) VALUES(?,?,?)`, u.ID, name, s.Now().Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if err := s.agentCall(r, rpc.MPGCreate, rpc.PGDB{Owner: u.Username, Name: name, Password: in.Password, MaxConn: s.dbxMaxConn(r.Context(), u.ID)}, nil); err != nil {
		s.deleteRow(r.Context(), "pg_databases", id)
		return nil, err
	}
	s.audit(r, "pg.create", name, "", true)
	return map[string]any{"id": id, "name": name, "role": name}, nil
}

func (s *Server) deletePG(w http.ResponseWriter, r *http.Request) (any, error) {
	id, name, err := s.ownPG(r)
	if err != nil {
		return nil, err
	}
	if err := s.requirePG(r); err != nil {
		return nil, err
	}
	if err := s.agentCall(r, rpc.MPGDrop, rpc.PGDB{Owner: userOf(r).Username, Name: name}, nil); err != nil {
		return nil, err
	}
	s.deleteRow(r.Context(), "pg_databases", id)
	s.audit(r, "pg.delete", name, "", true)
	return nil, nil
}

func (s *Server) passwordPG(w http.ResponseWriter, r *http.Request) (any, error) {
	var in PGPasswordReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	_, name, err := s.ownPG(r)
	if err != nil {
		return nil, err
	}
	if err := passwordErr(in.Password, "password"); err != nil {
		return nil, err
	}
	if err := s.requirePG(r); err != nil {
		return nil, err
	}
	if err := s.agentCall(r, rpc.MPGPassword, rpc.PGDB{Owner: userOf(r).Username, Name: name, Password: in.Password}, nil); err != nil {
		return nil, err
	}
	s.audit(r, "pg.password", name, "", true)
	return nil, nil
}

// ---- admin ---------------------------------------------------------------------------

func (s *Server) getDBXSettings(w http.ResponseWriter, r *http.Request) (any, error) {
	return map[string]any{"remote_enabled": s.remoteEnabled(), "postgresql": s.pgStatus(r), "mysql_port": 3306,
		"firewall_note": "remote MySQL needs an inbound TCP 3306 allow rule (Firewall page) and MariaDB bind-address not limited to 127.0.0.1"}, nil
}

func (s *Server) putDBXSettings(w http.ResponseWriter, r *http.Request) (any, error) {
	if userOf(r).Role != "admin" {
		return nil, forbidden()
	}
	var in DBXSettingsReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	v := "0"
	if in.RemoteEnabled {
		v = "1"
	}
	was := s.remoteEnabled()
	if err := s.Store.Set("dbx_remote_enabled", v); err != nil {
		return nil, err
	}
	s.audit(r, "dbx.remote_switch", v, "", true)
	if was != in.RemoteEnabled { // re-sync every account that has remote hosts
		users, err := store.Select[store.User](r.Context(), s.Store.DB, `SELECT * FROM users WHERE id IN (SELECT DISTINCT user_id FROM dbx_remote_hosts)`)
		if err != nil {
			return nil, err
		}
		failed := []string{}
		for i := range users {
			if err := s.dbxSync(r, &users[i]); err != nil {
				failed = append(failed, users[i].Username)
			}
		}
		return map[string]any{"ok": true, "failed": failed}, nil
	}
	return nil, nil
}

func (s *Server) getDBXLimit(w http.ResponseWriter, r *http.Request) (any, error) {
	u, err := s.visibleAccount(r)
	if err != nil {
		return nil, err
	}
	return map[string]any{"max_user_connections": s.dbxMaxConn(r.Context(), u.ID)}, nil
}

func (s *Server) putDBXLimit(w http.ResponseWriter, r *http.Request) (any, error) {
	u, err := s.manageableAccount(r)
	if err != nil {
		return nil, err
	}
	var in DBXLimitReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if in.MaxUserConnections < 0 || in.MaxUserConnections > 10000 {
		return nil, badField("invalid_max_connections", "max_user_connections")
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO dbx_limits(user_id,max_user_connections,updated_at) VALUES(?,?,?)
		ON CONFLICT(user_id) DO UPDATE SET max_user_connections=excluded.max_user_connections, updated_at=excluded.updated_at`, u.ID, in.MaxUserConnections, s.Now().Unix()); err != nil {
		return nil, err
	}
	if err := s.dbxSync(r, &u); err != nil {
		return nil, err
	}
	var names []string
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT name FROM pg_databases WHERE user_id=?`, u.ID)
	if err == nil {
		for rows.Next() {
			var n string
			if rows.Scan(&n) == nil {
				names = append(names, n)
			}
		}
		rows.Close()
	}
	if len(names) > 0 && s.pgStatus(r).Status == "ok" {
		if err := s.agentCall(r, rpc.MPGLimit, rpc.PGLimit{Owner: u.Username, Names: names, MaxConn: in.MaxUserConnections}, nil); err != nil {
			return nil, err
		}
	}
	s.audit(r, "dbx.limit", u.Username, "", true)
	return nil, nil
}
