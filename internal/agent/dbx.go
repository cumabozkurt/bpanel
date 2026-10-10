// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"database/sql"
	"strconv"
	"strings"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// v0.4 dbx (MariaDB side): remote hosts, MAX_USER_CONNECTIONS, process list
// and kill of the owner's own queries. Every name is checked against the
// owner prefix here again; the API is not trusted for tenancy.

const dbxMaxHosts = 16
const dbxMaxConn = 10000

var localDBHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}

// authPlugins whose stored hash can be copied verbatim with IDENTIFIED VIA ... USING.
var authPlugins = map[string]bool{"mysql_native_password": true, "ed25519": true, "parsec": true}

// likePrefix returns a LIKE pattern matching "<owner>_<anything>".
func likePrefix(owner string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(owner) + `\_%`
}

func dbxOwner(owner string) error {
	if owner == "" {
		return errf("owner_required", "no owning account given")
	}
	if err := validate.Username(owner); err != nil {
		return errf("invalid_username", "%s", owner)
	}
	return nil
}

// dbxHosts validates the requested remote hosts and returns their MariaDB form.
func dbxHosts(in []string) ([]string, error) {
	if len(in) > dbxMaxHosts {
		return nil, errf("too_many_remote_hosts", "at most %d", dbxMaxHosts)
	}
	seen := map[string]bool{}
	var out []string
	for _, h := range in {
		m, err := validate.RemoteDBHost(h)
		if err != nil {
			return nil, errf("invalid_remote_host", "%q", h)
		}
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out, nil
}

func (a *Agent) dbxRemoteSync(ctx context.Context, p rpc.DBXRemoteSync) (rpc.DBXRemoteResult, error) {
	res := rpc.DBXRemoteResult{Created: []string{}, Dropped: []string{}, Skipped: []string{}}
	if err := dbxOwner(p.Owner); err != nil {
		return res, err
	}
	hosts, err := dbxHosts(p.Hosts)
	if err != nil {
		return res, err
	}
	if p.MaxConn < 0 || p.MaxConn > dbxMaxConn {
		return res, errf("invalid_max_connections", "%d", p.MaxConn)
	}
	type grant struct{ db, privs string }
	users := map[string][]grant{}
	for _, u := range p.Users {
		if err := checkDBName(u.User); err != nil || len(u.User) > 32 {
			return res, errf("invalid_db_user", "%s", u.User)
		}
		if err := checkOwned(p.Owner, u.User, "invalid_db_user"); err != nil {
			return res, err
		}
		gs := []grant{}
		for _, g := range u.Grants {
			if err := checkDBName(g.DB); err != nil {
				return res, err
			}
			if err := checkOwned(p.Owner, g.DB, "db_prefix_required"); err != nil {
				return res, err
			}
			pr, err := grantPrivileges(g.Privileges)
			if err != nil {
				return res, err
			}
			gs = append(gs, grant{g.DB, pr})
		}
		users[u.User] = gs
	}
	db, err := a.mysql(ctx)
	if err != nil {
		return res, err
	}
	defer db.Close()
	allowed := map[string]bool{}
	for _, h := range hosts {
		allowed[h] = true
	}
	// 1. drop remote accounts of <owner>_ users that are no longer wanted
	rows, err := db.QueryContext(ctx, "SELECT User, Host FROM mysql.user WHERE User LIKE ?", likePrefix(p.Owner))
	if err != nil {
		return res, err
	}
	type acct struct{ u, h string }
	var existing []acct
	for rows.Next() {
		var x acct
		if err := rows.Scan(&x.u, &x.h); err != nil {
			rows.Close()
			return res, err
		}
		existing = append(existing, x)
	}
	rows.Close()
	for _, x := range existing {
		if !strings.HasPrefix(x.u, p.Owner+"_") || localDBHosts[x.h] {
			continue
		}
		if _, want := users[x.u]; want && allowed[x.h] {
			continue
		}
		if _, err := db.ExecContext(ctx, "DROP USER IF EXISTS ?@?", x.u, x.h); err != nil {
			return res, err
		}
		res.Dropped = append(res.Dropped, x.u+"@"+x.h)
	}
	limit := " WITH MAX_USER_CONNECTIONS " + strconv.Itoa(p.MaxConn)
	// 2. mirror every user to every allowed host
	for user, gs := range users {
		var hash, plugin string
		err := db.QueryRowContext(ctx, "SELECT authentication_string, plugin FROM mysql.user WHERE User=? AND Host='localhost'", user).Scan(&hash, &plugin)
		if err == sql.ErrNoRows {
			res.Skipped = append(res.Skipped, user)
			continue
		}
		if err != nil {
			return res, err
		}
		for _, h := range []string{"localhost", "127.0.0.1", "::1"} {
			// connection limit applies to the local accounts too (1133: missing pre-v0.3 twin)
			if _, err := db.ExecContext(ctx, "ALTER USER ?@?"+limit, user, h); err != nil && !strings.Contains(err.Error(), "1133") && !strings.Contains(err.Error(), "1396") {
				return res, err
			}
		}
		if len(hosts) == 0 {
			continue
		}
		if !authPlugins[plugin] || hash == "" {
			res.Skipped = append(res.Skipped, user)
			continue
		}
		for _, h := range hosts {
			if _, err := db.ExecContext(ctx, "CREATE USER IF NOT EXISTS ?@? IDENTIFIED VIA "+plugin+" USING ?", user, h, hash); err != nil {
				return res, err
			}
			if _, err := db.ExecContext(ctx, "ALTER USER ?@? IDENTIFIED VIA "+plugin+" USING ?"+limit, user, h, hash); err != nil {
				return res, err
			}
			// exact mirror: drop everything, then grant what the local account has
			if _, err := db.ExecContext(ctx, "REVOKE ALL PRIVILEGES, GRANT OPTION FROM ?@?", user, h); err != nil && !strings.Contains(err.Error(), "1141") {
				return res, err
			}
			for _, g := range gs {
				if _, err := db.ExecContext(ctx, "GRANT "+g.privs+" ON "+grantIdent(g.db)+".* TO ?@?", user, h); err != nil {
					return res, err
				}
			}
			res.Created = append(res.Created, user+"@"+h)
		}
	}
	return res, nil
}

// ---- process list ---------------------------------------------------------------

func (a *Agent) dbxProcessList(ctx context.Context, p rpc.DBXProcReq) (rpc.DBXProcList, error) {
	out := rpc.DBXProcList{Processes: []rpc.DBXProcess{}}
	if err := dbxOwner(p.Owner); err != nil {
		return out, err
	}
	out.MariaDB = rpc.DBXEngineStatus{Status: "ok"}
	if db, err := a.mysql(ctx); err != nil {
		out.MariaDB = rpc.DBXEngineStatus{Status: "unreachable", Reason: "mariadb_unreachable"}
	} else {
		ps, err := mariaProcs(ctx, db, p.Owner)
		db.Close()
		if err != nil {
			return out, err
		}
		out.Processes = append(out.Processes, ps...)
	}
	ps, st := pgProcs(ctx, p.Owner)
	out.PostgreSQL = st
	out.Processes = append(out.Processes, ps...)
	return out, nil
}

func mariaProcs(ctx context.Context, db *sql.DB, owner string) ([]rpc.DBXProcess, error) {
	rows, err := db.QueryContext(ctx, `SELECT ID, USER, COALESCE(HOST,''), COALESCE(DB,''), COALESCE(COMMAND,''), COALESCE(TIME,0),
		COALESCE(STATE,''), COALESCE(LEFT(INFO,300),'') FROM information_schema.PROCESSLIST WHERE USER LIKE ? ORDER BY TIME DESC LIMIT 200`, likePrefix(owner))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []rpc.DBXProcess{}
	for rows.Next() {
		x := rpc.DBXProcess{Engine: "mariadb"}
		if err := rows.Scan(&x.ID, &x.User, &x.Host, &x.DB, &x.Command, &x.Seconds, &x.State, &x.Query); err != nil {
			return nil, err
		}
		if strings.HasPrefix(x.User, owner+"_") { // defence in depth over LIKE
			out = append(out, x)
		}
	}
	return out, rows.Err()
}

func (a *Agent) dbxKill(ctx context.Context, p rpc.DBXKill) (rpc.Empty, error) {
	if err := dbxOwner(p.Owner); err != nil {
		return rpc.Empty{}, err
	}
	if p.ID <= 0 || p.ID > 1<<62 {
		return rpc.Empty{}, errf("invalid_process_id", "%d", p.ID)
	}
	switch p.Engine {
	case "mariadb":
		db, err := a.mysql(ctx)
		if err != nil {
			return rpc.Empty{}, err
		}
		defer db.Close()
		var user string
		if err := db.QueryRowContext(ctx, "SELECT USER FROM information_schema.PROCESSLIST WHERE ID=?", p.ID).Scan(&user); err != nil || !strings.HasPrefix(user, p.Owner+"_") {
			return rpc.Empty{}, errf("not_found", "no such query of %s", p.Owner)
		}
		_, err = db.ExecContext(ctx, "KILL QUERY "+strconv.FormatInt(p.ID, 10))
		if err != nil && strings.Contains(err.Error(), "1094") { // finished meanwhile
			return rpc.Empty{}, errf("not_found", "query finished")
		}
		return rpc.Empty{}, err
	case "postgresql":
		return rpc.Empty{}, pgKill(ctx, p.Owner, p.ID)
	}
	return rpc.Empty{}, errf("invalid_engine", "%s", p.Engine)
}
