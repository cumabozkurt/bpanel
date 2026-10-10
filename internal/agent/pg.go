// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// v0.4 dbx: optional PostgreSQL engine (PostgreSQL License, run as an
// external program; nothing is linked). Every statement is a constant
// script fed to `psql` on stdin, running as the postgres OS user via
// runuser, with -X (no psqlrc) and ON_ERROR_STOP=1. Names and values reach
// SQL only as psql variables (-v name=value, used as :"name" / :'name', which
// psql quotes) or through format('%I','%L') server-side; never by string
// interpolation. Names are additionally validated ([a-z0-9_], <owner>_
// prefix, <= 63 bytes). Passwords never leave the agent in clear: they are
// turned into a SCRAM-SHA-256 verifier here.

// pgExec runs one command; replaced by tests.
var pgExec = func(ctx context.Context, name string, args []string, stdin string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/nonexistent", "LC_ALL=C"}
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), errf("pg_failed", "%v %s", err, lastLines(errb.String(), 3))
	}
	return out.String(), nil
}

// pgFind locates a PostgreSQL client tool (psql, pg_dump, pg_restore).
var pgFind = func(tool string) string {
	if p, err := exec.LookPath(tool); err == nil {
		return p
	}
	for _, g := range []string{"/usr/lib/postgresql/*/bin/" + tool, "/usr/pgsql-*/bin/" + tool, "/usr/bin/" + tool} {
		if m, _ := filepath.Glob(g); len(m) > 0 {
			return m[len(m)-1]
		}
	}
	return ""
}

func runuserBin() string {
	for _, p := range []string{"/usr/sbin/runuser", "/sbin/runuser", "/usr/bin/runuser"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "runuser"
}

const pgSep, pgRec = "\x1f", "\x1e"

// psql runs script as postgres with the given variables.
func psql(ctx context.Context, vars [][2]string, script string) (string, error) {
	bin := pgFind("psql")
	if bin == "" {
		return "", errf("pg_not_installed", "psql was not found")
	}
	args := []string{"-u", "postgres", "--", bin, "-X", "-q", "-A", "-t", "-F", pgSep, "-R", pgRec, "-v", "ON_ERROR_STOP=1", "-d", "postgres"}
	for _, v := range vars {
		if strings.ContainsAny(v[0]+v[1], "\x00\n\r") {
			return "", errf("bad_params", "control character in %s", v[0])
		}
		args = append(args, "-v", v[0]+"="+v[1])
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return pgExec(cctx, runuserBin(), args, script)
}

func pgRecords(out string) [][]string {
	var r [][]string
	for _, rec := range strings.Split(strings.TrimRight(out, "\n"+pgRec), pgRec) {
		rec = strings.TrimPrefix(rec, "\n")
		if rec != "" {
			r = append(r, strings.Split(rec, pgSep))
		}
	}
	return r
}

func pgName(owner, name string) error {
	if len(name) > 63 {
		return errf("invalid_db_name", "%s", name)
	}
	if err := checkDBName(name); err != nil {
		return err
	}
	return checkOwned(owner, name, "db_prefix_required")
}

var reVerifier = regexp.MustCompile(`^SCRAM-SHA-256\$4096:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$`)

// scramVerifier builds the SCRAM-SHA-256 verifier PostgreSQL stores (RFC 5802/7677).
func scramVerifier(pw string) (string, error) {
	if len(pw) < 8 {
		return "", errf("password_too_short", "")
	}
	for _, c := range pw { // SASLprep of non-ASCII is not implemented: refuse instead of storing a hash the server would not match
		if c < 0x20 || c > 0x7e {
			return "", errf("password_not_ascii", "")
		}
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	salted, err := pbkdf2.Key(sha256.New, pw, salt, 4096, 32)
	if err != nil {
		return "", err
	}
	mac := func(k []byte, s string) []byte { h := hmac.New(sha256.New, k); h.Write([]byte(s)); return h.Sum(nil) }
	ck := mac(salted, "Client Key")
	stored := sha256.Sum256(ck)
	sk := mac(salted, "Server Key")
	b := base64.StdEncoding.EncodeToString
	return "SCRAM-SHA-256$4096:" + b(salt) + "$" + b(stored[:]) + ":" + b(sk), nil
}

func pgConnLimit(n int) (string, error) {
	if n < 0 || n > dbxMaxConn {
		return "", errf("invalid_max_connections", "%d", n)
	}
	if n == 0 {
		return "-1", nil
	}
	return strconv.Itoa(n), nil
}

func (a *Agent) pgStatus(ctx context.Context, _ rpc.Empty) (rpc.PGStatus, error) {
	if pgFind("psql") == "" {
		return rpc.PGStatus{Status: "not_installed", Reason: "PostgreSQL client (psql) was not found; enable the installer's PostgreSQL option"}, nil
	}
	out, err := psql(ctx, nil, "SELECT current_setting('server_version');\n")
	if err != nil {
		return rpc.PGStatus{Status: "unreachable", Reason: "the PostgreSQL server did not answer"}, nil
	}
	return rpc.PGStatus{Status: "ok", Version: strings.TrimSpace(strings.Trim(out, pgRec+"\n"))}, nil
}

const pgCreateScript = `SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L', :'role', :'verifier') WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role') \gexec
ALTER ROLE :"role" PASSWORD :'verifier';
ALTER ROLE :"role" CONNECTION LIMIT :connlimit;
SELECT format('CREATE DATABASE %I OWNER %I ENCODING %L TEMPLATE template0', :'db', :'role', 'UTF8') WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db') \gexec
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"db" TO :"role";
`

const pgDropScript = `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = :'db' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS :"db";
DROP ROLE IF EXISTS :"role";
`

const pgPasswordScript = `ALTER ROLE :"role" PASSWORD :'verifier';
`

const pgLimitScript = `ALTER ROLE :"role" CONNECTION LIMIT :connlimit;
`

const pgSizesScript = `SELECT datname, pg_database_size(datname) FROM pg_database WHERE datname LIKE :'pat' ORDER BY 1;
`

const pgProcsScript = `SELECT pid, usename, COALESCE(client_addr::text,''), COALESCE(datname,''), COALESCE(state,''), COALESCE(wait_event_type,''),
 COALESCE(EXTRACT(EPOCH FROM (now() - query_start))::bigint, 0), left(translate(COALESCE(query,''), E'\x1e\x1f', '  '), 300)
 FROM pg_stat_activity WHERE usename LIKE :'pat' AND backend_type = 'client backend' AND pid <> pg_backend_pid() ORDER BY 7 DESC LIMIT 200;
`

const pgKillScript = `SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE pid = :'pid'::int AND usename LIKE :'pat';
`

func (a *Agent) pgCreate(ctx context.Context, p rpc.PGDB) (rpc.Empty, error) {
	if err := pgName(p.Owner, p.Name); err != nil {
		return rpc.Empty{}, err
	}
	lim, err := pgConnLimit(p.MaxConn)
	if err != nil {
		return rpc.Empty{}, err
	}
	v, err := scramVerifier(p.Password)
	if err != nil {
		return rpc.Empty{}, err
	}
	_, err = psql(ctx, [][2]string{{"db", p.Name}, {"role", p.Name}, {"verifier", v}, {"connlimit", lim}}, pgCreateScript)
	return rpc.Empty{}, err
}

func (a *Agent) pgDrop(ctx context.Context, p rpc.PGDB) (rpc.Empty, error) {
	if err := pgName(p.Owner, p.Name); err != nil {
		return rpc.Empty{}, err
	}
	_, err := psql(ctx, [][2]string{{"db", p.Name}, {"role", p.Name}}, pgDropScript)
	return rpc.Empty{}, err
}

func (a *Agent) pgPassword(ctx context.Context, p rpc.PGDB) (rpc.Empty, error) {
	if err := pgName(p.Owner, p.Name); err != nil {
		return rpc.Empty{}, err
	}
	v, err := scramVerifier(p.Password)
	if err != nil {
		return rpc.Empty{}, err
	}
	if !reVerifier.MatchString(v) {
		return rpc.Empty{}, errf("pg_failed", "verifier")
	}
	_, err = psql(ctx, [][2]string{{"role", p.Name}, {"verifier", v}}, pgPasswordScript)
	return rpc.Empty{}, err
}

func (a *Agent) pgLimit(ctx context.Context, p rpc.PGLimit) (rpc.Empty, error) {
	if err := dbxOwner(p.Owner); err != nil {
		return rpc.Empty{}, err
	}
	lim, err := pgConnLimit(p.MaxConn)
	if err != nil {
		return rpc.Empty{}, err
	}
	for _, n := range p.Names {
		if err := pgName(p.Owner, n); err != nil {
			return rpc.Empty{}, err
		}
	}
	for _, n := range p.Names {
		if _, err := psql(ctx, [][2]string{{"role", n}, {"connlimit", lim}}, pgLimitScript); err != nil {
			return rpc.Empty{}, err
		}
	}
	return rpc.Empty{}, nil
}

func (a *Agent) pgSizes(ctx context.Context, p rpc.PGSizesReq) (rpc.DBSizes, error) {
	out := rpc.DBSizes{Sizes: map[string]int64{}}
	if err := dbxOwner(p.Owner); err != nil {
		return out, err
	}
	res, err := psql(ctx, [][2]string{{"pat", likePrefix(p.Owner)}}, pgSizesScript)
	if err != nil {
		return out, err
	}
	for _, r := range pgRecords(res) {
		if len(r) == 2 && strings.HasPrefix(r[0], p.Owner+"_") {
			n, _ := strconv.ParseInt(r[1], 10, 64)
			out.Sizes[r[0]] = n
		}
	}
	return out, nil
}

func pgProcs(ctx context.Context, owner string) ([]rpc.DBXProcess, rpc.DBXEngineStatus) {
	if pgFind("psql") == "" {
		return nil, rpc.DBXEngineStatus{Status: "not_installed"}
	}
	res, err := psql(ctx, [][2]string{{"pat", likePrefix(owner)}}, pgProcsScript)
	if err != nil {
		return nil, rpc.DBXEngineStatus{Status: "unreachable", Reason: "pg_failed"}
	}
	var out []rpc.DBXProcess
	for _, r := range pgRecords(res) {
		if len(r) != 8 || !strings.HasPrefix(r[1], owner+"_") {
			continue
		}
		id, _ := strconv.ParseInt(r[0], 10, 64)
		sec, _ := strconv.ParseInt(r[6], 10, 64)
		out = append(out, rpc.DBXProcess{Engine: "postgresql", ID: id, User: r[1], Host: r[2], DB: r[3], State: r[4], Command: r[5], Seconds: sec, Query: r[7]})
	}
	return out, rpc.DBXEngineStatus{Status: "ok"}
}

func pgKill(ctx context.Context, owner string, pid int64) error {
	if pid > 1<<31-1 {
		return errf("invalid_process_id", "%d", pid)
	}
	res, err := psql(ctx, [][2]string{{"pid", strconv.FormatInt(pid, 10)}, {"pat", likePrefix(owner)}}, pgKillScript)
	if err != nil {
		return err
	}
	if !strings.Contains(res, "t") {
		return errf("not_found", "no such query of %s", owner)
	}
	return nil
}

// ---- backup hooks (called from backupRun / backupRestore in misc.go) -----------

// pgBackup dumps every PostgreSQL database of the account (pg_dump -Fc,
// no owner/ACL) into the restic repository as /pg_<db>.dump. Nothing to do
// when PostgreSQL is not installed.
func (a *Agent) pgBackup(ctx context.Context, env []string, user string, res *rpc.BackupRunResult) error {
	if pgFind("psql") == "" || pgFind("pg_dump") == "" {
		return nil
	}
	sz, err := a.pgSizes(ctx, rpc.PGSizesReq{Owner: user})
	if err != nil {
		return err
	}
	for db := range sz.Sizes {
		if err := pgName(user, db); err != nil {
			return err
		}
		dump := exec.CommandContext(ctx, runuserBin(), "-u", "postgres", "--", pgFind("pg_dump"), "-Fc", "--no-owner", "--no-privileges", "-d", db)
		dump.Dir = "/"
		dump.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
		bk := exec.CommandContext(ctx, a.Cfg.ResticBin, "backup", "--json", "--tag", "pgdb,"+db, "--stdin", "--stdin-filename", "pg_"+db+".dump")
		bk.Env = env
		pipe, err := dump.StdoutPipe()
		if err != nil {
			return err
		}
		bk.Stdin = pipe
		var bout, berr, derr bytes.Buffer
		bk.Stdout, bk.Stderr, dump.Stderr = &bout, &berr, &derr
		if err := bk.Start(); err != nil {
			return err
		}
		if err := dump.Run(); err != nil {
			_ = bk.Process.Kill()
			_ = bk.Wait()
			return errf("dump_failed", "%s: %v %s", db, err, lastLines(derr.String(), 5))
		}
		if err := bk.Wait(); err != nil {
			return errf("backup_failed", "%s: %v %s", db, err, lastLines(berr.String(), 5))
		}
		res.SnapshotIDs = append(res.SnapshotIDs, snapshotFromJSON(bout.String()))
	}
	return nil
}

// restorePG replays /pg_<db>.dump of a snapshot into the existing database
// with pg_restore --role=<db role>, so the archive runs with the tenant
// role's rights only, never as superuser.
func (a *Agent) restorePG(ctx context.Context, env []string, p rpc.BackupRestore, db string) (rpc.BackupRestoreResult, error) {
	var res rpc.BackupRestoreResult
	if err := pgName(p.User, db); err != nil {
		return res, err
	}
	bin := pgFind("pg_restore")
	if bin == "" {
		return res, errf("pg_not_installed", "pg_restore was not found")
	}
	file := "/pg_" + db + ".dump"
	if out, err := a.restic(ctx, env, "ls", "--json", p.Snapshot, file); err != nil || !strings.Contains(out, `"`+file+`"`) {
		return res, errf("snapshot_kind_mismatch", "snapshot %s holds no dump of %s", p.Snapshot, db)
	}
	dump := exec.CommandContext(ctx, a.Cfg.ResticBin, "dump", p.Snapshot, file)
	dump.Env = env
	imp := exec.CommandContext(ctx, runuserBin(), "-u", "postgres", "--", bin, "--clean", "--if-exists", "--no-owner", "--no-privileges",
		"--exit-on-error", "--single-transaction", "--role="+db, "-d", db)
	imp.Dir = "/"
	imp.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	pipe, err := dump.StdoutPipe()
	if err != nil {
		return res, err
	}
	imp.Stdin = pipe
	var ierr bytes.Buffer
	imp.Stderr = &ierr
	if err := imp.Start(); err != nil {
		return res, err
	}
	if err := dump.Run(); err != nil {
		_ = imp.Process.Kill()
		_ = imp.Wait()
		return res, errf("restore_failed", "%v", err)
	}
	if err := imp.Wait(); err != nil {
		return res, errf("restore_failed", "%s: %v %s", db, err, lastLines(ierr.String(), 5))
	}
	res.RestoredTo = "postgresql database " + db
	return res, nil
}
