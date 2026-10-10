package api

// v0.4 backup module: restore verification results, "verify now" and
// admin-only snapshot deletion. The agent does the work (internal/backup);
// the panel only stores results in backup_verifications (0009_backup.sql).

import (
	"context"
	"database/sql"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/rbac"
)

// BackupVerifyInterval is how old an account's last verification may be
// before the housekeeping loop verifies it again.
const BackupVerifyInterval = 7 * 24 * time.Hour

var (
	verifyMu   sync.Mutex // one verification at a time, panel-wide
	snapIDAPIr = regexp.MustCompile(`^[0-9a-f]{8,64}$`)
)

type BackupVerificationRow struct {
	ID           int64  `json:"id"`
	AccountID    int64  `json:"account_id"`
	Username     string `json:"username"`
	SnapshotID   string `json:"snapshot_id"`
	StartedAt    int64  `json:"started_at"`
	FinishedAt   int64  `json:"finished_at"`
	FilesChecked int    `json:"files_checked"`
	Mismatches   int    `json:"mismatches"`
	CheckOK      bool   `json:"check_ok"`
	Status       string `json:"status"`
	Error        string `json:"error"`
	Trigger      string `json:"trigger"`
}

func (s *Server) mountBackupVerify(r chi.Router) {
	s.opPerm(r, rbac.BackupsRead, "GET", "/admin/backups/verifications", "backup", "Backup restore verification results (?account=id, latest 100)", nil, s.h(s.listBackupVerifications))
	s.opPerm(r, rbac.BackupsVerify, "POST", "/admin/accounts/{id}/backups/verify", "backup", "Restore the latest snapshot into a temp dir and verify it now", nil, s.h(s.verifyBackupNow))
	s.opPerm(r, rbac.BackupsDelete, "DELETE", "/admin/accounts/{id}/backups/{snap}", "backup", "Delete (forget + prune) one backup snapshot", nil, s.idempotent(s.h(s.deleteBackupSnapshot)))
}

// mountBackupVerifyUser: own account's last verification (read-only).
func (s *Server) mountBackupVerifyUser(r chi.Router) {
	s.op(r, "GET", "/user/backups/verification", "backup", "Last restore verification of the own account", nil, s.h(s.ownBackupVerification))
}

const bvCols = `id, account_id, username, snapshot_id, started_at, finished_at, files_checked, mismatches, check_ok, status, error, trigger`

func scanBV(sc interface{ Scan(...any) error }) (BackupVerificationRow, error) {
	var v BackupVerificationRow
	var ok int
	err := sc.Scan(&v.ID, &v.AccountID, &v.Username, &v.SnapshotID, &v.StartedAt, &v.FinishedAt, &v.FilesChecked, &v.Mismatches, &ok, &v.Status, &v.Error, &v.Trigger)
	v.CheckOK = ok == 1
	return v, err
}

func (s *Server) listBackupVerifications(w http.ResponseWriter, r *http.Request) (any, error) {
	q := `SELECT ` + bvCols + ` FROM backup_verifications`
	var args []any
	if acc := idQuery(r, "account"); acc > 0 {
		if !s.canManageAccount(r, acc) {
			return nil, forbidden()
		}
		q += ` WHERE account_id=?`
		args = append(args, acc)
	}
	rows, err := s.Store.DB.QueryContext(r.Context(), q+` ORDER BY started_at DESC, id DESC LIMIT 100`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BackupVerificationRow{}
	for rows.Next() {
		v, err := scanBV(rows)
		if err != nil {
			return nil, err
		}
		if acc := idQuery(r, "account"); acc == 0 && !s.canManageAccount(r, v.AccountID) {
			continue
		}
		out = append(out, v)
	}
	return map[string]any{"verifications": out}, rows.Err()
}

func idQuery(r *http.Request, k string) int64 {
	var id int64
	for _, c := range r.URL.Query().Get(k) {
		if c < '0' || c > '9' || id > 1<<50 {
			return 0
		}
		id = id*10 + int64(c-'0')
	}
	return id
}

func (s *Server) accountName(ctx context.Context, id int64) (string, error) {
	var name string
	err := s.Store.DB.QueryRowContext(ctx, `SELECT username FROM users WHERE id=? AND role='user'`, id).Scan(&name)
	if err == sql.ErrNoRows {
		return "", notFound()
	}
	return name, err
}

// runBackupVerify records a row, calls the agent and stores the result.
func (s *Server) runBackupVerify(ctx context.Context, id int64, user, trigger string) (BackupVerificationRow, error) {
	if !verifyMu.TryLock() {
		return BackupVerificationRow{}, &apiError{Status: 409, Code: "server_busy"}
	}
	defer verifyMu.Unlock()
	now := time.Now().Unix()
	res, err := s.Store.DB.ExecContext(ctx, `INSERT INTO backup_verifications(account_id, username, started_at, status, trigger) VALUES(?,?,?,?,?)`, id, user, now, "running", trigger)
	if err != nil {
		return BackupVerificationRow{}, err
	}
	rid, _ := res.LastInsertId()
	var out rpc.BackupVerification
	callErr := s.agentCallCtx(ctx, rpc.MBackupVerify, rpc.BackupVerify{User: user}, &out) // pushes secret-store creds first
	if callErr != nil {
		out.Status, out.Error = "error", agentCode(callErr)
	}
	ok := 0
	if out.CheckOK {
		ok = 1
	}
	if len(out.Error) > 1000 {
		out.Error = out.Error[:1000]
	}
	_, err = s.Store.DB.ExecContext(context.WithoutCancel(ctx), `UPDATE backup_verifications SET snapshot_id=?, finished_at=?, files_checked=?, mismatches=?, check_ok=?, status=?, error=? WHERE id=?`,
		out.SnapshotID, time.Now().Unix(), out.FilesChecked, out.Mismatches, ok, out.Status, out.Error, rid)
	if err != nil {
		return BackupVerificationRow{}, err
	}
	return scanBV(s.Store.DB.QueryRowContext(context.WithoutCancel(ctx), `SELECT `+bvCols+` FROM backup_verifications WHERE id=?`, rid))
}

func (s *Server) verifyBackupNow(w http.ResponseWriter, r *http.Request) (any, error) {
	id := idParam(r, "id")
	if !s.canManageAccount(r, id) {
		return nil, forbidden()
	}
	user, err := s.accountName(r.Context(), id)
	if err != nil {
		return nil, err
	}
	v, err := s.runBackupVerify(r.Context(), id, user, "manual")
	if err != nil {
		s.audit(r, "backup.verify", user, "error", false)
		return nil, err
	}
	s.audit(r, "backup.verify", user, v.Status, v.Status == "ok")
	return v, nil
}

func (s *Server) deleteBackupSnapshot(w http.ResponseWriter, r *http.Request) (any, error) {
	id := idParam(r, "id")
	snap := chi.URLParam(r, "snap")
	if !s.canManageAccount(r, id) {
		return nil, forbidden()
	}
	if !snapIDAPIr.MatchString(snap) {
		return nil, &apiError{Status: 400, Code: "invalid_snapshot"}
	}
	user, err := s.accountName(r.Context(), id)
	if err != nil {
		return nil, err
	}
	if err := s.agentCall(r, rpc.MBackupDelete, rpc.BackupDelete{User: user, Snapshot: snap}, nil); err != nil {
		s.audit(r, "backup.delete", user, snap+" "+agentCode(err), false)
		return nil, err
	}
	s.audit(r, "backup.delete", user, snap, true)
	return map[string]any{"ok": true}, nil
}

func (s *Server) ownBackupVerification(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	v, err := scanBV(s.Store.DB.QueryRowContext(r.Context(), `SELECT `+bvCols+` FROM backup_verifications WHERE account_id=? AND status<>'running' ORDER BY started_at DESC, id DESC LIMIT 1`, u.ID))
	if err == sql.ErrNoRows {
		return map[string]any{"verification": nil}, nil
	}
	if err != nil {
		return nil, err
	}
	v.Error = "" // agent detail is for admins
	return map[string]any{"verification": v}, nil
}

// backupVerifyTick (housekeeping): verify at most ONE account per tick whose
// last verification is older than BackupVerifyInterval, bounded by a timeout.
func (s *Server) backupVerifyTick(ctx context.Context) {
	if s.Store.Get("backup_verify_auto", "1") != "1" {
		return
	}
	var id int64
	var user string
	err := s.Store.DB.QueryRowContext(ctx, `SELECT u.id, u.username FROM users u
		WHERE u.role='user' AND u.status='active' AND COALESCE((SELECT MAX(started_at) FROM backup_verifications v WHERE v.account_id=u.id),0) < ?
		ORDER BY COALESCE((SELECT MAX(started_at) FROM backup_verifications v WHERE v.account_id=u.id),0), u.id LIMIT 1`,
		time.Now().Add(-BackupVerifyInterval).Unix()).Scan(&id, &user)
	if err != nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	v, err := s.runBackupVerify(cctx, id, user, "scheduled")
	if err != nil {
		return
	}
	s.auditSystem("backup.verify", user, v.Status, v.Status == "ok" || v.Status == "no_snapshot")
}
