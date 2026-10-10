package api

// v0.4 backup part B: scheduled backups with automatic retention, plus the
// admin overview (last verification + last scheduled run per account) and the
// backup policy settings.
//
// Housekeeping runs at most ONE scheduled backup per tick (oldest first) when
// backup_auto=1. After a successful backup the configured keep-* policy is
// applied with backup.forget (restic forget --prune), bounded by
// backupRetentionTimeout; its outcome is stored in backup_runs and a failure
// is published as event backup.retention_failed. A failed backup never prunes.

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/events"
	"github.com/cumabozkurt/bpanel/internal/rbac"
	"github.com/cumabozkurt/bpanel/internal/store"
)

const (
	backupRunTimeout       = 2 * time.Hour
	backupRetentionTimeout = 30 * time.Minute
)

// BackupPolicy is the panel-wide schedule + retention policy (settings table).
type BackupPolicy struct {
	Auto          bool `json:"auto"`
	IntervalHours int  `json:"interval_hours"`
	Databases     bool `json:"databases"`
	KeepLast      int  `json:"keep_last"`
	KeepDaily     int  `json:"keep_daily"`
	KeepWeekly    int  `json:"keep_weekly"`
	KeepMonthly   int  `json:"keep_monthly"`
	KeepYearly    int  `json:"keep_yearly"`
}

func (s *Server) settingInt(key string, def int) int {
	n, err := strconv.Atoi(s.Store.Get(key, strconv.Itoa(def)))
	if err != nil {
		return def
	}
	return n
}

func (s *Server) backupPolicy() BackupPolicy {
	return BackupPolicy{
		Auto: s.Store.Get("backup_auto", "0") == "1", IntervalHours: s.settingInt("backup_interval_hours", 24),
		Databases: s.Store.Get("backup_auto_databases", "1") == "1",
		KeepLast:  s.settingInt("backup_keep_last", 0), KeepDaily: s.settingInt("backup_keep_daily", 7),
		KeepWeekly: s.settingInt("backup_keep_weekly", 4), KeepMonthly: s.settingInt("backup_keep_monthly", 6),
		KeepYearly: s.settingInt("backup_keep_yearly", 0),
	}
}

func (p BackupPolicy) retention() rpc.RetentionPolicy {
	return rpc.RetentionPolicy{Last: p.KeepLast, Daily: p.KeepDaily, Weekly: p.KeepWeekly, Monthly: p.KeepMonthly, Yearly: p.KeepYearly}
}

func (p BackupPolicy) validate() error {
	if p.IntervalHours < 1 || p.IntervalHours > 24*31 {
		return &apiError{Status: 400, Code: "invalid_retention", Field: "interval_hours"}
	}
	n := 0
	for _, v := range []int{p.KeepLast, p.KeepDaily, p.KeepWeekly, p.KeepMonthly, p.KeepYearly} {
		if v < 0 || v > 1000 {
			return &apiError{Status: 400, Code: "invalid_retention"}
		}
		n += v
	}
	if n == 0 {
		return &apiError{Status: 400, Code: "invalid_retention", Message: "policy keeps nothing"}
	}
	return nil
}

func (s *Server) mountBackupSchedule(r chi.Router) {
	s.opPerm(r, rbac.BackupsRead, "GET", "/admin/backups/overview", "backup", "Per account: last restore verification and last scheduled backup/retention", nil, s.h(s.backupOverview))
	s.opPerm(r, rbac.BackupsRead, "GET", "/admin/backups/policy", "backup", "Scheduled backup + retention policy", nil, s.h(s.getBackupPolicy))
	s.opPermReauth(r, rbac.BackupsDelete, "PUT", "/admin/backups/policy", "backup", "Update the scheduled backup + retention policy (retention deletes snapshots)", BackupPolicy{}, s.h(s.putBackupPolicy))
	s.mountSecretsRotate(r) // backup_secrets.go
}

func (s *Server) getBackupPolicy(w http.ResponseWriter, r *http.Request) (any, error) {
	return s.backupPolicy(), nil
}

func (s *Server) putBackupPolicy(w http.ResponseWriter, r *http.Request) (any, error) {
	var in BackupPolicy
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	b := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	for k, v := range map[string]string{"backup_auto": b(in.Auto), "backup_auto_databases": b(in.Databases),
		"backup_interval_hours": strconv.Itoa(in.IntervalHours), "backup_keep_last": strconv.Itoa(in.KeepLast),
		"backup_keep_daily": strconv.Itoa(in.KeepDaily), "backup_keep_weekly": strconv.Itoa(in.KeepWeekly),
		"backup_keep_monthly": strconv.Itoa(in.KeepMonthly), "backup_keep_yearly": strconv.Itoa(in.KeepYearly)} {
		if err := s.Store.Set(k, v); err != nil {
			return nil, err
		}
	}
	s.audit(r, "backup.policy", "", strings.Join([]string{"auto=" + b(in.Auto), "every=" + strconv.Itoa(in.IntervalHours) + "h"}, " "), true)
	return s.backupPolicy(), nil
}

type backupOverviewRow struct {
	AccountID    int64                  `json:"account_id"`
	Username     string                 `json:"username"`
	Verification *BackupVerificationRow `json:"verification"`
	LastRun      *backupRunRow          `json:"last_run"`
}

type backupRunRow struct {
	StartedAt       int64  `json:"started_at"`
	FinishedAt      int64  `json:"finished_at"`
	Status          string `json:"status"`
	Error           string `json:"error"`
	RetentionStatus string `json:"retention_status"`
	RetentionError  string `json:"retention_error"`
	Removed         int    `json:"removed"`
}

func (s *Server) backupOverview(w http.ResponseWriter, r *http.Request) (any, error) {
	ctx := r.Context()
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT id, username FROM users WHERE role='user' AND status<>'deleted' ORDER BY username LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	var list []backupOverviewRow
	for rows.Next() {
		var o backupOverviewRow
		if rows.Scan(&o.AccountID, &o.Username) == nil {
			list = append(list, o)
		}
	}
	rows.Close()
	out := []backupOverviewRow{}
	for _, o := range list {
		if !s.canManageAccount(r, o.AccountID) {
			continue
		}
		if v, err := scanBV(s.Store.DB.QueryRowContext(ctx, `SELECT `+bvCols+` FROM backup_verifications WHERE account_id=? ORDER BY started_at DESC, id DESC LIMIT 1`, o.AccountID)); err == nil {
			o.Verification = &v
		}
		var br backupRunRow
		err := s.Store.DB.QueryRowContext(ctx, `SELECT started_at, finished_at, status, error, retention_status, retention_error, removed FROM backup_runs WHERE account_id=? ORDER BY started_at DESC, id DESC LIMIT 1`, o.AccountID).
			Scan(&br.StartedAt, &br.FinishedAt, &br.Status, &br.Error, &br.RetentionStatus, &br.RetentionError, &br.Removed)
		if err == nil {
			o.LastRun = &br
		}
		out = append(out, o)
	}
	return map[string]any{"accounts": out, "policy": s.backupPolicy()}, nil
}

// backupScheduleTick (housekeeping): one due account per tick.
func (s *Server) backupScheduleTick(ctx context.Context) {
	pol := s.backupPolicy()
	if !pol.Auto {
		return
	}
	var id int64
	var user string
	err := s.Store.DB.QueryRowContext(ctx, `SELECT u.id, u.username FROM users u
		WHERE u.role='user' AND u.status='active' AND COALESCE((SELECT MAX(started_at) FROM backup_runs b WHERE b.account_id=u.id),0) < ?
		ORDER BY COALESCE((SELECT MAX(started_at) FROM backup_runs b WHERE b.account_id=u.id),0), u.id LIMIT 1`,
		time.Now().Add(-time.Duration(pol.IntervalHours)*time.Hour).Unix()).Scan(&id, &user)
	if err != nil {
		return
	}
	s.runScheduledBackup(ctx, id, user, pol)
}

// runScheduledBackup: backup, then (only on success) retention. Every outcome
// is recorded in backup_runs; error texts are the agent's scrubbed codes.
func (s *Server) runScheduledBackup(ctx context.Context, id int64, user string, pol BackupPolicy) {
	start := time.Now().Unix()
	res, err := s.Store.DB.ExecContext(ctx, `INSERT INTO backup_runs(account_id, username, trigger, started_at) VALUES(?,?, 'scheduled', ?)`, id, user, start)
	if err != nil {
		return
	}
	runID, _ := res.LastInsertId()
	finish := func(status, errText, rs, rerr string, removed int, snaps string) {
		_, _ = s.Store.DB.ExecContext(context.WithoutCancel(ctx), `UPDATE backup_runs SET finished_at=?, status=?, error=?, retention_status=?, retention_error=?, removed=?, snapshot_ids=? WHERE id=?`,
			time.Now().Unix(), status, trunc(errText, 500), rs, trunc(rerr, 500), removed, snaps, runID)
	}
	req := rpc.BackupRun{User: user}
	if pol.Databases {
		if dbs, err := store.Select[store.Database](ctx, s.Store.DB, `SELECT *, '' AS users FROM databases WHERE user_id=?`, id); err == nil {
			for _, d := range dbs {
				req.Databases = append(req.Databases, d.Name)
			}
		}
	}
	bctx, cancel := context.WithTimeout(ctx, backupRunTimeout)
	var out rpc.BackupRunResult
	err = s.agentCallCtx(bctx, rpc.MBackupRun, req, &out)
	cancel()
	snaps := strings.Join(out.SnapshotIDs, ",")
	if err != nil {
		finish("failed", agentCode(err), "skipped", "", 0, "")
		s.auditSystem("backup.run", user, "scheduled: "+agentCode(err), false)
		events.Publish(ctx, events.Event{Type: "backup.failed", Severity: events.Warning, AccountID: id, Data: map[string]any{"code": agentCode(err)}})
		return
	}
	s.auditSystem("backup.run", user, "scheduled: "+snaps, true)
	rs, rerr, removed := s.applyRetention(ctx, id, user, pol)
	finish("ok", "", rs, rerr, removed, snaps)
}

// applyRetention runs restic forget --prune with the policy, bounded.
func (s *Server) applyRetention(ctx context.Context, id int64, user string, pol BackupPolicy) (status, errText string, removed int) {
	if pol.validate() != nil {
		s.auditSystem("backup.retention", user, "invalid_retention", false)
		return "failed", "invalid_retention", 0
	}
	rctx, cancel := context.WithTimeout(ctx, backupRetentionTimeout)
	defer cancel()
	var out rpc.BackupForgetResult
	if err := s.agentCallCtx(rctx, rpc.MBackupForget, rpc.BackupForget{User: user, Policy: pol.retention()}, &out); err != nil {
		code := agentCode(err)
		if rctx.Err() == context.DeadlineExceeded {
			code = "retention_timeout"
		}
		s.auditSystem("backup.retention", user, code, false)
		events.Publish(ctx, events.Event{Type: "backup.retention_failed", Severity: events.Warning, AccountID: id, Data: map[string]any{"code": code}})
		return "failed", code, 0
	}
	s.auditSystem("backup.retention", user, "removed "+strconv.Itoa(out.Removed)+", kept "+strconv.Itoa(out.Kept), true)
	return "ok", "", out.Removed
}

// agentCallCtx is agentCall with an explicit context (housekeeping has no request).
func (s *Server) agentCallCtx(ctx context.Context, method string, params, out any) error {
	if err := s.preBackupCall(ctx, method, params); err != nil {
		return err
	}
	err := s.Agent.Call(ctx, method, params, out)
	s.obsxAgent(method, err) // v0.4 obsx.go metrics
	return err
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
