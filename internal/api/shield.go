// SPDX-License-Identifier: Apache-2.0

package api

// v0.4 BPanel Shield: admin and user endpoints, the upload staging pipeline
// (uploadOne -> shield.stage.chunk/commit) and the journal poller that pulls
// agent events into shield_detections and publishes "shield.detection".
//
// Scope: admins see everything; a reseller sees detections and quarantine
// items of the accounts it owns (users.owner_id); a hosting user sees only
// its own detections and can ask for a restore (an admin decides).

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/auth"
	"github.com/cumabozkurt/bpanel/internal/events"
	"github.com/cumabozkurt/bpanel/internal/fileops"
	"github.com/cumabozkurt/bpanel/internal/rbac"
	"github.com/cumabozkurt/bpanel/internal/shield"
	"github.com/cumabozkurt/bpanel/internal/store"
)

// ShieldScanReq is an on-demand scan of one path of one account.
type ShieldScanReq struct {
	AccountID int64  `json:"account_id"`
	Path      string `json:"path"`
}

// ShieldFPReq marks a quarantine item false positive.
type ShieldFPReq struct {
	Scope string `json:"scope"` // account | global (global: admins only)
}

// ShieldDetection is one stored detection row.
type ShieldDetection struct {
	ID               int64              `json:"id"`
	TS               int64              `json:"ts"`
	AccountID        *int64             `json:"account_id"`
	Account          string             `json:"account"`
	Kind             string             `json:"kind"`
	Source           string             `json:"source"`
	Path             string             `json:"path"`
	SHA256           string             `json:"sha256"`
	Outcome          string             `json:"outcome"`
	Action           string             `json:"action"`
	Reason           string             `json:"reason"`
	Engine           string             `json:"engine"`
	Signature        string             `json:"signature"`
	Severity         string             `json:"severity"`
	QuarantineID     string             `json:"quarantine_id"`
	RestoreRequested *int64             `json:"restore_requested_at"`
	Detections       []shield.Detection `json:"detections"`
}

func (s *Server) mountShield(r chi.Router) {
	s.opPerm(r, rbac.ShieldRead, "GET", "/admin/shield/status", "shield", "Shield engines, signature age, real-time coverage and queue", nil, s.h(s.shieldStatus))
	s.opPerm(r, rbac.ShieldRead, "GET", "/admin/shield/detections", "shield", "Detections (?limit=&offset=&account_id=&format=json|csv)", nil, s.adminDetections)
	s.opPerm(r, rbac.ShieldRead, "GET", "/admin/shield/quarantine", "shield", "Quarantined files", nil, s.h(s.adminQuarantine))
	s.opPerm(r, rbac.ShieldWrite, "POST", "/admin/shield/quarantine/{qid}/restore", "shield", "Restore a quarantined file (rescan must be clean)", nil, s.h(s.quarantineAction(rpc.MShieldQRestore, "restored")))
	s.opPerm(r, rbac.ShieldWrite, "DELETE", "/admin/shield/quarantine/{qid}", "shield", "Delete a quarantined file permanently", nil, s.h(s.quarantineAction(rpc.MShieldQDelete, "deleted")))
	s.opPerm(r, rbac.ShieldWrite, "POST", "/admin/shield/quarantine/{qid}/false-positive", "shield", "Mark false positive (account or global allowlist) and restore", ShieldFPReq{}, s.h(s.quarantineAction(rpc.MShieldQFP, "false_positive")))
	s.mountShieldPolicies(r)
	s.opPerm(r, rbac.ShieldWrite, "POST", "/admin/shield/scan", "shield", "Scan one file of an account now", ShieldScanReq{}, s.h(s.adminShieldScan))
}

func (s *Server) mountShieldUser(r chi.Router) {
	s.op(r, "GET", "/user/shield/detections", "shield", "Own malware scan results (?limit=&offset=)", nil, s.h(s.userDetections))
	s.op(r, "POST", "/user/shield/detections/{id}/request-restore", "shield", "Ask an administrator to restore a quarantined file", nil, s.h(s.userRequestRestore))
}

// ---- scope ----------------------------------------------------------------------

// shieldScope is the SQL condition limiting rows (with an account_id column)
// to what the caller may see.
func shieldScope(me *store.User, col string) (string, []any) {
	if me.Role == "reseller" {
		return col + ` IN (SELECT id FROM users WHERE owner_id=?)`, []any{me.ID}
	}
	return "1=1", nil
}

// accountVisible reports whether the caller may act on account username.
func (s *Server) shieldAccount(ctx context.Context, me *store.User, username string) (int64, bool) {
	var id int64
	var owner sql.NullInt64
	var role string
	if err := s.Store.DB.QueryRowContext(ctx, `SELECT id, owner_id, role FROM users WHERE username=?`, username).Scan(&id, &owner, &role); err != nil {
		return 0, false
	}
	if role == "admin" {
		return id, false
	}
	if me.Role == "reseller" && (!owner.Valid || owner.Int64 != me.ID) {
		return id, false
	}
	return id, true
}

// ---- status / scan ----------------------------------------------------------------

func (s *Server) shieldStatus(w http.ResponseWriter, r *http.Request) (any, error) {
	var st rpc.ShieldStatusResult
	if err := s.agentCall(r, rpc.MShieldStatus, struct{}{}, &st); err != nil {
		return nil, err
	}
	var pending int
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM shield_detections WHERE restore_requested_at IS NOT NULL AND quarantine_id<>''
		AND quarantine_id IN (SELECT id FROM shield_quarantine_index WHERE status='quarantined')`).Scan(&pending)
	return map[string]any{"status": st, "restore_requests": pending,
		"notice": "No antivirus catches everything: Shield lowers risk, it does not replace updates, backups and least privilege."}, nil
}

func (s *Server) adminShieldScan(w http.ResponseWriter, r *http.Request) (any, error) {
	var in ShieldScanReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	me := userOf(r)
	u, err := s.userByID(r.Context(), in.AccountID)
	if err != nil || !u.SystemUser {
		return nil, notFound()
	}
	if _, ok := s.shieldAccount(r.Context(), me, u.Username); !ok {
		return nil, notFound()
	}
	if strings.TrimSpace(in.Path) == "" || len(in.Path) > 4096 {
		return nil, &apiError{Status: 400, Code: "invalid_path", Field: "path"}
	}
	var res rpc.ShieldScanResult
	err = s.agentCall(r, rpc.MShieldScan, rpc.ShieldScanReq{User: u.Username, Path: in.Path}, &res)
	s.audit(r, "shield.scan", u.Username, in.Path, err == nil)
	if err != nil {
		return nil, err
	}
	s.shieldPollOnce(r.Context()) // the result shows up in detections right away
	return res, nil
}

// ---- detections -------------------------------------------------------------------

const detCols = `id, ts, account_id, account, kind, source, path, sha256, outcome, action, reason, engine, signature, severity, quarantine_id, restore_requested_at, detections_json`

func scanDetections(rows *sql.Rows) ([]ShieldDetection, error) {
	defer rows.Close()
	out := []ShieldDetection{}
	for rows.Next() {
		var d ShieldDetection
		var acct, rr sql.NullInt64
		var dj string
		if err := rows.Scan(&d.ID, &d.TS, &acct, &d.Account, &d.Kind, &d.Source, &d.Path, &d.SHA256, &d.Outcome, &d.Action, &d.Reason,
			&d.Engine, &d.Signature, &d.Severity, &d.QuarantineID, &rr, &dj); err != nil {
			return nil, err
		}
		if acct.Valid {
			d.AccountID = &acct.Int64
		}
		if rr.Valid {
			d.RestoreRequested = &rr.Int64
		}
		_ = json.Unmarshal([]byte(dj), &d.Detections)
		if d.Detections == nil {
			d.Detections = []shield.Detection{}
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func shieldPage(r *http.Request, maxLimit int) (int, int) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > maxLimit {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func (s *Server) queryDetections(ctx context.Context, where string, args []any, limit, offset int) ([]ShieldDetection, int, error) {
	var total int
	if err := s.Store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM shield_detections WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT `+detCols+` FROM shield_detections WHERE `+where+` ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	items, err := scanDetections(rows)
	return items, total, err
}

func (s *Server) adminDetections(w http.ResponseWriter, r *http.Request) {
	me := userOf(r)
	where, args := shieldScope(me, "account_id")
	if v := r.URL.Query().Get("account_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			s.fail(w, r, &apiError{Status: 400, Code: "invalid_id", Field: "account_id"})
			return
		}
		where, args = where+" AND account_id=?", append(args, id)
	}
	csvOut := r.URL.Query().Get("format") == "csv"
	limit, offset := shieldPage(r, 500)
	if csvOut {
		limit, offset = 10000, 0
	}
	items, total, err := s.queryDetections(r.Context(), where, args, limit, offset)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !csvOut {
		writeJSON(w, 200, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset})
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="shield-detections.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "time", "account", "kind", "source", "path", "sha256", "outcome", "action", "engine", "signature", "severity", "quarantine_id"})
	for _, d := range items {
		_ = cw.Write([]string{strconv.FormatInt(d.ID, 10), time.Unix(d.TS, 0).UTC().Format(time.RFC3339), csvSafe(d.Account), d.Kind, d.Source,
			csvSafe(d.Path), d.SHA256, d.Outcome, d.Action, csvSafe(d.Engine), csvSafe(d.Signature), d.Severity, d.QuarantineID})
	}
	cw.Flush()
}

// csvSafe neutralises spreadsheet formula injection (file names are attacker-chosen).
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func (s *Server) userDetections(w http.ResponseWriter, r *http.Request) (any, error) {
	me := userOf(r)
	limit, offset := shieldPage(r, 200)
	items, total, err := s.queryDetections(r.Context(), "account_id=?", []any{me.ID}, limit, offset)
	if err != nil {
		return nil, err
	}
	return map[string]any{"items": items, "total": total, "limit": limit, "offset": offset}, nil
}

func (s *Server) userRequestRestore(w http.ResponseWriter, r *http.Request) (any, error) {
	me := userOf(r)
	id := idParam(r, "id")
	var qid string
	if err := s.Store.DB.QueryRowContext(r.Context(), `SELECT quarantine_id FROM shield_detections WHERE id=? AND account_id=?`, id, me.ID).Scan(&qid); err != nil {
		return nil, notFound()
	}
	if qid == "" {
		return nil, &apiError{Status: 422, Code: "not_quarantined"}
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `UPDATE shield_detections SET restore_requested_at=? WHERE id=?`, s.Now().Unix(), id); err != nil {
		return nil, err
	}
	s.audit(r, "shield.restore_request", qid, "", true)
	events.Publish(r.Context(), events.Event{Type: "shield.restore_requested", Severity: events.Info, AccountID: me.ID,
		Data: map[string]any{"quarantine_id": qid, "detection_id": id}})
	return nil, nil
}

// ---- quarantine --------------------------------------------------------------------

func (s *Server) syncQuarantine(ctx context.Context) ([]shield.QuarantineMeta, error) {
	var res rpc.ShieldQListResult
	if err := s.Agent.Call(ctx, rpc.MShieldQList, rpc.ShieldQListReq{}, &res); err != nil {
		return nil, err
	}
	now := s.Now().Unix()
	for _, m := range res.Items {
		dj, _ := json.Marshal(m.Detections)
		status := "quarantined"
		if m.FalsePositive != "" {
			status = "false_positive"
		}
		_, _ = s.Store.DB.ExecContext(ctx, `INSERT INTO shield_quarantine_index(id, account_id, account, orig_path, sha256, size, ts, status, detections_json, updated_at)
			VALUES(?, (SELECT id FROM users WHERE username=?), ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at`,
			m.ID, m.Account, m.Account, m.OrigPath, m.SHA256, m.Size, m.TS.Unix(), status, string(dj), now)
	}
	return res.Items, nil
}

func (s *Server) adminQuarantine(w http.ResponseWriter, r *http.Request) (any, error) {
	me := userOf(r)
	items, err := s.syncQuarantine(r.Context())
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, m := range items {
		id, ok := s.shieldAccount(r.Context(), me, m.Account)
		if !ok {
			continue
		}
		var req sql.NullInt64
		_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT MAX(restore_requested_at) FROM shield_detections WHERE quarantine_id=?`, m.ID).Scan(&req)
		row := map[string]any{"item": m, "account_id": id}
		if req.Valid {
			row["restore_requested_at"] = req.Int64
		}
		out = append(out, row)
	}
	return map[string]any{"items": out}, nil
}

func (s *Server) quarantineAction(method, status string) func(w http.ResponseWriter, r *http.Request) (any, error) {
	return func(w http.ResponseWriter, r *http.Request) (any, error) {
		me := userOf(r)
		qid := chi.URLParam(r, "qid")
		var in ShieldFPReq
		if method == rpc.MShieldQFP {
			if err := decode(r, &in); err != nil {
				return nil, err
			}
			if in.Scope == "" {
				in.Scope = "account"
			}
			if in.Scope != "account" && in.Scope != "global" {
				return nil, &apiError{Status: 400, Code: "invalid_scope", Field: "scope"}
			}
			if in.Scope == "global" && me.Role != "admin" {
				return nil, forbidden()
			}
		}
		var account string
		err := s.Store.DB.QueryRowContext(r.Context(), `SELECT account FROM shield_quarantine_index WHERE id=?`, qid).Scan(&account)
		if errors.Is(err, sql.ErrNoRows) {
			if _, serr := s.syncQuarantine(r.Context()); serr != nil {
				return nil, serr
			}
			err = s.Store.DB.QueryRowContext(r.Context(), `SELECT account FROM shield_quarantine_index WHERE id=?`, qid).Scan(&account)
		}
		if err != nil {
			return nil, notFound()
		}
		if _, ok := s.shieldAccount(r.Context(), me, account); !ok {
			return nil, notFound()
		}
		var m shield.QuarantineMeta
		err = s.agentCall(r, method, rpc.ShieldQRef{User: account, ID: qid, Scope: in.Scope}, &m)
		s.audit(r, method, account, qid, err == nil)
		if err != nil {
			return nil, err
		}
		_, _ = s.Store.DB.ExecContext(r.Context(), `UPDATE shield_quarantine_index SET status=?, updated_at=? WHERE id=?`, status, s.Now().Unix(), qid)
		s.shieldPollOnce(r.Context())
		return m, nil
	}
}

// ---- policy + upload pipeline -------------------------------------------------------

// shieldPolicy is the effective policy of account id: server defaults, then
// global shield_policies rows, then the account's own rows.
func (s *Server) shieldPolicy(ctx context.Context, accountID int64) shield.AccountPolicy {
	p := shield.DefaultPolicy()
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT file_class, on_unavailable, on_suspicious FROM shield_policies
		WHERE account_id IS NULL OR account_id=? ORDER BY account_id IS NOT NULL`, accountID)
	if err != nil {
		return p
	}
	defer rows.Close()
	for rows.Next() {
		var class, un, su string
		if rows.Scan(&class, &un, &su) != nil {
			continue
		}
		set := func(dst *shield.Action, v string) {
			if v != "" {
				*dst = shield.Action(v)
			}
		}
		switch class {
		case "script", "executable":
			set(&p.OnUnavailableScript, un)
			set(&p.OnSuspiciousScript, su)
		case "archive":
			set(&p.OnSuspiciousArchive, su)
		case "other":
			set(&p.OnUnavailableOther, un)
			set(&p.OnSuspiciousOther, su)
		}
	}
	return p
}

// uploadOne streams one uploaded file into a root-owned agent staging file,
// then asks the agent to scan it and place it (or refuse it). The account
// never holds an unscanned byte; a refused upload is a 422 shield_blocked
// with the detections.
func (s *Server) uploadOne(r *http.Request, u *store.User, target string, src io.Reader, buf []byte) error {
	id := auth.RandomToken(12)
	abort := func() {
		ctx, cancel := undoCtx(r.Context())
		defer cancel()
		if err := s.Agent.Call(ctx, rpc.MShieldStageAbort, rpc.ShieldStageRef{User: u.Username, ID: id}, nil); err != nil {
			s.Log.Warn("upload staging cleanup", "id", id, "err", err)
		}
	}
	var off int64
	for first := true; ; first = false {
		n, rerr := io.ReadFull(src, buf)
		if rerr != nil && !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF) {
			if !first {
				abort()
			}
			return uploadErr(rerr)
		}
		if n == 0 && !first {
			break
		}
		if off+int64(n) > fileops.MaxUploadBytes {
			if !first {
				abort()
			}
			return &apiError{Status: 413, Code: "file_too_large", Message: fmt.Sprintf("max %d bytes per file", fileops.MaxUploadBytes)}
		}
		op := rpc.ShieldStageChunk{User: u.Username, ID: id, Offset: off, Content: base64.StdEncoding.EncodeToString(buf[:n])}
		if err := s.agentCall(r, rpc.MShieldStageChunk, op, nil); err != nil {
			abort()
			return err
		}
		off += int64(n)
		if rerr != nil { // EOF after this chunk
			break
		}
	}
	var res rpc.ShieldStageCommitResult
	rel := strings.TrimLeft(target, "/")
	name := rel[strings.LastIndex(rel, "/")+1:]
	err := s.agentCall(r, rpc.MShieldStageCommit, rpc.ShieldStageCommit{User: u.Username, ID: id, Path: rel, Name: name,
		Policy: s.shieldPolicy(r.Context(), u.ID)}, &res)
	if err != nil {
		abort()
		return err
	}
	if res.EventUID != "" {
		s.storeShieldEvent(r.Context(), rpc.ShieldEvent{UID: res.EventUID, TS: s.Now().Unix(), Kind: "upload", Source: "upload",
			Account: u.Username, Path: rel, SHA256: res.SHA256, Outcome: res.Outcome, Action: res.Action, Reason: res.Reason,
			Detections: res.Detections, QuarantineID: res.QuarantineID})
	}
	if !res.Placed {
		s.audit(r, "shield.upload_blocked", u.Username, rel, true)
		return &apiError{Status: 422, Code: "shield_blocked", Message: res.Reason, Details: map[string]any{
			"file": name, "action": res.Action, "outcome": res.Outcome, "detections": res.Detections, "quarantine_id": res.QuarantineID}}
	}
	return nil
}

// ---- journal poller -----------------------------------------------------------------

// storeShieldEvent inserts one event (deduplicated by uid) and publishes it.
func (s *Server) storeShieldEvent(ctx context.Context, ev rpc.ShieldEvent) {
	var acct sql.NullInt64
	var aid int64
	if err := s.Store.DB.QueryRowContext(ctx, `SELECT id FROM users WHERE username=?`, ev.Account).Scan(&aid); err == nil {
		acct = sql.NullInt64{Int64: aid, Valid: true}
	}
	var engine, sig, sev string
	for _, d := range ev.Detections {
		if engine == "" || sevRank(d.Severity) > sevRank(sev) {
			engine, sig, sev = d.Engine, d.Signature, d.Severity
		}
	}
	dj, _ := json.Marshal(ev.Detections)
	if ev.Detections == nil {
		dj = []byte("[]")
	}
	res, err := s.Store.DB.ExecContext(ctx, `INSERT OR IGNORE INTO shield_detections(event_uid, seq, ts, account_id, account, kind, source, path, sha256,
		outcome, action, reason, engine, signature, severity, detections_json, quarantine_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ev.UID, ev.Seq, ev.TS, acct, ev.Account, ev.Kind, ev.Source, ev.Path, ev.SHA256, ev.Outcome, ev.Action, ev.Reason, engine, sig, sev, string(dj), ev.QuarantineID)
	if err != nil {
		s.Log.Warn("shield: store event", "err", err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if ev.Seq > 0 { // already stored synchronously (upload): keep the sequence
			_, _ = s.Store.DB.ExecContext(ctx, `UPDATE shield_detections SET seq=? WHERE event_uid=? AND seq=0`, ev.Seq, ev.UID)
		}
		return
	}
	if ev.QuarantineID != "" {
		_, _ = s.Store.DB.ExecContext(ctx, `INSERT OR IGNORE INTO shield_quarantine_index(id, account_id, account, orig_path, sha256, ts, detections_json, updated_at)
			VALUES(?,?,?,?,?,?,?,?)`, ev.QuarantineID, acct, ev.Account, ev.Path, ev.SHA256, ev.TS, string(dj), ev.TS)
	}
	evSev := events.Warning
	if ev.Outcome == string(shield.OutInfected) {
		evSev = events.Critical
	}
	if ev.Kind == "restore" || ev.Kind == "delete" || ev.Kind == "falsepositive" || ev.Outcome == string(shield.OutClean) {
		evSev = events.Info
	}
	events.Publish(ctx, events.Event{Type: "shield.detection", Severity: evSev, AccountID: aid, At: ev.TS,
		Data: map[string]any{"kind": ev.Kind, "source": ev.Source, "outcome": ev.Outcome, "action": ev.Action, "signature": sig}})
}

func sevRank(s string) int {
	switch s {
	case shield.SevCritical:
		return 4
	case shield.SevHigh:
		return 3
	case shield.SevMedium:
		return 2
	case shield.SevLow:
		return 1
	}
	return 0
}

// shieldPollOnce pulls new journal entries from the agent.
func (s *Server) shieldPollOnce(ctx context.Context) {
	s.shieldPollMu.Lock()
	defer s.shieldPollMu.Unlock()
	var cur int64
	_ = s.Store.DB.QueryRowContext(ctx, `SELECT last_seq FROM shield_cursor WHERE id=1`).Scan(&cur)
	for i := 0; i < 20; i++ {
		var res rpc.ShieldEventsResult
		if err := s.Agent.Call(ctx, rpc.MShieldEvents, rpc.ShieldEventsReq{Since: cur}, &res); err != nil {
			return
		}
		if res.LastSeq < cur { // journal was reset on the agent: start over (uids dedupe)
			cur = 0
			continue
		}
		for _, ev := range res.Events {
			s.storeShieldEvent(ctx, ev)
			if ev.Seq > cur {
				cur = ev.Seq
			}
		}
		_, _ = s.Store.DB.ExecContext(ctx, `UPDATE shield_cursor SET last_seq=? WHERE id=1`, cur)
		if len(res.Events) == 0 || cur >= res.LastSeq {
			return
		}
	}
}

// runShieldPoller polls the agent journal every 15 s.
func (s *Server) runShieldPoller(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		s.shieldPollOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
