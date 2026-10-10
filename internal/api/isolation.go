// SPDX-License-Identifier: Apache-2.0

package api

// v0.4 per-account resource isolation: limit profiles, per-account limits
// (profile + overrides) applied through the agent (isolation.apply), usage
// history from the sampler (isolation_sampler.go).

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/isolation"
	"github.com/cumabozkurt/bpanel/internal/rbac"
)

// LimitProfileReq is a limit profile (zero = unlimited).
type LimitProfileReq struct {
	Name string `json:"name"`
	isolation.Profile
}

// LimitProfile is a stored profile.
type LimitProfile struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	isolation.Profile
	Accounts int `json:"accounts"`
}

// AccountLimitsReq assigns a profile (null = none) and per-field overrides.
type AccountLimitsReq struct {
	ProfileID *int64           `json:"profile_id"`
	Overrides map[string]int64 `json:"overrides"`
}

const profCols = `cpu_percent, cpu_weight, mem_max_mb, mem_high_mb, io_read_bps, io_write_bps, io_read_iops, io_write_iops, tasks_max, inode_limit, disk_mb, entry_procs`

func profPtrs(p *isolation.Profile) []any {
	return []any{&p.CPUPercent, &p.CPUWeight, &p.MemMaxMB, &p.MemHighMB, &p.IOReadBps, &p.IOWriteBps, &p.IOReadIOPS, &p.IOWriteIOPS,
		&p.TasksMax, &p.InodeLimit, &p.DiskMB, &p.EntryProcs}
}

func profVals(p isolation.Profile) []any {
	return []any{p.CPUPercent, p.CPUWeight, p.MemMaxMB, p.MemHighMB, p.IOReadBps, p.IOWriteBps, p.IOReadIOPS, p.IOWriteIOPS,
		p.TasksMax, p.InodeLimit, p.DiskMB, p.EntryProcs}
}

// isoIOPath is the path whose block device the IO limits apply to.
var isoIOPath = "/home"

func (s *Server) mountIsolation(r chi.Router) {
	s.opPerm(r, rbac.IsolationRead, "GET", "/admin/limit-profiles", "isolation", "List resource limit profiles", nil, s.h(s.listLimitProfiles))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/limit-profiles", "isolation", "Create a resource limit profile", LimitProfileReq{}, s.h(s.createLimitProfile))
	s.opPerm(r, rbac.ServerWrite, "PUT", "/admin/limit-profiles/{id}", "isolation", "Edit a limit profile (re-applies it to its accounts)", LimitProfileReq{}, s.h(s.updateLimitProfile))
	s.opPerm(r, rbac.ServerWrite, "DELETE", "/admin/limit-profiles/{id}", "isolation", "Delete a limit profile", nil, s.h(s.deleteLimitProfile))
	s.opPerm(r, rbac.IsolationRead, "GET", "/admin/accounts/{id}/limits", "isolation", "An account's limit profile, overrides and effective limits", nil, s.h(s.getAccountLimits))
	s.opPerm(r, rbac.IsolationWrite, "PUT", "/admin/accounts/{id}/limits", "isolation", "Set an account's limit profile and overrides (applied via the agent)", AccountLimitsReq{}, s.h(s.putAccountLimits))
	s.opPerm(r, rbac.IsolationRead, "GET", "/admin/accounts/{id}/usage", "isolation", "Resource usage history of an account (?range=1h|24h|7d|30d)", nil, s.h(s.adminAccountUsage))
	s.opPerm(r, rbac.IsolationRead, "GET", "/admin/usage/top", "isolation", "Top resource consumers over the last hour", nil, s.h(s.usageTop))
	s.opPerm(r, rbac.IsolationRead, "GET", "/admin/isolation/status", "isolation", "Kernel support for resource isolation (cgroup v2)", nil, s.h(s.isolationStatus))
}

// mountIsolationUser mounts the user-realm usage view (own account only).
func (s *Server) mountIsolationUser(r chi.Router) {
	s.op(r, "GET", "/user/usage", "isolation", "Own resource usage history and limits (?range=1h|24h|7d|30d)", nil, s.h(s.ownUsage))
}

func (s *Server) listLimitProfiles(w http.ResponseWriter, r *http.Request) (any, error) {
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT p.id, p.name, `+prefixed("p.", profCols)+`,
		(SELECT COUNT(*) FROM users u WHERE u.limit_profile_id=p.id) FROM limit_profiles p ORDER BY p.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LimitProfile{}
	for rows.Next() {
		var p LimitProfile
		dst := append([]any{&p.ID, &p.Name}, profPtrs(&p.Profile)...)
		if err := rows.Scan(append(dst, &p.Accounts)...); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return map[string]any{"items": out}, rows.Err()
}

func prefixed(pfx, cols string) string {
	parts := strings.Split(cols, ", ")
	for i := range parts {
		parts[i] = pfx + parts[i]
	}
	return strings.Join(parts, ", ")
}

func validProfileReq(in LimitProfileReq) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		return badMsg("invalid_name", "name: 1-64 characters")
	}
	if err := in.Profile.Validate(); err != nil {
		return badMsg("invalid_limits", err.Error())
	}
	return nil
}

func (s *Server) createLimitProfile(w http.ResponseWriter, r *http.Request) (any, error) {
	var in LimitProfileReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := validProfileReq(in); err != nil {
		return nil, err
	}
	now := s.Now().Unix()
	args := append([]any{strings.TrimSpace(in.Name)}, profVals(in.Profile)...)
	res, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO limit_profiles(name, `+profCols+`, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, append(args, now, now)...)
	if err != nil {
		s.audit(r, "iso.profile.create", in.Name, "", false)
		return nil, err
	}
	id, _ := res.LastInsertId()
	s.audit(r, "iso.profile.create", in.Name, "", true)
	return map[string]any{"id": id}, nil
}

func (s *Server) updateLimitProfile(w http.ResponseWriter, r *http.Request) (any, error) {
	id := idParam(r, "id")
	var in LimitProfileReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := validProfileReq(in); err != nil {
		return nil, err
	}
	args := append([]any{strings.TrimSpace(in.Name)}, profVals(in.Profile)...)
	res, err := s.Store.DB.ExecContext(r.Context(), `UPDATE limit_profiles SET name=?, cpu_percent=?, cpu_weight=?, mem_max_mb=?, mem_high_mb=?,
		io_read_bps=?, io_write_bps=?, io_read_iops=?, io_write_iops=?, tasks_max=?, inode_limit=?, disk_mb=?, entry_procs=?, updated_at=? WHERE id=?`,
		append(args, s.Now().Unix(), id)...)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, notFound()
	}
	// re-apply to every account on this profile (best effort, reported)
	ids, err := s.idsWhere(r.Context(), `SELECT id FROM users WHERE limit_profile_id=?`, id)
	if err != nil {
		return nil, err
	}
	failed := 0
	for _, aid := range ids {
		if res := s.applyAccountLimits(r.Context(), aid); res["applied"] != true {
			failed++
		}
	}
	s.audit(r, "iso.profile.update", in.Name, fmt.Sprintf("accounts=%d failed=%d", len(ids), failed), true)
	return map[string]any{"ok": true, "accounts": len(ids), "apply_failed": failed}, nil
}

func (s *Server) deleteLimitProfile(w http.ResponseWriter, r *http.Request) (any, error) {
	id := idParam(r, "id")
	ids, err := s.idsWhere(r.Context(), `SELECT id FROM users WHERE limit_profile_id=?`, id)
	if err != nil {
		return nil, err
	}
	if len(ids) > 0 {
		return nil, conflict("profile_in_use")
	}
	res, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM limit_profiles WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, notFound()
	}
	s.audit(r, "iso.profile.delete", fmt.Sprint(id), "", true)
	return nil, nil
}

func (s *Server) idsWhere(ctx context.Context, q string, args ...any) ([]int64, error) {
	rows, err := s.Store.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// accountLimits loads an account's username, profile id, overrides and the
// effective profile (profile fields overlaid with the overrides).
type accountLimits struct {
	AccountID int64             `json:"account_id"`
	Username  string            `json:"username"`
	ProfileID *int64            `json:"profile_id"`
	Overrides map[string]int64  `json:"overrides"`
	Effective isolation.Profile `json:"effective"`
}

func (s *Server) loadAccountLimits(ctx context.Context, id int64) (accountLimits, error) {
	var a accountLimits
	var pid sql.NullInt64
	var ov string
	err := s.Store.DB.QueryRowContext(ctx, `SELECT id, username, limit_profile_id, limit_overrides FROM users WHERE id=?`, id).
		Scan(&a.AccountID, &a.Username, &pid, &ov)
	if err != nil {
		return a, err
	}
	if pid.Valid {
		v := pid.Int64
		a.ProfileID = &v
		if err := s.Store.DB.QueryRowContext(ctx, `SELECT `+profCols+` FROM limit_profiles WHERE id=?`, v).
			Scan(profPtrs(&a.Effective)...); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return a, err
		}
	}
	a.Overrides = map[string]int64{}
	_ = json.Unmarshal([]byte(ov), &a.Overrides)
	if len(a.Overrides) > 0 {
		b, _ := json.Marshal(a.Overrides)
		_ = json.Unmarshal(b, &a.Effective)
	}
	return a, nil
}

// overlay applies overrides to p; unknown keys are refused.
func overlay(p isolation.Profile, ov map[string]int64) (isolation.Profile, error) {
	if len(ov) == 0 {
		return p, nil
	}
	b, _ := json.Marshal(ov)
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, badMsg("invalid_limits", "unknown override field")
	}
	for k, v := range ov {
		if v < 0 {
			return p, badMsg("invalid_limits", k+" must be >= 0")
		}
	}
	return p, nil
}

// exceedsCap reports the first field where child is looser than the cap.
// A zero cap field is unlimited; a zero child field under a set cap exceeds it.
func exceedsCap(child, capP isolation.Profile) string {
	cb, _ := json.Marshal(child)
	pb, _ := json.Marshal(capP)
	var cm, pm map[string]int64
	_ = json.Unmarshal(cb, &cm)
	_ = json.Unmarshal(pb, &pm)
	for k, cv := range pm {
		if k == "cpu_weight" || cv == 0 {
			continue
		}
		if v := cm[k]; v == 0 || v > cv {
			return k
		}
	}
	return ""
}

func (s *Server) getAccountLimits(w http.ResponseWriter, r *http.Request) (any, error) {
	id := idParam(r, "id")
	if !s.canManageAccount(r, id) {
		return nil, forbidden()
	}
	return s.loadAccountLimits(r.Context(), id)
}

func (s *Server) putAccountLimits(w http.ResponseWriter, r *http.Request) (any, error) {
	id := idParam(r, "id")
	u := userOf(r)
	if u == nil || !s.canManageAccount(r, id) {
		return nil, forbidden()
	}
	role := roleOf(r)
	if role == rbac.Reseller && id == u.ID {
		return nil, forbidden() // a reseller cannot raise its own limits
	}
	var in AccountLimitsReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	cur, err := s.loadAccountLimits(r.Context(), id)
	if err != nil {
		return nil, err
	}
	var base isolation.Profile
	if in.ProfileID != nil {
		if err := s.Store.DB.QueryRowContext(r.Context(), `SELECT `+profCols+` FROM limit_profiles WHERE id=?`, *in.ProfileID).
			Scan(profPtrs(&base)...); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, badMsg("invalid_profile", "no such profile")
			}
			return nil, err
		}
	}
	eff, err := overlay(base, in.Overrides)
	if err != nil {
		return nil, err
	}
	if err := eff.Validate(); err != nil {
		return nil, badMsg("invalid_limits", err.Error())
	}
	if role == rbac.Reseller {
		own, err := s.loadAccountLimits(r.Context(), u.ID)
		if err != nil {
			return nil, err
		}
		if f := exceedsCap(eff, own.Effective); f != "" {
			s.audit(r, "iso.limits.set", cur.Username, "exceeds reseller allowance: "+f, false)
			return nil, &apiError{Status: 403, Code: "limit_exceeds_allowance", Message: f}
		}
	}
	if in.Overrides == nil {
		in.Overrides = map[string]int64{}
	}
	ovb, _ := json.Marshal(in.Overrides)
	if _, err := s.Store.DB.ExecContext(r.Context(), `UPDATE users SET limit_profile_id=?, limit_overrides=? WHERE id=?`, in.ProfileID, string(ovb), id); err != nil {
		return nil, err
	}
	res := s.applyAccountLimits(r.Context(), id)
	s.audit(r, "iso.limits.set", cur.Username, fmt.Sprintf("profile=%v overrides=%s status=%v", ptrStr(in.ProfileID), ovb, res["status"]), res["applied"] == true)
	return res, nil
}

func ptrStr(p *int64) string {
	if p == nil {
		return "none"
	}
	return fmt.Sprint(*p)
}

// applyAccountLimits pushes the effective limits of one account to the agent.
// The result is honest: applied=false with the agent's code when it failed.
func (s *Server) applyAccountLimits(ctx context.Context, id int64) map[string]any {
	a, err := s.loadAccountLimits(ctx, id)
	if err != nil {
		return map[string]any{"applied": false, "status": "error", "code": "not_found"}
	}
	p := rpc.IsolationApply{User: a.Username, Profile: a.Effective}
	if a.Effective.IOReadBps+a.Effective.IOWriteBps+a.Effective.IOReadIOPS+a.Effective.IOWriteIOPS > 0 {
		p.IOPath = isoIOPath
	}
	var out rpc.IsolationApplyResult
	if err := s.Agent.Call(ctx, rpc.MIsolationApply, p, &out); err != nil {
		code := "agent_error"
		var re *rpc.Error
		if errors.As(err, &re) {
			code = re.Code
		}
		if s.Log != nil {
			s.Log.Warn("isolation.apply", "account", a.Username, "code", code)
		}
		return map[string]any{"applied": false, "status": "failed", "code": code}
	}
	return map[string]any{"applied": true, "status": out.Status, "unit": out.Unit, "reason": out.Reason}
}

func (s *Server) isolationStatus(w http.ResponseWriter, r *http.Request) (any, error) {
	var out rpc.IsolationStatusResult
	if err := s.Agent.Call(r.Context(), rpc.MIsolationStatus, rpc.IsolationUser{}, &out); err != nil {
		var re *rpc.Error
		if errors.As(err, &re) && re.Code == "unknown_method" {
			return map[string]any{"supported": false, "reason": "agent does not support isolation"}, nil
		}
		return nil, err
	}
	return map[string]any{"supported": out.Probe.Supported, "reason": out.Probe.Reason, "probe": out.Probe, "systemd_pid1": out.SystemdPID1}, nil
}

// ---- usage ----------------------------------------------------------------------

// usageRange maps ?range= to (window seconds, step seconds).
func usageRange(v string) (int64, int64, error) {
	switch v {
	case "", "24h":
		return 86400, usageBucket, nil
	case "1h":
		return 3600, usageBucket, nil
	case "7d":
		return 7 * 86400, 3600, nil
	case "30d":
		return 30 * 86400, 4 * 3600, nil
	}
	return 0, 0, badMsg("invalid_range", "range: 1h|24h|7d|30d")
}

// UsagePoint is one chart point. CPUPct is the average over the step
// (100 = one core); IO values are average bytes per second.
type UsagePoint struct {
	TS       int64            `json:"ts"`
	CPUPct   float64          `json:"cpu_pct"`
	MemBytes int64            `json:"mem_bytes"`
	IORBps   int64            `json:"io_r_bps"`
	IOWBps   int64            `json:"io_w_bps"`
	Pids     int64            `json:"pids"`
	Events   map[string]int64 `json:"events,omitempty"`
}

func (s *Server) usageSeries(ctx context.Context, id int64, rng string) (map[string]any, error) {
	win, step, err := usageRange(rng)
	if err != nil {
		return nil, err
	}
	since := s.Now().Unix() - win
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT (bucket_ts/?)*? AS t, SUM(cpu_usec), MAX(mem_bytes), SUM(io_r), SUM(io_w), MAX(pids), group_concat(events, char(10))
		FROM usage_samples WHERE account_id=? AND bucket_ts>=? GROUP BY t ORDER BY t`, step, step, id, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pts := []UsagePoint{}
	totals := map[string]int64{}
	for rows.Next() {
		var p UsagePoint
		var cpu, ior, iow int64
		var evs sql.NullString
		if err := rows.Scan(&p.TS, &cpu, &p.MemBytes, &ior, &iow, &p.Pids, &evs); err != nil {
			return nil, err
		}
		p.CPUPct = float64(cpu) / float64(step*1e6) * 100
		p.IORBps, p.IOWBps = ior/step, iow/step
		for _, line := range strings.Split(evs.String, "\n") {
			m := map[string]int64{}
			if json.Unmarshal([]byte(line), &m) == nil {
				for k, v := range m {
					if p.Events == nil {
						p.Events = map[string]int64{}
					}
					p.Events[k] += v
					totals[k] += v
				}
			}
		}
		pts = append(pts, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	lim, err := s.loadAccountLimits(ctx, id)
	if err != nil {
		return nil, err
	}
	st := samplerStateOf(s)
	return map[string]any{"range": rangeOr(rng), "step": step, "points": pts, "events": totals, "limits": lim.Effective,
		"username": lim.Username, "sampler": st.status()}, nil
}

func rangeOr(v string) string {
	if v == "" {
		return "24h"
	}
	return v
}

func (s *Server) adminAccountUsage(w http.ResponseWriter, r *http.Request) (any, error) {
	id := idParam(r, "id")
	if !s.canManageAccount(r, id) {
		return nil, forbidden()
	}
	return s.usageSeries(r.Context(), id, r.URL.Query().Get("range"))
}

func (s *Server) ownUsage(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	if u == nil {
		return nil, forbidden()
	}
	return s.usageSeries(r.Context(), u.ID, r.URL.Query().Get("range"))
}

// usageTop lists the heaviest accounts of the last hour the caller may see.
func (s *Server) usageTop(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	if u == nil {
		return nil, forbidden()
	}
	where, args := "1=1", []any{}
	switch roleOf(r) {
	case rbac.SuperAdmin, rbac.ServerAdmin, rbac.SecurityAdmin, rbac.Auditor:
	case rbac.Reseller:
		where, args = "u.owner_id=?", []any{u.ID}
	case rbac.Technical:
		where, args = "u.id IN (SELECT account_id FROM tech_grants WHERE user_id=?)", []any{u.ID}
	default:
		return nil, forbidden()
	}
	since := s.Now().Unix() - 3600
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT u.id, u.username, SUM(x.cpu_usec), MAX(x.mem_bytes), SUM(x.io_r)+SUM(x.io_w), MAX(x.pids)
		FROM usage_samples x JOIN users u ON u.id=x.account_id WHERE x.bucket_ts>=? AND `+where+`
		GROUP BY u.id ORDER BY SUM(x.cpu_usec) DESC, MAX(x.mem_bytes) DESC LIMIT 20`, append([]any{since}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type top struct {
		ID       int64   `json:"id"`
		Username string  `json:"username"`
		CPUPct   float64 `json:"cpu_pct"`
		MemBytes int64   `json:"mem_bytes"`
		IOBytes  int64   `json:"io_bytes"`
		Pids     int64   `json:"pids"`
	}
	out := []top{}
	for rows.Next() {
		var t top
		var cpu int64
		if err := rows.Scan(&t.ID, &t.Username, &cpu, &t.MemBytes, &t.IOBytes, &t.Pids); err != nil {
			return nil, err
		}
		t.CPUPct = float64(cpu) / 3600e6 * 100
		out = append(out, t)
	}
	return map[string]any{"items": out, "sampler": samplerStateOf(s).status()}, rows.Err()
}
