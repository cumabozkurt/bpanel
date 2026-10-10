// SPDX-License-Identifier: Apache-2.0

package api

// v0.4 obsx (spec §8 monitoring/alerts/incidents, §14 notifications, §15 OS
// health): Prometheus /metrics (stdlib text format), an alert rule engine
// over internal/events and periodic checks with dedup + cooldown, incidents
// (open → acknowledged → resolved, assignment and history), notification
// channels (local SMTP, Telegram/Slack/Discord incoming webhooks; outbound
// webhooks are reused by subscribing them to "alert.*" events), file
// integrity monitoring through the agent, the OS health page and log
// retention. Everything is free software / free services; nothing paid.

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/events"
	"github.com/cumabozkurt/bpanel/internal/obsx"
	"github.com/cumabozkurt/bpanel/internal/rbac"
	"github.com/cumabozkurt/bpanel/internal/store"
)

// ---- per-server state -------------------------------------------------------

type obsxState struct {
	rec       *obsx.Recorder
	started   sync.Once
	mu        sync.Mutex
	health    *rpc.ObsxHealth
	healthAt  time.Time
	lastJobAt int64
	lastFIM   time.Time
}

var obsxStates sync.Map // *Server -> *obsxState

func (s *Server) obsx() *obsxState {
	if v, ok := obsxStates.Load(s); ok {
		return v.(*obsxState)
	}
	v, _ := obsxStates.LoadOrStore(s, &obsxState{rec: obsx.NewRecorder()})
	return v.(*obsxState)
}

// obsxSMTPAddr / obsxSend are swapped by tests.
var (
	obsxSMTPAddr = "127.0.0.1:25"
	obsxSendMail = smtp.SendMail
	obsxPost     = func(s *Server, ctx context.Context, u, ctype string, body []byte) (int, error) {
		req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Content-Type", ctype)
		req.Header.Set("User-Agent", "BPANEL-alerts")
		resp, err := s.webhookClient().Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
)

// ---- routes -------------------------------------------------------------------

func (s *Server) mountObsx(r chi.Router) {
	s.opPerm(r, rbac.ServerRead, "GET", "/admin/obsx/rules", "monitoring", "Alert rules (built-in catalogue + overrides)", nil, s.h(s.obsxListRules))
	s.opPerm(r, rbac.ServerWrite, "PUT", "/admin/obsx/rules/{rule}", "monitoring", "Change one alert rule", ObsxRuleReq{}, s.h(s.obsxPutRule))
	s.opPerm(r, rbac.ServerRead, "GET", "/admin/obsx/channels", "monitoring", "Notification channels (secrets never returned)", nil, s.h(s.obsxListChannels))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/obsx/channels", "monitoring", "Create a notification channel", ObsxChannelReq{}, s.h(s.obsxCreateChannel))
	s.opPerm(r, rbac.ServerWrite, "PUT", "/admin/obsx/channels/{id}", "monitoring", "Update a notification channel", ObsxChannelReq{}, s.h(s.obsxUpdateChannel))
	s.opPerm(r, rbac.ServerWrite, "DELETE", "/admin/obsx/channels/{id}", "monitoring", "Delete a notification channel", nil, s.h(s.obsxDeleteChannel))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/obsx/channels/{id}/test", "monitoring", "Send a test notification", nil, s.h(s.obsxTestChannel))
	s.opPerm(r, rbac.ServerRead, "GET", "/admin/obsx/incidents", "monitoring", "Incidents (?status=open|acknowledged|resolved)", nil, s.h(s.obsxListIncidents))
	s.opPerm(r, rbac.ServerRead, "GET", "/admin/obsx/incidents/{id}", "monitoring", "One incident with its history", nil, s.h(s.obsxGetIncident))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/obsx/incidents/{id}/action", "monitoring", "ack | assign | resolve | reopen | note", ObsxIncidentAction{}, s.h(s.obsxIncidentAction))
	s.opPerm(r, rbac.ServerRead, "GET", "/admin/obsx/health", "monitoring", "OS health: reboot-required, time sync, SMART, RAID, logrotate, failed units, disks", nil, s.h(s.obsxHealth))
	s.opPerm(r, rbac.ServerRead, "GET", "/admin/obsx/fim", "monitoring", "File integrity: baseline size and last check", nil, s.h(s.obsxFIMStatus))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/obsx/fim/baseline", "monitoring", "Record a new FIM baseline (agent scan)", nil, s.h(s.obsxFIMBaseline))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/obsx/fim/check", "monitoring", "Compare the files with the baseline now", nil, s.h(s.obsxFIMCheck))
	s.opPerm(r, rbac.ServerRead, "GET", "/admin/obsx/settings", "monitoring", "Monitoring settings and log retention", nil, s.h(s.obsxGetSettings))
	s.opPerm(r, rbac.ServerWrite, "PUT", "/admin/obsx/settings", "monitoring", "Change monitoring settings and log retention", ObsxSettings{}, s.h(s.obsxPutSettings))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/obsx/evaluate", "monitoring", "Run the periodic alert checks now", nil, s.h(s.obsxEvaluateNow))
}

// ---- metrics ------------------------------------------------------------------

// obsxHTTP records request count and latency per chi route pattern.
func (s *Server) obsxHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &obsxStatusWriter{ResponseWriter: w, code: 200}
		next.ServeHTTP(sw, r)
		route := ""
		if rc := chi.RouteContext(r.Context()); rc != nil {
			route = rc.RoutePattern()
		}
		s.obsx().rec.ObserveHTTP(r.Method, route, sw.code, time.Since(start))
	})
}

type obsxStatusWriter struct {
	http.ResponseWriter
	code int
}

func (w *obsxStatusWriter) WriteHeader(c int)           { w.code = c; w.ResponseWriter.WriteHeader(c) }
func (w *obsxStatusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *obsxStatusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		w.code = http.StatusSwitchingProtocols
		return h.Hijack()
	}
	return nil, nil, errors.New("hijack not supported")
}

func (w *obsxStatusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// obsxAgent records one agent call (called from agentCall / agentCallCtx).
func (s *Server) obsxAgent(method string, err error) { s.obsx().rec.ObserveAgent(method, err) }

func isLoopback(remote string) bool {
	h, _, err := net.SplitHostPort(remote)
	if err != nil {
		h = remote
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// obsxMetrics serves GET /metrics: an admin session/API token, or a
// loopback client when obsx_metrics_localhost is on (default on).
func (s *Server) obsxMetrics(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	allowed := u != nil && u.Role == "admin" && rbac.Has(rbac.Effective(u.Role, u.SecRole), rbac.ServerRead)
	if !allowed && s.Store.Get("obsx_metrics_localhost", "1") == "1" && isLoopback(r.RemoteAddr) && r.Header.Get("X-Forwarded-For") == "" {
		allowed = true
	}
	if !allowed {
		writeJSON(w, 403, apiError{Code: "forbidden"})
		return
	}
	var b bytes.Buffer
	if err := obsx.WriteText(&b, s.obsxFamilies(r.Context())); err != nil {
		writeJSON(w, 500, apiError{Code: "internal_error"})
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b.Bytes())
}

func (s *Server) obsxFamilies(ctx context.Context) []obsx.Family {
	fams := s.obsx().rec.Families()
	db := s.Store.DB
	gauge := func(name, help string) *obsx.Family {
		fams = append(fams, obsx.Family{Name: name, Help: help, Type: "gauge"})
		return &fams[len(fams)-1]
	}
	q := func(f *obsx.Family, sqlq string, labels ...string) {
		rows, err := db.QueryContext(ctx, sqlq)
		if err != nil {
			return
		}
		defer rows.Close()
		for rows.Next() {
			vals := make([]string, len(labels))
			var v float64
			dst := []any{}
			for i := range vals {
				dst = append(dst, &vals[i])
			}
			dst = append(dst, &v)
			if rows.Scan(dst...) == nil {
				var ls []obsx.Label
				for i, l := range labels {
					ls = append(ls, obsx.Label{Name: l, Value: vals[i]})
				}
				f.Samples = append(f.Samples, obsx.Sample{Labels: ls, Value: v})
			}
		}
	}
	q(gauge("bpanel_jobs", "Background jobs by status (queued, running, done, failed)."), `SELECT status, COUNT(*) FROM jobs GROUP BY status ORDER BY status`, "status")
	q(gauge("bpanel_backup_last_success_timestamp_seconds", "Unix time of the last successful backup run per account."),
		`SELECT username, MAX(finished_at) FROM backup_runs WHERE status='ok' GROUP BY username ORDER BY username`, "account")
	q(gauge("bpanel_shield_detections", "Shield detections stored, by kind."), `SELECT kind, COUNT(*) FROM shield_detections GROUP BY kind ORDER BY kind`, "kind")
	q(gauge("bpanel_incidents", "Incidents that are not resolved, by severity."), `SELECT severity, COUNT(*) FROM obsx_incidents WHERE status<>'resolved' GROUP BY severity ORDER BY severity`, "severity")
	q(gauge("bpanel_account_cpu_usec", "CPU microseconds in the newest isolation sample bucket, per account."),
		`SELECT u.username, s.cpu_usec FROM usage_samples s JOIN users u ON u.id=s.account_id WHERE s.bucket_ts=(SELECT MAX(bucket_ts) FROM usage_samples x WHERE x.account_id=s.account_id) ORDER BY u.username`, "account")
	q(gauge("bpanel_account_memory_bytes", "Memory in the newest isolation sample bucket, per account."),
		`SELECT u.username, s.mem_bytes FROM usage_samples s JOIN users u ON u.id=s.account_id WHERE s.bucket_ts=(SELECT MAX(bucket_ts) FROM usage_samples x WHERE x.account_id=s.account_id) ORDER BY u.username`, "account")
	cert := gauge("bpanel_cert_expiry_days", "Days until the TLS certificate of a domain expires.")
	for _, c := range s.obsxCerts(ctx) {
		cert.Samples = append(cert.Samples, obsx.Sample{Labels: obsx.L("domain", c.domain), Value: c.days})
	}
	if h, _ := s.obsxHealthCached(ctx); h != nil {
		du := gauge("bpanel_disk_used_ratio", "Used fraction of a filesystem.")
		iu := gauge("bpanel_inode_used_ratio", "Used fraction of inodes of a filesystem.")
		for _, d := range h.Disks {
			du.Samples = append(du.Samples, obsx.Sample{Labels: obsx.L("mount", d.Mount), Value: d.UsedPct / 100})
			iu.Samples = append(iu.Samples, obsx.Sample{Labels: obsx.L("mount", d.Mount), Value: d.InodePct / 100})
		}
	}
	fams = append(fams, obsx.Family{Name: "bpanel_events_dropped_total", Help: "Events dropped by the in-process bus.", Type: "counter",
		Samples: []obsx.Sample{{Value: float64(events.Dropped())}}})
	return fams
}

type certDays struct {
	domain string
	days   float64
}

func (s *Server) obsxCerts(ctx context.Context) []certDays {
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT name, ssl_expires FROM domains WHERE ssl_status='active' AND ssl_expires<>'' ORDER BY name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []certDays
	now := s.Now()
	for rows.Next() {
		var n, e string
		if rows.Scan(&n, &e) != nil {
			continue
		}
		t, err := time.Parse(time.RFC3339, e)
		if err != nil {
			continue
		}
		out = append(out, certDays{n, float64(int64(t.Sub(now).Hours()/24*10)) / 10})
	}
	return out
}

func (s *Server) obsxHealthCached(ctx context.Context) (*rpc.ObsxHealth, error) {
	st := s.obsx()
	st.mu.Lock()
	if st.health != nil && time.Since(st.healthAt) < 60*time.Second {
		h := st.health
		st.mu.Unlock()
		return h, nil
	}
	st.mu.Unlock()
	var h rpc.ObsxHealth
	c, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := s.agentCallCtx(c, rpc.MObsxOSHealth, rpc.ObsxHealthReq{}, &h); err != nil {
		return nil, err
	}
	st.mu.Lock()
	st.health, st.healthAt = &h, time.Now()
	st.mu.Unlock()
	return &h, nil
}

// ---- rules ----------------------------------------------------------------------

type ObsxRuleReq struct {
	Enabled   *bool    `json:"enabled,omitempty"`
	Severity  *string  `json:"severity,omitempty"`
	Threshold *float64 `json:"threshold,omitempty"`
	Cooldown  *int64   `json:"cooldown_sec,omitempty"`
}

func (s *Server) obsxRules(ctx context.Context) []obsx.Rule {
	rules := obsx.DefaultRules()
	type row struct {
		ID        string  `db:"id"`
		Enabled   int     `db:"enabled"`
		Severity  string  `db:"severity"`
		Threshold float64 `db:"threshold"`
		Cooldown  int64   `db:"cooldown_sec"`
	}
	rs, _ := selectRows[row](ctx, s, `SELECT id,enabled,severity,threshold,cooldown_sec FROM obsx_rules`)
	for _, o := range rs {
		for i := range rules {
			if rules[i].ID == o.ID {
				rules[i].Enabled, rules[i].Severity, rules[i].Threshold, rules[i].Cooldown = o.Enabled == 1, o.Severity, o.Threshold, o.Cooldown
			}
		}
	}
	return rules
}

func (s *Server) obsxRule(ctx context.Context, id string) (obsx.Rule, bool) {
	for _, r := range s.obsxRules(ctx) {
		if r.ID == id {
			return r, true
		}
	}
	return obsx.Rule{}, false
}

func (s *Server) obsxListRules(w http.ResponseWriter, r *http.Request) (any, error) {
	return map[string]any{"rules": s.obsxRules(r.Context())}, nil
}

func (s *Server) obsxPutRule(w http.ResponseWriter, r *http.Request) (any, error) {
	rule, ok := s.obsxRule(r.Context(), chi.URLParam(r, "rule"))
	if !ok {
		return nil, &apiError{Status: 404, Code: "obsx_unknown_rule"}
	}
	var in ObsxRuleReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if in.Enabled != nil {
		rule.Enabled = *in.Enabled
	}
	if in.Severity != nil {
		if obsx.SevRank(*in.Severity) == 0 {
			return nil, &apiError{Status: 400, Code: "obsx_bad_severity", Field: "severity"}
		}
		rule.Severity = *in.Severity
	}
	if in.Threshold != nil {
		t := *in.Threshold
		bad := t < 0 || t > 100000 || (rule.ID == obsx.RuleDiskFull && (t < 1 || t > 100)) || (rule.ID == obsx.RuleCertExpiring && (t < 1 || t > 365))
		if bad {
			return nil, &apiError{Status: 400, Code: "obsx_bad_threshold", Field: "threshold"}
		}
		rule.Threshold = t
	}
	if in.Cooldown != nil {
		if *in.Cooldown < 60 || *in.Cooldown > 30*86400 {
			return nil, &apiError{Status: 400, Code: "obsx_bad_threshold", Field: "cooldown_sec"}
		}
		rule.Cooldown = *in.Cooldown
	}
	en := 0
	if rule.Enabled {
		en = 1
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO obsx_rules(id,enabled,severity,threshold,cooldown_sec) VALUES(?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled, severity=excluded.severity, threshold=excluded.threshold, cooldown_sec=excluded.cooldown_sec`,
		rule.ID, en, rule.Severity, rule.Threshold, rule.Cooldown); err != nil {
		return nil, err
	}
	s.audit(r, "obsx.rule.update", rule.ID, "", true)
	return map[string]any{"rule": rule}, nil
}

// ---- incidents: raise / dedup / cooldown --------------------------------------------

// obsxRaise records one alert occurrence. A not-resolved incident with the
// same dedup key is reused (count, last_at); notification happens for a new
// incident and then at most once per rule cooldown. Returns the incident id
// and whether notifications were sent.
func (s *Server) obsxRaise(ctx context.Context, rule obsx.Rule, key, title, detail string, accountID int64) (int64, bool) {
	if !rule.Enabled {
		return 0, false
	}
	now := s.Now()
	db := s.Store.DB
	var id, lastNotified int64
	err := db.QueryRowContext(ctx, `SELECT id,last_notified_at FROM obsx_incidents WHERE dedup_key=? AND status<>'resolved' ORDER BY id DESC LIMIT 1`, key).Scan(&id, &lastNotified)
	notify := false
	switch {
	case err == nil:
		notify = obsx.ShouldNotify(lastNotified, now, rule.Cooldown)
		if notify {
			lastNotified = now.Unix()
		}
		db.ExecContext(ctx, `UPDATE obsx_incidents SET count=count+1, last_at=?, last_notified_at=?, detail=?, severity=? WHERE id=?`, now.Unix(), lastNotified, trunc(detail, 2000), rule.Severity, id)
	case errors.Is(err, sql.ErrNoRows):
		res, err := db.ExecContext(ctx, `INSERT INTO obsx_incidents(dedup_key,rule,severity,title,detail,account_id,status,first_at,last_at,last_notified_at) VALUES(?,?,?,?,?,?,'open',?,?,?)`,
			key, rule.ID, rule.Severity, trunc(title, 300), trunc(detail, 2000), accountID, now.Unix(), now.Unix(), now.Unix())
		if err != nil {
			return 0, false
		}
		id, _ = res.LastInsertId()
		db.ExecContext(ctx, `INSERT INTO obsx_incident_history(incident_id,at,action,note) VALUES(?,?,'opened',?)`, id, now.Unix(), trunc(title, 300))
		notify = true
	default:
		return 0, false
	}
	if notify {
		events.Publish(ctx, events.Event{Type: "alert.fired", Severity: rule.Severity, AccountID: accountID,
			Data: map[string]any{"incident_id": id, "rule": rule.ID, "title": title}})
		go s.obsxNotify(context.WithoutCancel(ctx), rule.Severity, fmt.Sprintf("[%s] %s", strings.ToUpper(rule.Severity), title), detail)
	}
	return id, notify
}

// obsxClear auto-resolves the open incident of key (condition no longer true).
func (s *Server) obsxClear(ctx context.Context, key string) {
	now := s.Now().Unix()
	var id int64
	if s.Store.DB.QueryRowContext(ctx, `SELECT id FROM obsx_incidents WHERE dedup_key=? AND status<>'resolved' ORDER BY id DESC LIMIT 1`, key).Scan(&id) != nil {
		return
	}
	s.Store.DB.ExecContext(ctx, `UPDATE obsx_incidents SET status='resolved', resolved_at=? WHERE id=?`, now, id)
	s.Store.DB.ExecContext(ctx, `INSERT INTO obsx_incident_history(incident_id,at,action,note) VALUES(?,?,'auto_resolved','condition cleared')`, id, now)
}

// obsxOnEvent maps bus events onto the event rules.
func (s *Server) obsxOnEvent(e events.Event) {
	if strings.HasPrefix(e.Type, "alert.") {
		return
	}
	ctx := context.Background()
	for _, rule := range s.obsxRules(ctx) {
		if rule.Events == "" || !eventMatches(rule.Events, e.Type) {
			continue
		}
		key := rule.ID
		if e.AccountID != 0 {
			key += ":" + strconv.FormatInt(e.AccountID, 10)
		}
		detail := ""
		if len(e.Data) > 0 {
			if b, err := json.Marshal(e.Data); err == nil {
				detail = string(b)
			}
		}
		s.obsxRaise(ctx, rule, key, e.Type, detail, e.AccountID)
	}
}

// startObsx subscribes the event rules and runs the periodic checks.
func (s *Server) startObsx(ctx context.Context) {
	s.obsx().started.Do(func() {
		unsub := events.Subscribe(func(e events.Event) { go s.obsxOnEvent(e) })
		go func() {
			defer unsub()
			s.obsx().lastJobAt = s.Now().Unix()
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			var last time.Time
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
				iv := time.Duration(s.settingInt("obsx_eval_interval_min", 5)) * time.Minute
				if iv <= 0 || time.Since(last) < iv {
					continue
				}
				last = time.Now()
				s.obsxEvaluate(ctx)
			}
		}()
	})
}

// obsxEvaluate runs the periodic (metric) rules once.
func (s *Server) obsxEvaluate(ctx context.Context) map[string]int {
	out := map[string]int{}
	rules := map[string]obsx.Rule{}
	for _, r := range s.obsxRules(ctx) {
		rules[r.ID] = r
	}
	if r := rules[obsx.RuleCertExpiring]; r.Enabled {
		for _, c := range s.obsxCerts(ctx) {
			key := "cert:" + c.domain
			if c.days < r.Threshold {
				s.obsxRaise(ctx, r, key, fmt.Sprintf("TLS certificate of %s expires in %.0f days", c.domain, c.days), "", 0)
				out[r.ID]++
			} else {
				s.obsxClear(ctx, key)
			}
		}
	}
	if r := rules[obsx.RuleDiskFull]; r.Enabled {
		if h, err := s.obsxHealthCached(ctx); err == nil {
			for _, d := range h.Disks {
				key := "disk:" + d.Mount
				if d.UsedPct > r.Threshold || d.InodePct > r.Threshold {
					s.obsxRaise(ctx, r, key, fmt.Sprintf("Filesystem %s is %.0f%% full (inodes %.0f%%)", d.Mount, d.UsedPct, d.InodePct), "", 0)
					out[r.ID]++
				} else {
					s.obsxClear(ctx, key)
				}
			}
		}
	}
	if r := rules[obsx.RuleServiceDown]; r.Enabled {
		var st rpc.ServiceStatus
		c, cancel := context.WithTimeout(ctx, time.Minute)
		if err := s.agentCallCtx(c, rpc.MServiceStatus, rpc.ServiceStatusReq{}, &st); err == nil {
			for _, sv := range st.Services {
				key := "service:" + sv.Unit
				if sv.Active == "failed" || (sv.Enabled == "enabled" && sv.Active == "inactive") {
					s.obsxRaise(ctx, r, key, fmt.Sprintf("Service %s is %s", sv.Unit, sv.Active), "", 0)
					out[r.ID]++
				} else {
					s.obsxClear(ctx, key)
				}
			}
		}
		cancel()
	}
	if r := rules[obsx.RuleLoginBurst]; r.Enabled {
		var n int
		s.Store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM login_failures WHERE at>=?`, s.Now().Add(-10*time.Minute).Unix()).Scan(&n)
		if float64(n) >= r.Threshold && n > 0 {
			s.obsxRaise(ctx, r, "login_burst", fmt.Sprintf("%d failed logins in the last 10 minutes", n), "", 0)
			out[r.ID]++
		}
	}
	if r := rules[obsx.RuleJobFailures]; r.Enabled {
		st := s.obsx()
		since := st.lastJobAt
		now := s.Now().Unix()
		var n int
		s.Store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs WHERE status='failed' AND updated_at>?`, since).Scan(&n)
		st.lastJobAt = now
		if n > 0 && float64(n) >= r.Threshold {
			s.obsxRaise(ctx, r, "jobs_failed", fmt.Sprintf("%d background job(s) failed", n), "", 0)
			out[r.ID]++
		}
	}
	if iv := s.settingInt("obsx_fim_interval_min", 360); iv > 0 {
		st := s.obsx()
		if time.Since(st.lastFIM) >= time.Duration(iv)*time.Minute {
			st.lastFIM = time.Now()
			if res, err := s.obsxFIMRun(ctx); err == nil && len(res) > 0 {
				out[obsx.RuleFIMChange] = len(res)
			}
		}
	}
	return out
}

func (s *Server) obsxEvaluateNow(w http.ResponseWriter, r *http.Request) (any, error) {
	s.audit(r, "obsx.evaluate", "", "", true)
	return map[string]any{"raised": s.obsxEvaluate(r.Context())}, nil
}

// ---- incidents API ------------------------------------------------------------------

type obsxIncident struct {
	ID         int64  `db:"id" json:"id"`
	Key        string `db:"dedup_key" json:"dedup_key"`
	Rule       string `db:"rule" json:"rule"`
	Severity   string `db:"severity" json:"severity"`
	Title      string `db:"title" json:"title"`
	Detail     string `db:"detail" json:"detail"`
	AccountID  int64  `db:"account_id" json:"account_id"`
	Status     string `db:"status" json:"status"`
	AssigneeID int64  `db:"assignee_id" json:"assignee_id"`
	Assignee   string `db:"assignee" json:"assignee"`
	Count      int64  `db:"count" json:"count"`
	FirstAt    int64  `db:"first_at" json:"first_at"`
	LastAt     int64  `db:"last_at" json:"last_at"`
	ResolvedAt int64  `db:"resolved_at" json:"resolved_at"`
}

const obsxIncSel = `SELECT i.id,i.dedup_key,i.rule,i.severity,i.title,i.detail,i.account_id,i.status,i.assignee_id,COALESCE(u.username,'') AS assignee,i.count,i.first_at,i.last_at,i.resolved_at FROM obsx_incidents i LEFT JOIN users u ON u.id=i.assignee_id`

func (s *Server) obsxListIncidents(w http.ResponseWriter, r *http.Request) (any, error) {
	st := r.URL.Query().Get("status")
	var rs []obsxIncident
	var err error
	switch st {
	case "", "active":
		rs, err = selectRows[obsxIncident](r.Context(), s, obsxIncSel+` WHERE i.status<>'resolved' ORDER BY i.last_at DESC LIMIT 500`)
	case obsx.IncOpen, obsx.IncAcknowledged, obsx.IncResolved:
		rs, err = selectRows[obsxIncident](r.Context(), s, obsxIncSel+` WHERE i.status=? ORDER BY i.last_at DESC LIMIT 500`, st)
	case "all":
		rs, err = selectRows[obsxIncident](r.Context(), s, obsxIncSel+` ORDER BY i.last_at DESC LIMIT 500`)
	default:
		return nil, &apiError{Status: 400, Code: "obsx_bad_filter", Field: "status"}
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"incidents": rs}, nil
}

type obsxHist struct {
	At     int64  `db:"at" json:"at"`
	Actor  string `db:"actor" json:"actor"`
	Action string `db:"action" json:"action"`
	Note   string `db:"note" json:"note"`
}

func (s *Server) obsxIncidentByID(ctx context.Context, id int64) (*obsxIncident, error) {
	rs, err := selectRows[obsxIncident](ctx, s, obsxIncSel+` WHERE i.id=?`, id)
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, notFound()
	}
	return &rs[0], nil
}

func (s *Server) obsxGetIncident(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	inc, err := s.obsxIncidentByID(r.Context(), id)
	if err != nil {
		return nil, err
	}
	hist, _ := selectRows[obsxHist](r.Context(), s, `SELECT at,actor,action,note FROM obsx_incident_history WHERE incident_id=? ORDER BY at, id`, id)
	return map[string]any{"incident": inc, "history": hist}, nil
}

type ObsxIncidentAction struct {
	Action     string `json:"action"` // ack | assign | resolve | reopen | note
	AssigneeID int64  `json:"assignee_id,omitempty"`
	Note       string `json:"note,omitempty"`
}

func (s *Server) obsxIncidentAction(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	var in ObsxIncidentAction
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if len(in.Note) > 2000 {
		return nil, &apiError{Status: 400, Code: "too_long", Field: "note", Max: 2000}
	}
	if in.Action == "note" && strings.TrimSpace(in.Note) == "" {
		return nil, &apiError{Status: 400, Code: "obsx_required", Field: "note"}
	}
	inc, err := s.obsxIncidentByID(r.Context(), id)
	if err != nil {
		return nil, err
	}
	next, err := obsx.Transition(inc.Status, in.Action)
	if err != nil {
		return nil, &apiError{Status: 409, Code: "incident_bad_transition", Message: inc.Status + " -> " + in.Action}
	}
	u := userOf(r)
	now := s.Now().Unix()
	note := in.Note
	assignee := inc.AssigneeID
	if in.Action == "assign" {
		var role string
		if in.AssigneeID != 0 {
			if err := s.Store.DB.QueryRowContext(r.Context(), `SELECT role FROM users WHERE id=?`, in.AssigneeID).Scan(&role); err != nil || role != "admin" {
				return nil, &apiError{Status: 400, Code: "obsx_bad_assignee", Field: "assignee_id"}
			}
		}
		assignee = in.AssigneeID
		if note == "" {
			note = "assignee_id=" + strconv.FormatInt(assignee, 10)
		}
	}
	resolvedAt := inc.ResolvedAt
	switch next {
	case obsx.IncResolved:
		if inc.Status != obsx.IncResolved {
			resolvedAt = now
		}
	case obsx.IncOpen:
		resolvedAt = 0
	}
	tx, err := s.Store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// optimistic: the status must still be what we read
	res, err := tx.ExecContext(r.Context(), `UPDATE obsx_incidents SET status=?, assignee_id=?, resolved_at=? WHERE id=? AND status=?`, next, assignee, resolvedAt, id, inc.Status)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, conflict("incident_bad_transition")
	}
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO obsx_incident_history(incident_id,at,actor_id,actor,action,note) VALUES(?,?,?,?,?,?)`, id, now, u.ID, u.Username, in.Action, note); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.audit(r, "obsx.incident."+in.Action, strconv.FormatInt(id, 10), "", true)
	return s.obsxGetIncident(w, r)
}

// ---- channels -----------------------------------------------------------------------

type ObsxChannelReq struct {
	Name        string  `json:"name"`
	Kind        string  `json:"kind"`
	Target      string  `json:"target"`
	Secret      *string `json:"secret,omitempty"` // telegram bot token / slack or discord webhook URL; write-only
	MinSeverity string  `json:"min_severity"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

type obsxChannel struct {
	ID          int64  `db:"id" json:"id"`
	Name        string `db:"name" json:"name"`
	Kind        string `db:"kind" json:"kind"`
	Target      string `db:"target" json:"target"`
	MinSeverity string `db:"min_severity" json:"min_severity"`
	Enabled     int    `db:"enabled" json:"enabled"`
	LastStatus  string `db:"last_status" json:"last_status"`
	LastError   string `db:"last_error" json:"last_error"`
	LastAt      int64  `db:"last_at" json:"last_at"`
	HasSecret   bool   `db:"-" json:"has_secret"`
}

var (
	reTgToken   = regexp.MustCompile(`^[0-9]{5,15}:[A-Za-z0-9_-]{30,64}$`)
	reTgChat    = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32})$`)
	reEmailAddr = regexp.MustCompile(`^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$`)
)

func obsxChanSecretName(id int64) string { return "obsx/channel/" + strconv.FormatInt(id, 10) }

func validSecretFor(kind, sec string) bool {
	switch kind {
	case "telegram":
		return reTgToken.MatchString(sec)
	case "slack":
		return strings.HasPrefix(sec, "https://hooks.slack.com/services/") && len(sec) < 300 && !strings.ContainsAny(sec, " \n")
	case "discord":
		return (strings.HasPrefix(sec, "https://discord.com/api/webhooks/") || strings.HasPrefix(sec, "https://discordapp.com/api/webhooks/")) && len(sec) < 300 && !strings.ContainsAny(sec, " \n")
	}
	return false
}

func (in *ObsxChannelReq) validate(creating bool) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 100 {
		return &apiError{Status: 400, Code: "obsx_required", Field: "name"}
	}
	if in.MinSeverity == "" {
		in.MinSeverity = obsx.SevWarning
	}
	if obsx.SevRank(in.MinSeverity) == 0 {
		return &apiError{Status: 400, Code: "obsx_bad_severity", Field: "min_severity"}
	}
	in.Target = strings.TrimSpace(in.Target)
	switch in.Kind {
	case "email":
		addrs := strings.Split(in.Target, ",")
		if in.Target == "" || len(addrs) > 10 {
			return &apiError{Status: 400, Code: "obsx_bad_target", Field: "target"}
		}
		for _, a := range addrs {
			if !reEmailAddr.MatchString(strings.TrimSpace(a)) {
				return &apiError{Status: 400, Code: "obsx_bad_target", Field: "target"}
			}
		}
		if in.Secret != nil && *in.Secret != "" {
			return &apiError{Status: 400, Code: "obsx_bad_secret", Field: "secret"}
		}
	case "telegram", "slack", "discord":
		if in.Kind == "telegram" && !reTgChat.MatchString(in.Target) {
			return &apiError{Status: 400, Code: "obsx_bad_target", Field: "target"}
		}
		if in.Kind != "telegram" {
			in.Target = ""
		}
		if creating && in.Secret == nil {
			return &apiError{Status: 400, Code: "obsx_bad_secret", Field: "secret"}
		}
		if in.Secret != nil && !validSecretFor(in.Kind, *in.Secret) {
			return &apiError{Status: 400, Code: "obsx_bad_secret", Field: "secret"}
		}
	default:
		return &apiError{Status: 400, Code: "obsx_bad_channel_kind", Field: "kind"}
	}
	return nil
}

func (s *Server) obsxChannels(ctx context.Context) ([]obsxChannel, error) {
	rs, err := selectRows[obsxChannel](ctx, s, `SELECT id,name,kind,target,min_severity,enabled,last_status,last_error,last_at FROM obsx_channels ORDER BY id`)
	for i := range rs {
		rs[i].HasSecret = rs[i].Kind == "email"
		if rs[i].Kind != "email" {
			if b, err := s.Secrets().Get(ctx, obsxChanSecretName(rs[i].ID)); err == nil && len(b) > 0 {
				rs[i].HasSecret = true
			}
		}
	}
	return rs, err
}

func (s *Server) obsxListChannels(w http.ResponseWriter, r *http.Request) (any, error) {
	rs, err := s.obsxChannels(r.Context())
	if err != nil {
		return nil, err
	}
	return map[string]any{"channels": rs, "secret_store": s.Secrets().Status(), "smtp": obsxSMTPAddr,
		"webhook_note": "outbound webhooks receive alert.fired events: subscribe a webhook to alert.*"}, nil
}

func (s *Server) obsxCreateChannel(w http.ResponseWriter, r *http.Request) (any, error) {
	var in ObsxChannelReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := in.validate(true); err != nil {
		return nil, err
	}
	en := 1
	if in.Enabled != nil && !*in.Enabled {
		en = 0
	}
	res, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO obsx_channels(name,kind,target,min_severity,enabled,created_at) VALUES(?,?,?,?,?,?)`,
		in.Name, in.Kind, in.Target, in.MinSeverity, en, s.Now().Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if in.Secret != nil && in.Kind != "email" {
		if err := s.Secrets().Put(r.Context(), obsxChanSecretName(id), []byte(*in.Secret)); err != nil {
			s.Store.DB.ExecContext(r.Context(), `DELETE FROM obsx_channels WHERE id=?`, id)
			return nil, errSecretsUnavailable
		}
	}
	s.audit(r, "obsx.channel.create", in.Name, in.Kind, true)
	return map[string]any{"id": id}, nil
}

func (s *Server) obsxChannelByID(ctx context.Context, id int64) (*obsxChannel, error) {
	rs, err := selectRows[obsxChannel](ctx, s, `SELECT id,name,kind,target,min_severity,enabled,last_status,last_error,last_at FROM obsx_channels WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, notFound()
	}
	return &rs[0], nil
}

func (s *Server) obsxUpdateChannel(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	ch, err := s.obsxChannelByID(r.Context(), id)
	if err != nil {
		return nil, err
	}
	var in ObsxChannelReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	in.Kind = ch.Kind // kind is immutable
	if err := in.validate(false); err != nil {
		return nil, err
	}
	en := ch.Enabled
	if in.Enabled != nil {
		en = 0
		if *in.Enabled {
			en = 1
		}
	}
	if in.Secret != nil && in.Kind != "email" {
		if err := s.Secrets().Put(r.Context(), obsxChanSecretName(id), []byte(*in.Secret)); err != nil {
			return nil, errSecretsUnavailable
		}
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `UPDATE obsx_channels SET name=?,target=?,min_severity=?,enabled=? WHERE id=?`, in.Name, in.Target, in.MinSeverity, en, id); err != nil {
		return nil, err
	}
	s.audit(r, "obsx.channel.update", in.Name, "", true)
	return nil, nil
}

func (s *Server) obsxDeleteChannel(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	ch, err := s.obsxChannelByID(r.Context(), id)
	if err != nil {
		return nil, err
	}
	s.Store.DB.ExecContext(r.Context(), `DELETE FROM obsx_channels WHERE id=?`, id)
	_ = s.Secrets().Delete(r.Context(), obsxChanSecretName(id))
	s.audit(r, "obsx.channel.delete", ch.Name, "", true)
	return nil, nil
}

func (s *Server) obsxTestChannel(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	ch, err := s.obsxChannelByID(r.Context(), id)
	if err != nil {
		return nil, err
	}
	code := s.obsxSendOne(r.Context(), ch, "[TEST] BPANEL alert channel test", "This is a test notification from BPANEL.")
	s.audit(r, "obsx.channel.test", ch.Name, code, code == "")
	if code != "" {
		return nil, &apiError{Status: 502, Code: code}
	}
	return map[string]any{"status": "sent"}, nil
}

// obsxNotify sends one alert to every enabled channel whose min severity is met.
func (s *Server) obsxNotify(ctx context.Context, severity, title, detail string) {
	chs, err := s.obsxChannels(ctx)
	if err != nil {
		return
	}
	for i := range chs {
		ch := &chs[i]
		if ch.Enabled != 1 || obsx.SevRank(severity) < obsx.SevRank(ch.MinSeverity) {
			continue
		}
		s.obsxSendOne(ctx, ch, title, detail)
	}
}

// obsxSendOne returns "" on success or an error code; the outcome is stored
// on the channel (codes only, never secrets or upstream bodies).
func (s *Server) obsxSendOne(ctx context.Context, ch *obsxChannel, title, detail string) string {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	host := s.Cfg.Hostname
	if host == "" {
		host = "localhost"
	}
	text := title
	if detail != "" {
		text += "\n" + trunc(detail, 1500)
	}
	text += "\n— BPANEL " + host
	code := ""
	switch ch.Kind {
	case "email":
		from := s.Store.Get("obsx_mail_from", "bpanel@"+host)
		var to []string
		for _, a := range strings.Split(ch.Target, ",") {
			to = append(to, strings.TrimSpace(a))
		}
		msg := "From: " + from + "\r\nTo: " + strings.Join(to, ", ") + "\r\nSubject: " + strings.NewReplacer("\r", " ", "\n", " ").Replace(title) +
			"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + strings.ReplaceAll(text, "\n", "\r\n") + "\r\n"
		if err := obsxSendMail(obsxSMTPAddr, nil, from, to, []byte(msg)); err != nil {
			code = "obsx_smtp_unavailable"
		}
	default:
		secret, err := s.Secrets().Get(ctx, obsxChanSecretName(ch.ID))
		if err != nil || len(secret) == 0 {
			code = "obsx_bad_secret"
			break
		}
		var u, ctype string
		var body []byte
		switch ch.Kind {
		case "telegram":
			u = "https://api.telegram.org/bot" + string(secret) + "/sendMessage"
			ctype = "application/x-www-form-urlencoded"
			body = []byte(url.Values{"chat_id": {ch.Target}, "text": {text}}.Encode())
		case "slack":
			u, ctype = string(secret), "application/json"
			body, _ = json.Marshal(map[string]string{"text": text})
		case "discord":
			u, ctype = string(secret), "application/json"
			body, _ = json.Marshal(map[string]string{"content": trunc(text, 1900)})
		}
		st, err := obsxPost(s, ctx, u, ctype, body)
		if err != nil || st < 200 || st > 299 {
			code = "obsx_send_failed"
		}
	}
	status := "sent"
	if code != "" {
		status = "failed"
	}
	s.Store.DB.ExecContext(context.WithoutCancel(ctx), `UPDATE obsx_channels SET last_status=?, last_error=?, last_at=? WHERE id=?`, status, code, s.Now().Unix(), ch.ID)
	return code
}

// ---- OS health ------------------------------------------------------------------------

func (s *Server) obsxHealth(w http.ResponseWriter, r *http.Request) (any, error) {
	st := s.obsx()
	st.mu.Lock()
	st.health = nil // explicit page load: fresh probe
	st.mu.Unlock()
	h, err := s.obsxHealthCached(r.Context())
	if err != nil {
		return nil, err
	}
	return h, nil
}

// ---- FIM --------------------------------------------------------------------------------

func (s *Server) obsxFIMScan(ctx context.Context) (*rpc.ObsxFIMResult, error) {
	var res rpc.ObsxFIMResult
	c, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := s.agentCallCtx(c, rpc.MObsxFIMScan, rpc.ObsxFIMReq{}, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

type obsxFIMRow struct {
	Path   string `db:"path"`
	Mode   string `db:"mode"`
	SHA256 string `db:"sha256"`
	Size   int64  `db:"size"`
	MTime  int64  `db:"mtime"`
	UID    int64  `db:"uid"`
	GID    int64  `db:"gid"`
	Perm   int64  `db:"perm"`
}

func (s *Server) obsxBaseline(ctx context.Context) ([]obsx.FIMEntry, error) {
	rs, err := selectRows[obsxFIMRow](ctx, s, `SELECT path,mode,sha256,size,mtime,uid,gid,perm FROM obsx_fim_baseline ORDER BY path`)
	if err != nil {
		return nil, err
	}
	out := make([]obsx.FIMEntry, len(rs))
	for i, r := range rs {
		out[i] = obsx.FIMEntry{Path: r.Path, Mode: r.Mode, SHA256: r.SHA256, Size: r.Size, MTime: r.MTime, UID: uint32(r.UID), GID: uint32(r.GID), Perm: uint32(r.Perm)}
	}
	return out, nil
}

func (s *Server) obsxSaveBaseline(ctx context.Context, es []obsx.FIMEntry) error {
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM obsx_fim_baseline`); err != nil {
		return err
	}
	now := s.Now().Unix()
	for _, e := range es {
		if _, err := tx.ExecContext(ctx, `INSERT INTO obsx_fim_baseline(path,mode,sha256,size,mtime,uid,gid,perm,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`,
			e.Path, e.Mode, e.SHA256, e.Size, e.MTime, e.UID, e.GID, e.Perm, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type obsxFIMLast struct {
	At      int64            `json:"at"`
	Changes []obsx.FIMChange `json:"changes"`
	Files   int              `json:"files"`
	Missing []string         `json:"missing"`
	Errors  []string         `json:"errors"`
}

// obsxFIMRun compares a fresh scan with the baseline, stores the result
// and raises fim_change (plus an obsx.fim_change event) on differences.
func (s *Server) obsxFIMRun(ctx context.Context) ([]obsx.FIMChange, error) {
	base, err := s.obsxBaseline(ctx)
	if err != nil {
		return nil, err
	}
	if len(base) == 0 {
		return nil, &apiError{Status: 409, Code: "obsx_no_baseline"}
	}
	res, err := s.obsxFIMScan(ctx)
	if err != nil {
		return nil, err
	}
	ch := obsx.Diff(base, res.Entries)
	if ch == nil {
		ch = []obsx.FIMChange{}
	}
	last := obsxFIMLast{At: s.Now().Unix(), Changes: ch, Files: len(res.Entries), Missing: res.Missing, Errors: res.Errors}
	if b, err := json.Marshal(last); err == nil {
		s.Store.Set("obsx_fim_last", string(b))
	}
	if len(ch) > 0 {
		paths := make([]string, 0, len(ch))
		for i, c := range ch {
			if i >= 20 {
				break
			}
			paths = append(paths, c.Change+" "+c.Path)
		}
		if rule, ok := s.obsxRule(ctx, obsx.RuleFIMChange); ok {
			s.obsxRaise(ctx, rule, "fim", fmt.Sprintf("File integrity: %d change(s) against the baseline", len(ch)), strings.Join(paths, "\n"), 0)
		}
		events.Publish(ctx, events.Event{Type: "obsx.fim_change", Severity: events.Critical, Data: map[string]any{"changes": len(ch), "paths": paths}})
		s.auditSystem("obsx.fim.change", "", strconv.Itoa(len(ch)), false)
	}
	return ch, nil
}

func (s *Server) obsxFIMStatus(w http.ResponseWriter, r *http.Request) (any, error) {
	var n int
	var at int64
	s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*), COALESCE(MAX(updated_at),0) FROM obsx_fim_baseline`).Scan(&n, &at)
	var last *obsxFIMLast
	if v := s.Store.Get("obsx_fim_last", ""); v != "" {
		var l obsxFIMLast
		if json.Unmarshal([]byte(v), &l) == nil {
			last = &l
		}
	}
	return map[string]any{"baseline_files": n, "baseline_at": at, "last": last, "interval_min": s.settingInt("obsx_fim_interval_min", 360)}, nil
}

func (s *Server) obsxFIMBaseline(w http.ResponseWriter, r *http.Request) (any, error) {
	res, err := s.obsxFIMScan(r.Context())
	if err != nil {
		return nil, err
	}
	if err := s.obsxSaveBaseline(r.Context(), res.Entries); err != nil {
		return nil, err
	}
	s.Store.Set("obsx_fim_last", "")
	s.audit(r, "obsx.fim.baseline", "", strconv.Itoa(len(res.Entries)), true)
	return map[string]any{"files": len(res.Entries), "missing": res.Missing, "errors": res.Errors, "reason": res.Reason}, nil
}

func (s *Server) obsxFIMCheck(w http.ResponseWriter, r *http.Request) (any, error) {
	ch, err := s.obsxFIMRun(r.Context())
	if err != nil {
		return nil, err
	}
	s.audit(r, "obsx.fim.check", "", strconv.Itoa(len(ch)), true)
	return map[string]any{"changes": ch}, nil
}

// ---- settings + retention --------------------------------------------------------------

type ObsxSettings struct {
	MetricsLocalhost *bool   `json:"metrics_localhost,omitempty"`
	EvalIntervalMin  *int    `json:"eval_interval_min,omitempty"`
	FIMIntervalMin   *int    `json:"fim_interval_min,omitempty"`
	MailFrom         *string `json:"mail_from,omitempty"`
	AuditDays        *int    `json:"audit_days,omitempty"`
	EventsDays       *int    `json:"events_days,omitempty"`
	BandwidthDays    *int    `json:"bandwidth_days,omitempty"`
	IncidentsDays    *int    `json:"incidents_days,omitempty"`
}

var obsxRetention = []struct {
	field, key   string
	def, min, mx int
}{
	{"audit_days", "obsx_ret_audit_days", 180, 7, 3650},
	{"events_days", "events_retention_days", 90, 1, 3650},
	{"bandwidth_days", "obsx_ret_bandwidth_days", 400, 31, 3650},
	{"incidents_days", "obsx_ret_incidents_days", 365, 7, 3650},
}

func (s *Server) obsxRetDays(key string) int {
	for _, r := range obsxRetention {
		if r.key == key {
			v := s.settingInt(key, r.def)
			if v < r.min || v > r.mx {
				return r.def
			}
			return v
		}
	}
	return 0
}

// obsxAuditDays is the audit_log retention used by prune (server.go).
func (s *Server) obsxAuditDays() int64 { return int64(s.obsxRetDays("obsx_ret_audit_days")) }

func (s *Server) obsxGetSettings(w http.ResponseWriter, r *http.Request) (any, error) {
	ret := map[string]int{}
	for _, x := range obsxRetention {
		ret[x.field] = s.obsxRetDays(x.key)
	}
	host := s.Cfg.Hostname
	if host == "" {
		host = "localhost"
	}
	return map[string]any{
		"metrics_localhost": s.Store.Get("obsx_metrics_localhost", "1") == "1",
		"eval_interval_min": s.settingInt("obsx_eval_interval_min", 5),
		"fim_interval_min":  s.settingInt("obsx_fim_interval_min", 360),
		"mail_from":         s.Store.Get("obsx_mail_from", "bpanel@"+host),
		"retention":         ret,
		"retention_limits":  obsxRetention2JSON(),
	}, nil
}

func obsxRetention2JSON() map[string][2]int {
	m := map[string][2]int{}
	for _, x := range obsxRetention {
		m[x.field] = [2]int{x.min, x.mx}
	}
	return m
}

func (s *Server) obsxPutSettings(w http.ResponseWriter, r *http.Request) (any, error) {
	var in ObsxSettings
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	sets := map[string]string{}
	if in.MetricsLocalhost != nil {
		sets["obsx_metrics_localhost"] = map[bool]string{true: "1", false: "0"}[*in.MetricsLocalhost]
	}
	if in.EvalIntervalMin != nil {
		if *in.EvalIntervalMin < 0 || *in.EvalIntervalMin > 1440 {
			return nil, &apiError{Status: 400, Code: "invalid_limit", Field: "eval_interval_min", Max: 1440}
		}
		sets["obsx_eval_interval_min"] = strconv.Itoa(*in.EvalIntervalMin)
	}
	if in.FIMIntervalMin != nil {
		if *in.FIMIntervalMin < 0 || *in.FIMIntervalMin > 10080 {
			return nil, &apiError{Status: 400, Code: "invalid_limit", Field: "fim_interval_min", Max: 10080}
		}
		sets["obsx_fim_interval_min"] = strconv.Itoa(*in.FIMIntervalMin)
	}
	if in.MailFrom != nil {
		if !reEmailAddr.MatchString(*in.MailFrom) {
			return nil, &apiError{Status: 400, Code: "obsx_bad_target", Field: "mail_from"}
		}
		sets["obsx_mail_from"] = *in.MailFrom
	}
	for _, x := range []struct {
		v     *int
		field string
	}{{in.AuditDays, "audit_days"}, {in.EventsDays, "events_days"}, {in.BandwidthDays, "bandwidth_days"}, {in.IncidentsDays, "incidents_days"}} {
		if x.v == nil {
			continue
		}
		for _, d := range obsxRetention {
			if d.field == x.field {
				if *x.v < d.min || *x.v > d.mx {
					return nil, &apiError{Status: 400, Code: "obsx_bad_retention", Field: x.field, Max: int64(d.mx)}
				}
				sets[d.key] = strconv.Itoa(*x.v)
			}
		}
	}
	keys := make([]string, 0, len(sets))
	for k, v := range sets {
		if err := s.Store.Set(k, v); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s.audit(r, "obsx.settings", "", strings.Join(keys, ","), true)
	return s.obsxGetSettings(w, r)
}

// obsxPrune is called from housekeeping (prune): bandwidth rows and resolved
// incidents past their retention. audit_log and events use their own
// retention settings in prune / pruneSec.
func (s *Server) obsxPrune(ctx context.Context) {
	now := s.Now()
	bwDay := now.AddDate(0, 0, -s.obsxRetDays("obsx_ret_bandwidth_days")).UTC().Format("2006-01-02")
	incCut := now.Add(-time.Duration(s.obsxRetDays("obsx_ret_incidents_days")) * 24 * time.Hour).Unix()
	for _, q := range []struct {
		sql string
		arg any
	}{
		{`DELETE FROM bw_daily WHERE day<?`, bwDay},
		{`DELETE FROM obsx_incident_history WHERE incident_id IN (SELECT id FROM obsx_incidents WHERE status='resolved' AND resolved_at>0 AND resolved_at<?)`, incCut},
		{`DELETE FROM obsx_incidents WHERE status='resolved' AND resolved_at>0 AND resolved_at<?`, incCut},
	} {
		if _, err := s.Store.DB.ExecContext(ctx, q.sql, q.arg); err != nil && s.Log != nil {
			s.Log.Warn("housekeeping", "sql", q.sql, "err", err)
		}
	}
}

var _ = store.Select[int]
