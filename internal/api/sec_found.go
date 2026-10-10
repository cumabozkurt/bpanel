package api

// v0.4 security foundation, part D: secret store wiring, event persistence,
// background jobs, idempotency keys and outbound webhooks.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cumabozkurt/bpanel/internal/events"
	"github.com/cumabozkurt/bpanel/internal/jobs"
	"github.com/cumabozkurt/bpanel/internal/rbac"
	"github.com/cumabozkurt/bpanel/internal/secrets"
	"github.com/cumabozkurt/bpanel/internal/store"
	"github.com/go-chi/chi/v5"
)

type secState struct {
	once     sync.Once
	store    secrets.SecretStore
	jobsOnce sync.Once
	jobs     *jobs.Runner
	wake     chan struct{}
	resolver func(ctx context.Context, host string) ([]net.IP, error)
}

const (
	idemTTL          = 24 * time.Hour
	webhookMaxTries  = 6
	webhookTimeout   = 10 * time.Second
	eventsRetainDays = 90
)

// initSec is called once from New.
func (s *Server) initSec() {
	s.sec = &secState{wake: make(chan struct{}, 1), resolver: func(ctx context.Context, host string) ([]net.IP, error) {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		ips := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
		return ips, err
	}}
	events.SetSink(s.eventSink)
}

// Secrets returns the secret store (local AES-256-GCM provider). If the key
// file cannot be opened the store reports unavailable on every call.
func (s *Server) Secrets() secrets.SecretStore {
	s.sec.once.Do(func() {
		s.sec.store = s.newSecretStore() // v0.4 baox: local|openbao (secrets_provider.go)
	})
	return s.sec.store
}

// Jobs returns the background job runner.
func (s *Server) Jobs() *jobs.Runner {
	s.sec.jobsOnce.Do(func() { s.sec.jobs = jobs.New(s.Store.DB, s.Log, 4) })
	return s.sec.jobs
}

// startSec launches the job workers and the webhook delivery worker.
func (s *Server) startSec(ctx context.Context) {
	s.Jobs().Start(ctx)
	go s.webhookWorker(ctx)
	s.startObsx(ctx) // v0.4 obsx.go alert engine
}

// pruneSec is called from prune (housekeeping).
func (s *Server) pruneSec(ctx context.Context) {
	now := s.Now()
	days := eventsRetainDays
	if v, err := strconv.Atoi(s.Store.Get("events_retention_days", "")); err == nil && v > 0 && v <= 3650 {
		days = v
	}
	for _, q := range []struct {
		sql string
		arg any
	}{
		{`DELETE FROM events WHERE ts<?`, now.Add(-time.Duration(days) * 24 * time.Hour).Unix()},
		{`DELETE FROM idempotency_keys WHERE created_at<?`, now.Add(-idemTTL).Unix()},
		{`DELETE FROM webhook_deliveries WHERE created_at<? AND status<>'pending'`, now.Add(-30 * 24 * time.Hour).Unix()},
	} {
		if _, err := s.Store.DB.ExecContext(ctx, q.sql, q.arg); err != nil {
			s.Log.Warn("housekeeping", "sql", q.sql, "err", err)
		}
	}
	_ = s.Jobs().Prune(ctx, 30*24*time.Hour)
}

type unavailableStore struct {
	secrets.NotConfigured
	provider, reason string
}

var errSecretsUnavailable = &apiError{Status: 503, Code: "secrets_unavailable"}

func (u unavailableStore) Status() map[string]any {
	if u.provider != "" {
		return map[string]any{"provider": u.provider, "status": "unavailable", "reason": u.reason}
	}
	return map[string]any{"provider": "local", "status": "unavailable", "reason": "master key file cannot be read or created"}
}

// ---- routes ------------------------------------------------------------------

func (s *Server) mountSecCommon(r chi.Router) {
	s.op(r, "GET", "/jobs/{id}", "jobs", "Background job status (owner or admin)", nil, s.h(s.getJob))
}

func (s *Server) mountSecFound(r chi.Router) {
	s.opPerm(r, rbac.EventsRead, "GET", "/admin/events", "events", "Security/ops events (?type=&severity=&account_id=&limit=&offset=)", nil, s.h(s.listEvents))
	s.opPerm(r, rbac.WebhooksRead, "GET", "/admin/webhooks", "webhooks", "List webhooks (secrets never returned)", nil, s.h(s.listWebhooks))
	s.opPerm(r, rbac.WebhooksWrite, "POST", "/admin/webhooks", "webhooks", "Create a webhook (signing secret shown once)", WebhookReq{}, s.h(s.createWebhook))
	s.opPerm(r, rbac.WebhooksRead, "GET", "/admin/webhooks/settings", "webhooks", "Webhook settings", nil, s.h(s.webhookSettings))
	s.opPerm(r, rbac.WebhooksWrite, "PUT", "/admin/webhooks/settings", "webhooks", "Change webhook settings (allow_private: super_admin only)", WebhookSettingsReq{}, s.h(s.putWebhookSettings))
	s.opPerm(r, rbac.WebhooksWrite, "PUT", "/admin/webhooks/{id}", "webhooks", "Update a webhook", WebhookReq{}, s.h(s.updateWebhook))
	s.opPerm(r, rbac.WebhooksWrite, "DELETE", "/admin/webhooks/{id}", "webhooks", "Delete a webhook", nil, s.h(s.deleteWebhook))
	s.opPerm(r, rbac.WebhooksWrite, "POST", "/admin/webhooks/{id}/secret", "webhooks", "Rotate the signing secret (shown once)", nil, s.h(s.rotateWebhookSecret))
	s.opPerm(r, rbac.WebhooksWrite, "POST", "/admin/webhooks/{id}/test", "webhooks", "Queue a webhook.test delivery", nil, s.h(s.testWebhook))
	s.opPerm(r, rbac.WebhooksRead, "GET", "/admin/webhooks/{id}/deliveries", "webhooks", "Delivery log", nil, s.h(s.listDeliveries))
}

// ---- events ------------------------------------------------------------------

func (s *Server) eventSink(ctx context.Context, e events.Event) {
	if s.Store == nil || s.Store.DB == nil {
		return
	}
	data := "{}"
	if len(e.Data) > 0 {
		if b, err := json.Marshal(e.Data); err == nil {
			data = string(b)
		}
	}
	res, err := s.Store.DB.ExecContext(ctx, `INSERT INTO events(ts,type,severity,account_id,data) VALUES(?,?,?,?,?)`, e.At, e.Type, e.Severity, e.AccountID, data)
	if err != nil {
		return // DB closed (tests) or busy: never fail the publisher
	}
	id, _ := res.LastInsertId()
	s.queueDeliveries(ctx, id, e.Type)
}

func eventMatches(filter, typ string) bool {
	filter = strings.TrimSpace(filter)
	if filter == "" || filter == "*" {
		return true
	}
	for _, p := range strings.Split(filter, ",") {
		p = strings.TrimSpace(p)
		if p == typ || p == "*" || (strings.HasSuffix(p, ".*") && strings.HasPrefix(typ, strings.TrimSuffix(p, "*"))) {
			return true
		}
	}
	return false
}

func (s *Server) queueDeliveries(ctx context.Context, eventID int64, typ string) {
	type hook struct {
		ID     int64  `db:"id"`
		Events string `db:"events"`
	}
	hs, err := selectRows[hook](ctx, s, `SELECT id, events FROM webhooks WHERE enabled=1`)
	if err != nil {
		return
	}
	now := s.Now().Unix()
	n := 0
	for _, h := range hs {
		if eventMatches(h.Events, typ) {
			if _, err := s.Store.DB.ExecContext(ctx, `INSERT INTO webhook_deliveries(webhook_id,event_id,status,next_at,created_at) VALUES(?,?,'pending',?,?)`, h.ID, eventID, now, now); err == nil {
				n++
			}
		}
	}
	if n > 0 {
		s.wakeWebhooks()
	}
}

func (s *Server) wakeWebhooks() {
	select {
	case s.sec.wake <- struct{}{}:
	default:
	}
}

type eventRow struct {
	ID        int64           `json:"id"`
	At        int64           `json:"at"`
	Type      string          `json:"type"`
	Severity  string          `json:"severity"`
	AccountID int64           `json:"account_id"`
	Data      json.RawMessage `json:"data"`
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) (any, error) {
	q := r.URL.Query()
	where, args := []string{"1=1"}, []any{}
	if t := q.Get("type"); t != "" {
		if strings.HasSuffix(t, ".*") {
			where, args = append(where, "type LIKE ?"), append(args, strings.TrimSuffix(t, "*")+"%")
		} else {
			where, args = append(where, "type=?"), append(args, t)
		}
	}
	if sv := q.Get("severity"); sv != "" {
		if sv != events.Info && sv != events.Warning && sv != events.Critical {
			return nil, bad("invalid_severity")
		}
		where, args = append(where, "severity=?"), append(args, sv)
	}
	if a := q.Get("account_id"); a != "" {
		id, err := strconv.ParseInt(a, 10, 64)
		if err != nil {
			return nil, bad("invalid_id")
		}
		where, args = append(where, "account_id=?"), append(args, id)
	}
	if roleOf(r) == rbac.Reseller {
		u := userOf(r)
		where = append(where, "account_id<>0 AND (account_id=? OR account_id IN (SELECT id FROM users WHERE owner_id=?))")
		args = append(args, u.ID, u.ID)
	}
	limit, offset := 50, 0
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 {
		limit = min(v, 500)
	}
	if v, err := strconv.Atoi(q.Get("offset")); err == nil && v > 0 {
		offset = v
	}
	cond := strings.Join(where, " AND ")
	var total int64
	if err := s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM events WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT id,ts,type,severity,account_id,data FROM events WHERE `+cond+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []eventRow{}
	for rows.Next() {
		var e eventRow
		var d string
		if err := rows.Scan(&e.ID, &e.At, &e.Type, &e.Severity, &e.AccountID, &d); err != nil {
			return nil, err
		}
		e.Data = json.RawMessage(d)
		out = append(out, e)
	}
	return map[string]any{"events": out, "total": total, "limit": limit, "offset": offset}, rows.Err()
}

// ---- jobs ----------------------------------------------------------------------

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) (any, error) {
	j, err := s.Jobs().Get(r.Context(), chi.URLParam(r, "id"))
	if errors.Is(err, jobs.ErrNotFound) {
		return nil, notFound()
	}
	if err != nil {
		return nil, err
	}
	u := userOf(r)
	if j.OwnerID != u.ID && !(u.Role == "admin" && hasPerm(r, rbac.JobsRead)) {
		return nil, notFound() // do not reveal other users' job ids
	}
	return j, nil
}

// ---- idempotency -----------------------------------------------------------------

type capture struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (c *capture) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *capture) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = 200
	}
	if c.buf.Len() < 1<<20 {
		c.buf.Write(b)
	}
	return c.ResponseWriter.Write(b)
}

// idempotent honours the Idempotency-Key header on a POST/DELETE handler:
// the first response (status < 500) is stored for 24h per user; a retry with
// the same key and the same request replays it, the same key with a
// different request is 422 idempotency_conflict.
func (s *Server) idempotent(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Idempotency-Key")
		u := userOf(r)
		if key == "" || u == nil {
			next(w, r)
			return
		}
		if len(key) > 128 || strings.ContainsFunc(key, func(c rune) bool { return c < 0x21 || c > 0x7e }) {
			writeJSON(w, 400, apiError{Code: "invalid_idempotency_key"})
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			writeJSON(w, 400, apiError{Code: "bad_request"})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		h := sha256.New()
		fmt.Fprintf(h, "%s\n%s\n", r.Method, r.URL.Path)
		h.Write(body)
		sum := hex.EncodeToString(h.Sum(nil))
		ctx := r.Context()
		now := s.Now().Unix()
		db := s.Store.DB
		_, _ = db.ExecContext(ctx, `DELETE FROM idempotency_keys WHERE user_id=? AND key=? AND created_at<?`, u.ID, key, now-int64(idemTTL/time.Second))
		res, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO idempotency_keys(user_id,key,req_hash,status,created_at) VALUES(?,?,?,0,?)`, u.ID, key, sum, now)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			var hash string
			var status int
			var stored []byte
			if err := db.QueryRowContext(ctx, `SELECT req_hash,status,body FROM idempotency_keys WHERE user_id=? AND key=?`, u.ID, key).Scan(&hash, &status, &stored); err != nil {
				s.fail(w, r, err)
				return
			}
			switch {
			case hash != sum:
				writeJSON(w, 422, apiError{Code: "idempotency_conflict"})
			case status == 0:
				writeJSON(w, 409, apiError{Code: "idempotency_in_progress"})
			default:
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Idempotent-Replayed", "true")
				w.WriteHeader(status)
				_, _ = w.Write(stored)
			}
			return
		}
		c := &capture{ResponseWriter: w}
		defer func() {
			if c.status == 0 || c.status >= 500 {
				_, _ = db.ExecContext(context.Background(), `DELETE FROM idempotency_keys WHERE user_id=? AND key=?`, u.ID, key)
				return
			}
			_, _ = db.ExecContext(context.Background(), `UPDATE idempotency_keys SET status=?, body=? WHERE user_id=? AND key=?`, c.status, c.buf.Bytes(), u.ID, key)
		}()
		next(c, r)
	}
}

// ---- webhooks: SSRF guard -----------------------------------------------------------

var blockedNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "64:ff9b::/96", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// blockedIP reports whether ip is loopback, private, link-local, ULA,
// CGNAT, documentation, multicast or a cloud metadata address.
func blockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast()
}

func (s *Server) allowPrivateHooks() bool { return s.Store.Get("webhook_allow_private", "0") == "1" }

var errBlockedTarget = errors.New("webhook_url_blocked")

// checkWebhookURL validates the URL and that every address it resolves to
// is allowed.
func (s *Server) checkWebhookURL(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || len(raw) > 2048 {
		return unprocessable("invalid_webhook_url")
	}
	if s.allowPrivateHooks() {
		return nil
	}
	host := u.Hostname()
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		ips, err = s.sec.resolver(c, host)
		if err != nil || len(ips) == 0 {
			return unprocessable("webhook_unresolvable")
		}
	}
	for _, ip := range ips {
		if blockedIP(ip) {
			return &apiError{Status: 422, Code: "webhook_url_blocked"}
		}
	}
	return nil
}

// webhookClient re-checks the IP actually connected to (DNS rebinding):
// the dialer's Control hook runs after resolution, right before connect.
func (s *Server) webhookClient() *http.Client {
	allow := s.allowPrivateHooks()
	d := &net.Dialer{Timeout: webhookTimeout, Control: func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if !allow && blockedIP(net.ParseIP(host)) {
			return errBlockedTarget
		}
		return nil
	}}
	tr := &http.Transport{Proxy: nil, DialContext: d.DialContext, TLSHandshakeTimeout: webhookTimeout,
		ResponseHeaderTimeout: webhookTimeout, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second}
	return &http.Client{Transport: tr, Timeout: webhookTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// ---- webhooks: CRUD ---------------------------------------------------------------

type WebhookReq struct {
	Name    string   `json:"name"`
	URL     string   `json:"url"`
	Events  []string `json:"events"` // exact types or "module.*"; empty = all
	Enabled *bool    `json:"enabled,omitempty"`
	Secret  string   `json:"secret,omitempty"` // optional, >= 16 chars; generated when empty
}

type WebhookSettingsReq struct {
	AllowPrivate bool `json:"allow_private"`
}

type webhookRow struct {
	ID        int64  `db:"id" json:"id"`
	Name      string `db:"name" json:"name"`
	URL       string `db:"url" json:"url"`
	Events    string `db:"events" json:"-"`
	Enabled   bool   `db:"enabled" json:"enabled"`
	CreatedAt int64  `db:"created_at" json:"created_at"`
	SecretRef string `db:"secret" json:"-"`
}

func (w webhookRow) MarshalJSON() ([]byte, error) {
	ev := []string{}
	for _, e := range strings.Split(w.Events, ",") {
		if e = strings.TrimSpace(e); e != "" {
			ev = append(ev, e)
		}
	}
	return json.Marshal(map[string]any{"id": w.ID, "name": w.Name, "url": w.URL, "events": ev, "enabled": w.Enabled,
		"created_at": w.CreatedAt, "has_secret": w.SecretRef != ""})
}

func secretName(id int64) string { return "webhook/" + strconv.FormatInt(id, 10) }

func normEvents(in []string) (string, error) {
	out := []string{}
	for _, e := range in {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if e != "*" && !events.ValidType(strings.TrimSuffix(e, ".*")+".x") && !events.ValidType(e) {
			return "", bad("invalid_events_filter")
		}
		out = append(out, e)
	}
	return strings.Join(out, ","), nil
}

func newWebhookSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "whsec_" + hex.EncodeToString(b)
}

func (s *Server) webhookByID(ctx context.Context, id int64) (*webhookRow, error) {
	rs, err := selectRows[webhookRow](ctx, s, `SELECT id,name,url,events,enabled,created_at,secret FROM webhooks WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, notFound()
	}
	return &rs[0], nil
}

func pathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, notFound()
	}
	return id, nil
}

func (s *Server) listWebhooks(w http.ResponseWriter, r *http.Request) (any, error) {
	rs, err := selectRows[webhookRow](r.Context(), s, `SELECT id,name,url,events,enabled,created_at,secret FROM webhooks ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return map[string]any{"webhooks": rs, "allow_private": s.allowPrivateHooks(), "secret_store": s.Secrets().Status()}, nil
}

func (s *Server) createWebhook(w http.ResponseWriter, r *http.Request) (any, error) {
	var in WebhookReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		return nil, bad("invalid_name")
	}
	ev, err := normEvents(in.Events)
	if err != nil {
		return nil, err
	}
	if err := s.checkWebhookURL(r.Context(), in.URL); err != nil {
		return nil, err
	}
	secret := in.Secret
	if secret == "" {
		secret = newWebhookSecret()
	} else if len(secret) < 16 || len(secret) > 256 {
		return nil, bad("weak_webhook_secret")
	}
	if st := s.Secrets(); st.Status()["status"] != "ok" {
		return nil, errSecretsUnavailable
	}
	enabled := in.Enabled == nil || *in.Enabled
	res, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO webhooks(name,url,secret,events,enabled,created_at) VALUES(?,?,'',?,?,?)`,
		in.Name, in.URL, ev, enabled, s.Now().Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if err := s.Secrets().Put(r.Context(), secretName(id), []byte(secret)); err != nil {
		s.Store.DB.ExecContext(r.Context(), `DELETE FROM webhooks WHERE id=?`, id)
		return nil, err
	}
	s.Store.DB.ExecContext(r.Context(), `UPDATE webhooks SET secret=? WHERE id=?`, "secret:"+secretName(id), id)
	s.audit(r, "webhook.create", in.Name, "", true)
	return map[string]any{"id": id, "secret": secret}, nil
}

func (s *Server) updateWebhook(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	h, err := s.webhookByID(r.Context(), id)
	if err != nil {
		return nil, err
	}
	var in WebhookReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if n := strings.TrimSpace(in.Name); n != "" {
		if len(n) > 64 {
			return nil, bad("invalid_name")
		}
		h.Name = n
	}
	if in.URL != "" && in.URL != h.URL {
		if err := s.checkWebhookURL(r.Context(), in.URL); err != nil {
			return nil, err
		}
		h.URL = in.URL
	}
	if in.Events != nil {
		if h.Events, err = normEvents(in.Events); err != nil {
			return nil, err
		}
	}
	if in.Enabled != nil {
		h.Enabled = *in.Enabled
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `UPDATE webhooks SET name=?,url=?,events=?,enabled=? WHERE id=?`, h.Name, h.URL, h.Events, h.Enabled, id); err != nil {
		return nil, err
	}
	s.audit(r, "webhook.update", h.Name, "", true)
	return h, nil
}

func (s *Server) deleteWebhook(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	h, err := s.webhookByID(r.Context(), id)
	if err != nil {
		return nil, err
	}
	s.Store.DB.ExecContext(r.Context(), `DELETE FROM webhook_deliveries WHERE webhook_id=?`, id)
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM webhooks WHERE id=?`, id); err != nil {
		return nil, err
	}
	_ = s.Secrets().Delete(r.Context(), secretName(id))
	s.audit(r, "webhook.delete", h.Name, "", true)
	return nil, nil
}

func (s *Server) rotateWebhookSecret(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	h, err := s.webhookByID(r.Context(), id)
	if err != nil {
		return nil, err
	}
	secret := newWebhookSecret()
	if err := s.Secrets().Put(r.Context(), secretName(id), []byte(secret)); err != nil {
		if errors.Is(err, secrets.ErrNotConfigured) {
			return nil, errSecretsUnavailable
		}
		return nil, err
	}
	s.Store.DB.ExecContext(r.Context(), `UPDATE webhooks SET secret=? WHERE id=?`, "secret:"+secretName(id), id)
	s.audit(r, "webhook.secret_rotate", h.Name, "", true)
	return map[string]any{"id": id, "secret": secret}, nil
}

func (s *Server) testWebhook(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	if _, err := s.webhookByID(r.Context(), id); err != nil {
		return nil, err
	}
	now := s.Now().Unix()
	res, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO webhook_deliveries(webhook_id,event_id,status,next_at,created_at) VALUES(?,0,'pending',?,?)`, id, now, now)
	if err != nil {
		return nil, err
	}
	did, _ := res.LastInsertId()
	s.wakeWebhooks()
	return map[string]any{"delivery_id": did}, nil
}

type deliveryRow struct {
	ID         int64  `db:"id" json:"id"`
	WebhookID  int64  `db:"webhook_id" json:"webhook_id"`
	EventID    int64  `db:"event_id" json:"event_id"`
	Status     string `db:"status" json:"status"`
	Attempts   int    `db:"attempts" json:"attempts"`
	HTTPStatus int    `db:"http_status" json:"http_status"`
	Error      string `db:"error" json:"error"`
	NextAt     int64  `db:"next_at" json:"next_at"`
	CreatedAt  int64  `db:"created_at" json:"created_at"`
}

func (s *Server) listDeliveries(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	if _, err := s.webhookByID(r.Context(), id); err != nil {
		return nil, err
	}
	rs, err := selectRows[deliveryRow](r.Context(), s, `SELECT id,webhook_id,event_id,status,attempts,http_status,error,next_at,created_at FROM webhook_deliveries WHERE webhook_id=? ORDER BY id DESC LIMIT 200`, id)
	if err != nil {
		return nil, err
	}
	return map[string]any{"deliveries": rs}, nil
}

func (s *Server) webhookSettings(w http.ResponseWriter, r *http.Request) (any, error) {
	return map[string]any{"allow_private": s.allowPrivateHooks(), "secret_store": s.Secrets().Status()}, nil
}

func (s *Server) putWebhookSettings(w http.ResponseWriter, r *http.Request) (any, error) {
	var in WebhookSettingsReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if in.AllowPrivate != s.allowPrivateHooks() && roleOf(r) != rbac.SuperAdmin {
		return nil, &apiError{Status: 403, Code: "permission_denied"}
	}
	v := "0"
	if in.AllowPrivate {
		v = "1"
	}
	if err := s.Store.Set("webhook_allow_private", v); err != nil {
		return nil, err
	}
	s.audit(r, "webhook.settings", "allow_private="+v, "", true)
	return map[string]any{"allow_private": in.AllowPrivate}, nil
}

// ---- webhooks: delivery ---------------------------------------------------------------

// webhookBackoff is the delay before attempt n+1 after n failed attempts:
// 30s, 1m, 2m, 4m, 8m (capped at 1h).
func webhookBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	d := 30 * time.Second << (attempts - 1)
	if d > time.Hour || d <= 0 {
		d = time.Hour
	}
	return d
}

// signWebhook returns the X-BPanel-Signature value.
func signWebhook(secret []byte, ts string, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts))
	m.Write([]byte("."))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func (s *Server) webhookWorker(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		s.webhookTick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.sec.wake:
		}
	}
}

// webhookTick sends every due delivery once and returns how many it tried.
func (s *Server) webhookTick(ctx context.Context) int {
	due, err := selectRows[deliveryRow](ctx, s, `SELECT id,webhook_id,event_id,status,attempts,http_status,error,next_at,created_at FROM webhook_deliveries WHERE status='pending' AND next_at<=? ORDER BY id LIMIT 20`, s.Now().Unix())
	if err != nil {
		return 0
	}
	client := s.webhookClient()
	for _, d := range due {
		if ctx.Err() != nil {
			break
		}
		s.deliverOne(ctx, client, d)
	}
	return len(due)
}

func (s *Server) deliverOne(ctx context.Context, client *http.Client, d deliveryRow) {
	db := s.Store.DB
	h, err := s.webhookByID(ctx, d.WebhookID)
	if err != nil || !h.Enabled {
		db.ExecContext(ctx, `UPDATE webhook_deliveries SET status='cancelled', error='webhook_disabled' WHERE id=?`, d.ID)
		return
	}
	body := map[string]any{"id": "evt_" + strconv.FormatInt(d.EventID, 10), "type": "webhook.test", "severity": events.Info, "at": s.Now().Unix(), "data": map[string]any{}}
	if d.EventID > 0 {
		var e eventRow
		var data string
		if err := db.QueryRowContext(ctx, `SELECT id,ts,type,severity,account_id,data FROM events WHERE id=?`, d.EventID).Scan(&e.ID, &e.At, &e.Type, &e.Severity, &e.AccountID, &data); err != nil {
			db.ExecContext(ctx, `UPDATE webhook_deliveries SET status='cancelled', error='event_gone' WHERE id=?`, d.ID)
			return
		}
		body = map[string]any{"id": "evt_" + strconv.FormatInt(e.ID, 10), "type": e.Type, "severity": e.Severity, "account_id": e.AccountID, "at": e.At, "data": json.RawMessage(data)}
	}
	payload, _ := json.Marshal(body)
	secret, err := s.Secrets().Get(ctx, secretName(h.ID))
	status, code, msg := "", 0, ""
	if err != nil {
		msg = "secret_unavailable"
	} else {
		ts := strconv.FormatInt(s.Now().Unix(), 10)
		req, err := http.NewRequestWithContext(ctx, "POST", h.URL, bytes.NewReader(payload))
		if err != nil {
			msg = "invalid_webhook_url"
		} else {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "BPanel-Webhook/"+s.Version)
			req.Header.Set("X-BPanel-Event", body["type"].(string))
			req.Header.Set("X-BPanel-Id", body["id"].(string))
			req.Header.Set("X-BPanel-Timestamp", ts)
			req.Header.Set("X-BPanel-Signature", signWebhook(secret, ts, payload))
			resp, err := client.Do(req)
			if err != nil {
				msg = deliveryErr(err)
			} else {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
				resp.Body.Close()
				code = resp.StatusCode
				if code >= 200 && code < 300 {
					status = "delivered"
				} else {
					msg = "http_" + strconv.Itoa(code)
				}
			}
		}
	}
	attempts := d.Attempts + 1
	next := int64(0)
	if status == "" {
		if attempts >= webhookMaxTries {
			status = "failed"
		} else {
			status = "pending"
			next = s.Now().Add(webhookBackoff(attempts)).Unix()
		}
	}
	db.ExecContext(ctx, `UPDATE webhook_deliveries SET status=?, attempts=?, http_status=?, error=?, next_at=? WHERE id=?`, status, attempts, code, msg, next, d.ID)
}

// deliveryErr maps a transport error to a short code (never the URL's
// userinfo or the secret).
func deliveryErr(err error) string {
	switch {
	case errors.Is(err, errBlockedTarget):
		return "webhook_url_blocked"
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "Timeout"):
		return "timeout"
	case strings.Contains(err.Error(), "no such host"):
		return "webhook_unresolvable"
	case strings.Contains(err.Error(), "refused"):
		return "connection_refused"
	case strings.Contains(err.Error(), "tls") || strings.Contains(err.Error(), "x509"):
		return "tls_error"
	}
	return "network_error"
}

// selectRows runs a query on the writer pool and closes rows before return.
func selectRows[T any](ctx context.Context, s *Server, q string, args ...any) ([]T, error) {
	return store.Select[T](ctx, s.Store.DB, q, args...)
}
