// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/mailx"
	"github.com/cumabozkurt/bpanel/internal/store"
)

// v0.4 mailx: user mail tools (autoresponders, email filters, spam filters,
// track delivery). Every endpoint works only on the caller's own mailboxes
// and mail domains; the agent re-checks ownership (mustOwn) on its side.

var mailxMu sync.Mutex // serialises Sieve/spam syncs (DB state -> agent)

type AutoresponderReq struct {
	Subject      string `json:"subject"`
	Body         string `json:"body"`
	Start        string `json:"start"`
	End          string `json:"end"`
	IntervalDays int    `json:"interval_days"`
	From         string `json:"from"`
	Enabled      *bool  `json:"enabled"`
}

type FilterReq struct {
	MailboxID int64  `json:"mailbox_id"`
	Name      string `json:"name"`
	Field     string `json:"field"`
	Header    string `json:"header"`
	Op        string `json:"op"`
	Value     string `json:"value"`
	Action    string `json:"action"`
	Target    string `json:"target"`
}

type SpamReq struct {
	Enabled       bool     `json:"enabled"`
	RequiredScore float64  `json:"required_score"`
	Allow         []string `json:"allow"`
	Deny          []string `json:"deny"`
}

func (s *Server) mountMailx(r chi.Router) {
	s.op(r, "GET", "/user/email/autoresponders", "email", "List autoresponders (Sieve vacation) of the own mailboxes", nil, s.h(s.listAutoresponders))
	s.op(r, "PUT", "/user/email/autoresponders/{id}", "email", "Set the autoresponder of one own mailbox (id = mailbox id)", AutoresponderReq{}, s.h(s.putAutoresponder))
	s.op(r, "DELETE", "/user/email/autoresponders/{id}", "email", "Remove the autoresponder of one own mailbox", nil, s.h(s.deleteAutoresponder))
	s.op(r, "GET", "/user/email/filters", "email", "List email filters of the own mailboxes", nil, s.h(s.listMailFilters))
	s.op(r, "POST", "/user/email/filters", "email", "Add an email filter (compiled to Sieve)", FilterReq{}, s.h(s.createMailFilter))
	s.op(r, "DELETE", "/user/email/filters/{id}", "email", "Delete an email filter", nil, s.h(s.deleteMailFilter))
	s.op(r, "GET", "/user/email/spam", "email", "Spam filter settings of the own account (Rspamd)", nil, s.h(s.getSpam))
	s.op(r, "PUT", "/user/email/spam", "email", "Change the spam filter settings of the own account", SpamReq{}, s.h(s.putSpam))
	s.op(r, "GET", "/user/email/track", "email", "Track delivery: Postfix log entries of the own mail domains (?q=&limit=)", nil, s.h(s.trackDelivery))
}

func mailxBad(err error) error {
	var me *mailx.Error
	if errors.As(err, &me) {
		return badField(me.Code, me.Field)
	}
	return err
}

type mxBox struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
}

func (s *Server) ownBoxes(ctx context.Context, uid int64) ([]mxBox, error) {
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT id, email FROM mailboxes WHERE user_id=? ORDER BY email`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []mxBox{}
	for rows.Next() {
		var b mxBox
		if err := rows.Scan(&b.ID, &b.Email); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Server) ownBox(r *http.Request, id int64) (store.Mailbox, error) {
	m, err := store.One[store.Mailbox](r.Context(), s.Store.DB, `SELECT * FROM mailboxes WHERE id=? AND user_id=?`, id, userOf(r).ID)
	if err != nil {
		return m, notFound()
	}
	return m, nil
}

func (s *Server) boxVacation(ctx context.Context, boxID int64) (*mailx.Vacation, bool, error) {
	var v mailx.Vacation
	var en int
	err := s.Store.DB.QueryRowContext(ctx, `SELECT subject, body, start_date, end_date, interval_days, from_addr, enabled FROM mail_autoresponders WHERE mailbox_id=?`, boxID).
		Scan(&v.Subject, &v.Body, &v.Start, &v.End, &v.Days, &v.From, &en)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	return &v, en == 1, err
}

func (s *Server) boxRules(ctx context.Context, boxID int64) ([]mailx.Rule, error) {
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT name, field, header, op, value, action, target FROM mail_filters WHERE mailbox_id=? ORDER BY id`, boxID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []mailx.Rule{}
	for rows.Next() {
		var x mailx.Rule
		if err := rows.Scan(&x.Name, &x.Field, &x.Header, &x.Op, &x.Value, &x.Action, &x.Target); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// applySieve pushes the desired script state of a mailbox to the agent and
// records the result. It is called before the DB change is committed.
func (s *Server) applySieve(r *http.Request, m store.Mailbox, vac *mailx.Vacation, rules []mailx.Rule) (rpc.MailxStatus, error) {
	if _, err := mailx.Generate(m.Email, vac, rules); err != nil {
		return rpc.MailxStatus{}, mailxBad(err)
	}
	var st rpc.MailxStatus
	if err := s.agentCall(r, rpc.MMailSieveApply, rpc.MailSieveReq{User: userOf(r).Username, Email: m.Email, Vacation: vac, Rules: rules}, &st); err != nil {
		return st, err
	}
	_, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO mail_sieve_status(mailbox_id,status,reason,updated_at) VALUES(?,?,?,?)
		ON CONFLICT(mailbox_id) DO UPDATE SET status=excluded.status, reason=excluded.reason, updated_at=excluded.updated_at`, m.ID, st.Status, st.Reason, s.Now().Unix())
	return st, err
}

func (s *Server) sieveStatus(ctx context.Context, uid int64) map[int64]rpc.MailxStatus {
	out := map[int64]rpc.MailxStatus{}
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT st.mailbox_id, st.status, st.reason FROM mail_sieve_status st JOIN mailboxes m ON m.id=st.mailbox_id WHERE m.user_id=?`, uid)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var st rpc.MailxStatus
		if rows.Scan(&id, &st.Status, &st.Reason) == nil {
			out[id] = st
		}
	}
	return out
}

// ---- autoresponders --------------------------------------------------------------

type autoresponderRow struct {
	MailboxID    int64  `json:"mailbox_id"`
	Email        string `json:"email"`
	Subject      string `json:"subject"`
	Body         string `json:"body"`
	Start        string `json:"start"`
	End          string `json:"end"`
	IntervalDays int    `json:"interval_days"`
	From         string `json:"from"`
	Enabled      bool   `json:"enabled"`
	Status       string `json:"status"`
	Reason       string `json:"reason,omitempty"`
}

func (s *Server) listAutoresponders(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	st := s.sieveStatus(r.Context(), u.ID) // before the next query: the DB has one connection
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT a.mailbox_id, m.email, a.subject, a.body, a.start_date, a.end_date, a.interval_days, a.from_addr, a.enabled
		FROM mail_autoresponders a JOIN mailboxes m ON m.id=a.mailbox_id WHERE m.user_id=? ORDER BY m.email`, u.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []autoresponderRow{}
	for rows.Next() {
		var a autoresponderRow
		var en int
		if err := rows.Scan(&a.MailboxID, &a.Email, &a.Subject, &a.Body, &a.Start, &a.End, &a.IntervalDays, &a.From, &en); err != nil {
			return nil, err
		}
		a.Enabled = en == 1
		a.Status, a.Reason = st[a.MailboxID].Status, st[a.MailboxID].Reason
		list = append(list, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	boxes, err := s.ownBoxes(r.Context(), u.ID)
	return map[string]any{"autoresponders": list, "mailboxes": boxes}, err
}

func (s *Server) putAutoresponder(w http.ResponseWriter, r *http.Request) (any, error) {
	var in AutoresponderReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	m, err := s.ownBox(r, idParam(r, "id"))
	if err != nil {
		return nil, err
	}
	enabled := in.Enabled == nil || *in.Enabled
	v, err := mailx.Vacation{Subject: in.Subject, Body: in.Body, Start: in.Start, End: in.End, Days: in.IntervalDays, From: in.From}.Normalize()
	if err != nil {
		return nil, mailxBad(err)
	}
	if v.From != "" && v.From != m.Email {
		// the reply sender must be one of the account's own addresses
		if s.count(`SELECT COUNT(*) FROM mailboxes WHERE email=? AND user_id=?`, v.From, userOf(r).ID) == 0 {
			return nil, badField("autoresponder_from_not_owned", "from")
		}
	}
	mailxMu.Lock()
	defer mailxMu.Unlock()
	rules, err := s.boxRules(r.Context(), m.ID)
	if err != nil {
		return nil, err
	}
	var vac *mailx.Vacation
	if enabled {
		vac = &v
	}
	st, err := s.applySieve(r, m, vac, rules)
	if err != nil {
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO mail_autoresponders(mailbox_id,user_id,subject,body,start_date,end_date,interval_days,from_addr,enabled,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(mailbox_id) DO UPDATE SET subject=excluded.subject, body=excluded.body, start_date=excluded.start_date,
		end_date=excluded.end_date, interval_days=excluded.interval_days, from_addr=excluded.from_addr, enabled=excluded.enabled, updated_at=excluded.updated_at`,
		m.ID, userOf(r).ID, v.Subject, v.Body, v.Start, v.End, v.Days, v.From, boolInt(enabled), s.Now().Unix()); err != nil {
		return nil, err
	}
	s.audit(r, "email.autoresponder", m.Email, map[bool]string{true: "on", false: "off"}[enabled], true)
	return st, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Server) deleteAutoresponder(w http.ResponseWriter, r *http.Request) (any, error) {
	m, err := s.ownBox(r, idParam(r, "id"))
	if err != nil {
		return nil, err
	}
	mailxMu.Lock()
	defer mailxMu.Unlock()
	rules, err := s.boxRules(r.Context(), m.ID)
	if err != nil {
		return nil, err
	}
	st, err := s.applySieve(r, m, nil, rules)
	if err != nil {
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM mail_autoresponders WHERE mailbox_id=?`, m.ID); err != nil {
		return nil, err
	}
	s.audit(r, "email.autoresponder", m.Email, "delete", true)
	return st, nil
}

// ---- filters ---------------------------------------------------------------------

type filterRow struct {
	ID        int64  `json:"id"`
	MailboxID int64  `json:"mailbox_id"`
	Email     string `json:"email"`
	mailx.Rule
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

func (s *Server) listMailFilters(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	st := s.sieveStatus(r.Context(), u.ID) // before the next query: the DB has one connection
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT f.id, f.mailbox_id, m.email, f.name, f.field, f.header, f.op, f.value, f.action, f.target
		FROM mail_filters f JOIN mailboxes m ON m.id=f.mailbox_id WHERE m.user_id=? ORDER BY m.email, f.id`, u.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []filterRow{}
	for rows.Next() {
		var f filterRow
		if err := rows.Scan(&f.ID, &f.MailboxID, &f.Email, &f.Name, &f.Field, &f.Header, &f.Op, &f.Value, &f.Action, &f.Target); err != nil {
			return nil, err
		}
		f.Status, f.Reason = st[f.MailboxID].Status, st[f.MailboxID].Reason
		list = append(list, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	boxes, err := s.ownBoxes(r.Context(), u.ID)
	return map[string]any{"filters": list, "mailboxes": boxes, "max_per_mailbox": mailx.MaxRules}, err
}

func (s *Server) createMailFilter(w http.ResponseWriter, r *http.Request) (any, error) {
	var in FilterReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	m, err := s.ownBox(r, in.MailboxID)
	if err != nil {
		return nil, err
	}
	rule, err := mailx.Rule{Name: in.Name, Field: in.Field, Header: in.Header, Op: in.Op, Value: in.Value, Action: in.Action, Target: in.Target}.Normalize()
	if err != nil {
		return nil, mailxBad(err)
	}
	if rule.Action == "redirect" && rule.Target == m.Email {
		return nil, badField("forwarder_loop", "target")
	}
	mailxMu.Lock()
	defer mailxMu.Unlock()
	rules, err := s.boxRules(r.Context(), m.ID)
	if err != nil {
		return nil, err
	}
	if len(rules) >= mailx.MaxRules {
		return nil, limitReached("mail_filters")
	}
	vac, en, err := s.boxVacation(r.Context(), m.ID)
	if err != nil {
		return nil, err
	}
	if !en {
		vac = nil
	}
	st, err := s.applySieve(r, m, vac, append(rules, rule))
	if err != nil {
		return nil, err
	}
	res, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO mail_filters(user_id,mailbox_id,name,field,header,op,value,action,target,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		userOf(r).ID, m.ID, rule.Name, rule.Field, rule.Header, rule.Op, rule.Value, rule.Action, rule.Target, s.Now().Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	s.audit(r, "email.filter", m.Email, rule.Name, true)
	return map[string]any{"id": id, "status": st.Status, "reason": st.Reason}, nil
}

func (s *Server) deleteMailFilter(w http.ResponseWriter, r *http.Request) (any, error) {
	var boxID int64
	var name string
	if err := s.Store.DB.QueryRowContext(r.Context(), `SELECT mailbox_id, name FROM mail_filters WHERE id=? AND user_id=?`, idParam(r, "id"), userOf(r).ID).Scan(&boxID, &name); err != nil {
		return nil, notFound()
	}
	m, err := s.ownBox(r, boxID)
	if err != nil {
		return nil, err
	}
	mailxMu.Lock()
	defer mailxMu.Unlock()
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT id, name, field, header, op, value, action, target FROM mail_filters WHERE mailbox_id=? ORDER BY id`, m.ID)
	if err != nil {
		return nil, err
	}
	var keep []mailx.Rule
	for rows.Next() {
		var id int64
		var x mailx.Rule
		if err := rows.Scan(&id, &x.Name, &x.Field, &x.Header, &x.Op, &x.Value, &x.Action, &x.Target); err != nil {
			rows.Close()
			return nil, err
		}
		if id != idParam(r, "id") {
			keep = append(keep, x)
		}
	}
	rows.Close()
	vac, en, err := s.boxVacation(r.Context(), m.ID)
	if err != nil {
		return nil, err
	}
	if !en {
		vac = nil
	}
	st, err := s.applySieve(r, m, vac, keep)
	if err != nil {
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM mail_filters WHERE id=? AND user_id=?`, idParam(r, "id"), userOf(r).ID); err != nil {
		return nil, err
	}
	s.audit(r, "email.filter", m.Email, "delete "+name, true)
	return st, nil
}

// ---- spam ------------------------------------------------------------------------

func (s *Server) mailDomainNames(ctx context.Context, uid int64) []string {
	doms, _ := s.domainsOf(ctx, uid)
	names := []string{}
	for _, d := range doms {
		if d.Kind != "sub" {
			names = append(names, d.Name)
		}
	}
	return names
}

func mxSplitList(s string) []string {
	out := []string{}
	for _, x := range strings.Split(s, "\n") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func (s *Server) getSpam(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	p := mailx.Spam{Enabled: true, RequiredScore: 6, Allow: []string{}, Deny: []string{}}
	var en int
	var allow, deny, status, reason string
	err := s.Store.DB.QueryRowContext(r.Context(), `SELECT enabled, required_score, allow_list, deny_list, status, reason FROM mail_spam WHERE user_id=?`, u.ID).
		Scan(&en, &p.RequiredScore, &allow, &deny, &status, &reason)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if err == nil {
		p.Enabled, p.Allow, p.Deny = en == 1, mxSplitList(allow), mxSplitList(deny)
	}
	return map[string]any{"policy": p, "status": status, "reason": reason, "domains": s.mailDomainNames(r.Context(), u.ID), "configured": err == nil}, nil
}

func (s *Server) putSpam(w http.ResponseWriter, r *http.Request) (any, error) {
	var in SpamReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	p, err := mailx.Spam{Enabled: in.Enabled, RequiredScore: in.RequiredScore, Allow: in.Allow, Deny: in.Deny}.Normalize()
	if err != nil {
		return nil, mailxBad(err)
	}
	doms := s.mailDomainNames(r.Context(), u.ID)
	mailxMu.Lock()
	defer mailxMu.Unlock()
	var st rpc.MailxStatus
	if err := s.agentCall(r, rpc.MMailSpamApply, rpc.MailSpamReq{User: u.Username, Domains: doms, Policy: p}, &st); err != nil {
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO mail_spam(user_id,enabled,required_score,allow_list,deny_list,status,reason,updated_at) VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(user_id) DO UPDATE SET enabled=excluded.enabled, required_score=excluded.required_score, allow_list=excluded.allow_list,
		deny_list=excluded.deny_list, status=excluded.status, reason=excluded.reason, updated_at=excluded.updated_at`,
		u.ID, boolInt(p.Enabled), p.RequiredScore, strings.Join(p.Allow, "\n"), strings.Join(p.Deny, "\n"), st.Status, st.Reason, s.Now().Unix()); err != nil {
		return nil, err
	}
	s.audit(r, "email.spam", u.Username, strconv.FormatBool(p.Enabled), true)
	return map[string]any{"policy": p, "status": st.Status, "reason": st.Reason}, nil
}

// ---- track delivery --------------------------------------------------------------

func (s *Server) trackDelivery(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > 100 || strings.ContainsAny(q, "\x00\r\n") {
		return nil, badField("bad_params", "q")
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	doms := s.mailDomainNames(r.Context(), u.ID)
	if len(doms) == 0 {
		return rpc.MailLogResult{Status: "ok", Entries: []mailx.Delivery{}}, nil
	}
	var res rpc.MailLogResult
	if err := s.agentCall(r, rpc.MMailLogSearch, rpc.MailLogReq{User: u.Username, Domains: doms, Query: q, Limit: limit}, &res); err != nil {
		return nil, err
	}
	// defence in depth: drop anything that is not to/from an own domain
	own := map[string]bool{}
	for _, d := range doms {
		own[d] = true
	}
	kept := []mailx.Delivery{}
	for _, d := range res.Entries {
		if own[mxDomain(d.To)] || own[mxDomain(d.From)] {
			kept = append(kept, d)
		}
	}
	res.Entries = kept
	return res, nil
}

func mxDomain(a string) string {
	if i := strings.LastIndexByte(a, '@'); i >= 0 {
		return strings.ToLower(a[i+1:])
	}
	return ""
}
