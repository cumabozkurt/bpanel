// SPDX-License-Identifier: Apache-2.0

package api

// v0.4 network security API (admin realm, perm-guarded via perm.go):
// firewall rules (DB) → versioned apply with confirm token + automatic
// rollback in the agent, history + rollback to a version, temporary blocks
// with expiry, and per-domain WAF includes (netsec.waf.apply).

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/events"
	"github.com/cumabozkurt/bpanel/internal/netsec"
	"github.com/cumabozkurt/bpanel/internal/rbac"
	"github.com/cumabozkurt/bpanel/internal/store"
)

// FwApplyReq optionally sets the confirm window (10..600 s, default 60).
type FwApplyReq struct {
	ConfirmSeconds int `json:"confirm_seconds,omitempty"`
}

// FwConfirmReq confirms a pending version with the token apply returned.
type FwConfirmReq struct {
	Version int64  `json:"version"`
	Token   string `json:"token"`
}

// FwBlockReq adds a temporary block.
type FwBlockReq struct {
	IP             string `json:"ip"`
	Reason         string `json:"reason,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// WAFReq sets a domain's WAF mode and exclusions (numeric rule IDs as strings).
type WAFReq struct {
	Mode       string   `json:"mode"`
	Exclusions []string `json:"exclusions"`
}

// netsecSSHPort is the SSH port protected by the lockout guard.
var netsecSSHPort = 22

func (s *Server) mountNetsec(r chi.Router) {
	const tg = "netsec"
	s.opPerm(r, rbac.FirewallRead, "GET", "/admin/firewall/rules", tg, "List firewall rules (draft, applied with /apply)", nil, s.h(s.fwListRules))
	s.opPerm(r, rbac.FirewallWrite, "POST", "/admin/firewall/rules", tg, "Add a firewall rule (lockout-guarded)", netsec.Rule{}, s.h(s.fwCreateRule))
	s.opPerm(r, rbac.FirewallWrite, "PUT", "/admin/firewall/rules/{id}", tg, "Edit a firewall rule", netsec.Rule{}, s.h(s.fwUpdateRule))
	s.opPerm(r, rbac.FirewallWrite, "DELETE", "/admin/firewall/rules/{id}", tg, "Delete a firewall rule", nil, s.h(s.fwDeleteRule))
	s.opPermReauth(r, rbac.FirewallWrite, "POST", "/admin/firewall/apply", tg, "Apply the rules (confirm within the window or the agent rolls back)", FwApplyReq{}, s.h(s.fwApply))
	s.opPerm(r, rbac.FirewallWrite, "POST", "/admin/firewall/confirm", tg, "Confirm a pending firewall version", FwConfirmReq{}, s.h(s.fwConfirm))
	s.opPerm(r, rbac.FirewallRead, "GET", "/admin/firewall/status", tg, "Firewall support, pending change and current version", nil, s.h(s.fwStatus))
	s.opPerm(r, rbac.FirewallRead, "GET", "/admin/firewall/history", tg, "Applied firewall versions", nil, s.h(s.fwHistory))
	s.opPermReauth(r, rbac.FirewallWrite, "POST", "/admin/firewall/rollback/{version}", tg, "Re-apply an earlier version (with confirm window)", FwApplyReq{}, s.h(s.fwRollback))
	s.opPerm(r, rbac.FirewallRead, "GET", "/admin/firewall/blocks", tg, "Temporary IP blocks", nil, s.h(s.fwListBlocks))
	s.opPerm(r, rbac.FirewallWrite, "POST", "/admin/firewall/blocks", tg, "Block an IP temporarily", FwBlockReq{}, s.h(s.fwAddBlock))
	s.opPerm(r, rbac.FirewallWrite, "DELETE", "/admin/firewall/blocks/{id}", tg, "Remove a temporary block", nil, s.h(s.fwDelBlock))
	s.opPerm(r, rbac.WAFRead, "GET", "/admin/waf", tg, "WAF provider status and per-domain modes", nil, s.h(s.wafList))
	s.opPerm(r, rbac.WAFWrite, "PUT", "/admin/waf/{domain}", tg, "Set a domain's WAF mode/exclusions and apply", WAFReq{}, s.h(s.wafPut))
}

// ---- helpers -------------------------------------------------------------------

func nsErr(err error) error {
	var ne *netsec.Error
	if errors.As(err, &ne) {
		switch ne.Code {
		case netsec.CodeLockout:
			return badMsg("fw_lockout", ne.Msg)
		case "waf_invalid":
			return badMsg("waf_invalid", ne.Msg)
		}
		return badMsg("fw_invalid", ne.Msg)
	}
	return err
}

func nsAgentCode(err error) string {
	var re *rpc.Error
	if errors.As(err, &re) {
		return re.Code
	}
	return "agent_error"
}

func (s *Server) panelPorts() []int {
	out := []int{}
	for _, p := range []int{s.Cfg.AdminPort, s.Cfg.UserPort, s.Cfg.AdminHTTPPort, s.Cfg.UserHTTPPort} {
		if p > 0 {
			out = append(out, p)
		}
	}
	return out
}

func joinPorts(ps []int) string {
	ss := make([]string, len(ps))
	for i, p := range ps {
		ss[i] = strconv.Itoa(p)
	}
	return strings.Join(ss, ",")
}

func splitPorts(s string) []int {
	var out []int
	for _, f := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(f)); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func (s *Server) loadRules(ctx context.Context) ([]netsec.Rule, error) {
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT id, action, family, cidr, proto, ports, rate_per_min, comment, source, expires_at
		FROM fw_rules WHERE expires_at=0 OR expires_at>? ORDER BY id`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []netsec.Rule{}
	for rows.Next() {
		var r netsec.Rule
		var ports string
		var exp int64
		if err := rows.Scan(&r.ID, &r.Action, &r.Family, &r.CIDR, &r.Proto, &ports, &r.RatePerMin, &r.Comment, &r.Source, &exp); err != nil {
			return nil, err
		}
		r.Ports = splitPorts(ports)
		if exp > 0 {
			r.ExpiresAt = time.Unix(exp, 0).UTC()
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ruleset builds the ruleset to apply/check for the calling admin.
func (s *Server) ruleset(r *http.Request, rules []netsec.Rule) netsec.Ruleset {
	return netsec.Ruleset{Rules: rules, SSHPort: netsecSSHPort, PanelPorts: s.panelPorts(), AdminIP: s.clientIP(r)}
}

// checkRules validates rules (incl. the lockout guard for the caller's IP).
func (s *Server) checkRules(r *http.Request, rules []netsec.Rule) error {
	rs := s.ruleset(r, rules)
	if err := rs.Validate(); err != nil {
		return nsErr(err)
	}
	return nil
}

// ---- rules -----------------------------------------------------------------------

func (s *Server) fwListRules(w http.ResponseWriter, r *http.Request) (any, error) {
	rules, err := s.loadRules(r.Context())
	if err != nil {
		return nil, err
	}
	return map[string]any{"rules": rules, "client_ip": s.clientIP(r)}, nil
}

func (s *Server) saveRule(r *http.Request, id int64) (any, error) {
	var in netsec.Rule
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	in.ID, in.Source = 0, netsec.SourceManual
	if err := in.Normalize(); err != nil {
		return nil, nsErr(err)
	}
	rules, err := s.loadRules(r.Context())
	if err != nil {
		return nil, err
	}
	found := id == 0
	for i := range rules {
		if rules[i].ID == id {
			rules[i], found = in, true
		}
	}
	if !found {
		return nil, notFound()
	}
	if id == 0 {
		rules = append(rules, in)
	}
	if err := s.checkRules(r, rules); err != nil {
		s.audit(r, "firewall.rule", in.CIDR, err.Error(), false)
		return nil, err
	}
	var exp int64
	if !in.ExpiresAt.IsZero() {
		exp = in.ExpiresAt.Unix()
	}
	vals := []any{in.Action, in.Family, in.CIDR, in.Proto, joinPorts(in.Ports), in.RatePerMin, in.Comment, exp}
	if id == 0 {
		res, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO fw_rules(action,family,cidr,proto,ports,rate_per_min,comment,expires_at,source,created_by,created_at)
			VALUES(?,?,?,?,?,?,?,?,'manual',?,?)`, append(vals, userOf(r).ID, time.Now().Unix())...)
		if err != nil {
			return nil, err
		}
		id, _ = res.LastInsertId()
	} else if _, err := s.Store.DB.ExecContext(r.Context(), `UPDATE fw_rules SET action=?,family=?,cidr=?,proto=?,ports=?,rate_per_min=?,comment=?,expires_at=? WHERE id=?`,
		append(vals, id)...); err != nil {
		return nil, err
	}
	in.ID = id
	s.audit(r, "firewall.rule", strconv.FormatInt(id, 10), in.Action+" "+in.CIDR, true)
	return in, nil
}

func (s *Server) fwCreateRule(w http.ResponseWriter, r *http.Request) (any, error) {
	return s.saveRule(r, 0)
}

func (s *Server) fwUpdateRule(w http.ResponseWriter, r *http.Request) (any, error) {
	id := idParam(r, "id")
	if id == 0 {
		return nil, notFound()
	}
	return s.saveRule(r, id)
}

func (s *Server) fwDeleteRule(w http.ResponseWriter, r *http.Request) (any, error) {
	res, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM fw_rules WHERE id=?`, idParam(r, "id"))
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, notFound()
	}
	s.audit(r, "firewall.rule.delete", chi.URLParam(r, "id"), "", true)
	return nil, nil
}

// ---- apply / confirm / status ------------------------------------------------------

func tokenHash(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// applyRuleset sends rs to the agent and records a new version.
func (s *Server) applyRuleset(r *http.Request, rs netsec.Ruleset, confirmSec int, rollbackOf int64) (any, error) {
	if err := rs.Validate(); err != nil {
		s.audit(r, "firewall.apply", "", err.Error(), false)
		return nil, nsErr(err)
	}
	if confirmSec == 0 {
		confirmSec = 60
	}
	if confirmSec < 10 || confirmSec > 600 {
		return nil, badMsg("bad_params", "confirm_seconds must be 10..600")
	}
	s.fwReconcile(r.Context())
	var npend int
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM fw_changes WHERE status='pending'`).Scan(&npend)
	if npend > 0 {
		return nil, conflict("fw_pending")
	}
	var out rpc.NetsecFwApplyResult
	if err := s.Agent.Call(r.Context(), rpc.MNetsecFwApply, rpc.NetsecFwApplyParams{Ruleset: rs, ConfirmSeconds: confirmSec}, &out); err != nil {
		s.audit(r, "firewall.apply", "", nsAgentCode(err), false)
		return nil, err
	}
	js, _ := json.Marshal(rs)
	status := out.Status
	if status != "pending" {
		status = "unsupported"
	}
	var dl int64
	if !out.Deadline.IsZero() {
		dl = out.Deadline.Unix()
	}
	th := ""
	if out.Token != "" {
		th = tokenHash(out.Token)
	}
	res, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO fw_changes(ruleset_text,ruleset_json,applied_by,status,created_at,token_hash,deadline,reason,rollback_of)
		VALUES(?,?,?,?,?,?,?,?,?)`, out.Script, string(js), userOf(r).ID, status, time.Now().Unix(), th, dl, out.Reason, rollbackOf)
	if err != nil {
		return nil, err
	}
	ver, _ := res.LastInsertId()
	s.audit(r, "firewall.apply", "v"+strconv.FormatInt(ver, 10), status, status == "pending")
	resp := map[string]any{"version": ver, "status": status, "reason": out.Reason, "syntax_ok": out.SyntaxOK}
	if status == "pending" {
		resp["token"] = out.Token
		resp["deadline"] = out.Deadline
		resp["confirm_seconds"] = confirmSec
	}
	return resp, nil
}

func (s *Server) fwApply(w http.ResponseWriter, r *http.Request) (any, error) {
	var in FwApplyReq
	if r.ContentLength != 0 {
		if err := decode(r, &in); err != nil {
			return nil, err
		}
	}
	rules, err := s.loadRules(r.Context())
	if err != nil {
		return nil, err
	}
	return s.applyRuleset(r, s.ruleset(r, rules), in.ConfirmSeconds, 0)
}

func (s *Server) fwRollback(w http.ResponseWriter, r *http.Request) (any, error) {
	var in FwApplyReq
	if r.ContentLength != 0 {
		if err := decode(r, &in); err != nil {
			return nil, err
		}
	}
	ver, _ := strconv.ParseInt(chi.URLParam(r, "version"), 10, 64)
	var js string
	if err := s.Store.DB.QueryRowContext(r.Context(), `SELECT ruleset_json FROM fw_changes WHERE version=?`, ver).Scan(&js); err != nil {
		return nil, notFound()
	}
	var rs netsec.Ruleset
	if err := json.Unmarshal([]byte(js), &rs); err != nil {
		return nil, badMsg("fw_invalid", "stored version is unreadable")
	}
	// the guard always protects whoever is applying now
	rs.AdminIP, rs.SSHPort, rs.PanelPorts = s.clientIP(r), netsecSSHPort, s.panelPorts()
	return s.applyRuleset(r, rs, in.ConfirmSeconds, ver)
}

func (s *Server) fwConfirm(w http.ResponseWriter, r *http.Request) (any, error) {
	var in FwConfirmReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	var th string
	var dl int64
	err := s.Store.DB.QueryRowContext(r.Context(), `SELECT token_hash, deadline FROM fw_changes WHERE version=? AND status='pending'`, in.Version).Scan(&th, &dl)
	if err != nil {
		return nil, conflict("fw_no_pending")
	}
	if in.Token == "" || subtle.ConstantTimeCompare([]byte(th), []byte(tokenHash(in.Token))) != 1 {
		s.audit(r, "firewall.confirm", "v"+strconv.FormatInt(in.Version, 10), "bad token", false)
		return nil, badMsg("fw_no_pending", "token does not match the pending version")
	}
	var out rpc.NetsecFwConfirmResult
	if err := s.Agent.Call(r.Context(), rpc.MNetsecFwConfirm, rpc.NetsecFwConfirmParams{Token: in.Token}, &out); err != nil {
		code := nsAgentCode(err)
		if code == "fw_no_pending" {
			// the agent already rolled back (deadline passed / restart)
			_, _ = s.Store.DB.ExecContext(r.Context(), `UPDATE fw_changes SET status='rolled_back', reason='timeout' WHERE version=? AND status='pending'`, in.Version)
		}
		s.audit(r, "firewall.confirm", "v"+strconv.FormatInt(in.Version, 10), code, false)
		return nil, err
	}
	_, _ = s.Store.DB.ExecContext(r.Context(), `UPDATE fw_changes SET status='confirmed', token_hash='' WHERE version=?`, in.Version)
	s.audit(r, "firewall.confirm", "v"+strconv.FormatInt(in.Version, 10), "", true)
	return map[string]any{"version": in.Version, "status": "confirmed"}, nil
}

// fwReconcile marks pending versions the agent no longer holds as rolled back.
func (s *Server) fwReconcile(ctx context.Context) *rpc.NetsecFwStatusResult {
	var st rpc.NetsecFwStatusResult
	if err := s.Agent.Call(ctx, rpc.MNetsecFwStatus, rpc.NetsecFwStatusParams{}, &st); err != nil {
		return nil
	}
	if !st.Pending {
		reason := st.LastRollback
		if reason == "" {
			reason = "timeout"
		}
		res, _ := s.Store.DB.ExecContext(ctx, `UPDATE fw_changes SET status='rolled_back', reason=?, token_hash='' WHERE status='pending'`, reason)
		if res != nil {
			if n, _ := res.RowsAffected(); n > 0 {
				events.Publish(ctx, events.Event{Type: "netsec.fw_rolled_back", Severity: events.Warning, Data: map[string]any{"reason": reason}})
			}
		}
	}
	return &st
}

func (s *Server) fwStatus(w http.ResponseWriter, r *http.Request) (any, error) {
	st := s.fwReconcile(r.Context())
	resp := map[string]any{"client_ip": s.clientIP(r), "ssh_port": netsecSSHPort, "panel_ports": s.panelPorts()}
	if st == nil {
		resp["supported"], resp["reason"] = false, "agent_unreachable"
	} else {
		resp["supported"], resp["reason"], resp["pending"], resp["last_rollback"] = st.Supported, st.Reason, st.Pending, st.LastRollback
		if st.Pending {
			resp["deadline"] = st.Deadline
		}
	}
	var cur, pend sql.NullInt64
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT MAX(version) FROM fw_changes WHERE status='confirmed'`).Scan(&cur)
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT MAX(version) FROM fw_changes WHERE status='pending'`).Scan(&pend)
	resp["current_version"], resp["pending_version"] = cur.Int64, pend.Int64
	var last string
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT status FROM fw_changes ORDER BY version DESC LIMIT 1`).Scan(&last)
	resp["last_status"] = last
	return resp, nil
}

func (s *Server) fwHistory(w http.ResponseWriter, r *http.Request) (any, error) {
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT c.version, c.status, c.reason, c.created_at, c.rollback_of, COALESCE(u.username,''), c.ruleset_json
		FROM fw_changes c LEFT JOIN users u ON u.id=c.applied_by ORDER BY c.version DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var ver, at, rb int64
		var st, reason, by, js string
		if err := rows.Scan(&ver, &st, &reason, &at, &rb, &by, &js); err != nil {
			return nil, err
		}
		var rs netsec.Ruleset
		_ = json.Unmarshal([]byte(js), &rs)
		out = append(out, map[string]any{"version": ver, "status": st, "reason": reason, "created_at": at, "rollback_of": rb, "applied_by": by, "rules": len(rs.Rules)})
	}
	return map[string]any{"history": out}, rows.Err()
}

// ---- temporary blocks ----------------------------------------------------------------

func (s *Server) fwListBlocks(w http.ResponseWriter, r *http.Request) (any, error) {
	s.netsecExpire(r.Context())
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT id, ip, reason, source, expires_at, created_at FROM fw_blocks ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, exp, at int64
		var ip, reason, src string
		if err := rows.Scan(&id, &ip, &reason, &src, &exp, &at); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "ip": ip, "reason": reason, "source": src, "expires_at": exp, "created_at": at})
	}
	return map[string]any{"blocks": out}, rows.Err()
}

func (s *Server) fwAddBlock(w http.ResponseWriter, r *http.Request) (any, error) {
	var in FwBlockReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	ttl := time.Duration(in.TimeoutSeconds) * time.Second
	if in.TimeoutSeconds <= 0 {
		return nil, badMsg("fw_invalid", "timeout_seconds is required")
	}
	if len(in.Reason) > 200 {
		return nil, badMsg("fw_invalid", "reason too long")
	}
	admin := s.clientIP(r)
	if _, _, err := netsec.BlockElement(in.IP, ttl, admin); err != nil {
		return nil, nsErr(err)
	}
	p, err := netsec.ParseCIDR(in.IP)
	if err != nil {
		return nil, badMsg("fw_invalid", "invalid address")
	}
	ip := p.String()
	if p.IsSingleIP() {
		ip = p.Addr().String()
	}
	var out rpc.NetsecFwBlockResult
	if err := s.Agent.Call(r.Context(), rpc.MNetsecFwBlock, rpc.NetsecFwBlockParams{IP: ip, TimeoutSeconds: in.TimeoutSeconds, AdminIP: admin}, &out); err != nil {
		s.audit(r, "firewall.block", ip, nsAgentCode(err), false)
		return nil, err
	}
	now := time.Now()
	exp := now.Add(ttl).Unix()
	res, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO fw_blocks(ip,reason,source,expires_at,created_at) VALUES(?,?,'manual',?,?)
		ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, expires_at=excluded.expires_at`, ip, in.Reason, exp, now.Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	s.audit(r, "firewall.block", ip, out.Status, true)
	events.Publish(r.Context(), events.Event{Type: "netsec.block", Severity: events.Info, Data: map[string]any{"action": "add", "ip": ip, "expires_at": exp, "kernel": out.Status}})
	return map[string]any{"id": id, "ip": ip, "expires_at": exp, "status": out.Status, "reason": out.Reason}, nil
}

func (s *Server) fwDelBlock(w http.ResponseWriter, r *http.Request) (any, error) {
	var ip string
	if err := s.Store.DB.QueryRowContext(r.Context(), `SELECT ip FROM fw_blocks WHERE id=?`, idParam(r, "id")).Scan(&ip); err != nil {
		return nil, notFound()
	}
	var out rpc.NetsecFwBlockResult
	if err := s.Agent.Call(r.Context(), rpc.MNetsecFwUnblock, rpc.NetsecFwUnblockParams{IP: ip}, &out); err != nil {
		s.audit(r, "firewall.unblock", ip, nsAgentCode(err), false)
		return nil, err
	}
	_, _ = s.Store.DB.ExecContext(r.Context(), `DELETE FROM fw_blocks WHERE id=?`, idParam(r, "id"))
	s.audit(r, "firewall.unblock", ip, out.Status, true)
	events.Publish(r.Context(), events.Event{Type: "netsec.block", Severity: events.Info, Data: map[string]any{"action": "remove", "ip": ip}})
	return map[string]any{"status": out.Status}, nil
}

// netsecExpire deletes expired blocks (the kernel drops them by element
// timeout) and expired temporary rules from the DB.
func (s *Server) netsecExpire(ctx context.Context) int {
	now := time.Now().Unix()
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT ip FROM fw_blocks WHERE expires_at>0 AND expires_at<=?`, now)
	if err != nil {
		return 0
	}
	var ips []string
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) == nil {
			ips = append(ips, ip)
		}
	}
	rows.Close()
	for _, ip := range ips {
		if _, err := s.Store.DB.ExecContext(ctx, `DELETE FROM fw_blocks WHERE ip=? AND expires_at>0 AND expires_at<=?`, ip, now); err == nil {
			events.Publish(ctx, events.Event{Type: "netsec.block", Severity: events.Info, Data: map[string]any{"action": "expired", "ip": ip}})
		}
	}
	_, _ = s.Store.DB.ExecContext(ctx, `DELETE FROM fw_rules WHERE expires_at>0 AND expires_at<=?`, now)
	return len(ips)
}

// netsecLoop expires blocks every minute (started from Run).
func (s *Server) netsecLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.netsecExpire(ctx)
			s.fwReconcile(ctx)
		}
	}
}

// ---- WAF -----------------------------------------------------------------------------

func (s *Server) wafList(w http.ResponseWriter, r *http.Request) (any, error) {
	var st rpc.NetsecWafStatusResult
	if err := s.Agent.Call(r.Context(), rpc.MNetsecWafStatus, rpc.NetsecWafStatusParams{}, &st); err != nil {
		st = rpc.NetsecWafStatusResult{Status: "unsupported", Reason: nsAgentCode(err)}
	}
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT d.name, COALESCE(w.mode,'audit'), COALESCE(w.exclusions,'[]'), COALESCE(w.version,0), COALESCE(w.status,''), COALESCE(w.reason,'')
		FROM domains d LEFT JOIN waf_domains w ON w.domain=d.name ORDER BY d.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var d, mode, ex, status, reason string
		var ver int64
		if err := rows.Scan(&d, &mode, &ex, &ver, &status, &reason); err != nil {
			return nil, err
		}
		var ids []int
		_ = json.Unmarshal([]byte(ex), &ids)
		if ids == nil {
			ids = []int{}
		}
		out = append(out, map[string]any{"domain": d, "mode": mode, "exclusions": ids, "version": ver, "status": status, "reason": reason})
	}
	return map[string]any{"provider": st, "domains": out}, rows.Err()
}

func (s *Server) wafPut(w http.ResponseWriter, r *http.Request) (any, error) {
	var in WAFReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	domain := strings.ToLower(chi.URLParam(r, "domain"))
	if !netsec.ValidWAFDomain(domain) {
		return nil, badMsg("waf_invalid", "invalid domain")
	}
	var n int
	if err := s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM domains WHERE name=?`, domain).Scan(&n); err != nil || n == 0 {
		return nil, notFound()
	}
	if in.Mode == "" {
		in.Mode = netsec.WAFAudit
	}
	if !netsec.ValidWAFMode(in.Mode) {
		return nil, badMsg("waf_invalid", "mode must be audit, block or off")
	}
	ex, err := netsec.ParseWAFExclusions(in.Exclusions)
	if err != nil {
		return nil, nsErr(err)
	}
	var ver int64
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT version FROM waf_domains WHERE domain=?`, domain).Scan(&ver)
	ver++
	cfg := netsec.WAFConfig{Domain: domain, Mode: in.Mode, Exclusions: ex}
	var out rpc.NetsecWafApplyResult
	status, reason := "", ""
	if err := s.Agent.Call(r.Context(), rpc.MNetsecWafApply, rpc.NetsecWafApplyParams{Config: cfg, Version: ver, Vhost: s.wafVhost(r.Context(), domain)}, &out); err != nil {
		code := nsAgentCode(err)
		s.audit(r, "waf.apply", domain, code, false)
		_, _ = s.Store.DB.ExecContext(r.Context(), `INSERT INTO waf_changes(domain,version,mode,exclusions,status,applied_by,created_at) VALUES(?,?,?,?,?,?,?)`,
			domain, ver, in.Mode, mustJSON(ex), "failed:"+code, userOf(r).ID, time.Now().Unix())
		return nil, err
	}
	status, reason = out.Status, out.Reason
	exj := mustJSON(ex)
	if _, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO waf_domains(domain,mode,exclusions,version,status,reason,updated_at) VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(domain) DO UPDATE SET mode=excluded.mode, exclusions=excluded.exclusions, version=excluded.version, status=excluded.status, reason=excluded.reason, updated_at=excluded.updated_at`,
		domain, in.Mode, exj, ver, status, reason, time.Now().Unix()); err != nil {
		return nil, err
	}
	_, _ = s.Store.DB.ExecContext(r.Context(), `INSERT INTO waf_changes(domain,version,mode,exclusions,status,applied_by,created_at) VALUES(?,?,?,?,?,?,?)`,
		domain, ver, in.Mode, exj, status, userOf(r).ID, time.Now().Unix())
	s.audit(r, "waf.apply", domain, in.Mode+" "+status, status == "applied")
	return map[string]any{"domain": domain, "mode": in.Mode, "exclusions": ex, "version": ver, "status": status, "reason": reason, "server": out.Server, "wired": out.Wired}, nil
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// wafVhost builds the domain's vhost exactly like applyWebRec does, so the
// agent can re-apply it with the WAF include (v0.4 netsec C). nil when the
// domain is an alias (served by its parent) or cannot be resolved; the agent
// then only reports whether the existing vhost is wired.
func (s *Server) wafVhost(ctx context.Context, domain string) *rpc.Vhost {
	var uid int64
	if err := s.Store.DB.QueryRowContext(ctx, `SELECT user_id FROM domains WHERE name=?`, domain).Scan(&uid); err != nil {
		return nil
	}
	u, err := s.userByID(ctx, uid)
	if err != nil {
		return nil
	}
	doms, err := s.domainsOf(ctx, uid)
	if err != nil {
		return nil
	}
	var d *store.Domain
	for i := range doms {
		if doms[i].Name == domain && doms[i].Kind != "alias" {
			d = &doms[i]
		}
	}
	if d == nil {
		return nil
	}
	var al []string
	if d.Kind != "sub" {
		al = append(al, "www."+d.Name)
	}
	for _, x := range doms {
		if x.Kind == "alias" && x.ParentID != nil && *x.ParentID == d.ID {
			al = append(al, x.Name, "www."+x.Name)
		}
	}
	return &rpc.Vhost{User: u.Username, Domain: d.Name, Aliases: al, DocRoot: d.DocRoot, PHPVersion: s.phpFor(&u, *d),
		Mode: u.WebMode, SSL: d.SSLStatus == "active", Suspended: u.Status == "suspended", Redirect: d.Redirect}
}
