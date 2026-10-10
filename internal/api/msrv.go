package api

// v0.4 msrv (spec §16): remote nodes. Admin API under /admin/servers and the
// token-authenticated enrolment endpoint POST /msrv/join used by
// `bpanel-agent join`. Panel ↔ node traffic is mTLS (internal/msrv).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cumabozkurt/bpanel/internal/jobs"
	"github.com/cumabozkurt/bpanel/internal/msrv"
	"github.com/cumabozkurt/bpanel/internal/rbac"
)

const msrvAgentPort = 8445

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// MsrvHealthInterval is the period of the background health check.
var MsrvHealthInterval = time.Minute

var msrvMgrs sync.Map // *Server -> *msrv.Manager

func (s *Server) msrv() *msrv.Manager {
	if m, ok := msrvMgrs.Load(s); ok {
		return m.(*msrv.Manager)
	}
	m := &msrv.Manager{Store: &msrv.Store{DB: s.Store.DB, Now: s.Now}, KV: s.Secrets(), Now: s.Now}
	v, _ := msrvMgrs.LoadOrStore(s, m)
	return v.(*msrv.Manager)
}

type MsrvCreateReq struct {
	Name    string   `json:"name"`
	Address string   `json:"address"` // host:port of the node's remote listener (optional until enrolled)
	Roles   []string `json:"roles"`
}

type MsrvUpdateReq struct {
	Address string `json:"address"`
}

type MsrvPushReq struct {
	Bundle  string  `json:"bundle"`
	NodeIDs []int64 `json:"node_ids"`
}

type MsrvJoinReq struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
}

func (s *Server) mountMsrvAdmin(r chi.Router) {
	s.Jobs().Register(msrv.JobPush, s.msrvRunPush)
	s.opPerm(r, rbac.ServerRead, "GET", "/admin/servers", "servers", "Remote nodes (roles, health, certificate expiry) and the panel CA fingerprint", nil, s.h(s.msrvList))
	s.opPermReauth(r, rbac.ServerWrite, "POST", "/admin/servers", "servers", "Register a node and get a one-time join token (15 min, single use)", MsrvCreateReq{}, s.h(s.msrvCreate))
	s.opPerm(r, rbac.ServerWrite, "PUT", "/admin/servers/{id}", "servers", "Change a node's agent address (host:port)", MsrvUpdateReq{}, s.h(s.msrvUpdate))
	s.opPermReauth(r, rbac.ServerWrite, "POST", "/admin/servers/{id}/rotate", "servers", "New one-time token to re-enrol a node (new key + certificate, old serial revoked)", nil, s.h(s.msrvRotate))
	s.opPermReauth(r, rbac.ServerWrite, "POST", "/admin/servers/{id}/revoke", "servers", "Revoke a node: certificate serial revoked, tokens invalidated", nil, s.h(s.msrvRevoke))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/servers/{id}/health", "servers", "Ping one node over mTLS now", nil, s.h(s.msrvHealthOne))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/servers/health", "servers", "Ping every active node over mTLS now", nil, s.h(s.msrvHealthAll))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/servers/push", "servers", "Push a named config bundle (firewall, revocations) to nodes as jobs", MsrvPushReq{}, s.h(s.msrvPush))
	s.opPerm(r, rbac.ServerRead, "GET", "/admin/servers/{id}/jobs", "servers", "Recent jobs targeted at a node", nil, s.h(s.msrvJobs))
}

// mountMsrvPublic: the enrolment endpoint (token auth, no session).
func (s *Server) mountMsrvPublic(r chi.Router) {
	r.Post("/msrv/join", s.h(s.msrvJoin))
}

func msrvErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, msrv.ErrNodeUnknown):
		return notFound()
	case errors.Is(err, msrv.ErrNameTaken):
		return conflict("msrv_name_taken")
	case errors.Is(err, msrv.ErrBadName):
		return badMsg("msrv_bad_name", "lower-case letters, digits, dot and dash (max 63)")
	case errors.Is(err, msrv.ErrBadAddress):
		return badMsg("msrv_bad_address", "host:port")
	case errors.Is(err, msrv.ErrBadRoles):
		return badMsg("msrv_bad_roles", "roles: web, dns, mail, db, backup, monitor")
	case errors.Is(err, msrv.ErrBadCSR):
		return badMsg("msrv_bad_csr", "")
	case errors.Is(err, msrv.ErrTokenInvalid):
		return &apiError{Status: 403, Code: "msrv_token_invalid"}
	case errors.Is(err, msrv.ErrRevoked):
		return conflict("msrv_cert_revoked")
	case errors.Is(err, msrv.ErrNoAddress):
		return conflict("msrv_no_address")
	case errors.Is(err, msrv.ErrCAUnusable):
		return &apiError{Status: 503, Code: "msrv_ca_unavailable"}
	}
	return err
}

func (s *Server) msrvList(w http.ResponseWriter, r *http.Request) (any, error) {
	m := s.msrv()
	nodes, err := m.Store.List(r.Context())
	if err != nil {
		return nil, err
	}
	out := map[string]any{"nodes": nodes, "roles": msrv.Roles, "bundles": msrv.Bundles, "ca_fingerprint": "", "ca_status": "ok"}
	if ca, err := m.CA(r.Context()); err == nil {
		out["ca_fingerprint"] = ca.Fingerprint()
	} else {
		out["ca_status"] = "unavailable"
	}
	return out, nil
}

func joinCommand(r *http.Request, tok string) string {
	scheme := "https"
	return "BPANEL_JOIN_TOKEN=" + tok + " bpanel-agent join --panel " + scheme + "://" + r.Host
}

func (s *Server) msrvCreate(w http.ResponseWriter, r *http.Request) (any, error) {
	var in MsrvCreateReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	m := s.msrv()
	if _, err := m.CA(r.Context()); err != nil {
		return nil, msrvErr(err)
	}
	n, tok, exp, err := m.Store.CreateNode(r.Context(), in.Name, in.Address, in.Roles, userOf(r).ID)
	if err != nil {
		s.audit(r, "msrv.create", in.Name, err.Error(), false)
		return nil, msrvErr(err)
	}
	s.audit(r, "msrv.create", n.Name, "token issued", true)
	return map[string]any{"node": n, "token": tok, "expires_at": exp, "command": joinCommand(r, tok)}, nil
}

func (s *Server) msrvUpdate(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	var in MsrvUpdateReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := s.msrv().Store.SetAddress(r.Context(), id, in.Address); err != nil {
		return nil, msrvErr(err)
	}
	s.audit(r, "msrv.update", strconv.FormatInt(id, 10), in.Address, true)
	return s.msrv().Store.Get(r.Context(), id)
}

func (s *Server) msrvRotate(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	tok, exp, err := s.msrv().Store.NewRotateToken(r.Context(), id, userOf(r).ID)
	if err != nil {
		s.audit(r, "msrv.rotate", strconv.FormatInt(id, 10), err.Error(), false)
		return nil, msrvErr(err)
	}
	s.audit(r, "msrv.rotate", strconv.FormatInt(id, 10), "rotate token issued", true)
	return map[string]any{"token": tok, "expires_at": exp, "command": joinCommand(r, tok)}, nil
}

func (s *Server) msrvRevoke(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	m := s.msrv()
	if err := m.Store.Revoke(r.Context(), id, "admin"); err != nil {
		return nil, msrvErr(err)
	}
	s.audit(r, "msrv.revoke", strconv.FormatInt(id, 10), "", true)
	// tell the other nodes too (their revocation list), as jobs
	jobsOut := s.msrvEnqueueAll(r, "revocations", nil, nil)
	return map[string]any{"status": "revoked", "jobs": jobsOut}, nil
}

func (s *Server) msrvHealthOne(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	if _, err := s.msrv().Store.Get(r.Context(), id); err != nil {
		return nil, msrvErr(err)
	}
	return s.msrv().Check(r.Context(), id), nil
}

func (s *Server) msrvHealthAll(w http.ResponseWriter, r *http.Request) (any, error) {
	return map[string]any{"results": s.msrv().CheckAll(r.Context())}, nil
}

type msrvJobRef struct {
	NodeID int64  `json:"node_id"`
	JobID  string `json:"job_id,omitempty"`
	Error  string `json:"error,omitempty"`
}

// msrvEnqueueAll enqueues bundle for ids (nil = every active node).
func (s *Server) msrvEnqueueAll(r *http.Request, bundle string, ids []int64, pl *msrv.PushPayload) []msrvJobRef {
	ctx := r.Context()
	m := s.msrv()
	if ids == nil {
		nodes, _ := m.Store.List(ctx)
		for _, n := range nodes {
			if n.Status == "active" {
				ids = append(ids, n.ID)
			}
		}
	}
	out := []msrvJobRef{}
	for _, id := range ids {
		p := msrv.PushPayload{NodeID: id, Bundle: bundle}
		if pl != nil {
			p.Ruleset = pl.Ruleset
		}
		ref := msrvJobRef{NodeID: id}
		n, err := m.Store.Get(ctx, id)
		if err == nil && n.Status != "active" {
			err = msrv.ErrNodeUnknown
		}
		if err != nil {
			ref.Error = "msrv_node_unknown"
			out = append(out, ref)
			continue
		}
		jid, err := s.Jobs().Enqueue(ctx, jobs.Spec{Kind: msrv.JobPush, ActorID: userOf(r).ID, Payload: p})
		if err == nil {
			_, err = s.Store.DB.ExecContext(ctx, `UPDATE jobs SET node_id=? WHERE id=?`, id, jid)
		}
		if err != nil {
			ref.Error = err.Error()
		} else {
			ref.JobID = jid
		}
		out = append(out, ref)
	}
	return out
}

func (s *Server) msrvPush(w http.ResponseWriter, r *http.Request) (any, error) {
	var in MsrvPushReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if len(in.NodeIDs) == 0 || len(in.NodeIDs) > 500 {
		return nil, badMsg("bad_params", "node_ids: 1..500")
	}
	var pl *msrv.PushPayload
	switch in.Bundle {
	case "revocations":
	case "firewall":
		rules, err := s.loadRules(r.Context())
		if err != nil {
			return nil, err
		}
		rs := s.ruleset(r, rules)
		// the node must stay reachable for the panel on its remote listener
		// port, otherwise the confirm fails and the node rolls back by itself
		if !containsInt(rs.PanelPorts, msrvAgentPort) && len(rs.PanelPorts) < 8 {
			rs.PanelPorts = append(append([]int{}, rs.PanelPorts...), msrvAgentPort)
		}
		if err := rs.Validate(); err != nil {
			return nil, nsErr(err)
		}
		pl = &msrv.PushPayload{Ruleset: &rs}
	default:
		return nil, badMsg("msrv_bad_bundle", "bundle: firewall | revocations")
	}
	refs := s.msrvEnqueueAll(r, in.Bundle, in.NodeIDs, pl)
	s.audit(r, "msrv.push", in.Bundle, strconv.Itoa(len(refs))+" node(s)", true)
	return map[string]any{"jobs": refs}, nil
}

func (s *Server) msrvRunPush(ctx context.Context, j *jobs.Job) (any, error) {
	p, err := msrv.DecodePush(j.Payload)
	if err != nil {
		return nil, err
	}
	res, err := s.msrv().Push(ctx, p)
	s.auditSystem("msrv.push."+p.Bundle, strconv.FormatInt(p.NodeID, 10), "", err == nil)
	if err != nil {
		return res, errors.New(msrvCodeOf(err))
	}
	return res, nil
}

func msrvCodeOf(err error) string {
	var ae *apiError
	if errors.As(msrvErr(err), &ae) {
		return ae.Code
	}
	return err.Error()
}

func (s *Server) msrvJobs(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT id,kind,status,result,error,created_at,updated_at FROM jobs WHERE node_id=? ORDER BY created_at DESC LIMIT 50`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var jid, kind, st, res, e string
		var c, u int64
		if err := rows.Scan(&jid, &kind, &st, &res, &e, &c, &u); err != nil {
			return nil, err
		}
		item := map[string]any{"id": jid, "kind": kind, "status": st, "error": e, "created_at": c / 1e9, "updated_at": u / 1e9}
		if res != "" {
			item["result"] = json.RawMessage(res)
		}
		out = append(out, item)
	}
	return map[string]any{"jobs": out}, rows.Err()
}

func (s *Server) msrvJoin(w http.ResponseWriter, r *http.Request) (any, error) {
	if !s.loginIP.Allow("msrv-join:" + s.clientIP(r)) {
		return nil, &apiError{Status: 429, Code: "rate_limited"}
	}
	var in MsrvJoinReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	m := s.msrv()
	ca, err := m.CA(r.Context())
	if err != nil {
		return nil, msrvErr(err)
	}
	en, err := m.Store.Enroll(r.Context(), ca, in.Token, []byte(in.CSR))
	if err != nil {
		s.auditSystem("msrv.join", s.clientIP(r), msrvCodeOf(err), false)
		return nil, msrvErr(err)
	}
	s.auditSystem("msrv.join", strconv.FormatInt(en.NodeID, 10), "enrolled from "+s.clientIP(r), true)
	return en, nil
}

// msrvLoop pings every active node periodically.
func (s *Server) msrvLoop(ctx context.Context) {
	t := time.NewTicker(MsrvHealthInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.msrv().CheckAll(ctx)
		}
	}
}
