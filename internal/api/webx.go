// SPDX-License-Identifier: Apache-2.0

package api

// v0.4 webx: user-panel web extras per domain (directory privacy, hotlink
// protection, custom error pages, MIME types, IP blocker). Every endpoint
// resolves the domain through ownDomain (the caller's own account only),
// validates with internal/webx, and applies through the agent's webx.apply,
// which re-applies the vhost with a config test and rolls back on failure.
// The database row is written only after the agent succeeded.

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/store"
	"github.com/cumabozkurt/bpanel/internal/webx"
)

// WebxPrivacyUserReq: Password empty keeps the user's current password.
type WebxPrivacyUserReq struct {
	Name     string `json:"name"`
	Password string `json:"password,omitempty"`
}

type WebxPrivacyDirReq struct {
	Path  string               `json:"path"`
	Realm string               `json:"realm"`
	Users []WebxPrivacyUserReq `json:"users"`
}

type WebxPrivacyReq struct {
	Dirs []WebxPrivacyDirReq `json:"dirs"`
}

type WebxErrorPagesReq struct {
	Pages map[string]string `json:"pages"`
}

type WebxMIMEReq struct {
	Types []webx.MIMEType `json:"types"`
}

type WebxDenyReq struct {
	Deny []string `json:"deny"`
}

type WebxIndexesReq struct {
	Indexes []webx.IndexDir `json:"indexes"`
}

type WebxHandlersReq struct {
	Handlers []webx.Handler `json:"handlers"`
}

type WebxLeechReq struct {
	Path     string `json:"path"`
	LeechMax int    `json:"leech_max"`
}

type WebxLeechUserReq struct {
	Path string `json:"path"`
	User string `json:"user"`
}

func (s *Server) mountWebx(r chi.Router) {
	s.op(r, "GET", "/user/web/extras", "web", "Web extras (privacy, hotlink, error pages, MIME, IP blocker) of every own domain", nil, s.h(s.webxList))
	s.op(r, "GET", "/user/web/{id}/extras", "web", "Web extras of one own domain (password hashes are never returned)", nil, s.h(s.webxGet))
	s.op(r, "PUT", "/user/web/{id}/privacy", "web", "Replace the password-protected directories (empty password keeps the current one)", WebxPrivacyReq{}, s.h(s.webxPutPrivacy))
	s.op(r, "PUT", "/user/web/{id}/hotlink", "web", "Set hotlink protection", webx.Hotlink{}, s.h(s.webxPutHotlink))
	s.op(r, "PUT", "/user/web/{id}/error-pages", "web", "Replace the custom error pages (400 401 403 404 500 502 503)", WebxErrorPagesReq{}, s.h(s.webxPutErrorPages))
	s.op(r, "PUT", "/user/web/{id}/mime", "web", "Replace the extra MIME types", WebxMIMEReq{}, s.h(s.webxPutMIME))
	s.op(r, "PUT", "/user/web/{id}/ip-blocker", "web", "Replace the blocked IPs / CIDR ranges", WebxDenyReq{}, s.h(s.webxPutDeny))
	// v1.1 parity: Directory Indexes, Apache Handlers, Leech Protection
	s.op(r, "PUT", "/user/web/{id}/indexes", "web", "Replace the directory listing settings (Options Indexes / autoindex) per directory", WebxIndexesReq{}, s.h(s.webxPutIndexes))
	s.op(r, "PUT", "/user/web/{id}/handlers", "web", "Replace the Apache handlers (default-handler, text-plain, server-parsed) per extension", WebxHandlersReq{}, s.h(s.webxPutHandlers))
	s.op(r, "PUT", "/user/web/{id}/leech", "web", "Set the Leech Protection limit of one protected directory (max distinct IPs per login in 2 hours; 0 = off)", WebxLeechReq{}, s.h(s.webxPutLeech))
	s.op(r, "POST", "/user/web/{id}/leech/enable", "web", "Re-enable a login that Leech Protection disabled", WebxLeechUserReq{}, s.h(s.webxLeechEnable))
	s.op(r, "POST", "/user/web/{id}/leech/scan", "web", "Run the Leech Protection scan of this domain now", nil, s.h(s.webxLeechScanNow))
}

func webxErr(err error) error {
	if e, ok := err.(*webx.Error); ok {
		return badMsg(e.Code, e.Msg)
	}
	return badMsg("webx_invalid", "invalid settings")
}

// webxLoad returns the stored config (Domain set) of an own, non-alias domain.
func (s *Server) webxLoad(r *http.Request) (store.Domain, webx.Config, int64, error) {
	d, err := s.ownDomain(r, idParam(r, "id"))
	if err != nil {
		return d, webx.Config{}, 0, err
	}
	if d.Kind == "alias" {
		return d, webx.Config{}, 0, badMsg("webx_alias", "an alias is served by its parent domain")
	}
	c, ver := s.webxStored(r.Context(), d)
	return d, c, ver, nil
}

func (s *Server) webxStored(ctx context.Context, d store.Domain) (webx.Config, int64) {
	var raw string
	var ver int64
	c := webx.Config{}
	if err := s.Store.DB.QueryRowContext(ctx, `SELECT config, version FROM webx_domains WHERE domain_id=?`, d.ID).Scan(&raw, &ver); err == nil {
		_ = json.Unmarshal([]byte(raw), &c)
	}
	c.Domain = d.Name
	if c.ErrorPages == nil {
		c.ErrorPages = map[string]string{}
	}
	return c, ver
}

// public strips password hashes.
func webxPublic(d store.Domain, c webx.Config, ver int64, status string) map[string]any {
	type pu struct {
		Path     string   `json:"path"`
		Realm    string   `json:"realm"`
		Users    []string `json:"users"`
		Disabled []string `json:"disabled"`
		LeechMax int      `json:"leech_max"`
	}
	priv := []pu{}
	for _, p := range c.Privacy {
		x := pu{Path: p.Path, Realm: p.Realm, Users: []string{}, Disabled: []string{}, LeechMax: p.LeechMax}
		for _, u := range p.Users {
			x.Users = append(x.Users, u.Name)
			if u.Disabled {
				x.Disabled = append(x.Disabled, u.Name)
			}
		}
		priv = append(priv, x)
	}
	idx, hnd := c.Indexes, c.Handlers
	if idx == nil {
		idx = []webx.IndexDir{}
	}
	if hnd == nil {
		hnd = []webx.Handler{}
	}
	h := c.Hotlink
	if h.Allowed == nil {
		h.Allowed = []string{}
	}
	if h.Exts == nil {
		h.Exts = []string{}
	}
	mime, deny := c.MIME, c.Deny
	if mime == nil {
		mime = []webx.MIMEType{}
	}
	if deny == nil {
		deny = []string{}
	}
	return map[string]any{"id": d.ID, "domain": d.Name, "kind": d.Kind, "privacy": priv, "hotlink": h, "error_pages": c.ErrorPages,
		"error_codes": webx.ErrorCodes, "mime": mime, "deny": deny, "version": ver, "status": status,
		"indexes": idx, "handlers": hnd, "handler_names": webx.Handlers, "leech_window": webx.LeechWindow}
}

func (s *Server) webxList(w http.ResponseWriter, r *http.Request) (any, error) {
	doms, err := s.domainsOf(r.Context(), userOf(r).ID)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, d := range doms {
		if d.Kind == "alias" {
			continue
		}
		c, ver := s.webxStored(r.Context(), d)
		var st string
		_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT status FROM webx_domains WHERE domain_id=?`, d.ID).Scan(&st)
		out = append(out, webxPublic(d, c, ver, st))
	}
	return map[string]any{"domains": out, "error_codes": webx.ErrorCodes}, nil
}

func (s *Server) webxGet(w http.ResponseWriter, r *http.Request) (any, error) {
	d, c, ver, err := s.webxLoad(r)
	if err != nil {
		return nil, err
	}
	return webxPublic(d, c, ver, ""), nil
}

// webxApply validates, applies through the agent and persists on success.
func (s *Server) webxApply(ctx context.Context, d store.Domain, c webx.Config, ver int64) (webx.Config, int64, string, error) {
	if err := c.Normalize(); err != nil {
		return c, ver, "", webxErr(err)
	}
	vh := s.wafVhost(ctx, d.Name)
	if vh == nil {
		return c, ver, "", badMsg("webx_alias", "the domain has no own vhost")
	}
	var out rpc.WebxApplyResult
	if err := s.Agent.Call(ctx, rpc.MWebxApply, rpc.WebxApplyParams{User: vh.User, Config: c, Vhost: *vh}, &out); err != nil {
		return c, ver, "", err
	}
	ver++
	if _, err := s.Store.DB.ExecContext(ctx, `INSERT INTO webx_domains(domain_id,config,version,status,updated_at) VALUES(?,?,?,?,?)
		ON CONFLICT(domain_id) DO UPDATE SET config=excluded.config, version=excluded.version, status=excluded.status, updated_at=excluded.updated_at`,
		d.ID, mustJSON(c), ver, out.Status, time.Now().Unix()); err != nil {
		return c, ver, "", err
	}
	return c, ver, out.Status, nil
}

// webxSave is webxApply for a request (audited).
func (s *Server) webxSave(r *http.Request, d store.Domain, c webx.Config, ver int64, what string) (any, error) {
	c, ver, st, err := s.webxApply(r.Context(), d, c, ver)
	if err != nil {
		if _, ok := err.(*apiError); !ok {
			s.audit(r, "webx."+what, d.Name, nsAgentCode(err), false)
		}
		return nil, err
	}
	s.audit(r, "webx."+what, d.Name, st, true)
	return webxPublic(d, c, ver, st), nil
}

func (s *Server) webxPutPrivacy(w http.ResponseWriter, r *http.Request) (any, error) {
	var in WebxPrivacyReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	d, c, ver, err := s.webxLoad(r)
	if err != nil {
		return nil, err
	}
	if len(in.Dirs) > webx.MaxPrivacyDirs {
		return nil, badMsg("webx_invalid", "too many protected directories")
	}
	old := map[string]string{} // path|user -> hash
	oldDis := map[string]bool{}
	oldLeech := map[string]int{}
	for _, p := range c.Privacy {
		oldLeech[p.Path] = p.LeechMax
		for _, u := range p.Users {
			old[p.Path+"|"+u.Name] = u.Hash
			oldDis[p.Path+"|"+u.Name] = u.Disabled
		}
	}
	dirs := []webx.PrivacyDir{}
	for _, dr := range in.Dirs {
		path, err := webx.CleanPath(dr.Path)
		if err != nil {
			return nil, webxErr(err)
		}
		if len(dr.Users) > webx.MaxPrivacyUsers {
			return nil, badMsg("webx_invalid", "too many users")
		}
		pd := webx.PrivacyDir{Path: path, Realm: strings.TrimSpace(dr.Realm), LeechMax: oldLeech[path]}
		for _, u := range dr.Users {
			name := strings.TrimSpace(u.Name)
			var hash string
			switch {
			case u.Password != "":
				if len(u.Password) < 8 || len(u.Password) > 72 {
					return nil, badMsg("webx_weak_password", "password must be 8 to 72 bytes")
				}
				b, err := bcrypt.GenerateFromPassword([]byte(u.Password), 10)
				if err != nil {
					return nil, err
				}
				// $2y$ is the prefix Apache htpasswd writes; nginx (libxcrypt) accepts it too
				hash = "$2y$" + strings.TrimPrefix(string(b), "$2a$")
			case old[path+"|"+name] != "":
				hash = old[path+"|"+name]
			default:
				return nil, badMsg("webx_password_required", "a new user needs a password")
			}
			// a new password re-enables a login Leech Protection disabled
			pd.Users = append(pd.Users, webx.PrivacyUser{Name: name, Hash: hash, Disabled: u.Password == "" && oldDis[path+"|"+name]})
		}
		if len(pd.Users) == 0 {
			return nil, badMsg("webx_password_required", "a protected directory needs at least one user")
		}
		dirs = append(dirs, pd)
	}
	c.Privacy = dirs
	return s.webxSave(r, d, c, ver, "privacy")
}

func (s *Server) webxPutHotlink(w http.ResponseWriter, r *http.Request) (any, error) {
	var in webx.Hotlink
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	d, c, ver, err := s.webxLoad(r)
	if err != nil {
		return nil, err
	}
	c.Hotlink = in
	return s.webxSave(r, d, c, ver, "hotlink")
}

func (s *Server) webxPutErrorPages(w http.ResponseWriter, r *http.Request) (any, error) {
	var in WebxErrorPagesReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	d, c, ver, err := s.webxLoad(r)
	if err != nil {
		return nil, err
	}
	if in.Pages == nil {
		in.Pages = map[string]string{}
	}
	c.ErrorPages = in.Pages
	return s.webxSave(r, d, c, ver, "error_pages")
}

func (s *Server) webxPutMIME(w http.ResponseWriter, r *http.Request) (any, error) {
	var in WebxMIMEReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	d, c, ver, err := s.webxLoad(r)
	if err != nil {
		return nil, err
	}
	c.MIME = in.Types
	return s.webxSave(r, d, c, ver, "mime")
}

func (s *Server) webxPutDeny(w http.ResponseWriter, r *http.Request) (any, error) {
	var in WebxDenyReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	d, c, ver, err := s.webxLoad(r)
	if err != nil {
		return nil, err
	}
	c.Deny = in.Deny
	return s.webxSave(r, d, c, ver, "ip_blocker")
}

// ---- v1.1: Directory Indexes, Apache Handlers, Leech Protection -------------------

func (s *Server) webxPutIndexes(w http.ResponseWriter, r *http.Request) (any, error) {
	var in WebxIndexesReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	d, c, ver, err := s.webxLoad(r)
	if err != nil {
		return nil, err
	}
	c.Indexes = in.Indexes
	return s.webxSave(r, d, c, ver, "indexes")
}

func (s *Server) webxPutHandlers(w http.ResponseWriter, r *http.Request) (any, error) {
	var in WebxHandlersReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	d, c, ver, err := s.webxLoad(r)
	if err != nil {
		return nil, err
	}
	c.Handlers = in.Handlers
	return s.webxSave(r, d, c, ver, "handlers")
}

func (s *Server) webxPutLeech(w http.ResponseWriter, r *http.Request) (any, error) {
	var in WebxLeechReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	d, c, ver, err := s.webxLoad(r)
	if err != nil {
		return nil, err
	}
	p, err := webx.CleanPath(in.Path)
	if err != nil {
		return nil, webxErr(err)
	}
	for i := range c.Privacy {
		if c.Privacy[i].Path == p {
			c.Privacy[i].LeechMax = in.LeechMax
			return s.webxSave(r, d, c, ver, "leech")
		}
	}
	return nil, badMsg("webx_not_protected", "protect the directory with a password first")
}

func (s *Server) webxLeechEnable(w http.ResponseWriter, r *http.Request) (any, error) {
	var in WebxLeechUserReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	d, c, ver, err := s.webxLoad(r)
	if err != nil {
		return nil, err
	}
	p, err := webx.CleanPath(in.Path)
	if err != nil {
		return nil, webxErr(err)
	}
	for i := range c.Privacy {
		if c.Privacy[i].Path != p {
			continue
		}
		for j := range c.Privacy[i].Users {
			if c.Privacy[i].Users[j].Name == in.User {
				c.Privacy[i].Users[j].Disabled = false
				return s.webxSave(r, d, c, ver, "leech_enable")
			}
		}
	}
	return nil, notFound()
}

func (s *Server) webxLeechScanNow(w http.ResponseWriter, r *http.Request) (any, error) {
	d, c, ver, err := s.webxLoad(r)
	if err != nil {
		return nil, err
	}
	n, err := s.leechCheck(r.Context(), d, c, ver)
	if err != nil {
		return nil, err
	}
	s.audit(r, "webx.leech_scan", d.Name, strconv.Itoa(n), true)
	c, ver = s.webxStored(r.Context(), d)
	out := webxPublic(d, c, ver, "")
	out["disabled_now"] = n
	return out, nil
}

// leechCheck scans the domain log once and disables every login used from
// more distinct IPs than its directory allows within LeechWindow. It
// returns how many logins it disabled.
func (s *Server) leechCheck(ctx context.Context, d store.Domain, c webx.Config, ver int64) (int, error) {
	var paths []string
	limit := map[string]int{}
	for _, p := range c.Privacy {
		if p.LeechMax > 0 {
			paths = append(paths, p.Path)
			limit[p.Path] = p.LeechMax
		}
	}
	if len(paths) == 0 {
		return 0, nil
	}
	vh := s.wafVhost(ctx, d.Name)
	if vh == nil {
		return 0, nil
	}
	var res rpc.LeechScanResult
	if err := s.Agent.Call(ctx, rpc.MWebxLeechScan, rpc.LeechScanParams{User: vh.User, Domain: d.Name, Paths: paths, Window: webx.LeechWindow}, &res); err != nil {
		return 0, err
	}
	n := 0
	for _, h := range res.Hits {
		if h.IPs <= limit[h.Path] {
			continue
		}
		for i := range c.Privacy {
			if c.Privacy[i].Path != h.Path {
				continue
			}
			for j := range c.Privacy[i].Users {
				u := &c.Privacy[i].Users[j]
				if u.Name == h.Login && !u.Disabled {
					u.Disabled = true
					n++
					s.auditSystem("webx.leech_disable", d.Name+h.Path+" "+h.Login, strconv.Itoa(h.IPs)+" IPs", true)
				}
			}
		}
	}
	if n == 0 {
		return 0, nil
	}
	if _, _, _, err := s.webxApply(ctx, d, c, ver); err != nil {
		return 0, err
	}
	return n, nil
}

// leechSweep runs leechCheck for every domain with a Leech Protection limit.
func (s *Server) leechSweep(ctx context.Context) {
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT domain_id FROM webx_domains WHERE config LIKE '%"leech_max":%'`)
	if err != nil {
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		d, err := store.One[store.Domain](ctx, s.Store.DB, `SELECT * FROM domains WHERE id=?`, id)
		if err != nil {
			continue
		}
		c, ver := s.webxStored(ctx, d)
		if _, err := s.leechCheck(ctx, d, c, ver); err != nil && s.Log != nil {
			s.Log.Warn("leech protection scan", "domain", d.Name, "err", err)
		}
	}
}

// leechLoop runs leechSweep every leech_sweep_minutes (Tweak Settings).
func (s *Server) leechLoop(ctx context.Context) {
	for {
		d := time.Duration(s.tweakInt("leech_sweep_minutes", 10)) * time.Minute
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
		if s.featureOn("leech_protection") {
			s.leechSweep(ctx)
		}
	}
}
