// SPDX-License-Identifier: Apache-2.0

package api

// v0.4 appx: Application Manager (Node.js / Python), app installer (free
// apps, pinned checksums) and WordPress toolkit. Every user endpoint is
// scoped to the caller's own account (rows by user_id, domains through
// ownDomain); the agent re-checks the account and the domain owner. Rows are
// written before the agent call and undone when it fails.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/appx"
	"github.com/cumabozkurt/bpanel/internal/rbac"
	"github.com/cumabozkurt/bpanel/internal/store"
)

type AppxAppReq struct {
	Name     string            `json:"name"`
	Runtime  string            `json:"runtime"`
	Version  string            `json:"version"`
	Root     string            `json:"root"`
	Startup  string            `json:"startup"`
	DomainID int64             `json:"domain_id"` // 0 = no public URL
	URLPath  string            `json:"url_path"`
	Env      map[string]string `json:"env"`
}

type AppxCtlReq struct {
	Action string `json:"action"` // start | stop | restart | status
}

type AppxInstallReq struct {
	App      string `json:"app"`
	DomainID int64  `json:"domain_id"`
	Path     string `json:"path"` // below the domain's document root, "" = the root itself
}

type AppxMaintReq struct {
	On bool `json:"on"`
}

type AppxSettingsReq struct {
	PortLo int `json:"port_lo"`
	PortHi int `json:"port_hi"`
}

func (s *Server) mountAppx(r chi.Router) {
	s.op(r, "GET", "/user/apps", "apps", "Applications (Node.js / Python), detected runtimes and whether services can run", nil, s.h(s.appxList))
	s.op(r, "POST", "/user/apps", "apps", "Create an application (port is allocated by the server)", AppxAppReq{}, s.h(s.appxCreate))
	s.op(r, "PUT", "/user/apps/{id}", "apps", "Change an application", AppxAppReq{}, s.h(s.appxUpdate))
	s.op(r, "DELETE", "/user/apps/{id}", "apps", "Stop and delete an application (files are kept)", nil, s.h(s.appxDelete))
	s.op(r, "POST", "/user/apps/{id}/ctl", "apps", "Start, stop, restart or read the state of an application (systemd only)", AppxCtlReq{}, s.h(s.appxCtl))
	s.op(r, "GET", "/user/apps/{id}/logs", "apps", "Last journal lines of an application (systemd only)", nil, s.h(s.appxLogs))
	s.op(r, "POST", "/user/apps/{id}/deps", "apps", "npm install / pip install -r requirements.txt as the account", nil, s.h(s.appxDeps))
	s.op(r, "GET", "/user/installer/catalog", "apps", "Free application catalogue (pinned versions and checksums)", nil, s.h(s.appxCatalog))
	s.op(r, "GET", "/user/installer/installs", "apps", "Installed applications", nil, s.h(s.appxInstalls))
	s.op(r, "POST", "/user/installer/install", "apps", "Install a catalogue app into an own domain (creates its database)", AppxInstallReq{}, s.h(s.appxInstall))
	s.op(r, "DELETE", "/user/installer/installs/{id}", "apps", "Forget an installation (files and database are kept)", nil, s.h(s.appxForget))
	s.op(r, "GET", "/user/wordpress/{id}", "apps", "WordPress installation details (version, maintenance, WP-CLI)", nil, s.h(s.appxWPInfo))
	s.op(r, "POST", "/user/wordpress/{id}/maintenance", "apps", "Turn WordPress maintenance mode on or off", AppxMaintReq{}, s.h(s.appxWPMaint))
	s.op(r, "POST", "/user/wordpress/{id}/update", "apps", "Update WordPress core with WP-CLI (when installed)", nil, s.h(s.appxWPUpdate))
}

func (s *Server) mountAppxAdmin(r chi.Router) {
	s.opPerm(r, rbac.ServerRead, "GET", "/admin/apps/settings", "apps", "Application port range, detected runtimes, systemd and WP-CLI state", nil, s.h(s.appxAdminGet))
	s.opPerm(r, rbac.ServerWrite, "PUT", "/admin/apps/settings", "apps", "Set the application port range", AppxSettingsReq{}, s.h(s.appxAdminPut))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/apps/wpcli", "apps", "Install the official WP-CLI phar (verified against its published sha512)", nil, s.h(s.appxAdminWPCLI))
}

func appxAPIErr(err error) error {
	var e *appx.Error
	if errors.As(err, &e) {
		return badMsg(e.Code, e.Msg)
	}
	return err
}

func (s *Server) appxRange(ctx context.Context) (int, int) {
	lo, hi := appx.DefaultPortLo, appx.DefaultPortHi
	var v string
	if s.Store.DB.QueryRowContext(ctx, `SELECT value FROM appx_settings WHERE key='port_lo'`).Scan(&v) == nil {
		if n, err := strconv.Atoi(v); err == nil {
			lo = n
		}
	}
	if s.Store.DB.QueryRowContext(ctx, `SELECT value FROM appx_settings WHERE key='port_hi'`).Scan(&v) == nil {
		if n, err := strconv.Atoi(v); err == nil {
			hi = n
		}
	}
	return lo, hi
}

type appxRow struct {
	appx.App
	UserID   int64  `json:"-"`
	DomainID int64  `json:"domain_id"`
	Status   string `json:"status"`
	URL      string `json:"url,omitempty"`
}

const appxCols = `a.id, a.user_id, COALESCE(a.domain_id,0), COALESCE(d.name,''), a.name, a.runtime, a.version, a.root, a.startup, a.url_path, a.port, a.env, a.status`

func scanApp(sc interface{ Scan(...any) error }) (appxRow, error) {
	var x appxRow
	var env string
	err := sc.Scan(&x.ID, &x.UserID, &x.DomainID, &x.Domain, &x.Name, &x.Runtime, &x.Version, &x.Root, &x.Startup, &x.URLPath, &x.Port, &env, &x.Status)
	_ = json.Unmarshal([]byte(env), &x.Env)
	if x.Env == nil {
		x.Env = map[string]string{}
	}
	if x.Domain != "" {
		x.URL = "https://" + x.Domain + strings.TrimSuffix(x.URLPath, "/") + "/"
	} else {
		x.URLPath = ""
	}
	return x, err
}

func (s *Server) appxOwn(r *http.Request) (appxRow, error) {
	row := s.Store.DB.QueryRowContext(r.Context(), `SELECT `+appxCols+` FROM appx_apps a LEFT JOIN domains d ON d.id=a.domain_id WHERE a.id=? AND a.user_id=?`,
		idParam(r, "id"), userOf(r).ID)
	x, err := scanApp(row)
	if err != nil {
		return x, notFound()
	}
	return x, nil
}

func (s *Server) appxList(w http.ResponseWriter, r *http.Request) (any, error) {
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT `+appxCols+` FROM appx_apps a LEFT JOIN domains d ON d.id=a.domain_id WHERE a.user_id=? ORDER BY a.name`, userOf(r).ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	apps := []appxRow{}
	for rows.Next() {
		x, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		apps = append(apps, x)
	}
	var rt rpc.AppxRuntimesResult
	if err := s.agentCall(r, rpc.MAppxRuntimes, struct{}{}, &rt); err != nil {
		return nil, err
	}
	if rt.Runtimes == nil {
		rt.Runtimes = []rpc.AppxRuntime{}
	}
	out := map[string]any{"apps": apps, "runtimes": rt.Runtimes, "systemd": rt.Systemd, "max_apps": appx.MaxApps}
	if !rt.Systemd {
		out["unsupported_reason"] = "systemd is not PID 1 on this server: applications can be configured but not started"
	}
	return out, nil
}

// appxProxies returns every proxy entry of a domain (all accounts' apps on it
// are the domain owner's, since domain_id is checked through ownDomain).
func (s *Server) appxProxies(ctx context.Context, domainID int64) ([]appx.Proxy, error) {
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT url_path, port FROM appx_apps WHERE domain_id=?`, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []appx.Proxy{}
	for rows.Next() {
		var p appx.Proxy
		if err := rows.Scan(&p.URLPath, &p.Port); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Server) appxDomainList(ctx context.Context, ids ...int64) ([]rpc.AppxDomain, error) {
	out := []rpc.AppxDomain{}
	seen := map[int64]bool{}
	for _, id := range ids {
		if id == 0 || seen[id] {
			continue
		}
		seen[id] = true
		var name string
		if err := s.Store.DB.QueryRowContext(ctx, `SELECT name FROM domains WHERE id=?`, id).Scan(&name); err != nil {
			continue
		}
		vh := s.wafVhost(ctx, name)
		if vh == nil {
			continue
		}
		px, err := s.appxProxies(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, rpc.AppxDomain{Vhost: *vh, Proxies: px})
	}
	return out, nil
}

// appxBuild validates a request into an App (domain resolved through ownDomain).
func (s *Server) appxBuild(r *http.Request, in AppxAppReq, id int64, port int) (appx.App, int64, error) {
	a := appx.App{ID: id, User: userOf(r).Username, Name: strings.TrimSpace(in.Name), Runtime: in.Runtime, Version: strings.TrimSpace(in.Version),
		Root: in.Root, Startup: in.Startup, URLPath: in.URLPath, Port: port, Env: in.Env}
	var domID int64
	if in.DomainID != 0 {
		d, err := s.ownDomain(r, in.DomainID)
		if err != nil {
			return a, 0, err
		}
		if d.Kind == "alias" {
			return a, 0, badMsg("appx_alias", "an alias is served by its parent domain")
		}
		a.Domain, domID = d.Name, d.ID
	}
	if err := a.Validate(); err != nil {
		return a, 0, appxAPIErr(err)
	}
	if domID != 0 {
		var n int
		_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM appx_apps WHERE domain_id=? AND url_path=? AND id<>?`, domID, a.URLPath, id).Scan(&n)
		if n > 0 {
			return a, 0, badMsg("appx_url_path_taken", "another application already serves this URL")
		}
	}
	return a, domID, nil
}

func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func (s *Server) appxCreate(w http.ResponseWriter, r *http.Request) (any, error) {
	var in AppxAppReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	if _, _, err := s.appxBuild(r, in, 0, appx.DefaultPortLo); err != nil {
		return nil, err
	}
	var n int
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM appx_apps WHERE user_id=?`, u.ID).Scan(&n)
	if n >= appx.MaxApps {
		return nil, badMsg("appx_limit", "application limit reached")
	}
	lo, hi := s.appxRange(r.Context())
	var id int64
	var port int
	for try := 0; ; try++ {
		used := map[int]bool{}
		rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT port FROM appx_apps`)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var p int
			_ = rows.Scan(&p)
			used[p] = true
		}
		rows.Close()
		if port, err = appx.AllocPort(used, lo, hi); err != nil {
			return nil, appxAPIErr(err)
		}
		res, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO appx_apps(user_id,name,runtime,version,root,startup,port,created_at) VALUES(?,?,?,?,?,?,?,?)`,
			u.ID, strings.TrimSpace(in.Name), in.Runtime, in.Version, in.Root, in.Startup, port, time.Now().Unix())
		if err != nil {
			if strings.Contains(err.Error(), "appx_apps.user_id, appx_apps.name") {
				return nil, badMsg("already_exists", "an application with this name exists")
			}
			if try < 3 && strings.Contains(err.Error(), "UNIQUE") {
				continue // port taken concurrently
			}
			return nil, err
		}
		id, _ = res.LastInsertId()
		break
	}
	a, domID, err := s.appxBuild(r, in, id, port)
	if err == nil {
		_, err = s.Store.DB.ExecContext(r.Context(), `UPDATE appx_apps SET domain_id=?, url_path=?, env=?, root=?, startup=? WHERE id=?`,
			nullID(domID), a.URLPath, mustJSON(a.Env), a.Root, a.Startup, id)
	}
	if err == nil {
		err = s.appxPush(r, a, domID)
	}
	if err != nil {
		s.deleteRow(r.Context(), "appx_apps", id)
		if domID != 0 { // put the domain's proxy back as it was
			if doms, derr := s.appxDomainList(context.WithoutCancel(r.Context()), domID); derr == nil && len(doms) > 0 {
				_ = s.Agent.Call(context.WithoutCancel(r.Context()), rpc.MAppxAppRemove, rpc.AppxAppRef{User: u.Username, ID: id, Domains: doms}, nil)
			}
		}
		s.audit(r, "appx.create", in.Name, nsAgentCode(err), false)
		return nil, err
	}
	s.audit(r, "appx.create", a.Name, strconv.Itoa(port), true)
	return s.appxOwnByID(r, id)
}

func (s *Server) appxOwnByID(r *http.Request, id int64) (any, error) {
	row := s.Store.DB.QueryRowContext(r.Context(), `SELECT `+appxCols+` FROM appx_apps a LEFT JOIN domains d ON d.id=a.domain_id WHERE a.id=? AND a.user_id=?`, id, userOf(r).ID)
	return scanApp(row)
}

func (s *Server) appxPush(r *http.Request, a appx.App, domIDs ...int64) error {
	doms, err := s.appxDomainList(r.Context(), domIDs...)
	if err != nil {
		return err
	}
	var out rpc.AppxAppResult
	if err := s.agentCall(r, rpc.MAppxAppApply, rpc.AppxAppApplyParams{User: a.User, App: a, Domains: doms}, &out); err != nil {
		return err
	}
	_, _ = s.Store.DB.ExecContext(r.Context(), `UPDATE appx_apps SET status=? WHERE id=?`, out.Status, a.ID)
	return nil
}

func (s *Server) appxUpdate(w http.ResponseWriter, r *http.Request) (any, error) {
	var in AppxAppReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	old, err := s.appxOwn(r)
	if err != nil {
		return nil, err
	}
	in.Name = old.Name // the name is the identity shown in the unit; not renamed
	a, domID, err := s.appxBuild(r, in, old.ID, old.Port)
	if err != nil {
		return nil, err
	}
	upd := `UPDATE appx_apps SET domain_id=?, url_path=?, env=?, root=?, startup=?, runtime=?, version=? WHERE id=?`
	if _, err := s.Store.DB.ExecContext(r.Context(), upd, nullID(domID), a.URLPath, mustJSON(a.Env), a.Root, a.Startup, a.Runtime, a.Version, a.ID); err != nil {
		return nil, err
	}
	if err := s.appxPush(r, a, domID, old.DomainID); err != nil {
		ctx := context.WithoutCancel(r.Context())
		_, _ = s.Store.DB.ExecContext(ctx, upd, nullID(old.DomainID), old.URLPath, mustJSON(old.Env), old.Root, old.Startup, old.Runtime, old.Version, old.ID)
		s.audit(r, "appx.update", a.Name, nsAgentCode(err), false)
		return nil, err
	}
	s.audit(r, "appx.update", a.Name, "", true)
	return s.appxOwnByID(r, a.ID)
}

func (s *Server) appxDelete(w http.ResponseWriter, r *http.Request) (any, error) {
	x, err := s.appxOwn(r)
	if err != nil {
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM appx_apps WHERE id=?`, x.ID); err != nil {
		return nil, err
	}
	doms, err := s.appxDomainList(r.Context(), x.DomainID)
	if err == nil {
		err = s.agentCall(r, rpc.MAppxAppRemove, rpc.AppxAppRef{User: userOf(r).Username, ID: x.ID, Domains: doms}, nil)
	}
	if err != nil {
		ctx := context.WithoutCancel(r.Context())
		_, _ = s.Store.DB.ExecContext(ctx, `INSERT INTO appx_apps(id,user_id,domain_id,name,runtime,version,root,startup,url_path,port,env,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			x.ID, x.UserID, nullID(x.DomainID), x.Name, x.Runtime, x.Version, x.Root, x.Startup, x.URLPath, x.Port, mustJSON(x.Env), x.Status, time.Now().Unix())
		s.audit(r, "appx.delete", x.Name, nsAgentCode(err), false)
		return nil, err
	}
	s.audit(r, "appx.delete", x.Name, "", true)
	return map[string]any{"deleted": true}, nil
}

func (s *Server) appxCtl(w http.ResponseWriter, r *http.Request) (any, error) {
	var in AppxCtlReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	x, err := s.appxOwn(r)
	if err != nil {
		return nil, err
	}
	switch in.Action {
	case "start", "stop", "restart", "status":
	default:
		return nil, badMsg("appx_invalid", "unknown action")
	}
	var out rpc.AppxCtlResult
	if err := s.agentCall(r, rpc.MAppxAppCtl, rpc.AppxAppRef{User: userOf(r).Username, ID: x.ID, Action: in.Action}, &out); err != nil {
		if in.Action != "status" {
			s.audit(r, "appx."+in.Action, x.Name, nsAgentCode(err), false)
		}
		return nil, err
	}
	if in.Action != "status" {
		s.audit(r, "appx."+in.Action, x.Name, out.Active, true)
	}
	return out, nil
}

func (s *Server) appxLogs(w http.ResponseWriter, r *http.Request) (any, error) {
	x, err := s.appxOwn(r)
	if err != nil {
		return nil, err
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	var out rpc.AppxOutput
	if err := s.agentCall(r, rpc.MAppxAppLogs, rpc.AppxAppRef{User: userOf(r).Username, ID: x.ID, Lines: n}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Server) appxDeps(w http.ResponseWriter, r *http.Request) (any, error) {
	x, err := s.appxOwn(r)
	if err != nil {
		return nil, err
	}
	var out rpc.AppxOutput
	if err := s.agentCall(r, rpc.MAppxAppDeps, rpc.AppxAppRef{User: userOf(r).Username, ID: x.ID}, &out); err != nil {
		s.audit(r, "appx.deps", x.Name, nsAgentCode(err), false)
		return nil, err
	}
	s.audit(r, "appx.deps", x.Name, "", true)
	return out, nil
}

// ---- installer ----

func (s *Server) appxCatalog(w http.ResponseWriter, r *http.Request) (any, error) {
	return map[string]any{"apps": appx.Catalog}, nil
}

type appxInstallRow struct {
	ID       int64  `json:"id"`
	DomainID int64  `json:"domain_id"`
	Domain   string `json:"domain"`
	App      string `json:"app"`
	Version  string `json:"version"`
	Path     string `json:"path"`
	URL      string `json:"url"`
	DBName   string `json:"db_name"`
	DBUser   string `json:"db_user"`
	Created  int64  `json:"created_at"`
}

const appxInstCols = `i.id, COALESCE(i.domain_id,0), COALESCE(d.name,''), i.app, i.version, i.path, i.url, i.db_name, i.db_user, i.created_at`

func scanInst(sc interface{ Scan(...any) error }) (appxInstallRow, error) {
	var x appxInstallRow
	err := sc.Scan(&x.ID, &x.DomainID, &x.Domain, &x.App, &x.Version, &x.Path, &x.URL, &x.DBName, &x.DBUser, &x.Created)
	return x, err
}

func (s *Server) appxInstalls(w http.ResponseWriter, r *http.Request) (any, error) {
	q := `SELECT ` + appxInstCols + ` FROM appx_installs i LEFT JOIN domains d ON d.id=i.domain_id WHERE i.user_id=?`
	args := []any{userOf(r).ID}
	if a := r.URL.Query().Get("app"); a != "" {
		q += ` AND i.app=?`
		args = append(args, a)
	}
	rows, err := s.Store.DB.QueryContext(r.Context(), q+` ORDER BY i.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []appxInstallRow{}
	for rows.Next() {
		x, err := scanInst(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return map[string]any{"installs": out}, nil
}

func (s *Server) appxOwnInstall(r *http.Request) (appxInstallRow, error) {
	x, err := scanInst(s.Store.DB.QueryRowContext(r.Context(), `SELECT `+appxInstCols+` FROM appx_installs i LEFT JOIN domains d ON d.id=i.domain_id WHERE i.id=? AND i.user_id=?`,
		idParam(r, "id"), userOf(r).ID))
	if err != nil {
		return x, notFound()
	}
	return x, nil
}

func (s *Server) appxInstall(w http.ResponseWriter, r *http.Request) (any, error) {
	var in AppxInstallReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	c, ok := appx.Find(in.App)
	if !ok || !c.Enabled {
		return nil, badMsg("appx_app_unavailable", "this application is not installable")
	}
	d, err := s.ownDomain(r, in.DomainID)
	if err != nil {
		return nil, err
	}
	if d.Kind == "alias" || d.Redirect != "" {
		return nil, badMsg("appx_alias", "pick a domain that serves its own document root")
	}
	dest := d.DocRoot
	sub := strings.Trim(strings.TrimSpace(in.Path), "/")
	if c.RootOnly && sub != "" {
		return nil, badMsg("appx_root_only", "this application must be installed in the document root of a domain")
	}
	if sub != "" {
		if sub, err = appx.CleanRel(sub); err != nil {
			return nil, appxAPIErr(err)
		}
		dest = path.Join(d.DocRoot, sub)
	}
	if dest, err = appx.CleanRel(dest); err != nil {
		return nil, appxAPIErr(err)
	}
	var n int
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM appx_installs WHERE user_id=? AND path=?`, userOf(r).ID, dest).Scan(&n)
	if n > 0 {
		return nil, badMsg("appx_dest_not_empty", "an application is already installed there")
	}
	u := userOf(r)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 15*time.Minute)
	defer cancel()
	r = r.WithContext(ctx)
	var dbName, dbUser, dbPass string
	var undo []func()
	rollback := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
	if c.NeedsDB {
		tag, _ := appx.RandomString(4, "abcdefghijklmnopqrstuvwxyz0123456789")
		short := c.ID[:min(len(c.ID), 4)] + tag
		if dbPass, err = appx.RandomString(20, "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"); err != nil {
			return nil, err
		}
		dbPass = "Aa7-" + dbPass
		dbID, name, err := s.newDatabase(r, short)
		if err != nil {
			return nil, err
		}
		dbName = name
		undo = append(undo, func() {
			if s.Agent.Call(ctx, rpc.MDBDrop, rpc.DBRef{Owner: u.Username, Name: name}, nil) == nil {
				s.deleteRow(ctx, "databases", dbID)
			}
		})
		uid, uname, err := s.newDBUser(r, short, dbPass)
		if err != nil {
			rollback()
			return nil, err
		}
		dbUser = uname
		undo = append(undo, func() {
			if s.Agent.Call(ctx, rpc.MDBUserDrop, rpc.DBUserRef{Owner: u.Username, User: uname}, nil) == nil {
				s.deleteRow(ctx, "db_users", uid)
			}
		})
		privs, _ := grantList(nil, true)
		if err := s.doGrant(r, u, dbID, name, uid, uname, privs); err != nil {
			rollback()
			return nil, err
		}
	}
	var out rpc.AppxInstallResult
	p := rpc.AppxInstallParams{User: u.Username, App: c.ID, Dest: dest}
	if c.ID == "wordpress" {
		p.DB = appx.WPConfig{DBName: dbName, DBUser: dbUser, DBPassword: dbPass, DBHost: "localhost"}
	}
	if err := s.agentCall(r, rpc.MAppxInstall, p, &out); err != nil {
		rollback()
		s.audit(r, "appx.install", c.ID+":"+dest, nsAgentCode(err), false)
		return nil, err
	}
	url := "https://" + d.Name + "/"
	if sub != "" {
		url += sub + "/"
	}
	res, err := s.Store.DB.ExecContext(ctx, `INSERT INTO appx_installs(user_id,domain_id,app,version,path,url,db_name,db_user,created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		u.ID, d.ID, c.ID, out.Version, dest, url, dbName, dbUser, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	s.audit(r, "appx.install", c.ID+":"+dest, out.Version, true)
	resp := map[string]any{"id": id, "app": c.ID, "version": out.Version, "path": dest, "url": url, "db_name": dbName, "db_user": dbUser,
		"config_written": out.Config, "post_install": c.PostInstall}
	if c.NeedsDB && c.ID != "wordpress" {
		resp["db_password"] = dbPass // shown once: the user types it into the app's web installer
		resp["db_host"] = "localhost"
	}
	return resp, nil
}

func (s *Server) appxForget(w http.ResponseWriter, r *http.Request) (any, error) {
	x, err := s.appxOwnInstall(r)
	if err != nil {
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM appx_installs WHERE id=?`, x.ID); err != nil {
		return nil, err
	}
	s.audit(r, "appx.forget", x.App+":"+x.Path, "", true)
	return map[string]any{"deleted": true}, nil
}

// ---- WordPress ----

func (s *Server) appxWPCall(r *http.Request, action string) (any, error) {
	x, err := s.appxOwnInstall(r)
	if err != nil {
		return nil, err
	}
	if x.App != "wordpress" {
		return nil, badMsg("appx_not_wordpress", "not a WordPress installation")
	}
	var out rpc.AppxWPResult
	if err := s.agentCall(r, rpc.MAppxWP, rpc.AppxWPParams{User: userOf(r).Username, Path: x.Path, Action: action}, &out); err != nil {
		if action != "info" {
			s.audit(r, "appx.wp."+action, x.Path, nsAgentCode(err), false)
		}
		return nil, err
	}
	if action != "info" {
		s.audit(r, "appx.wp."+action, x.Path, out.Version, true)
		if out.Version != "" {
			_, _ = s.Store.DB.ExecContext(r.Context(), `UPDATE appx_installs SET version=? WHERE id=?`, out.Version, x.ID)
		}
	}
	return map[string]any{"install": x, "version": out.Version, "maintenance": out.Maintenance, "wpcli": out.WPCLI, "output": out.Output}, nil
}

func (s *Server) appxWPInfo(w http.ResponseWriter, r *http.Request) (any, error) {
	return s.appxWPCall(r, "info")
}

func (s *Server) appxWPMaint(w http.ResponseWriter, r *http.Request) (any, error) {
	var in AppxMaintReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if in.On {
		return s.appxWPCall(r, "maintenance_on")
	}
	return s.appxWPCall(r, "maintenance_off")
}

func (s *Server) appxWPUpdate(w http.ResponseWriter, r *http.Request) (any, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 12*time.Minute)
	defer cancel()
	return s.appxWPCall(r.WithContext(ctx), "core_update")
}

// ---- admin ----

func (s *Server) appxAdminGet(w http.ResponseWriter, r *http.Request) (any, error) {
	lo, hi := s.appxRange(r.Context())
	var rt rpc.AppxRuntimesResult
	if err := s.agentCall(r, rpc.MAppxRuntimes, struct{}{}, &rt); err != nil {
		return nil, err
	}
	if rt.Runtimes == nil {
		rt.Runtimes = []rpc.AppxRuntime{}
	}
	var used int
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM appx_apps`).Scan(&used)
	return map[string]any{"port_lo": lo, "port_hi": hi, "ports_used": used, "runtimes": rt.Runtimes, "systemd": rt.Systemd, "wpcli": rt.WPCLI, "php_cli": rt.PHPCLI}, nil
}

func (s *Server) appxAdminPut(w http.ResponseWriter, r *http.Request) (any, error) {
	if u := userOf(r); u == nil || u.Role != "admin" {
		return nil, &apiError{Status: 403, Code: "forbidden"}
	}
	var in AppxSettingsReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if _, err := appx.AllocPort(nil, in.PortLo, in.PortHi); err != nil || in.PortHi-in.PortLo < 9 {
		return nil, badMsg("appx_port_range", "port range must be 1024-65535 with at least 10 ports")
	}
	var outside int
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM appx_apps WHERE port<? OR port>?`, in.PortLo, in.PortHi).Scan(&outside)
	if outside > 0 {
		return nil, badMsg("appx_port_range", "existing applications use ports outside this range")
	}
	tx, err := s.Store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for k, v := range map[string]int{"port_lo": in.PortLo, "port_hi": in.PortHi} {
		if _, err := tx.ExecContext(r.Context(), `INSERT INTO appx_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, k, strconv.Itoa(v)); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		return nil, err
	}
	s.audit(r, "appx.settings", "ports", strconv.Itoa(in.PortLo)+"-"+strconv.Itoa(in.PortHi), true)
	return s.appxAdminGet(w, r)
}

func (s *Server) appxAdminWPCLI(w http.ResponseWriter, r *http.Request) (any, error) {
	if u := userOf(r); u == nil || u.Role != "admin" {
		return nil, &apiError{Status: 403, Code: "forbidden"}
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Minute)
	defer cancel()
	var out rpc.AppxWPResult
	if err := s.agentCall(r.WithContext(ctx), rpc.MAppxWPCLIInstall, struct{}{}, &out); err != nil {
		s.audit(r, "appx.wpcli.install", "wp-cli", nsAgentCode(err), false)
		return nil, err
	}
	s.audit(r, "appx.wpcli.install", "wp-cli", "", true)
	return out, nil
}

var _ = store.Domain{}
