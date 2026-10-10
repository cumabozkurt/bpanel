// SPDX-License-Identifier: Apache-2.0

package api

// v0.4 devx: Git Version Control, browser terminal, Track DNS (resolver
// lookups + traceroute) and Dynamic DNS. All free/open-source: git,
// traceroute/tracepath (separate GPL processes run by the agent),
// golang.org/x/net/websocket (BSD-3), miekg/dns for CAA (BSD-3).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
	"golang.org/x/net/websocket"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/auth"
	"github.com/cumabozkurt/bpanel/internal/devx"
	"github.com/cumabozkurt/bpanel/internal/store"
)

const (
	termIdleTimeout = 15 * time.Minute
	termMaxMsg      = 64 << 10
	maxGitRepos     = 50
)

// rate limiters (keys are prefixed with the server pointer so test servers
// do not share buckets)
var devxLim = struct{ lookup, trace, git, ddnsIP, ddnsTok *auth.Limiter }{
	lookup:  auth.NewLimiter(30, 10),
	trace:   auth.NewLimiter(3, 2),
	git:     auth.NewLimiter(30, 20),
	ddnsIP:  auth.NewLimiter(30, 10),
	ddnsTok: auth.NewLimiter(10, 5),
}

func (s *Server) devxAllow(l *auth.Limiter, key string) error {
	if !l.Allow(fmt.Sprintf("%p|%s", s, key)) {
		return &apiError{Status: 429, Code: "rate_limited"}
	}
	return nil
}

func (s *Server) mountDevx(r chi.Router) {
	const tg = "devx"
	s.op(r, "GET", "/user/git", tg, "List own Git repositories", nil, s.h(s.gitList))
	s.op(r, "POST", "/user/git", tg, "Create a repository (empty, or clone an https/ssh remote; private/loopback targets refused)", GitCreateReq{}, s.h(s.gitCreate))
	s.op(r, "GET", "/user/git/{id}", tg, "Repository details: branches and last commit", nil, s.h(s.gitGet))
	s.op(r, "PUT", "/user/git/{id}", tg, "Change the deploy path (a docroot under the home)", GitUpdateReq{}, s.h(s.gitUpdate))
	s.op(r, "POST", "/user/git/{id}/deploy", tg, "git pull --ff-only and/or export HEAD into the deploy path", GitDeployReq{}, s.h(s.gitDeployH))
	s.op(r, "DELETE", "/user/git/{id}", tg, "Remove a repository (?files=1 also deletes the directory)", nil, s.h(s.gitDelete))
	s.op(r, "GET", "/user/dns-lookup", tg, "Track DNS: resolver lookup (?host=&type=A|AAAA|MX|TXT|NS|CNAME|CAA)", nil, s.h(s.dnsLookup))
	s.op(r, "POST", "/user/traceroute", tg, "Track DNS: traceroute to a public host", TraceReq{}, s.h(s.traceRouteH))
	s.op(r, "GET", "/user/terminal", tg, "Terminal availability (shell access, re-authentication, idle timeout)", nil, s.h(s.terminalStatus))
	s.op(r, "GET", "/user/terminal/ws", tg, "Terminal WebSocket (recent re-authentication and shell access required)", nil, s.terminalWS)
	s.op(r, "GET", "/user/ddns", tg, "Dynamic DNS hosts (subdomains) and their state", nil, s.h(s.ddnsList))
	s.op(r, "POST", "/user/ddns", tg, "Enable DDNS on a subdomain or rotate its token (token shown once)", DDNSReq{}, s.h(s.ddnsCreate))
	s.op(r, "DELETE", "/user/ddns/{id}", tg, "Disable DDNS for a subdomain (token revoked)", nil, s.h(s.ddnsDelete))
}

// mountDevxPublic: the token-authenticated DDNS update endpoint (no session).
func (s *Server) mountDevxPublic(r chi.Router) {
	r.Get("/ddns/update", s.ddnsUpdate)
	r.Post("/ddns/update", s.ddnsUpdate)
}

func devxCode(err error) error {
	if c := devx.Code(err); c != "" {
		return unprocessable(c)
	}
	return err
}

func (s *Server) devxResolve(ctx context.Context, host string) ([]net.IP, error) {
	if s.sec != nil && s.sec.resolver != nil {
		return s.sec.resolver(ctx, host)
	}
	return devx.DefaultResolver(ctx, host)
}

// checkCloneURL validates a git remote and applies the webhook SSRF guard
// (blockedIP; the super-admin's webhook_allow_private setting applies too).
func (s *Server) checkCloneURL(ctx context.Context, raw string) (devx.CloneURL, error) {
	u, err := devx.ParseCloneURL(raw)
	if err != nil {
		return u, devxCode(err)
	}
	if s.allowPrivateHooks() {
		return u, nil
	}
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := devx.CheckHost(c, u.Host, s.devxResolve, blockedIP); err != nil {
		return u, devxCode(err)
	}
	return u, nil
}

// ---- git -----------------------------------------------------------------------------

type GitRepo struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Path       string `json:"path"`
	CloneURL   string `json:"clone_url"`
	DeployPath string `json:"deploy_path"`
	LastDeploy int64  `json:"last_deploy"`
	CreatedAt  int64  `json:"created_at"`
}

type GitCreateReq struct {
	Name       string `json:"name"`
	Path       string `json:"path,omitempty"` // default repositories/<name>
	CloneURL   string `json:"clone_url,omitempty"`
	Branch     string `json:"branch,omitempty"`
	DeployPath string `json:"deploy_path,omitempty"`
}

type GitUpdateReq struct {
	DeployPath string `json:"deploy_path"`
}

type GitDeployReq struct {
	Pull   bool `json:"pull"`
	Deploy bool `json:"deploy"`
}

func validRepoName(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for i, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || (i > 0 && (c == '-' || c == '_' || c == '.'))) {
			return false
		}
	}
	return !strings.HasSuffix(n, ".")
}

// checkDeployPath: "" (none), public_html[/...], or the docroot (or a
// subdirectory of it) of one of the caller's domains.
func (s *Server) checkDeployPath(ctx context.Context, u *store.User, p string) (string, error) {
	if p == "" {
		return "", nil
	}
	c, err := devx.CleanRel(p)
	if err != nil {
		return "", badField("git_deploy_path_invalid", "deploy_path")
	}
	roots := []string{"public_html"}
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT docroot FROM domains WHERE user_id=?`, u.ID)
	if err == nil {
		for rows.Next() {
			var d string
			if rows.Scan(&d) == nil && d != "" {
				roots = append(roots, strings.Trim(d, "/"))
			}
		}
		rows.Close()
	}
	for _, r := range roots {
		if c == r || strings.HasPrefix(c, r+"/") {
			return c, nil
		}
	}
	return "", badField("git_deploy_path_invalid", "deploy_path")
}

func (s *Server) gitRepoOf(r *http.Request) (GitRepo, error) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		return GitRepo{}, notFound()
	}
	var g GitRepo
	err = s.Store.DB.QueryRowContext(r.Context(), `SELECT id,name,path,clone_url,deploy_path,last_deploy,created_at FROM git_repos WHERE id=? AND user_id=?`,
		id, userOf(r).ID).Scan(&g.ID, &g.Name, &g.Path, &g.CloneURL, &g.DeployPath, &g.LastDeploy, &g.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return g, notFound() // other accounts' repositories do not exist for the caller
	}
	return g, err
}

func (s *Server) gitList(w http.ResponseWriter, r *http.Request) (any, error) {
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT id,name,path,clone_url,deploy_path,last_deploy,created_at FROM git_repos WHERE user_id=? ORDER BY name`, userOf(r).ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GitRepo{}
	for rows.Next() {
		var g GitRepo
		if err := rows.Scan(&g.ID, &g.Name, &g.Path, &g.CloneURL, &g.DeployPath, &g.LastDeploy, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return map[string]any{"repos": out, "git_installed": true}, rows.Err()
}

func (s *Server) gitCreate(w http.ResponseWriter, r *http.Request) (any, error) {
	var in GitCreateReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	if !validRepoName(in.Name) {
		return nil, badField("git_name_invalid", "name")
	}
	if in.Path == "" {
		in.Path = "repositories/" + in.Name
	}
	p, err := devx.CleanRel(in.Path)
	if err != nil {
		return nil, badField("git_path_invalid", "path")
	}
	if !devx.ValidBranch(in.Branch) {
		return nil, badField("git_branch_invalid", "branch")
	}
	dp, err := s.checkDeployPath(r.Context(), u, in.DeployPath)
	if err != nil {
		return nil, err
	}
	if dp != "" && (dp == p || strings.HasPrefix(dp+"/", p+"/") || strings.HasPrefix(p+"/", dp+"/")) {
		return nil, badField("git_deploy_path_invalid", "deploy_path")
	}
	var n int
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM git_repos WHERE user_id=?`, u.ID).Scan(&n)
	if n >= maxGitRepos {
		return nil, unprocessable("git_limit")
	}
	var exists int
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM git_repos WHERE user_id=? AND path=?`, u.ID, p).Scan(&exists)
	if exists > 0 {
		return nil, &apiError{Status: 409, Code: "git_path_exists", Field: "path"}
	}
	if err := s.devxAllow(devxLim.git, u.Username); err != nil {
		return nil, err
	}
	var info rpc.GitInfo
	clone := ""
	if in.CloneURL != "" {
		cu, err := s.checkCloneURL(r.Context(), in.CloneURL)
		if err != nil {
			return nil, err
		}
		clone = cu.Normalized
		err = s.agentCall(r, rpc.MGitClone, rpc.GitClone{User: u.Username, Path: p, URL: clone, Branch: in.Branch, AllowPrivate: s.allowPrivateHooks()}, &info)
		if err != nil {
			s.audit(r, "git.clone", p, cu.Host, false)
			return nil, err
		}
		s.audit(r, "git.clone", p, cu.Host, true)
	} else {
		if err := s.agentCall(r, rpc.MGitInit, rpc.GitRepoRef{User: u.Username, Path: p}, &info); err != nil {
			s.audit(r, "git.init", p, "", false)
			return nil, err
		}
		s.audit(r, "git.init", p, "", true)
	}
	res, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO git_repos(user_id,name,path,clone_url,deploy_path,created_at) VALUES(?,?,?,?,?,?)`,
		u.ID, in.Name, p, clone, dp, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return map[string]any{"id": id, "path": p, "info": info}, nil
}

func (s *Server) gitGet(w http.ResponseWriter, r *http.Request) (any, error) {
	g, err := s.gitRepoOf(r)
	if err != nil {
		return nil, err
	}
	var info rpc.GitInfo
	if err := s.agentCall(r, rpc.MGitInfo, rpc.GitRepoRef{User: userOf(r).Username, Path: g.Path}, &info); err != nil {
		return nil, err
	}
	return map[string]any{"repo": g, "info": info}, nil
}

func (s *Server) gitUpdate(w http.ResponseWriter, r *http.Request) (any, error) {
	g, err := s.gitRepoOf(r)
	if err != nil {
		return nil, err
	}
	var in GitUpdateReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	dp, err := s.checkDeployPath(r.Context(), userOf(r), in.DeployPath)
	if err != nil {
		return nil, err
	}
	if dp != "" && (dp == g.Path || strings.HasPrefix(dp+"/", g.Path+"/") || strings.HasPrefix(g.Path+"/", dp+"/")) {
		return nil, badField("git_deploy_path_invalid", "deploy_path")
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `UPDATE git_repos SET deploy_path=? WHERE id=? AND user_id=?`, dp, g.ID, userOf(r).ID); err != nil {
		return nil, err
	}
	s.audit(r, "git.update", g.Path, dp, true)
	return nil, nil
}

func (s *Server) gitDeployH(w http.ResponseWriter, r *http.Request) (any, error) {
	g, err := s.gitRepoOf(r)
	if err != nil {
		return nil, err
	}
	var in GitDeployReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	if err := s.devxAllow(devxLim.git, u.Username); err != nil {
		return nil, err
	}
	if in.Deploy && g.DeployPath == "" {
		return nil, unprocessable("git_deploy_path_missing")
	}
	if !in.Pull && !in.Deploy {
		return nil, bad("bad_params")
	}
	p := rpc.GitDeploy{User: u.Username, Path: g.Path, Pull: in.Pull, AllowPrivate: s.allowPrivateHooks()}
	if in.Deploy {
		p.DeployPath = g.DeployPath
	}
	var res rpc.GitDeployResult
	err = s.agentCall(r, rpc.MGitDeploy, p, &res)
	s.audit(r, "git.deploy", g.Path, fmt.Sprintf("pull=%v deploy=%s", in.Pull, p.DeployPath), err == nil)
	if err != nil {
		return nil, err
	}
	if res.Deployed {
		_, _ = s.Store.DB.ExecContext(r.Context(), `UPDATE git_repos SET last_deploy=? WHERE id=?`, time.Now().Unix(), g.ID)
	}
	return res, nil
}

func (s *Server) gitDelete(w http.ResponseWriter, r *http.Request) (any, error) {
	g, err := s.gitRepoOf(r)
	if err != nil {
		return nil, err
	}
	if r.URL.Query().Get("files") == "1" {
		if err := s.agentCall(r, rpc.MGitRemove, rpc.GitRepoRef{User: userOf(r).Username, Path: g.Path}, nil); err != nil && agentCode(err) != "git_not_a_repo" {
			return nil, err
		}
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM git_repos WHERE id=? AND user_id=?`, g.ID, userOf(r).ID); err != nil {
		return nil, err
	}
	s.audit(r, "git.delete", g.Path, r.URL.Query().Get("files"), true)
	return nil, nil
}

// ---- Track DNS -------------------------------------------------------------------------

var lookupTypes = map[string]bool{"A": true, "AAAA": true, "MX": true, "TXT": true, "NS": true, "CNAME": true, "CAA": true}

// devxCAA is the CAA query (net.Resolver has no CAA support); overridable in tests.
var devxCAA = func(ctx context.Context, host string) ([]string, error) {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(cfg.Servers) == 0 {
		return nil, errors.New("no resolver")
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeCAA)
	m.RecursionDesired = true
	c := &dns.Client{Timeout: 4 * time.Second}
	in, _, err := c.ExchangeContext(ctx, m, net.JoinHostPort(cfg.Servers[0], cfg.Port))
	if err != nil {
		return nil, err
	}
	if in.Rcode == dns.RcodeNameError {
		return nil, &net.DNSError{IsNotFound: true, Err: "no such host", Name: host}
	}
	out := []string{}
	for _, rr := range in.Answer {
		if c, ok := rr.(*dns.CAA); ok {
			out = append(out, fmt.Sprintf("%d %s %q", c.Flag, c.Tag, c.Value))
		}
	}
	return out, nil
}

var devxNetResolver = &net.Resolver{PreferGo: true}

func (s *Server) dnsLookup(w http.ResponseWriter, r *http.Request) (any, error) {
	q := r.URL.Query()
	host := strings.TrimSuffix(strings.TrimSpace(q.Get("host")), ".")
	typ := strings.ToUpper(q.Get("type"))
	if typ == "" {
		typ = "A"
	}
	if !devx.ValidHost(host) {
		return nil, badField("invalid_host", "host")
	}
	if !lookupTypes[typ] {
		return nil, badField("invalid_record_type", "type")
	}
	if err := s.devxAllow(devxLim.lookup, userOf(r).Username); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	res := devxNetResolver
	var recs []string
	var err error
	switch typ {
	case "A", "AAAA":
		var as []net.IPAddr
		as, err = res.LookupIPAddr(ctx, host)
		for _, a := range as {
			if (a.IP.To4() != nil) == (typ == "A") {
				recs = append(recs, a.IP.String())
			}
		}
	case "MX":
		var mx []*net.MX
		mx, err = res.LookupMX(ctx, host)
		for _, m := range mx {
			recs = append(recs, fmt.Sprintf("%d %s", m.Pref, m.Host))
		}
	case "TXT":
		recs, err = res.LookupTXT(ctx, host)
	case "NS":
		var ns []*net.NS
		ns, err = res.LookupNS(ctx, host)
		for _, n := range ns {
			recs = append(recs, n.Host)
		}
	case "CNAME":
		var c string
		c, err = res.LookupCNAME(ctx, host)
		if err == nil && strings.TrimSuffix(c, ".") != host {
			recs = append(recs, c)
		}
	case "CAA":
		recs, err = devxCAA(ctx, host)
	}
	status := "ok"
	if err != nil {
		var de *net.DNSError
		switch {
		case errors.As(err, &de) && de.IsNotFound:
			status = "nxdomain"
		case ctx.Err() != nil || (errors.As(err, &de) && de.IsTimeout):
			status = "timeout"
		default:
			status = "error"
		}
		recs = nil
	}
	if recs == nil {
		recs = []string{}
	}
	sort.Strings(recs)
	return map[string]any{"host": host, "type": typ, "status": status, "records": recs}, nil
}

type TraceReq struct {
	Host string `json:"host"`
}

func (s *Server) traceRouteH(w http.ResponseWriter, r *http.Request) (any, error) {
	var in TraceReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	host := strings.TrimSuffix(strings.TrimSpace(in.Host), ".")
	if !devx.ValidHost(host) {
		return nil, badField("invalid_host", "host")
	}
	// tenants may not map the panel's internal network
	c, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := devx.CheckHost(c, host, s.devxResolve, blockedIP); err != nil {
		return nil, devxCode(err)
	}
	if err := s.devxAllow(devxLim.trace, userOf(r).Username); err != nil {
		return nil, err
	}
	var out rpc.TraceRouteResult
	if err := s.agentCall(r, rpc.MTraceRoute, rpc.TraceRoute{Host: host}, &out); err != nil {
		return nil, err
	}
	s.audit(r, "net.traceroute", host, out.Status, true)
	return out, nil
}

// ---- terminal --------------------------------------------------------------------------

func (s *Server) shellAccess(ctx context.Context, u *store.User) bool {
	return s.overridesOf(ctx, s.Store.DB, u.ID).ShellAccess
}

func (s *Server) terminalStatus(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	return map[string]any{"shell_access": s.shellAccess(r.Context(), u), "recent_auth": s.recentlyAuthenticated(r, 0),
		"session": sessionOf(r) != nil, "idle_timeout_seconds": int(termIdleTimeout.Seconds())}, nil
}

type termMsg struct {
	T string `json:"t"` // i = input, r = resize, p = ping
	D string `json:"d,omitempty"`
	C int    `json:"c,omitempty"`
	R int    `json:"r,omitempty"`
}

func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return false
	}
	u, err := url.Parse(o)
	return err == nil && u.Host != "" && strings.EqualFold(u.Host, r.Host)
}

func (s *Server) terminalWS(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	switch {
	case sessionOf(r) == nil: // API tokens never get a shell
		writeJSON(w, 403, apiError{Code: "forbidden"})
		return
	case u.Status != "" && u.Status != "active":
		writeJSON(w, 403, apiError{Code: "account_suspended"})
		return
	case !s.shellAccess(r.Context(), u):
		writeJSON(w, 403, apiError{Code: "shell_disabled"})
		return
	case !s.recentlyAuthenticated(r, 0):
		writeJSON(w, 403, apiError{Code: "reauth_required"})
		return
	case !strings.EqualFold(r.Header.Get("Upgrade"), "websocket"):
		writeJSON(w, 400, apiError{Code: "websocket_required"})
		return
	case !sameOrigin(r): // cross-site WebSocket hijacking
		writeJSON(w, 403, apiError{Code: "bad_origin"})
		return
	}
	cols, _ := strconv.Atoi(r.URL.Query().Get("cols"))
	rows, _ := strconv.Atoi(r.URL.Query().Get("rows"))
	var open rpc.TermOpenResult
	if err := s.Agent.Call(r.Context(), rpc.MTermOpen, rpc.TermOpen{User: u.Username, Cols: cols, Rows: rows}, &open); err != nil {
		s.audit(r, "terminal.open", u.Username, agentCode(err), false)
		s.fail(w, r, err)
		return
	}
	s.audit(r, "terminal.open", u.Username, "", true)
	started := time.Now()
	user := u.Username
	srv := websocket.Server{Handshake: func(*websocket.Config, *http.Request) error { return nil }, Handler: func(ws *websocket.Conn) {
		ws.MaxPayloadBytes = termMaxMsg
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { // agent -> browser
			defer ws.Close()
			for ctx.Err() == nil {
				var rd rpc.TermReadResult
				if err := s.Agent.Call(ctx, rpc.MTermRead, rpc.TermIO{User: user, ID: open.ID, WaitMS: 1000}, &rd); err != nil {
					return
				}
				if len(rd.Data) > 0 {
					if websocket.Message.Send(ws, rd.Data) != nil {
						return
					}
				}
				if rd.Exited {
					return
				}
				if len(rd.Data) == 0 { // the agent long-polls; never spin on an instant empty answer
					select {
					case <-ctx.Done():
					case <-time.After(20 * time.Millisecond):
					}
				}
			}
		}()
		for { // browser -> agent
			_ = ws.SetReadDeadline(time.Now().Add(termIdleTimeout))
			var raw string
			if err := websocket.Message.Receive(ws, &raw); err != nil {
				break
			}
			var m termMsg
			if json.Unmarshal([]byte(raw), &m) != nil {
				continue
			}
			switch m.T {
			case "i":
				if len(m.D) > 0 && s.Agent.Call(ctx, rpc.MTermWrite, rpc.TermIO{User: user, ID: open.ID, Data: []byte(m.D)}, nil) != nil {
					cancel()
				}
			case "r":
				_ = s.Agent.Call(ctx, rpc.MTermResize, rpc.TermIO{User: user, ID: open.ID, Cols: m.C, Rows: m.R}, nil)
			}
			if ctx.Err() != nil {
				break
			}
		}
		cancel()
		_ = s.Agent.Call(context.Background(), rpc.MTermClose, rpc.TermIO{User: user, ID: open.ID}, nil)
		ws.Close()
		s.audit(r, "terminal.close", user, fmt.Sprintf("%ds", int(time.Since(started).Seconds())), true)
	}}
	srv.ServeHTTP(w, r)
}

// ---- Dynamic DNS ---------------------------------------------------------------------

type DDNSReq struct {
	DomainID int64 `json:"domain_id"`
}

type DDNSHost struct {
	DomainID   int64  `json:"domain_id"`
	Domain     string `json:"domain"`
	Enabled    bool   `json:"enabled"`
	ID         int64  `json:"id,omitempty"`
	LastIPv4   string `json:"last_ipv4"`
	LastIPv6   string `json:"last_ipv6"`
	LastUpdate int64  `json:"last_update"`
}

func (s *Server) ddnsList(w http.ResponseWriter, r *http.Request) (any, error) {
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT d.id, d.name, IFNULL(h.id,0), IFNULL(h.last_ipv4,''), IFNULL(h.last_ipv6,''), IFNULL(h.last_update,0)
		FROM domains d LEFT JOIN ddns_hosts h ON h.domain_id=d.id WHERE d.user_id=? AND d.kind='sub' ORDER BY d.name`, userOf(r).ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DDNSHost{}
	for rows.Next() {
		var h DDNSHost
		if err := rows.Scan(&h.DomainID, &h.Domain, &h.ID, &h.LastIPv4, &h.LastIPv6, &h.LastUpdate); err != nil {
			return nil, err
		}
		h.Enabled = h.ID > 0
		out = append(out, h)
	}
	return map[string]any{"hosts": out, "update_path": "/ddns/update"}, rows.Err()
}

func (s *Server) ddnsCreate(w http.ResponseWriter, r *http.Request) (any, error) {
	var in DDNSReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	var name, kind string
	err := s.Store.DB.QueryRowContext(r.Context(), `SELECT name, kind FROM domains WHERE id=? AND user_id=?`, in.DomainID, u.ID).Scan(&name, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound()
	} else if err != nil {
		return nil, err
	}
	if kind != "sub" {
		return nil, unprocessable("ddns_not_subdomain")
	}
	tok, hash, err := devx.NewToken()
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if _, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO ddns_hosts(user_id,domain_id,token_hash,created_at) VALUES(?,?,?,?)
		ON CONFLICT(domain_id) DO UPDATE SET token_hash=excluded.token_hash`, u.ID, in.DomainID, hash, now); err != nil {
		return nil, err
	}
	s.audit(r, "ddns.token", name, "", true)
	return map[string]any{"domain": name, "token": tok, "update_path": "/ddns/update?token=" + tok}, nil
}

func (s *Server) ddnsDelete(w http.ResponseWriter, r *http.Request) (any, error) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	res, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM ddns_hosts WHERE id=? AND user_id=?`, id, userOf(r).ID)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, notFound()
	}
	s.audit(r, "ddns.delete", strconv.FormatInt(id, 10), "", true)
	return nil, nil
}

func ddnsText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body + "\n"))
}

// ddnsUpdate: GET/POST /ddns/update?token=...[&ip=...] (dyndns-style plain
// text answers: good <ip> | nochg <ip> | badauth | abuse | badip | 911).
// The token may also come as the Authorization: Bearer header or the form.
func (s *Server) ddnsUpdate(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if err := s.devxAllow(devxLim.ddnsIP, "ip|"+ip); err != nil {
		ddnsText(w, 429, "abuse")
		return
	}
	tok := r.URL.Query().Get("token")
	if h := r.Header.Get("Authorization"); tok == "" && strings.HasPrefix(h, "Bearer ") {
		tok = strings.TrimPrefix(h, "Bearer ")
	}
	if tok == "" && r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		tok = r.PostFormValue("token")
	}
	if !devx.WellFormedToken(tok) {
		ddnsText(w, 401, "badauth")
		return
	}
	hash := devx.HashToken(tok)
	if err := s.devxAllow(devxLim.ddnsTok, "tok|"+hash); err != nil {
		ddnsText(w, 429, "abuse")
		return
	}
	ctx := r.Context()
	var hid, uid int64
	var name, owner, status, last4, last6 string
	var parentID sql.NullInt64
	err := s.Store.DB.QueryRowContext(ctx, `SELECT h.id, h.user_id, d.name, d.parent_id, u.username, u.status, h.last_ipv4, h.last_ipv6
		FROM ddns_hosts h JOIN domains d ON d.id=h.domain_id JOIN users u ON u.id=h.user_id WHERE h.token_hash=? AND d.user_id=h.user_id AND d.kind='sub'`, hash).
		Scan(&hid, &uid, &name, &parentID, &owner, &status, &last4, &last6)
	if err != nil {
		ddnsText(w, 401, "badauth")
		return
	}
	if status != "" && status != "active" {
		ddnsText(w, 403, "badauth")
		return
	}
	want := r.URL.Query().Get("ip")
	if want == "" {
		want = r.URL.Query().Get("myip")
	}
	if want == "" {
		want = ip
	}
	a, perr := netip.ParseAddr(want)
	if perr != nil || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.Zone() != "" {
		ddnsText(w, 400, "badip")
		return
	}
	a = a.Unmap()
	typ, cur := "A", last4
	if a.Is6() {
		typ, cur = "AAAA", last6
	}
	if cur == a.String() {
		ddnsText(w, 200, "nochg "+a.String())
		return
	}
	var zone string
	if !parentID.Valid || s.Store.DB.QueryRowContext(ctx, `SELECT name FROM domains WHERE id=? AND user_id=?`, parentID.Int64, uid).Scan(&zone) != nil {
		ddnsText(w, 500, "911")
		return
	}
	if err := s.Agent.Call(ctx, rpc.MDNSRRSetReplace, rpc.RRSet{Owner: owner, Zone: zone, Name: name, Type: typ, TTL: 300, Records: []string{a.String()}}, nil); err != nil {
		s.auditSystem("ddns.update", name, typ+" "+a.String()+" "+agentCode(err), false)
		ddnsText(w, 502, "911")
		return
	}
	col := "last_ipv4"
	if typ == "AAAA" {
		col = "last_ipv6"
	}
	_, _ = s.Store.DB.ExecContext(ctx, `UPDATE ddns_hosts SET `+col+`=?, last_update=? WHERE id=?`, a.String(), time.Now().Unix(), hid)
	s.auditSystem("ddns.update", name, typ+" "+a.String(), true)
	ddnsText(w, 200, "good "+a.String())
}
