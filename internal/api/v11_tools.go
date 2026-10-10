// SPDX-License-Identifier: Apache-2.0

package api

// v1.1 feature parity, user realm (part 2): Site Publisher, Images,
// PostgreSQL web UI (phpPgAdmin equivalent) and the optional Cloudflare
// integration. Site Publisher and Images write through the agent's file
// operations (os.Root inside the account home); the PostgreSQL UI connects
// with the database role's own password, so it can never do more than the
// role itself; Cloudflare uses the tenant's own API token (secret store).

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/cloudflare"
	"github.com/cumabozkurt/bpanel/internal/imagex"
	"github.com/cumabozkurt/bpanel/internal/secrets"
	"github.com/cumabozkurt/bpanel/internal/sitepub"
)

type SitePublishReq struct {
	DomainID  int64          `json:"domain_id"`
	Template  string         `json:"template"`
	Lang      string         `json:"lang"`
	Fields    sitepub.Fields `json:"fields"`
	Overwrite bool           `json:"overwrite"`
}

type ImageReq struct {
	Path string `json:"path"`
	imagex.Params
}

type PGQueryReq struct {
	DatabaseID int64  `json:"database_id"`
	Password   string `json:"password"`
	SQL        string `json:"sql"`
}

type CloudflareTokenReq struct {
	Token string `json:"token"`
}

type CloudflareSyncReq struct {
	DomainID int64 `json:"domain_id"`
	DryRun   bool  `json:"dry_run"`
}

func (s *Server) mountV11Tools(r chi.Router) {
	s.op(r, "GET", "/user/site-publisher", "web", "Site Publisher templates and the own domains", nil, s.h(s.sitePubInfo))
	s.op(r, "POST", "/user/site-publisher", "web", "Publish a template as index.html of an own domain's document root", SitePublishReq{}, s.h(s.sitePublish))
	s.op(r, "POST", "/user/images", "files", "Images: thumbnail, scale or convert an image of the own home (result written next to it)", ImageReq{}, s.h(s.imageProcess))
	s.op(r, "GET", "/user/postgresql/browser", "databases", "PostgreSQL web UI: the own databases and whether psql is available", nil, s.h(s.pgBrowserInfo))
	s.op(r, "POST", "/user/postgresql/browser/tables", "databases", "PostgreSQL web UI: list tables of an own database (role password required)", PGQueryReq{}, s.h(s.pgBrowserTables))
	s.op(r, "POST", "/user/postgresql/browser/query", "databases", "PostgreSQL web UI: run SQL as the database role (statement timeout 15 s, 1000 rows)", PGQueryReq{}, s.h(s.pgBrowserQuery))
	s.op(r, "GET", "/user/cloudflare", "dns", "Cloudflare (optional): link status and, per own domain, whether it is on Cloudflare (NS detection)", nil, s.h(s.cfInfo))
	s.op(r, "PUT", "/user/cloudflare", "dns", "Link a Cloudflare API token (verified, stored in the secret store)", CloudflareTokenReq{}, s.h(s.cfLink))
	s.op(r, "DELETE", "/user/cloudflare", "dns", "Unlink Cloudflare (forget the token)", nil, s.h(s.cfUnlink))
	s.op(r, "POST", "/user/cloudflare/sync", "dns", "Create on Cloudflare the A/AAAA/CNAME/MX/TXT records of the panel zone it lacks (dry_run lists them)", CloudflareSyncReq{}, s.h(s.cfSync))
}

// ---- Site Publisher ----------------------------------------------------------------------

func (s *Server) sitePubInfo(w http.ResponseWriter, r *http.Request) (any, error) {
	doms, err := s.domainsOf(r.Context(), userOf(r).ID)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, d := range doms {
		if d.Kind != "alias" && d.Redirect == "" {
			out = append(out, map[string]any{"id": d.ID, "name": d.Name, "docroot": d.DocRoot})
		}
	}
	return map[string]any{"templates": sitepub.Templates, "domains": out}, nil
}

func sitepubErr(err error) error {
	var e *sitepub.Error
	if errors.As(err, &e) {
		return badField(e.Code, e.Field)
	}
	return err
}

func (s *Server) sitePublish(w http.ResponseWriter, r *http.Request) (any, error) {
	var in SitePublishReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	d, err := s.ownDomain(r, in.DomainID)
	if err != nil {
		return nil, err
	}
	if d.Kind == "alias" || d.DocRoot == "" {
		return nil, badMsg("site_no_docroot", "this domain has no own document root")
	}
	html, err := sitepub.Render(in.Template, in.Lang, in.Fields)
	if err != nil {
		return nil, sitepubErr(err)
	}
	u := userOf(r).Username
	target := path.Join(d.DocRoot, "index.html")
	if !in.Overwrite {
		var st rpc.FileResult
		if err := s.agentCall(r, rpc.MFiles, rpc.FileOp{User: u, Op: "list", Path: d.DocRoot}, &st); err == nil {
			for _, e := range st.Entries {
				if e.Name == "index.html" || e.Name == "index.php" {
					return nil, conflict("site_exists")
				}
			}
		}
	}
	if err := s.agentCall(r, rpc.MFiles, rpc.FileOp{User: u, Op: "write", Path: target, Content: string(html)}, nil); err != nil {
		s.audit(r, "site_publisher.publish", d.Name, nsAgentCode(err), false)
		return nil, err
	}
	s.audit(r, "site_publisher.publish", d.Name, in.Template, true)
	return map[string]any{"path": target, "url": "http://" + d.Name + "/", "bytes": len(html)}, nil
}

// ---- Images ------------------------------------------------------------------------------

func imageErr(err error) error {
	var e *imagex.Error
	if errors.As(err, &e) {
		return bad(e.Code)
	}
	return err
}

func (s *Server) imageProcess(w http.ResponseWriter, r *http.Request) (any, error) {
	var in ImageReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	p := strings.TrimPrefix(path.Clean("/"+in.Path), "/")
	if p == "" || p == "." || strings.HasPrefix(p, "..") {
		return nil, badField("invalid_path", "path")
	}
	u := userOf(r).Username
	var src rpc.FileResult
	if err := s.agentCall(r, rpc.MFiles, rpc.FileOp{User: u, Op: "download", Path: p}, &src); err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(src.Content)
	if err != nil {
		return nil, bad("image_unsupported")
	}
	out, format, info, err := imagex.Process(raw, in.Params)
	if err != nil {
		return nil, imageErr(err)
	}
	dir, base := path.Split(p)
	stem := strings.TrimSuffix(base, path.Ext(base))
	var dst string
	switch in.Op {
	case "thumbnail":
		dst = path.Join(dir, "thumbnails", "tn_"+stem+"."+imagex.Ext(format))
		_ = s.agentCall(r, rpc.MFiles, rpc.FileOp{User: u, Op: "mkdir", Path: path.Join(dir, "thumbnails")}, nil)
	case "scale":
		dst = path.Join(dir, stem+"-"+strconv.Itoa(info.Width)+"x"+strconv.Itoa(info.Height)+"."+imagex.Ext(format))
	default:
		dst = path.Join(dir, stem+"."+imagex.Ext(format))
		if dst == p {
			return nil, bad("image_same_format")
		}
	}
	if err := s.agentCall(r, rpc.MFiles, rpc.FileOp{User: u, Op: "upload", Path: dst, Content: base64.StdEncoding.EncodeToString(out)}, nil); err != nil {
		return nil, err
	}
	s.audit(r, "images.process", p, in.Op+" -> "+dst, true)
	return map[string]any{"path": dst, "format": format, "width": info.Width, "height": info.Height, "bytes": len(out)}, nil
}

// ---- PostgreSQL web UI ---------------------------------------------------------------------

// psqlBin and psqlHost are variables for tests.
var (
	psqlBin  = "psql"
	psqlHost = "127.0.0.1"
)

func (s *Server) pgBrowserInfo(w http.ResponseWriter, r *http.Request) (any, error) {
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT id, name FROM pg_databases WHERE user_id=? ORDER BY name`, userOf(r).ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	dbs := []map[string]any{}
	for rows.Next() {
		var id int64
		var n string
		if rows.Scan(&id, &n) == nil {
			dbs = append(dbs, map[string]any{"id": id, "name": n, "role": n})
		}
	}
	_, lerr := exec.LookPath(psqlBin)
	st := "ok"
	reason := ""
	if lerr != nil {
		st, reason = "not_installed", "the psql client is not installed on this server"
	}
	return map[string]any{"status": st, "reason": reason, "databases": dbs}, nil
}

// PGResult is one psql --csv result.
type PGResult struct {
	Columns   []string   `json:"columns"`
	Rows      [][]string `json:"rows"`
	Truncated bool       `json:"truncated"`
	Command   string     `json:"command,omitempty"`
	Millis    int64      `json:"ms"`
}

func (s *Server) pgRun(ctx context.Context, uid int64, dbID int64, password, sql string) (PGResult, error) {
	var res PGResult
	var name string
	if err := s.Store.DB.QueryRowContext(ctx, `SELECT name FROM pg_databases WHERE id=? AND user_id=?`, dbID, uid).Scan(&name); err != nil {
		return res, notFound()
	}
	if password == "" || len(password) > 200 || strings.ContainsAny(password, "\x00\n") {
		return res, badField("pg_password_required", "password")
	}
	if strings.TrimSpace(sql) == "" || len(sql) > 64<<10 || strings.ContainsRune(sql, 0) {
		return res, badField("pg_bad_sql", "sql")
	}
	if strings.HasPrefix(strings.TrimSpace(sql), `\`) || strings.Contains(sql, "\n\\") {
		return res, badMsg("pg_bad_sql", "psql meta-commands are not allowed")
	}
	bin, err := exec.LookPath(psqlBin)
	if err != nil {
		return res, conflict("pg_not_installed")
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, "-X", "-q", "--csv", "-v", "ON_ERROR_STOP=1", "-h", psqlHost, "-U", name, "-d", name, "-f", "-")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "PGPASSWORD=" + password, "PGCONNECT_TIMEOUT=5",
		"PGOPTIONS=-c statement_timeout=15000", "PGAPPNAME=bpanel-pg-ui", "HOME=" + os.TempDir()}
	cmd.Stdin = strings.NewReader(sql)
	var out, errb bytes.Buffer
	cmd.Stdout = &limitedBuffer{b: &out, n: 4 << 20}
	cmd.Stderr = &limitedBuffer{b: &errb, n: 64 << 10}
	t0 := time.Now()
	err = cmd.Run()
	res.Millis = time.Since(t0).Milliseconds()
	if err != nil {
		msg := strings.TrimSpace(errb.String())
		if i := strings.Index(msg, "FATAL:"); i >= 0 && strings.Contains(msg, "password authentication failed") {
			return res, badMsg("pg_auth_failed", "password authentication failed for role "+name)
		}
		if msg == "" {
			msg = "psql failed"
		}
		return res, badMsg("pg_query_failed", lastLine(msg))
	}
	cr := csv.NewReader(&out)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	res.Columns, res.Rows = []string{}, [][]string{}
	for i := 0; ; i++ {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if i == 0 {
			res.Columns = rec
			continue
		}
		if len(res.Rows) >= 1000 {
			res.Truncated = true
			break
		}
		res.Rows = append(res.Rows, rec)
	}
	if len(res.Columns) == 0 {
		res.Command = "OK"
	}
	return res, nil
}

type limitedBuffer struct {
	b *bytes.Buffer
	n int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.n - l.b.Len(); room > 0 {
		if len(p) > room {
			l.b.Write(p[:room])
		} else {
			l.b.Write(p)
		}
	}
	return len(p), nil
}

func lastLine(s string) string {
	ls := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimPrefix(strings.TrimSpace(ls[len(ls)-1]), "psql:<stdin>:")
}

func (s *Server) pgBrowserTables(w http.ResponseWriter, r *http.Request) (any, error) {
	var in PGQueryReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	res, err := s.pgRun(r.Context(), userOf(r).ID, in.DatabaseID, in.Password,
		`SELECT table_schema AS schema, table_name AS name, table_type AS type FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema') ORDER BY 1,2;`)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *Server) pgBrowserQuery(w http.ResponseWriter, r *http.Request) (any, error) {
	var in PGQueryReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	res, err := s.pgRun(r.Context(), userOf(r).ID, in.DatabaseID, in.Password, in.SQL)
	ok := err == nil
	s.audit(r, "postgresql.query", strconv.FormatInt(in.DatabaseID, 10), strconv.Itoa(len(in.SQL))+" bytes", ok)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// ---- Cloudflare (optional) -------------------------------------------------------------------

var lookupNS = net.DefaultResolver.LookupNS

func cfSecret(uid int64) string { return "cloudflare:token:" + strconv.FormatInt(uid, 10) }

func cfErr(err error) error {
	var e *cloudflare.Error
	if errors.As(err, &e) {
		return badMsg(e.Code, e.Msg)
	}
	return err
}

func (s *Server) cfClient(ctx context.Context, uid int64) (*cloudflare.Client, error) {
	st, ok := s.secretsUsable()
	if !ok {
		return nil, conflict("secrets_unavailable")
	}
	b, err := st.Get(ctx, cfSecret(uid))
	if errors.Is(err, secrets.ErrNotFound) {
		return nil, conflict("cloudflare_not_linked")
	}
	if err != nil {
		return nil, err
	}
	return &cloudflare.Client{Base: s.Store.Get("cloudflare_api_base", cloudflare.DefaultBase), Token: string(b)}, nil
}

func (s *Server) cfInfo(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	doms, err := s.domainsOf(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	linked := false
	if st, ok := s.secretsUsable(); ok {
		_, err := st.Get(r.Context(), cfSecret(u.ID))
		linked = err == nil
	}
	var zones []cloudflare.Zone
	var cfErrMsg string
	if linked {
		if c, err := s.cfClient(r.Context(), u.ID); err == nil {
			if zones, err = c.Zones(r.Context(), ""); err != nil {
				cfErrMsg = err.Error()
			}
		}
	}
	byName := map[string]cloudflare.Zone{}
	for _, z := range zones {
		byName[strings.ToLower(z.Name)] = z
	}
	out := []map[string]any{}
	for _, d := range doms {
		if d.Kind == "sub" || d.Kind == "alias" {
			continue
		}
		cf, ns := cloudflare.Detect(r.Context(), d.Name, lookupNS)
		z, inAcct := byName[d.Name]
		out = append(out, map[string]any{"id": d.ID, "domain": d.Name, "on_cloudflare": cf, "nameservers": ns,
			"in_account": inAcct, "zone_status": z.Status, "plan": z.Plan.Name})
	}
	return map[string]any{"linked": linked, "error": cfErrMsg, "domains": out}, nil
}

func (s *Server) cfLink(w http.ResponseWriter, r *http.Request) (any, error) {
	var in CloudflareTokenReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	in.Token = strings.TrimSpace(in.Token)
	if len(in.Token) < 20 || len(in.Token) > 200 || strings.ContainsAny(in.Token, " \r\n\t") {
		return nil, badField("cloudflare_bad_token", "token")
	}
	c := &cloudflare.Client{Base: s.Store.Get("cloudflare_api_base", cloudflare.DefaultBase), Token: in.Token}
	if err := c.Verify(r.Context()); err != nil {
		s.audit(r, "cloudflare.link", "", "verify failed", false)
		return nil, cfErr(err)
	}
	st, ok := s.secretsUsable()
	if !ok {
		return nil, conflict("secrets_unavailable")
	}
	if err := st.Put(r.Context(), cfSecret(userOf(r).ID), []byte(in.Token)); err != nil {
		return nil, err
	}
	_, _ = s.Store.DB.ExecContext(r.Context(), `INSERT INTO cloudflare_links(user_id,account,updated_at) VALUES(?,?,?)
		ON CONFLICT(user_id) DO UPDATE SET updated_at=excluded.updated_at`, userOf(r).ID, "", s.Now().Unix())
	s.audit(r, "cloudflare.link", "", "", true)
	return s.cfInfo(w, r)
}

func (s *Server) cfUnlink(w http.ResponseWriter, r *http.Request) (any, error) {
	if st, ok := s.secretsUsable(); ok {
		_ = st.Delete(r.Context(), cfSecret(userOf(r).ID))
	}
	_, _ = s.Store.DB.ExecContext(r.Context(), `DELETE FROM cloudflare_links WHERE user_id=?`, userOf(r).ID)
	s.audit(r, "cloudflare.unlink", "", "", true)
	return s.cfInfo(w, r)
}

func (s *Server) cfSync(w http.ResponseWriter, r *http.Request) (any, error) {
	var in CloudflareSyncReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	d, err := s.ownDomain(r, in.DomainID)
	if err != nil {
		return nil, err
	}
	c, err := s.cfClient(r.Context(), userOf(r).ID)
	if err != nil {
		return nil, err
	}
	zs, err := c.Zones(r.Context(), d.Name)
	if err != nil {
		return nil, cfErr(err)
	}
	if len(zs) == 0 {
		return nil, badMsg("cloudflare_zone_missing", "add "+d.Name+" to your Cloudflare account first")
	}
	var z rpc.DNSZone
	if err := s.agentCall(r, rpc.MDNSZoneGet, rpc.ZoneRef{Owner: userOf(r).Username, Zone: d.Name}, &z); err != nil {
		return nil, err
	}
	want := []cloudflare.Record{}
	for _, rr := range z.Records {
		if rr.Disabled {
			continue
		}
		rec := cloudflare.Record{Type: rr.Type, Name: strings.TrimSuffix(rr.Name, "."), Content: strings.TrimSuffix(rr.Content, "."), TTL: 1}
		if rr.Type == "MX" {
			f := strings.Fields(rr.Content)
			if len(f) != 2 {
				continue
			}
			p, _ := strconv.Atoi(f[0])
			rec.Priority, rec.Content = &p, strings.TrimSuffix(f[1], ".")
		}
		if rr.Type == "TXT" {
			rec.Content = strings.Trim(rr.Content, `"`)
		}
		want = append(want, rec)
	}
	have, err := c.Records(r.Context(), zs[0].ID)
	if err != nil {
		return nil, cfErr(err)
	}
	miss := cloudflare.Missing(have, want)
	created := 0
	if !in.DryRun {
		for _, rec := range miss {
			if err := c.Create(r.Context(), zs[0].ID, rec); err != nil {
				s.audit(r, "cloudflare.sync", d.Name, strconv.Itoa(created)+" created; "+err.Error(), false)
				return nil, cfErr(err)
			}
			created++
		}
		s.audit(r, "cloudflare.sync", d.Name, strconv.Itoa(created), true)
	}
	return map[string]any{"zone_id": zs[0].ID, "missing": miss, "created": created, "dry_run": in.DryRun}, nil
}
