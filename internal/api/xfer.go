// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/jobs"
	"github.com/cumabozkurt/bpanel/internal/rbac"
	"github.com/cumabozkurt/bpanel/internal/store"
	"github.com/cumabozkurt/bpanel/internal/xfer"
)

// v0.4 xfer (spec §10): Transfer Tool. Sources: an archive already in the
// agent's xfer directory, or a remote pull over SFTP (credential kept in the
// secret store only until the fetch job ends). Analyse = read-only parse +
// conflict check; import = a job that creates the account through the normal
// provisioning paths (CreateAccount, createDomain, newDatabase, createMailbox,
// createForwarder, dnsx zone import) and then restores home + SQL dumps
// through typed agent actions. Export writes a BPanel-native archive.

const (
	jobXferImport = "xfer.import"
	jobXferExport = "xfer.export"
	jobXferFetch  = "xfer.fetch"

	xferMaxFetchBytes = 100 << 30
)

type XferAnalyseReq struct {
	Archive string `json:"archive"`
}

type XferImportReq struct {
	Archive   string `json:"archive"`
	PackageID int64  `json:"package_id"`
	SkipDNS   bool   `json:"skip_dns"`
	SkipHome  bool   `json:"skip_home"`
	SkipDBs   bool   `json:"skip_databases"`
	SkipMail  bool   `json:"skip_mail"`
}

type XferFetchReq struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	User         string `json:"user"`
	RemotePath   string `json:"remote_path"`
	Auth         string `json:"auth"`   // key | password
	Secret       string `json:"secret"` // private key or password; stored in the secret store until the job ends
	AllowPrivate bool   `json:"allow_private"`
}

func (s *Server) mountXfer(r chi.Router) {
	s.opPerm(r, rbac.XferRead, "GET", "/admin/xfer/archives", "transfer", "Transfer Tool: archives in the transfer directory", nil, s.h(s.xferArchives))
	s.opPerm(r, rbac.XferWrite, "DELETE", "/admin/xfer/archives/{name}", "transfer", "Transfer Tool: delete an archive", nil, s.h(s.xferDeleteArchive))
	s.opPerm(r, rbac.XferRead, "POST", "/admin/xfer/analyse", "transfer", "Transfer Tool: parse an archive (BPanel, cPanel; HestiaCP detected) and report conflicts; read-only", XferAnalyseReq{}, s.h(s.xferAnalyse))
	s.opPermReauth(r, rbac.XferWrite, "POST", "/admin/xfer/fetch", "transfer", "Transfer Tool: pull an archive from a remote server over SFTP (job)", XferFetchReq{}, s.h(s.xferFetch))
	s.opPermReauth(r, rbac.XferWrite, "POST", "/admin/xfer/import", "transfer", "Transfer Tool: import an analysed archive as a new account (job)", XferImportReq{}, s.h(s.xferImport))
	s.opPerm(r, rbac.XferRead, "GET", "/admin/xfer/imports", "transfer", "Transfer Tool: import/export history with reports", nil, s.h(s.xferHistory))
	s.opPermReauth(r, rbac.XferWrite, "POST", "/admin/accounts/{id}/export", "transfer", "Export an account to a BPanel transfer archive (job)", nil, s.h(s.xferExport))
	s.Jobs().Register(jobXferImport, s.runXferImport)
	s.Jobs().Register(jobXferExport, s.runXferExport)
	s.Jobs().Register(jobXferFetch, s.runXferFetch)
}

var xferArchiveRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.(tar\.gz|tgz|tar)$`)

func xferArchiveName(n string) error {
	if !xferArchiveRe.MatchString(n) || strings.Contains(n, "..") {
		return badField("xfer_invalid_archive", "archive")
	}
	return nil
}

func (s *Server) xferArchives(w http.ResponseWriter, r *http.Request) (any, error) {
	var res rpc.XferArchiveList
	if err := s.agentCall(r, rpc.MXferList, rpc.Empty{}, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func (s *Server) xferDeleteArchive(w http.ResponseWriter, r *http.Request) (any, error) {
	n := chi.URLParam(r, "name")
	if err := xferArchiveName(n); err != nil {
		return nil, err
	}
	err := s.agentCall(r, rpc.MXferDelete, rpc.XferArchiveRef{Archive: n}, &rpc.Empty{})
	s.audit(r, "xfer.delete", n, "", err == nil)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

// XferConflict is one reason an import cannot proceed as-is.
type XferConflict struct {
	Kind  string `json:"kind"` // username | domain | database
	Value string `json:"value"`
}

func (s *Server) xferConflicts(ctx context.Context, m *xfer.Model) []XferConflict {
	out := []XferConflict{}
	var n int
	if _ = s.Store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE username=?`, m.Account.Username).Scan(&n); n > 0 {
		out = append(out, XferConflict{Kind: "username", Value: m.Account.Username})
	}
	for _, rn := range s.reservedNames() {
		if rn == m.Account.Username {
			out = append(out, XferConflict{Kind: "username", Value: m.Account.Username})
		}
	}
	for _, d := range m.Domains {
		n = 0
		_ = s.Store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM domains WHERE name=?`, d.Name).Scan(&n)
		if n > 0 {
			out = append(out, XferConflict{Kind: "domain", Value: d.Name})
		}
	}
	for _, db := range m.Databases {
		n = 0
		_ = s.Store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM databases WHERE name=?`, xferDBName(m.Account.Username, db.Name)).Scan(&n)
		if n > 0 {
			out = append(out, XferConflict{Kind: "database", Value: db.Name})
		}
	}
	return out
}

// xferDBName is the BPanel database a dump lands in (<user>_<short>).
func xferDBName(user, src string) string {
	short := strings.TrimPrefix(src, user+"_")
	return user + "_" + short
}

func (s *Server) xferAnalyse(w http.ResponseWriter, r *http.Request) (any, error) {
	var in XferAnalyseReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := xferArchiveName(in.Archive); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	var res rpc.XferAnalyseResult
	if err := s.Agent.Call(ctx, rpc.MXferAnalyse, rpc.XferArchiveRef{Archive: in.Archive}, &res); err != nil {
		s.audit(r, "xfer.analyse", in.Archive, "", false)
		return nil, err
	}
	s.audit(r, "xfer.analyse", in.Archive, res.Model.Format+" "+res.Model.Account.Username, true)
	return map[string]any{"model": res.Model, "conflicts": s.xferConflicts(r.Context(), &res.Model)}, nil
}

func (s *Server) xferRecord(ctx context.Context, kind, archive, format, username, jobID string, actor int64) {
	_, _ = s.Store.DB.ExecContext(ctx, `INSERT INTO xfer_runs(kind, archive, format, username, job_id, actor_id, status, created_at) VALUES(?,?,?,?,?,?,'queued',?)`,
		kind, archive, format, username, jobID, actor, time.Now().Unix())
}

func (s *Server) xferFinish(ctx context.Context, jobID, status string, report any) {
	b, _ := json.Marshal(report)
	_, _ = s.Store.DB.ExecContext(context.WithoutCancel(ctx), `UPDATE xfer_runs SET status=?, report=?, finished_at=? WHERE job_id=?`, status, string(b), time.Now().Unix(), jobID)
}

func (s *Server) xferHistory(w http.ResponseWriter, r *http.Request) (any, error) {
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT x.id, x.kind, x.archive, x.format, x.username, x.job_id, x.status, x.report, x.created_at, x.finished_at, COALESCE(u.username,'')
		FROM xfer_runs x LEFT JOIN users u ON u.id=x.actor_id ORDER BY x.id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, created, finished int64
		var kind, archive, format, user, job, status, report, actor string
		if err := rows.Scan(&id, &kind, &archive, &format, &user, &job, &status, &report, &created, &finished, &actor); err != nil {
			return nil, err
		}
		var rep any
		if report != "" {
			_ = json.Unmarshal([]byte(report), &rep)
		}
		out = append(out, map[string]any{"id": id, "kind": kind, "archive": archive, "format": format, "username": user, "job_id": job,
			"status": status, "report": rep, "created_at": created, "finished_at": finished, "actor": actor})
	}
	return map[string]any{"runs": out}, rows.Err()
}

// ---- remote pull ------------------------------------------------------------------

type xferFetchPayload struct {
	Remote       xfer.Remote `json:"remote"`
	SecretName   string      `json:"secret_name"`
	Archive      string      `json:"archive"`
	AllowPrivate bool        `json:"allow_private"`
}

func (s *Server) xferFetch(w http.ResponseWriter, r *http.Request) (any, error) {
	var in XferFetchReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	rem := xfer.Remote{Host: in.Host, Port: in.Port, User: in.User, RemotePath: in.RemotePath, Auth: in.Auth}
	if err := rem.Validate(); err != nil {
		var xe *xfer.Error
		if errors.As(err, &xe) {
			return nil, badMsg(xe.Code.Error(), xe.Detail)
		}
		return nil, bad("xfer_remote_invalid")
	}
	if strings.TrimSpace(in.Secret) == "" || len(in.Secret) > 16<<10 {
		return nil, badField("xfer_remote_invalid", "secret")
	}
	// fast SSRF pre-check for literal addresses; the agent re-checks after resolving
	if _, err := xfer.ResolveSafe(r.Context(), noResolve{}, rem.Host, in.AllowPrivate); errors.Is(err, xfer.ErrRemoteBlocked) {
		s.audit(r, "xfer.fetch", rem.Host, "blocked address", false)
		return nil, bad("xfer_remote_blocked")
	}
	st, ok := s.secretsUsable()
	if !ok {
		return nil, conflict("secrets_unavailable")
	}
	base := rem.RemotePath[strings.LastIndexByte(rem.RemotePath, '/')+1:]
	archive := "pull-" + time.Now().UTC().Format("20060102-150405") + "-" + xferToken(4) + "-" + base
	if !xferArchiveRe.MatchString(archive) {
		archive = "pull-" + time.Now().UTC().Format("20060102-150405") + "-" + xferToken(4) + ".tar.gz"
	}
	name := "xfer.fetch." + xferToken(8)
	if err := st.Put(r.Context(), name, []byte(in.Secret)); err != nil {
		return nil, err
	}
	id, err := s.Jobs().Enqueue(r.Context(), jobs.Spec{Kind: jobXferFetch, ActorID: userOf(r).ID,
		Payload: xferFetchPayload{Remote: rem, SecretName: name, Archive: archive, AllowPrivate: in.AllowPrivate}})
	if err != nil {
		_ = st.Delete(context.WithoutCancel(r.Context()), name)
		return nil, err
	}
	s.xferRecord(r.Context(), "fetch", archive, "", "", id, userOf(r).ID)
	s.audit(r, "xfer.fetch", rem.User+"@"+rem.Host+":"+rem.RemotePath, "job "+id, true)
	return map[string]any{"job_id": id, "archive": archive}, nil
}

// noResolve only judges literal IPs (hostnames are resolved by the agent).
type noResolve struct{}

func (noResolve) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, errors.New("not resolved here")
}

func (s *Server) runXferFetch(ctx context.Context, j *jobs.Job) (any, error) {
	var pl xferFetchPayload
	if err := json.Unmarshal(j.Payload, &pl); err != nil {
		return nil, err
	}
	st, ok := s.secretsUsable()
	if !ok {
		return nil, errors.New("secrets_unavailable")
	}
	defer func() { _ = st.Delete(context.WithoutCancel(ctx), pl.SecretName) }() // credential never outlives the job
	sec, err := st.Get(ctx, pl.SecretName)
	if err != nil {
		s.xferFinish(ctx, j.ID, "failed", map[string]any{"error": "secret_not_found"})
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Hour+time.Minute)
	defer cancel()
	var res rpc.XferFetchResult
	err = s.Agent.Call(cctx, rpc.MXferFetch, rpc.XferFetch{Remote: pl.Remote, Secret: string(sec), Archive: pl.Archive, AllowPrivate: pl.AllowPrivate, MaxBytes: xferMaxFetchBytes}, &res)
	for i := range sec {
		sec[i] = 0
	}
	if err != nil {
		s.xferFinish(ctx, j.ID, "failed", map[string]any{"error": errCode(err)})
		return nil, err
	}
	out := map[string]any{"archive": pl.Archive, "bytes": res.Bytes}
	s.xferFinish(ctx, j.ID, "done", out)
	return out, nil
}

func errCode(err error) string {
	var re *rpc.Error
	if errors.As(err, &re) {
		return re.Code
	}
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return "action_failed"
}

func xferToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return strings.ToLower(strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "=")) // may contain - and _
}

// ---- import ------------------------------------------------------------------------

type xferImportPayload struct {
	XferImportReq
}

func (s *Server) xferImport(w http.ResponseWriter, r *http.Request) (any, error) {
	var in XferImportReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := xferArchiveName(in.Archive); err != nil {
		return nil, err
	}
	if in.PackageID != 0 {
		var n int
		if _ = s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM packages WHERE id=?`, in.PackageID).Scan(&n); n == 0 {
			return nil, badField("not_found", "package_id")
		}
	}
	id, err := s.Jobs().Enqueue(r.Context(), jobs.Spec{Kind: jobXferImport, ActorID: userOf(r).ID, Payload: xferImportPayload{in}})
	if err != nil {
		return nil, err
	}
	s.xferRecord(r.Context(), "import", in.Archive, "", "", id, userOf(r).ID)
	s.audit(r, "xfer.import", in.Archive, "job "+id, true)
	return map[string]any{"job_id": id}, nil
}

// XferStep is one line of an import report.
type XferStep struct {
	Part   string `json:"part"`
	Item   string `json:"item,omitempty"`
	Status string `json:"status"` // ok | failed | skipped | action_required
	Detail string `json:"detail,omitempty"`
}

type XferReport struct {
	Format      string            `json:"format"`
	Username    string            `json:"username"`
	AccountID   int64             `json:"account_id,omitempty"`
	Steps       []XferStep        `json:"steps"`
	Unsupported []xfer.ReportItem `json:"unsupported"`
	Warnings    []string          `json:"warnings"`
	Conflicts   []XferConflict    `json:"conflicts,omitempty"`
}

func (rep *XferReport) add(part, item, status, detail string) {
	rep.Steps = append(rep.Steps, XferStep{Part: part, Item: item, Status: status, Detail: detail})
}

// asUser builds an internal request carrying u, so the account's own
// handlers (with every validation, limit and audit) do the provisioning.
func asUser(ctx context.Context, u *store.User, body any) *http.Request {
	b, _ := json.Marshal(body)
	r, _ := http.NewRequestWithContext(context.WithValue(ctx, kUser, u), "POST", "/internal/xfer", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func xferPassword() string { return "Xf-" + xferToken(15) + "-9aZ" }

func (s *Server) runXferImport(ctx context.Context, j *jobs.Job) (any, error) {
	var pl xferImportPayload
	if err := json.Unmarshal(j.Payload, &pl); err != nil {
		return nil, err
	}
	rep, err := s.xferDoImport(ctx, j.OwnerID, pl.XferImportReq)
	status := "done"
	if err != nil {
		status = "failed"
		if rep == nil {
			rep = &XferReport{Steps: []XferStep{}}
		}
		rep.add("import", "", "failed", errCode(err))
	}
	s.xferFinish(ctx, j.ID, status, rep)
	if err != nil {
		return rep, err
	}
	return rep, nil
}

func (s *Server) xferDoImport(ctx context.Context, actorID int64, in XferImportReq) (*XferReport, error) {
	actor, err := s.userByID(ctx, actorID)
	if err != nil {
		return nil, err
	}
	actx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	var an rpc.XferAnalyseResult
	err = s.Agent.Call(actx, rpc.MXferAnalyse, rpc.XferArchiveRef{Archive: in.Archive}, &an)
	cancel()
	if err != nil {
		return nil, err
	}
	m := &an.Model
	rep := &XferReport{Format: m.Format, Username: m.Account.Username, Steps: []XferStep{}, Unsupported: m.Unsupported, Warnings: m.Warnings}
	_, _ = s.Store.DB.ExecContext(ctx, `UPDATE xfer_runs SET format=?, username=?, status='running' WHERE archive=? AND status='queued' AND kind='import'`, m.Format, m.Account.Username, in.Archive)
	if c := s.xferConflicts(ctx, m); len(c) > 0 {
		rep.Conflicts = c
		return rep, conflict("xfer_conflict")
	}
	pkgID := in.PackageID
	if pkgID == 0 {
		_ = s.Store.DB.QueryRowContext(ctx, `SELECT id FROM packages WHERE name=?`, m.Account.Plan).Scan(&pkgID)
		if pkgID == 0 {
			_ = s.Store.DB.QueryRowContext(ctx, `SELECT id FROM packages WHERE name='default'`).Scan(&pkgID)
		}
	}
	email := m.Account.Email
	if !strings.Contains(email, "@") || len(email) > 254 {
		email = ""
	}
	u, warns, err := s.CreateAccount(ctx, &actor, CreateAccountReq{Username: m.Account.Username, Domain: m.Account.MainDomain,
		Password: xferPassword(), Email: email, PackageID: pkgID})
	if err != nil {
		rep.add("account", m.Account.Username, "failed", errCode(err))
		return rep, err
	}
	rep.AccountID = u.ID
	rep.add("account", u.Username, "action_required", "created with a random password; set a new password for the account")
	for _, w := range warns {
		rep.Warnings = append(rep.Warnings, fmt.Sprint(w))
	}
	mainID := int64(0)
	_ = s.Store.DB.QueryRowContext(ctx, `SELECT id FROM domains WHERE name=? AND user_id=?`, m.Account.MainDomain, u.ID).Scan(&mainID)

	// domains
	for _, d := range m.Domains {
		if d.Kind == "main" {
			continue
		}
		req := DomainReq{Name: d.Name, Kind: d.Kind}
		switch d.Kind {
		case "parked":
			req.Kind, req.ParentID = "alias", mainID
		case "sub":
			if !strings.HasSuffix(d.Name, "."+m.Account.MainDomain) {
				req.Kind = "addon" // subdomain of an addon: kept as its own site
			} else {
				req.Name, req.ParentID = strings.TrimSuffix(d.Name, "."+m.Account.MainDomain), mainID
			}
		}
		_, err := s.createDomain(nil, asUser(ctx, u, req))
		s.xferStep(rep, "domain", d.Name, err)
	}
	// DNS zones (merged into the zones provisioning created)
	if !in.SkipDNS {
		for _, z := range m.Zones {
			var did int64
			_ = s.Store.DB.QueryRowContext(ctx, `SELECT id FROM domains WHERE name=? AND user_id=?`, z.Domain, u.ID).Scan(&did)
			if did == 0 {
				rep.add("dns", z.Domain, "skipped", "zone of a domain that was not created")
				continue
			}
			s.xferStep(rep, "dns", z.Domain, s.xferZoneImport(ctx, u, z))
		}
	}
	// home directory
	if !in.SkipHome && m.Home.Files > 0 {
		var hr rpc.XferRestoreResult
		hctx, hc := context.WithTimeout(ctx, 6*time.Hour)
		err := s.Agent.Call(hctx, rpc.MXferRestoreHome, rpc.XferRestoreHome{User: u.Username, Archive: in.Archive, Prefix: m.HomePrefix()}, &hr)
		hc()
		if err == nil {
			rep.add("home", "", "ok", fmt.Sprintf("%d files, %d bytes", hr.Files, hr.Bytes))
		} else {
			rep.add("home", "", "failed", errCode(err))
		}
	}
	// databases
	if !in.SkipDBs {
		for _, d := range m.Databases {
			short := strings.TrimPrefix(d.Name, u.Username+"_")
			_, name, err := s.newDatabase(asUser(ctx, u, nil), short)
			if err != nil {
				rep.add("database", d.Name, "failed", errCode(err))
				continue
			}
			var dr rpc.XferRestoreResult
			dctx, dc := context.WithTimeout(ctx, 4*time.Hour+time.Minute)
			err = s.Agent.Call(dctx, rpc.MXferRestoreDB, rpc.XferRestoreDB{Owner: u.Username, Archive: in.Archive, Member: m.Member(d.Dump), DB: name}, &dr)
			dc()
			if err != nil {
				rep.add("database", name, "failed", errCode(err))
			} else {
				rep.add("database", name, "action_required", "data imported; create a database user and update the site's configuration")
			}
		}
	}
	// mail
	if !in.SkipMail {
		for _, mb := range m.Mailboxes {
			local, dom, _ := strings.Cut(mb.Address, "@")
			req := MailboxReq{Local: local, Domain: dom, Password: xferPassword()}
			req.QuotaMB = LimitOf(1024) // BPanel's default mailbox quota
			if mb.QuotaMB > 0 {
				req.QuotaMB = LimitOf(mb.QuotaMB)
			}
			_, err := s.createMailbox(nil, asUser(ctx, u, req))
			if err != nil {
				rep.add("mailbox", mb.Address, "failed", errCode(err))
			} else {
				rep.add("mailbox", mb.Address, "action_required", "created with a random password (password hashes are not imported yet); set a new password")
			}
		}
		for _, f := range m.Forwarders {
			local, dom, _ := strings.Cut(f.From, "@")
			for _, to := range f.To {
				_, err := s.createForwarder(nil, asUser(ctx, u, ForwarderReq{Source: local, Domain: dom, Destination: to}))
				s.xferStep(rep, "forwarder", f.From+" → "+to, err)
			}
		}
	}
	for _, c := range m.Certs {
		rep.add("ssl", c.Domain, "skipped", "issue a free Let's Encrypt certificate after DNS points to this server")
	}
	s.Log.Info("xfer import finished", "user", u.Username, "format", m.Format, "steps", len(rep.Steps))
	return rep, nil
}

func (s *Server) xferStep(rep *XferReport, part, item string, err error) {
	if err != nil {
		rep.add(part, item, "failed", errCode(err))
		return
	}
	rep.add(part, item, "ok", "")
}

func (s *Server) xferZoneImport(ctx context.Context, u *store.User, z xfer.Zone) error {
	r := asUser(ctx, u, ZoneImportReq{Text: z.Text, Mode: "merge"})
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("domain", z.Domain)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	_, err := s.applyImport(nil, r)
	return err
}

// ---- export -------------------------------------------------------------------------

type xferExportPayload struct {
	UserID  int64  `json:"user_id"`
	Archive string `json:"archive"`
}

func (s *Server) xferExport(w http.ResponseWriter, r *http.Request) (any, error) {
	u, err := s.userByID(r.Context(), idParam(r, "id"))
	if err != nil || u.Role != "user" {
		return nil, notFound()
	}
	archive := "bpanel-" + u.Username + "-" + time.Now().UTC().Format("20060102-150405") + ".tar.gz"
	id, err := s.Jobs().Enqueue(r.Context(), jobs.Spec{Kind: jobXferExport, ActorID: userOf(r).ID, Payload: xferExportPayload{UserID: u.ID, Archive: archive}})
	if err != nil {
		return nil, err
	}
	s.xferRecord(r.Context(), "export", archive, xfer.FormatBPanel, u.Username, id, userOf(r).ID)
	s.audit(r, "xfer.export", u.Username, "job "+id, true)
	return map[string]any{"job_id": id, "archive": archive}, nil
}

func (s *Server) runXferExport(ctx context.Context, j *jobs.Job) (any, error) {
	var pl xferExportPayload
	if err := json.Unmarshal(j.Payload, &pl); err != nil {
		return nil, err
	}
	res, err := s.xferDoExport(ctx, pl)
	if err != nil {
		s.xferFinish(ctx, j.ID, "failed", map[string]any{"error": errCode(err)})
		return nil, err
	}
	s.xferFinish(ctx, j.ID, "done", res)
	return res, nil
}

func (s *Server) xferDoExport(ctx context.Context, pl xferExportPayload) (*rpc.XferExportResult, error) {
	u, err := s.userByID(ctx, pl.UserID)
	if err != nil {
		return nil, err
	}
	man := xfer.Manifest{BPanelVersion: s.Version, Account: xfer.Account{Username: u.Username, Email: u.Email}}
	var dbs []string
	var blobs []rpc.XferBlob
	ds, err := s.domainsOf(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	for _, d := range ds {
		kind := d.Kind
		switch {
		case d.Kind == "main":
			kind = "main"
			man.Account.MainDomain = d.Name
		case d.Kind == "alias":
			kind = "parked"
		}
		man.Domains = append(man.Domains, xfer.Domain{Name: d.Name, Kind: kind})
	}
	if man.Account.MainDomain == "" && len(man.Domains) > 0 {
		man.Account.MainDomain, man.Domains[0].Kind = man.Domains[0].Name, "main"
	}
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT name FROM databases WHERE user_id=? ORDER BY name`, u.ID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			dbs = append(dbs, n)
			man.Databases = append(man.Databases, xfer.Database{Name: n, Dump: "mysql/" + n + ".sql"})
		}
	}
	rows.Close()
	// zones: BIND text from the dnsx exporter
	for _, d := range ds {
		if d.Kind == "sub" {
			continue
		}
		r := asUser(ctx, &u, nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("domain", d.Name)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
		out, err := s.exportZone(nil, r)
		if err != nil {
			continue
		}
		var txt string
		if mm, ok := out.(map[string]any); ok {
			txt, _ = mm["text"].(string)
		}
		if txt == "" {
			continue
		}
		member := "dnszones/" + d.Name + ".zone"
		blobs = append(blobs, rpc.XferBlob{Name: member, Content: txt})
		man.Zones = append(man.Zones, xfer.Zone{Domain: d.Name, Member: member})
	}
	// mail: forwarders and mailbox names/quotas (hashes stay on the source)
	type mbx struct {
		Address string `json:"address"`
		QuotaMB int64  `json:"quota_mb"`
	}
	mbs := []mbx{}
	if rows, err := s.Store.DB.QueryContext(ctx, `SELECT email, quota_mb FROM mailboxes WHERE user_id=? ORDER BY email`, u.ID); err == nil {
		for rows.Next() {
			var x mbx
			if rows.Scan(&x.Address, &x.QuotaMB) == nil {
				mbs = append(mbs, x)
			}
		}
		rows.Close()
	}
	if rows, err := s.Store.DB.QueryContext(ctx, `SELECT source, destination FROM forwarders WHERE user_id=? ORDER BY source, destination`, u.ID); err == nil {
		for rows.Next() {
			var from, to string
			if rows.Scan(&from, &to) == nil {
				man.Forwarders = append(man.Forwarders, xfer.Forwarder{From: from, To: []string{to}})
			}
		}
		rows.Close()
	}
	mb, _ := json.Marshal(mbs)
	blobs = append(blobs, rpc.XferBlob{Name: "mail/mailboxes.json", Content: string(mb)})
	raw, _ := json.Marshal(man)
	var res rpc.XferExportResult
	cctx, cancel := context.WithTimeout(ctx, 8*time.Hour)
	defer cancel()
	if err := s.Agent.Call(cctx, rpc.MXferExport, rpc.XferExport{User: u.Username, Archive: pl.Archive, Databases: dbs, Blobs: blobs, Manifest: raw}, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
