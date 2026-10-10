// SPDX-License-Identifier: Apache-2.0

package api

// v1.1 feature parity, user realm: visitor statistics, email routing,
// BoxTrapper, email encryption (GnuPG), calendars & contacts (Radicale,
// proxied at /dav/), SSH keys. Each tool is behind an install/feature flag
// (features.go) and every privileged step goes through a typed agent method
// that re-checks ownership.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/mailx"
)

type EmailRoutingReq struct {
	Mode string `json:"mode"` // auto | local | remote | backup
}

type BoxTrapperReq struct {
	Enabled   bool     `json:"enabled"`
	Whitelist []string `json:"whitelist"`
	Blacklist []string `json:"blacklist"`
	Folder    string   `json:"folder"`
}

type DavPasswordReq struct {
	Password string `json:"password"`
}

type GPGImportReq struct {
	Armored string `json:"armored"`
}

type SSHAuthorizeReq struct {
	Authorize bool `json:"authorize"`
}

func (s *Server) mountV11User(r chi.Router) {
	s.op(r, "GET", "/user/stats/visitors", "stats", "Visitor statistics (Awstats/Visitors style) of one own domain (?domain=); without it, the list of domains", nil, s.h(s.visitorStats))
	s.op(r, "GET", "/user/email/routing", "email", "Email routing (local / remote / backup MX / automatic) of the own mail domains", nil, s.h(s.emailRoutingList))
	s.op(r, "PUT", "/user/email/routing/{domain}", "email", "Set the email routing of one own mail domain", EmailRoutingReq{}, s.h(s.emailRoutingSet))
	s.op(r, "GET", "/user/email/boxtrapper", "email", "BoxTrapper (sender whitelist quarantine) of the own mailboxes", nil, s.h(s.boxTrapperList))
	s.op(r, "PUT", "/user/email/boxtrapper/{id}", "email", "Configure BoxTrapper of one own mailbox (id = mailbox id)", BoxTrapperReq{}, s.h(s.boxTrapperPut))
	s.op(r, "GET", "/user/gpg", "email", "GnuPG keys of the own keyring (email encryption)", nil, s.h(s.gpgList))
	s.op(r, "POST", "/user/gpg/generate", "email", "Generate a GnuPG key pair", rpc.GPGGenerateParams{}, s.h(s.gpgGenerate))
	s.op(r, "POST", "/user/gpg/import", "email", "Import an ASCII-armored GnuPG key", GPGImportReq{}, s.h(s.gpgImport))
	s.op(r, "GET", "/user/gpg/{fpr}/export", "email", "Export the ASCII-armored public key", nil, s.h(s.gpgExport))
	s.op(r, "DELETE", "/user/gpg/{fpr}", "email", "Delete a GnuPG key (and its secret part)", nil, s.h(s.gpgDelete))
	s.op(r, "GET", "/user/calendars", "email", "Calendars & contacts (CalDAV/CardDAV, Radicale): status, URL and the DAV logins of the own mailboxes", nil, s.h(s.davList))
	s.op(r, "PUT", "/user/calendars/{id}", "email", "Enable CalDAV/CardDAV for one own mailbox or change its DAV password", DavPasswordReq{}, s.h(s.davPut))
	s.op(r, "DELETE", "/user/calendars/{id}", "email", "Disable CalDAV/CardDAV for one own mailbox", nil, s.h(s.davDelete))
	s.op(r, "GET", "/user/ssh-keys", "ssh", "SSH keys of the own account (~/.ssh, authorized_keys)", nil, s.h(s.sshKeyList))
	s.op(r, "POST", "/user/ssh-keys/import", "ssh", "Import a public (and optional private) SSH key", rpc.SSHKeyImportParams{}, s.h(s.sshKeyImport))
	s.op(r, "POST", "/user/ssh-keys/generate", "ssh", "Generate an ed25519 or RSA key pair (the private key is returned once)", rpc.SSHKeyGenerateParams{}, s.h(s.sshKeyGenerate))
	s.op(r, "POST", "/user/ssh-keys/{name}/authorize", "ssh", "Authorize or deauthorize a key for SSH/SFTP logins", SSHAuthorizeReq{}, s.h(s.sshKeyAuthorize))
	s.op(r, "DELETE", "/user/ssh-keys/{name}", "ssh", "Delete a key (files and authorization)", nil, s.h(s.sshKeyDelete))
}

// ---- visitor statistics ---------------------------------------------------------------

func (s *Server) visitorStats(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	doms, err := s.domainsOf(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, d := range doms {
		if d.Kind != "alias" {
			names = append(names, d.Name)
		}
	}
	sort.Strings(names)
	want := strings.ToLower(r.URL.Query().Get("domain"))
	if want == "" {
		return map[string]any{"domains": names}, nil
	}
	ok := false
	for _, n := range names {
		ok = ok || n == want
	}
	if !ok {
		return nil, notFound()
	}
	var res rpc.LogStatsResult
	if err := s.agentCall(r, rpc.MLogStats, rpc.LogStatsParams{User: u.Username, Domain: want}, &res); err != nil {
		return nil, err
	}
	return map[string]any{"domains": names, "domain": want, "stats": res}, nil
}

// ---- email routing ------------------------------------------------------------------

// mxIsLocal reports whether one of the domain's MX hosts resolves to this
// server (hostname or a server address); unknown = true (local).
var lookupMX = net.DefaultResolver.LookupMX
var lookupHost = net.DefaultResolver.LookupHost

func (s *Server) mxIsLocal(ctx context.Context, domain string) (bool, []string) {
	mxs, err := lookupMX(ctx, domain)
	if err != nil || len(mxs) == 0 {
		return true, []string{}
	}
	hosts := []string{}
	local := map[string]bool{strings.ToLower(s.Cfg.ServerIP): true}
	if h := strings.ToLower(strings.TrimSuffix(s.Cfg.Hostname, ".")); h != "" {
		local[h] = true
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if pn, ok := a.(*net.IPNet); ok {
				local[pn.IP.String()] = true
			}
		}
	}
	isLocal := false
	for _, mx := range mxs {
		h := strings.ToLower(strings.TrimSuffix(mx.Host, "."))
		hosts = append(hosts, h)
		if local[h] {
			isLocal = true
			continue
		}
		if ips, err := lookupHost(ctx, h); err == nil {
			for _, ip := range ips {
				if local[ip] {
					isLocal = true
				}
			}
		}
	}
	return isLocal, hosts
}

func (s *Server) emailRoutingList(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	out := []map[string]any{}
	for _, d := range s.mailDomainNames(r.Context(), u.ID) {
		mode, eff := "auto", "local"
		_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT mode, effective FROM mail_routing WHERE domain=? AND user_id=?`, d, u.ID).Scan(&mode, &eff)
		local, mx := s.mxIsLocal(r.Context(), d)
		out = append(out, map[string]any{"domain": d, "mode": mode, "effective": eff, "mx": mx, "mx_local": local})
	}
	return map[string]any{"domains": out, "modes": []string{"auto", "local", "backup", "remote"}}, nil
}

func (s *Server) emailRoutingSet(w http.ResponseWriter, r *http.Request) (any, error) {
	var in EmailRoutingReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	d := strings.ToLower(chi.URLParam(r, "domain"))
	ok := false
	for _, n := range s.mailDomainNames(r.Context(), u.ID) {
		ok = ok || n == d
	}
	if !ok {
		return nil, notFound()
	}
	eff := in.Mode
	switch in.Mode {
	case "auto":
		eff = "remote"
		if local, _ := s.mxIsLocal(r.Context(), d); local {
			eff = "local"
		}
	case "local", "remote", "backup":
	default:
		return nil, badField("invalid_mode", "mode")
	}
	var res rpc.MailRoutingResult
	if err := s.agentCall(r, rpc.MMailRoutingSet, rpc.MailRoutingParams{User: u.Username, Domain: d, Mode: eff}, &res); err != nil {
		s.audit(r, "email.routing", d, nsAgentCode(err), false)
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO mail_routing(domain,user_id,mode,effective,updated_at) VALUES(?,?,?,?,?)
		ON CONFLICT(domain) DO UPDATE SET user_id=excluded.user_id, mode=excluded.mode, effective=excluded.effective, updated_at=excluded.updated_at`,
		d, u.ID, in.Mode, eff, s.Now().Unix()); err != nil {
		return nil, err
	}
	s.audit(r, "email.routing", d, in.Mode+"->"+eff, true)
	return map[string]any{"domain": d, "mode": in.Mode, "effective": eff, "status": res.Status, "reason": res.Reason}, nil
}

// ---- BoxTrapper ----------------------------------------------------------------------

func (s *Server) boxTrapperOf(ctx context.Context, boxID int64) *mailx.BoxTrapper {
	var en int
	var wl, bl, folder string
	if err := s.Store.DB.QueryRowContext(ctx, `SELECT enabled, whitelist, blacklist, folder FROM mail_boxtrapper WHERE mailbox_id=?`, boxID).Scan(&en, &wl, &bl, &folder); err != nil {
		return nil
	}
	bt := &mailx.BoxTrapper{Enabled: en == 1, Folder: folder, Whitelist: []string{}, Blacklist: []string{}}
	_ = json.Unmarshal([]byte(wl), &bt.Whitelist)
	_ = json.Unmarshal([]byte(bl), &bt.Blacklist)
	return bt
}

func (s *Server) boxTrapperList(w http.ResponseWriter, r *http.Request) (any, error) {
	boxes, err := s.ownBoxes(r.Context(), userOf(r).ID)
	if err != nil {
		return nil, err
	}
	st := s.sieveStatus(r.Context(), userOf(r).ID)
	out := []map[string]any{}
	for _, b := range boxes {
		bt := s.boxTrapperOf(r.Context(), b.ID)
		if bt == nil {
			bt = &mailx.BoxTrapper{Folder: "BoxTrapper", Whitelist: []string{}, Blacklist: []string{}}
		}
		out = append(out, map[string]any{"mailbox_id": b.ID, "email": b.Email, "enabled": bt.Enabled, "whitelist": bt.Whitelist,
			"blacklist": bt.Blacklist, "folder": bt.Folder, "status": st[b.ID].Status, "reason": st[b.ID].Reason})
	}
	return map[string]any{"mailboxes": out}, nil
}

func (s *Server) boxTrapperPut(w http.ResponseWriter, r *http.Request) (any, error) {
	var in BoxTrapperReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	m, err := s.ownBox(r, idParam(r, "id"))
	if err != nil {
		return nil, err
	}
	bt, err := mailx.BoxTrapper{Enabled: in.Enabled, Whitelist: in.Whitelist, Blacklist: in.Blacklist, Folder: in.Folder}.Normalize()
	if err != nil {
		return nil, mailxBad(err)
	}
	vac, en, err := s.boxVacation(r.Context(), m.ID)
	if err != nil {
		return nil, err
	}
	if !en {
		vac = nil
	}
	rules, err := s.boxRules(r.Context(), m.ID)
	if err != nil {
		return nil, err
	}
	st, err := s.applySieveBT(r, m, vac, rules, &bt)
	if err != nil {
		s.audit(r, "email.boxtrapper", m.Email, nsAgentCode(err), false)
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO mail_boxtrapper(mailbox_id,enabled,whitelist,blacklist,folder,updated_at) VALUES(?,?,?,?,?,?)
		ON CONFLICT(mailbox_id) DO UPDATE SET enabled=excluded.enabled, whitelist=excluded.whitelist, blacklist=excluded.blacklist, folder=excluded.folder, updated_at=excluded.updated_at`,
		m.ID, boolInt(bt.Enabled), mustJSON(bt.Whitelist), mustJSON(bt.Blacklist), bt.Folder, s.Now().Unix()); err != nil {
		return nil, err
	}
	s.audit(r, "email.boxtrapper", m.Email, map[bool]string{true: "enabled", false: "disabled"}[bt.Enabled], true)
	return map[string]any{"mailbox_id": m.ID, "email": m.Email, "enabled": bt.Enabled, "whitelist": bt.Whitelist, "blacklist": bt.Blacklist,
		"folder": bt.Folder, "status": st.Status, "reason": st.Reason}, nil
}

// ---- GnuPG -----------------------------------------------------------------------------

func (s *Server) gpgList(w http.ResponseWriter, r *http.Request) (any, error) {
	var res rpc.GPGListResult
	if err := s.agentCall(r, rpc.MGPGList, rpc.GPGListParams{User: userOf(r).Username}, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func (s *Server) gpgGenerate(w http.ResponseWriter, r *http.Request) (any, error) {
	var in rpc.GPGGenerateParams
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	in.User = userOf(r).Username
	var res rpc.GPGOutput
	if err := s.agentCall(r, rpc.MGPGGenerate, in, &res); err != nil {
		s.audit(r, "gpg.generate", in.Email, nsAgentCode(err), false)
		return nil, err
	}
	s.audit(r, "gpg.generate", in.Email, in.Algo, true)
	return s.gpgList(w, r)
}

func (s *Server) gpgImport(w http.ResponseWriter, r *http.Request) (any, error) {
	var in GPGImportReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	var res rpc.GPGOutput
	if err := s.agentCall(r, rpc.MGPGImport, rpc.GPGImportParams{User: userOf(r).Username, Armored: in.Armored}, &res); err != nil {
		s.audit(r, "gpg.import", "", nsAgentCode(err), false)
		return nil, err
	}
	s.audit(r, "gpg.import", "", "", true)
	return s.gpgList(w, r)
}

func (s *Server) gpgExport(w http.ResponseWriter, r *http.Request) (any, error) {
	var res rpc.GPGOutput
	if err := s.agentCall(r, rpc.MGPGExport, rpc.GPGKeyRef{User: userOf(r).Username, Fingerprint: strings.ToUpper(chi.URLParam(r, "fpr"))}, &res); err != nil {
		return nil, err
	}
	return map[string]any{"armored": res.Armored}, nil
}

func (s *Server) gpgDelete(w http.ResponseWriter, r *http.Request) (any, error) {
	f := strings.ToUpper(chi.URLParam(r, "fpr"))
	var res rpc.GPGOutput
	if err := s.agentCall(r, rpc.MGPGDelete, rpc.GPGKeyRef{User: userOf(r).Username, Fingerprint: f}, &res); err != nil {
		s.audit(r, "gpg.delete", f, nsAgentCode(err), false)
		return nil, err
	}
	s.audit(r, "gpg.delete", f, "", true)
	return s.gpgList(w, r)
}

// ---- calendars & contacts (Radicale) ------------------------------------------------------

// DavURL is where clients connect (the user panel port; /dav/ is proxied).
func (s *Server) davURL() string {
	h := s.Cfg.Hostname
	if h == "" {
		h = "localhost"
	}
	port := s.Cfg.UserPort
	if port == 0 {
		port = 2083
	}
	return "https://" + h + ":" + strconv.Itoa(port) + "/dav/"
}

func (s *Server) davSyncUser(r *http.Request) (rpc.DavStatusResult, error) {
	u := userOf(r)
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT m.email, d.hash FROM dav_logins d JOIN mailboxes m ON m.id=d.mailbox_id WHERE m.user_id=? ORDER BY m.email`, u.ID)
	if err != nil {
		return rpc.DavStatusResult{}, err
	}
	logins := []rpc.DavLogin{}
	for rows.Next() {
		var l rpc.DavLogin
		if rows.Scan(&l.Name, &l.Hash) == nil {
			logins = append(logins, l)
		}
	}
	rows.Close()
	var st rpc.DavStatusResult
	err = s.agentCall(r, rpc.MDavSync, rpc.DavSyncParams{User: u.Username, Logins: logins}, &st)
	return st, err
}

func (s *Server) davList(w http.ResponseWriter, r *http.Request) (any, error) {
	boxes, err := s.ownBoxes(r.Context(), userOf(r).ID)
	if err != nil {
		return nil, err
	}
	var st rpc.DavStatusResult
	if err := s.agentCall(r, rpc.MDavStatus, struct{}{}, &st); err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, b := range boxes {
		var n int
		_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM dav_logins WHERE mailbox_id=?`, b.ID).Scan(&n)
		out = append(out, map[string]any{"mailbox_id": b.ID, "email": b.Email, "enabled": n > 0,
			"calendar_url": s.davURL() + b.Email + "/", "addressbook_url": s.davURL() + b.Email + "/"})
	}
	return map[string]any{"status": st.Status, "reason": st.Reason, "url": s.davURL(), "mailboxes": out}, nil
}

func (s *Server) davPut(w http.ResponseWriter, r *http.Request) (any, error) {
	var in DavPasswordReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	m, err := s.ownBox(r, idParam(r, "id"))
	if err != nil {
		return nil, err
	}
	if len(in.Password) < 10 || len(in.Password) > 72 {
		return nil, badField("weak_password", "password")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(in.Password), 10)
	if err != nil {
		return nil, err
	}
	hash := "$2y$" + strings.TrimPrefix(string(h), "$2a$")
	var prev sql.NullString
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT hash FROM dav_logins WHERE mailbox_id=?`, m.ID).Scan(&prev)
	if _, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO dav_logins(mailbox_id,hash,updated_at) VALUES(?,?,?)
		ON CONFLICT(mailbox_id) DO UPDATE SET hash=excluded.hash, updated_at=excluded.updated_at`, m.ID, hash, s.Now().Unix()); err != nil {
		return nil, err
	}
	st, err := s.davSyncUser(r)
	if err != nil {
		if prev.Valid {
			_, _ = s.Store.DB.ExecContext(r.Context(), `UPDATE dav_logins SET hash=? WHERE mailbox_id=?`, prev.String, m.ID)
		} else {
			_, _ = s.Store.DB.ExecContext(r.Context(), `DELETE FROM dav_logins WHERE mailbox_id=?`, m.ID)
		}
		s.audit(r, "dav.enable", m.Email, nsAgentCode(err), false)
		return nil, err
	}
	s.audit(r, "dav.enable", m.Email, st.Status, true)
	return map[string]any{"status": st.Status, "reason": st.Reason, "url": s.davURL() + m.Email + "/"}, nil
}

func (s *Server) davDelete(w http.ResponseWriter, r *http.Request) (any, error) {
	m, err := s.ownBox(r, idParam(r, "id"))
	if err != nil {
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM dav_logins WHERE mailbox_id=?`, m.ID); err != nil {
		return nil, err
	}
	st, err := s.davSyncUser(r)
	if err != nil {
		return nil, err
	}
	s.audit(r, "dav.disable", m.Email, st.Status, true)
	return map[string]any{"status": st.Status}, nil
}

// davProxy forwards /dav/* (user panel port) to Radicale on 127.0.0.1:5232.
// Radicale authenticates every request itself (htpasswd of DAV logins).
func (s *Server) davProxy() http.Handler {
	up := s.Cfg.DavUpstream
	if up == "" {
		up = "http://127.0.0.1:5232"
	}
	u, err := url.Parse(up)
	if err != nil {
		return http.NotFoundHandler()
	}
	p := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			pr.Out.URL.Path = strings.TrimPrefix(pr.In.URL.Path, "/dav")
			if pr.Out.URL.Path == "" {
				pr.Out.URL.Path = "/"
			}
			pr.Out.URL.RawPath = ""
			pr.Out.Header.Set("X-Script-Name", "/dav")
			pr.Out.Header.Del("Cookie")
			pr.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "calendar service unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.featureOn("calendars") {
			http.NotFound(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
		p.ServeHTTP(w, r)
	})
}

// ---- SSH keys -------------------------------------------------------------------------------

func (s *Server) sshKeyList(w http.ResponseWriter, r *http.Request) (any, error) {
	var res rpc.SSHKeyListResult
	if err := s.agentCall(r, rpc.MSSHKeyList, rpc.SSHKeyListParams{User: userOf(r).Username}, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func (s *Server) sshKeyImport(w http.ResponseWriter, r *http.Request) (any, error) {
	var in rpc.SSHKeyImportParams
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	in.User = userOf(r).Username
	var k rpc.SSHKey
	if err := s.agentCall(r, rpc.MSSHKeyImport, in, &k); err != nil {
		s.audit(r, "ssh_key.import", in.Name, nsAgentCode(err), false)
		return nil, err
	}
	s.audit(r, "ssh_key.import", in.Name, k.Fingerprint, true)
	return k, nil
}

func (s *Server) sshKeyGenerate(w http.ResponseWriter, r *http.Request) (any, error) {
	var in rpc.SSHKeyGenerateParams
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	in.User = userOf(r).Username
	var res rpc.SSHKeyGenerateResult
	if err := s.agentCall(r, rpc.MSSHKeyGenerate, in, &res); err != nil {
		s.audit(r, "ssh_key.generate", in.Name, nsAgentCode(err), false)
		return nil, err
	}
	s.audit(r, "ssh_key.generate", in.Name, res.Key.Fingerprint, true)
	w.Header().Set("Cache-Control", "no-store")
	return res, nil
}

func (s *Server) sshKeyAuthorize(w http.ResponseWriter, r *http.Request) (any, error) {
	var in SSHAuthorizeReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	name := chi.URLParam(r, "name")
	if err := s.agentCall(r, rpc.MSSHKeyAuthorize, rpc.SSHKeyRef{User: userOf(r).Username, Name: name, Authorize: in.Authorize}, nil); err != nil {
		return nil, err
	}
	s.audit(r, "ssh_key.authorize", name, map[bool]string{true: "on", false: "off"}[in.Authorize], true)
	return s.sshKeyList(w, r)
}

func (s *Server) sshKeyDelete(w http.ResponseWriter, r *http.Request) (any, error) {
	name := chi.URLParam(r, "name")
	if err := s.agentCall(r, rpc.MSSHKeyDelete, rpc.SSHKeyRef{User: userOf(r).Username, Name: name}, nil); err != nil {
		s.audit(r, "ssh_key.delete", name, nsAgentCode(err), false)
		return nil, err
	}
	s.audit(r, "ssh_key.delete", name, "", true)
	return s.sshKeyList(w, r)
}
