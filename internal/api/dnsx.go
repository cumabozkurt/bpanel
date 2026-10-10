// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/dnsx"
	"github.com/cumabozkurt/bpanel/internal/store"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// v0.4 dnsx (spec §11): DNSSEC, zone import/export, DNS change history with
// revert, zone consistency checks, and mlmmj mailing lists. Every endpoint
// works on the caller's own zones/domains only (zoneDomain /
// ownDomainByName); the agent re-checks ownership (mustOwn).

type DNSSECReq struct {
	Enabled bool `json:"enabled"`
}

type ZoneImportReq struct {
	Text  string `json:"text"`
	Mode  string `json:"mode"`  // merge (default) | replace
	Force bool   `json:"force"` // apply despite error-level findings
}

type RevertReq struct {
	Force bool `json:"force"`
}

type MailingListReq struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Owner  string `json:"owner"`
}

type ListSubReq struct {
	Address string `json:"address"`
}

func (s *Server) mountDnsx(r chi.Router) {
	s.op(r, "GET", "/user/dnsx/{domain}/dnssec", "dns", "DNSSEC state and DS records of an own zone", nil, s.h(s.getDNSSEC))
	s.op(r, "POST", "/user/dnsx/{domain}/dnssec", "dns", "Enable or disable DNSSEC (pdnsutil)", DNSSECReq{}, s.h(s.setDNSSEC))
	s.op(r, "GET", "/user/dnsx/{domain}/export", "dns", "Export an own zone as a BIND zone file", nil, s.h(s.exportZone))
	s.op(r, "POST", "/user/dnsx/{domain}/import/preview", "dns", "Parse BIND zone text and preview the changes + checks", ZoneImportReq{}, s.h(s.previewImport))
	s.op(r, "POST", "/user/dnsx/{domain}/import/apply", "dns", "Apply a BIND zone import", ZoneImportReq{}, s.h(s.applyImport))
	s.op(r, "GET", "/user/dnsx/{domain}/check", "dns", "Consistency checks of an own zone", nil, s.h(s.checkZone))
	s.op(r, "GET", "/user/dnsx/{domain}/history", "dns", "DNS change history of an own zone", nil, s.h(s.zoneHistory))
	s.op(r, "POST", "/user/dnsx/{domain}/history/{id}/revert", "dns", "Revert one recorded DNS change", RevertReq{}, s.h(s.revertChange))
	s.op(r, "GET", "/user/lists", "email", "List the own mailing lists (mlmmj)", nil, s.h(s.listMailingLists))
	s.op(r, "POST", "/user/lists", "email", "Create a mailing list on an own domain", MailingListReq{}, s.h(s.createMailingList))
	s.op(r, "DELETE", "/user/lists/{id}", "email", "Delete an own mailing list", nil, s.h(s.deleteMailingList))
	s.op(r, "GET", "/user/lists/{id}/subscribers", "email", "Subscribers of an own mailing list", nil, s.h(s.listSubscribers))
	s.op(r, "POST", "/user/lists/{id}/subscribers", "email", "Subscribe an address", ListSubReq{}, s.h(s.addSubscriber))
	s.op(r, "DELETE", "/user/lists/{id}/subscribers", "email", "Unsubscribe an address (?address=)", nil, s.h(s.removeSubscriber))
}

// ---- zone state + history -------------------------------------------------

func (s *Server) zoneSets(r *http.Request, zone string) ([]dnsx.RRSet, int64, error) {
	var z rpc.DNSZone
	if err := s.agentCall(r, rpc.MDNSZoneGet, rpc.ZoneRef{Owner: userOf(r).Username, Zone: zone}, &z); err != nil {
		return nil, 0, err
	}
	return dnsx.Group(z.Records), z.Serial, nil
}

// dnsxBefore returns the current rrset (nil = absent or unknown).
func (s *Server) dnsxBefore(r *http.Request, zone, name, typ string) *dnsx.RRSet {
	sets, _, err := s.zoneSets(r, zone)
	if err != nil {
		return nil
	}
	return dnsx.Find(sets, strings.TrimSuffix(name, "."), typ)
}

func normSet(name, typ string, ttl int, recs []string) *dnsx.RRSet {
	if len(recs) == 0 {
		return nil
	}
	out := &dnsx.RRSet{Name: strings.TrimSuffix(strings.ToLower(name), "."), Type: typ, TTL: ttl}
	for _, c := range recs {
		out.Records = append(out.Records, dnsx.Normalize(typ, c))
	}
	return out
}

// dnsxRecord stores one rrset change. History is best effort: a failed
// insert is logged, never turned into a failed DNS change.
func (s *Server) dnsxRecord(r *http.Request, zone, name, typ, action string, before, after *dnsx.RRSet, revertOf int64) int64 {
	bj, _ := json.Marshal(before)
	aj, _ := json.Marshal(after)
	var ro any
	if revertOf > 0 {
		ro = revertOf
	}
	res, err := s.Store.DB.ExecContext(context.WithoutCancel(r.Context()), `INSERT INTO dns_changes(user_id, zone, name, type, action, actor, before_json, after_json, revert_of, created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`, userOf(r).ID, zone, strings.TrimSuffix(name, "."), typ, action, sessionActor(r), string(bj), string(aj), ro, time.Now().Unix())
	if err != nil {
		s.Log.Warn("dns history", "err", err)
		return 0
	}
	id, _ := res.LastInsertId()
	return id
}

func sessionActor(r *http.Request) string {
	if u := userOf(r); u != nil {
		return u.Username
	}
	return ""
}

// dnsxRecordDiff records every rrset that differs between two snapshots.
func (s *Server) dnsxRecordDiff(r *http.Request, zone, action string, before, after []dnsx.RRSet) {
	for _, c := range dnsx.Diff(zone, before, after, "replace") {
		if c.Type == "SOA" {
			continue
		}
		s.dnsxRecord(r, zone, c.Name, c.Type, action, c.Before, c.After, 0)
	}
	// sets present before but protected from Diff's delete (e.g. apex NS)
	for _, b := range before {
		b := b
		if dnsx.Protected(zone, b) && b.Type != "SOA" && dnsx.Find(after, b.Name, b.Type) == nil {
			s.dnsxRecord(r, zone, b.Name, b.Type, action, &b, nil, 0)
		}
	}
}

// applySet makes name/type look like after (nil = delete) via the existing
// rrset agent methods.
func (s *Server) applySet(r *http.Request, zone, name, typ string, after *dnsx.RRSet) error {
	if after == nil || len(after.Records) == 0 {
		return s.agentCall(r, rpc.MDNSRRSetDelete, rpc.RRSetRef{Owner: userOf(r).Username, Zone: zone, Name: name, Type: typ}, nil)
	}
	return s.agentCall(r, rpc.MDNSRRSetReplace, rpc.RRSet{Owner: userOf(r).Username, Zone: zone, Name: name, Type: typ, TTL: after.TTL, Records: after.Records}, nil)
}

// ---- DNSSEC ----------------------------------------------------------------

func (s *Server) dnssecCall(r *http.Request, action string) (rpc.DNSSECStatus, error) {
	var st rpc.DNSSECStatus
	d, err := s.zoneDomain(r)
	if err != nil {
		return st, err
	}
	if err := s.agentCall(r, rpc.MDNSSEC, rpc.DNSSECReq{Owner: userOf(r).Username, Zone: d.Name, Action: action}, &st); err != nil {
		return st, err
	}
	if st.DS == nil {
		st.DS = []string{}
	}
	if st.DNSKEY == nil {
		st.DNSKEY = []string{}
	}
	return st, nil
}

func (s *Server) getDNSSEC(w http.ResponseWriter, r *http.Request) (any, error) {
	return s.dnssecCall(r, "status")
}

func (s *Server) setDNSSEC(w http.ResponseWriter, r *http.Request) (any, error) {
	var in DNSSECReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	act := "disable"
	if in.Enabled {
		act = "enable"
	}
	st, err := s.dnssecCall(r, act)
	if err != nil {
		return nil, err
	}
	if st.Status == "not_installed" {
		return nil, &apiError{Status: 409, Code: "dnssec_not_installed", Message: st.Reason}
	}
	s.audit(r, "dns.dnssec", chi.URLParam(r, "domain"), act, true)
	return st, nil
}

// ---- export / import / check ----------------------------------------------

func (s *Server) exportZone(w http.ResponseWriter, r *http.Request) (any, error) {
	d, err := s.zoneDomain(r)
	if err != nil {
		return nil, err
	}
	var z rpc.DNSZone
	if err := s.agentCall(r, rpc.MDNSZoneGet, rpc.ZoneRef{Owner: userOf(r).Username, Zone: d.Name}, &z); err != nil {
		return nil, err
	}
	return map[string]any{"zone": d.Name, "filename": d.Name + ".zone", "text": dnsx.Export(d.Name, z.Records, z.Serial)}, nil
}

type importPreview struct {
	Changes  []dnsx.Change     `json:"changes"`
	Findings []dnsx.Finding    `json:"findings"`
	Errors   []dnsx.ParseError `json:"errors"`
	Notes    []dnsx.Note       `json:"notes"`
	Count    int               `json:"count"`
	Mode     string            `json:"mode"`
	Applied  int               `json:"applied"`
}

func (s *Server) importPlan(r *http.Request) (store.Domain, ZoneImportReq, importPreview, []dnsx.RRSet, error) {
	var in ZoneImportReq
	var pv importPreview
	if err := decode(r, &in); err != nil {
		return store.Domain{}, in, pv, nil, err
	}
	if in.Mode == "" {
		in.Mode = "merge"
	}
	if in.Mode != "merge" && in.Mode != "replace" {
		return store.Domain{}, in, pv, nil, badField("dnsx_invalid_mode", "mode")
	}
	if len(in.Text) > dnsx.MaxImportBytes {
		return store.Domain{}, in, pv, nil, tooLong("text", dnsx.MaxImportBytes)
	}
	d, err := s.zoneDomain(r)
	if err != nil {
		return d, in, pv, nil, err
	}
	res := dnsx.Parse(d.Name, in.Text)
	cur, _, err := s.zoneSets(r, d.Name)
	if err != nil {
		return d, in, pv, nil, err
	}
	pv = importPreview{Changes: []dnsx.Change{}, Errors: res.Errors, Notes: res.Notes, Count: res.Count, Mode: in.Mode}
	if len(res.Errors) == 0 {
		pv.Changes = dnsx.Diff(d.Name, cur, res.RRSets, in.Mode)
	}
	// checks run on the zone as it would be after the import
	next := cur
	for _, c := range pv.Changes {
		next = dnsx.Apply(next, c.Name, c.Type, c.After)
	}
	pv.Findings = append(res.Warn, dnsx.Check(d.Name, next)...)
	return d, in, pv, cur, nil
}

func (s *Server) previewImport(w http.ResponseWriter, r *http.Request) (any, error) {
	_, _, pv, _, err := s.importPlan(r)
	if err != nil {
		return nil, err
	}
	return pv, nil
}

func (s *Server) applyImport(w http.ResponseWriter, r *http.Request) (any, error) {
	d, in, pv, cur, err := s.importPlan(r)
	if err != nil {
		return nil, err
	}
	if len(pv.Errors) > 0 {
		return nil, badMsg("dnsx_import_invalid", strconv.Itoa(len(pv.Errors))+" error(s); see preview")
	}
	if dnsx.HasErrors(pv.Findings) && !in.Force {
		return nil, conflict("dnsx_check_failed")
	}
	for _, c := range pv.Changes {
		if err := s.applySet(r, d.Name, c.Name, c.Type, c.After); err != nil {
			s.audit(r, "dns.import", d.Name, "partial "+strconv.Itoa(pv.Applied), false)
			return nil, err
		}
		before := dnsx.Find(cur, c.Name, c.Type)
		s.dnsxRecord(r, d.Name, c.Name, c.Type, "import", before, c.After, 0)
		pv.Applied++
	}
	s.audit(r, "dns.import", d.Name, in.Mode+" "+strconv.Itoa(pv.Applied), true)
	return pv, nil
}

func (s *Server) checkZone(w http.ResponseWriter, r *http.Request) (any, error) {
	d, err := s.zoneDomain(r)
	if err != nil {
		return nil, err
	}
	sets, _, err := s.zoneSets(r, d.Name)
	if err != nil {
		return nil, err
	}
	return map[string]any{"findings": dnsx.Check(d.Name, sets)}, nil
}

// ---- history + revert -----------------------------------------------------

type dnsChange struct {
	ID        int64       `json:"id"`
	Zone      string      `json:"zone"`
	Name      string      `json:"name"`
	Type      string      `json:"type"`
	Action    string      `json:"action"`
	Actor     string      `json:"actor"`
	Before    *dnsx.RRSet `json:"before"`
	After     *dnsx.RRSet `json:"after"`
	RevertOf  *int64      `json:"revert_of"`
	CreatedAt int64       `json:"created_at"`
}

func scanChanges(rows *sql.Rows) ([]dnsChange, error) {
	defer rows.Close()
	out := []dnsChange{}
	for rows.Next() {
		var c dnsChange
		var bj, aj string
		var ro sql.NullInt64
		if err := rows.Scan(&c.ID, &c.Zone, &c.Name, &c.Type, &c.Action, &c.Actor, &bj, &aj, &ro, &c.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(bj), &c.Before)
		_ = json.Unmarshal([]byte(aj), &c.After)
		if ro.Valid {
			c.RevertOf = &ro.Int64
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

const changeCols = `id, zone, name, type, action, actor, before_json, after_json, revert_of, created_at`

func (s *Server) zoneHistory(w http.ResponseWriter, r *http.Request) (any, error) {
	d, err := s.zoneDomain(r)
	if err != nil {
		return nil, err
	}
	limit, offset := pageParams(r)
	if limit < 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT `+changeCols+` FROM dns_changes WHERE user_id=? AND zone=? ORDER BY id DESC LIMIT ? OFFSET ?`,
		userOf(r).ID, d.Name, limit, offset)
	if err != nil {
		return nil, err
	}
	items, err := scanChanges(rows)
	if err != nil {
		return nil, err
	}
	return map[string]any{"items": items}, nil
}

func (s *Server) revertChange(w http.ResponseWriter, r *http.Request) (any, error) {
	var in RevertReq
	if r.ContentLength != 0 {
		if err := decode(r, &in); err != nil {
			return nil, err
		}
	}
	d, err := s.zoneDomain(r)
	if err != nil {
		return nil, err
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		return nil, notFound()
	}
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT `+changeCols+` FROM dns_changes WHERE id=? AND user_id=? AND zone=?`, id, userOf(r).ID, d.Name)
	if err != nil {
		return nil, err
	}
	items, err := scanChanges(rows)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, notFound()
	}
	c := items[0]
	if !validate.DNSTypes[c.Type] {
		return nil, bad("dnsx_revert_unsupported")
	}
	sets, _, err := s.zoneSets(r, d.Name)
	if err != nil {
		return nil, err
	}
	now := dnsx.Find(sets, c.Name, c.Type)
	same := (now == nil && c.After == nil) || (now != nil && c.After != nil && now.Equal(*c.After))
	if !same && !in.Force {
		return nil, conflict("dnsx_revert_conflict")
	}
	if err := s.applySet(r, d.Name, c.Name, c.Type, c.Before); err != nil {
		return nil, err
	}
	nid := s.dnsxRecord(r, d.Name, c.Name, c.Type, "revert", now, c.Before, c.ID)
	s.audit(r, "dns.revert", d.Name, strconv.FormatInt(c.ID, 10), true)
	return map[string]any{"reverted": c.ID, "change": nid}, nil
}

// ---- mailing lists (mlmmj) ------------------------------------------------

type mailingList struct {
	ID        int64  `json:"id"`
	DomainID  int64  `json:"domain_id"`
	Domain    string `json:"domain"`
	Name      string `json:"name"`
	Address   string `json:"address"`
	Owner     string `json:"owner"`
	CreatedAt int64  `json:"created_at"`
}

func (s *Server) ownList(r *http.Request) (mailingList, error) {
	var l mailingList
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		return l, notFound()
	}
	err = s.Store.DB.QueryRowContext(r.Context(), `SELECT l.id, l.domain_id, d.name, l.name, l.address, l.owner, l.created_at
		FROM mailing_lists l JOIN domains d ON d.id=l.domain_id WHERE l.id=? AND l.user_id=?`, id, userOf(r).ID).
		Scan(&l.ID, &l.DomainID, &l.Domain, &l.Name, &l.Address, &l.Owner, &l.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return l, notFound()
	}
	return l, err
}

func notInstalled(st rpc.ListStatus) error {
	return &apiError{Status: 409, Code: "mlist_not_installed", Message: st.Reason}
}

func (s *Server) listMailingLists(w http.ResponseWriter, r *http.Request) (any, error) {
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT l.id, l.domain_id, d.name, l.name, l.address, l.owner, l.created_at
		FROM mailing_lists l JOIN domains d ON d.id=l.domain_id WHERE l.user_id=? ORDER BY l.address`, userOf(r).ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []mailingList{}
	for rows.Next() {
		var l mailingList
		if err := rows.Scan(&l.ID, &l.DomainID, &l.Domain, &l.Name, &l.Address, &l.Owner, &l.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return map[string]any{"lists": out}, rows.Err()
}

func (s *Server) createMailingList(w http.ResponseWriter, r *http.Request) (any, error) {
	var in MailingListReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	in.Owner = strings.TrimSpace(in.Owner)
	if err := dnsx.ListName(in.Name); err != nil {
		return nil, badField("dnsx_invalid_list_name", "name")
	}
	if err := maxLen("owner", in.Owner, 254); err != nil {
		return nil, err
	}
	if err := validate.Email(in.Owner); err != nil {
		return nil, badField("invalid_email", "owner")
	}
	d, err := s.ownDomainByName(r, strings.ToLower(strings.TrimSpace(in.Domain)))
	if err != nil {
		return nil, err
	}
	addr := in.Name + "@" + d.Name
	var n int
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM mailboxes WHERE email=?`, addr).Scan(&n)
	var m int
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM mailing_lists WHERE address=?`, addr).Scan(&m)
	if n+m > 0 {
		return nil, conflict("already_exists")
	}
	var st rpc.ListStatus
	if err := s.agentCall(r, rpc.MListApply, rpc.ListReq{User: userOf(r).Username, Domain: d.Name, Name: in.Name, Owner: in.Owner, Action: "create"}, &st); err != nil {
		return nil, err
	}
	if st.Status == "not_installed" {
		return nil, notInstalled(st)
	}
	res, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO mailing_lists(user_id, domain_id, name, address, owner, created_at) VALUES(?,?,?,?,?,?)`,
		userOf(r).ID, d.ID, in.Name, addr, in.Owner, time.Now().Unix())
	if err != nil {
		uctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
		defer cancel()
		_ = s.Agent.Call(uctx, rpc.MListApply, rpc.ListReq{User: userOf(r).Username, Domain: d.Name, Name: in.Name, Action: "delete"}, nil)
		return nil, err
	}
	id, _ := res.LastInsertId()
	s.audit(r, "mlist.create", addr, "", true)
	return mailingList{ID: id, DomainID: d.ID, Domain: d.Name, Name: in.Name, Address: addr, Owner: in.Owner, CreatedAt: time.Now().Unix()}, nil
}

func (s *Server) deleteMailingList(w http.ResponseWriter, r *http.Request) (any, error) {
	l, err := s.ownList(r)
	if err != nil {
		return nil, err
	}
	var st rpc.ListStatus
	err = s.agentCall(r, rpc.MListApply, rpc.ListReq{User: userOf(r).Username, Domain: l.Domain, Name: l.Name, Action: "delete"}, &st)
	var re *rpc.Error
	if err != nil && !(errors.As(err, &re) && re.Code == "not_found") {
		return nil, err
	}
	if st.Status == "not_installed" {
		return nil, notInstalled(st)
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM mailing_lists WHERE id=? AND user_id=?`, l.ID, userOf(r).ID); err != nil {
		return nil, err
	}
	s.audit(r, "mlist.delete", l.Address, "", true)
	return nil, nil
}

func (s *Server) subsCall(r *http.Request, action, addr string) (any, error) {
	l, err := s.ownList(r)
	if err != nil {
		return nil, err
	}
	if action != "list" {
		addr = strings.ToLower(strings.TrimSpace(addr))
		if len(addr) > 254 || validate.Email(addr) != nil {
			return nil, badField("invalid_email", "address")
		}
	}
	var st rpc.ListStatus
	if err := s.agentCall(r, rpc.MListSubs, rpc.ListSubsReq{User: userOf(r).Username, Domain: l.Domain, Name: l.Name, Action: action, Address: addr}, &st); err != nil {
		return nil, err
	}
	if st.Status == "not_installed" {
		if action == "list" {
			return map[string]any{"status": st.Status, "reason": st.Reason, "subscribers": []string{}}, nil
		}
		return nil, notInstalled(st)
	}
	if action != "list" {
		s.audit(r, "mlist."+action, l.Address, "", true)
	}
	if st.Subscribers == nil {
		st.Subscribers = []string{}
	}
	return map[string]any{"status": st.Status, "reason": st.Reason, "subscribers": st.Subscribers}, nil
}

func (s *Server) listSubscribers(w http.ResponseWriter, r *http.Request) (any, error) {
	return s.subsCall(r, "list", "")
}

func (s *Server) addSubscriber(w http.ResponseWriter, r *http.Request) (any, error) {
	var in ListSubReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	return s.subsCall(r, "add", in.Address)
}

func (s *Server) removeSubscriber(w http.ResponseWriter, r *http.Request) (any, error) {
	return s.subsCall(r, "remove", r.URL.Query().Get("address"))
}
