// SPDX-License-Identifier: Apache-2.0

package api

// v1.1 feature parity, admin realm: Mail Queue Manager, Mail Troubleshooter,
// IP Functions (server addresses + dedicated IP per account), Change
// Hostname, Tweak Settings (typed allowlist), PHP extensions (EasyApache-like)
// and the billing (WHMCS) integration catalogue. Every route carries an RBAC
// permission (opPerm); the host work happens in the agent (v11_server.go).

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/events"
	"github.com/cumabozkurt/bpanel/internal/rbac"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

type MailQueueActionReq struct {
	Action string   `json:"action"`
	IDs    []string `json:"ids"`
	All    bool     `json:"all"`
}

type MailTraceReq struct {
	Address string `json:"address"`
}

type HostnameReq struct {
	Hostname string `json:"hostname"`
}

type IPReq struct {
	IP     string `json:"ip"`
	Prefix int    `json:"prefix"`
	Dev    string `json:"dev"`
}

type AccountIPReq struct {
	IP string `json:"ip"` // "" = back to the shared server IP
}

type PHPExtReq struct {
	Install bool `json:"install"`
}

// TweakReq maps setting keys to values; only keys in tweakCatalogue are accepted.
type TweakReq struct {
	Values map[string]string `json:"values"`
}

var (
	reIface       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:@-]{0,14}$`)
	reTweakString = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)
)

// tweak is one Tweak Settings entry.
type tweak struct {
	Key     string   `json:"key"`
	Kind    string   `json:"kind"` // bool | int | enum | string
	Default string   `json:"default"`
	Min     int      `json:"min,omitempty"`
	Max     int      `json:"max,omitempty"`
	Options []string `json:"options,omitempty"`
	Group   string   `json:"group"`
}

// toolFeatures are optional v1.1 tools an administrator can switch off
// server-wide (Tweak Settings). Unlike gatedFeatures they need no install
// profile: switching one off hides and refuses the tool, nothing is removed.
var toolFeatures = []string{"visitors", "email_routing", "boxtrapper", "encryption", "calendars", "ssh_keys",
	"site_publisher", "images", "pg_browser", "cloudflare", "leech_protection"}

var tweakCatalogue = func() []tweak {
	t := []tweak{
		{Key: "leech_sweep_minutes", Kind: "int", Default: "10", Min: 5, Max: 1440, Group: "security"},
		{Key: "visitors_default_days", Kind: "int", Default: "7", Min: 1, Max: 31, Group: "stats"},
		{Key: "boxtrapper_default_folder", Kind: "string", Default: "BoxTrapper", Group: "mail"},
		{Key: "mail_queue_page_size", Kind: "int", Default: "500", Min: 50, Max: 5000, Group: "mail"},
		{Key: "default_lang", Kind: "enum", Default: "en", Options: []string{"en", "tr"}, Group: "general"},
	}
	for _, f := range toolFeatures {
		t = append(t, tweak{Key: "feature_" + f, Kind: "bool", Default: "1", Group: "tools"})
	}
	return t
}()

func (s *Server) tweakInt(key string, def int) int {
	for _, t := range tweakCatalogue {
		if t.Key == key {
			if n, err := strconv.Atoi(s.Store.Get(key, t.Default)); err == nil && n >= t.Min && n <= t.Max {
				return n
			}
		}
	}
	return def
}

func (s *Server) mountV11Admin(r chi.Router) {
	s.opPerm(r, rbac.MailQueueRead, "GET", "/admin/mail-queue", "mail", "Mail Queue Manager: queued messages (?q= filters sender/recipient/id)", nil, s.h(s.mailQueueList))
	s.opPerm(r, rbac.MailQueueRead, "GET", "/admin/mail-queue/{qid}", "mail", "Mail Queue Manager: headers and body of one message (bounded)", nil, s.h(s.mailQueueShow))
	s.opPerm(r, rbac.MailQueueWrite, "POST", "/admin/mail-queue/action", "mail", "Mail Queue Manager: delete, hold, release, requeue, deliver or flush", MailQueueActionReq{}, s.h(s.mailQueueAction))
	s.opPerm(r, rbac.MailQueueRead, "GET", "/admin/mail-troubleshooter", "mail", "Mail Troubleshooter: trace how Postfix would route an address (?address=)", nil, s.h(s.mailTroubleshoot))

	s.opPerm(r, rbac.NetworkRead, "GET", "/admin/ips", "server", "IP Functions: interfaces, addresses and dedicated IP assignments", nil, s.h(s.ipList))
	s.opPermReauth(r, rbac.NetworkWrite, "POST", "/admin/ips", "server", "IP Functions: add an address to an interface (persistent)", IPReq{}, s.h(s.ipAdd))
	s.opPermReauth(r, rbac.NetworkWrite, "POST", "/admin/ips/remove", "server", "IP Functions: remove a panel-added address", IPReq{}, s.h(s.ipRemove))
	s.opPerm(r, rbac.NetworkWrite, "PUT", "/admin/accounts/{id}/ip", "server", "Assign a dedicated IP to an account (DNS A records follow)", AccountIPReq{}, s.h(s.accountIPSet))
	s.opPermReauth(r, rbac.NetworkWrite, "PUT", "/admin/hostname", "server", "Change Hostname (system, /etc/hosts, Postfix, panel config)", HostnameReq{}, s.h(s.hostnameSet))

	s.opPerm(r, rbac.ServerRead, "GET", "/admin/tweak-settings", "server", "Tweak Settings: typed settings with defaults and current values", nil, s.h(s.tweakGet))
	s.opPermReauth(r, rbac.ServerWrite, "PUT", "/admin/tweak-settings", "server", "Tweak Settings: change allowlisted settings", TweakReq{}, s.h(s.tweakPut))

	s.opPerm(r, rbac.SoftwareRead, "GET", "/admin/php/{version}/extensions", "server", "PHP extensions (EasyApache-like) of one installed PHP version", nil, s.h(s.phpExtList))
	s.opPerm(r, rbac.SoftwareWrite, "PUT", "/admin/php/{version}/extensions/{ext}", "server", "Install or remove one allowlisted PHP extension", PHPExtReq{}, s.h(s.phpExtSet))

	s.opPerm(r, rbac.WebhooksRead, "GET", "/admin/billing", "webhooks", "Billing (WHMCS) integration: lifecycle events and provisioning endpoints", nil, s.h(s.billingInfo))
}

// ---- mail queue -------------------------------------------------------------------------

func (s *Server) mailQueueList(w http.ResponseWriter, r *http.Request) (any, error) {
	var out rpc.MailQueueListResult
	if err := s.agentCall(r, rpc.MMailQueueList, rpc.MailQueueListParams{Limit: s.tweakInt("mail_queue_page_size", 500)}, &out); err != nil {
		return nil, err
	}
	if q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q"))); q != "" {
		keep := out.Messages[:0]
		for _, m := range out.Messages {
			hit := strings.Contains(strings.ToLower(m.ID+" "+m.Sender), q)
			for _, rc := range m.Recipients {
				hit = hit || strings.Contains(strings.ToLower(rc.Address), q)
			}
			if hit {
				keep = append(keep, m)
			}
		}
		out.Messages = keep
	}
	if out.Messages == nil {
		out.Messages = []rpc.QueueMsg{}
	}
	return out, nil
}

func (s *Server) mailQueueShow(w http.ResponseWriter, r *http.Request) (any, error) {
	var out rpc.MailQueueShowResult
	if err := s.agentCall(r, rpc.MMailQueueShow, rpc.MailQueueShowParams{ID: chi.URLParam(r, "qid")}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Server) mailQueueAction(w http.ResponseWriter, r *http.Request) (any, error) {
	var in MailQueueActionReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	switch in.Action {
	case "delete", "hold", "release", "requeue", "deliver", "flush":
	default:
		return nil, badField("invalid_queue_action", "action")
	}
	if in.Action != "flush" && !in.All && len(in.IDs) == 0 {
		return nil, badField("queue_ids_required", "ids")
	}
	if len(in.IDs) > 5000 {
		return nil, badField("too_many_ids", "ids")
	}
	var out rpc.MailQueueActionResult
	err := s.agentCall(r, rpc.MMailQueueAction, rpc.MailQueueActionParams{Action: in.Action, IDs: in.IDs, All: in.All}, &out)
	detail := in.Action + " " + strconv.Itoa(len(in.IDs))
	if in.All {
		detail = in.Action + " all"
	}
	s.audit(r, "mailqueue.action", "", detail, err == nil)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// lookupTXT is a variable for tests.
var lookupTXT = net.DefaultResolver.LookupTXT

func (s *Server) mailTroubleshoot(w http.ResponseWriter, r *http.Request) (any, error) {
	in := MailTraceReq{Address: strings.ToLower(strings.TrimSpace(r.URL.Query().Get("address")))}
	if err := validate.Email(in.Address); err != nil {
		if validate.Domain(in.Address) != nil {
			return nil, badField("invalid_email", "address")
		}
		in.Address = "postmaster@" + in.Address
	}
	var out rpc.MailTraceResult
	if err := s.agentCall(r, rpc.MMailTrace, rpc.MailTraceParams{Address: in.Address}, &out); err != nil {
		return nil, err
	}
	dom := in.Address[strings.LastIndexByte(in.Address, '@')+1:]
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	dns := []rpc.TraceStep{}
	if mx, err := lookupMX(ctx, dom); err != nil || len(mx) == 0 {
		dns = append(dns, rpc.TraceStep{Check: "dns_mx", Result: "fail", Detail: "no MX record"})
	} else {
		hs := []string{}
		for _, m := range mx {
			hs = append(hs, strconv.Itoa(int(m.Pref))+" "+strings.TrimSuffix(m.Host, "."))
		}
		res := "info"
		if local, _ := s.mxIsLocal(ctx, dom); local {
			res = "pass"
		}
		dns = append(dns, rpc.TraceStep{Check: "dns_mx", Result: res, Detail: strings.Join(hs, ", ")})
	}
	spf, dmarc := "", ""
	if txt, err := lookupTXT(ctx, dom); err == nil {
		for _, t := range txt {
			if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
				spf = t
			}
		}
	}
	if txt, err := lookupTXT(ctx, "_dmarc."+dom); err == nil {
		for _, t := range txt {
			if strings.HasPrefix(strings.ToUpper(t), "V=DMARC1") {
				dmarc = t
			}
		}
	}
	dns = append(dns, stepOf("dns_spf", spf), stepOf("dns_dmarc", dmarc))
	out.Steps = append(out.Steps, dns...)
	return out, nil
}

func stepOf(check, v string) rpc.TraceStep {
	if v == "" {
		return rpc.TraceStep{Check: check, Result: "fail", Detail: "missing"}
	}
	return rpc.TraceStep{Check: check, Result: "pass", Detail: v}
}

// ---- IP functions ---------------------------------------------------------------------

func (s *Server) ipList(w http.ResponseWriter, r *http.Request) (any, error) {
	var out rpc.NetIPsResult
	if err := s.agentCall(r, rpc.MNetIPs, struct{}{}, &out); err != nil {
		return nil, err
	}
	type assign struct {
		UserID   int64  `json:"user_id"`
		Username string `json:"username"`
		IP       string `json:"ip"`
	}
	as := []assign{}
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT a.user_id, u.username, a.ip FROM account_ips a JOIN users u ON u.id=a.user_id ORDER BY a.ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var a assign
		if rows.Scan(&a.UserID, &a.Username, &a.IP) == nil {
			as = append(as, a)
		}
	}
	return map[string]any{"interfaces": out.Interfaces, "server_ip": s.serverIP(), "assignments": as}, nil
}

func ipParams(in IPReq) (rpc.NetIPParams, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(in.IP))
	if err != nil || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a.Zone() != "" {
		return rpc.NetIPParams{}, badField("invalid_ip", "ip")
	}
	maxp := 32
	if a.Is6() {
		maxp = 128
	}
	if in.Prefix == 0 {
		in.Prefix = maxp
	}
	if in.Prefix < 8 || in.Prefix > maxp {
		return rpc.NetIPParams{}, badField("invalid_prefix", "prefix")
	}
	if !reIface.MatchString(in.Dev) || in.Dev == "lo" {
		return rpc.NetIPParams{}, badField("invalid_interface", "dev")
	}
	return rpc.NetIPParams{IP: a.String(), Prefix: in.Prefix, Dev: in.Dev}, nil
}

func (s *Server) ipAdd(w http.ResponseWriter, r *http.Request) (any, error) {
	var in IPReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	p, err := ipParams(in)
	if err != nil {
		return nil, err
	}
	err = s.agentCall(r, rpc.MNetIPAdd, p, nil)
	s.audit(r, "ip.add", p.IP, strconv.Itoa(p.Prefix)+" "+p.Dev, err == nil)
	if err != nil {
		return nil, err
	}
	return s.ipList(w, r)
}

func (s *Server) ipRemove(w http.ResponseWriter, r *http.Request) (any, error) {
	var in IPReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	p, err := ipParams(in)
	if err != nil {
		return nil, err
	}
	if p.IP == s.serverIP() {
		return nil, conflict("ip_is_server_ip")
	}
	var n int
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM account_ips WHERE ip=?`, p.IP).Scan(&n)
	if n > 0 {
		return nil, conflict("ip_in_use")
	}
	err = s.agentCall(r, rpc.MNetIPRemove, p, nil)
	s.audit(r, "ip.remove", p.IP, "", err == nil)
	if err != nil {
		return nil, err
	}
	return s.ipList(w, r)
}

// accountIP is the address an account's DNS A records point at.
func (s *Server) accountIP(ctx context.Context, uid int64) string {
	var ip string
	if s.Store.DB.QueryRowContext(ctx, `SELECT ip FROM account_ips WHERE user_id=?`, uid).Scan(&ip) == nil && ip != "" {
		return ip
	}
	return s.serverIP()
}

func (s *Server) accountIPSet(w http.ResponseWriter, r *http.Request) (any, error) {
	u, err := s.visibleAccount(r)
	if err != nil {
		return nil, err
	}
	var in AccountIPReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	ip := strings.TrimSpace(in.IP)
	if ip != "" {
		a, err := netip.ParseAddr(ip)
		if err != nil || !a.Is4() {
			return nil, badField("invalid_ip", "ip")
		}
		ip = a.String()
		// the address must be configured on this server
		var nets rpc.NetIPsResult
		if err := s.agentCall(r, rpc.MNetIPs, struct{}{}, &nets); err != nil {
			return nil, err
		}
		found := ip == s.serverIP()
		for _, ifc := range nets.Interfaces {
			for _, ad := range ifc.Addrs {
				found = found || ad.IP == ip
			}
		}
		if !found {
			return nil, badMsg("ip_not_configured", ip+" is not configured on this server (IP Functions)")
		}
		var other int
		_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM account_ips WHERE ip=? AND user_id<>?`, ip, u.ID).Scan(&other)
		if other > 0 && ip != s.serverIP() {
			return nil, conflict("ip_in_use")
		}
		if _, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO account_ips(user_id,ip,updated_at) VALUES(?,?,?)
			ON CONFLICT(user_id) DO UPDATE SET ip=excluded.ip, updated_at=excluded.updated_at`, u.ID, ip, s.Now().Unix()); err != nil {
			return nil, err
		}
	} else if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM account_ips WHERE user_id=?`, u.ID); err != nil {
		return nil, err
	}
	target := s.accountIP(r.Context(), u.ID)
	warnings := []Warning{}
	if s.featureOn("dns") {
		doms, err := s.domainsOf(r.Context(), u.ID)
		if err != nil {
			return nil, err
		}
		for _, d := range doms {
			if d.Kind == "alias" {
				continue
			}
			zone := d.Name
			if d.Kind == "sub" && d.ParentName != "" {
				zone = d.ParentName
			}
			if err := s.Agent.Call(r.Context(), rpc.MDNSRRSetReplace, rpc.RRSet{Owner: u.Username, Zone: zone, Name: d.Name, Type: "A", TTL: 3600, Records: []string{target}}, nil); err != nil {
				warnings = append(warnings, warn(WarnDNSSetupFailed, "dns", d.Name+": "+agentCode(err)))
			}
		}
	}
	s.audit(r, "account.ip", u.Username, target, true)
	events.Publish(r.Context(), events.Event{Type: "account.ip_changed", Severity: events.Info, AccountID: u.ID, Data: map[string]any{"ip": target}})
	return map[string]any{"ip": target, "dedicated": ip != "", "warnings": warnings}, nil
}

// ---- hostname -------------------------------------------------------------------------

func (s *Server) hostnameSet(w http.ResponseWriter, r *http.Request) (any, error) {
	var in HostnameReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Hostname), "."))
	if validate.Domain(h) != nil || strings.Count(h, ".") < 1 {
		return nil, badField("invalid_hostname", "hostname")
	}
	var out rpc.SysHostnameResult
	err := s.agentCall(r, rpc.MSysHostname, rpc.SysHostnameParams{Hostname: h}, &out)
	s.audit(r, "server.hostname", h, out.Previous, err == nil)
	if err != nil {
		return nil, err
	}
	events.Publish(r.Context(), events.Event{Type: "server.hostname_changed", Severity: events.Warning, Data: map[string]any{"from": out.Previous, "to": h}})
	return map[string]any{"previous": out.Previous, "hostname": out.Hostname, "steps": out.Steps,
		"restart_required": true, "note": "restart bpanel-api (and reissue the panel certificate) to serve the new name"}, nil
}

// ---- tweak settings ---------------------------------------------------------------------

func (s *Server) tweakGet(w http.ResponseWriter, r *http.Request) (any, error) {
	type item struct {
		tweak
		Value string `json:"value"`
	}
	out := []item{}
	for _, t := range tweakCatalogue {
		out = append(out, item{tweak: t, Value: s.Store.Get(t.Key, t.Default)})
	}
	return map[string]any{"settings": out}, nil
}

func (t tweak) check(v string) bool {
	switch t.Kind {
	case "bool":
		return v == "0" || v == "1"
	case "int":
		n, err := strconv.Atoi(v)
		return err == nil && n >= t.Min && n <= t.Max
	case "enum":
		for _, o := range t.Options {
			if o == v {
				return true
			}
		}
		return false
	}
	return reTweakString.MatchString(v)
}

func (s *Server) tweakPut(w http.ResponseWriter, r *http.Request) (any, error) {
	var in TweakReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if len(in.Values) == 0 {
		return nil, bad("nothing_to_change")
	}
	byKey := map[string]tweak{}
	for _, t := range tweakCatalogue {
		byKey[t.Key] = t
	}
	keys := make([]string, 0, len(in.Values))
	for k, v := range in.Values {
		t, ok := byKey[k]
		if !ok {
			return nil, badField("unknown_setting", k)
		}
		if !t.check(strings.TrimSpace(v)) {
			return nil, badField("invalid_setting", k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := s.Store.Set(k, strings.TrimSpace(in.Values[k])); err != nil {
			return nil, err
		}
	}
	s.audit(r, "settings.tweak", "", strings.Join(keys, ","), true)
	return s.tweakGet(w, r)
}

// ---- PHP extensions ----------------------------------------------------------------------

func (s *Server) phpExtList(w http.ResponseWriter, r *http.Request) (any, error) {
	v := chi.URLParam(r, "version")
	if validate.PHPVersion(v) != nil {
		return nil, badField("invalid_php_version", "version")
	}
	var out rpc.PHPExtListResult
	if err := s.agentCall(r, rpc.MPHPExtList, rpc.PHPExtListParams{Version: v}, &out); err != nil {
		return nil, err
	}
	if out.Extensions == nil {
		out.Extensions = []rpc.PHPExt{}
	}
	return out, nil
}

func (s *Server) phpExtSet(w http.ResponseWriter, r *http.Request) (any, error) {
	v, ext := chi.URLParam(r, "version"), chi.URLParam(r, "ext")
	if validate.PHPVersion(v) != nil {
		return nil, badField("invalid_php_version", "version")
	}
	var in PHPExtReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	var out rpc.PHPExtSetResult
	err := s.agentCall(r, rpc.MPHPExtSet, rpc.PHPExtSetParams{Version: v, Ext: ext, Install: in.Install}, &out)
	if in.Install {
		s.audit(r, "php.ext_install", v+"/"+ext, "", err == nil)
	} else {
		s.audit(r, "php.ext_remove", v+"/"+ext, "", err == nil)
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ---- billing (WHMCS) -----------------------------------------------------------------------

// BillingEvents are the account lifecycle events published for billing
// systems (webhook subscriptions; docs/integrations/whmcs.md).
var BillingEvents = []string{"account.created", "account.suspended", "account.unsuspended", "account.terminated",
	"account.package_changed", "account.password_changed", "account.ip_changed", "account.primary_domain_changed"}

func (s *Server) billingInfo(w http.ResponseWriter, r *http.Request) (any, error) {
	return map[string]any{
		"events": BillingEvents,
		"provisioning": []map[string]string{
			{"action": "CreateAccount", "method": "POST", "path": "/api/v1/admin/accounts"},
			{"action": "SuspendAccount", "method": "POST", "path": "/api/v1/admin/accounts/{id}/suspend"},
			{"action": "UnsuspendAccount", "method": "POST", "path": "/api/v1/admin/accounts/{id}/unsuspend"},
			{"action": "TerminateAccount", "method": "DELETE", "path": "/api/v1/admin/accounts/{id}"},
			{"action": "ChangePackage", "method": "PUT", "path": "/api/v1/admin/accounts/{id}/package"},
			{"action": "ChangePassword", "method": "POST", "path": "/api/v1/admin/accounts/{id}/password"},
			{"action": "LoginLink", "method": "POST", "path": "/api/v1/admin/accounts/{id}/login"},
			{"action": "UsageUpdate", "method": "GET", "path": "/api/v1/admin/accounts"},
		},
		"docs":    "docs/integrations/whmcs.md",
		"example": "examples/whmcs/modules/servers/bpanel/bpanel.php",
	}, nil
}

// billingEvent publishes an account lifecycle event (BillingEvents) for
// webhook subscribers such as a WHMCS hook receiver.
func (s *Server) billingEvent(r *http.Request, typ string, uid int64, username string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["username"] = username
	events.Publish(r.Context(), events.Event{Type: typ, Severity: events.Info, AccountID: uid, Data: data})
}
