// SPDX-License-Identifier: Apache-2.0

package agent

// v1.1 server tools: Mail Queue Manager, Mail Troubleshooter, Radicale
// status, Change Hostname, IP Functions and the PHP extension manager.
// All are server-level (gateExempt); every argument is validated before it
// reaches an argv (no shell anywhere).

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/distro"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

var (
	reQueueID = regexp.MustCompile(`^[A-Za-z0-9]{5,20}$`)
	reDev     = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
	// v11Cmd runs a command (replaced in tests).
	v11Cmd = func(ctx context.Context, stdin []byte, argv ...string) (string, error) {
		return run(ctx, stdin, argv...)
	}
	// IPsConf persists panel-added addresses ("ip/prefix dev" lines);
	// bpanel-ips.service re-adds them at boot.
	IPsConf      = "/etc/bpanel/ips.conf"
	ipsUnitPath  = "/etc/systemd/system/bpanel-ips.service"
	hostsFile    = "/etc/hosts"
	hostnameFile = "/etc/hostname"
	sethostname  = func(h string) error { return syscall.Sethostname([]byte(h)) }
	// APIConfigPath is the API configuration whose "hostname" follows a change.
	APIConfigPath = "/etc/bpanel/api.json"
)

func init() {
	for m, why := range map[string]string{
		rpc.MMailQueueList:   "server (read-only postqueue -j)",
		rpc.MMailQueueAction: "server (postsuper/postqueue on validated queue ids)",
		rpc.MMailQueueShow:   "server (postcat -q of one validated queue id, bounded)",
		rpc.MMailTrace:       "server (postmap -q lookups of one validated address)",
		rpc.MDavStatus:       "server (Radicale presence and unit state)",
		rpc.MSysHostname:     "server (hostname; validated FQDN)",
		rpc.MNetIPs:          "server (read-only interface list)",
		rpc.MNetIPAdd:        "server (ip addr add of a validated address)",
		rpc.MNetIPRemove:     "server (ip addr del of a panel-added address)",
		rpc.MPHPExtList:      "server (read-only package query)",
		rpc.MPHPExtSet:       "server (install/remove one allowlisted PHP extension package)",
	} {
		gateExempt[m] = why
	}
}

func (a *Agent) v11ServerRoutes() map[string]handler {
	return map[string]handler{
		rpc.MMailQueueList: bind(a.mailQueueList), rpc.MMailQueueAction: bind(a.mailQueueAction), rpc.MMailQueueShow: bind(a.mailQueueShow),
		rpc.MMailTrace: bind(a.mailTrace), rpc.MDavStatus: bind(a.davStatus), rpc.MSysHostname: bind(a.sysHostname),
		rpc.MNetIPs: bind(a.netIPs), rpc.MNetIPAdd: bind(a.netIPAdd), rpc.MNetIPRemove: bind(a.netIPRemove),
		rpc.MPHPExtList: bind(a.phpExtList), rpc.MPHPExtSet: bind(a.phpExtSet),
	}
}

// ---- mail queue -----------------------------------------------------------------

type pqJSON struct {
	Queue      string `json:"queue_name"`
	ID         string `json:"queue_id"`
	Arrival    int64  `json:"arrival_time"`
	Size       int64  `json:"message_size"`
	Sender     string `json:"sender"`
	Recipients []struct {
		Address string `json:"address"`
		Reason  string `json:"delay_reason"`
	} `json:"recipients"`
}

// ParsePostqueueJSON parses `postqueue -j` (one JSON object per line).
func ParsePostqueueJSON(out string, limit int) (int, []rpc.QueueMsg) {
	msgs := []rpc.QueueMsg{}
	total := 0
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var q pqJSON
		if json.Unmarshal(sc.Bytes(), &q) != nil || !reQueueID.MatchString(q.ID) {
			continue
		}
		total++
		if len(msgs) >= limit {
			continue
		}
		m := rpc.QueueMsg{ID: q.ID, Queue: q.Queue, Sender: q.Sender, Size: q.Size, Arrival: q.Arrival, Recipients: []rpc.QueueRcpt{}}
		for _, r := range q.Recipients {
			m.Recipients = append(m.Recipients, rpc.QueueRcpt{Address: r.Address, Reason: r.Reason})
		}
		msgs = append(msgs, m)
	}
	sort.SliceStable(msgs, func(i, j int) bool { return msgs[i].Arrival > msgs[j].Arrival })
	return total, msgs
}

func (a *Agent) mailQueueList(ctx context.Context, p rpc.MailQueueListParams) (rpc.MailQueueListResult, error) {
	if !v11Have("postqueue") {
		return rpc.MailQueueListResult{Status: "not_installed", Reason: "Postfix (postqueue) is not installed", Messages: []rpc.QueueMsg{}}, nil
	}
	limit := p.Limit
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	out, err := v11Cmd(ctx, nil, "postqueue", "-j")
	if err != nil {
		return rpc.MailQueueListResult{}, errf("action_failed", "postqueue -j failed")
	}
	total, msgs := ParsePostqueueJSON(out, limit)
	return rpc.MailQueueListResult{Status: "ok", Total: total, Messages: msgs}, nil
}

func (a *Agent) mailQueueAction(ctx context.Context, p rpc.MailQueueActionParams) (rpc.MailQueueActionResult, error) {
	if !v11Have("postsuper") {
		return rpc.MailQueueActionResult{Status: "not_installed"}, nil
	}
	if len(p.IDs) > 1000 {
		return rpc.MailQueueActionResult{}, errf("bad_params", "too many ids")
	}
	for _, id := range p.IDs {
		if !reQueueID.MatchString(id) {
			return rpc.MailQueueActionResult{}, errf("bad_params", "invalid queue id")
		}
	}
	if !p.All && len(p.IDs) == 0 && p.Action != "flush" {
		return rpc.MailQueueActionResult{}, errf("bad_params", "no messages selected")
	}
	flag := map[string]string{"delete": "-d", "hold": "-h", "release": "-H", "requeue": "-r"}[p.Action]
	var out string
	var err error
	switch {
	case p.Action == "flush":
		out, err = v11Cmd(ctx, nil, "postqueue", "-f")
	case p.Action == "deliver":
		for _, id := range p.IDs {
			o, e := v11Cmd(ctx, nil, "postqueue", "-i", id)
			out += o
			if e != nil {
				err = e
			}
		}
	case flag == "":
		return rpc.MailQueueActionResult{}, errf("bad_params", "unknown action")
	case p.All:
		out, err = v11Cmd(ctx, nil, "postsuper", flag, "ALL")
	default:
		out, err = v11Cmd(ctx, []byte(strings.Join(p.IDs, "\n")+"\n"), "postsuper", flag, "-")
	}
	if err != nil {
		return rpc.MailQueueActionResult{}, errf("action_failed", "%s", lastLines(err.Error(), 2))
	}
	n := len(p.IDs)
	if m := regexp.MustCompile(`(\d+) messages?`).FindStringSubmatch(out); m != nil {
		fmt.Sscanf(m[1], "%d", &n)
	}
	return rpc.MailQueueActionResult{Status: "ok", Affected: n, Output: tail(out)}, nil
}

func (a *Agent) mailQueueShow(ctx context.Context, p rpc.MailQueueShowParams) (rpc.MailQueueShowResult, error) {
	if !reQueueID.MatchString(p.ID) {
		return rpc.MailQueueShowResult{}, errf("bad_params", "invalid queue id")
	}
	if !v11Have("postcat") {
		return rpc.MailQueueShowResult{Status: "not_installed"}, nil
	}
	out, err := v11Cmd(ctx, nil, "postcat", "-hb", "-q", p.ID)
	if err != nil {
		return rpc.MailQueueShowResult{}, errf("not_found", "%s", p.ID)
	}
	res := rpc.MailQueueShowResult{Status: "ok", Text: out}
	if len(out) > 128<<10 {
		res.Text, res.Truncated = out[:128<<10], true
	}
	return res, nil
}

// ---- mail troubleshooter ------------------------------------------------------------

func (a *Agent) postmapQ(ctx context.Context, key, mp string) (string, bool) {
	out, err := v11Cmd(ctx, nil, "postmap", "-q", key, mp)
	return strings.TrimSpace(out), err == nil && strings.TrimSpace(out) != ""
}

func (a *Agent) mailTrace(ctx context.Context, p rpc.MailTraceParams) (rpc.MailTraceResult, error) {
	local, domain, err := splitEmail(strings.ToLower(strings.TrimSpace(p.Address)))
	if err != nil {
		return rpc.MailTraceResult{}, err
	}
	addr := local + "@" + domain
	if !v11Have("postmap") || !v11Have("postconf") {
		return rpc.MailTraceResult{Status: "not_installed", Reason: "Postfix is not installed", Steps: []rpc.TraceStep{}}, nil
	}
	conf := func(k string) string {
		o, _ := v11Cmd(ctx, nil, "postconf", "-h", k)
		return strings.TrimSpace(o)
	}
	maps := func(v string) []string {
		var out []string
		for _, m := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			if strings.Contains(m, ":") && !strings.HasPrefix(m, "$") {
				out = append(out, m)
			}
		}
		return out
	}
	steps := []rpc.TraceStep{}
	add := func(check, result, detail string) {
		steps = append(steps, rpc.TraceStep{Check: check, Result: result, Detail: detail})
	}
	// 1. domain class
	local1 := false
	for _, m := range maps(conf("virtual_mailbox_domains")) {
		if _, ok := a.postmapQ(ctx, domain, m); ok {
			local1 = true
			add("virtual_mailbox_domains", "pass", domain+" is hosted here ("+m+")")
		}
	}
	if !local1 {
		add("virtual_mailbox_domains", "info", domain+" is not a local mail domain: mail is relayed to its MX hosts")
	}
	// 2. reject list
	for _, m := range maps(conf("smtpd_recipient_restrictions")) {
		if v, ok := a.postmapQ(ctx, addr, m); ok {
			add("recipient access", "fail", addr+" -> "+v)
		}
	}
	// 3. aliases / forwarders (exact, then catch-all)
	aliased := false
	for _, m := range maps(conf("virtual_alias_maps")) {
		for _, k := range []string{addr, "@" + domain} {
			if v, ok := a.postmapQ(ctx, k, m); ok {
				aliased = true
				add("virtual_alias_maps", "pass", k+" -> "+v)
			}
		}
	}
	// 4. mailbox
	boxed := false
	for _, m := range maps(conf("virtual_mailbox_maps")) {
		if v, ok := a.postmapQ(ctx, addr, m); ok {
			boxed = true
			add("virtual_mailbox_maps", "pass", addr+" -> mailbox "+v)
		}
	}
	if local1 && !boxed && !aliased {
		add("recipient", "fail", addr+" has no mailbox, forwarder or catch-all: Postfix rejects it (550 user unknown)")
	} else if local1 && !boxed {
		add("virtual_mailbox_maps", "info", "no mailbox: delivery follows the alias above")
	}
	// 5. transport
	tr := ""
	for _, m := range maps(conf("transport_maps")) {
		for _, k := range []string{addr, domain} {
			if v, ok := a.postmapQ(ctx, k, m); ok && tr == "" {
				tr = v
				add("transport_maps", "info", k+" -> "+v)
			}
		}
	}
	switch {
	case tr != "":
	case local1:
		add("transport", "pass", "delivered locally via "+conf("virtual_transport"))
	default:
		add("transport", "info", "default transport "+conf("default_transport"))
	}
	return rpc.MailTraceResult{Status: "ok", Steps: steps}, nil
}

// ---- hostname ------------------------------------------------------------------------

// RewriteHosts replaces old with new in /etc/hosts (word match) or adds
// "127.0.1.1 new short" when neither is present.
func RewriteHosts(orig, old, nw string) string {
	short := strings.SplitN(nw, ".", 2)[0]
	lines := strings.Split(strings.TrimRight(orig, "\n"), "\n")
	found := false
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		f := strings.Fields(l)
		changed := false
		for j := 1; j < len(f); j++ {
			if old != "" && f[j] == old {
				f[j], changed = nw, true
			} else if old != "" && f[j] == strings.SplitN(old, ".", 2)[0] && old != short {
				f[j], changed = short, true
			}
			if f[j] == nw {
				found = true
			}
		}
		if changed {
			lines[i] = strings.Join(f, " ")
		}
	}
	if !found {
		lines = append(lines, "127.0.1.1 "+nw+" "+short)
	}
	return strings.Join(lines, "\n") + "\n"
}

func (a *Agent) sysHostname(ctx context.Context, p rpc.SysHostnameParams) (rpc.SysHostnameResult, error) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Hostname), "."))
	if validate.Domain(h) != nil || strings.Count(h, ".") < 1 || len(h) > 253 {
		return rpc.SysHostnameResult{}, errf("invalid_hostname", "a fully qualified host name is required")
	}
	defer a.lock("hostname")()
	prev, _ := os.Hostname()
	res := rpc.SysHostnameResult{Previous: prev, Hostname: h, Steps: []string{}}
	if !a.Cfg.NoSystemd && v11Have("hostnamectl") {
		if _, err := v11Cmd(ctx, nil, "hostnamectl", "set-hostname", h); err != nil {
			return res, errf("action_failed", "hostnamectl: %s", lastLines(err.Error(), 2))
		}
		res.Steps = append(res.Steps, "hostnamectl set-hostname")
	} else {
		if err := writeAtomic(hostnameFile, []byte(h+"\n"), 0o644, -1, -1); err != nil {
			return res, errf("action_failed", "write %s", hostnameFile)
		}
		if err := sethostname(h); err != nil {
			res.Steps = append(res.Steps, "sethostname: "+err.Error())
		} else {
			res.Steps = append(res.Steps, hostnameFile+" + sethostname")
		}
	}
	if b, err := os.ReadFile(hostsFile); err == nil {
		if nb := RewriteHosts(string(b), prev, h); nb != string(b) {
			if err := writeAtomic(hostsFile, []byte(nb), 0o644, -1, -1); err == nil {
				res.Steps = append(res.Steps, hostsFile)
			}
		}
	}
	if v11Have("postconf") {
		if _, err := v11Cmd(ctx, nil, "postconf", "-e", "myhostname="+h); err == nil {
			res.Steps = append(res.Steps, "postfix myhostname")
			if !a.Cfg.NoSystemd {
				_ = a.systemctl(ctx, "reload", "postfix")
			}
		}
	}
	if b, err := os.ReadFile(APIConfigPath); err == nil {
		var m map[string]any
		if json.Unmarshal(b, &m) == nil {
			m["hostname"] = h
			if nb, err := json.MarshalIndent(m, "", "  "); err == nil {
				uid, gid := keepOwner(APIConfigPath, 0, -1)
				if err := writeAtomic(APIConfigPath, append(nb, '\n'), 0o640, uid, gid); err == nil {
					res.Steps = append(res.Steps, APIConfigPath)
				}
			}
		}
	}
	a.Cfg.Hostname = h
	return res, nil
}

// ---- IP functions ------------------------------------------------------------------

func scopeOf(ip netip.Addr) string {
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast():
		return "link"
	case ip.IsPrivate():
		return "private"
	}
	return "global"
}

func readIPsConf() []string {
	b, _ := os.ReadFile(IPsConf)
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func (a *Agent) netIPs(ctx context.Context, _ struct{}) (rpc.NetIPsResult, error) {
	managed := map[string]bool{}
	for _, l := range readIPsConf() {
		if f := strings.Fields(l); len(f) == 2 {
			if pf, err := netip.ParsePrefix(f[0]); err == nil {
				managed[pf.Addr().String()] = true
			}
		}
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return rpc.NetIPsResult{}, errf("action_failed", "interfaces: %v", err)
	}
	out := rpc.NetIPsResult{Interfaces: []rpc.NetIface{}}
	for _, i := range ifs {
		ni := rpc.NetIface{Name: i.Name, Up: i.Flags&net.FlagUp != 0, MAC: i.HardwareAddr.String(), Addrs: []rpc.NetAddr{}}
		as, _ := i.Addrs()
		for _, ad := range as {
			pn, ok := ad.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(pn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			ones, _ := pn.Mask.Size()
			fam := "ipv6"
			if ip.Is4() {
				fam = "ipv4"
			}
			ni.Addrs = append(ni.Addrs, rpc.NetAddr{IP: ip.String(), Prefix: ones, Family: fam, Scope: scopeOf(ip), Managed: managed[ip.String()]})
		}
		out.Interfaces = append(out.Interfaces, ni)
	}
	return out, nil
}

// ValidIPParams validates an address to add/remove.
func ValidIPParams(p rpc.NetIPParams) (netip.Prefix, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(p.IP))
	if err != nil || ip.Zone() != "" || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return netip.Prefix{}, errf("invalid_ip", "invalid address")
	}
	ip = ip.Unmap()
	max := 128
	if ip.Is4() {
		max = 32
	}
	if p.Prefix < 8 || p.Prefix > max {
		return netip.Prefix{}, errf("invalid_ip", "invalid prefix length")
	}
	if !reDev.MatchString(p.Dev) || p.Dev == "lo" {
		return netip.Prefix{}, errf("invalid_ip", "invalid interface")
	}
	return netip.PrefixFrom(ip, p.Prefix), nil
}

const ipsUnit = `# Managed by BOZKURT PANEL — re-adds the addresses of /etc/bpanel/ips.conf at boot.
[Unit]
Description=BPANEL additional IP addresses
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'grep -v "^#" /etc/bpanel/ips.conf | while read a d; do [ -n "$d" ] && ip addr replace "$a" dev "$d"; done; true'

[Install]
WantedBy=multi-user.target
`

func (a *Agent) netIPAdd(ctx context.Context, p rpc.NetIPParams) (rpc.Empty, error) {
	pf, err := ValidIPParams(p)
	if err != nil {
		return rpc.Empty{}, err
	}
	if _, err := net.InterfaceByName(p.Dev); err != nil {
		return rpc.Empty{}, errf("invalid_ip", "no interface %s", p.Dev)
	}
	defer a.lock("ips")()
	line := pf.String() + " " + p.Dev
	for _, l := range readIPsConf() {
		if l == line {
			return rpc.Empty{}, errf("ip_exists", "%s is already configured", pf)
		}
	}
	if _, err := v11Cmd(ctx, nil, "ip", "addr", "add", pf.String(), "dev", p.Dev); err != nil {
		return rpc.Empty{}, errf("action_failed", "ip addr add: %s", lastLines(err.Error(), 2))
	}
	cur := readIPsConf()
	cur = append(cur, line)
	if err := writeAtomic(IPsConf, []byte("# Managed by BOZKURT PANEL — ip/prefix dev\n"+strings.Join(cur, "\n")+"\n"), 0o644, -1, -1); err != nil {
		return rpc.Empty{}, errf("action_failed", "write %s", IPsConf)
	}
	if !a.Cfg.NoSystemd {
		if _, err := os.Stat(ipsUnitPath); err != nil {
			_ = writeAtomic(ipsUnitPath, []byte(ipsUnit), 0o644, -1, -1)
			_, _ = v11Cmd(ctx, nil, "systemctl", "daemon-reload")
			_, _ = v11Cmd(ctx, nil, "systemctl", "enable", "bpanel-ips.service")
		}
	}
	return rpc.Empty{}, nil
}

func (a *Agent) netIPRemove(ctx context.Context, p rpc.NetIPParams) (rpc.Empty, error) {
	pf, err := ValidIPParams(p)
	if err != nil {
		return rpc.Empty{}, err
	}
	defer a.lock("ips")()
	line := pf.String() + " " + p.Dev
	var keep []string
	found := false
	for _, l := range readIPsConf() {
		if l == line {
			found = true
			continue
		}
		keep = append(keep, l)
	}
	if !found {
		return rpc.Empty{}, errf("refused", "only addresses added by the panel can be removed")
	}
	if _, err := v11Cmd(ctx, nil, "ip", "addr", "del", pf.String(), "dev", p.Dev); err != nil {
		a.Log.Warn("ip addr del", "ip", pf.String(), "err", err)
	}
	body := "# Managed by BOZKURT PANEL — ip/prefix dev\n"
	if len(keep) > 0 {
		body += strings.Join(keep, "\n") + "\n"
	}
	if err := writeAtomic(IPsConf, []byte(body), 0o644, -1, -1); err != nil {
		return rpc.Empty{}, errf("action_failed", "write %s", IPsConf)
	}
	return rpc.Empty{}, nil
}

// ---- PHP extensions (EasyApache-style) ---------------------------------------------

func phpExtAllowed(ext string) bool {
	for _, e := range distro.PHPExtensions {
		if e == ext {
			return true
		}
	}
	return false
}

func (a *Agent) pkgInstalled(ctx context.Context, pkg string) bool {
	if a.L.Family == distro.Debian {
		out, err := v11Cmd(ctx, nil, "dpkg-query", "-W", "-f=${Status}", pkg)
		return err == nil && strings.Contains(out, "install ok installed")
	}
	_, err := v11Cmd(ctx, nil, "rpm", "-q", pkg)
	return err == nil
}

func (a *Agent) phpExtList(ctx context.Context, p rpc.PHPExtListParams) (rpc.PHPExtListResult, error) {
	if err := validate.PHPVersion(p.Version); err != nil {
		return rpc.PHPExtListResult{}, errf("invalid_php_version", "%s", p.Version)
	}
	mgr := "apt"
	if a.L.Family != distro.Debian {
		mgr = "dnf"
	}
	res := rpc.PHPExtListResult{Status: "ok", Manager: mgr, Extensions: []rpc.PHPExt{}}
	if (mgr == "apt" && !v11Have("dpkg-query")) || (mgr == "dnf" && !v11Have("rpm")) {
		res.Status, res.Reason = "not_installed", "package manager not available"
		return res, nil
	}
	// modules compiled in / loaded: php -m of that version (when present)
	loaded := map[string]bool{}
	for _, bin := range []string{"/usr/bin/php" + p.Version, "/opt/remi/php" + strings.ReplaceAll(p.Version, ".", "") + "/root/usr/bin/php"} {
		if regularFile(bin) {
			if out, err := v11Cmd(ctx, nil, bin, "-m"); err == nil {
				for _, l := range strings.Split(out, "\n") {
					loaded[strings.ToLower(strings.TrimSpace(l))] = true
				}
			}
			break
		}
	}
	for _, e := range distro.PHPExtensions {
		pkg := a.L.PHPExtPackage(p.Version, e)
		x := rpc.PHPExt{Name: e, Package: pkg, Installed: a.pkgInstalled(ctx, pkg)}
		name := map[string]string{"mysql": "mysqli", "opcache": "zend opcache"}[e]
		if name == "" {
			name = e
		}
		if !x.Installed && loaded[name] {
			x.Installed, x.Builtin = true, true
		}
		res.Extensions = append(res.Extensions, x)
	}
	return res, nil
}

func (a *Agent) phpExtSet(ctx context.Context, p rpc.PHPExtSetParams) (rpc.PHPExtSetResult, error) {
	if err := validate.PHPVersion(p.Version); err != nil {
		return rpc.PHPExtSetResult{}, errf("invalid_php_version", "%s", p.Version)
	}
	if !phpExtAllowed(p.Ext) {
		return rpc.PHPExtSetResult{}, errf("php_ext_unknown", "%s is not in the extension allowlist", p.Ext)
	}
	ph := a.L.PHPFor(p.Version)
	if !regularFile(ph.Binary) {
		return rpc.PHPExtSetResult{}, errf("php_version_missing", "PHP %s is not installed", p.Version)
	}
	pkg := a.L.PHPExtPackage(p.Version, p.Ext)
	defer a.lock("packages")()
	var argv []string
	switch {
	case a.L.Family == distro.Debian && p.Install:
		if _, err := v11Cmd(ctx, nil, "apt-get", "-q", "update"); err != nil {
			return rpc.PHPExtSetResult{}, errf("php_ext_failed", "apt-get update failed")
		}
		argv = []string{"apt-get", "-y", "-q", "-o", "Dpkg::Options::=--force-confold", "install", pkg}
	case a.L.Family == distro.Debian:
		argv = []string{"apt-get", "-y", "-q", "remove", pkg}
	case p.Install:
		argv = []string{"dnf", "-y", "install", pkg}
	default:
		argv = []string{"dnf", "-y", "remove", "--noautoremove", pkg}
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	out, err := v11Cmd(cctx, nil, argv...)
	if err != nil {
		return rpc.PHPExtSetResult{Status: "failed", Output: tail(out)}, errf("php_ext_failed", "%s %s failed", argv[0], pkg)
	}
	if !a.Cfg.NoSystemd {
		_ = a.systemctl(ctx, "restart", ph.Unit)
	}
	a.Log.Info("php extension changed", "version", p.Version, "ext", p.Ext, "install", p.Install)
	return rpc.PHPExtSetResult{Status: "ok", Output: tail(out)}, nil
}

// keepOwner returns the owner of an existing file (or uid:gid for a new
// one) when the agent runs as root; -1,-1 otherwise (tests).
func keepOwner(p string, uid, gid int) (int, int) {
	if os.Geteuid() != 0 {
		return -1, -1
	}
	if st, err := os.Stat(p); err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			return int(sys.Uid), int(sys.Gid)
		}
	}
	return uid, gid
}
