// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/dnsx"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// v0.4 dnsx. DNSSEC is driven with pdnsutil (PowerDNS, GPL-2.0, invoked as
// a separate process); mailing lists use mlmmj (MIT licence, separate
// programs mlmmj-receive/-sub/-unsub/-list). Every command is argv-only
// with its own timeout. Nothing is pretended: a missing binary returns
// not_installed with the reason.

var (
	MlmmjSpool       = "/var/spool/mlmmj"
	MlmmjTransport   = "" // "" = <postfix dir>/bpanel_mlmmj_transport
	dnsxHave         = have
	dnsxRun          = run
	dnsxTimeout      = 60 * time.Second
	dnsxReloadPostfx = func(a *Agent, ctx context.Context) error { return a.reloadPostfix(ctx) }
)

func init() {
	accountField[rpc.MDNSSEC] = struct {
		key      string
		optional bool
	}{"owner", false}
	for _, m := range []string{rpc.MListApply, rpc.MListSubs} {
		accountField[m] = struct {
			key      string
			optional bool
		}{"user", false}
	}
}

func (a *Agent) dnsxRoutes() map[string]handler {
	return map[string]handler{
		rpc.MDNSSEC:    bind(a.dnssec),
		rpc.MListApply: bind(a.listApply),
		rpc.MListSubs:  bind(a.listSubs),
	}
}

func dnsxCmd(ctx context.Context, argv ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, dnsxTimeout)
	defer cancel()
	return dnsxRun(cctx, nil, argv...)
}

func (a *Agent) dnssec(ctx context.Context, p rpc.DNSSECReq) (rpc.DNSSECStatus, error) {
	res := rpc.DNSSECStatus{DS: []string{}, DNSKEY: []string{}}
	if err := checkZone(p.Zone); err != nil {
		return res, err
	}
	zone := strings.TrimSuffix(strings.ToLower(p.Zone), ".")
	if err := a.mustOwn(kindZone, zone, p.Owner); err != nil {
		return res, err
	}
	if !dnsxHave("pdnsutil") {
		res.Status, res.Reason = "not_installed", "pdnsutil not found (PowerDNS Authoritative not installed)"
		return res, nil
	}
	switch p.Action {
	case "status":
	case "enable":
		if _, err := dnsxCmd(ctx, "pdnsutil", "secure-zone", zone); err != nil {
			// already secured is fine; anything else is reported
			if !strings.Contains(err.Error(), "already secure") {
				return res, errf("dnssec_failed", "secure-zone: %s", lastLines(err.Error(), 2))
			}
		}
		if _, err := dnsxCmd(ctx, "pdnsutil", "rectify-zone", zone); err != nil {
			return res, errf("dnssec_failed", "rectify-zone: %s", lastLines(err.Error(), 2))
		}
		_, _ = dnsxCmd(ctx, "pdnsutil", "increase-serial", zone)
		a.Log.Info("dnssec enabled", "zone", zone, "owner", p.Owner)
	case "disable":
		if _, err := dnsxCmd(ctx, "pdnsutil", "disable-dnssec", zone); err != nil {
			return res, errf("dnssec_failed", "disable-dnssec: %s", lastLines(err.Error(), 2))
		}
		_, _ = dnsxCmd(ctx, "pdnsutil", "rectify-zone", zone)
		_, _ = dnsxCmd(ctx, "pdnsutil", "increase-serial", zone)
		a.Log.Info("dnssec disabled", "zone", zone, "owner", p.Owner)
	default:
		return res, errf("invalid_action", "%s", p.Action)
	}
	out, err := dnsxCmd(ctx, "pdnsutil", "show-zone", zone)
	if err != nil && !strings.Contains(out, "not actively secured") {
		return res, errf("dnssec_failed", "show-zone: %s", lastLines(err.Error(), 2))
	}
	info := dnsx.ParseShowZone(out)
	res.Status = "inactive"
	if info.Secured {
		res.Status = "active"
	}
	res.DS, res.DNSKEY = info.DS, info.DNSKEY
	return res, nil
}

// ---- mlmmj ----------------------------------------------------------------

func (a *Agent) mlmmjTransport() string {
	if MlmmjTransport != "" {
		return MlmmjTransport
	}
	return filepath.Join(a.postfixDir(), "bpanel_mlmmj_transport")
}

func mlmmjMissing() string {
	for _, b := range []string{"mlmmj-receive", "mlmmj-sub", "mlmmj-unsub", "mlmmj-list"} {
		if !dnsxHave(b) {
			return b + " not found (mlmmj not installed)"
		}
	}
	return ""
}

func (a *Agent) listCheck(p rpc.ListReq) (string, error) {
	if err := validate.Domain(p.Domain); err != nil {
		return "", errf("invalid_domain", "%s", p.Domain)
	}
	dir, err := dnsx.ListDir(MlmmjSpool, strings.ToLower(p.Domain), p.Name)
	if err != nil {
		return "", errf(err.Error(), "%s", p.Name)
	}
	if err := a.mustOwn(kindMail, strings.ToLower(p.Domain), p.User); err != nil {
		return "", err
	}
	return dir, nil
}

// scanLists returns every list present under the spool.
func scanLists() []dnsx.ListRef {
	var out []dnsx.ListRef
	doms, _ := os.ReadDir(MlmmjSpool)
	for _, d := range doms {
		if !d.IsDir() || validate.Domain(d.Name()) != nil {
			continue
		}
		ls, _ := os.ReadDir(filepath.Join(MlmmjSpool, d.Name()))
		for _, l := range ls {
			if l.IsDir() && dnsx.ListName(l.Name()) == nil {
				if _, err := os.Stat(filepath.Join(MlmmjSpool, d.Name(), l.Name(), "control", "listaddress")); err == nil {
					out = append(out, dnsx.ListRef{Domain: d.Name(), Name: l.Name()})
				}
			}
		}
	}
	return out
}

// writeTransport rewrites the managed transport map, postmaps it and
// reloads Postfix. On failure the previous map is restored.
func (a *Agent) writeTransport(ctx context.Context) error {
	path := a.mlmmjTransport()
	old, oldErr := os.ReadFile(path)
	restore := func() {
		if oldErr == nil {
			_ = os.WriteFile(path, old, 0o644)
		} else {
			_ = os.Remove(path)
		}
		if dnsxHave("postmap") {
			_, _ = dnsxCmd(ctx, "postmap", a.mapType()+":"+path)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return errf("mlist_failed", "transport dir")
	}
	tmp := path + ".bpanel-tmp"
	if err := os.WriteFile(tmp, []byte(dnsx.TransportMap(scanLists())+a.routingLines()), 0o644); err != nil {
		return errf("mlist_failed", "write transport")
	}
	if err := os.Rename(tmp, path); err != nil {
		return errf("mlist_failed", "write transport")
	}
	if dnsxHave("postmap") {
		if _, err := dnsxCmd(ctx, "postmap", a.mapType()+":"+path); err != nil {
			restore()
			return errf("mlist_failed", "postmap: %s", lastLines(err.Error(), 2))
		}
	}
	if err := dnsxReloadPostfx(a, ctx); err != nil {
		restore()
		_ = dnsxReloadPostfx(a, ctx)
		return errf("mlist_failed", "postfix reload failed")
	}
	return nil
}

func mlmmjIDs() (int, int) {
	u, err := user.Lookup("mlmmj")
	if err != nil {
		return -1, -1
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return uid, gid
}

func (a *Agent) listApply(ctx context.Context, p rpc.ListReq) (rpc.ListStatus, error) {
	res := rpc.ListStatus{Subscribers: []string{}}
	dir, err := a.listCheck(p)
	if err != nil {
		return res, err
	}
	if why := mlmmjMissing(); why != "" {
		res.Status, res.Reason = "not_installed", why
		return res, nil
	}
	addr := p.Name + "@" + strings.ToLower(p.Domain)
	switch p.Action {
	case "create":
		if err := validate.Email(p.Owner); err != nil {
			return res, errf("invalid_email", "owner")
		}
		if _, err := os.Lstat(dir); err == nil {
			return res, errf("already_exists", "%s", addr)
		}
		// the documented mlmmj spool layout (what mlmmj-make-ml creates)
		for _, sub := range []string{"incoming", "queue", "queue/discarded", "archive", "text", "subconf", "unsubconf",
			"bounce", "control", "moderation", "subscribers.d", "digesters.d", "nomailsubs.d", "requeue"} {
			if err := os.MkdirAll(filepath.Join(dir, sub), 0o750); err != nil {
				_ = os.RemoveAll(dir)
				return res, errf("mlist_failed", "mkdir")
			}
		}
		files := map[string]string{"control/listaddress": addr + "\n", "control/owner": p.Owner + "\n",
			"control/delimiter": "+\n", "control/customheaders": "List-Id: <" + p.Name + "." + strings.ToLower(p.Domain) + ">\n",
			"index": ""}
		for f, c := range files {
			if err := os.WriteFile(filepath.Join(dir, f), []byte(c), 0o640); err != nil {
				_ = os.RemoveAll(dir)
				return res, errf("mlist_failed", "write control")
			}
		}
		if uid, gid := mlmmjIDs(); uid >= 0 {
			_ = filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
				if err == nil {
					_ = os.Lchown(p, uid, gid)
				}
				return nil
			})
			_ = os.Lchown(filepath.Dir(dir), uid, gid)
		}
		if err := a.writeTransport(ctx); err != nil {
			_ = os.RemoveAll(dir)
			return res, err
		}
		a.Log.Info("mailing list created", "list", addr, "user", p.User)
	case "delete":
		if _, err := os.Stat(filepath.Join(dir, "control", "listaddress")); err != nil {
			return res, errf("not_found", "%s", addr)
		}
		// take it out of the map first; keep the files until Postfix is reloaded
		parked := dir + ".deleting"
		if err := os.Rename(dir, parked); err != nil {
			return res, errf("mlist_failed", "park")
		}
		if err := a.writeTransport(ctx); err != nil {
			_ = os.Rename(parked, dir)
			return res, err
		}
		_ = os.RemoveAll(parked)
		a.Log.Info("mailing list deleted", "list", addr, "user", p.User)
	default:
		return res, errf("invalid_action", "%s", p.Action)
	}
	res.Status = "ok"
	return res, nil
}

func (a *Agent) listSubs(ctx context.Context, p rpc.ListSubsReq) (rpc.ListStatus, error) {
	res := rpc.ListStatus{Subscribers: []string{}}
	dir, err := a.listCheck(rpc.ListReq{User: p.User, Domain: p.Domain, Name: p.Name})
	if err != nil {
		return res, err
	}
	if why := mlmmjMissing(); why != "" {
		res.Status, res.Reason = "not_installed", why
		return res, nil
	}
	if _, err := os.Stat(filepath.Join(dir, "control", "listaddress")); err != nil {
		return res, errf("not_found", "%s@%s", p.Name, p.Domain)
	}
	switch p.Action {
	case "list":
	case "add", "remove":
		if err := validate.Email(p.Address); err != nil || strings.HasPrefix(p.Address, "-") {
			return res, errf("invalid_email", "address")
		}
		bin := "mlmmj-sub"
		if p.Action == "remove" {
			bin = "mlmmj-unsub"
		}
		// -q: no owner notification, -s: no welcome/goodbye mail (panel-driven)
		if _, err := dnsxCmd(ctx, bin, "-L", dir, "-a", strings.ToLower(p.Address), "-q", "-s"); err != nil {
			return res, errf("mlist_failed", "%s: %s", bin, lastLines(err.Error(), 2))
		}
	default:
		return res, errf("invalid_action", "%s", p.Action)
	}
	out, err := dnsxCmd(ctx, "mlmmj-list", "-L", dir)
	if err != nil {
		return res, errf("mlist_failed", "mlmmj-list")
	}
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" && validate.Email(l) == nil {
			res.Subscribers = append(res.Subscribers, l)
		}
	}
	sort.Strings(res.Subscribers)
	res.Status = "ok"
	return res, nil
}
