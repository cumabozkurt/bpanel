// SPDX-License-Identifier: Apache-2.0

package api

// v0.4 usagex: PHP ini editor (per account + version, rendered into the
// account's own FPM pool), bandwidth accounting from domain logs, the user
// ModSecurity view and the admin brute-force (fail2ban) page.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // date.timezone validation must not depend on the host tz database

	"github.com/go-chi/chi/v5"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/netsec"
	"github.com/cumabozkurt/bpanel/internal/rbac"
	"github.com/cumabozkurt/bpanel/internal/store"
)

func (s *Server) mountUsagexUser(r chi.Router) {
	const tg = "usage"
	s.op(r, "GET", "/user/php-ini", tg, "Own PHP settings for one version (?version=)", nil, s.h(s.getPHPIni))
	s.op(r, "PUT", "/user/php-ini", tg, "Change own PHP settings (validated by php-fpm -t, rolled back on failure)", PHPIniReq{}, s.h(s.putPHPIni))
	s.op(r, "GET", "/user/bandwidth", tg, "Own bandwidth per domain for a month (?month=YYYY-MM)", nil, s.h(s.userBandwidth))
	s.op(r, "GET", "/user/waf", tg, "WAF (ModSecurity) mode of own domains", nil, s.h(s.userWAFList))
	s.op(r, "PUT", "/user/waf/{domain}", tg, "Set the WAF mode of an own domain", WAFReq{}, s.h(s.userWAFPut))
}

func (s *Server) mountUsagexAdmin(r chi.Router) {
	const tg = "usage"
	s.opPerm(r, rbac.AccountsRead, "GET", "/admin/bandwidth", tg, "Bandwidth per account and domain for a month (?month=YYYY-MM; resellers see own accounts)", nil, s.h(s.adminBandwidth))
	s.opPerm(r, rbac.ServerWrite, "POST", "/admin/bandwidth/collect", tg, "Parse new domain-log lines now", nil, s.h(s.bandwidthCollectNow))
	s.opPerm(r, rbac.AccountsWrite, "PUT", "/admin/accounts/{id}/waf/{domain}", tg, "Set (and optionally lock) the WAF mode of a managed account's domain", AdminWAFReq{}, s.h(s.adminAccountWAFPut))
	s.opPerm(r, rbac.FirewallRead, "GET", "/admin/brute-force", tg, "Brute-force protection: fail2ban jails/bans, temporary blocks, allowlist", nil, s.h(s.bfStatus))
	s.opPerm(r, rbac.FirewallWrite, "POST", "/admin/brute-force/unban", tg, "Unban an IP from a fail2ban jail", BFUnbanReq{}, s.h(s.bfUnban))
	s.opPerm(r, rbac.FirewallWrite, "POST", "/admin/brute-force/allowlist", tg, "Allowlist an IP/CIDR (pushed to every fail2ban jail as ignoreip)", BFAllowReq{}, s.h(s.bfAllowAdd))
	s.opPerm(r, rbac.FirewallWrite, "DELETE", "/admin/brute-force/allowlist/{id}", tg, "Remove an allowlist entry", nil, s.h(s.bfAllowDel))
}

// ---- PHP ini ---------------------------------------------------------------

type PHPIniReq struct {
	Version  string            `json:"version"`
	Settings map[string]string `json:"settings"`
}

// phpIniKeys is the user-editable allowlist, in display order.
var phpIniKeys = []string{"memory_limit", "upload_max_filesize", "post_max_size", "max_execution_time", "max_input_vars", "display_errors", "date.timezone"}

var phpIniDefaults = map[string]string{"memory_limit": "256M", "upload_max_filesize": "64M", "post_max_size": "64M",
	"max_execution_time": "120", "max_input_vars": "1000", "display_errors": "Off", "date.timezone": "UTC"}

var tzNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+\-]*(/[A-Za-z0-9_+\-]+){0,2}$`)

// phpSizeMB parses 128M / 1G / 65536K into MB (K rounds up); false when invalid.
func phpSizeMB(v string) (int64, bool) {
	if len(v) < 2 || len(v) > 6 {
		return 0, false
	}
	unit := v[len(v)-1]
	n, err := strconv.ParseInt(v[:len(v)-1], 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	switch unit {
	case 'K':
		return (n + 1023) / 1024, true
	case 'M':
		return n, true
	case 'G':
		return n * 1024, true
	}
	return 0, false
}

// memCapMB is the largest memory_limit an account may set: its package memory
// limit when it has one, otherwise 2048 MB.
func memCapMB(pkg store.Package) int64 {
	if pkg.MemoryMB > 0 {
		return pkg.MemoryMB
	}
	return 2048
}

// ValidatePHPIni checks and normalises one settings set (only allowlisted
// keys). Returns the cleaned map or an api error naming the field.
func ValidatePHPIni(in map[string]string, capMB int64) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range in {
		v = strings.TrimSpace(v)
		if _, ok := phpIniDefaults[k]; !ok {
			return nil, badField("php_ini_invalid", k)
		}
		if v == "" {
			continue // empty = back to the default
		}
		switch k {
		case "memory_limit":
			mb, ok := phpSizeMB(strings.ToUpper(v))
			if !ok || mb < 32 {
				return nil, badField("php_ini_invalid", k)
			}
			if mb > capMB {
				return nil, &apiError{Status: 400, Code: "php_ini_memory_cap", Field: k, Message: fmt.Sprintf("at most %dM", capMB)}
			}
			v = strings.ToUpper(v)
		case "upload_max_filesize", "post_max_size":
			mb, ok := phpSizeMB(strings.ToUpper(v))
			if !ok || mb > 2048 {
				return nil, badField("php_ini_invalid", k)
			}
			v = strings.ToUpper(v)
		case "max_execution_time":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 3600 {
				return nil, badField("php_ini_invalid", k)
			}
			v = strconv.Itoa(n)
		case "max_input_vars":
			n, err := strconv.Atoi(v)
			if err != nil || n < 100 || n > 100000 {
				return nil, badField("php_ini_invalid", k)
			}
			v = strconv.Itoa(n)
		case "display_errors":
			switch strings.ToLower(v) {
			case "on", "1", "true":
				v = "On"
			case "off", "0", "false":
				v = "Off"
			default:
				return nil, badField("php_ini_invalid", k)
			}
		case "date.timezone":
			if !tzNameRe.MatchString(v) || len(v) > 64 {
				return nil, badField("php_ini_invalid", k)
			}
			if _, err := time.LoadLocation(v); err != nil || v == "Local" {
				return nil, badField("php_ini_invalid", k)
			}
		}
		out[k] = v
	}
	up, post := out["upload_max_filesize"], out["post_max_size"]
	if up == "" {
		up = phpIniDefaults["upload_max_filesize"]
	}
	if post == "" {
		post = phpIniDefaults["post_max_size"]
	}
	if a, _ := phpSizeMB(up); true {
		if b, _ := phpSizeMB(post); b < a {
			return nil, &apiError{Status: 400, Code: "php_ini_invalid", Field: "post_max_size", Message: "post_max_size must be >= upload_max_filesize"}
		}
	}
	return out, nil
}

func (s *Server) phpIniOf(ctx context.Context, uid int64, version string) map[string]string {
	out := map[string]string{}
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT key, value FROM php_ini_settings WHERE user_id=? AND version=?`, uid, version)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) == nil {
			out[k] = v
		}
	}
	return out
}

// phpPoolSpec is the FPM pool of one account + version: package defaults
// overlaid with the account's saved php_ini settings (used by provisioning too).
func (s *Server) phpPoolSpec(ctx context.Context, u *store.User, version string, pkg store.Package) rpc.PHPPool {
	mem := "256M"
	maxChildren := 10
	if pkg.MemoryMB > 0 && pkg.MemoryMB < 512 {
		mem = "128M"
		maxChildren = 5
	}
	p := rpc.PHPPool{User: u.Username, Version: version, MaxChildren: maxChildren, MemoryLimit: mem, UploadMax: "64M", MaxExecution: 120}
	set := s.phpIniOf(ctx, u.ID, version)
	if v, ok := set["memory_limit"]; ok {
		if mb, ok2 := phpSizeMB(v); ok2 && mb <= memCapMB(pkg) {
			p.MemoryLimit = v
		}
	}
	if v, ok := set["upload_max_filesize"]; ok {
		p.UploadMax = v
	}
	if v, ok := set["max_execution_time"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			p.MaxExecution = n
		}
	}
	for _, k := range []string{"post_max_size", "max_input_vars", "display_errors", "date.timezone"} {
		if v, ok := set[k]; ok {
			if p.INI == nil {
				p.INI = map[string]string{}
			}
			p.INI[k] = v
		}
	}
	if p.INI["post_max_size"] == "" && set["upload_max_filesize"] != "" { // keep post >= upload
		if p.INI == nil {
			p.INI = map[string]string{}
		}
		p.INI["post_max_size"] = p.UploadMax
	}
	return p
}

// accountPHPVersions lists the PHP versions the account's (non-alias) domains use.
func (s *Server) accountPHPVersions(ctx context.Context, u *store.User) []string {
	doms, _ := s.domainsOf(ctx, u.ID)
	seen := map[string]bool{}
	for _, d := range doms {
		if d.Kind != "alias" {
			seen[s.phpFor(u, d)] = true
		}
	}
	if len(seen) == 0 {
		seen[s.phpFor(u, store.Domain{})] = true
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func (s *Server) getPHPIni(w http.ResponseWriter, r *http.Request) (any, error) {
	u := userOf(r)
	versions := s.accountPHPVersions(r.Context(), u)
	v := r.URL.Query().Get("version")
	if v == "" {
		v = versions[0]
	}
	if !contains(versions, v) {
		return nil, badField("invalid_php_version", "version")
	}
	pkg := s.packageOf(r.Context(), u)
	spec := s.phpPoolSpec(r.Context(), u, v, pkg)
	eff := map[string]string{"memory_limit": spec.MemoryLimit, "upload_max_filesize": spec.UploadMax,
		"max_execution_time": strconv.Itoa(spec.MaxExecution), "post_max_size": spec.UploadMax}
	for k, d := range phpIniDefaults {
		if _, ok := eff[k]; !ok {
			eff[k] = d
		}
	}
	for k, val := range spec.INI {
		eff[k] = val
	}
	return map[string]any{"version": v, "versions": versions, "keys": phpIniKeys, "settings": s.phpIniOf(r.Context(), u.ID, v),
		"effective": eff, "memory_cap_mb": memCapMB(pkg)}, nil
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func (s *Server) putPHPIni(w http.ResponseWriter, r *http.Request) (any, error) {
	var in PHPIniReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	u := userOf(r)
	if !contains(s.accountPHPVersions(r.Context(), u), in.Version) {
		return nil, badField("invalid_php_version", "version")
	}
	pkg := s.packageOf(r.Context(), u)
	clean, err := ValidatePHPIni(in.Settings, memCapMB(pkg))
	if err != nil {
		return nil, err
	}
	old := s.phpIniOf(r.Context(), u.ID, in.Version)
	save := func(ctx context.Context, set map[string]string) error {
		tx, err := s.Store.DB.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, `DELETE FROM php_ini_settings WHERE user_id=? AND version=?`, u.ID, in.Version); err != nil {
			return err
		}
		now := time.Now().Unix()
		for k, v := range set {
			if _, err := tx.ExecContext(ctx, `INSERT INTO php_ini_settings(user_id,version,key,value,updated_at) VALUES(?,?,?,?,?)`, u.ID, in.Version, k, v, now); err != nil {
				return err
			}
		}
		return tx.Commit()
	}
	if err := save(r.Context(), clean); err != nil {
		return nil, err
	}
	spec := s.phpPoolSpec(r.Context(), u, in.Version, pkg)
	if err := s.Agent.Call(r.Context(), rpc.MPHPPoolApply, spec, nil); err != nil {
		// the agent validated with php-fpm -t and restored the previous pool; restore the DB too
		_ = save(context.WithoutCancel(r.Context()), old)
		s.audit(r, "php.ini", u.Username+" "+in.Version, nsAgentCode(err), false)
		return nil, err
	}
	s.audit(r, "php.ini", u.Username+" "+in.Version, strings.Join(sortedKeys(clean), ","), true)
	return map[string]any{"status": "applied", "version": in.Version, "settings": clean}, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- bandwidth -------------------------------------------------------------

const bwRetainDays = 400

var monthRe = regexp.MustCompile(`^\d{4}-(0[1-9]|1[0-2])$`)

func monthParam(r *http.Request, now time.Time) (string, error) {
	m := r.URL.Query().Get("month")
	if m == "" {
		return now.UTC().Format("2006-01"), nil
	}
	if !monthRe.MatchString(m) {
		return "", badField("invalid_month", "month")
	}
	return m, nil
}

// bandwidthCollect parses the new lines of every domain log once (a few
// bounded rounds when a log has a backlog) and folds them into bw_daily.
func (s *Server) bandwidthCollect(ctx context.Context) (int, error) {
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT d.name, COALESCE(c.inode,0), COALESCE(c.offset,0) FROM domains d
		LEFT JOIN bw_cursors c ON c.domain=d.name WHERE d.kind<>'alias' ORDER BY d.name`)
	if err != nil {
		return 0, err
	}
	var cur []rpc.BWCursor
	for rows.Next() {
		var c rpc.BWCursor
		var ino int64
		if rows.Scan(&c.Domain, &ino, &c.Offset) == nil {
			c.Inode = uint64(ino)
			cur = append(cur, c)
		}
	}
	rows.Close()
	lines := 0
	for round := 0; round < 4 && len(cur) > 0; round++ {
		var out rpc.BWScanResult
		if err := s.Agent.Call(ctx, rpc.MUsageBandwidthScan, rpc.BWScanParams{Cursors: cur}, &out); err != nil {
			return lines, err
		}
		next := []rpc.BWCursor{}
		now := time.Now().Unix()
		for _, d := range out.Domains {
			for _, day := range d.Days {
				lines += int(day.Hits)
				if _, err := s.Store.DB.ExecContext(ctx, `INSERT INTO bw_daily(domain,day,bytes,hits) VALUES(?,?,?,?)
					ON CONFLICT(domain,day) DO UPDATE SET bytes=bytes+excluded.bytes, hits=hits+excluded.hits`, d.Domain, day.Day, day.Bytes, day.Hits); err != nil {
					return lines, err
				}
			}
			if _, err := s.Store.DB.ExecContext(ctx, `INSERT INTO bw_cursors(domain,inode,offset,status,updated_at) VALUES(?,?,?,?,?)
				ON CONFLICT(domain) DO UPDATE SET inode=excluded.inode, offset=excluded.offset, status=excluded.status, updated_at=excluded.updated_at`,
				d.Domain, int64(d.Inode), d.Offset, d.Status, now); err != nil {
				return lines, err
			}
			if d.More {
				next = append(next, rpc.BWCursor{Domain: d.Domain, Inode: d.Inode, Offset: d.Offset})
			}
		}
		cur = next
	}
	return lines, nil
}

// bandwidthHousekeep drops old days and cursors of deleted domains.
func (s *Server) bandwidthHousekeep(ctx context.Context, now time.Time) {
	cut := now.UTC().AddDate(0, 0, -bwRetainDays).Format("2006-01-02")
	_, _ = s.Store.DB.ExecContext(ctx, `DELETE FROM bw_daily WHERE day<?`, cut)
	_, _ = s.Store.DB.ExecContext(ctx, `DELETE FROM bw_cursors WHERE domain NOT IN (SELECT name FROM domains)`)
}

// usagexLoop runs the bandwidth collector every 15 minutes (started in Run).
func (s *Server) usagexLoop(ctx context.Context) {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			if _, err := s.bandwidthCollect(cctx); err != nil && s.Log != nil {
				s.Log.Warn("bandwidth collect", "err", err)
			}
			s.bandwidthHousekeep(cctx, time.Now())
			cancel()
		}
	}
}

func (s *Server) bandwidthCollectNow(w http.ResponseWriter, r *http.Request) (any, error) {
	n, err := s.bandwidthCollect(r.Context())
	if err != nil {
		return nil, err
	}
	s.bandwidthHousekeep(r.Context(), time.Now())
	s.audit(r, "bandwidth.collect", "", strconv.Itoa(n), true)
	return map[string]any{"hits": n}, nil
}

type bwRow struct {
	Domain string `json:"domain"`
	User   string `json:"user,omitempty"`
	Bytes  int64  `json:"bytes"`
	Hits   int64  `json:"hits"`
}

func (s *Server) bwQuery(ctx context.Context, month, where string, args ...any) ([]bwRow, []map[string]any, error) {
	q := `SELECT b.domain, u.username, SUM(b.bytes), SUM(b.hits) FROM bw_daily b JOIN domains d ON d.name=b.domain JOIN users u ON u.id=d.user_id
		WHERE substr(b.day,1,7)=? ` + where + ` GROUP BY b.domain, u.username ORDER BY SUM(b.bytes) DESC`
	rows, err := s.Store.DB.QueryContext(ctx, q, append([]any{month}, args...)...)
	if err != nil {
		return nil, nil, err
	}
	out := []bwRow{}
	for rows.Next() {
		var x bwRow
		if err := rows.Scan(&x.Domain, &x.User, &x.Bytes, &x.Hits); err != nil {
			rows.Close()
			return nil, nil, err
		}
		out = append(out, x)
	}
	rows.Close()
	dq := `SELECT b.day, SUM(b.bytes), SUM(b.hits) FROM bw_daily b JOIN domains d ON d.name=b.domain JOIN users u ON u.id=d.user_id
		WHERE substr(b.day,1,7)=? ` + where + ` GROUP BY b.day ORDER BY b.day`
	drows, err := s.Store.DB.QueryContext(ctx, dq, append([]any{month}, args...)...)
	if err != nil {
		return nil, nil, err
	}
	defer drows.Close()
	days := []map[string]any{}
	for drows.Next() {
		var d string
		var b, h int64
		if err := drows.Scan(&d, &b, &h); err != nil {
			return nil, nil, err
		}
		days = append(days, map[string]any{"day": d, "bytes": b, "hits": h})
	}
	return out, days, drows.Err()
}

func bwTotal(rows []bwRow) (b, h int64) {
	for _, x := range rows {
		b += x.Bytes
		h += x.Hits
	}
	return
}

func (s *Server) userBandwidth(w http.ResponseWriter, r *http.Request) (any, error) {
	month, err := monthParam(r, time.Now())
	if err != nil {
		return nil, err
	}
	u := userOf(r)
	rows, days, err := s.bwQuery(r.Context(), month, `AND d.user_id=?`, u.ID)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i].User = ""
	}
	b, h := bwTotal(rows)
	pkg := s.packageOf(r.Context(), u)
	return map[string]any{"month": month, "domains": rows, "days": days, "total_bytes": b, "total_hits": h,
		"limit_mb": pkgBandwidthMB(pkg)}, nil
}

func (s *Server) adminBandwidth(w http.ResponseWriter, r *http.Request) (any, error) {
	month, err := monthParam(r, time.Now())
	if err != nil {
		return nil, err
	}
	where, args := "", []any{}
	switch roleOf(r) {
	case rbac.SuperAdmin, rbac.ServerAdmin, rbac.SecurityAdmin, rbac.Auditor:
	case rbac.Reseller:
		where, args = `AND (u.owner_id=? OR u.id=?)`, []any{userOf(r).ID, userOf(r).ID}
	default:
		where, args = `AND u.id IN (SELECT account_id FROM tech_grants WHERE user_id=?)`, []any{userOf(r).ID}
	}
	rows, days, err := s.bwQuery(r.Context(), month, where, args...)
	if err != nil {
		return nil, err
	}
	b, h := bwTotal(rows)
	return map[string]any{"month": month, "domains": rows, "days": days, "total_bytes": b, "total_hits": h}, nil
}

// rebody returns a copy of r whose body is v as JSON (to reuse a handler).
func rebody(r *http.Request, v any) (*http.Request, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	r2 := r.Clone(r.Context())
	r2.Body = io.NopCloser(bytes.NewReader(b))
	r2.ContentLength = int64(len(b))
	return r2, nil
}

// pkgBandwidthMB reads the package's monthly bandwidth limit when the schema
// has one (0 = unlimited / unknown).
func pkgBandwidthMB(p store.Package) int64 { return p.BandwidthMB }

// ---- ModSecurity (user / reseller) -------------------------------------------

type AdminWAFReq struct {
	WAFReq
	Lock bool `json:"lock"`
}

func (s *Server) userWAFList(w http.ResponseWriter, r *http.Request) (any, error) {
	var st rpc.NetsecWafStatusResult
	if err := s.Agent.Call(r.Context(), rpc.MNetsecWafStatus, rpc.NetsecWafStatusParams{}, &st); err != nil {
		st = rpc.NetsecWafStatusResult{Status: "unsupported", Reason: nsAgentCode(err)}
	}
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT d.name, COALESCE(w.mode,'audit'), COALESCE(w.status,''), COALESCE(w.reason,''), COALESCE(l.locked,0)
		FROM domains d LEFT JOIN waf_domains w ON w.domain=d.name LEFT JOIN waf_locks l ON l.domain=d.name
		WHERE d.user_id=? AND d.kind<>'alias' ORDER BY d.name`, userOf(r).ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var d, mode, status, reason string
		var locked int
		if err := rows.Scan(&d, &mode, &status, &reason, &locked); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"domain": d, "mode": mode, "status": status, "reason": reason, "locked": locked == 1})
	}
	return map[string]any{"provider": map[string]any{"status": st.Status, "reason": st.Reason}, "domains": out}, rows.Err()
}

func (s *Server) domainOwner(ctx context.Context, domain string) (int64, bool) {
	var uid int64
	err := s.Store.DB.QueryRowContext(ctx, `SELECT user_id FROM domains WHERE name=? AND kind<>'alias'`, domain).Scan(&uid)
	return uid, err == nil
}

func (s *Server) userWAFPut(w http.ResponseWriter, r *http.Request) (any, error) {
	domain := strings.ToLower(chi.URLParam(r, "domain"))
	if !netsec.ValidWAFDomain(domain) {
		return nil, badMsg("waf_invalid", "invalid domain")
	}
	uid, ok := s.domainOwner(r.Context(), domain)
	if !ok || uid != userOf(r).ID {
		return nil, notFound()
	}
	var locked int
	_ = s.Store.DB.QueryRowContext(r.Context(), `SELECT locked FROM waf_locks WHERE domain=?`, domain).Scan(&locked)
	if locked == 1 {
		return nil, &apiError{Status: 403, Code: "waf_locked"}
	}
	return s.wafPut(w, r)
}

func (s *Server) adminAccountWAFPut(w http.ResponseWriter, r *http.Request) (any, error) {
	id := idParam(r, "id")
	if !s.canManageAccount(r, id) {
		return nil, notFound()
	}
	domain := strings.ToLower(chi.URLParam(r, "domain"))
	if uid, ok := s.domainOwner(r.Context(), domain); !ok || uid != id {
		return nil, notFound()
	}
	var in AdminWAFReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	r2, err := rebody(r, in.WAFReq)
	if err != nil {
		return nil, err
	}
	res, err := s.wafPut(w, r2)
	if err != nil {
		return nil, err
	}
	lock := 0
	if in.Lock {
		lock = 1
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO waf_locks(domain,locked,updated_at) VALUES(?,?,?)
		ON CONFLICT(domain) DO UPDATE SET locked=excluded.locked, updated_at=excluded.updated_at`, domain, lock, time.Now().Unix()); err != nil {
		return nil, err
	}
	s.audit(r, "waf.lock", domain, strconv.Itoa(lock), true)
	if m, ok := res.(map[string]any); ok {
		m["locked"] = in.Lock
	}
	return res, nil
}

// ---- brute force (fail2ban) ----------------------------------------------------

type BFUnbanReq struct {
	Jail string `json:"jail"`
	IP   string `json:"ip"`
}

type BFAllowReq struct {
	IP   string `json:"ip"`
	Note string `json:"note"`
}

func normIPOrCIDR(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.Masked().String(), true
	}
	if a, err := netip.ParseAddr(v); err == nil && a.Zone() == "" {
		return a.Unmap().String(), true
	}
	return "", false
}

func (s *Server) bfAllowlist(ctx context.Context) ([]map[string]any, []string) {
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT id, ip, note, created_at FROM bf_allowlist ORDER BY id`)
	out, ips := []map[string]any{}, []string{}
	if err != nil {
		return out, ips
	}
	defer rows.Close()
	for rows.Next() {
		var id, at int64
		var ip, note string
		if rows.Scan(&id, &ip, &note, &at) == nil {
			out = append(out, map[string]any{"id": id, "ip": ip, "note": note, "created_at": at})
			ips = append(ips, ip)
		}
	}
	return out, ips
}

func (s *Server) f2bStatus(ctx context.Context) rpc.F2BStatusResult {
	var st rpc.F2BStatusResult
	if err := s.Agent.Call(ctx, rpc.MF2BStatus, rpc.F2BStatusParams{}, &st); err != nil {
		return rpc.F2BStatusResult{Status: "unsupported", Reason: nsAgentCode(err), Jails: []rpc.F2BJail{}}
	}
	if st.Jails == nil {
		st.Jails = []rpc.F2BJail{}
	}
	return st
}

func (s *Server) bfStatus(w http.ResponseWriter, r *http.Request) (any, error) {
	st := s.f2bStatus(r.Context())
	allow, _ := s.bfAllowlist(r.Context())
	blocks, err := s.fwListBlocks(w, r)
	if err != nil {
		return nil, err
	}
	return map[string]any{"fail2ban": st, "allowlist": allow, "blocks": blocks.(map[string]any)["blocks"]}, nil
}

func (s *Server) bfUnban(w http.ResponseWriter, r *http.Request) (any, error) {
	var in BFUnbanReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	ip, ok := normIPOrCIDR(in.IP)
	if !ok || strings.Contains(ip, "/") {
		return nil, badField("invalid_ip", "ip")
	}
	var out rpc.F2BActionResult
	if err := s.Agent.Call(r.Context(), rpc.MF2BUnban, rpc.F2BUnbanParams{Jail: in.Jail, IP: ip}, &out); err != nil {
		s.audit(r, "bruteforce.unban", in.Jail+" "+ip, nsAgentCode(err), false)
		return nil, err
	}
	switch out.Status {
	case "done":
	case "not_installed":
		return nil, &apiError{Status: 409, Code: "f2b_not_installed", Message: out.Reason}
	default:
		return nil, &apiError{Status: 409, Code: "f2b_not_running", Message: out.Reason}
	}
	s.audit(r, "bruteforce.unban", in.Jail+" "+ip, "", true)
	return out, nil
}

func (s *Server) bfAllowAdd(w http.ResponseWriter, r *http.Request) (any, error) {
	var in BFAllowReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	ip, ok := normIPOrCIDR(in.IP)
	if !ok {
		return nil, badField("invalid_ip", "ip")
	}
	if len(in.Note) > 200 {
		return nil, badField("invalid_note", "note")
	}
	res, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO bf_allowlist(ip,note,created_at) VALUES(?,?,?)`, ip, strings.TrimSpace(in.Note), time.Now().Unix())
	if err != nil {
		return nil, &apiError{Status: 409, Code: "already_exists"}
	}
	id, _ := res.LastInsertId()
	push := s.bfPush(r.Context(), ip, false)
	s.audit(r, "bruteforce.allow", ip, push, true)
	return map[string]any{"id": id, "ip": ip, "fail2ban": push}, nil
}

func (s *Server) bfAllowDel(w http.ResponseWriter, r *http.Request) (any, error) {
	var ip string
	if err := s.Store.DB.QueryRowContext(r.Context(), `SELECT ip FROM bf_allowlist WHERE id=?`, idParam(r, "id")).Scan(&ip); err != nil {
		if err == sql.ErrNoRows {
			return nil, notFound()
		}
		return nil, err
	}
	if _, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM bf_allowlist WHERE id=?`, idParam(r, "id")); err != nil {
		return nil, err
	}
	push := s.bfPush(r.Context(), ip, true)
	s.audit(r, "bruteforce.allow.remove", ip, push, true)
	return map[string]any{"fail2ban": push}, nil
}

// bfPush applies one allowlist change to every running jail (runtime
// ignoreip). Returns done | not_installed | not_running | unsupported.
func (s *Server) bfPush(ctx context.Context, ip string, remove bool) string {
	st := s.f2bStatus(ctx)
	if st.Status != "ok" {
		return st.Status
	}
	jails := make([]string, 0, len(st.Jails))
	for _, j := range st.Jails {
		jails = append(jails, j.Name)
	}
	if len(jails) == 0 {
		return "done"
	}
	var out rpc.F2BActionResult
	if err := s.Agent.Call(ctx, rpc.MF2BIgnore, rpc.F2BIgnoreParams{Jails: jails, IP: ip, Remove: remove}, &out); err != nil {
		return nsAgentCode(err)
	}
	return out.Status
}

// bfResync re-pushes the whole allowlist to every running jail. fail2ban keeps
// addignoreip changes only in memory, so a fail2ban restart (package update,
// reboot) would silently drop them; the loop below heals that within
// bfResyncEvery. addignoreip of an IP already present is a no-op.
func (s *Server) bfResync(ctx context.Context) (int, string) {
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT ip FROM bf_allowlist ORDER BY id`)
	if err != nil {
		return 0, "error"
	}
	var ips []string
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) == nil {
			ips = append(ips, ip)
		}
	}
	rows.Close()
	if len(ips) == 0 {
		return 0, "done"
	}
	st := s.f2bStatus(ctx)
	if st.Status != "ok" {
		return 0, st.Status
	}
	jails := make([]string, 0, len(st.Jails))
	for _, j := range st.Jails {
		jails = append(jails, j.Name)
	}
	if len(jails) == 0 {
		return 0, "done"
	}
	n := 0
	for _, ip := range ips {
		var out rpc.F2BActionResult
		if err := s.Agent.Call(ctx, rpc.MF2BIgnore, rpc.F2BIgnoreParams{Jails: jails, IP: ip}, &out); err != nil {
			return n, nsAgentCode(err)
		}
		n++
	}
	return n, "done"
}

// bfResyncEvery is how often bfLoop re-applies the allowlist.
var bfResyncEvery = 5 * time.Minute

// bfLoop runs bfResync shortly after start and then every bfResyncEvery.
func (s *Server) bfLoop(ctx context.Context) {
	d := 30 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
		d = bfResyncEvery
		cctx, cancel := context.WithTimeout(ctx, time.Minute)
		if n, st := s.bfResync(cctx); st != "done" && st != "not_installed" && st != "not_running" && s.Log != nil {
			s.Log.Warn("brute-force allowlist resync", "status", st, "pushed", n)
		}
		cancel()
	}
}
