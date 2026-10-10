// SPDX-License-Identifier: Apache-2.0

package agent

// v0.4 usagex: bandwidth accounting (bounded, incremental parse of nginx
// domain logs) and the fail2ban bridge for the brute-force page. fail2ban is
// GPL software invoked as a separate process (argv only, never a shell).

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// DomlogDir is where the nginx vhost template writes per-domain access logs.
var DomlogDir = "/var/log/bpanel/domlogs"

// F2BClient is the fail2ban-client binary (looked up on PATH when empty).
var F2BClient = ""

const (
	bwDefaultMax = 32 << 20
	bwHardMax    = 256 << 20
	bwMaxLine    = 64 << 10
	bwMaxDomains = 5000
)

func init() {
	for m, why := range map[string]string{
		rpc.MUsageBandwidthScan: "server (read-only parse of the fixed domlog directory; domain names validated)",
		rpc.MF2BStatus:          "server (read-only fail2ban status)",
		rpc.MF2BUnban:           "server (fail2ban unban; jail and IP validated)",
		rpc.MF2BIgnore:          "server (fail2ban runtime ignoreip; jail and IP validated)",
	} {
		gateExempt[m] = why
	}
}

func (a *Agent) usagexRoutes() map[string]handler {
	return map[string]handler{
		rpc.MUsageBandwidthScan: bind(a.bandwidthScan),
		rpc.MF2BStatus:          bind(a.f2bStatus),
		rpc.MF2BUnban:           bind(a.f2bUnban),
		rpc.MF2BIgnore:          bind(a.f2bIgnore),
	}
}

// ---- bandwidth -------------------------------------------------------------

func (a *Agent) bandwidthScan(ctx context.Context, p rpc.BWScanParams) (rpc.BWScanResult, error) {
	if len(p.Cursors) > bwMaxDomains {
		return rpc.BWScanResult{}, errf("bad_params", "too many domains")
	}
	max := p.MaxBytes
	if max <= 0 {
		max = bwDefaultMax
	}
	if max > bwHardMax {
		max = bwHardMax
	}
	out := rpc.BWScanResult{Domains: []rpc.BWDomainResult{}}
	for _, c := range p.Cursors {
		if ctx.Err() != nil {
			break
		}
		d := strings.ToLower(c.Domain)
		if validate.Domain(d) != nil || strings.ContainsAny(d, "/\\") {
			return rpc.BWScanResult{}, errf("invalid_domain", "%s", c.Domain)
		}
		out.Domains = append(out.Domains, ScanDomlog(filepath.Join(DomlogDir, d+".access.log"), d, c.Inode, c.Offset, max))
	}
	return out, nil
}

// ScanDomlog reads at most max bytes of complete lines of one log, starting at
// offset when the file is still the same inode (else from 0: rotated).
func ScanDomlog(path, domain string, inode uint64, offset, max int64) rpc.BWDomainResult {
	res := rpc.BWDomainResult{Domain: domain, Status: "ok", Days: []rpc.BWDay{}, Inode: inode, Offset: offset}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		res.Status, res.Reason = "no_log", "log file not found"
		if !errors.Is(err, os.ErrNotExist) {
			res.Reason = "log file not readable"
		}
		return res
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		res.Status, res.Reason = "no_log", "not a regular file"
		return res
	}
	var ino uint64
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		ino = sys.Ino
	}
	if ino != inode || st.Size() < offset || offset < 0 {
		if inode != 0 {
			res.Status = "rotated"
		}
		offset = 0
	}
	res.Inode = ino
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		res.Offset = 0
		return res
	}
	days := map[string]*rpc.BWDay{}
	consumed, skipped, more := ParseAccessLog(io.LimitReader(f, max), days)
	res.Offset = offset + consumed
	res.Skipped = skipped
	res.More = more || res.Offset < st.Size() && consumed >= max-bwMaxLine
	keys := make([]string, 0, len(days))
	for k := range days {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res.Days = append(res.Days, *days[k])
	}
	return res
}

// ParseAccessLog aggregates nginx "combined" lines (bytes sent = $body_bytes_sent)
// into days (UTC). Only complete (newline-terminated) lines are consumed; the
// returned count is the number of bytes consumed so a partial trailing line is
// re-read next time. Over-long lines are skipped as unparsable.
func ParseAccessLog(r io.Reader, days map[string]*rpc.BWDay) (consumed, skipped int64, more bool) {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// over-long line: consume it to its end
			n := int64(len(line))
			for errors.Is(err, bufio.ErrBufferFull) {
				line, err = br.ReadSlice('\n')
				n += int64(len(line))
			}
			if err != nil {
				return consumed, skipped, true
			}
			consumed += n
			skipped++
			continue
		}
		if err != nil { // EOF / limit: partial line not consumed
			return consumed, skipped, len(line) > 0
		}
		consumed += int64(len(line))
		day, b, ok := parseCombined(line)
		if !ok {
			skipped++
			continue
		}
		d := days[day]
		if d == nil {
			d = &rpc.BWDay{Day: day}
			days[day] = d
		}
		d.Bytes += b
		d.Hits++
	}
}

// parseCombined extracts the UTC day and the bytes field of one combined line:
// ip - user [10/Oct/2026:13:55:36 +0300] "GET / HTTP/1.1" 200 1234 "ref" "ua"
func parseCombined(l []byte) (string, int64, bool) {
	i := bytes.IndexByte(l, '[')
	j := bytes.IndexByte(l, ']')
	if i < 0 || j < i {
		return "", 0, false
	}
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", string(l[i+1:j]))
	if err != nil {
		return "", 0, false
	}
	rest := l[j+1:]
	q1 := bytes.IndexByte(rest, '"')
	if q1 < 0 {
		return "", 0, false
	}
	q2 := q1 + 1
	for q2 < len(rest) { // request may contain escaped quotes (\x22 in nginx, but be safe)
		if rest[q2] == '"' && rest[q2-1] != '\\' {
			break
		}
		q2++
	}
	if q2 >= len(rest) {
		return "", 0, false
	}
	f := bytes.Fields(rest[q2+1:])
	if len(f) < 2 {
		return "", 0, false
	}
	if _, err := strconv.Atoi(string(f[0])); err != nil {
		return "", 0, false
	}
	var n int64
	if string(f[1]) != "-" {
		n, err = strconv.ParseInt(string(f[1]), 10, 64)
		if err != nil || n < 0 {
			return "", 0, false
		}
	}
	return t.UTC().Format("2006-01-02"), n, true
}

// ---- fail2ban --------------------------------------------------------------

var jailRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func f2bBin() (string, error) {
	if F2BClient != "" {
		if _, err := os.Stat(F2BClient); err != nil {
			return "", err
		}
		return F2BClient, nil
	}
	return exec.LookPath("fail2ban-client")
}

func f2bRun(ctx context.Context, args ...string) (string, error) {
	bin, err := f2bBin()
	if err != nil {
		return "", errNotInstalled
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return run(cctx, nil, append([]string{bin}, args...)...)
}

var errNotInstalled = errors.New("fail2ban client not found")

func f2bErrStatus(err error) (string, string) {
	if errors.Is(err, errNotInstalled) {
		return "not_installed", "fail2ban-client was not found"
	}
	return "not_running", "fail2ban server is not reachable"
}

func (a *Agent) f2bStatus(ctx context.Context, _ rpc.F2BStatusParams) (rpc.F2BStatusResult, error) {
	res := rpc.F2BStatusResult{Status: "ok", Jails: []rpc.F2BJail{}}
	out, err := f2bRun(ctx, "status")
	if err != nil {
		res.Status, res.Reason = f2bErrStatus(err)
		return res, nil
	}
	for _, j := range ParseF2BJailList(out) {
		if !jailRe.MatchString(j) {
			continue
		}
		jo, err := f2bRun(ctx, "status", j)
		if err != nil {
			continue
		}
		res.Jails = append(res.Jails, ParseF2BJail(j, jo))
	}
	return res, nil
}

// ParseF2BJailList reads "`- Jail list:	sshd, nginx-http-auth".
func ParseF2BJailList(out string) []string {
	for _, l := range strings.Split(out, "\n") {
		if k := strings.Index(l, "Jail list:"); k >= 0 {
			var js []string
			for _, j := range strings.Split(l[k+len("Jail list:"):], ",") {
				if j = strings.TrimSpace(j); j != "" {
					js = append(js, j)
				}
			}
			return js
		}
	}
	return nil
}

// ParseF2BJail reads the output of "fail2ban-client status <jail>".
func ParseF2BJail(name, out string) rpc.F2BJail {
	j := rpc.F2BJail{Name: name, Banned: []string{}}
	num := func(l, key string) (int, bool) {
		k := strings.Index(l, key)
		if k < 0 {
			return 0, false
		}
		n, err := strconv.Atoi(strings.TrimSpace(l[k+len(key):]))
		return n, err == nil
	}
	for _, l := range strings.Split(out, "\n") {
		if n, ok := num(l, "Currently failed:"); ok {
			j.CurrentlyFailed = n
		} else if n, ok := num(l, "Currently banned:"); ok {
			j.CurrentlyBanned = n
		} else if n, ok := num(l, "Total banned:"); ok {
			j.TotalBanned = n
		} else if k := strings.Index(l, "Banned IP list:"); k >= 0 {
			for _, ip := range strings.Fields(l[k+len("Banned IP list:"):]) {
				if _, err := netip.ParseAddr(ip); err == nil {
					j.Banned = append(j.Banned, ip)
				}
			}
		}
	}
	return j
}

func f2bIP(s string) (string, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String(), nil
	}
	ad, err := netip.ParseAddr(s)
	if err != nil {
		return "", errf("invalid_ip", "%s", s)
	}
	return ad.Unmap().String(), nil
}

func (a *Agent) f2bUnban(ctx context.Context, p rpc.F2BUnbanParams) (rpc.F2BActionResult, error) {
	if !jailRe.MatchString(p.Jail) {
		return rpc.F2BActionResult{}, errf("invalid_jail", "%s", p.Jail)
	}
	ip, err := f2bIP(p.IP)
	if err != nil || strings.Contains(ip, "/") {
		return rpc.F2BActionResult{}, errf("invalid_ip", "%s", p.IP)
	}
	if _, err := f2bRun(ctx, "set", p.Jail, "unbanip", ip); err != nil {
		st, why := f2bErrStatus(err)
		return rpc.F2BActionResult{Status: st, Reason: why}, nil
	}
	return rpc.F2BActionResult{Status: "done"}, nil
}

func (a *Agent) f2bIgnore(ctx context.Context, p rpc.F2BIgnoreParams) (rpc.F2BActionResult, error) {
	ip, err := f2bIP(p.IP)
	if err != nil {
		return rpc.F2BActionResult{}, err
	}
	if len(p.Jails) > 100 {
		return rpc.F2BActionResult{}, errf("bad_params", "too many jails")
	}
	verb := "addignoreip"
	if p.Remove {
		verb = "delignoreip"
	}
	for _, j := range p.Jails {
		if !jailRe.MatchString(j) {
			return rpc.F2BActionResult{}, errf("invalid_jail", "%s", j)
		}
	}
	for _, j := range p.Jails {
		if _, err := f2bRun(ctx, "set", j, verb, ip); err != nil {
			st, why := f2bErrStatus(err)
			return rpc.F2BActionResult{Status: st, Reason: why}, nil
		}
	}
	return rpc.F2BActionResult{Status: "done"}, nil
}
