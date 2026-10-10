// SPDX-License-Identifier: Apache-2.0

// Package logstat parses nginx/Apache "combined" access-log lines and builds
// the Awstats / cPanel "Visitors"-style summaries of the user panel
// (visitors per day, top pages, referrers, browsers, systems, status codes)
// and the Leech Protection counts (distinct client IPs per basic-auth login).
// It is pure: the agent feeds it a bounded tail of a domain log.
package logstat

import (
	"bufio"
	"bytes"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// Hit is one parsed line.
type Hit struct {
	IP       string
	User     string // basic-auth login ("" when "-")
	Time     time.Time
	Method   string
	Path     string // without the query string
	Status   int
	Bytes    int64
	Referrer string
	Agent    string
}

// MaxLine bounds one line; longer lines are skipped.
const MaxLine = 16 << 10

// quoted returns the content of the next "..." field of b and the rest.
func quoted(b []byte) (string, []byte, bool) {
	i := bytes.IndexByte(b, '"')
	if i < 0 {
		return "", nil, false
	}
	j := i + 1
	for j < len(b) {
		if b[j] == '"' && b[j-1] != '\\' {
			return string(b[i+1 : j]), b[j+1:], true
		}
		j++
	}
	return "", nil, false
}

// ParseLine parses one combined line:
// ip - user [10/Oct/2026:13:55:36 +0300] "GET /a?b HTTP/1.1" 200 1234 "ref" "ua"
func ParseLine(l []byte) (Hit, bool) {
	var h Hit
	l = bytes.TrimRight(l, "\r\n")
	if len(l) == 0 || len(l) > MaxLine {
		return h, false
	}
	i := bytes.IndexByte(l, '[')
	j := bytes.IndexByte(l, ']')
	if i < 0 || j < i {
		return h, false
	}
	head := bytes.Fields(l[:i])
	if len(head) < 3 {
		return h, false
	}
	ip, err := netip.ParseAddr(string(head[0]))
	if err != nil {
		return h, false
	}
	h.IP = ip.Unmap().String()
	if u := string(head[2]); u != "-" {
		h.User = u
	}
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", string(l[i+1:j]))
	if err != nil {
		return h, false
	}
	h.Time = t
	req, rest, ok := quoted(l[j+1:])
	if !ok {
		return h, false
	}
	if f := strings.Fields(req); len(f) >= 2 {
		h.Method, h.Path = f[0], f[1]
		if q := strings.IndexByte(h.Path, '?'); q >= 0 {
			h.Path = h.Path[:q]
		}
	}
	f := bytes.Fields(rest)
	if len(f) < 2 {
		return h, false
	}
	if h.Status, err = strconv.Atoi(string(f[0])); err != nil || h.Status < 100 || h.Status > 999 {
		return h, false
	}
	if string(f[1]) != "-" {
		if h.Bytes, err = strconv.ParseInt(string(f[1]), 10, 64); err != nil || h.Bytes < 0 {
			return h, false
		}
	}
	// referrer and user agent are optional (common log format has neither)
	if ref, rest2, ok := quoted(rest); ok {
		if ref != "-" {
			h.Referrer = ref
		}
		if ua, _, ok := quoted(rest2); ok && ua != "-" {
			h.Agent = ua
		}
	}
	return h, true
}

// Browser maps a User-Agent to a browser family.
func Browser(ua string) string {
	l := strings.ToLower(ua)
	switch {
	case ua == "":
		return "Unknown"
	case strings.Contains(l, "bot") || strings.Contains(l, "crawler") || strings.Contains(l, "spider") || strings.Contains(l, "slurp"):
		return "Robot"
	case strings.Contains(l, "curl/") || strings.Contains(l, "wget/") || strings.Contains(l, "python-") || strings.Contains(l, "go-http-client"):
		return "Script"
	case strings.Contains(l, "edg/"):
		return "Edge"
	case strings.Contains(l, "opr/") || strings.Contains(l, "opera"):
		return "Opera"
	case strings.Contains(l, "firefox/"):
		return "Firefox"
	case strings.Contains(l, "chrome/") || strings.Contains(l, "crios/"):
		return "Chrome"
	case strings.Contains(l, "safari/"):
		return "Safari"
	}
	return "Other"
}

// System maps a User-Agent to an operating system family.
func System(ua string) string {
	l := strings.ToLower(ua)
	switch {
	case strings.Contains(l, "android"):
		return "Android"
	case strings.Contains(l, "iphone") || strings.Contains(l, "ipad"):
		return "iOS"
	case strings.Contains(l, "windows"):
		return "Windows"
	case strings.Contains(l, "mac os x") || strings.Contains(l, "macintosh"):
		return "macOS"
	case strings.Contains(l, "linux"):
		return "Linux"
	}
	return "Other"
}

// IsPage reports whether a request counts as a page view (not an asset).
func IsPage(h Hit) bool {
	if h.Status >= 300 && h.Status != 304 || h.Method != "GET" && h.Method != "POST" {
		return false
	}
	p := strings.ToLower(h.Path)
	dot := strings.LastIndexByte(p, '.')
	if dot < strings.LastIndexByte(p, '/') || dot < 0 {
		return true
	}
	switch p[dot+1:] {
	case "html", "htm", "php", "shtml", "asp", "aspx", "jsp", "cgi", "pl":
		return true
	}
	return false
}

// Stats aggregates hits.
type Stats struct {
	Lines, Skipped int64
	days           map[string]*rpc.LogDay
	dayIPs         map[string]map[string]bool
	pages, refs    map[string]int64
	browsers, oses map[string]int64
	codes, hosts   map[string]int64
	recent         []rpc.LogHit
	self           string
}

// NewStats returns an empty aggregator; self is the site's own domain
// (referrers from it are not counted).
func NewStats(self string) *Stats {
	return &Stats{days: map[string]*rpc.LogDay{}, dayIPs: map[string]map[string]bool{}, pages: map[string]int64{},
		refs: map[string]int64{}, browsers: map[string]int64{}, oses: map[string]int64{}, codes: map[string]int64{},
		hosts: map[string]int64{}, self: strings.ToLower(self)}
}

const maxKeys = 20000 // distinct keys kept per table (memory bound)

func bump(m map[string]int64, k string) {
	if _, ok := m[k]; ok || len(m) < maxKeys {
		m[k]++
	}
}

// RecentMax is how many of the newest hits are kept.
const RecentMax = 100

// Add counts one hit.
func (s *Stats) Add(h Hit) {
	day := h.Time.UTC().Format("2006-01-02")
	d := s.days[day]
	if d == nil {
		d = &rpc.LogDay{Day: day}
		s.days[day] = d
		s.dayIPs[day] = map[string]bool{}
	}
	d.Hits++
	d.Bytes += h.Bytes
	if !s.dayIPs[day][h.IP] && len(s.dayIPs[day]) < 1<<20 {
		s.dayIPs[day][h.IP] = true
		d.Visitors++
	}
	if IsPage(h) {
		d.Pages++
		bump(s.pages, h.Path)
	}
	if h.Referrer != "" {
		host := h.Referrer
		if k := strings.Index(host, "://"); k >= 0 {
			host = host[k+3:]
		}
		if k := strings.IndexAny(host, "/?#"); k >= 0 {
			host = host[:k]
		}
		host = strings.ToLower(host)
		if host != "" && host != s.self && !strings.HasSuffix(host, "."+s.self) {
			bump(s.refs, host)
		}
	}
	bump(s.browsers, Browser(h.Agent))
	bump(s.oses, System(h.Agent))
	bump(s.codes, strconv.Itoa(h.Status))
	bump(s.hosts, h.IP)
	s.recent = append(s.recent, rpc.LogHit{Time: h.Time.Unix(), IP: h.IP, Method: h.Method, Path: h.Path, Status: h.Status,
		Bytes: h.Bytes, Referrer: h.Referrer, Agent: h.Agent})
	if len(s.recent) > 2*RecentMax {
		s.recent = append(s.recent[:0], s.recent[len(s.recent)-RecentMax:]...)
	}
}

// Feed parses every line of r.
func (s *Stats) Feed(r io.Reader) {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			s.Skipped++
			for err == bufio.ErrBufferFull {
				_, err = br.ReadSlice('\n')
			}
			continue
		}
		if len(line) > 0 {
			s.Lines++
			if h, ok := ParseLine(line); ok {
				s.Add(h)
			} else {
				s.Skipped++
			}
		}
		if err != nil {
			return
		}
	}
}

func top(m map[string]int64, n int) []rpc.LogCount {
	out := make([]rpc.LogCount, 0, len(m))
	for k, v := range m {
		out = append(out, rpc.LogCount{Key: k, N: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Result renders the aggregate (days ascending, tables top-N, newest hits first).
func (s *Stats) Result() rpc.LogStatsResult {
	res := rpc.LogStatsResult{Status: "ok", Lines: s.Lines, Skipped: s.Skipped, Days: []rpc.LogDay{}}
	keys := make([]string, 0, len(s.days))
	for k := range s.days {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res.Days = append(res.Days, *s.days[k])
	}
	res.Pages, res.Referrers, res.Browsers = top(s.pages, 25), top(s.refs, 25), top(s.browsers, 10)
	res.Systems, res.Codes, res.Hosts = top(s.oses, 10), top(s.codes, 15), top(s.hosts, 25)
	rec := s.recent
	if len(rec) > RecentMax {
		rec = rec[len(rec)-RecentMax:]
	}
	res.Recent = make([]rpc.LogHit, 0, len(rec))
	for i := len(rec) - 1; i >= 0; i-- {
		res.Recent = append(res.Recent, rec[i])
	}
	return res
}

// Leech counts distinct client IPs per (protected path, login) for hits not
// older than since. paths are "/dir/" prefixes; the longest match wins.
func Leech(r io.Reader, paths []string, since time.Time) []rpc.LeechHit {
	ps := append([]string{}, paths...)
	sort.Slice(ps, func(i, j int) bool { return len(ps[i]) > len(ps[j]) })
	seen := map[[2]string]map[string]bool{}
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			for err == bufio.ErrBufferFull {
				_, err = br.ReadSlice('\n')
			}
			continue
		}
		if h, ok := ParseLine(line); ok && h.User != "" && !h.Time.Before(since) && h.Status < 400 {
			for _, p := range ps {
				if strings.HasPrefix(h.Path, p) || h.Path+"/" == p {
					k := [2]string{p, h.User}
					if seen[k] == nil {
						if len(seen) > maxKeys {
							break
						}
						seen[k] = map[string]bool{}
					}
					if len(seen[k]) < 10000 {
						seen[k][h.IP] = true
					}
					break
				}
			}
		}
		if err != nil {
			break
		}
	}
	out := []rpc.LeechHit{}
	for k, v := range seen {
		out = append(out, rpc.LeechHit{Path: k[0], Login: k[1], IPs: len(v)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Login < out[j].Login
	})
	return out
}
