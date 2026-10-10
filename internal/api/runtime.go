package api

import (
	"compress/gzip"
	"context"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/auth"
)

// ---- R2-PERF-1: bounded argon2id ------------------------------------------------
//
// argon2id costs 19 MiB and ~50 ms of CPU per hash. Without a cap, 40
// parallel logins took 920 MB RSS and 50-100 killed the process. At most
// hashSlots hashes run at once; a request waits up to hashWait for a slot
// and is then refused with 503 server_busy (Retry-After) instead of
// queueing without bound.

type gate struct{ ch chan struct{} }

func newGate(n int) *gate { return &gate{ch: make(chan struct{}, max(n, 1))} }

// acquire takes a slot, waiting at most wait (or until ctx ends).
func (g *gate) acquire(ctx context.Context, wait time.Duration) (func(), bool) {
	select {
	case g.ch <- struct{}{}:
		return g.release, true
	default:
	}
	if wait <= 0 {
		return nil, false
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case g.ch <- struct{}{}:
		return g.release, true
	case <-t.C:
	case <-ctx.Done():
	}
	return nil, false
}

func (g *gate) release() { <-g.ch }

func serverBusy() error {
	return &apiError{Status: http.StatusServiceUnavailable, Code: "server_busy"}
}

const hashWait = 3 * time.Second

func hashSlots() int { return max(2, 2*runtime.NumCPU()) }

// checkPassword verifies a password under the hash gate.
func (s *Server) checkPassword(ctx context.Context, hash, pw string) (bool, error) {
	rel, ok := s.hashGate.acquire(ctx, hashWait)
	if !ok {
		return false, serverBusy()
	}
	defer rel()
	return auth.CheckPassword(hash, pw), nil
}

// hashPassword hashes a password under the hash gate.
func (s *Server) hashPassword(ctx context.Context, pw string) (string, error) {
	rel, ok := s.hashGate.acquire(ctx, hashWait)
	if !ok {
		return "", serverBusy()
	}
	defer rel()
	return auth.HashPassword(pw)
}

// ---- R2-PERF-3: upload buffers ------------------------------------------------

// uploadSlots bounds parallel uploads (each holds one chunk buffer plus its
// base64 copy); further uploads get 503 server_busy.
const uploadSlots = 4

// chunkPool recycles upload chunk buffers instead of allocating 8 MiB per
// request (RSS stayed at 184 MB after an upload burst).
var chunkPool = sync.Pool{New: func() any { b := make([]byte, 0); return &b }}

func getChunk(n int) *[]byte {
	p := chunkPool.Get().(*[]byte)
	if cap(*p) < n {
		b := make([]byte, n)
		p = &b
	}
	*p = (*p)[:n]
	return p
}

func putChunk(p *[]byte) { chunkPool.Put(p) }

// ---- R2-PERF-11: log sampling -------------------------------------------------------

// sampler lets the first event per key through every window and counts
// the rest; the next event that passes reports how many were suppressed.
// A flood of 429s used to write 30 MB of identical WARN lines in 45 s.
type sampler struct {
	mu     sync.Mutex
	window time.Duration
	seen   map[string]*sampleState
	now    func() time.Time
}

type sampleState struct {
	last       time.Time
	suppressed int
}

func newSampler(window time.Duration) *sampler {
	return &sampler{window: window, seen: map[string]*sampleState{}, now: time.Now}
}

// allow reports whether to log now and how many events were dropped since
// the last logged one.
func (sm *sampler) allow(key string) (bool, int) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	now := sm.now()
	st := sm.seen[key]
	if st == nil {
		if len(sm.seen) > 10000 { // bounded memory under a spray of keys
			for k, v := range sm.seen {
				if now.Sub(v.last) > sm.window {
					delete(sm.seen, k)
				}
			}
			if len(sm.seen) > 10000 {
				sm.seen = map[string]*sampleState{}
			}
		}
		sm.seen[key] = &sampleState{last: now}
		return true, 0
	}
	if now.Sub(st.last) >= sm.window {
		n := st.suppressed
		st.last, st.suppressed = now, 0
		return true, n
	}
	st.suppressed++
	return false, 0
}

// ---- R2-PERF-2: cached counts ---------------------------------------------------------

type countCache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]countEntry
}

type countEntry struct {
	n  int64
	at time.Time
}

func (c *countCache) get(key string, now time.Time, fn func() int64) int64 {
	c.mu.Lock()
	if e, ok := c.m[key]; ok && now.Sub(e.at) < c.ttl {
		c.mu.Unlock()
		return e.n
	}
	c.mu.Unlock()
	n := fn()
	c.mu.Lock()
	if c.m == nil || len(c.m) > 256 {
		c.m = map[string]countEntry{}
	}
	c.m[key] = countEntry{n, now}
	c.mu.Unlock()
	return n
}

func (c *countCache) clear() {
	c.mu.Lock()
	c.m = nil
	c.mu.Unlock()
}

// ---- R2-PERF-7: compression ------------------------------------------------------------

// compressible content types (JSON API responses, the UI shell and assets).
func compressible(ct string) bool {
	mt, _, _ := mime.ParseMediaType(ct)
	switch {
	case mt == "application/json", mt == "application/javascript", mt == "text/javascript", mt == "image/svg+xml",
		mt == "application/manifest+json", strings.HasPrefix(mt, "text/"):
		return true
	}
	return false
}

var gzPool = sync.Pool{New: func() any { w, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed); return w }}

// gzipWriter compresses the body when the handler's Content-Type is
// compressible and no Content-Encoding was set.
type gzipWriter struct {
	http.ResponseWriter
	gz      *gzip.Writer
	decided bool
	on      bool
}

func (g *gzipWriter) decide(code int) {
	if g.decided {
		return
	}
	g.decided = true
	h := g.Header()
	if code < 200 || code == http.StatusNoContent || code == http.StatusNotModified ||
		h.Get("Content-Encoding") != "" || !compressible(h.Get("Content-Type")) {
		return
	}
	g.on = true
	h.Del("Content-Length")
	h.Set("Content-Encoding", "gzip")
	g.gz = gzPool.Get().(*gzip.Writer)
	g.gz.Reset(g.ResponseWriter)
}

func (g *gzipWriter) WriteHeader(code int) {
	g.decide(code)
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	if !g.decided {
		if g.Header().Get("Content-Type") == "" {
			g.Header().Set("Content-Type", http.DetectContentType(b))
		}
		g.decide(http.StatusOK)
	}
	if g.on {
		return g.gz.Write(b)
	}
	return g.ResponseWriter.Write(b)
}

func (g *gzipWriter) Flush() {
	if g.on {
		_ = g.gz.Flush()
	}
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the connection.
func (g *gzipWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

func (g *gzipWriter) close() {
	if g.on {
		_ = g.gz.Close()
		g.gz.Reset(io.Discard)
		gzPool.Put(g.gz)
	}
}

func acceptsEncoding(r *http.Request, enc string) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(name), enc) {
			continue
		}
		for _, p := range strings.Split(params, ";") {
			k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
			if strings.EqualFold(k, "q") {
				if q, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && q == 0 {
					return false
				}
			}
		}
		return true
	}
	return false
}

// compress gzips API and UI responses (R2-PERF-7). Downloads, uploads and
// the phpMyAdmin proxy are left alone, as are HEAD and Range requests.
func (s *Server) compress(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if r.Method == http.MethodHead || r.Header.Get("Range") != "" || !acceptsEncoding(r, "gzip") ||
			p == "/api/v1/user/files/download" || p == "/api/v1/user/files/upload" || strings.HasPrefix(p, "/3rdparty/") ||
			p == "/api/v1/user/terminal/ws" { // v0.4 devx: WebSocket upgrade needs the raw (hijackable) writer
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Accept-Encoding")
		gw := &gzipWriter{ResponseWriter: w}
		defer gw.close()
		next.ServeHTTP(gw, r)
	})
}

// precompressed serves name.br / name.gz from the embedded UI when the
// build produced them and the client accepts the encoding.
func (s *Server) precompressed(w http.ResponseWriter, r *http.Request, name string) bool {
	for _, enc := range []struct{ ext, name string }{{".br", "br"}, {".gz", "gzip"}} {
		if !acceptsEncoding(r, enc.name) {
			continue
		}
		b, err := fs.ReadFile(s.Static, name+enc.ext)
		if err != nil {
			continue
		}
		ct := mime.TypeByExtension(path.Ext(name))
		if ct == "" {
			ct = "application/octet-stream"
		}
		h := w.Header()
		h.Set("Content-Type", ct)
		h.Set("Content-Encoding", enc.name)
		h.Add("Vary", "Accept-Encoding")
		_, _ = w.Write(b)
		return true
	}
	return false
}

// ---- R2-PERF-16: sysinfo cache -------------------------------------------------------

// sysInfoCache keeps the agent's host metrics for a few seconds: every
// dashboard load used to cost a 200 ms CPU sample in the agent.
type sysInfoCache struct {
	mu sync.Mutex
	at time.Time
	v  rpc.SysInfo
}

const sysInfoTTL = 5 * time.Second

func (s *Server) sysInfo(r *http.Request) (rpc.SysInfo, error) {
	s.sysCache.mu.Lock()
	defer s.sysCache.mu.Unlock() // one fetch at a time; others wait and reuse it
	if !s.sysCache.at.IsZero() && s.Now().Sub(s.sysCache.at) < sysInfoTTL {
		return s.sysCache.v, nil
	}
	var si rpc.SysInfo
	if err := s.agentCall(r, rpc.MSysInfo, rpc.Empty{}, &si); err != nil {
		return si, err
	}
	s.sysCache.v, s.sysCache.at = si, s.Now()
	return si, nil
}
