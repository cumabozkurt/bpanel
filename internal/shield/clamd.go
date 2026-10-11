package shield

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ClamAV through clamd's socket protocol (zINSTREAM). Implemented here with
// the standard library only; ClamAV itself (GPL-2.0) runs as a separate
// daemon and is never linked into BPANEL.
//
// Protocol (clamd(8), "INSTREAM"): the client sends "zINSTREAM\0", then the
// file as chunks of <uint32 big-endian length><bytes>, then a zero-length
// chunk. clamd answers one NUL-terminated line:
//
//	"stream: OK"
//	"stream: Eicar-Test-Signature FOUND"
//	"INSTREAM size limit exceeded. ERROR"
//	"<anything> ERROR"
type Clamd struct {
	// Addr is "unix:/run/clamav/clamd.ctl" or "tcp:127.0.0.1:3310".
	Addr string
	// Timeout bounds one whole scan (connect + stream + verdict).
	Timeout time.Duration
	// ChunkSize of the INSTREAM chunks (clamd's StreamMaxLength still applies).
	ChunkSize int
	// MaxStream is the largest file sent (should be <= clamd StreamMaxLength).
	MaxStream int64
	// Disabled by the admin (status "disabled", never scans).
	Disabled bool

	mu       sync.Mutex
	verCache string
	verAt    time.Time
}

const DefaultClamdAddr = "unix:/run/clamav/clamd.ctl"

func NewClamd(addr string) *Clamd {
	if addr == "" {
		addr = DefaultClamdAddr
	}
	return &Clamd{Addr: addr, Timeout: 60 * time.Second, ChunkSize: 64 << 10, MaxStream: 100 << 20}
}

func (c *Clamd) Name() string { return "clamav" }
func (c *Clamd) Kind() string { return KindExternal }

func (c *Clamd) dial(ctx context.Context) (net.Conn, error) {
	network, addr, ok := strings.Cut(c.Addr, ":")
	if !ok || (network != "unix" && network != "tcp") {
		return nil, fmt.Errorf("%w: bad clamd address %q", ErrUnavailable, c.Addr)
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	return conn, nil
}

// command sends one z-command without payload and returns the reply line.
func (c *Clamd) command(ctx context.Context, cmd string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := c.dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("z" + cmd + "\x00")); err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return readReply(conn)
}

func readReply(r io.Reader) (string, error) {
	br := bufio.NewReader(io.LimitReader(r, 4096))
	line, err := br.ReadString(0)
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return "", ErrTimeout
		}
		return "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return strings.TrimRight(line, "\x00\n"), nil
}

// Ping is clamd's PING ("PONG").
func (c *Clamd) Ping(ctx context.Context) error {
	r, err := c.command(ctx, "PING")
	if err != nil {
		return err
	}
	if r != "PONG" {
		return fmt.Errorf("%w: unexpected PING reply %q", ErrUnavailable, r)
	}
	return nil
}

// Version returns clamd's VERSION line, e.g.
// "ClamAV 1.0.7/27423/Wed Oct  8 08:31:12 2026" (engine/db-version/db-date).
//
// ClamAV 1.5 can disable the VERSION command ("COMMAND UNAVAILABLE"); the
// reply was then shown as the engine version next to an "OK" status. Any
// reply that is not a version line falls back to the local "clamscan
// --version" (same engine and database on a single-host install).
func (c *Clamd) Version(ctx context.Context) (string, error) {
	v, err := c.command(ctx, "VERSION")
	if err == nil && strings.HasPrefix(v, "ClamAV ") {
		return v, nil
	}
	if lv, lerr := localClamVersion(ctx); lerr == nil {
		return lv, nil
	}
	if err != nil {
		return "", err
	}
	return "", fmt.Errorf("%w: clamd VERSION reply %q", ErrUnavailable, v)
}

// localClamVersion runs "clamscan --version" (variable for tests).
var localClamVersion = func(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "clamscan", "--version").Output()
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(out))
	if !strings.HasPrefix(v, "ClamAV ") {
		return "", fmt.Errorf("%w: unexpected clamscan --version output", ErrUnavailable)
	}
	return v, nil
}

// ParseClamVersion splits a VERSION line into engine, db version and db time.
func ParseClamVersion(v string) (engine, db string, dbTime time.Time) {
	parts := strings.SplitN(v, "/", 3)
	engine = strings.TrimSpace(parts[0])
	if len(parts) > 1 {
		db = strings.TrimSpace(parts[1])
	}
	if len(parts) > 2 {
		for _, layout := range []string{"Mon Jan _2 15:04:05 2006", "Mon Jan 2 15:04:05 2006"} {
			if t, err := time.Parse(layout, strings.TrimSpace(parts[2])); err == nil {
				dbTime = t
				break
			}
		}
	}
	return
}

func (c *Clamd) Available(ctx context.Context) bool {
	return !c.Disabled && c.Ping(ctx) == nil
}

func (c *Clamd) SignatureVersion(ctx context.Context) string {
	c.mu.Lock()
	if c.verCache != "" && time.Since(c.verAt) < time.Minute {
		v := c.verCache
		c.mu.Unlock()
		return v
	}
	c.mu.Unlock()
	v, err := c.Version(ctx)
	if err != nil {
		return "clamav:unavailable"
	}
	eng, db, _ := ParseClamVersion(v)
	s := "clamav:" + eng + "/" + db
	c.mu.Lock()
	c.verCache, c.verAt = s, time.Now()
	c.mu.Unlock()
	return s
}

// MaxDBAge after which the signature DB is reported as degraded.
var MaxDBAge = 72 * time.Hour

func (c *Clamd) Status(ctx context.Context) ProviderStatus {
	st := ProviderStatus{Name: c.Name(), Kind: c.Kind(), License: "GPL-2.0 (separate daemon, not linked)", RealTime: true, OnDemand: true,
		CheckedUnix: time.Now().Unix()}
	if c.Disabled {
		st.Status, st.Reason = StatusDisabled, "disabled in the Shield settings"
		return st
	}
	if err := c.Ping(ctx); err != nil {
		st.Status = StatusUnavailable
		if network, addr, _ := strings.Cut(c.Addr, ":"); network == "unix" {
			if _, serr := os.Stat(addr); serr != nil {
				st.Status = StatusNotInstalled
				st.Reason = "clamd socket " + addr + " not found (clamav-daemon not installed or not running)"
				return st
			}
		}
		st.Reason = err.Error()
		return st
	}
	v, err := c.Version(ctx)
	if err != nil {
		// clamd answers PING, so scans work; only the engine/database
		// version (and with it the signature age) is unknown.
		st.Status, st.Reason = StatusDegraded, "clamd is running but its version is unknown: "+err.Error()
		return st
	}
	eng, db, t := ParseClamVersion(v)
	st.Status, st.Version, st.SigVersion = StatusOK, eng, db
	if !t.IsZero() {
		st.DBTimeUnix = t.Unix()
		st.DBAgeHours = int64(time.Since(t).Hours())
		if time.Since(t) > MaxDBAge {
			st.Status = StatusDegraded
			st.Reason = "signature database is older than " + strconv.Itoa(int(MaxDBAge.Hours())) + " hours (is freshclam running?)"
		}
	}
	return st
}

// Scan streams the file to clamd with zINSTREAM.
func (c *Clamd) Scan(ctx context.Context, t Target) (EngineResult, error) {
	start := time.Now()
	res := EngineResult{Engine: c.Name()}
	if c.Disabled {
		return res, fmt.Errorf("%w: disabled", ErrUnavailable)
	}
	f, err := os.Open(t.Path)
	if err != nil {
		return res, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return res, err
	}
	if c.MaxStream > 0 && st.Size() > c.MaxStream {
		return res, ErrTooLarge
	}
	res, err = c.ScanReader(ctx, f)
	res.Took = time.Since(start)
	return res, err
}

// ScanReader streams r to clamd.
func (c *Clamd) ScanReader(ctx context.Context, r io.Reader) (EngineResult, error) {
	res := EngineResult{Engine: c.Name()}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := c.dial(ctx)
	if err != nil {
		return res, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	w := bufio.NewWriterSize(conn, 64<<10)
	if _, err := w.WriteString("zINSTREAM\x00"); err != nil {
		return res, c.ioErr(ctx, err)
	}
	cs := c.ChunkSize
	if cs <= 0 {
		cs = 64 << 10
	}
	buf := make([]byte, cs)
	var hdr [4]byte
	var sent int64
	for {
		n, rerr := io.ReadFull(r, buf)
		if n > 0 {
			binary.BigEndian.PutUint32(hdr[:], uint32(n))
			if _, err := w.Write(hdr[:]); err != nil {
				return c.writeFail(ctx, conn, res, err)
			}
			if _, err := w.Write(buf[:n]); err != nil {
				return c.writeFail(ctx, conn, res, err)
			}
			sent += int64(n)
			if c.MaxStream > 0 && sent > c.MaxStream {
				return res, ErrTooLarge
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
				break
			}
			return res, rerr
		}
	}
	binary.BigEndian.PutUint32(hdr[:], 0)
	if _, err := w.Write(hdr[:]); err != nil {
		return res, c.ioErr(ctx, err)
	}
	if err := w.Flush(); err != nil {
		return c.writeFail(ctx, conn, res, err)
	}
	line, err := readReply(conn)
	if err != nil {
		if ctx.Err() != nil {
			return res, ErrTimeout
		}
		return res, err
	}
	return parseInstreamReply(line, res)
}

// writeFail: clamd closes the stream early (e.g. "INSTREAM size limit
// exceeded. ERROR") and our write then fails with EPIPE; read its reply.
func (c *Clamd) writeFail(ctx context.Context, conn net.Conn, res EngineResult, err error) (EngineResult, error) {
	if ctx.Err() == nil {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if line, rerr := readReply(conn); rerr == nil && line != "" {
			return parseInstreamReply(line, res)
		}
	}
	return res, c.ioErr(ctx, err)
}

func (c *Clamd) ioErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ErrTimeout
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}

func parseInstreamReply(line string, res EngineResult) (EngineResult, error) {
	body := line
	if i := strings.Index(line, ": "); i >= 0 && strings.HasPrefix(line, "stream") {
		body = line[i+2:]
	}
	switch {
	case body == "OK":
		res.Verdict = Clean
		return res, nil
	case strings.HasSuffix(body, " FOUND"):
		sig := strings.TrimSuffix(body, " FOUND")
		v, sev := Infected, SevHigh
		// ClamAV "PUA." (potentially unwanted) and heuristic hits are softer
		if strings.HasPrefix(sig, "PUA.") || strings.HasPrefix(sig, "Heuristics.") {
			v, sev = Suspicious, SevMedium
		}
		res.Verdict = v
		res.Detections = []Detection{{Engine: "clamav", Signature: sig, Verdict: v, Severity: sev}}
		return res, nil
	case strings.Contains(body, "size limit exceeded"):
		return res, ErrTooLarge
	case strings.HasSuffix(body, " ERROR") || strings.HasSuffix(line, "ERROR"):
		return res, fmt.Errorf("%w: clamd: %s", ErrUnavailable, line)
	}
	return res, fmt.Errorf("%w: unexpected clamd reply %q", ErrUnavailable, line)
}

// ---- fake clamd for tests (speaks the real protocol) ----------------------------

// FakeClamd is a minimal clamd speaking PING/VERSION/zINSTREAM over a real
// socket, flagging a stream that contains any of Sigs. Used by tests when
// clamav-daemon cannot be installed; it exercises the real client code path.
type FakeClamd struct {
	Sigs    map[string]string // byte pattern -> signature name
	Version string
	Delay   time.Duration // per INSTREAM, to simulate a slow engine
	MaxLen  int           // StreamMaxLength; 0 = 200 MiB
	ln      net.Listener
	wg      sync.WaitGroup
	Scans   int
	mu      sync.Mutex
}

// EICAR is the standard antivirus test string (not malware).
// Split so that BPANEL's own source/binary does not trip antivirus scanners.
const EICAR = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR` + `-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

func StartFakeClamd(sock string) (*FakeClamd, error) {
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	f := &FakeClamd{ln: ln, Sigs: map[string]string{EICAR: "Eicar-Test-Signature"},
		Version: "ClamAV 1.0.7/27423/" + time.Now().UTC().Format("Mon Jan _2 15:04:05 2006")}
	f.wg.Add(1)
	go f.serve()
	return f, nil
}

func (f *FakeClamd) Close() { _ = f.ln.Close(); f.wg.Wait() }

func (f *FakeClamd) serve() {
	defer f.wg.Done()
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.wg.Add(1)
		go func() { defer f.wg.Done(); f.handle(c) }()
	}
}

func (f *FakeClamd) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	cmd, err := br.ReadString(0)
	if err != nil {
		return
	}
	cmd = strings.TrimSuffix(cmd, "\x00")
	switch cmd {
	case "zPING":
		_, _ = c.Write([]byte("PONG\x00"))
	case "zVERSION":
		_, _ = c.Write([]byte(f.Version + "\x00"))
	case "zINSTREAM":
		var data bytes.Buffer
		var hdr [4]byte
		for {
			if _, err := io.ReadFull(br, hdr[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(hdr[:])
			if n == 0 {
				break
			}
			limit := 200 << 20
			if f.MaxLen > 0 {
				limit = f.MaxLen
			}
			if data.Len()+int(n) > limit {
				_, _ = c.Write([]byte("INSTREAM size limit exceeded. ERROR\x00"))
				return
			}
			if _, err := io.CopyN(&data, br, int64(n)); err != nil {
				return
			}
		}
		f.mu.Lock()
		f.Scans++
		d := f.Delay
		f.mu.Unlock()
		if d > 0 {
			time.Sleep(d)
		}
		for pat, name := range f.Sigs {
			if bytes.Contains(data.Bytes(), []byte(pat)) {
				_, _ = c.Write([]byte("stream: " + name + " FOUND\x00"))
				return
			}
		}
		_, _ = c.Write([]byte("stream: OK\x00"))
	default:
		_, _ = c.Write([]byte("UNKNOWN COMMAND\x00"))
	}
}
