package agentrpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"time"
)

// Caller is implemented by the real socket client and by the mock agent.
type Caller interface {
	Call(ctx context.Context, method string, params any, result any) error
}

// MaxLine is the largest JSON line either side accepts. File transfers are
// chunked (fileops.MaxChunkBytes, base64) so every message stays well below it.
const MaxLine = 32 << 20

// MethodTimeout is the default deadline for one agent call. Package installs
// and backups may take long; everything else is expected to finish quickly.
// The agent uses the same table, so the API never gives up (and starts a
// rollback) while the agent is still working on the same action (CODE-14).
func MethodTimeout(method string) time.Duration {
	switch method {
	case MPHPInstall:
		return 30 * time.Minute
	case MBackupRun, MBackupRestore, MBackupVerify:
		return 60 * time.Minute
	case MSSLIssue:
		return 5 * time.Minute
	case MAccountCreate, MAccountTerminate, MDiskUsage, MMailUsage, MFiles:
		return 10 * time.Minute
	default:
		return 2 * time.Minute
	}
}

// Client talks to bpanel-agent over its unix socket. One connection per call
// keeps it simple and robust across agent restarts. Closing the connection
// (context cancelled) tells the agent to cancel the running action.
type Client struct {
	Socket string
	// Timeout overrides MethodTimeout for every method when non-zero.
	Timeout time.Duration
	// DialFn, when set, replaces the unix socket dial (v0.4 msrv: mTLS to a
	// remote node). The protocol on the connection is identical.
	DialFn func(ctx context.Context) (net.Conn, error)
	seq    atomic.Uint64
}

func NewClient(socket string) *Client {
	return &Client{Socket: socket}
}

func (c *Client) Call(ctx context.Context, method string, params any, result any) error {
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = MethodTimeout(method)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := net.Dialer{Timeout: 2 * time.Second} // a missing agent fails fast (R2-PERF-6)
	var conn net.Conn
	if c.DialFn != nil {
		conn, err = c.DialFn(ctx)
	} else {
		conn, err = d.DialContext(ctx, "unix", c.Socket)
	}
	if err != nil {
		return &Error{Code: "agent_unreachable", Message: err.Error()}
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	// Abort a blocked read/write as soon as the caller's context ends.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	req := Request{V: Version, ID: c.seq.Add(1), Method: method, Params: raw}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		if ctx.Err() != nil || errors.Is(err, os.ErrDeadlineExceeded) {
			return &Error{Code: "agent_timeout", Message: "agent did not answer in time"}
		}
		return &Error{Code: "agent_io", Message: err.Error()}
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64<<10), MaxLine)
	if !sc.Scan() {
		// the socket deadline equals the context deadline and may fire first
		if ctx.Err() != nil || errors.Is(sc.Err(), os.ErrDeadlineExceeded) {
			return &Error{Code: "agent_timeout", Message: "agent did not answer in time"}
		}
		if err := sc.Err(); err != nil {
			if errors.Is(err, bufio.ErrTooLong) {
				return &Error{Code: "agent_response_too_large", Message: err.Error()}
			}
			return &Error{Code: "agent_io", Message: err.Error()}
		}
		return &Error{Code: "agent_io", Message: "no response"}
	}
	var resp Response
	if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
		return &Error{Code: "agent_io", Message: "bad response: " + err.Error()}
	}
	if resp.ID != req.ID {
		return &Error{Code: "agent_io", Message: "agent response id mismatch"}
	}
	if resp.Error != nil {
		return resp.Error
	}
	if result != nil && len(resp.Result) > 0 {
		return json.Unmarshal(resp.Result, result)
	}
	return nil
}
