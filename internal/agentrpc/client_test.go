package agentrpc

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeAgent answers one request per connection with reply(req).
func fakeAgent(t *testing.T, reply func(Request) string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "a.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadBytes('\n')
				if err != nil {
					return
				}
				var req Request
				_ = json.Unmarshal(line, &req)
				out := reply(req)
				if out != "" {
					_, _ = c.Write([]byte(out + "\n"))
				}
			}(c)
		}
	}()
	return sock
}

func TestClientFraming(t *testing.T) {
	sock := fakeAgent(t, func(r Request) string {
		switch r.Method {
		case "ok":
			return `{"id":` + jsonInt(r.ID) + `,"result":{"version":"x"}}`
		case "err":
			return `{"id":` + jsonInt(r.ID) + `,"error":{"code":"not_found","message":"m"}}`
		case "mismatch":
			return `{"id":999999,"result":{}}`
		case "huge":
			return `{"id":` + jsonInt(r.ID) + `,"result":"` + strings.Repeat("a", MaxLine+10) + `"}`
		case "hang":
			time.Sleep(3 * time.Second)
		}
		return ""
	})
	c := NewClient(sock)
	var pr PingResult
	if err := c.Call(context.Background(), "ok", Empty{}, &pr); err != nil || pr.Version != "x" {
		t.Fatalf("ok: %v %+v", err, pr)
	}
	if err := c.Call(context.Background(), "err", Empty{}, nil); errCode(err) != "not_found" {
		t.Fatalf("err: %v", err)
	}
	if err := c.Call(context.Background(), "mismatch", Empty{}, nil); errCode(err) != "agent_io" {
		t.Fatalf("mismatch: %v", err)
	}
	if err := c.Call(context.Background(), "huge", Empty{}, nil); errCode(err) != "agent_response_too_large" {
		t.Fatalf("huge: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := c.Call(ctx, "hang", Empty{}, nil); errCode(err) != "agent_timeout" || time.Since(start) > 2*time.Second {
		t.Fatalf("hang: %v after %v", err, time.Since(start))
	}
	if err := NewClient(filepath.Join(t.TempDir(), "none.sock")).Call(context.Background(), "ok", Empty{}, nil); errCode(err) != "agent_unreachable" {
		t.Fatalf("unreachable: %v", err)
	}
}

func TestMethodTimeouts(t *testing.T) {
	if MethodTimeout(MBackupRun) <= MethodTimeout(MPing) || MethodTimeout(MPHPInstall) < 15*time.Minute {
		t.Fatal("timeouts not per method")
	}
}

func jsonInt(n uint64) string { b, _ := json.Marshal(n); return string(b) }

func errCode(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return "?" + err.Error()
}
