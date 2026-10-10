// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

const bwLines = `1.2.3.4 - - [10/Oct/2026:13:55:36 +0300] "GET / HTTP/1.1" 200 1000 "-" "curl"
1.2.3.4 - - [10/Oct/2026:23:59:59 +0000] "GET /a\"b HTTP/1.1" 200 500 "-" "x"
garbage line
5.6.7.8 - - [11/Oct/2026:01:00:00 +0300] "HEAD / HTTP/1.1" 304 - "-" "y"
5.6.7.8 - - [11/Oct/2026:12:00:00 +0000] "GET /big HTTP/2.0" 200 2048 "-" "z"
`

func TestParseAccessLog(t *testing.T) {
	days := map[string]*rpc.BWDay{}
	n, skipped, more := ParseAccessLog(strings.NewReader(bwLines+`9.9.9.9 - - [11/Oct/2026:12:00:00 +0000] "GET`), days)
	if n != int64(len(bwLines)) || skipped != 1 || !more {
		t.Fatalf("consumed=%d want %d skipped=%d more=%v", n, len(bwLines), skipped, more)
	}
	// 01:00 +0300 on the 11th is 22:00 UTC on the 10th
	if d := days["2026-10-10"]; d == nil || d.Bytes != 1500 || d.Hits != 3 {
		t.Fatalf("10th: %+v", d)
	}
	if d := days["2026-10-11"]; d == nil || d.Bytes != 2048 || d.Hits != 1 {
		t.Fatalf("11th: %+v", d)
	}
}

func TestParseAccessLogLongLine(t *testing.T) {
	long := `1.1.1.1 - - [10/Oct/2026:10:00:00 +0000] "GET /` + strings.Repeat("a", 200<<10) + ` HTTP/1.1" 200 5 "-" "-"` + "\n"
	days := map[string]*rpc.BWDay{}
	n, skipped, _ := ParseAccessLog(strings.NewReader(long+bwLines), days)
	if n != int64(len(long)+len(bwLines)) || skipped != 2 {
		t.Fatalf("n=%d skipped=%d", n, skipped)
	}
}

func TestScanDomlogIncrementalAndRotation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.com.access.log")
	if err := os.WriteFile(p, []byte(bwLines), 0o644); err != nil {
		t.Fatal(err)
	}
	r := ScanDomlog(p, "a.com", 0, 0, 1<<20)
	if r.Status != "ok" || r.Offset != int64(len(bwLines)) || len(r.Days) != 2 {
		t.Fatalf("%+v", r)
	}
	// nothing new: no days
	r2 := ScanDomlog(p, "a.com", r.Inode, r.Offset, 1<<20)
	if len(r2.Days) != 0 || r2.Offset != r.Offset {
		t.Fatalf("%+v", r2)
	}
	// bound: small max consumes only whole lines
	r3 := ScanDomlog(p, "a.com", 0, 0, 100)
	if r3.Offset == 0 || r3.Offset > 100 || !r3.More {
		t.Fatalf("bounded %+v", r3)
	}
	// truncated (rotated in place): restart at 0
	os.WriteFile(p, []byte(bwLines[:90]), 0o644)
	r4 := ScanDomlog(p, "a.com", r.Inode, r.Offset, 1<<20)
	if r4.Offset != 87 && r4.Offset > 90 {
		t.Fatalf("rotated %+v", r4)
	}
	// symlinks are not followed
	os.Symlink(p, filepath.Join(dir, "b.com.access.log"))
	if r5 := ScanDomlog(filepath.Join(dir, "b.com.access.log"), "b.com", 0, 0, 1<<20); r5.Status != "no_log" {
		t.Fatalf("symlink followed: %+v", r5)
	}
	if r6 := ScanDomlog(filepath.Join(dir, "none.log"), "c.com", 0, 0, 1<<20); r6.Status != "no_log" {
		t.Fatalf("%+v", r6)
	}
}

func TestBandwidthScanRejectsBadDomain(t *testing.T) {
	a := &Agent{}
	for _, d := range []string{"../etc/passwd", "a/b.com", ""} {
		if _, err := a.bandwidthScan(t.Context(), rpc.BWScanParams{Cursors: []rpc.BWCursor{{Domain: d}}}); err == nil {
			t.Fatalf("%q accepted", d)
		}
	}
}

func TestF2BParsers(t *testing.T) {
	js := ParseF2BJailList("Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, nginx-http-auth\n")
	if len(js) != 2 || js[1] != "nginx-http-auth" {
		t.Fatalf("%v", js)
	}
	j := ParseF2BJail("sshd", "Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t3\n|  |- Total failed:\t40\n`- Actions\n   |- Currently banned:\t2\n   |- Total banned:\t9\n   `- Banned IP list:\t203.0.113.5 2001:db8::1 bogus\n")
	if j.CurrentlyFailed != 3 || j.CurrentlyBanned != 2 || j.TotalBanned != 9 || len(j.Banned) != 2 {
		t.Fatalf("%+v", j)
	}
}

func TestF2BNotInstalled(t *testing.T) {
	old := F2BClient
	F2BClient = filepath.Join(t.TempDir(), "nope")
	defer func() { F2BClient = old }()
	a := &Agent{}
	st, err := a.f2bStatus(t.Context(), rpc.F2BStatusParams{})
	if err != nil || st.Status != "not_installed" {
		t.Fatalf("%+v %v", st, err)
	}
	if _, err := a.f2bUnban(t.Context(), rpc.F2BUnbanParams{Jail: "sshd;rm", IP: "1.2.3.4"}); err == nil {
		t.Fatal("bad jail accepted")
	}
	if _, err := a.f2bUnban(t.Context(), rpc.F2BUnbanParams{Jail: "sshd", IP: "1.2.3.4 -x"}); err == nil {
		t.Fatal("bad ip accepted")
	}
	r, err := a.f2bUnban(t.Context(), rpc.F2BUnbanParams{Jail: "sshd", IP: "1.2.3.4"})
	if err != nil || r.Status != "not_installed" {
		t.Fatalf("%+v %v", r, err)
	}
}
