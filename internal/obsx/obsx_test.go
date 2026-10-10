// SPDX-License-Identifier: Apache-2.0

package obsx

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestWriteTextFormat(t *testing.T) {
	r := NewRecorder()
	r.ObserveHTTP("GET", "/api/v1/admin/x", 200, 30*time.Millisecond)
	r.ObserveHTTP("GET", "/api/v1/admin/x", 503, 2*time.Second)
	r.ObserveAgent("system.info", nil)
	r.ObserveAgent("system.info", errors.New("x"))
	fams := append(r.Families(), Family{Name: "bpanel_cert_expiry_days", Help: "Days.\nline", Type: "gauge",
		Samples: []Sample{{L("domain", `a"b\c`), 12.5}}})
	var b bytes.Buffer
	if err := WriteText(&b, fams); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# TYPE bpanel_http_requests_total counter",
		`bpanel_http_requests_total{method="GET",route="/api/v1/admin/x",code="2xx"} 1`,
		`bpanel_http_requests_total{method="GET",route="/api/v1/admin/x",code="5xx"} 1`,
		`bpanel_http_request_duration_seconds_bucket{method="GET",route="/api/v1/admin/x",le="0.05"} 1`,
		`bpanel_http_request_duration_seconds_bucket{method="GET",route="/api/v1/admin/x",le="+Inf"} 2`,
		`bpanel_http_request_duration_seconds_count{method="GET",route="/api/v1/admin/x"} 2`,
		`bpanel_agent_calls_total{method="system.info",result="error"} 1`,
		`bpanel_cert_expiry_days{domain="a\"b\\c"} 12.5`,
		`# HELP bpanel_cert_expiry_days Days.\nline`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	line := regexp.MustCompile(`^(# (HELP|TYPE) .+|[a-zA-Z_:][a-zA-Z0-9_:]*(\{.*\})? [-+0-9.eInfNa]+)$`)
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		if !line.MatchString(ln) {
			t.Errorf("bad exposition line %q", ln)
		}
	}
}

func TestDedupCooldown(t *testing.T) {
	d := NewDeduper()
	t0 := time.Unix(1_000_000, 0)
	if n, c := d.Fire("disk:/", t0, 600); !n || c != 1 {
		t.Fatal("first fire must notify")
	}
	if n, c := d.Fire("disk:/", t0.Add(5*time.Minute), 600); n || c != 2 {
		t.Fatal("repeat inside cooldown must not notify", n, c)
	}
	if n, _ := d.Fire("other", t0.Add(5*time.Minute), 600); !n {
		t.Fatal("different key must notify")
	}
	if n, c := d.Fire("disk:/", t0.Add(11*time.Minute), 600); !n || c != 3 {
		t.Fatal("after cooldown must notify again")
	}
	d.Resolve("disk:/")
	if n, c := d.Fire("disk:/", t0.Add(12*time.Minute), 600); !n || c != 1 {
		t.Fatal("after resolve a new incident notifies")
	}
	if !ShouldNotify(0, t0, 99999) || ShouldNotify(t0.Unix(), t0.Add(time.Second), 10) {
		t.Fatal("ShouldNotify")
	}
}

func TestIncidentStateMachine(t *testing.T) {
	cases := []struct {
		from, act, to string
		ok            bool
	}{
		{IncOpen, "ack", IncAcknowledged, true},
		{IncAcknowledged, "ack", IncAcknowledged, false},
		{IncOpen, "assign", IncOpen, true},
		{IncAcknowledged, "resolve", IncResolved, true},
		{IncResolved, "resolve", IncResolved, false},
		{IncResolved, "assign", IncResolved, false},
		{IncResolved, "reopen", IncOpen, true},
		{IncOpen, "reopen", IncOpen, false},
		{IncResolved, "note", IncResolved, true},
		{IncOpen, "bogus", IncOpen, false},
	}
	for _, c := range cases {
		got, err := Transition(c.from, c.act)
		if (err == nil) != c.ok || got != c.to {
			t.Errorf("%s --%s--> %s err=%v, want %s ok=%v", c.from, c.act, got, err, c.to, c.ok)
		}
	}
}

func TestFIMDetectsChanges(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "conf")
	os.MkdirAll(conf, 0o755)
	a, b, sec := filepath.Join(conf, "a.conf"), filepath.Join(conf, "b.conf"), filepath.Join(dir, "shadow")
	os.WriteFile(a, []byte("one"), 0o644)
	os.WriteFile(b, []byte("two"), 0o644)
	os.WriteFile(sec, []byte("secret"), 0o600)
	targets := []FIMTarget{{conf, FIMHash}, {sec, FIMMeta}, {filepath.Join(dir, "missing"), FIMHash}}
	base, missing, errs := Scan(targets)
	if len(base) != 3 || len(missing) != 1 || len(errs) != 0 {
		t.Fatalf("scan: %d %v %v", len(base), missing, errs)
	}
	for _, e := range base {
		if e.Path == sec && e.SHA256 != "" {
			t.Fatal("meta mode must not hash content")
		}
	}
	if d := Diff(base, base); len(d) != 0 {
		t.Fatal("no change expected", d)
	}
	os.WriteFile(a, []byte("ONE"), 0o644) // same size, different content
	os.Remove(b)
	os.WriteFile(filepath.Join(conf, "c.conf"), []byte("x"), 0o644)
	os.Chmod(sec, 0o644)
	cur, _, _ := Scan(targets)
	d := Diff(base, cur)
	got := map[string]string{}
	for _, c := range d {
		got[filepath.Base(c.Path)] = c.Change + ":" + strings.Join(c.Fields, ",")
	}
	want := map[string]string{"a.conf": "modified:sha256", "b.conf": "removed:", "c.conf": "added:", "shadow": "modified:perm"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q (all %v)", k, got[k], v, got)
		}
	}
}

func TestHealthParsers(t *testing.T) {
	md := "Personalities : [raid1]\nmd0 : active raid1 sdb1[1] sda1[0]\n      1046528 blocks super 1.2 [2/1] [U_]\n\nunused devices: <none>\n"
	if c := ParseMdstat(md); c.Status != HFail {
		t.Fatal("degraded", c)
	}
	if c := ParseMdstat("Personalities :\nunused devices: <none>\n"); c.Status != HUnsupported {
		t.Fatal(c)
	}
	if c := ParseTimedatectl("Timezone=UTC\nNTP=yes\nNTPSynchronized=yes\n"); c.Status != HOK {
		t.Fatal(c)
	}
	if c := ParseChrony("Reference ID    : A9FEA9FE (x)\nLeap status     : Not synchronised\n"); c.Status != HWarn {
		t.Fatal(c)
	}
	if s, _ := ParseSmart("/dev/sda", "SMART overall-health self-assessment test result: PASSED\n"); s != HOK {
		t.Fatal(s)
	}
	if c := ParseFailedUnits("● nginx.service loaded failed failed nginx\n"); c.Status != HFail || c.Details[0] != "nginx.service" {
		t.Fatal(c)
	}
	if c := ParseFailedUnits(""); c.Status != HOK {
		t.Fatal(c)
	}
}
