// SPDX-License-Identifier: Apache-2.0

package logstat

import (
	"strings"
	"testing"
	"time"
)

const sample = `203.0.113.5 - - [10/Oct/2026:10:00:00 +0000] "GET /index.php?x=1 HTTP/1.1" 200 1000 "https://www.google.com/search?q=a" "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/129.0 Safari/537.36"
203.0.113.5 - - [10/Oct/2026:10:00:01 +0000] "GET /style.css HTTP/1.1" 200 500 "https://site.test/index.php" "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/129.0 Safari/537.36"
198.51.100.9 - alice [10/Oct/2026:10:05:00 +0000] "GET /members/a.html HTTP/1.1" 200 10 "-" "curl/8.5"
198.51.100.10 - alice [10/Oct/2026:10:06:00 +0000] "GET /members/b.html HTTP/1.1" 200 10 "-" "Mozilla/5.0 (iPhone) Safari/604.1"
198.51.100.11 - alice [10/Oct/2026:10:07:00 +0000] "GET /members HTTP/1.1" 301 0 "-" "Mozilla/5.0 (Linux; Android 14) Firefox/130.0"
198.51.100.12 - bob [10/Oct/2026:10:08:00 +0000] "GET /members/ HTTP/1.1" 401 0 "-" "x"
::ffff:192.0.2.1 - - [11/Oct/2026:00:00:00 +0300] "POST /wp-login.php HTTP/1.1" 403 12 "-" "Googlebot/2.1"
garbage line
`

func TestParseLine(t *testing.T) {
	h, ok := ParseLine([]byte(strings.Split(sample, "\n")[0]))
	if !ok || h.IP != "203.0.113.5" || h.Path != "/index.php" || h.Status != 200 || h.Bytes != 1000 || h.Method != "GET" ||
		!strings.HasPrefix(h.Referrer, "https://www.google.com") || Browser(h.Agent) != "Chrome" || System(h.Agent) != "Windows" {
		t.Fatalf("%+v %v", h, ok)
	}
	if _, ok := ParseLine([]byte("garbage")); ok {
		t.Fatal("garbage parsed")
	}
	h, ok = ParseLine([]byte(`::ffff:192.0.2.1 - - [11/Oct/2026:00:00:00 +0300] "GET / HTTP/1.1" 200 - "-" "-"`))
	if !ok || h.IP != "192.0.2.1" || h.Bytes != 0 || h.Agent != "" {
		t.Fatalf("%+v %v", h, ok)
	}
}

func TestStats(t *testing.T) {
	s := NewStats("site.test")
	s.Feed(strings.NewReader(sample))
	r := s.Result()
	if r.Lines != 8 || r.Skipped != 1 || len(r.Days) != 1 {
		t.Fatalf("lines %d skipped %d days %+v", r.Lines, r.Skipped, r.Days)
	}
	d := r.Days[0] // 2026-10-10 (the +0300 line is 2026-10-10 21:00 UTC)
	if d.Day != "2026-10-10" || d.Hits != 7 || d.Visitors != 6 || d.Pages != 3 {
		t.Fatalf("%+v", r.Days)
	}
	if len(r.Referrers) != 1 || r.Referrers[0].Key != "www.google.com" {
		t.Fatalf("refs %+v", r.Referrers)
	}
	if r.Recent[0].Path != "/wp-login.php" || len(r.Recent) != 7 {
		t.Fatalf("recent %+v", r.Recent)
	}
	found := map[string]bool{}
	for _, b := range r.Browsers {
		found[b.Key] = true
	}
	for _, b := range []string{"Chrome", "Script", "Safari", "Firefox", "Robot"} {
		if !found[b] {
			t.Errorf("browser %s missing in %+v", b, r.Browsers)
		}
	}
}

func TestLeech(t *testing.T) {
	since := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	got := Leech(strings.NewReader(sample), []string{"/members/"}, since)
	if len(got) != 1 || got[0].Login != "alice" || got[0].IPs != 3 {
		t.Fatalf("%+v", got) // bob's 401 is not counted
	}
	if got := Leech(strings.NewReader(sample), []string{"/members/"}, since.Add(48*time.Hour)); len(got) != 0 {
		t.Fatalf("window: %+v", got)
	}
}

func FuzzParseLine(f *testing.F) {
	for _, l := range strings.Split(sample, "\n") {
		f.Add([]byte(l))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		h, ok := ParseLine(b)
		if ok && (h.Status < 100 || h.Bytes < 0 || h.IP == "") {
			t.Fatalf("bad hit %+v", h)
		}
	})
}
