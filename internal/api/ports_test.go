package api

import "testing"

// Ports must match cPanel/WHM conventions.
func TestDefaultPortsMatchCPanel(t *testing.T) {
	c := DefaultConfig()
	got := map[string]int{"user": c.UserPort, "user-http": c.UserHTTPPort, "admin": c.AdminPort, "admin-http": c.AdminHTTPPort, "webmail": c.WebmailPort}
	want := map[string]int{"user": 2083, "user-http": 2082, "admin": 2087, "admin-http": 2086, "webmail": 2096}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s port = %d, want %d", k, got[k], v)
		}
	}
}
