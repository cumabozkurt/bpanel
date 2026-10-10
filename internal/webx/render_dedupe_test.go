package webx

import (
	"strings"
	"testing"
)

func TestReferersDeduplicated(t *testing.T) {
	c := &Config{Domain: "a.test"}
	c.Hotlink.Allowed = []string{"a.test", "B.test", "b.test"}
	got := RenderCtx{Mode: "nginx-apache"}.referers(c)
	for _, d := range []string{"a.test", "b.test"} {
		if n := strings.Count(got, " "+d); n != 1 {
			t.Errorf("%s rendered %d times: %s", d, n, got)
		}
	}
}

// "server_names" already covers the vhost names; repeating one makes nginx
// fail with "conflicting parameter".
func TestReferersSkipServerNames(t *testing.T) {
	c := &Config{Domain: "a.test"}
	c.Hotlink.Allowed = []string{"a.test", "c.test"}
	got := RenderCtx{Mode: "nginx-apache", Names: []string{"a.test", "www.a.test"}}.referers(c)
	if strings.Contains(got, " a.test") || !strings.Contains(got, " *.a.test") || !strings.Contains(got, " c.test") {
		t.Fatalf("got %s", got)
	}
}
