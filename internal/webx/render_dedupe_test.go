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
