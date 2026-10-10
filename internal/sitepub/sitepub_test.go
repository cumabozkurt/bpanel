// SPDX-License-Identifier: Apache-2.0

package sitepub

import (
	"strings"
	"testing"
)

func TestRenderEscapes(t *testing.T) {
	b, err := Render("business", "tr", Fields{Title: `Acme <script>alert(1)</script>`, About: "line1\nline2", Email: "info@acme.test", Accent: "#ff0000"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "<script>alert") || !strings.Contains(s, "&lt;script&gt;") || !strings.Contains(s, `lang="tr"`) ||
		!strings.Contains(s, "E-posta") || !strings.Contains(s, "--a:#ff0000") {
		t.Fatalf("%s", s)
	}
	for _, f := range []Fields{{}, {Title: "x", Accent: "red;}body{x"}, {Title: "x", Email: "nope"}, {Title: "x", Phone: "<b>"}} {
		if _, err := Render("business", "en", f); err == nil {
			t.Errorf("accepted %+v", f)
		}
	}
	if _, err := Render("nope", "en", Fields{Title: "x"}); err == nil {
		t.Error("unknown template accepted")
	}
	if b, _ := Render("maintenance", "en", Fields{Title: "x"}); !strings.Contains(string(b), "Under maintenance") {
		t.Error("badge")
	}
}
