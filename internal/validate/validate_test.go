package validate

import (
	"slices"
	"strings"
	"testing"
)

// SEC-1 / SEC-9 / CODE-1: config-bound paths accept only [A-Za-z0-9._-/].
func TestRelPathStrict(t *testing.T) {
	for _, p := range []string{"a;\n}\nserver {", "x\ny:z", "dir with spaces", `a"b`, "a{b}", "x:0:0", "a$b", `a\b`,
		"a#b", "../etc", "a/../../b", ".ssh", "a/.git", "a\x00b", "a\tb", strings.Repeat("a", 256)} {
		if _, err := RelPath(p); err == nil {
			t.Errorf("RelPath accepted %q", p)
		}
	}
	for in, want := range map[string]string{"public_html": "public_html", "/public_html/": "public_html", "a//b": "a/b",
		"sites/shop.example.com": "sites/shop.example.com", "": "", "/": "", "a-b_c.d": "a-b_c.d"} {
		got, err := RelPath(in)
		if err != nil || got != want {
			t.Errorf("RelPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

// CODE-18: docroots may not be the home or a private directory.
func TestDocRoot(t *testing.T) {
	for _, p := range []string{"", "/", "mail", "mail/x.test", "etc", "logs", "tmp", "backups/restore-1", "ssl", ".ssh", ".bpanel"} {
		if _, err := DocRoot(p); err == nil {
			t.Errorf("DocRoot accepted %q", p)
		}
	}
	for _, p := range []string{"public_html", "public_html/blog", "shop.example.com", "mailer"} {
		if _, err := DocRoot(p); err != nil {
			t.Errorf("DocRoot refused %q: %v", p, err)
		}
	}
}

// The File Manager keeps accepting real-world names (spaces, unicode) but never escapes.
func TestFilePath(t *testing.T) {
	for in, want := range map[string]string{"My Docs/ünï code.txt": "My Docs/ünï code.txt", "../../etc/passwd": "etc/passwd", "/": "", "a/./b": "a/b"} {
		got, err := FilePath(in)
		if err != nil || got != want {
			t.Errorf("FilePath(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := FilePath("a\x00b"); err == nil {
		t.Error("NUL accepted")
	}
}

func TestConfigSafe(t *testing.T) {
	for _, s := range []string{"a;b", "a b", "a\nb", `a"b`, "a'b", "a{", "a}", "$x", `a\b`, "a#b", "a\x7f"} {
		if ConfigSafe(s) {
			t.Errorf("ConfigSafe(%q) = true", s)
		}
	}
	for _, s := range []string{"", "/home/u/public_html", "https://x.test/a?b=c&d=%20", "/run/php/bpanel-u-83.sock"} {
		if !ConfigSafe(s) {
			t.Errorf("ConfigSafe(%q) = false", s)
		}
	}
}

// Cron: numeric ranges are enforced (CODE: cron validation).
func TestCronSchedule(t *testing.T) {
	good := [][]string{{"*", "*", "*", "*", "*"}, {"*/15", "0-23/2", "1,15,31", "jan-dec", "mon-fri"}, {"0", "0", "1", "1", "0"}, {"59", "23", "31", "12", "7"}}
	bad := [][]string{{"60", "*", "*", "*", "*"}, {"*", "24", "*", "*", "*"}, {"*", "*", "0", "*", "*"}, {"*", "*", "*", "13", "*"},
		{"*", "*", "*", "*", "8"}, {"*/0", "*", "*", "*", "*"}, {"5-1", "*", "*", "*", "*"}, {"*", "*", "*", "*"}, {"a", "*", "*", "*", "*"},
		{"1,,2", "*", "*", "*", "*"}, {"*/61", "*", "*", "*", "*"}}
	for _, f := range good {
		if err := CronSchedule(f); err != nil {
			t.Errorf("refused %v", f)
		}
	}
	for _, f := range bad {
		if err := CronSchedule(f); err == nil {
			t.Errorf("accepted %v", f)
		}
	}
}

// CODE-17: '%' is escaped, control characters rejected.
func TestCronCommand(t *testing.T) {
	if err := CronCommand("date +%F"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"", "  ", "a\nb", "a\rb", "a\x00", "a\x1b[2J"} {
		if CronCommand(c) == nil {
			t.Errorf("accepted %q", c)
		}
	}
	if got := EscapeCronPercent(`date +%F \%H %%`); got != `date +\%F \%H \%\%` {
		t.Fatalf("got %q", got)
	}
}

// SEC-5: cloud-image login users are reserved.
func TestReservedUsernames(t *testing.T) {
	for _, u := range []string{"ubuntu", "debian", "almalinux", "rocky", "centos", "opc", "azureuser", "root", "admin"} {
		if Username(u) == nil {
			t.Errorf("%s not reserved", u)
		}
	}
	if Username("alice") != nil {
		t.Error("alice refused")
	}
	l := Limits()
	if l["username"].(map[string]any)["reserved"].([]string)[0] == "" || l["docroot"] == nil {
		t.Fatal("limits incomplete")
	}
}

func TestRecordContentControl(t *testing.T) {
	if RecordContent("TXT", "a\x1bb") == nil {
		t.Fatal("control char accepted")
	}
}

func FuzzRelPathConfigSafe(f *testing.F) {
	for _, s := range []string{"public_html", "a;b", "a\nb", "a b", "x:y", "../a", "a/./b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		r, err := RelPath(p)
		if err != nil {
			return
		}
		if !ConfigSafe(r) || strings.ContainsAny(r, ":") || slices.Contains(strings.Split(r, "/"), "..") || strings.HasPrefix(r, "/") {
			t.Fatalf("RelPath(%q) = %q is not config safe", p, r)
		}
	})
}

func FuzzCronCommand(f *testing.F) {
	for _, s := range []string{"%00000000", "date +%F", `a\%b`, "x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, c string) {
		if CronCommand(c) != nil {
			return
		}
		e := EscapeCronPercent(c)
		for i := 0; i < len(e); i++ {
			if e[i] == '%' && (i == 0 || e[i-1] != '\\') {
				t.Fatalf("unescaped %% in %q", e)
			}
		}
		if strings.ContainsAny(e, "\n\r\x00") {
			t.Fatalf("line break in %q", e)
		}
	})
}

func TestLangOnlyShippedLanguages(t *testing.T) {
	for _, ok := range []string{"en", "tr", "en-US", "tr-TR"} {
		if err := Lang(ok); err != nil {
			t.Errorf("Lang(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "xx", "de", "EN", "en_US", "tr-tr", "english", "../en"} {
		if err := Lang(bad); err == nil {
			t.Errorf("Lang(%q) = nil, want invalid_language", bad)
		}
	}
}
