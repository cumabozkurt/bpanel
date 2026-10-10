package validate

import (
	"strings"
	"testing"
)

// R2-UX-11 / R2-WB-4: domain normalisation.
func TestR2NormalizeDomain(t *testing.T) {
	ok := map[string]string{
		"Example.COM":         "example.com",
		" example.com. ":      "example.com",
		"çiçek.com.tr":        "xn--iek-1lab.com.tr",
		"xn--iek-1lab.com.tr": "xn--iek-1lab.com.tr",
		"shop.com.tr":         "shop.com.tr",
		"a-b.example.org":     "a-b.example.org",
	}
	for in, want := range ok {
		got, err := NormalizeDomain(in)
		if err != nil || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := map[string]string{
		"😀.com":                                  "invalid_idn",
		"a😀b.example.com":                        "invalid_idn",
		"♥.example":                              "invalid_idn",
		"http://example.com":                     "invalid_domain",
		"example.com/path":                       "invalid_domain",
		"user@example.com":                       "invalid_domain",
		"com.tr":                                 "public_suffix",
		"com":                                    "invalid_domain", // single label
		"github.io":                              "public_suffix",
		strings.Repeat("a", 64) + ".com":         "invalid_domain",
		strings.Repeat("abcdefghi.", 26) + "com": "too_long",
		"":                                       "invalid_domain",
	}
	for in, want := range bad {
		if _, err := NormalizeDomain(in); err == nil || err.Error() != want {
			t.Errorf("NormalizeDomain(%q) = %v, want %s", in, err, want)
		}
	}
}

func TestR2PublicSuffix(t *testing.T) {
	for _, n := range []string{"com", "com.tr", "co.uk", "github.io", "bel.tr", "k12.tr"} {
		if !IsPublicSuffix(n) {
			t.Errorf("%s not a public suffix", n)
		}
	}
	for _, n := range []string{"example.com", "shop.com.tr", "panel.example.net", "user.github.io", "internal.lan"} {
		if IsPublicSuffix(n) {
			t.Errorf("%s is a public suffix", n)
		}
	}
}

// R2-UX-12 / R2-UX-13: docroot and FTP dir errors.
func TestR2DocRootAndFTPDir(t *testing.T) {
	for in, want := range map[string]string{
		"mail": "private_dir", "etc/x": "private_dir", "ssl": "private_dir", "logs": "private_dir",
		strings.Repeat("a", 129): "too_long", strings.Repeat("a/", 130): "too_long",
		"a b": "invalid_docroot", "": "invalid_docroot",
	} {
		if _, err := DocRoot(in); err == nil || err.Error() != want {
			t.Errorf("DocRoot(%q) = %v, want %s", in, err, want)
		}
	}
	for in, want := range map[string]string{"etc": "private_dir", "mail/x.com": "private_dir", "backups": "private_dir", "tmp": "private_dir", "../x": "invalid_path"} {
		if _, err := FTPDir(in); err == nil || err.Error() != want {
			t.Errorf("FTPDir(%q) = %v, want %s", in, err, want)
		}
	}
	for _, in := range []string{"", "public_html", "public_html/shop", "etcetera"} {
		if _, err := FTPDir(in); err != nil {
			t.Errorf("FTPDir(%q): %v", in, err)
		}
	}
	long := strings.Repeat("a", 61) + "." + strings.Repeat("b", 61) + "." + strings.Repeat("c", 61) + "." + strings.Repeat("d", 57) + ".com"
	d := DefaultDocRoot(long)
	if len(d) > MaxDocRootSegment {
		t.Fatalf("default docroot %d chars", len(d))
	}
	if _, err := DocRoot(d); err != nil {
		t.Fatalf("default docroot invalid: %v", err)
	}
	if DefaultDocRoot(long) == DefaultDocRoot(strings.Replace(long, "a", "z", 1)) {
		t.Fatal("default docroots collide")
	}
	if DefaultDocRoot("short.example.com") != "short.example.com" {
		t.Fatal("short docroot changed")
	}
}

// R2-UX-16: file operation names.
func TestR2FileOpPath(t *testing.T) {
	for _, p := range []string{"public_html/" + strings.Repeat("x", 300), "a/.", "..", "a\x00b"} {
		if FileOpPath(p) == nil {
			t.Errorf("accepted %q", p)
		}
	}
	for _, p := range []string{"public_html/new.txt", strings.Repeat("x", 255), "a/b/c/"} {
		if err := FileOpPath(p); err != nil {
			t.Errorf("FileOpPath(%q): %v", p, err)
		}
	}
}

// UX-40: package names.
func TestR2PackageName(t *testing.T) {
	for _, n := range []string{"basic", "Gold_2026", "a.b-c"} {
		if err := PackageName(n); err != nil {
			t.Errorf("%q: %v", n, err)
		}
	}
	for n, want := range map[string]string{"😀": "invalid_name", "-x": "invalid_name", "a..b": "invalid_name", " a": "invalid_name", strings.Repeat("a", 65): "too_long", "a b": "invalid_name"} {
		if err := PackageName(n); err == nil || err.Error() != want {
			t.Errorf("%q: %v, want %s", n, err, want)
		}
	}
}

func FuzzR2NormalizeDomain(f *testing.F) {
	for _, s := range []string{"example.com", "çiçek.com.tr", "😀.com", "a..b", "xn--", "com.tr."} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := NormalizeDomain(s)
		if err != nil {
			return
		}
		if Domain(d) != nil || len(d) > MaxDomain || IsPublicSuffix(d) || d != strings.ToLower(d) {
			t.Fatalf("NormalizeDomain(%q) = %q passes but is invalid", s, d)
		}
		for i := 0; i < len(d); i++ {
			if d[i] >= 0x80 {
				t.Fatalf("non-ASCII output %q", d)
			}
		}
	})
}
