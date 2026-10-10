// SPDX-License-Identifier: Apache-2.0

package xfer

import (
	"archive/tar"
	"bytes"
	"io"
	"path"
	"strings"
	"testing"
)

func FuzzCleanName(f *testing.F) {
	for _, s := range []string{"a/b", "./a", "../a", "/etc/passwd", "a/../../b", "a\x00b", "", ".", "a//b/"} {
		f.Add(s, "x")
	}
	f.Fuzz(func(t *testing.T, name, target string) {
		c, err := CleanName(name)
		if err == nil {
			if c == "" || strings.HasPrefix(c, "/") || strings.Contains(c, "\x00") || c == ".." || strings.HasPrefix(c, "../") || strings.Contains(c, "/../") || strings.HasSuffix(c, "/..") {
				t.Fatalf("CleanName(%q) = %q escapes", name, c)
			}
			if c2, err := CleanName(c); err != nil || c2 != c {
				t.Fatalf("not idempotent: %q -> %q (%v)", c, c2, err)
			}
			if LinkInside(c, target) {
				j := path.Join(path.Dir(c), target)
				if strings.HasPrefix(target, "/") || j == ".." || strings.HasPrefix(j, "../") {
					t.Fatalf("LinkInside(%q,%q) true but resolves to %q", c, target, j)
				}
			}
		}
	})
}

func tarOf(entries ...*tar.Header) []byte {
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, h := range entries {
		_ = w.WriteHeader(h)
		if h.Typeflag == tar.TypeReg {
			_, _ = w.Write(bytes.Repeat([]byte("x"), int(h.Size)))
		}
	}
	_ = w.Close()
	return b.Bytes()
}

// FuzzWalk: an arbitrary (possibly gzipped) archive never panics and every
// member handed to the callback is canonical and inside the root.
func FuzzWalk(f *testing.F) {
	f.Add(tarOf(&tar.Header{Name: "a/b.txt", Typeflag: tar.TypeReg, Size: 3, Mode: 0644}))
	f.Add(tarOf(&tar.Header{Name: "l", Typeflag: tar.TypeSymlink, Linkname: "../../etc"}))
	f.Add(tarOf(&tar.Header{Name: "../x", Typeflag: tar.TypeReg, Size: 1}))
	f.Add([]byte{0x1f, 0x8b, 0, 0})
	lim := Limits{MaxEntries: 50, MaxEntryBytes: 1 << 16, MaxTotalBytes: 1 << 18, MaxMetaBytes: 1 << 12}
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = Walk(bytes.NewReader(data), lim, func(e Entry, body io.Reader) error {
			if c, err := CleanName(e.Name); err != nil || c != e.Name {
				t.Fatalf("non-canonical entry %q", e.Name)
			}
			if e.Type == tar.TypeSymlink && !LinkInside(e.Name, e.Linkname) {
				t.Fatalf("escaping symlink %q -> %q", e.Name, e.Linkname)
			}
			if e.Type != tar.TypeReg && e.Type != tar.TypeDir && e.Type != tar.TypeSymlink {
				t.Fatalf("type %d passed", e.Type)
			}
			if body != nil {
				n, _ := io.Copy(io.Discard, body)
				if n > lim.MaxEntryBytes {
					t.Fatalf("entry over limit: %d", n)
				}
			}
			return nil
		})
	})
}
