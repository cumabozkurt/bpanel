// SPDX-License-Identifier: Apache-2.0

package appx

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

// MaxArchiveBytes caps a download; MaxExtractBytes caps the unpacked size.
const (
	MaxArchiveBytes = 512 << 20
	MaxExtractBytes = 2 << 30
	MaxEntries      = 200000
)

// VerifyFile compares the SHA-256 (and, when given, SHA-1) of a file with
// the pinned values in constant time. Both empty is a refusal: nothing is
// installed without a checksum.
func VerifyFile(p, wantSHA256, wantSHA1 string) error {
	if wantSHA256 == "" && wantSHA1 == "" {
		return errf("appx_checksum_missing", "no pinned checksum")
	}
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	h2, h1 := sha256.New(), sha1.New()
	if _, err := io.Copy(io.MultiWriter(h2, h1), io.LimitReader(f, MaxArchiveBytes+1)); err != nil {
		return err
	}
	check := func(h hash.Hash, want string) bool {
		got := hex.EncodeToString(h.Sum(nil))
		return subtle.ConstantTimeCompare([]byte(got), []byte(strings.ToLower(want))) == 1
	}
	if wantSHA256 != "" && !check(h2, wantSHA256) {
		return errf("appx_checksum_mismatch", "sha256 does not match the pinned value")
	}
	if wantSHA1 != "" && !check(h1, wantSHA1) {
		return errf("appx_checksum_mismatch", "sha1 does not match the pinned value")
	}
	return nil
}

// cleanEntry maps an archive name to a path inside the target, stripping
// the top directory. ok=false skips the entry (the top dir itself, pax
// headers); an escaping name is an error. With only=true an entry outside
// strip/ (a README next to the application directory) is skipped instead of
// refused; unsafe names are still errors.
func cleanEntry(name, strip string, only ...bool) (string, bool, error) {
	name = strings.TrimPrefix(name, "./")
	if strings.HasPrefix(name, "/") || strings.ContainsRune(name, '\\') || strings.ContainsRune(name, 0) {
		return "", false, errf("appx_archive_unsafe", "absolute or invalid entry %q", name)
	}
	for _, s := range strings.Split(name, "/") {
		if s == ".." {
			return "", false, errf("appx_archive_unsafe", "entry escapes the target: %q", name)
		}
	}
	name = path.Clean(name)
	if strip != "" {
		if name == strip {
			return "", false, nil
		}
		if !strings.HasPrefix(name, strip+"/") {
			if len(only) > 0 && only[0] {
				return "", false, nil
			}
			return "", false, errf("appx_archive_unsafe", "entry outside %s/: %q", strip, name)
		}
		name = strings.TrimPrefix(name, strip+"/")
	}
	if name == "." || name == "" {
		return "", false, nil
	}
	return name, true, nil
}

// writer creates the extracted tree inside root, enforcing the entry count
// and the unpacked-size limit on the bytes actually written.
type writer struct {
	root     *os.Root
	uid, gid int
	total    int64
	n        int
	links    [][2]string // deferred link entries: path -> target path (both inside root)
}

// link records a symlink / hard link entry. Links are never created: once
// every regular file is written, the link becomes a regular copy of its
// target, which must be a regular file inside the extracted tree (Nextcloud
// ships *.js.map.license -> *.js.license symlinks). An absolute target or one
// that leaves the tree is refused.
func (w *writer) link(p, target string) error {
	if target == "" || strings.HasPrefix(target, "/") || strings.ContainsRune(target, '\\') || strings.ContainsRune(target, 0) {
		return errf("appx_archive_unsafe", "unsafe link target %q", target)
	}
	t := path.Clean(target)
	if t == ".." || strings.HasPrefix(t, "../") || t == "." {
		return errf("appx_archive_unsafe", "link leaves the archive: %q", target)
	}
	w.links = append(w.links, [2]string{p, t})
	return nil
}

// resolveLinks turns the recorded links into copies (a few passes so a link
// to a link works; a dangling or cyclic link is an error).
func (w *writer) resolveLinks() error {
	for pass := 0; len(w.links) > 0; pass++ {
		var left [][2]string
		for _, l := range w.links {
			st, err := w.root.Lstat(l[1])
			if err != nil || !st.Mode().IsRegular() {
				left = append(left, l)
				continue
			}
			src, err := w.root.Open(l[1])
			if err != nil {
				return err
			}
			err = w.file(l[0], st.Mode()&0o111 != 0, src)
			src.Close()
			if err != nil {
				return err
			}
		}
		if len(left) == len(w.links) || pass > 8 {
			return errf("appx_archive_unsafe", "link to a missing or non-regular file: %q -> %q", left[0][0], left[0][1])
		}
		w.links = left
	}
	return nil
}

func (w *writer) chown(p string) error {
	if w.uid < 0 {
		return nil
	}
	return w.root.Lchown(p, w.uid, w.gid)
}

func (w *writer) count() error {
	if w.n++; w.n > MaxEntries {
		return errf("appx_archive_unsafe", "too many entries")
	}
	return nil
}

// dir creates p and every missing parent, chowning each one it creates
// (archives often omit directory entries: MkdirAll alone left root-owned
// parents in the account's document root, e.g. MediaWiki extensions/*).
func (w *writer) dir(p string) error {
	cur := ""
	for _, seg := range strings.Split(p, "/") {
		cur = path.Join(cur, seg)
		if st, err := w.root.Lstat(cur); err == nil {
			if !st.IsDir() {
				return errf("appx_archive_unsafe", "%q is not a directory", cur)
			}
			continue
		}
		if err := w.root.Mkdir(cur, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		if err := w.chown(cur); err != nil {
			return err
		}
	}
	return w.chown(p)
}

func (w *writer) file(p string, exec bool, r io.Reader) error {
	if d := path.Dir(p); d != "." {
		if err := w.dir(d); err != nil {
			return err
		}
	}
	mode := fs.FileMode(0o644)
	if exec {
		mode = 0o755
	}
	f, err := w.root.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	left := MaxExtractBytes - w.total
	n, cerr := io.Copy(f, io.LimitReader(r, left+1))
	if err := f.Close(); cerr == nil {
		cerr = err
	}
	if w.total += n; w.total > MaxExtractBytes {
		return errf("appx_archive_unsafe", "archive expands beyond the limit")
	}
	if cerr != nil {
		return errf("appx_archive_unsafe", "corrupt archive")
	}
	return w.chown(p)
}

// ExtractApp unpacks the downloaded (already verified) archive of catalogue
// entry c into root: tar.gz, tar.bz2 or zip.
func ExtractApp(f *os.File, c CatalogApp, root *os.Root, uid, gid int) (int, error) {
	if c.Format == "zip" {
		st, err := f.Stat()
		if err != nil {
			return 0, err
		}
		return extractZip(f, st.Size(), c.Strip, c.StripOnly, root, uid, gid)
	}
	return extractTar(f, c.Format, c.Strip, c.StripOnly, root, uid, gid)
}

func extractZip(ra io.ReaderAt, size int64, strip string, only bool, root *os.Root, uid, gid int) (int, error) {
	if size > MaxArchiveBytes {
		return 0, errf("appx_archive_unsafe", "archive too large")
	}
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return 0, errf("appx_archive_unsafe", "not a zip archive")
	}
	if len(zr.File) > MaxEntries {
		return 0, errf("appx_archive_unsafe", "too many entries")
	}
	w := &writer{root: root, uid: uid, gid: gid}
	for _, zf := range zr.File {
		if err := w.count(); err != nil {
			return w.n, err
		}
		p, ok, err := cleanEntry(zf.Name, strip, only)
		if err != nil {
			return w.n, err
		}
		if !ok {
			continue
		}
		mode := zf.Mode()
		switch {
		case mode.IsDir() || strings.HasSuffix(zf.Name, "/"):
			if err := w.dir(p); err != nil {
				return w.n, err
			}
		case mode.IsRegular():
			rc, err := zf.Open()
			if err != nil {
				return w.n, errf("appx_archive_unsafe", "corrupt archive")
			}
			err = w.file(p, mode&0o111 != 0, rc)
			rc.Close()
			if err != nil {
				return w.n, err
			}
		default:
			return w.n, errf("appx_archive_unsafe", "links and special files are refused: %q", zf.Name)
		}
	}
	return w.n, nil
}

// Extract unpacks a tar.gz / tar.bz2 into root (an os.Root, so the kernel
// refuses any path or symlink that leaves it). No link is ever created:
// a symlink or hard link whose target is a regular file of the same archive
// becomes a plain copy (writer.link); any other link and device nodes are
// refused. Every created path is chowned to uid:gid when uid >= 0. Files are 0644/0755 (exec bit kept), dirs 0755.
func Extract(r io.Reader, format, strip string, root *os.Root, uid, gid int) (int, error) {
	return extractTar(r, format, strip, false, root, uid, gid)
}

func extractTar(r io.Reader, format, strip string, only bool, root *os.Root, uid, gid int) (int, error) {
	var zr io.Reader
	switch format {
	case "tar.gz":
		g, err := gzip.NewReader(r)
		if err != nil {
			return 0, errf("appx_archive_unsafe", "not a gzip archive")
		}
		defer g.Close()
		zr = g
	case "tar.bz2":
		zr = bzip2.NewReader(r)
	default:
		return 0, errf("appx_archive_unsafe", "unsupported archive format %q", format)
	}
	tr := tar.NewReader(zr)
	w := &writer{root: root, uid: uid, gid: gid}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return w.n, w.resolveLinks()
		}
		if err != nil {
			return w.n, errf("appx_archive_unsafe", "corrupt archive")
		}
		if err := w.count(); err != nil {
			return w.n, err
		}
		if h.Typeflag == tar.TypeXGlobalHeader || h.Typeflag == tar.TypeXHeader {
			continue
		}
		p, ok, err := cleanEntry(h.Name, strip, only)
		if err != nil {
			return w.n, err
		}
		if !ok {
			continue
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := w.dir(p); err != nil {
				return w.n, err
			}
		case tar.TypeReg:
			if h.Size > MaxExtractBytes-w.total {
				return w.n, errf("appx_archive_unsafe", "archive expands beyond the limit")
			}
			if err := w.file(p, h.Mode&0o111 != 0, tr); err != nil {
				return w.n, err
			}
		case tar.TypeSymlink:
			// relative to the link's own directory
			if h.Linkname == "" || strings.HasPrefix(h.Linkname, "/") {
				return w.n, errf("appx_archive_unsafe", "absolute or empty link target %q", h.Linkname)
			}
			if err := w.link(p, path.Join(path.Dir(p), h.Linkname)); err != nil {
				return w.n, err
			}
		case tar.TypeLink:
			// hard link names are archive paths: strip them like entries
			t, ok, err := cleanEntry(h.Linkname, strip, only)
			if err != nil || !ok {
				return w.n, errf("appx_archive_unsafe", "unsafe hard link %q", h.Linkname)
			}
			if err := w.link(p, t); err != nil {
				return w.n, err
			}
		default:
			return w.n, errf("appx_archive_unsafe", "links and special files are refused: %q", h.Name)
		}
	}
}
