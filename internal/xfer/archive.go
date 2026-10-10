// SPDX-License-Identifier: Apache-2.0

// Package xfer is BPanel's account transfer engine (v0.4, spec §10): the
// BPanel-native account archive (export/verify) and read-only parsers for
// foreign backups (cPanel cpmove/backup archives, HestiaCP detection) into
// one import Model. Nothing inside an archive is ever executed: archives are
// only read as data, every entry name is canonicalised, links that escape
// are refused, device nodes are refused and sizes are capped.
package xfer

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// Error codes (also API error codes; see internal/api/errcodes.go).
var (
	ErrUnsafe      = errors.New("xfer_archive_unsafe")
	ErrTooLarge    = errors.New("xfer_archive_too_large")
	ErrChecksum    = errors.New("xfer_checksum_mismatch")
	ErrFormat      = errors.New("xfer_unknown_format")
	ErrManifest    = errors.New("xfer_manifest_invalid")
	ErrUnsupported = errors.New("xfer_format_unsupported")
)

// Error wraps one of the sentinel codes with detail that is safe to show.
type Error struct {
	Code   error
	Detail string
}

func (e *Error) Error() string { return e.Code.Error() + ": " + e.Detail }
func (e *Error) Unwrap() error { return e.Code }

func errf(code error, f string, a ...any) error {
	return &Error{Code: code, Detail: fmt.Sprintf(f, a...)}
}

// Limits caps what one archive may contain.
type Limits struct {
	MaxEntries    int
	MaxEntryBytes int64
	MaxTotalBytes int64
	MaxMetaBytes  int64 // small metadata files read into memory
}

// DefaultLimits are generous for real accounts and still bounded.
var DefaultLimits = Limits{MaxEntries: 500000, MaxEntryBytes: 50 << 30, MaxTotalBytes: 200 << 30, MaxMetaBytes: 4 << 20}

// CleanName canonicalises a tar entry name and rejects anything that could
// leave the extraction root (absolute paths, "..", NUL, empty).
func CleanName(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) || len(name) > 4096 {
		return "", errf(ErrUnsafe, "bad entry name")
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) || (len(name) > 1 && name[1] == ':') {
		return "", errf(ErrUnsafe, "absolute path %q", trunc(name))
	}
	for _, seg := range strings.Split(strings.ReplaceAll(name, `\`, "/"), "/") {
		if seg == ".." {
			return "", errf(ErrUnsafe, "path traversal %q", trunc(name))
		}
	}
	c := path.Clean(name)
	if c == "." || c == "" {
		return ".", nil
	}
	// Re-check the cleaned name: "./\x" or "./C:x" only look absolute after
	// path.Clean drops the "./" prefix, and CleanName must be idempotent
	// (found by FuzzCleanName).
	if strings.HasPrefix(c, `\`) || (len(c) > 1 && c[1] == ':') {
		return "", errf(ErrUnsafe, "absolute path %q", trunc(name))
	}
	return c, nil
}

// LinkInside reports whether a symlink at name with the given target stays
// inside the archive root.
func LinkInside(name, target string) bool {
	if target == "" || strings.HasPrefix(target, "/") || strings.ContainsRune(target, 0) {
		return false
	}
	j := path.Clean(path.Join(path.Dir(name), target))
	return j != ".." && !strings.HasPrefix(j, "../") && !strings.HasPrefix(j, "/")
}

func trunc(s string) string {
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

// Entry is one validated archive member.
type Entry struct {
	Name     string // canonical
	Type     byte   // tar.TypeReg, TypeDir, TypeSymlink
	Mode     int64
	Size     int64
	Linkname string
}

// Walk reads a tar or tar.gz stream, validates every header and calls fn for
// regular files (with their content reader), directories and symlinks.
// Hard links, devices, FIFOs and links leaving the root are refused.
func Walk(r io.Reader, lim Limits, fn func(e Entry, body io.Reader) error) error {
	br := bufio.NewReader(r)
	var src io.Reader = br
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return errf(ErrFormat, "gzip: %v", err)
		}
		defer gz.Close()
		src = gz
	}
	tr := tar.NewReader(src)
	var n int
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errf(ErrFormat, "tar: %v", err)
		}
		n++
		if lim.MaxEntries > 0 && n > lim.MaxEntries {
			return errf(ErrTooLarge, "more than %d entries", lim.MaxEntries)
		}
		name, err := CleanName(h.Name)
		if err != nil {
			return err
		}
		e := Entry{Name: name, Mode: h.Mode & 0o7777, Size: h.Size}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			e.Type = tar.TypeReg
		case tar.TypeDir:
			e.Type = tar.TypeDir
		case tar.TypeSymlink:
			if !LinkInside(name, h.Linkname) {
				return errf(ErrUnsafe, "symlink %q points outside the archive", trunc(name))
			}
			e.Type, e.Linkname = tar.TypeSymlink, h.Linkname
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			continue
		default:
			return errf(ErrUnsafe, "entry %q has a forbidden type (%q)", trunc(name), string(h.Typeflag))
		}
		if h.Size < 0 || (lim.MaxEntryBytes > 0 && h.Size > lim.MaxEntryBytes) {
			return errf(ErrTooLarge, "entry %q is too large", trunc(name))
		}
		total += h.Size
		if lim.MaxTotalBytes > 0 && total > lim.MaxTotalBytes {
			return errf(ErrTooLarge, "archive content exceeds %d bytes", lim.MaxTotalBytes)
		}
		var body io.Reader = eofReader{}
		if e.Type == tar.TypeReg {
			body = io.LimitReader(tr, h.Size)
		}
		if err := fn(e, body); err != nil {
			return err
		}
	}
}

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }

// WalkFile opens path and walks it.
func WalkFile(p string, lim Limits, fn func(e Entry, body io.Reader) error) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	return Walk(f, lim, fn)
}

// ExtractOptions selects and places members during Extract.
type ExtractOptions struct {
	Prefix string // only members under this archive directory, stripped ("homedir")
	Skip   func(rel string) bool
	// Chown is applied to every created path (nil = leave as created).
	UID, GID int
	Chown    bool
}

// Extract writes the selected members below dest through an os.Root, so no
// path (and no symlink created earlier) can lead outside dest. Existing
// files are overwritten; existing symlinks are never followed for writes.
func Extract(archive, dest string, lim Limits, o ExtractOptions) (files int, bytes int64, err error) {
	root, err := os.OpenRoot(dest)
	if err != nil {
		return 0, 0, err
	}
	defer root.Close()
	pre := strings.Trim(o.Prefix, "/")
	err = WalkFile(archive, lim, func(e Entry, body io.Reader) error {
		rel := e.Name
		if pre != "" {
			if rel == pre {
				return nil
			}
			if !strings.HasPrefix(rel, pre+"/") {
				return nil
			}
			rel = strings.TrimPrefix(rel, pre+"/")
		}
		if rel == "." || rel == "" || (o.Skip != nil && o.Skip(rel)) {
			return nil
		}
		if d := path.Dir(rel); d != "." {
			if err := mkdirAll(root, d, o); err != nil {
				return err
			}
		}
		switch e.Type {
		case tar.TypeDir:
			return mkdirAll(root, rel, o)
		case tar.TypeSymlink:
			if !LinkInside(rel, e.Linkname) {
				return errf(ErrUnsafe, "symlink %q points outside", trunc(rel))
			}
			_ = root.Remove(rel)
			if err := root.Symlink(e.Linkname, rel); err != nil {
				return err
			}
			if o.Chown {
				_ = root.Lchown(rel, o.UID, o.GID)
			}
			return nil
		}
		if fi, err := root.Lstat(rel); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			if err := root.Remove(rel); err != nil { // never write through an existing link
				return err
			}
		}
		mode := os.FileMode(e.Mode & 0o777)
		if mode == 0 {
			mode = 0o644
		}
		f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
		if err != nil {
			return err
		}
		n, cerr := io.Copy(f, body)
		if err := f.Close(); cerr == nil {
			cerr = err
		}
		if cerr != nil {
			return cerr
		}
		if o.Chown {
			_ = root.Lchown(rel, o.UID, o.GID)
		}
		_ = root.Chmod(rel, mode) // drop setuid/setgid bits from the archive
		files++
		bytes += n
		return nil
	})
	return files, bytes, err
}

func mkdirAll(root *os.Root, rel string, o ExtractOptions) error {
	cur := ""
	for _, seg := range strings.Split(rel, "/") {
		if cur == "" {
			cur = seg
		} else {
			cur += "/" + seg
		}
		fi, err := root.Lstat(cur)
		if err == nil {
			if !fi.IsDir() {
				return errf(ErrUnsafe, "%q is not a directory", trunc(cur))
			}
			continue
		}
		if err := root.Mkdir(cur, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if o.Chown {
			_ = root.Lchown(cur, o.UID, o.GID)
		}
	}
	return nil
}
