// SPDX-License-Identifier: Apache-2.0

package appx

import (
	"archive/tar"
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
// headers); an escaping name is an error.
func cleanEntry(name, strip string) (string, bool, error) {
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
			return "", false, errf("appx_archive_unsafe", "entry outside %s/: %q", strip, name)
		}
		name = strings.TrimPrefix(name, strip+"/")
	}
	if name == "." || name == "" {
		return "", false, nil
	}
	return name, true, nil
}

// Extract unpacks a tar.gz / tar.bz2 into root (an os.Root, so the kernel
// refuses any path or symlink that leaves it). Symlinks, hard links and
// device nodes are refused. Every created path is chowned to uid:gid when
// uid >= 0. Files are 0644/0755 (exec bit kept), dirs 0755.
func Extract(r io.Reader, format, strip string, root *os.Root, uid, gid int) (int, error) {
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
	var total int64
	n := 0
	chown := func(p string) error {
		if uid < 0 {
			return nil
		}
		return root.Lchown(p, uid, gid)
	}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, errf("appx_archive_unsafe", "corrupt archive")
		}
		if n++; n > MaxEntries {
			return n, errf("appx_archive_unsafe", "too many entries")
		}
		if h.Typeflag == tar.TypeXGlobalHeader || h.Typeflag == tar.TypeXHeader {
			continue
		}
		p, ok, err := cleanEntry(h.Name, strip)
		if err != nil {
			return n, err
		}
		if !ok {
			continue
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(p, 0o755); err != nil {
				return n, err
			}
			if err := chown(p); err != nil {
				return n, err
			}
		case tar.TypeReg:
			if total += h.Size; total > MaxExtractBytes {
				return n, errf("appx_archive_unsafe", "archive expands beyond the limit")
			}
			if d := path.Dir(p); d != "." {
				if err := root.MkdirAll(d, 0o755); err != nil {
					return n, err
				}
				if err := chown(d); err != nil {
					return n, err
				}
			}
			mode := fs.FileMode(0o644)
			if h.Mode&0o111 != 0 {
				mode = 0o755
			}
			f, err := root.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				return n, err
			}
			_, cerr := io.CopyN(f, tr, h.Size)
			if err := f.Close(); cerr == nil {
				cerr = err
			}
			if cerr != nil {
				return n, cerr
			}
			if err := chown(p); err != nil {
				return n, err
			}
		default:
			return n, errf("appx_archive_unsafe", "links and special files are refused: %q", h.Name)
		}
	}
}
