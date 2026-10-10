package shield

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ArchiveLimits bound the work an archive may cause (zip bombs, deep
// nesting, entry floods).
type ArchiveLimits struct {
	MaxTotal     int64   // total uncompressed bytes across all entries (incl. nested)
	MaxEntry     int64   // one entry's uncompressed bytes
	MaxRatio     float64 // total uncompressed / compressed archive size
	MaxEntries   int     // entries across all levels
	MaxDepth     int     // nesting depth (1 = no nested archives)
	MinRatioBase int64   // ratio only enforced once total > this (small files compress well)
}

func DefaultArchiveLimits() ArchiveLimits {
	return ArchiveLimits{MaxTotal: 512 << 20, MaxEntry: 128 << 20, MaxRatio: 100, MaxEntries: 10000, MaxDepth: 3, MinRatioBase: 1 << 20}
}

var (
	ErrArchiveBomb    = errors.New("archive: decompression limit exceeded (possible zip bomb)")
	ErrArchiveEntries = errors.New("archive: too many entries")
	ErrArchiveDepth   = errors.New("archive: nested too deeply")
	ErrArchivePath    = errors.New("archive: entry path escapes the destination (zip-slip) or is absolute")
	ErrArchiveLink    = errors.New("archive: symlink/hardlink/device entries are not allowed")
	ErrArchiveFormat  = errors.New("archive: unsupported or corrupt archive")
)

// ArchiveEntry is one regular file inside an archive.
type ArchiveEntry struct {
	Name  string `json:"name"` // "outer.zip!inner/a.php" for nested
	Size  int64  `json:"size"`
	Depth int    `json:"depth"`
	Dir   bool   `json:"dir,omitempty"`
}

// SafeEntryName validates an archive member name.
func SafeEntryName(name string) (string, error) {
	n := strings.ReplaceAll(name, "\\", "/")
	if n == "" || strings.ContainsRune(n, 0) || strings.HasPrefix(n, "/") || (len(n) > 1 && n[1] == ':') {
		return "", fmt.Errorf("%w: %q", ErrArchivePath, name)
	}
	for _, part := range strings.Split(n, "/") {
		if part == ".." {
			return "", fmt.Errorf("%w: %q", ErrArchivePath, name)
		}
	}
	c := path.Clean(n)
	if c == "." || c == ".." || strings.HasPrefix(c, "../") {
		return "", fmt.Errorf("%w: %q", ErrArchivePath, name)
	}
	return c, nil
}

type walker struct {
	lim        ArchiveLimits
	compressed int64
	total      int64
	entries    int
	fn         func(e ArchiveEntry, data []byte) error
}

func (w *walker) account(n int64) error {
	w.total += n
	if w.lim.MaxTotal > 0 && w.total > w.lim.MaxTotal {
		return ErrArchiveBomb
	}
	if w.lim.MaxRatio > 0 && w.compressed > 0 && w.total > w.lim.MinRatioBase && float64(w.total)/float64(w.compressed) > w.lim.MaxRatio {
		return ErrArchiveBomb
	}
	return nil
}

// readEntry reads at most MaxEntry bytes, counting real decompressed bytes
// (declared sizes in headers are not trusted).
func (w *walker) readEntry(r io.Reader) ([]byte, error) {
	max := w.lim.MaxEntry
	if max <= 0 {
		max = 128 << 20
	}
	var buf bytes.Buffer
	chunk := make([]byte, 32<<10)
	for {
		n, err := r.Read(chunk)
		if n > 0 {
			if int64(buf.Len()+n) > max {
				return nil, ErrArchiveBomb
			}
			if aerr := w.account(int64(n)); aerr != nil {
				return nil, aerr
			}
			buf.Write(chunk[:n])
		}
		if err == io.EOF {
			return buf.Bytes(), nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrArchiveFormat, err)
		}
	}
}

func (w *walker) entry(prefix, name string, depth int) (string, error) {
	w.entries++
	if w.lim.MaxEntries > 0 && w.entries > w.lim.MaxEntries {
		return "", ErrArchiveEntries
	}
	clean, err := SafeEntryName(name)
	if err != nil {
		return "", err
	}
	if prefix != "" {
		clean = prefix + "!" + clean
	}
	return clean, nil
}

func (w *walker) member(full string, data []byte, depth int) error {
	if err := w.fn(ArchiveEntry{Name: full, Size: int64(len(data)), Depth: depth}, data); err != nil {
		return err
	}
	k := DetectType(head(data), full).Kind
	if k == "zip" || k == "gzip" || k == "tar" {
		return w.walk(data, full, depth+1)
	}
	return nil
}

func (w *walker) walk(data []byte, prefix string, depth int) error {
	if w.lim.MaxDepth > 0 && depth > w.lim.MaxDepth {
		return ErrArchiveDepth
	}
	switch DetectType(head(data), prefix).Kind {
	case "zip":
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return fmt.Errorf("%w: %v", ErrArchiveFormat, err)
		}
		for _, f := range zr.File {
			full, err := w.entry(prefix, f.Name, depth)
			if err != nil {
				return err
			}
			m := f.Mode()
			if m&fs.ModeSymlink != 0 || m&(fs.ModeDevice|fs.ModeNamedPipe|fs.ModeSocket|fs.ModeCharDevice) != 0 {
				return fmt.Errorf("%w: %q", ErrArchiveLink, f.Name)
			}
			if m.IsDir() || strings.HasSuffix(f.Name, "/") {
				continue
			}
			if w.lim.MaxEntry > 0 && f.UncompressedSize64 > uint64(w.lim.MaxEntry) {
				return ErrArchiveBomb
			}
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("%w: %v", ErrArchiveFormat, err)
			}
			b, err := w.readEntry(rc)
			rc.Close()
			if err != nil {
				return err
			}
			if err := w.member(full, b, depth); err != nil {
				return err
			}
		}
		return nil
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("%w: %v", ErrArchiveFormat, err)
		}
		defer zr.Close()
		b, err := w.readEntry(zr)
		if err != nil {
			return err
		}
		if DetectType(head(b), "").Kind == "tar" {
			return w.walkTar(b, prefix, depth)
		}
		name := strings.TrimSuffix(path.Base(strings.ReplaceAll(prefix, "!", "/")), ".gz")
		if name == "" || name == "." {
			name = "data"
		}
		full, err := w.entry(prefix, name, depth)
		if err != nil {
			return err
		}
		return w.member(full, b, depth)
	case "tar":
		return w.walkTar(data, prefix, depth)
	}
	return ErrArchiveFormat
}

func (w *walker) walkTar(data []byte, prefix string, depth int) error {
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrArchiveFormat, err)
		}
		full, err := w.entry(prefix, h.Name, depth)
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg, tar.TypeRegA:
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			continue
		default:
			return fmt.Errorf("%w: %q", ErrArchiveLink, h.Name)
		}
		if w.lim.MaxEntry > 0 && h.Size > w.lim.MaxEntry {
			return ErrArchiveBomb
		}
		b, err := w.readEntry(tr)
		if err != nil {
			return err
		}
		if err := w.member(full, b, depth); err != nil {
			return err
		}
	}
}

// WalkArchive visits every regular member (recursing into nested archives)
// enforcing lim. Any limit violation aborts the walk with an error.
func WalkArchive(p string, lim ArchiveLimits, fn func(e ArchiveEntry, data []byte) error) error {
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%w: not a regular file", ErrArchiveFormat)
	}
	// the outer archive itself is bounded by MaxTotal
	if lim.MaxTotal > 0 && st.Size() > lim.MaxTotal {
		return ErrArchiveBomb
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	w := &walker{lim: lim, compressed: int64(len(data)), fn: fn}
	return w.walk(data, "", 1)
}

// InspectArchive lists the members after validating every limit.
func InspectArchive(p string, lim ArchiveLimits) ([]ArchiveEntry, error) {
	var out []ArchiveEntry
	err := WalkArchive(p, lim, func(e ArchiveEntry, _ []byte) error { out = append(out, e); return nil })
	return out, err
}

// ExtractArchive validates the whole archive first, then writes top-level
// members under dest (nested archives are extracted as files, not
// recursively). Files are created with O_EXCL (never through an existing
// symlink) and mode 0640; directories 0750.
func ExtractArchive(p, dest string, lim ArchiveLimits) ([]string, error) {
	if _, err := InspectArchive(p, lim); err != nil {
		return nil, err
	}
	root, err := filepath.Abs(dest)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, err
	}
	var written []string
	err = WalkArchive(p, lim, func(e ArchiveEntry, data []byte) error {
		if e.Depth != 1 {
			return nil
		}
		target := filepath.Join(root, filepath.FromSlash(e.Name))
		if rel, rerr := filepath.Rel(root, target); rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return ErrArchivePath
		}
		if err := mkdirNoSymlink(root, filepath.Dir(target)); err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
		if err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			return err
		}
		written = append(written, e.Name)
		return f.Close()
	})
	return written, err
}

// mkdirNoSymlink creates dir under root refusing any symlinked component.
func mkdirNoSymlink(root, dir string) error {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return err
	}
	cur := root
	if rel == "." {
		return nil
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		st, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			if err := os.Mkdir(cur, 0o750); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if st.Mode()&fs.ModeSymlink != 0 || !st.IsDir() {
			return fmt.Errorf("%w: %s", ErrArchiveLink, cur)
		}
	}
	return nil
}
