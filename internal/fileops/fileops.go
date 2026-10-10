// Package fileops implements the File Manager operations inside an os.Root,
// which makes path traversal and symlink escapes impossible by construction.
// On a real server the agent runs this in a helper process that has dropped
// to the account's uid/gid, so the kernel enforces permissions as well.
package fileops

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

const (
	MaxEditBytes     = 5 << 20   // text editor limit
	MaxUploadBytes   = 256 << 20 // single upload (whole file)
	MaxDownloadBytes = 4 << 30   // single download (streamed in chunks)
	MaxChunkBytes    = 8 << 20   // one read_chunk/write_chunk (keeps agent RPC lines small)
	MaxUnzipBytes    = 4 << 30   // zip bomb guard (actual bytes written)
	MaxUnzipEntries  = 100000
)

type Error struct{ Code string }

func (e *Error) Error() string { return e.Code }

func fail(code string) error { return &Error{Code: code} }

func rel(p string) (string, error) {
	r, err := validate.FilePath(p)
	if err != nil {
		return "", fail("invalid_path")
	}
	if r == "" {
		return ".", nil
	}
	return r, nil
}

// Exec runs one operation against root.
func Exec(root *os.Root, op rpc.FileOp) (rpc.FileResult, error) {
	var res rpc.FileResult
	p, err := rel(op.Path)
	if err != nil {
		return res, err
	}
	switch op.Op {
	case "list":
		f, err := root.Open(p)
		if err != nil {
			return res, mapErr(err)
		}
		defer f.Close()
		ents, err := f.ReadDir(-1)
		if err != nil {
			return res, mapErr(err)
		}
		for _, e := range ents {
			info, err := e.Info()
			if err != nil {
				continue
			}
			fe := rpc.FileEntry{Name: e.Name(), Size: info.Size(), Mode: info.Mode().String(), Perm: uint32(info.Mode().Perm()),
				IsDir: info.IsDir(), IsLink: info.Mode()&fs.ModeSymlink != 0, ModUnix: info.ModTime().Unix()}
			if fe.IsLink {
				if st, err := root.Stat(path.Join(p, e.Name())); err == nil && st.IsDir() {
					fe.IsDir = true
				}
			}
			res.Entries = append(res.Entries, fe)
		}
		sort.Slice(res.Entries, func(i, j int) bool {
			if res.Entries[i].IsDir != res.Entries[j].IsDir {
				return res.Entries[i].IsDir
			}
			return strings.ToLower(res.Entries[i].Name) < strings.ToLower(res.Entries[j].Name)
		})
	case "read":
		st, err := root.Stat(p)
		if err != nil {
			return res, mapErr(err)
		}
		if st.IsDir() {
			return res, fail("is_directory")
		}
		if st.Size() > MaxEditBytes {
			return res, fail("file_too_large")
		}
		b, err := root.ReadFile(p)
		if err != nil {
			return res, mapErr(err)
		}
		if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
			return res, fail("binary_file")
		}
		res.Content, res.Size = string(b), st.Size()
	case "download":
		st, err := root.Stat(p)
		if err != nil {
			return res, mapErr(err)
		}
		if st.IsDir() {
			return res, fail("is_directory")
		}
		if st.Size() > MaxChunkBytes { // larger files go through read_chunk
			return res, fail("file_too_large")
		}
		b, err := root.ReadFile(p)
		if err != nil {
			return res, mapErr(err)
		}
		res.Content, res.Size = base64.StdEncoding.EncodeToString(b), st.Size()
	case "write":
		if len(op.Content) > MaxEditBytes {
			return res, fail("file_too_large")
		}
		mode := os.FileMode(0o644)
		if st, err := root.Stat(p); err == nil {
			mode = st.Mode().Perm()
		}
		if err := root.WriteFile(p, []byte(op.Content), mode); err != nil {
			return res, mapErr(err)
		}
	case "upload":
		b, err := base64.StdEncoding.DecodeString(op.Content)
		if err != nil {
			return res, fail("bad_upload")
		}
		if len(b) > MaxChunkBytes { // larger files go through write_chunk
			return res, fail("file_too_large")
		}
		if err := root.WriteFile(p, b, 0o644); err != nil {
			return res, mapErr(err)
		}
		res.Size = int64(len(b))
	case "write_chunk":
		// Streamed upload (CODE-7): chunks are appended at Offset; Offset 0
		// creates/truncates. The API writes to a temporary name and renames.
		b, err := base64.StdEncoding.DecodeString(op.Content)
		if err != nil || len(b) > MaxChunkBytes || op.Offset < 0 || op.Offset+int64(len(b)) > MaxUploadBytes {
			return res, fail("bad_upload")
		}
		flag := os.O_WRONLY | os.O_CREATE
		if op.Offset == 0 {
			flag |= os.O_TRUNC
		}
		f, err := root.OpenFile(p, flag, 0o644)
		if err != nil {
			return res, mapErr(err)
		}
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() {
			f.Close()
			return res, fail("bad_upload")
		}
		if st.Size() != op.Offset {
			f.Close()
			return res, fail("bad_upload_offset")
		}
		if _, err := f.WriteAt(b, op.Offset); err != nil {
			f.Close()
			return res, mapErr(err)
		}
		if err := f.Close(); err != nil {
			return res, mapErr(err)
		}
		res.Size = op.Offset + int64(len(b))
	case "read_chunk":
		// Streamed download (CODE-7): returns at most Length bytes from Offset
		// plus the total file size.
		n := op.Length
		if n <= 0 || n > MaxChunkBytes {
			n = MaxChunkBytes
		}
		f, err := root.Open(p)
		if err != nil {
			return res, mapErr(err)
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return res, mapErr(err)
		}
		if st.IsDir() {
			return res, fail("is_directory")
		}
		if !st.Mode().IsRegular() {
			return res, fail("not_regular_file")
		}
		if st.Size() > MaxDownloadBytes {
			return res, fail("file_too_large")
		}
		if op.Offset < 0 || op.Offset > st.Size() {
			return res, fail("bad_offset")
		}
		buf := make([]byte, min(n, st.Size()-op.Offset))
		if _, err := f.ReadAt(buf, op.Offset); err != nil && !errors.Is(err, io.EOF) {
			return res, mapErr(err)
		}
		res.Content, res.Size = base64.StdEncoding.EncodeToString(buf), st.Size()
	case "mkdir":
		if err := root.MkdirAll(p, 0o755); err != nil {
			return res, mapErr(err)
		}
	case "touch":
		f, err := root.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return res, mapErr(err)
		}
		if err := f.Close(); err != nil {
			return res, mapErr(err)
		}
	case "delete":
		targets := op.Paths
		if len(targets) == 0 {
			targets = []string{op.Path}
		}
		for _, q := range targets {
			r, err := rel(q)
			if err != nil || r == "." {
				return res, fail("refused")
			}
			if err := root.RemoveAll(r); err != nil {
				return res, mapErr(err)
			}
		}
	case "rename", "move":
		d, err := rel(op.Dest)
		if err != nil || p == "." || d == "." {
			return res, fail("invalid_path")
		}
		if st, err := root.Stat(d); err == nil && st.IsDir() {
			d = path.Join(d, path.Base(p))
		}
		if err := root.Rename(p, d); err != nil {
			return res, mapErr(err)
		}
	case "copy":
		d, err := rel(op.Dest)
		if err != nil || p == "." {
			return res, fail("invalid_path")
		}
		if st, err := root.Stat(d); err == nil && st.IsDir() {
			d = path.Join(d, path.Base(p))
		}
		if err := copyTree(root, p, d); err != nil {
			return res, mapErr(err)
		}
	case "chmod":
		if err := validate.Mode(op.Mode); err != nil {
			return res, fail("invalid_mode")
		}
		targets := []string{p}
		if len(op.Paths) > 0 {
			targets = nil
			for _, q := range op.Paths {
				r, err := rel(q)
				if err != nil {
					return res, err
				}
				targets = append(targets, r)
			}
		}
		for _, t := range targets {
			if err := root.Chmod(t, os.FileMode(op.Mode)); err != nil {
				return res, mapErr(err)
			}
		}
	case "zip":
		d, err := rel(op.Dest)
		if err != nil || !strings.HasSuffix(d, ".zip") {
			return res, fail("invalid_path")
		}
		srcs := op.Paths
		if len(srcs) == 0 {
			srcs = []string{op.Path}
		}
		if err := zipTo(root, srcs, d); err != nil {
			return res, mapErr(err)
		}
	case "unzip":
		d, err := rel(op.Dest)
		if err != nil {
			return res, err
		}
		if err := unzip(root, p, d); err != nil {
			return res, mapErr(err)
		}
	default:
		return res, fail("unknown_op")
	}
	return res, nil
}

func mapErr(err error) error {
	var fe *Error
	switch {
	case errors.As(err, &fe):
		return err
	case errors.Is(err, fs.ErrNotExist):
		return fail("not_found")
	case errors.Is(err, fs.ErrExist):
		return fail("already_exists")
	case errors.Is(err, fs.ErrPermission):
		return fail("permission_denied")
	case strings.Contains(err.Error(), "escapes from parent") || strings.Contains(err.Error(), "path escapes"):
		return fail("invalid_path")
	case errors.Is(err, syscall.EDQUOT):
		return fail("quota_exceeded")
	case errors.Is(err, syscall.ENOSPC):
		return fail("disk_full") // the server disk, not the account quota (R2-PERF-13)
	case errors.Is(err, syscall.ENAMETOOLONG):
		return fail("invalid_filename") // was 502 io_error (R2-UX-16)
	case errors.Is(err, syscall.ENOTDIR):
		return fail("not_a_directory")
	case errors.Is(err, syscall.ENOTEMPTY):
		return fail("not_empty")
	}
	return fail("io_error")
}

func copyTree(root *os.Root, src, dst string) error {
	st, err := root.Lstat(src)
	if err != nil {
		return err
	}
	if st.Mode()&fs.ModeSymlink != 0 {
		return nil // never copy symlinks
	}
	if st.IsDir() {
		if strings.HasPrefix(dst+"/", src+"/") {
			return fail("copy_into_self")
		}
		if err := root.MkdirAll(dst, st.Mode().Perm()); err != nil {
			return err
		}
		f, err := root.Open(src)
		if err != nil {
			return err
		}
		ents, err := f.ReadDir(-1)
		f.Close()
		if err != nil {
			return err
		}
		for _, e := range ents {
			if err := copyTree(root, path.Join(src, e.Name()), path.Join(dst, e.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	in, err := root.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := root.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, st.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close() // a failed close (quota, EIO) means the copy is incomplete
}

func zipTo(root *os.Root, srcs []string, dst string) (err error) {
	out, err := root.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()
	zw := zip.NewWriter(out)
	for _, s := range srcs {
		r, err := rel(s)
		if err != nil || r == "." {
			return fail("invalid_path")
		}
		base := path.Dir(r)
		err = fs.WalkDir(root.FS(), r, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if p == dst || d.Type()&fs.ModeSymlink != 0 {
				return nil
			}
			name := strings.TrimPrefix(strings.TrimPrefix(p, base), "/")
			info, err := d.Info()
			if err != nil {
				return err
			}
			hdr, err := zip.FileInfoHeader(info)
			if err != nil {
				return err
			}
			hdr.Name = name
			if d.IsDir() {
				hdr.Name += "/"
				_, err := zw.CreateHeader(hdr)
				return err
			}
			hdr.Method = zip.Deflate
			w, err := zw.CreateHeader(hdr)
			if err != nil {
				return err
			}
			f, err := root.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(w, f)
			return err
		})
		if err != nil {
			return err
		}
	}
	return zw.Close()
}

func unzip(root *os.Root, src, dst string) error {
	f, err := root.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		return fail("bad_zip")
	}
	if len(zr.File) > MaxUnzipEntries {
		return fail("zip_too_large")
	}
	var total uint64
	budget := int64(MaxUnzipBytes) // bytes actually written, not the (forgeable) header sizes
	for _, zf := range zr.File {
		total += zf.UncompressedSize64
		if total > MaxUnzipBytes {
			return fail("zip_too_large")
		}
		name, err := validate.FilePath(zf.Name)
		if err != nil || name == "" {
			return fail("bad_zip_entry")
		}
		target := path.Join(dst, name)
		if zf.FileInfo().IsDir() {
			if err := root.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if zf.Mode()&fs.ModeSymlink != 0 {
			continue
		}
		if err := root.MkdirAll(path.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		mode := zf.Mode().Perm()
		if mode == 0 {
			mode = 0o644
		}
		out, err := root.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode&0o755)
		if err != nil {
			rc.Close()
			return err
		}
		n, err := io.Copy(out, io.LimitReader(rc, budget+1))
		rc.Close()
		cerr := out.Close()
		if err != nil {
			return err
		}
		if cerr != nil {
			return cerr
		}
		budget -= n
		if budget < 0 {
			_ = root.Remove(target)
			return fail("zip_too_large")
		}
	}
	return nil
}
