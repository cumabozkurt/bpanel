// SPDX-License-Identifier: Apache-2.0

package obsx

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// FIM modes: hash = sha256 of content; meta = mtime/size/owner/mode only
// (used for /etc/shadow and /etc/passwd: the panel never reads their content).
const (
	FIMHash = "hash"
	FIMMeta = "meta"
)

// FIMTarget is one watched path; directories are walked (regular files only,
// no symlink following, at most MaxFiles entries).
type FIMTarget struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

// FIMEntry is one file's fingerprint.
type FIMEntry struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size"`
	MTime  int64  `json:"mtime"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Perm   uint32 `json:"perm"`
}

// FIMChange is one difference against the baseline.
type FIMChange struct {
	Path   string   `json:"path"`
	Change string   `json:"change"` // added | removed | modified
	Fields []string `json:"fields,omitempty"`
}

const (
	MaxFIMFiles    = 5000
	MaxFIMFileSize = 256 << 20
)

// DefaultFIMTargets is the agent's allowlist (only these are ever scanned).
func DefaultFIMTargets(panelBin []string) []FIMTarget {
	t := []FIMTarget{
		{"/etc/bpanel", FIMHash},
		{"/etc/ssh/sshd_config", FIMHash},
		{"/etc/ssh/sshd_config.d", FIMHash},
		{"/etc/nginx", FIMHash},
		{"/etc/php", FIMHash}, // php-fpm pool dirs live under /etc/php/<v>/fpm/pool.d
		{"/etc/opt/remi", FIMHash},
		{"/etc/php-fpm.d", FIMHash},
		{"/etc/passwd", FIMMeta},
		{"/etc/shadow", FIMMeta},
		{"/etc/group", FIMMeta},
		{"/etc/sudoers", FIMMeta},
	}
	for _, b := range panelBin {
		t = append(t, FIMTarget{b, FIMHash})
	}
	return t
}

func fingerprint(path, mode string, fi fs.FileInfo) (FIMEntry, error) {
	e := FIMEntry{Path: path, Mode: mode, Size: fi.Size(), MTime: fi.ModTime().Unix(), Perm: uint32(fi.Mode().Perm())}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		e.UID, e.GID = st.Uid, st.Gid
	}
	if mode == FIMHash && fi.Size() <= MaxFIMFileSize {
		f, err := os.Open(path)
		if err != nil {
			return e, err
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return e, err
		}
		e.SHA256 = hex.EncodeToString(h.Sum(nil))
	}
	return e, nil
}

// Scan fingerprints the targets. Missing targets are skipped (reported in
// missing); unreadable files are reported in errs by path (no content).
func Scan(targets []FIMTarget) (entries []FIMEntry, missing []string, errs []string) {
	for _, t := range targets {
		fi, err := os.Lstat(t.Path)
		if err != nil {
			missing = append(missing, t.Path)
			continue
		}
		if fi.Mode().IsRegular() {
			if e, err := fingerprint(t.Path, t.Mode, fi); err == nil {
				entries = append(entries, e)
			} else {
				errs = append(errs, t.Path)
			}
			continue
		}
		if !fi.IsDir() {
			continue
		}
		_ = filepath.WalkDir(t.Path, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				errs = append(errs, p)
				return nil
			}
			if len(entries) >= MaxFIMFiles {
				return filepath.SkipAll
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				errs = append(errs, p)
				return nil
			}
			if e, err := fingerprint(p, t.Mode, info); err == nil {
				entries = append(entries, e)
			} else {
				errs = append(errs, p)
			}
			return nil
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return
}

// Diff compares a baseline with a fresh scan.
func Diff(base, cur []FIMEntry) []FIMChange {
	bm := map[string]FIMEntry{}
	for _, e := range base {
		bm[e.Path] = e
	}
	var out []FIMChange
	seen := map[string]bool{}
	for _, c := range cur {
		seen[c.Path] = true
		b, ok := bm[c.Path]
		if !ok {
			out = append(out, FIMChange{Path: c.Path, Change: "added"})
			continue
		}
		var f []string
		if b.SHA256 != c.SHA256 {
			f = append(f, "sha256")
		}
		if b.Size != c.Size {
			f = append(f, "size")
		}
		if b.MTime != c.MTime && c.Mode == FIMMeta {
			f = append(f, "mtime") // for hash mode the content hash is authoritative
		}
		if b.UID != c.UID || b.GID != c.GID {
			f = append(f, "owner")
		}
		if b.Perm != c.Perm {
			f = append(f, "perm")
		}
		if len(f) > 0 {
			out = append(out, FIMChange{Path: c.Path, Change: "modified", Fields: f})
		}
	}
	for _, b := range base {
		if !seen[b.Path] {
			out = append(out, FIMChange{Path: b.Path, Change: "removed"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
