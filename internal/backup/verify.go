package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	snapIDRe = regexp.MustCompile(`^[0-9a-f]{8,64}$`)
	subsetRe = regexp.MustCompile(`^([0-9]{1,3}(\.[0-9]{1,2})?%|[0-9]{1,4}/[0-9]{1,4})$`)
)

// FileEntry is one regular file recorded at backup time.
type FileEntry struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	MTime  int64  `json:"mtime_ns"`
}

// Manifest is the independent record of what was backed up: computed by
// BPanel from the live files (not from restic), so a restore can be compared
// against it.
type Manifest struct {
	SnapshotID string               `json:"snapshot_id"`
	Root       string               `json:"root"`
	Created    time.Time            `json:"created"`
	Files      map[string]FileEntry `json:"files"` // key: path relative to Root
	Skipped    int                  `json:"skipped"`
}

// MaxManifestFiles bounds the manifest (very large homes are sampled at
// verification time anyway; files beyond the bound are not recorded).
const MaxManifestFiles = 200000

func hashFile(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// BuildManifest walks root (no symlink following) and hashes every regular
// file not under one of excludes.
func BuildManifest(root string, excludes []string) (*Manifest, error) {
	root = filepath.Clean(root)
	m := &Manifest{Root: root, Created: time.Now().UTC(), Files: map[string]FileEntry{}}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			m.Skipped++
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		for _, x := range excludes {
			if p == x || strings.HasPrefix(p, x+"/") {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if len(m.Files) >= MaxManifestFiles {
			m.Skipped++
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			m.Skipped++
			return nil
		}
		sum, n, err := hashFile(p)
		if err != nil {
			m.Skipped++
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		m.Files[rel] = FileEntry{SHA256: sum, Size: n, MTime: fi.ModTime().UnixNano()}
		return nil
	})
	return m, err
}

// DropChanged removes entries whose file changed after hashing (mtime or
// size differ now), so a file being written during the backup is not
// reported as a restore mismatch later.
func (m *Manifest) DropChanged() {
	for rel, fe := range m.Files {
		fi, err := os.Lstat(filepath.Join(m.Root, rel))
		if err != nil || fi.Size() != fe.Size || fi.ModTime().UnixNano() != fe.MTime {
			delete(m.Files, rel)
			m.Skipped++
		}
	}
}

// Verification is the result of one restore test.
type Verification struct {
	Account      string    `json:"account"`
	SnapshotID   string    `json:"snapshot_id"`
	Started      time.Time `json:"started"`
	Finished     time.Time `json:"finished"`
	FilesChecked int       `json:"files_checked"`
	Mismatches   int       `json:"mismatches"`
	Missing      int       `json:"missing"`
	CheckOK      bool      `json:"check_ok"`
	Status       string    `json:"status"` // ok | failed | no_snapshot | no_manifest
	Error        string    `json:"error,omitempty"`
	Samples      []string  `json:"mismatch_samples,omitempty"` // relative paths, max 10
}

// VerifyOptions tunes VerifyRestore.
type VerifyOptions struct {
	SampleAll      int    // verify every file when the manifest has at most this many (default 500)
	SampleSize     int    // otherwise this many (default 300)
	ReadDataSubset string // restic check --read-data-subset (default "5%")
	TempDir        string // root-only staging parent (default os.TempDir())
}

// VerifyRestore restores the latest "files" snapshot of account into a fresh
// temp dir, compares sha256 of a sample (all files for small accounts) with
// the manifest recorded at backup time, and runs restic check with a data
// subset. Status is "ok" only when both pass.
func (e *Engine) VerifyRestore(ctx context.Context, account string, o VerifyOptions) Verification {
	v := Verification{Account: account, Started: time.Now().UTC(), Status: "failed"}
	defer func() { v.Finished = time.Now().UTC() }()
	if o.SampleAll == 0 {
		o.SampleAll = 500
	}
	if o.SampleSize == 0 {
		o.SampleSize = 300
	}
	if o.ReadDataSubset == "" {
		o.ReadDataSubset = "5%"
	}
	finish := func(status string, err error) Verification {
		v.Status = status
		if err != nil {
			v.Error = e.scrub(err.Error())
		}
		v.Finished = time.Now().UTC()
		return v
	}
	snaps, err := e.Snapshots(ctx, account, "files")
	if err != nil {
		return finish("failed", err)
	}
	if len(snaps) == 0 {
		return finish("no_snapshot", errors.New("no files snapshot"))
	}
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].Time.Before(snaps[j].Time) })
	snap := snaps[len(snaps)-1]
	v.SnapshotID = snap.ID
	m, err := e.LoadManifest(account, snap.ID)
	if err != nil {
		return finish("no_manifest", fmt.Errorf("no manifest for snapshot %s", snap.ShortID))
	}
	tmp, err := os.MkdirTemp(o.TempDir, "bpanel-verify-")
	if err != nil {
		return finish("failed", err)
	}
	defer os.RemoveAll(tmp)
	if err := os.Chmod(tmp, 0o700); err != nil {
		return finish("failed", err)
	}
	var restoreErr error
	if err := e.Restore(ctx, account, snap.ID, "", tmp); err != nil {
		restoreErr = err // keep comparing what did come back
	}
	keys := make([]string, 0, len(m.Files))
	for k := range m.Files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	keys = sample(keys, o.SampleAll, o.SampleSize)
	for _, rel := range keys {
		want := m.Files[rel]
		got, _, err := hashFile(filepath.Join(tmp, m.Root, rel))
		v.FilesChecked++
		if err != nil {
			v.Missing++
			v.Mismatches++
		} else if got != want.SHA256 {
			v.Mismatches++
		} else {
			continue
		}
		if len(v.Samples) < 10 {
			v.Samples = append(v.Samples, rel)
		}
	}
	checkErr := e.Check(ctx, account, o.ReadDataSubset)
	v.CheckOK = checkErr == nil
	var msgs []string
	if restoreErr != nil {
		msgs = append(msgs, "restore: "+restoreErr.Error())
	}
	if checkErr != nil {
		msgs = append(msgs, "check: "+checkErr.Error())
	}
	if v.Mismatches > 0 {
		msgs = append(msgs, fmt.Sprintf("%d of %d sampled files differ or are missing", v.Mismatches, v.FilesChecked))
	}
	if len(msgs) == 0 {
		v.Status = "ok"
	} else {
		v.Error = e.scrub(strings.Join(msgs, "; "))
	}
	return v
}

// sample returns all keys when there are at most all of them, otherwise a
// deterministic, evenly spread subset of n keys (stable across runs so that
// regressions are reproducible; rotated by day so coverage grows over time).
func sample(keys []string, all, n int) []string {
	if len(keys) <= all || n >= len(keys) {
		return keys
	}
	off := int(time.Now().Unix()/86400) % (len(keys) / n)
	out := make([]string, 0, n)
	step := float64(len(keys)) / float64(n)
	for i := 0; i < n; i++ {
		idx := int(float64(i)*step) + off
		if idx >= len(keys) {
			idx = len(keys) - 1
		}
		out = append(out, keys[idx])
	}
	return out
}
