package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ---- secret files ---------------------------------------------------------------

// ErrInsecureSecret is returned when a password/credential file is readable
// by anyone but its (root) owner.
var ErrInsecureSecret = errors.New("backup secret file must be mode 0600 and owned by root")

// CheckSecretFile enforces that path is a regular file, mode 0600 (no group /
// other bits) and owned by wantUID (0 = root in production; tests pass their
// own uid). Accounts therefore never get the repository password or target
// credentials (§14: a compromised account must not be able to delete backups).
func CheckSecretFile(path string, wantUID int) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		return ErrInsecureSecret
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != wantUID {
		return ErrInsecureSecret
	}
	return nil
}

// ForgetCounts parses `restic forget --json` output (one array of groups,
// each with keep/remove lists) into totals.
func ForgetCounts(out string) (kept, removed int) {
	var groups []struct {
		Keep   []json.RawMessage `json:"keep"`
		Remove []json.RawMessage `json:"remove"`
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[") {
			continue
		}
		if json.Unmarshal([]byte(line), &groups) == nil {
			for _, g := range groups {
				kept += len(g.Keep)
				removed += len(g.Remove)
			}
			return
		}
	}
	return
}

// EnsurePasswordFile creates a random repository password file (0600) when
// missing and verifies its permissions.
// TODO(v0.4 secrets): when internal/secrets lands, store the repository
// password in the secret store and materialise it into a 0600 root file only
// for the duration of a restic call.
func EnsurePasswordFile(path string, wantUID int) error {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, werr := fmt.Fprintf(f, "%x\n", b)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return werr
		}
	}
	return CheckSecretFile(path, wantUID)
}

// LoadCreds reads a JSON Creds file after CheckSecretFile.
func LoadCreds(path string, wantUID int) (Creds, error) {
	var c Creds
	if path == "" {
		return c, nil
	}
	if err := CheckSecretFile(path, wantUID); err != nil {
		return c, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, errors.New("backup credentials file is not valid JSON")
	}
	return c, nil
}

// ---- retention ------------------------------------------------------------------

// Retention maps to `restic forget --prune --keep-*`.
type Retention struct {
	Last    int `json:"keep_last"`
	Daily   int `json:"keep_daily"`
	Weekly  int `json:"keep_weekly"`
	Monthly int `json:"keep_monthly"`
	Yearly  int `json:"keep_yearly"`
}

// DefaultRetention: 7 daily, 4 weekly, 6 monthly.
var DefaultRetention = Retention{Daily: 7, Weekly: 4, Monthly: 6}

// ForgetArgs returns the restic argv (without the binary) for the policy.
// A policy that keeps nothing is refused: forget without keep-* flags would
// remove every snapshot.
func (r Retention) ForgetArgs() ([]string, error) {
	args := []string{"forget", "--prune", "--group-by", "host,paths"}
	n := 0
	for _, kv := range []struct {
		flag string
		v    int
	}{{"--keep-last", r.Last}, {"--keep-daily", r.Daily}, {"--keep-weekly", r.Weekly}, {"--keep-monthly", r.Monthly}, {"--keep-yearly", r.Yearly}} {
		if kv.v < 0 || kv.v > 1000 {
			return nil, fmt.Errorf("retention %s out of range", kv.flag)
		}
		if kv.v > 0 {
			args = append(args, kv.flag, strconv.Itoa(kv.v))
			n++
		}
	}
	if n == 0 {
		return nil, errors.New("retention policy keeps nothing")
	}
	return args, nil
}

// ---- runner ---------------------------------------------------------------------

// Engine runs restic for one target. It is used by the root agent only.
type Engine struct {
	Bin          string // restic binary
	Target       Target
	Creds        Creds
	PasswordFile string // root 0600 (legacy; unused when Password is set)
	// Password (v0.4 part B) comes from the panel secret store via agent
	// memory and reaches restic only as RESTIC_PASSWORD in the child env.
	Password    string
	CacheDir    string
	ManifestDir string // root-only; <dir>/<account>/<snapshot>.json
	SecretUID   int    // expected owner of PasswordFile (0 in production)
	Timeout     time.Duration
}

func (e *Engine) env(account string) ([]string, error) {
	repo, err := e.Target.RepoURL(account)
	if err != nil {
		return nil, err
	}
	env := []string{"RESTIC_REPOSITORY=" + repo, "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + os.TempDir()}
	if e.Password != "" {
		env = append(env, "RESTIC_PASSWORD="+e.Password)
	} else {
		if err := CheckSecretFile(e.PasswordFile, e.SecretUID); err != nil {
			return nil, err
		}
		env = append(env, "RESTIC_PASSWORD_FILE="+e.PasswordFile)
	}
	if e.CacheDir != "" {
		env = append(env, "RESTIC_CACHE_DIR="+e.CacheDir)
	} else {
		env = append(env, "RESTIC_CACHE_DIR="+filepath.Join(os.TempDir(), "bpanel-restic-cache"))
	}
	return append(env, e.Target.Env(e.Creds)...), nil
}

func (e *Engine) scrub(s string) string {
	for _, v := range append(e.Creds.secrets(), e.Password) {
		if v == "" {
			continue
		}
		s = strings.ReplaceAll(s, v, "[redacted]")
	}
	return s
}

// Run executes restic with args for account and returns stdout. Errors carry
// the last stderr lines, scrubbed of secrets.
func (e *Engine) Run(ctx context.Context, account string, args ...string) (string, error) {
	for _, a := range args {
		if a == "--no-lock" {
			return "", errors.New("--no-lock is not allowed")
		}
	}
	env, err := e.env(account)
	if err != nil {
		return "", err
	}
	if e.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, e.Bin, args...)
	cmd.Env = env
	var out, serr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &serr
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("restic %s: %v: %s", args[0], err, e.scrub(tail(serr.String(), 6)))
	}
	return out.String(), nil
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// Init creates the repository if it does not exist yet.
func (e *Engine) Init(ctx context.Context, account string) error {
	if _, err := e.Run(ctx, account, "cat", "config"); err == nil {
		return nil
	}
	_, err := e.Run(ctx, account, "init")
	return err
}

// Snapshot is the subset of `restic snapshots --json` we use.
type Snapshot struct {
	ID      string    `json:"id"`
	ShortID string    `json:"short_id"`
	Time    time.Time `json:"time"`
	Paths   []string  `json:"paths"`
	Tags    []string  `json:"tags"`
}

// Snapshots lists snapshots with an optional tag filter.
func (e *Engine) Snapshots(ctx context.Context, account, tag string) ([]Snapshot, error) {
	args := []string{"snapshots", "--json"}
	if tag != "" {
		args = append(args, "--tag", tag)
	}
	out, err := e.Run(ctx, account, args...)
	if err != nil {
		return nil, err
	}
	var s []Snapshot
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		return nil, fmt.Errorf("restic snapshots: bad json: %v", err)
	}
	return s, nil
}

// BackupDir backs up dir (absolute) with tag "files", records the manifest
// and returns the snapshot id. excludes are absolute paths.
func (e *Engine) BackupDir(ctx context.Context, account, dir string, excludes []string) (string, *Manifest, error) {
	if err := e.Init(ctx, account); err != nil {
		return "", nil, err
	}
	m, err := BuildManifest(dir, excludes)
	if err != nil {
		return "", nil, err
	}
	args := []string{"backup", "--json", "--tag", "files"}
	for _, x := range excludes {
		args = append(args, "--exclude", x)
	}
	args = append(args, dir)
	out, err := e.Run(ctx, account, args...)
	if err != nil {
		return "", nil, err
	}
	id := SummarySnapshotID(out)
	if id == "" {
		return "", nil, errors.New("restic backup: no snapshot id in output")
	}
	m.DropChanged() // files modified while restic was reading them
	m.SnapshotID = id
	if err := e.saveManifest(account, m); err != nil {
		return id, m, err
	}
	return id, m, nil
}

// SummarySnapshotID extracts snapshot_id from restic backup --json output.
func SummarySnapshotID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		var s struct {
			Type string `json:"message_type"`
			ID   string `json:"snapshot_id"`
		}
		if json.Unmarshal([]byte(line), &s) == nil && s.Type == "summary" && s.ID != "" {
			return s.ID
		}
	}
	return ""
}

// Forget applies the retention policy.
func (e *Engine) Forget(ctx context.Context, account string, r Retention) (string, error) {
	args, err := r.ForgetArgs()
	if err != nil {
		return "", err
	}
	return e.Run(ctx, account, append(args, "--json")...)
}

// ForgetSnapshot removes one snapshot (admin-only action).
func (e *Engine) ForgetSnapshot(ctx context.Context, account, id string) error {
	if !snapIDRe.MatchString(id) {
		return errors.New("invalid snapshot id")
	}
	_, err := e.Run(ctx, account, "forget", "--prune", id)
	return err
}

// Restore restores snapshot (optionally only include, an absolute path inside
// the snapshot) into target.
func (e *Engine) Restore(ctx context.Context, account, snapshot, include, target string) error {
	if snapshot != "latest" && !snapIDRe.MatchString(snapshot) {
		return errors.New("invalid snapshot id")
	}
	args := []string{"restore", snapshot, "--target", target}
	if include != "" {
		args = append(args, "--include", include)
	}
	_, err := e.Run(ctx, account, args...)
	return err
}

// Check runs restic check, reading subset ("5%", "1/10", "" = metadata only).
func (e *Engine) Check(ctx context.Context, account, subset string) error {
	args := []string{"check"}
	if subset != "" {
		if !subsetRe.MatchString(subset) {
			return errors.New("invalid read-data-subset")
		}
		args = append(args, "--read-data-subset="+subset)
	}
	_, err := e.Run(ctx, account, args...)
	return err
}

func (e *Engine) manifestPath(account, snap string) string {
	return filepath.Join(e.ManifestDir, account, snap+".json")
}

func (e *Engine) saveManifest(account string, m *Manifest) error {
	if e.ManifestDir == "" {
		return errors.New("no manifest dir configured")
	}
	p := e.manifestPath(account, m.SnapshotID)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(m)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// LoadManifest loads the manifest recorded for a snapshot.
func (e *Engine) LoadManifest(account, snap string) (*Manifest, error) {
	if !snapIDRe.MatchString(snap) {
		return nil, errors.New("invalid snapshot id")
	}
	b, err := os.ReadFile(e.manifestPath(account, snap))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// SaveManifest records m (m.SnapshotID must be set) for account.
func (e *Engine) SaveManifest(account string, m *Manifest) error {
	if m == nil || !snapIDRe.MatchString(m.SnapshotID) || !ValidAccount(account) {
		return errors.New("invalid manifest")
	}
	return e.saveManifest(account, m)
}
