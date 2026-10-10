package shield

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// QuarantineMeta describes one quarantined file (<id>.json).
type QuarantineMeta struct {
	ID            string      `json:"id"`
	Account       string      `json:"account"`
	OrigPath      string      `json:"orig_path"`
	UID           int         `json:"uid"`
	GID           int         `json:"gid"`
	Mode          os.FileMode `json:"mode"`
	Size          int64       `json:"size"`
	SHA256        string      `json:"sha256"`
	Detections    []Detection `json:"detections,omitempty"`
	TS            time.Time   `json:"ts"`
	FalsePositive string      `json:"false_positive,omitempty"` // "", "account", "global"
}

// Quarantine errors.
var (
	ErrNotRegular         = errors.New("not a regular file")
	ErrQuarantineTooLarge = errors.New("file too large for quarantine")
	ErrOutsideRoot        = errors.New("restore target outside account root")
	ErrTargetExists       = errors.New("restore target already exists")
	ErrTargetSymlink      = errors.New("restore target is a symlink")
	ErrRestoreInfected    = errors.New("rescan before restore did not return clean")
	ErrBadID              = errors.New("invalid quarantine id")
	ErrBadKeyPerms        = errors.New("quarantine key file is accessible by group/others")
)

// RescanFunc scans a candidate restore file for account.
type RescanFunc func(ctx context.Context, path, account string) (Result, error)

// Quarantine is an encrypted at-rest store: <root>/<id>.bin (AES-256-GCM,
// 0400) and <root>/<id>.json metadata; key in <root>/key (0600); root 0700.
type Quarantine struct {
	Root        string
	MaxSize     int64                                // default 256 MiB
	AccountRoot func(account string) (string, error) // required for Restore
	Rescan      RescanFunc                           // required for Restore
	Allow       *Allowlist
	mu          sync.Mutex
	aead        cipher.AEAD
}

// OpenQuarantine creates/opens the store under root.
func OpenQuarantine(root string) (*Quarantine, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(root, 0700); err != nil {
		return nil, err
	}
	key, err := loadOrCreateKey(filepath.Join(root, "key"))
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	al, err := LoadAllowlist(filepath.Join(root, "allowlist.json"))
	if err != nil {
		return nil, err
	}
	return &Quarantine{Root: root, MaxSize: 256 << 20, aead: aead, Allow: al}, nil
}

func loadOrCreateKey(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err == nil {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			f.Close()
			return nil, err
		}
		if _, err := f.Write(k); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, err
		}
		return k, f.Close()
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	f, err = os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0077 != 0 {
		return nil, ErrBadKeyPerms
	}
	k := make([]byte, 33)
	n, _ := io.ReadFull(f, k)
	if n != 32 {
		return nil, errors.New("quarantine key file must be exactly 32 bytes")
	}
	return k[:32], nil
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

// Put moves path into quarantine: opened with O_NOFOLLOW, encrypted, fsynced,
// then the original is unlinked (only if it is still the same inode).
func (q *Quarantine) Put(path, account string, dets []Detection) (QuarantineMeta, error) {
	return q.PutAs(path, path, account, dets)
}

// PutAs is Put with a different recorded original path: the upload pipeline
// quarantines a root-owned staging file whose restore target is the path the
// account asked to upload to.
func (q *Quarantine) PutAs(path, origPath, account string, dets []Detection) (QuarantineMeta, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return QuarantineMeta{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return QuarantineMeta{}, err
	}
	if !st.Mode().IsRegular() {
		return QuarantineMeta{}, ErrNotRegular
	}
	max := q.MaxSize
	if max <= 0 {
		max = 256 << 20
	}
	if st.Size() > max {
		return QuarantineMeta{}, ErrQuarantineTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return QuarantineMeta{}, err
	}
	if int64(len(data)) > max {
		return QuarantineMeta{}, ErrQuarantineTooLarge
	}
	sum := sha256.Sum256(data)
	m := QuarantineMeta{ID: newID(), Account: account, OrigPath: filepath.Clean(origPath), Mode: st.Mode().Perm(),
		Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Detections: dets, TS: time.Now().UTC()}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		m.UID, m.GID = int(sys.Uid), int(sys.Gid)
	}
	nonce := make([]byte, q.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return QuarantineMeta{}, err
	}
	ct := q.aead.Seal(nonce, nonce, data, []byte(m.ID))
	q.mu.Lock()
	defer q.mu.Unlock()
	binPath := filepath.Join(q.Root, m.ID+".bin")
	if err := atomicWrite(binPath, ct, 0400); err != nil {
		return QuarantineMeta{}, err
	}
	if err := q.writeMeta(m); err != nil {
		os.Remove(binPath)
		return QuarantineMeta{}, err
	}
	// unlink original only if the name still points at the inode we copied
	lst, err := os.Lstat(path)
	if err != nil || !os.SameFile(st, lst) {
		return m, fmt.Errorf("original changed during quarantine; copy kept, original not removed")
	}
	if err := os.Remove(path); err != nil {
		return m, fmt.Errorf("quarantined but could not remove original: %w", err)
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		d.Sync()
		d.Close()
	}
	return m, nil
}

func (q *Quarantine) writeMeta(m QuarantineMeta) error {
	b, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(q.Root, m.ID+".json"), b, 0600)
}

// Get returns one item's metadata.
func (q *Quarantine) Get(id string) (QuarantineMeta, error) {
	var m QuarantineMeta
	if !validID(id) {
		return m, ErrBadID
	}
	b, err := os.ReadFile(filepath.Join(q.Root, id+".json"))
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(b, &m)
	return m, err
}

// Decrypt returns the plaintext of an item (in memory only).
func (q *Quarantine) Decrypt(id string) ([]byte, error) {
	if !validID(id) {
		return nil, ErrBadID
	}
	ct, err := os.ReadFile(filepath.Join(q.Root, id+".bin"))
	if err != nil {
		return nil, err
	}
	ns := q.aead.NonceSize()
	if len(ct) < ns {
		return nil, errors.New("quarantine blob truncated")
	}
	return q.aead.Open(nil, ct[:ns], ct[ns:], []byte(id))
}

func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../") && !filepath.IsAbs(rel)
}

// Restore puts an item back at its original path. Refuses when the target's
// parent resolves outside the account root, when the target exists or is a
// symlink, or when a rescan is not clean. Owner/mode are restored.
func (q *Quarantine) Restore(ctx context.Context, id string) (QuarantineMeta, error) {
	m, err := q.Get(id)
	if err != nil {
		return m, err
	}
	if q.AccountRoot == nil || q.Rescan == nil {
		return m, errors.New("restore not configured (account root / rescan)")
	}
	aroot, err := q.AccountRoot(m.Account)
	if err != nil {
		return m, err
	}
	raroot, err := filepath.EvalSymlinks(aroot)
	if err != nil {
		return m, err
	}
	target := filepath.Clean(m.OrigPath)
	parent, err := filepath.EvalSymlinks(filepath.Dir(target))
	if err != nil {
		return m, fmt.Errorf("restore parent: %w", err)
	}
	if !within(raroot, parent) {
		return m, ErrOutsideRoot
	}
	final := filepath.Join(parent, filepath.Base(target))
	if lst, err := os.Lstat(final); err == nil {
		if lst.Mode()&os.ModeSymlink != 0 {
			return m, ErrTargetSymlink
		}
		return m, ErrTargetExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return m, err
	}
	data, err := q.Decrypt(id)
	if err != nil {
		return m, err
	}
	tf, err := os.CreateTemp(parent, ".bpanel-restore-*")
	if err != nil {
		return m, err
	}
	tmp := tf.Name()
	defer os.Remove(tmp)
	if _, err := tf.Write(data); err != nil {
		tf.Close()
		return m, err
	}
	if err := tf.Sync(); err != nil {
		tf.Close()
		return m, err
	}
	tf.Close()
	res, err := q.Rescan(ctx, tmp, m.Account)
	if err != nil {
		return m, fmt.Errorf("rescan: %w", err)
	}
	if res.Outcome != OutClean {
		return m, fmt.Errorf("%w: %s", ErrRestoreInfected, res.Outcome)
	}
	if os.Geteuid() == 0 {
		if err := os.Lchown(tmp, m.UID, m.GID); err != nil {
			return m, err
		}
	}
	if err := os.Chmod(tmp, m.Mode); err != nil {
		return m, err
	}
	// link(2) never overwrites: a target that appeared meanwhile makes it fail
	if err := os.Link(tmp, final); err != nil {
		if errors.Is(err, os.ErrExist) {
			return m, ErrTargetExists
		}
		return m, err
	}
	q.mu.Lock()
	q.removeLocked(id)
	q.mu.Unlock()
	return m, nil
}

// Delete permanently removes an item.
func (q *Quarantine) Delete(id string) error {
	if !validID(id) {
		return ErrBadID
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, err := os.Stat(filepath.Join(q.Root, id+".json")); err != nil {
		return err
	}
	return q.removeLocked(id)
}

func (q *Quarantine) removeLocked(id string) error {
	e1 := os.Remove(filepath.Join(q.Root, id+".bin"))
	e2 := os.Remove(filepath.Join(q.Root, id+".json"))
	if e1 != nil && !errors.Is(e1, os.ErrNotExist) {
		return e1
	}
	if e2 != nil && !errors.Is(e2, os.ErrNotExist) {
		return e2
	}
	return nil
}

// MarkFalsePositive allowlists the item's sha256 for its account ("account")
// or everywhere ("global"). The scanner consults the allowlist before engines.
func (q *Quarantine) MarkFalsePositive(id, scope string) (QuarantineMeta, error) {
	m, err := q.Get(id)
	if err != nil {
		return m, err
	}
	switch scope {
	case "account":
		err = q.Allow.Add(m.SHA256, m.Account)
	case "global":
		err = q.Allow.Add(m.SHA256, "")
	default:
		return m, fmt.Errorf("invalid scope %q (account|global)", scope)
	}
	if err != nil {
		return m, err
	}
	m.FalsePositive = scope
	q.mu.Lock()
	defer q.mu.Unlock()
	return m, q.writeMeta(m)
}

// List returns items of account ("" = all), newest first.
func (q *Quarantine) List(account string) ([]QuarantineMeta, error) {
	ents, err := os.ReadDir(q.Root)
	if err != nil {
		return nil, err
	}
	var out []QuarantineMeta
	for _, e := range ents {
		n := e.Name()
		if !strings.HasSuffix(n, ".json") || n == "allowlist.json" {
			continue
		}
		m, err := q.Get(strings.TrimSuffix(n, ".json"))
		if err != nil {
			continue
		}
		if account == "" || m.Account == account {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TS.After(out[j].TS) })
	return out, nil
}

// Allowlist is a persisted set of false-positive sha256 values, global or per account.
type Allowlist struct {
	Path    string `json:"-"`
	mu      sync.RWMutex
	Global  map[string]bool            `json:"global"`
	Account map[string]map[string]bool `json:"account"`
}

// LoadAllowlist loads (or starts) an allowlist persisted at p ("" = memory only).
func LoadAllowlist(p string) (*Allowlist, error) {
	a := &Allowlist{Path: p, Global: map[string]bool{}, Account: map[string]map[string]bool{}}
	if p == "" {
		return a, nil
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, a); err != nil {
		return nil, fmt.Errorf("allowlist corrupt: %w", err)
	}
	if a.Global == nil {
		a.Global = map[string]bool{}
	}
	if a.Account == nil {
		a.Account = map[string]map[string]bool{}
	}
	return a, nil
}

// Add allowlists sha for account ("" = global) and persists.
func (a *Allowlist) Add(sha, account string) error {
	sha = strings.ToLower(sha)
	if len(sha) != 64 {
		return errors.New("invalid sha256")
	}
	a.mu.Lock()
	if account == "" {
		a.Global[sha] = true
	} else {
		if a.Account[account] == nil {
			a.Account[account] = map[string]bool{}
		}
		a.Account[account][sha] = true
	}
	var b []byte
	var err error
	if a.Path != "" {
		b, err = json.Marshal(a)
	}
	a.mu.Unlock()
	if err != nil || a.Path == "" {
		return err
	}
	return atomicWrite(a.Path, b, 0600)
}

// Allowed implements AllowChecker.
func (a *Allowlist) Allowed(sha, account string) bool {
	if a == nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	sha = strings.ToLower(sha)
	if a.Global[sha] {
		return true
	}
	return account != "" && a.Account[account][sha]
}
