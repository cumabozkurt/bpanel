package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Local is the AES-256-GCM provider backed by the `secrets` table.
type Local struct {
	db      *sql.DB
	keyPath string
	mu      sync.RWMutex
	cur     string            // current key id
	keys    map[string][]byte // kid -> key (current + any still in the ring)
	now     func() time.Time
}

func keyID(k []byte) string {
	h := sha256.Sum256(k)
	return "k" + hex.EncodeToString(h[:6])
}

func ringPath(p string) string { return p + ".ring" }

type ringFile struct {
	Current string            `json:"current"`
	Keys    map[string]string `json:"keys"` // kid -> base64 key
}

// writeFile0600 writes atomically with mode 0600.
func writeFile0600(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// NewLocal opens (or creates) the master key file at keyPath and returns
// the provider. A missing file is created with 32 random bytes, mode 0600.
// A key file with looser permissions is tightened to 0600.
func NewLocal(db *sql.DB, keyPath string) (*Local, error) {
	if keyPath == "" {
		keyPath = DefaultKeyPath
	}
	l := &Local{db: db, keyPath: keyPath, keys: map[string][]byte{}, now: time.Now}
	key, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := writeFile0600(keyPath, key); err != nil {
			return nil, fmt.Errorf("secrets: create key file: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("secrets: read key file: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("secrets: key file %s must hold exactly 32 bytes", keyPath)
	}
	if fi, err := os.Stat(keyPath); err == nil && fi.Mode().Perm()&0o077 != 0 {
		_ = os.Chmod(keyPath, 0o600)
	}
	l.cur = keyID(key)
	l.keys[l.cur] = key
	// an interrupted rotation leaves a ring: load every key it holds.
	if b, err := os.ReadFile(ringPath(keyPath)); err == nil {
		var rf ringFile
		if json.Unmarshal(b, &rf) == nil {
			for kid, s := range rf.Keys {
				if k, err := base64.StdEncoding.DecodeString(s); err == nil && len(k) == 32 && keyID(k) == kid {
					l.keys[kid] = k
				}
			}
		}
	}
	return l, nil
}

// KeyPath returns the master key file path.
func (l *Local) KeyPath() string { return l.keyPath }

func (l *Local) Status() map[string]any {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return map[string]any{"provider": "local", "status": "ok", "key_id": l.cur, "keys_loaded": len(l.keys)}
}

func gcmFor(k []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func (l *Local) encrypt(plain []byte, aad string) (kid string, nonce, ct []byte, err error) {
	l.mu.RLock()
	kid, k := l.cur, l.keys[l.cur]
	l.mu.RUnlock()
	g, err := gcmFor(k)
	if err != nil {
		return "", nil, nil, err
	}
	nonce = make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, nil, err
	}
	return kid, nonce, g.Seal(nil, nonce, plain, []byte(aad)), nil
}

func (l *Local) decrypt(kid string, nonce, ct []byte, aad string) ([]byte, error) {
	l.mu.RLock()
	k, ok := l.keys[kid]
	l.mu.RUnlock()
	if !ok {
		return nil, ErrUnknownKey
	}
	g, err := gcmFor(k)
	if err != nil {
		return nil, err
	}
	if len(nonce) != g.NonceSize() {
		return nil, ErrCorrupt
	}
	p, err := g.Open(nil, nonce, ct, []byte(aad))
	if err != nil {
		return nil, ErrCorrupt
	}
	return p, nil
}

func (l *Local) Seal(_ context.Context, plain []byte, aad string) (string, error) {
	kid, n, ct, err := l.encrypt(plain, aad)
	if err != nil {
		return "", err
	}
	e := base64.RawURLEncoding
	return SealedPrefix + kid + ":" + e.EncodeToString(n) + ":" + e.EncodeToString(ct), nil
}

func (l *Local) Open(_ context.Context, sealed, aad string) ([]byte, error) {
	if !IsSealed(sealed) {
		return nil, ErrCorrupt
	}
	parts := strings.Split(strings.TrimPrefix(sealed, SealedPrefix), ":")
	if len(parts) != 3 {
		return nil, ErrCorrupt
	}
	e := base64.RawURLEncoding
	n, err1 := e.DecodeString(parts[1])
	ct, err2 := e.DecodeString(parts[2])
	if err1 != nil || err2 != nil {
		return nil, ErrCorrupt
	}
	return l.decrypt(parts[0], n, ct, aad)
}

func aadFor(name string) string { return "bpanel-secret:" + name }

func (l *Local) Put(ctx context.Context, name string, value []byte) error {
	if !validName(name) {
		return ErrBadName
	}
	kid, n, ct, err := l.encrypt(value, aadFor(name))
	if err != nil {
		return err
	}
	now := l.now().Unix()
	_, err = l.db.ExecContext(ctx, `INSERT INTO secrets(name,key_id,nonce,ciphertext,created_at,rotated_at) VALUES(?,?,?,?,?,0)
		ON CONFLICT(name) DO UPDATE SET key_id=excluded.key_id, nonce=excluded.nonce, ciphertext=excluded.ciphertext, rotated_at=?`,
		name, kid, n, ct, now, now)
	return err
}

func (l *Local) Get(ctx context.Context, name string) ([]byte, error) {
	var kid string
	var n, ct []byte
	err := l.db.QueryRowContext(ctx, `SELECT key_id,nonce,ciphertext FROM secrets WHERE name=?`, name).Scan(&kid, &n, &ct)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return l.decrypt(kid, n, ct, aadFor(name))
}

func (l *Local) Delete(ctx context.Context, name string) error {
	res, err := l.db.ExecContext(ctx, `DELETE FROM secrets WHERE name=?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (l *Local) List(ctx context.Context) ([]Meta, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT name,key_id,created_at,rotated_at FROM secrets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Meta{}
	for rows.Next() {
		var m Meta
		if err := rows.Scan(&m.Name, &m.KeyID, &m.CreatedAt, &m.RotatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (l *Local) writeRing() error {
	rf := ringFile{Current: l.cur, Keys: map[string]string{}}
	for kid, k := range l.keys {
		rf.Keys[kid] = base64.StdEncoding.EncodeToString(k)
	}
	b, _ := json.Marshal(rf)
	return writeFile0600(ringPath(l.keyPath), b)
}

// Rotate generates a new master key and re-encrypts every row of the
// secrets table under it. Order (crash-safe): 1) ring file with old+new
// keys, 2) new key becomes the master key file, 3) rows rewritten in one
// transaction, 4) ring removed and old keys forgotten. Values sealed with
// Seal and stored elsewhere (e.g. webhooks.secret) must be re-sealed by
// their owner via Reseal; until then the old key stays in the ring.
func (l *Local) Rotate(ctx context.Context) (int, error) {
	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return 0, err
	}
	nk := keyID(newKey)
	l.mu.Lock()
	l.keys[nk] = newKey
	old := l.cur
	if err := l.writeRing(); err != nil {
		delete(l.keys, nk)
		l.mu.Unlock()
		return 0, err
	}
	if err := writeFile0600(l.keyPath, newKey); err != nil {
		l.mu.Unlock()
		return 0, err
	}
	l.cur = nk
	l.mu.Unlock()

	type row struct {
		name, kid string
		n, ct     []byte
	}
	rows, err := l.db.QueryContext(ctx, `SELECT name,key_id,nonce,ciphertext FROM secrets WHERE key_id<>?`, nk)
	if err != nil {
		return 0, err
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.name, &r.kid, &r.n, &r.ct); err != nil {
			rows.Close()
			return 0, err
		}
		all = append(all, r)
	}
	rows.Close()
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := l.now().Unix()
	for _, r := range all {
		p, err := l.decrypt(r.kid, r.n, r.ct, aadFor(r.name))
		if err != nil {
			return 0, fmt.Errorf("secrets: rotate %s: %w", r.name, err)
		}
		kid, n, ct, err := l.encrypt(p, aadFor(r.name))
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE secrets SET key_id=?,nonce=?,ciphertext=?,rotated_at=? WHERE name=?`, kid, n, ct, now, r.name); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	_ = old
	return len(all), nil
}

// FinishRotation forgets every key except the current one and removes the
// ring file. Call it after all externally stored sealed values have been
// re-sealed (Reseal). Rotate alone keeps old keys so such values still open.
func (l *Local) FinishRotation() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for kid := range l.keys {
		if kid != l.cur {
			delete(l.keys, kid)
		}
	}
	err := os.Remove(ringPath(l.keyPath))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Reseal re-encrypts a Seal output under the current key (no-op if already current).
func (l *Local) Reseal(ctx context.Context, sealed, aad string) (string, error) {
	l.mu.RLock()
	cur := l.cur
	l.mu.RUnlock()
	if strings.HasPrefix(sealed, SealedPrefix+cur+":") {
		return sealed, nil
	}
	p, err := l.Open(ctx, sealed, aad)
	if err != nil {
		return "", err
	}
	return l.Seal(ctx, p, aad)
}
