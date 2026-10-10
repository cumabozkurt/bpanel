// Package secrets is BPANEL's secret store (v0.4 security foundation).
//
// The local provider encrypts every value with AES-256-GCM under a 32-byte
// master key kept in a 0600 file (default /etc/bpanel/secret.key). Every
// record carries the key_id it was sealed with; Rotate re-encrypts all rows
// under a fresh key. While a rotation runs, every key that may still be
// referenced is kept in a keyring file (<key>.ring, 0600) so a crash during
// rotation never strands a row; the ring is removed when rotation completes.
//
// Values never leave this package except through Get/Open: List returns
// names and metadata only.
package secrets

import (
	"context"
	"errors"
	"strings"
)

// DefaultKeyPath is the master key file used when the config names none.
const DefaultKeyPath = "/etc/bpanel/secret.key"

var (
	ErrNotFound      = errors.New("secret_not_found")
	ErrNotConfigured = errors.New("not_configured")
	ErrUnknownKey    = errors.New("secret_key_unknown")
	ErrCorrupt       = errors.New("secret_corrupt")
	ErrBadName       = errors.New("invalid_secret_name")
)

// Meta describes a stored secret without its value.
type Meta struct {
	Name      string `json:"name"`
	KeyID     string `json:"key_id"`
	CreatedAt int64  `json:"created_at"`
	RotatedAt int64  `json:"rotated_at"`
}

// SecretStore keeps named secrets.
type SecretStore interface {
	Put(ctx context.Context, name string, value []byte) error
	Get(ctx context.Context, name string) ([]byte, error)
	Delete(ctx context.Context, name string) error
	List(ctx context.Context) ([]Meta, error)
	// Rotate re-encrypts every record under a new key and returns how many
	// rows were rewritten.
	Rotate(ctx context.Context) (int, error)
	// Seal / Open encrypt a value that the caller stores itself (e.g. a
	// column of another table). aad binds the ciphertext to its context.
	Seal(ctx context.Context, plain []byte, aad string) (string, error)
	Open(ctx context.Context, sealed string, aad string) ([]byte, error)
	// Status reports the provider name and current key id (never key bytes).
	Status() map[string]any
}

// SealedPrefix starts every string produced by Seal.
const SealedPrefix = "bpsec:v1:"

// IsSealed reports whether s looks like a Seal output.
func IsSealed(s string) bool { return strings.HasPrefix(s, SealedPrefix) }

func validName(n string) bool {
	if n == "" || len(n) > 128 {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == ':' || c == '/') {
			return false
		}
	}
	return true
}

// NotConfigured is a SecretStore whose every call reports not_configured
// (never a fake success). Embed it to build "unavailable" stores.
type NotConfigured struct{}

func (NotConfigured) Put(context.Context, string, []byte) error   { return ErrNotConfigured }
func (NotConfigured) Get(context.Context, string) ([]byte, error) { return nil, ErrNotConfigured }
func (NotConfigured) Delete(context.Context, string) error        { return ErrNotConfigured }
func (NotConfigured) List(context.Context) ([]Meta, error)        { return nil, ErrNotConfigured }
func (NotConfigured) Rotate(context.Context) (int, error)         { return 0, ErrNotConfigured }
func (NotConfigured) Seal(context.Context, []byte, string) (string, error) {
	return "", ErrNotConfigured
}
func (NotConfigured) Open(context.Context, string, string) ([]byte, error) {
	return nil, ErrNotConfigured
}
func (NotConfigured) Status() map[string]any {
	return map[string]any{"provider": "none", "status": "not_configured"}
}

var _ SecretStore = NotConfigured{}
var _ SecretStore = (*Local)(nil)
