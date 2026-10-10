// Package auth: password hashing (argon2id), TOTP (RFC 6238), tokens and rate limiting.
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters (OWASP 2024 baseline: m=19MiB, t=2, p=1).
const (
	argonTime    = 2
	argonMemory  = 19 * 1024
	argonThreads = 1
	argonKeyLen  = 32
)

func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func CheckPassword(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// RandomToken returns n random bytes, hex encoded.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// RandomPassword returns a password that satisfies validate.Password.
func RandomPassword(n int) string {
	const set = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_+="
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	out := make([]byte, n)
	for i := range b {
		out[i] = set[int(b[i])%len(set)]
	}
	// guarantee classes
	out[0], out[1], out[2] = 'a'+out[0]%26, 'A'+out[1]%26, '2'+out[2]%8
	return string(out)
}

func SHA256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// ---- TOTP -----------------------------------------------------------------

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func NewTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b32.EncodeToString(b)
}

func TOTPURL(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + v.Encode()
}

func totpAt(secret string, counter uint64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	_, _ = m.Write(msg[:]) // hash.Hash.Write never fails
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// TOTPCode returns the current code (used by tests and the CLI).
func TOTPCode(secret string, t time.Time) string {
	c, _ := totpAt(secret, uint64(t.Unix()/30))
	return c
}

// VerifyTOTP accepts the current step and one step either side.
// It does NOT prevent replay; login paths must use VerifyTOTPStep.
func VerifyTOTP(secret, code string, t time.Time) bool {
	_, ok := VerifyTOTPStep(secret, code, t, 0)
	return ok
}

// VerifyTOTPStep accepts a code from the current step or one step either
// side, but only from a step strictly after lastStep, and returns the matched
// step. Storing that step and passing it back next time makes every code
// single-use (SEC-17 / CODE-19).
func VerifyTOTPStep(secret, code string, t time.Time, lastStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	if _, err := strconv.Atoi(code); err != nil {
		return 0, false
	}
	step := t.Unix() / 30
	for d := int64(-1); d <= 1; d++ {
		if step+d <= lastStep {
			continue
		}
		c, err := totpAt(secret, uint64(step+d))
		if err == nil && subtle.ConstantTimeCompare([]byte(c), []byte(code)) == 1 {
			return step + d, true
		}
	}
	return 0, false
}

// ---- rate limiting ----------------------------------------------------------

// Limiter is a token bucket per key (IP, user, ...).
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
	// MaxKeys bounds memory; when reached, idle (already refilled) buckets
	// are evicted first, then the least recently used ones. Buckets are never
	// all wiped at once, so flooding many keys cannot reset everyone's limits.
	MaxKeys int
}

type bucket struct {
	tokens float64
	last   time.Time
}

func NewLimiter(perMinute, burst int) *Limiter {
	return &Limiter{rate: float64(perMinute) / 60, burst: float64(burst), buckets: map[string]*bucket{}, MaxKeys: 100000}
}

// evict frees room for new keys (called with mu held).
func (l *Limiter) evict(now time.Time) {
	full := time.Duration(l.burst / l.rate * float64(time.Second))
	for k, b := range l.buckets {
		if now.Sub(b.last) >= full { // would be back at burst: forgetting it changes nothing
			delete(l.buckets, k)
		}
	}
	if len(l.buckets) < l.MaxKeys {
		return
	}
	// still full of active keys: drop the least recently used tenth
	type kv struct {
		k string
		t time.Time
	}
	all := make([]kv, 0, len(l.buckets))
	for k, b := range l.buckets {
		all = append(all, kv{k, b.last})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	for _, e := range all[:len(all)/10+1] {
		delete(l.buckets, e.k)
	}
}

func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.MaxKeys {
			l.evict(now)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

var ErrLocked = errors.New("too_many_attempts")

// SealWithToken encrypts secret with a key derived from a one-time token
// (AES-256-GCM). Only SHA256Hex(token) is stored, so a database copy alone
// never reveals the secret (SEC-8: phpMyAdmin SSO password at rest).
func SealWithToken(token, secret string) (string, error) {
	gcm, err := tokenAEAD(token)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return "v1:" + base64.RawStdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(secret), []byte("bpanel-pma"))), nil
}

// OpenWithToken reverses SealWithToken.
func OpenWithToken(token, sealed string) (string, error) {
	b64, ok := strings.CutPrefix(sealed, "v1:")
	if !ok {
		return "", errors.New("unsealed value")
	}
	raw, err := base64.RawStdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	gcm, err := tokenAEAD(token)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("short ciphertext")
	}
	pt, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], []byte("bpanel-pma"))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func tokenAEAD(token string) (cipher.AEAD, error) {
	k := sha256.Sum256([]byte("bpanel-seal-key\x00" + token)) // domain-separated from SHA256Hex(token)
	blk, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}
