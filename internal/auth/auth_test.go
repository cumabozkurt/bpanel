package auth

import (
	"fmt"
	"testing"
	"time"

	"github.com/cumabozkurt/bpanel/internal/validate"
)

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("Correct-Horse-9")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "Correct-Horse-9") {
		t.Fatal("expected match")
	}
	if CheckPassword(h, "wrong") {
		t.Fatal("expected mismatch")
	}
}

// RFC 6238 appendix B test vector (SHA1, secret "12345678901234567890").
func TestTOTPVector(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	got := TOTPCode(secret, time.Unix(59, 0))
	if got != "287082" { // last 6 digits of 94287082
		t.Fatalf("got %s", got)
	}
	if !VerifyTOTP(secret, "287082", time.Unix(59+30, 0)) {
		t.Fatal("expected one-step skew to verify")
	}
	if VerifyTOTP(secret, "287082", time.Unix(59+120, 0)) {
		t.Fatal("expected old code to fail")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(1, 3)
	for i := 0; i < 3; i++ {
		if !l.Allow("x") {
			t.Fatal("burst should allow")
		}
	}
	if l.Allow("x") {
		t.Fatal("should be limited")
	}
	if !l.Allow("y") {
		t.Fatal("other key independent")
	}
}

func TestRandomPasswordValid(t *testing.T) {
	for i := 0; i < 50; i++ {
		if err := validate.Password(RandomPassword(16)); err != nil {
			t.Fatal(err)
		}
	}
}

// SEC-17: a code is accepted once per step, never again (or older).
func TestVerifyTOTPStepReplay(t *testing.T) {
	sec := NewTOTPSecret()
	now := time.Now()
	c := TOTPCode(sec, now)
	step, ok := VerifyTOTPStep(sec, c, now, 0)
	if !ok {
		t.Fatal("valid code refused")
	}
	if _, ok := VerifyTOTPStep(sec, c, now, step); ok {
		t.Fatal("replayed code accepted")
	}
	prev := TOTPCode(sec, now.Add(-30*time.Second))
	if _, ok := VerifyTOTPStep(sec, prev, now, step); ok {
		t.Fatal("older code accepted after a newer one")
	}
}

// CODE-19: flooding new keys never resets an existing bucket.
func TestLimiterNoWipe(t *testing.T) {
	l := NewLimiter(1, 2)
	l.MaxKeys = 50
	if !l.Allow("victim") || !l.Allow("victim") {
		t.Fatal("burst")
	}
	if l.Allow("victim") {
		t.Fatal("not limited")
	}
	for i := 0; i < 500; i++ {
		l.Allow(fmt.Sprintf("spray-%d", i))
		l.Allow("victim") // keeps it recently used
	}
	if l.Allow("victim") {
		t.Fatal("limiter state for an active key was reset by spraying")
	}
	if len(l.buckets) > l.MaxKeys {
		t.Fatalf("unbounded: %d", len(l.buckets))
	}
}
