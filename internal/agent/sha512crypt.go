package agent

import (
	"crypto/rand"
	"crypto/sha512"
	"strconv"
	"strings"
)

// ---- R2-WB-13: mailbox password hashes ----------------------------------------
//
// Mailbox passwords were stored as {SSHA512}: one salted SHA-512, cracked at
// billions of guesses per second once the passwd file leaks. They are now
// SHA512-CRYPT ($6$) with mailCryptRounds rounds, which every Dovecot
// (2.3 and 2.4) verifies through libc crypt(3), unlike ARGON2ID/BLF-CRYPT,
// whose support depends on how Dovecot was built. Existing {SSHA512} lines
// keep working (Dovecot reads the scheme prefix) and are upgraded on the
// next password change.

const mailCryptRounds = 100000

const cryptB64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// HashMailPassword returns a Dovecot {SHA512-CRYPT} hash with a random salt.
func HashMailPassword(pw string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on Linux
	}
	salt := make([]byte, 16)
	for i := range b {
		salt[i] = cryptB64[int(b[i])%64]
	}
	return "{SHA512-CRYPT}" + sha512Crypt([]byte(pw), string(salt), mailCryptRounds)
}

// sha512Crypt implements Ulrich Drepper's SHA-crypt ($6$), as glibc does.
func sha512Crypt(pw []byte, salt string, rounds int) string {
	const defRounds = 5000
	if rounds < 1000 {
		rounds = 1000
	}
	if rounds > 999999999 {
		rounds = 999999999
	}
	if len(salt) > 16 {
		salt = salt[:16]
	}
	s := []byte(salt)

	// B = H(P S P)
	h := sha512.New()
	h.Write(pw)
	h.Write(s)
	h.Write(pw)
	bsum := h.Sum(nil)

	// A = H(P S B-repeated, then P/B by the bits of len(P))
	h.Reset()
	h.Write(pw)
	h.Write(s)
	for n := len(pw); n > 0; n -= 64 {
		h.Write(bsum[:min(n, 64)])
	}
	for n := len(pw); n > 0; n >>= 1 {
		if n&1 != 0 {
			h.Write(bsum)
		} else {
			h.Write(pw)
		}
	}
	asum := h.Sum(nil)

	// P-sequence
	h.Reset()
	for i := 0; i < len(pw); i++ {
		h.Write(pw)
	}
	dp := h.Sum(nil)
	pseq := make([]byte, 0, len(pw))
	for n := len(pw); n > 0; n -= 64 {
		pseq = append(pseq, dp[:min(n, 64)]...)
	}

	// S-sequence
	h.Reset()
	for i := 0; i < 16+int(asum[0]); i++ {
		h.Write(s)
	}
	ds := h.Sum(nil)
	sseq := make([]byte, 0, len(s))
	for n := len(s); n > 0; n -= 64 {
		sseq = append(sseq, ds[:min(n, 64)]...)
	}

	c := asum
	for i := 0; i < rounds; i++ {
		h.Reset()
		if i&1 != 0 {
			h.Write(pseq)
		} else {
			h.Write(c)
		}
		if i%3 != 0 {
			h.Write(sseq)
		}
		if i%7 != 0 {
			h.Write(pseq)
		}
		if i&1 != 0 {
			h.Write(c)
		} else {
			h.Write(pseq)
		}
		c = h.Sum(nil)
	}

	var out strings.Builder
	out.WriteString("$6$")
	if rounds != defRounds {
		out.WriteString("rounds=" + strconv.Itoa(rounds) + "$")
	}
	out.WriteString(salt)
	out.WriteByte('$')
	enc := func(b2, b1, b0 byte, n int) {
		w := uint(b2)<<16 | uint(b1)<<8 | uint(b0)
		for ; n > 0; n-- {
			out.WriteByte(cryptB64[w&0x3f])
			w >>= 6
		}
	}
	perm := [][3]int{{0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4}, {47, 5, 26}, {6, 27, 48},
		{28, 49, 7}, {50, 8, 29}, {9, 30, 51}, {31, 52, 10}, {53, 11, 32}, {12, 33, 54}, {34, 55, 13}, {56, 14, 35},
		{15, 36, 57}, {37, 58, 16}, {59, 17, 38}, {18, 39, 60}, {40, 61, 19}, {62, 20, 41}}
	for _, p := range perm {
		enc(c[p[0]], c[p[1]], c[p[2]], 4)
	}
	enc(0, 0, c[63], 2)
	return out.String()
}
