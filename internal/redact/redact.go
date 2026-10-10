// Package redact removes secrets from log lines and error text (master spec
// §18 "loglarda secret redaction"). It is applied as a slog.Handler wrapper
// to the API logger, and String can be used on any free text.
package redact

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
)

// Mask replaces a removed value.
const Mask = "[REDACTED]"

// sensitiveKey matches attribute / field names whose value is always secret.
var sensitiveKey = regexp.MustCompile(`(?i)(pass(word|wd|phrase)?|secret|token|authorization|cookie|api[_-]?key|private[_-]?key|credential|csrf|totp|otp|recovery[_-]?code|session[_-]?id|dek|kek)`)

// IsSensitiveKey reports whether a field called k must never be logged.
func IsSensitiveKey(k string) bool {
	if k == "" {
		return false
	}
	switch strings.ToLower(k) {
	case "totp_required", "totp_enabled", "token_id", "password_set", "reauth_required":
		return false
	}
	return sensitiveKey.MatchString(k)
}

var patterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	// PEM private keys (RSA, EC, OPENSSH, PKCS8, encrypted)
	{regexp.MustCompile(`-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----[\s\S]*?(-----END ([A-Z0-9 ]*)PRIVATE KEY-----|$)`), "-----BEGIN $1PRIVATE KEY-----" + Mask + "-----END $1PRIVATE KEY-----"},
	// Authorization headers / bearer and basic credentials
	{regexp.MustCompile(`(?i)\b(authorization\s*[:=]\s*)("?)(bearer|basic|token)\s+[^\s",;]+`), "$1$2$3 " + Mask},
	{regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}`), "Bearer " + Mask},
	// BPANEL API tokens and sealed secrets
	{regexp.MustCompile(`\bbpt_[A-Za-z0-9_-]{8,}`), "bpt_" + Mask},
	{regexp.MustCompile(`\bbpsec:v1:[A-Za-z0-9_-]+:[A-Za-z0-9+/=:_-]+`), "bpsec:" + Mask},
	// key=value and "key":"value" forms
	{regexp.MustCompile(`(?i)("(?:[a-z_-]*)(?:password|passwd|secret|token|api_?key|private_?key|recovery_?code|totp)(?:[a-z_-]*)"\s*:\s*")((?:[^"\\]|\\.)*)(")`), "${1}" + Mask + "${3}"},
	{regexp.MustCompile(`(?i)\b([a-z_-]*(?:password|passwd|pwd|secret|token|api_?key|private_?key)[a-z_-]*)=([^\s&"']+)`), "${1}=" + Mask},
	// URL userinfo (scheme://user:pass@host)
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:)([^@\s/]+)@`), "${1}" + Mask + "@"},
}

// String returns s with every recognised secret masked.
func String(s string) string {
	if s == "" {
		return s
	}
	for _, p := range patterns {
		s = p.re.ReplaceAllString(s, p.repl)
	}
	return s
}

// Handler wraps a slog.Handler and redacts attributes.
type Handler struct{ next slog.Handler }

// NewHandler wraps next. Wrapping twice is harmless.
func NewHandler(next slog.Handler) slog.Handler {
	if h, ok := next.(*Handler); ok {
		return h
	}
	return &Handler{next: next}
}

func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool { return h.next.Enabled(ctx, l) }

func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, String(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(Attr(a))
		return true
	})
	return h.next.Handle(ctx, nr)
}

func (h *Handler) WithAttrs(as []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(as))
	for i, a := range as {
		out[i] = Attr(a)
	}
	return &Handler{next: h.next.WithAttrs(out)}
}

func (h *Handler) WithGroup(name string) slog.Handler { return &Handler{next: h.next.WithGroup(name)} }

// Attr redacts one attribute (recursively for groups).
func Attr(a slog.Attr) slog.Attr {
	if IsSensitiveKey(a.Key) {
		if a.Value.Kind() == slog.KindString && a.Value.String() == "" {
			return a
		}
		return slog.String(a.Key, Mask)
	}
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, String(v.String()))
	case slog.KindGroup:
		gs := v.Group()
		out := make([]any, len(gs))
		for i, g := range gs {
			out[i] = Attr(g)
		}
		return slog.Group(a.Key, out...)
	case slog.KindAny:
		if err, ok := v.Any().(error); ok {
			return slog.String(a.Key, String(err.Error()))
		}
		if st, ok := v.Any().(interface{ String() string }); ok {
			return slog.String(a.Key, String(st.String()))
		}
		return a
	}
	return a
}
