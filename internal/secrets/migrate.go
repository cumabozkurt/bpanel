package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

// MigrateResult summarises a provider migration (names only, never values).
type MigrateResult struct {
	Copied   int      `json:"copied"`
	Verified int      `json:"verified"`
	Failed   []string `json:"failed,omitempty"`
}

// ErrMigrateVerify means at least one secret did not read back identically.
var ErrMigrateVerify = errors.New("secret_migrate_verify_failed")

// Migrate copies every named secret from src to dst and then reads each one
// back from dst and compares it byte-for-byte with src. It never deletes
// anything from src, so a failed or interrupted migration leaves the old
// provider authoritative; the caller switches providers only when err==nil.
// Errors name the secret, never its value.
func Migrate(ctx context.Context, src, dst SecretStore) (MigrateResult, error) {
	var res MigrateResult
	metas, err := src.List(ctx)
	if err != nil {
		return res, fmt.Errorf("list source: %w", err)
	}
	for _, m := range metas {
		v, err := src.Get(ctx, m.Name)
		if err != nil {
			res.Failed = append(res.Failed, m.Name)
			continue
		}
		if err := dst.Put(ctx, m.Name, v); err != nil {
			res.Failed = append(res.Failed, m.Name)
			continue
		}
		res.Copied++
	}
	for _, m := range metas {
		want, err1 := src.Get(ctx, m.Name)
		got, err2 := dst.Get(ctx, m.Name)
		if err1 != nil || err2 != nil || !bytes.Equal(want, got) {
			if !contains(res.Failed, m.Name) {
				res.Failed = append(res.Failed, m.Name)
			}
			continue
		}
		res.Verified++
	}
	if len(res.Failed) > 0 || res.Verified != len(metas) {
		return res, fmt.Errorf("%w: %d of %d secrets not verified", ErrMigrateVerify, len(metas)-res.Verified, len(metas))
	}
	return res, nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
