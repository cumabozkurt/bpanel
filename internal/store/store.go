// Package store owns the panel's SQLite database (the desired state).
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	// DB is the writer pool: one connection (SQLite has one writer), every
	// transaction BEGIN IMMEDIATE so a write never fails half-way with
	// SQLITE_BUSY after its reads (R2-PERF-4).
	DB *sql.DB
	// R is a read-only pool (WAL readers run in parallel with the writer).
	// List, search and count queries use it so a slow read never queues
	// behind, or blocks, the single writer connection (R2-PERF-2). For
	// ":memory:" databases R is DB.
	R *sql.DB
}

// ErrDatabaseMissing is returned when the database file is gone although
// this server was initialised before (R2-PERF-12): starting with a fresh,
// empty database would silently lose every account.
var ErrDatabaseMissing = errors.New("database file is missing but the server was initialised before (marker present); restore it from a backup or set BPANEL_ALLOW_NEW_DB=1 to start empty")

// ErrSchemaTooNew is returned when the database was migrated by a newer
// release than this binary (downgrade guard, R2-PERF-12).
var ErrSchemaTooNew = errors.New("database schema is newer than this program (downgrade); install the newer release again")

// MarkerPath is the file that proves a database has been created at path.
func MarkerPath(path string) string { return path + ".initialized" }

// Open opens (and migrates) the database at path. Use ":memory:" in tests.
func Open(path string) (*Store, error) {
	var dsn, rdsn string
	if path != ":memory:" {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			if _, merr := os.Stat(MarkerPath(path)); merr == nil && os.Getenv("BPANEL_ALLOW_NEW_DB") != "1" {
				return nil, ErrDatabaseMissing
			}
		}
		base := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
		dsn = base + "&_txlock=immediate"
		rdsn = base + "&_pragma=query_only(1)"
	} else {
		dsn = "file::memory:?cache=shared&_pragma=foreign_keys(1)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite: one writer. NOTE: with a single connection, never run a query
	// on s.DB while a Rows from s.DB is still open or inside Tx (deadlock).
	db.SetMaxOpenConns(1)
	s := &Store{DB: db, R: db}
	if err := s.quickCheck(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if rdsn != "" {
		r, err := sql.Open("sqlite", rdsn)
		if err != nil {
			_ = db.Close()
			return nil, err
		}
		r.SetMaxOpenConns(4)
		r.SetMaxIdleConns(4)
		r.SetConnMaxIdleTime(5 * time.Minute)
		s.R = r
		if _, err := os.Stat(MarkerPath(path)); errors.Is(err, os.ErrNotExist) {
			// best effort: only the missing-database guard depends on it
			_ = os.WriteFile(MarkerPath(path), []byte("created-by=bpanel\n"), 0o600)
		}
	}
	return s, nil
}

// quickCheck runs PRAGMA quick_check before anything else touches the file
// (R2-PERF-12): a corrupt database refuses to start instead of failing
// later in random requests.
func (s *Store) quickCheck() error {
	rows, err := s.DB.Query(`PRAGMA quick_check(5)`)
	if err != nil {
		return fmt.Errorf("database integrity check: %w", err)
	}
	defer rows.Close()
	var msgs []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return err
		}
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("database integrity check: %w", err)
	}
	if len(msgs) != 1 || msgs[0] != "ok" {
		return fmt.Errorf("database integrity check failed: %s", strings.Join(msgs, "; "))
	}
	return nil
}

func (s *Store) Close() error {
	if s.R != nil && s.R != s.DB {
		_ = s.R.Close()
	}
	return s.DB.Close()
}

func (s *Store) migrate() error {
	if _, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, at INTEGER NOT NULL)`); err != nil {
		return err
	}
	// v2: remember a checksum of every applied migration, so an edited
	// (already shipped) migration is detected instead of silently skipped.
	var hasSum int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('schema_migrations') WHERE name='checksum'`).Scan(&hasSum); err != nil {
		return err
	}
	if hasSum == 0 {
		if _, err := s.DB.Exec(`ALTER TABLE schema_migrations ADD COLUMN checksum TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	ents, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := []string{}
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	known := map[string]bool{}
	for _, n := range names {
		known[n] = true
	}
	applied, err := s.DB.Query(`SELECT name FROM schema_migrations`)
	if err != nil {
		return err
	}
	var unknown []string
	for applied.Next() {
		var n string
		if err := applied.Scan(&n); err != nil {
			applied.Close()
			return err
		}
		if !known[n] {
			unknown = append(unknown, n)
		}
	}
	applied.Close()
	if len(unknown) > 0 {
		return fmt.Errorf("%w (unknown migrations: %s)", ErrSchemaTooNew, strings.Join(unknown, ", "))
	}
	for _, n := range names {
		b, err := migrations.ReadFile("migrations/" + n)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		want := hex.EncodeToString(sum[:])
		var got string
		err = s.DB.QueryRow(`SELECT checksum FROM schema_migrations WHERE name=?`, n).Scan(&got)
		if err == nil {
			switch got {
			case want:
			case "":
				if _, err := s.DB.Exec(`UPDATE schema_migrations SET checksum=? WHERE name=?`, want, n); err != nil {
					return err
				}
			default:
				return fmt.Errorf("migration %s was modified after it was applied (checksum mismatch)", n)
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		tx, err := s.DB.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(b)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %s: %w", n, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(name,at,checksum) VALUES(?,?,?)`, n, time.Now().Unix(), want); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// IsUniqueViolation reports whether err is a SQLite UNIQUE / PRIMARY KEY
// constraint failure (detected by error code, not message text).
func IsUniqueViolation(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		c := se.Code()
		return c == sqlite3.SQLITE_CONSTRAINT_UNIQUE || c == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
	}
	return false
}

// IsBusy reports SQLITE_BUSY / SQLITE_LOCKED (another writer held the
// database longer than busy_timeout). The API answers 503 db_busy.
func IsBusy(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		c := se.Code() & 0xff
		return c == sqlite3.SQLITE_BUSY || c == sqlite3.SQLITE_LOCKED
	}
	return false
}

// IsDiskFull reports SQLITE_FULL (the filesystem holding the database is
// full). The API answers 507 disk_full (R2-PERF-13).
func IsDiskFull(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		return se.Code()&0xff == sqlite3.SQLITE_FULL
	}
	return errors.Is(err, syscall.ENOSPC)
}

// Tx runs fn inside one transaction. With SetMaxOpenConns(1) the transaction
// holds the only connection, so check-then-insert sequences inside fn are
// atomic with respect to every other request (CODE-13). fn must use tx only.
func (s *Store) Tx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	// a panic inside fn must not keep the only connection busy forever
	defer func() {
		if v := recover(); v != nil {
			_ = tx.Rollback()
			panic(v)
		}
	}()
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Querier is satisfied by *sql.DB and *sql.Tx.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// Setting helpers.
func (s *Store) Get(key, def string) string {
	var v string
	if err := s.DB.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v); err != nil {
		return def
	}
	return v
}

func (s *Store) Set(key, value string) error {
	_, err := s.DB.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// Select scans rows into a slice of structs, mapping columns to `db` tags.
func Select[T any](ctx context.Context, db Querier, q string, args ...any) ([]T, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := []T{}
	for rows.Next() {
		var t T
		v := reflect.ValueOf(&t).Elem()
		ptrs := make([]any, len(cols))
		for i, c := range cols {
			f := fieldByTag(v, c)
			if f.IsValid() {
				ptrs[i] = f.Addr().Interface()
			} else {
				var discard any
				ptrs[i] = &discard
			}
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// One returns the first row or sql.ErrNoRows.
func One[T any](ctx context.Context, db Querier, q string, args ...any) (T, error) {
	var zero T
	rs, err := Select[T](ctx, db, q, args...)
	if err != nil {
		return zero, err
	}
	if len(rs) == 0 {
		return zero, sql.ErrNoRows
	}
	return rs[0], nil
}

var (
	tagMu    sync.Mutex
	tagCache = map[reflect.Type]map[string]int{}
)

func fieldByTag(v reflect.Value, col string) reflect.Value {
	t := v.Type()
	tagMu.Lock()
	defer tagMu.Unlock()
	m, ok := tagCache[t]
	if !ok {
		m = map[string]int{}
		for i := 0; i < t.NumField(); i++ {
			tag := t.Field(i).Tag.Get("db")
			if tag == "" {
				tag = strings.ToLower(t.Field(i).Name)
			}
			m[tag] = i
		}
		tagCache[t] = m
	}
	if i, ok := m[col]; ok {
		return v.Field(i)
	}
	return reflect.Value{}
}

func Now() int64 { return time.Now().Unix() }
