package store

// Round-2: R2-PERF-2/4/10/12/13 and the G1 limit migration.

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func openFile(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bpanel.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, p
}

// R2-PERF-12: a missing database with the install marker refuses to start.
func TestR2MissingDatabaseGuard(t *testing.T) {
	s, p := openFile(t)
	s.Close()
	if _, err := os.Stat(MarkerPath(p)); err != nil {
		t.Fatalf("marker not written: %v", err)
	}
	for _, f := range []string{p, p + "-wal", p + "-shm"} {
		_ = os.Remove(f)
	}
	if _, err := Open(p); !errors.Is(err, ErrDatabaseMissing) {
		t.Fatalf("got %v, want ErrDatabaseMissing", err)
	}
	t.Setenv("BPANEL_ALLOW_NEW_DB", "1")
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()
}

// R2-PERF-12: a database migrated by a newer release refuses to start.
func TestR2SchemaDowngradeGuard(t *testing.T) {
	s, p := openFile(t)
	if _, err := s.DB.Exec(`INSERT INTO schema_migrations(name, at) VALUES('9999_future.sql', 0)`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(p); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("got %v, want ErrSchemaTooNew", err)
	}
}

// R2-PERF-12: a corrupt file fails quick_check instead of random requests.
func TestR2QuickCheckCorrupt(t *testing.T) {
	s, p := openFile(t)
	for i := 0; i < 200; i++ {
		if _, err := s.DB.Exec(`INSERT INTO audit_log(at,actor,ip,action,target,detail,ok) VALUES(?,?,?,?,?,?,1)`, i, "a", "", "x", "t", "d"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := f.Stat()
	junk := make([]byte, 4096)
	for i := range junk {
		junk[i] = 0xA5
	}
	// overwrite pages in the middle (not the header)
	for off := int64(8192); off < st.Size()-4096; off += 16384 {
		_, _ = f.WriteAt(junk, off)
	}
	f.Close()
	if _, err := Open(p); err == nil {
		t.Fatal("corrupt database opened")
	}
}

// G1 + R2-PERF-10: migration 0004 turns 0 limits into -1 and adds indexes.
func TestR2LimitMigrationAndIndexes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "old.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	// simulate a v0.2 database: forget 0004, store old-style zeros
	if _, err := s.DB.Exec(`INSERT INTO packages(name,disk_mb,max_ftp,max_email,created_at) VALUES('old',0,0,5,0)`); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN ('mailboxes_user','users_package','domains_parent','db_grants_user')`).Scan(&n)
	if n != 4 {
		t.Fatalf("indexes: %d", n)
	}
	// the migration itself: run its UPDATE statements on fresh zero rows
	b, err := migrations.ReadFile("migrations/0004_r2.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE packages SET disk_mb=0, max_ftp=0 WHERE name='old'`); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range strings.Split(string(b), ";") {
		var keep []string
		for _, l := range strings.Split(stmt, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), "--") {
				keep = append(keep, l)
			}
		}
		stmt = strings.TrimSpace(strings.Join(keep, "\n"))
		if strings.HasPrefix(stmt, "UPDATE") {
			if _, err := s.DB.Exec(stmt); err != nil {
				t.Fatal(err)
			}
		}
	}
	var disk, ftp, email int64
	_ = s.DB.QueryRow(`SELECT disk_mb, max_ftp, max_email FROM packages WHERE name='old'`).Scan(&disk, &ftp, &email)
	if disk != -1 || ftp != -1 || email != 5 {
		t.Fatalf("migrated: disk=%d ftp=%d email=%d", disk, ftp, email)
	}
	s.Close()
}

// R2-PERF-2: the FTS index follows inserts and deletes; reads use the reader pool.
func TestR2AuditFTS(t *testing.T) {
	s, _ := openFile(t)
	if s.R == s.DB {
		t.Fatal("no separate reader pool for a file database")
	}
	for i, a := range []string{"account.create", "dns.update", "mailbox.create"} {
		if _, err := s.DB.Exec(`INSERT INTO audit_log(at,actor,ip,action,target,detail,ok) VALUES(?,?,?,?,?,?,1)`, i, "root", "", a, "Alice.Test", ""); err != nil {
			t.Fatal(err)
		}
	}
	count := func(q string) int {
		var n int
		if err := s.R.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE id IN (SELECT rowid FROM audit_fts WHERE audit_fts MATCH ?)`, `"`+q+`"`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count("create") != 2 || count("alice") != 3 || count("ns.up") != 1 {
		t.Fatalf("fts: %d %d %d", count("create"), count("alice"), count("ns.up"))
	}
	if _, err := s.DB.Exec(`DELETE FROM audit_log WHERE action='dns.update'`); err != nil {
		t.Fatal(err)
	}
	if count("ns.up") != 0 {
		t.Fatal("fts not updated on delete")
	}
	// the reader pool cannot write
	if _, err := s.R.Exec(`DELETE FROM audit_log`); err == nil {
		t.Fatal("reader pool wrote")
	}
}

// R2-PERF-4: BEGIN IMMEDIATE: concurrent read-then-write transactions from
// two processes (two Stores on one file) never fail half-way with BUSY
// after their reads; a writer held past busy_timeout is IsBusy.
func TestR2ImmediateTransactions(t *testing.T) {
	s1, p := openFile(t)
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 20; i++ {
		for _, s := range []*Store{s1, s2} {
			wg.Add(1)
			go func(s *Store, i int) {
				defer wg.Done()
				errs <- s.Tx(context.Background(), func(tx *sql.Tx) error {
					var n int
					if err := tx.QueryRow(`SELECT COUNT(*) FROM settings`).Scan(&n); err != nil {
						return err
					}
					_, err := tx.Exec(`INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)`, "k"+time.Now().String(), "v")
					return err
				})
			}(s, i)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("transaction failed: %v", err)
		}
	}
	// a writer that holds the lock: the other side reports busy (503 db_busy)
	tx, err := s1.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO settings(key,value) VALUES('lock','1')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.DB.Exec(`PRAGMA busy_timeout=100`); err != nil {
		t.Fatal(err)
	}
	_, err = s2.DB.Exec(`INSERT INTO settings(key,value) VALUES('other','1')`)
	if !IsBusy(err) {
		t.Fatalf("got %v, want busy", err)
	}
}

// R2-PERF-13: ENOSPC is disk_full.
func TestR2IsDiskFull(t *testing.T) {
	if !IsDiskFull(&os.PathError{Op: "write", Path: "x", Err: syscall.ENOSPC}) {
		t.Fatal("ENOSPC not disk full")
	}
	if IsDiskFull(errors.New("other")) {
		t.Fatal("other error is disk full")
	}
}
