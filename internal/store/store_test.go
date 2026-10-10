package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestMigrationsIdempotentAndChecksummed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE checksum<>''`).Scan(&n); err != nil || n < 2 {
		t.Fatalf("checksums: %d %v", n, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(p) // re-open: nothing re-applied
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE schema_migrations SET checksum='tampered' WHERE name='0001_init.sql'`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(p); err == nil {
		t.Fatal("modified migration not detected")
	}
}

func TestUniqueViolationAndTx(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ins := `INSERT INTO packages(name,created_at) VALUES('p',1)`
	if _, err := s.DB.Exec(ins); err != nil {
		t.Fatal(err)
	}
	_, err = s.DB.Exec(ins)
	if !IsUniqueViolation(err) {
		t.Fatalf("not detected as unique violation: %v", err)
	}
	if IsUniqueViolation(errors.New("UNIQUE constraint failed")) {
		t.Fatal("message text must not count")
	}
	boom := errors.New("boom")
	err = s.Tx(context.Background(), func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO packages(name,created_at) VALUES('q',1)`); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if _, err := One[Package](context.Background(), s.DB, `SELECT * FROM packages WHERE name='q'`); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("tx not rolled back")
	}
	ps, err := Select[Package](context.Background(), s.DB, `SELECT *, 7 AS accounts, 'x' AS unknown_col FROM packages`)
	if err != nil || len(ps) != 1 || ps[0].Accounts != 7 {
		t.Fatalf("select: %+v %v", ps, err)
	}
}

func TestForeignKeyCascade(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, q := range []string{
		`INSERT INTO users(id,username,role,password_hash,created_at) VALUES(1,'u','user','x',1)`,
		`INSERT INTO domains(id,user_id,name,kind,created_at) VALUES(1,1,'d.test','main',1)`,
		`INSERT INTO mailboxes(user_id,domain_id,email,created_at) VALUES(1,1,'a@d.test',1)`,
		`DELETE FROM domains WHERE id=1`,
	} {
		if _, err := s.DB.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM mailboxes`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("cascade: %d %v", n, err)
	}
}

func TestTxPanicReleasesConnection(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	func() {
		defer func() { _ = recover() }()
		_ = s.Tx(context.Background(), func(tx *sql.Tx) error { panic("boom") })
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var n int
	if err := s.DB.QueryRowContext(ctx, `SELECT 1`).Scan(&n); err != nil {
		t.Fatalf("connection still held after panic: %v", err)
	}
}
