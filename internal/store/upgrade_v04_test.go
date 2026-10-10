package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func migrationNames(t *testing.T) []string {
	ents, err := migrations.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	var n []string
	for _, e := range ents {
		n = append(n, e.Name())
	}
	sort.Strings(n)
	return n
}

func appliedNames(t *testing.T, db *sql.DB) []string {
	rows, err := db.Query(`SELECT name FROM schema_migrations ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		rows.Scan(&s)
		out = append(out, s)
	}
	return out
}

// v0.4 instx: every migration applies in order on a fresh database, and a
// re-open (idempotent re-run) changes nothing.
func TestV04AllMigrationsFresh(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fresh.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	got := appliedNames(t, s.DB)
	s.Close()
	want := migrationNames(t)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("applied %v want %v", got, want)
	}
	if len(want) < 21 || want[len(want)-1] < "0021" { // v1.1 adds 0022+
		t.Fatalf("expected migrations through 0021, have %v", want)
	}
	s2, err := Open(p)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	if n := len(appliedNames(t, s2.DB)); n != len(want) {
		t.Fatalf("re-open applied %d", n)
	}
	s2.Close()
}

// A database as v0.3 left it (0001-0004 applied, v0.3 bookkeeping) with data
// in it upgrades to v0.4 (0005-0021) without losing rows.
func TestV04UpgradeFromV03Schema(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v03.db")
	db, err := sql.Open("sqlite", "file:"+p+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, at INTEGER NOT NULL, checksum TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	var v03 []string
	for _, n := range migrationNames(t) {
		if n >= "0005" {
			break
		}
		b, _ := migrations.ReadFile("migrations/" + n)
		if _, err := db.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		sum := sha256.Sum256(b)
		if _, err := db.Exec(`INSERT INTO schema_migrations VALUES(?,?,?)`, n, time.Now().Unix(), hex.EncodeToString(sum[:])); err != nil {
			t.Fatal(err)
		}
		v03 = append(v03, n)
	}
	if len(v03) != 4 {
		t.Fatalf("v0.3 migrations: %v", v03)
	}
	if _, err := db.Exec(`INSERT INTO settings(key,value) VALUES('v03.marker','kept')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err := Open(p)
	if err != nil {
		t.Fatalf("upgrade v0.3 -> v0.4: %v", err)
	}
	defer s.Close()
	if got := s.Get("v03.marker", ""); got != "kept" {
		t.Fatalf("data lost: %q", got)
	}
	got := appliedNames(t, s.DB)
	if strings.Join(got, ",") != strings.Join(migrationNames(t), ",") {
		t.Fatalf("applied %v", got)
	}
}
