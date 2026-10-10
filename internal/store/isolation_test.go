// SPDX-License-Identifier: Apache-2.0

package store

import (
	"path/filepath"
	"testing"
)

func TestIsolationMigration(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	db := s.DB
	if _, err := db.Exec(`INSERT INTO limit_profiles(name, cpu_percent, mem_max_mb, tasks_max) VALUES('basic',100,512,64)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO limit_profiles(name, mem_max_mb) VALUES('bad',-1)`); err == nil {
		t.Error("negative limit accepted")
	}
	if _, err := db.Exec(`INSERT INTO users(username, role, password_hash, created_at) VALUES('alice','user','x',0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE users SET limit_profile_id=1, limit_overrides='{"mem_max_mb":1024}' WHERE username='alice'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE users SET limit_overrides='not json' WHERE username='alice'`); err == nil {
		t.Error("invalid json accepted")
	}
	var uid int64
	db.QueryRow(`SELECT id FROM users WHERE username='alice'`).Scan(&uid)
	if _, err := db.Exec(`INSERT INTO usage_samples(account_id, bucket_ts, cpu_usec, mem_bytes, io_r, io_w, pids, events) VALUES(?,60,1,2,3,4,5,'{"oom_kill":1}')`, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO usage_samples(account_id, bucket_ts) VALUES(?,60)`, uid); err == nil {
		t.Error("duplicate bucket accepted")
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='usage_samples_bucket'`).Scan(&n)
	if n != 1 {
		t.Error("index missing")
	}
}
