// SPDX-License-Identifier: Apache-2.0

package agent

import "testing"

// v0.3: Dovecot 2.4 reads the mailbox quota from userdb_quota_storage_size.
func TestR3DovecotQuotaSyntax(t *testing.T) {
	for v, want := range map[string]bool{"2.3": false, "2.3.21 (47349e2482)": false, "2.4": true, "2.4.1 (7cd4f5e9a4)": true, "3.0.0": true, "": false, "junk": false} {
		if got := dovecotIs24(v); got != want {
			t.Errorf("dovecotIs24(%q) = %v", v, got)
		}
	}
	if got := quotaKV(100, false); got != "userdb_quota_rule=*:storage=100M" {
		t.Errorf("2.3: %q", got)
	}
	if got := quotaKV(100, true); got != "userdb_quota_storage_size=100M" {
		t.Errorf("2.4: %q", got)
	}
	if got := quotaKV(0, true); got != "" {
		t.Errorf("unlimited: %q", got)
	}
	// switching syntax replaces the other form instead of keeping both
	if got := setQuotaExtra("userdb_quota_rule=*:storage=50M foo=bar", 200, true); got != "foo=bar userdb_quota_storage_size=200M" {
		t.Errorf("2.3->2.4: %q", got)
	}
	if got := setQuotaExtra("userdb_quota_storage_size=50M", 70, false); got != "userdb_quota_rule=*:storage=70M" {
		t.Errorf("2.4->2.3: %q", got)
	}
	a := &Agent{Cfg: Config{DovecotSyntax: "2.4"}}
	if !a.dovecotV24() {
		t.Error("Cfg.DovecotSyntax=2.4 not honoured")
	}
	if line := passwdLine("{X}h", passwdEntry{uid: 1, gid: 2}, "/h", 10, true); line != "{X}h:1:2::/h::userdb_quota_storage_size=10M" {
		t.Errorf("passwdLine 2.4: %q", line)
	}
}

// v0.3 (R2-SYS-15): a local DB user also exists as 'u'@'127.0.0.1' and 'u'@'::1'.
func TestR3DBHosts(t *testing.T) {
	for in, want := range map[string]int{"": 3, "localhost": 3, "10.0.0.5": 1, "%": 1} {
		hs, err := dbHosts(in)
		if err != nil || len(hs) != want {
			t.Errorf("dbHosts(%q) = %v %v", in, hs, err)
		}
	}
	if hs, _ := dbHosts(""); hs[0] != "localhost" || hs[1] != "127.0.0.1" || hs[2] != "::1" {
		t.Errorf("order %v", hs)
	}
	if _, err := dbHosts("a'b"); err == nil {
		t.Error("quote accepted")
	}
}
