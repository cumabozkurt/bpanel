package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A suspended account's mailboxes must stop authenticating (IMAP, POP3 and
// SMTP AUTH all use the Dovecot passwd-file), other accounts must not be
// touched, and unsuspending must restore the original hash byte for byte.
func TestMailLockOnSuspend(t *testing.T) {
	e := newTestEnv(t)
	pw := e.a.dovecotPasswd()
	if err := os.MkdirAll(filepath.Dir(pw), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := "a@t.test:{SHA512-CRYPT}$6$salt$hashA:1500:1500::/h/a::userdb_quota_rule=*:storage=10M\n" +
		"b@t.test:{SHA512-CRYPT}$6$salt$hashB:1500:1500::/h/b::\n" +
		"c@o.test:{SHA512-CRYPT}$6$salt$hashC:1600:1600::/h/c::\n"
	if err := os.WriteFile(pw, []byte(orig), 0o640); err != nil {
		t.Fatal(err)
	}
	if e.a.mailLocked(1500) {
		t.Fatal("locked before suspend")
	}
	for i := 0; i < 2; i++ { // idempotent
		if err := e.a.setMailLock(1500, true); err != nil {
			t.Fatal(err)
		}
	}
	m, _ := readMap(pw, ":")
	got := map[string]string{}
	for _, kv := range m {
		got[kv[0]] = kv[1]
	}
	for _, k := range []string{"a@t.test", "b@t.test"} {
		if !strings.HasPrefix(got[k], mailLockPrefix+"{SHA512-CRYPT}$6$salt$hash") || strings.Count(got[k], mailLockPrefix) != 1 {
			t.Errorf("%s not locked once: %q", k, got[k])
		}
	}
	if strings.HasPrefix(got["c@o.test"], mailLockPrefix) {
		t.Errorf("other account locked: %q", got["c@o.test"])
	}
	if !strings.HasSuffix(got["a@t.test"], "::userdb_quota_rule=*:storage=10M") {
		t.Errorf("extra field damaged: %q", got["a@t.test"])
	}
	if !e.a.mailLocked(1500) || e.a.mailLocked(1600) {
		t.Error("mailLocked wrong")
	}
	if err := e.a.setMailLock(1500, false); err != nil {
		t.Fatal(err)
	}
	m2, _ := readMap(pw, ":")
	for _, kv := range m2 {
		if !strings.Contains(orig, kv[0]+":"+kv[1]+"\n") {
			t.Errorf("unlock did not restore %s: %q", kv[0], kv[1])
		}
	}
	if e.a.mailLocked(1500) {
		t.Error("still locked after unsuspend")
	}
}

// No passwd-file yet (no mailboxes): suspending must not create one.
func TestMailLockNoPasswdFile(t *testing.T) {
	e := newTestEnv(t)
	if err := e.a.setMailLock(1500, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(e.a.dovecotPasswd()); !os.IsNotExist(err) {
		t.Errorf("passwd-file created: %v", err)
	}
}
