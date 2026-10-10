package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// handoff-installer H-10: root's mail follows the contact email; no injection.
func TestMailRootAlias(t *testing.T) {
	e := newTestEnv(t)
	old := AliasesFile
	AliasesFile = filepath.Join(e.base, "aliases")
	t.Cleanup(func() { AliasesFile = old })
	if err := os.WriteFile(AliasesFile, []byte("mailer-daemon: postmaster\nroot: old@example.org\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"a@b.test\nevil: |/bin/sh", "x@y.test:z", "|/bin/sh@x.test", "a b@c.test", ""} {
		if _, err := e.a.mailRootAlias(context.Background(), rpc.RootAlias{Email: bad}); code(err) != "invalid_email" {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := e.a.mailRootAlias(context.Background(), rpc.RootAlias{Email: "admin@example.com"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(AliasesFile)
	s := string(b)
	if strings.Count(s, "root:") != 1 || !strings.Contains(s, "root: admin@example.com") || !strings.Contains(s, "postmaster: root") || !strings.Contains(s, "mailer-daemon: postmaster") {
		t.Fatalf("aliases:\n%s", s)
	}
}
