package fileops

import (
	"os"
	"path/filepath"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

func TestFileOps(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o600)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	must := func(op rpc.FileOp) rpc.FileResult {
		t.Helper()
		r, err := Exec(root, op)
		if err != nil {
			t.Fatalf("%s: %v", op.Op, err)
		}
		return r
	}
	must(rpc.FileOp{Op: "mkdir", Path: "public_html/a"})
	must(rpc.FileOp{Op: "write", Path: "public_html/index.php", Content: "<?php echo 1;"})
	if r := must(rpc.FileOp{Op: "read", Path: "public_html/index.php"}); r.Content != "<?php echo 1;" {
		t.Fatal("read mismatch")
	}
	must(rpc.FileOp{Op: "chmod", Path: "public_html/index.php", Mode: 0o600})
	must(rpc.FileOp{Op: "zip", Paths: []string{"public_html"}, Dest: "site.zip"})
	must(rpc.FileOp{Op: "unzip", Path: "site.zip", Dest: "restore"})
	if r := must(rpc.FileOp{Op: "read", Path: "restore/public_html/index.php"}); r.Content != "<?php echo 1;" {
		t.Fatal("unzip mismatch")
	}
	must(rpc.FileOp{Op: "copy", Path: "public_html/index.php", Dest: "public_html/a"})
	must(rpc.FileOp{Op: "rename", Path: "public_html/a/index.php", Dest: "public_html/a/x.php"})
	r := must(rpc.FileOp{Op: "list", Path: "public_html/a"})
	if len(r.Entries) != 1 || r.Entries[0].Name != "x.php" {
		t.Fatalf("list: %+v", r.Entries)
	}
	// escapes
	if _, err := Exec(root, rpc.FileOp{Op: "read", Path: "../" + filepath.Base(outside) + "/secret"}); err == nil {
		t.Fatal("dotdot escape allowed")
	}
	os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "link"))
	if _, err := Exec(root, rpc.FileOp{Op: "read", Path: "link"}); err == nil {
		t.Fatal("symlink escape allowed")
	}
	if _, err := Exec(root, rpc.FileOp{Op: "delete", Path: "/"}); err == nil {
		t.Fatal("deleting home allowed")
	}
	must(rpc.FileOp{Op: "delete", Paths: []string{"restore", "site.zip"}})
}
