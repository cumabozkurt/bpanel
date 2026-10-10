// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/xfer"
)

func xferEnv(t *testing.T) (src, dst string) {
	t.Helper()
	old, oldDir := passwdFile, xferDir
	t.Cleanup(func() { passwdFile, xferDir = old, oldDir })
	base := t.TempDir()
	xferDir = filepath.Join(base, "xfer")
	src, dst = filepath.Join(base, "home", "bob"), filepath.Join(base, "home", "bob2")
	for _, d := range []string{src, dst, filepath.Join(src, "public_html"), filepath.Join(src, ".ssh")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	uid, gid := os.Getuid(), os.Getgid()
	pw := filepath.Join(base, "passwd")
	line := func(n, h string) string {
		return n + ":x:" + strconv.Itoa(uid) + ":" + strconv.Itoa(gid) + "::" + h + ":/bin/bash\n"
	}
	os.WriteFile(pw, []byte(line("bob", src)+line("bob2", dst)), 0o644)
	passwdFile = pw
	os.WriteFile(filepath.Join(src, "public_html/index.php"), []byte("<?php echo 1;"), 0o644)
	os.WriteFile(filepath.Join(src, ".ssh/authorized_keys"), []byte("ssh-ed25519 AAAA"), 0o600)
	os.Symlink("public_html", filepath.Join(src, "www"))
	os.Symlink("/etc/passwd", filepath.Join(src, "escape"))
	return src, dst
}

func TestXferExportAnalyseRestoreHome(t *testing.T) {
	_, dst := xferEnv(t)
	a := &Agent{}
	ctx := context.Background()
	man, _ := json.Marshal(xfer.Manifest{Account: xfer.Account{Username: "bob", MainDomain: "bob.test"},
		Domains: []xfer.Domain{{Name: "bob.test", Kind: "main"}}, Zones: []xfer.Zone{{Domain: "bob.test", Member: "dnszones/bob.test.zone"}}})
	res, err := a.xferExport(ctx, rpc.XferExport{User: "bob", Archive: "bob-1.tar.gz", Manifest: man,
		Blobs: []rpc.XferBlob{{Name: "dnszones/bob.test.zone", Content: "www 300 IN A 192.0.2.1\n"}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 2 {
		t.Fatalf("files=%d (want index.php + zone; .ssh and the escaping link excluded)", res.Files)
	}
	if _, err := a.xferExport(ctx, rpc.XferExport{User: "bob", Archive: "x.tar.gz", Manifest: man, Blobs: []rpc.XferBlob{{Name: "../etc/x", Content: "x"}}}); err == nil {
		t.Fatal("blob outside allowed dirs accepted")
	}
	an, err := a.xferAnalyse(ctx, rpc.XferArchiveRef{Archive: "bob-1.tar.gz"})
	if err != nil {
		t.Fatal(err)
	}
	if an.Model.Format != xfer.FormatBPanel || an.Model.Account.Username != "bob" || len(an.Model.Zones) != 1 {
		t.Fatalf("model %+v", an.Model)
	}
	r, err := a.xferRestoreHome(ctx, rpc.XferRestoreHome{User: "bob2", Archive: "bob-1.tar.gz", Prefix: an.Model.HomePrefix()})
	if err != nil || r.Files != 1 {
		t.Fatalf("restore %+v %v", r, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "www/index.php")); string(b) != "<?php echo 1;" {
		t.Fatal("restored content/link wrong")
	}
	if _, err := os.Lstat(filepath.Join(dst, "escape")); err == nil {
		t.Fatal("escaping symlink restored")
	}
	if _, err := os.Lstat(filepath.Join(dst, ".ssh")); err == nil {
		t.Fatal(".ssh restored")
	}
	// name validation
	for _, n := range []string{"../x.tar.gz", "/etc/x.tar.gz", "a/b.tar.gz", "x.zip"} {
		var re *rpc.Error
		if _, err := a.xferAnalyse(ctx, rpc.XferArchiveRef{Archive: n}); !errors.As(err, &re) || re.Code != "xfer_invalid_archive" {
			t.Errorf("%s: %v", n, err)
		}
	}
	// symlinked archive refused
	os.Symlink("/etc/passwd", filepath.Join(xferDir, "link.tar.gz"))
	if _, err := a.xferAnalyse(ctx, rpc.XferArchiveRef{Archive: "link.tar.gz"}); err == nil {
		t.Fatal("symlinked archive accepted")
	}
	if _, err := a.xferRestoreDB(ctx, rpc.XferRestoreDB{Owner: "bob2", Archive: "bob-1.tar.gz", Member: "mysql/other_db.sql", DB: "other_db"}); err == nil {
		t.Fatal("foreign database accepted")
	}
	if _, err := a.xferRestoreHome(ctx, rpc.XferRestoreHome{User: "bob2", Archive: "bob-1.tar.gz", Prefix: "../homedir"}); err == nil {
		t.Fatal("bad prefix accepted")
	}
}

func TestXferFetchValidation(t *testing.T) {
	xferEnv(t)
	a := &Agent{}
	cases := []rpc.XferFetch{
		{Remote: xfer.Remote{Host: "127.0.0.1", User: "root", RemotePath: "/a.tar.gz", Auth: "key"}, Secret: "k", Archive: "a.tar.gz"},
		{Remote: xfer.Remote{Host: "169.254.169.254", User: "root", RemotePath: "/a.tar.gz", Auth: "key"}, Secret: "k", Archive: "a.tar.gz"},
		{Remote: xfer.Remote{Host: "h.example", User: "root", RemotePath: "/a.tar.gz;id", Auth: "key"}, Secret: "k", Archive: "a.tar.gz"},
		{Remote: xfer.Remote{Host: "203.0.113.9", User: "root", RemotePath: "/a.tar.gz", Auth: "key"}, Secret: "", Archive: "a.tar.gz"},
	}
	for i, c := range cases {
		if _, err := a.xferFetch(context.Background(), c); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
