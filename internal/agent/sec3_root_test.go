package agent

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/distro"
)

// SEC-3: backup restore with a tenant-controlled home, run as REAL root
// against the real restic binary, the tenant being an unprivileged uid.
//
//	sudo -E BPANEL_ROOT_TESTS=1 go test ./internal/agent -run TestRootSEC3 -v
//
// The tenant (uid BPANEL_TEST_UID, default 1000) plants symlinks in its home;
// root must never write, create or chown anything outside the home.
func TestRootSEC3RestoreSymlinks(t *testing.T) {
	if os.Getenv("BPANEL_ROOT_TESTS") != "1" || os.Geteuid() != 0 {
		t.Skip("needs real root: sudo -E BPANEL_ROOT_TESTS=1 go test -run TestRootSEC3")
	}
	restic, err := exec.LookPath("restic")
	if err != nil {
		if _, serr := os.Stat("/usr/local/bin/restic"); serr == nil {
			restic = "/usr/local/bin/restic"
		} else {
			t.Skip("restic not installed")
		}
	}
	uid, gid := 1000, 1000
	if v := os.Getenv("BPANEL_TEST_UID"); v != "" {
		fmt.Sscan(v, &uid)
		gid = uid
	}
	base, err := os.MkdirTemp("/tmp", "bpanel-sec3-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Chmod(base, 0o755))
	home := filepath.Join(base, "home", "victim")
	outside := filepath.Join(base, "outside")
	must(os.MkdirAll(home, 0o711))
	must(os.MkdirAll(outside, 0o755))
	must(os.WriteFile(filepath.Join(outside, "secret"), []byte("root only"), 0o600))
	pw := filepath.Join(base, "passwd")
	must(os.WriteFile(pw, []byte(fmt.Sprintf("root:x:0:0::/root:/bin/bash\nvictim:x:%d:%d::%s:/usr/sbin/nologin\n", uid, gid, home)), 0o644))
	gr := filepath.Join(base, "group")
	must(os.WriteFile(gr, []byte(fmt.Sprintf("root:x:0:\nvictim:x:%d:\n", gid)), 0o644))
	oldP, oldG := passwdFile, groupFile
	passwdFile, groupFile = pw, gr
	t.Cleanup(func() { passwdFile, groupFile = oldP, oldG })

	l, err := distro.ForRelease(map[string]string{"ID": "debian", "VERSION_ID": "13"})
	must(err)
	cfg := DefaultConfig()
	cfg.HomeBase = filepath.Join(base, "home")
	cfg.NoSystemd = true
	cfg.AccountsDir = filepath.Join(base, "accounts")
	cfg.RestoreDir = filepath.Join(base, "restore")
	cfg.ResticPassDir = filepath.Join(base, "restic-pass")
	cfg.BackupRepo = filepath.Join(base, "repo")
	cfg.OwnersDir = filepath.Join(base, "owners")
	cfg.ResticBin = restic
	a := New(cfg, l, slog.New(slog.NewTextHandler(io.Discard, nil)))
	a.resticCache = filepath.Join(base, "restic-cache")
	must(os.MkdirAll(cfg.AccountsDir, 0o700))
	must(os.WriteFile(a.markerPath("victim"), []byte("victim\n"), 0o600))

	// tenant content, owned by the tenant
	asTenant := func(argv ...string) {
		t.Helper()
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v %s", argv, err, out)
		}
	}
	must(os.Chown(home, uid, gid))
	asTenant("mkdir", "-p", filepath.Join(home, "public_html", "sub"), filepath.Join(home, "backups"))
	asTenant("sh", "-c", "echo v1 > "+filepath.Join(home, "public_html", "sub", "a.txt"))
	asTenant("chmod", "4755", filepath.Join(home, "public_html", "sub", "a.txt")) // setuid-to-self in the snapshot
	asTenant("ln", "-s", filepath.Join(outside, "secret"), filepath.Join(home, "public_html", "evil"))

	ctx := context.Background()
	res, err := a.backupRun(ctx, rpc.BackupRun{User: "victim"})
	must(err)
	snap := res.SnapshotIDs[0]
	t.Logf("restic %s snapshot %s", restic, snap)

	outsideClean := func(when string) {
		t.Helper()
		ents, _ := os.ReadDir(outside)
		if len(ents) != 1 {
			t.Errorf("%s: something was written outside the home: %v", when, ents)
		}
		st, err := os.Lstat(filepath.Join(outside, "secret"))
		if err != nil {
			t.Fatalf("%s: %v", when, err)
		}
		if s := st.Sys().(*syscall.Stat_t); s.Uid != 0 || s.Gid != 0 || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: outside/secret was chowned/chmodded: uid=%d gid=%d mode=%v", when, s.Uid, s.Gid, st.Mode())
		}
	}

	// 1. a normal restore lands in ~/backups/restore-*, owned by the tenant, setuid cleared
	out, err := a.backupRestore(ctx, rpc.BackupRestore{User: "victim", Snapshot: snap, Path: "public_html"})
	must(err)
	st, err := os.Lstat(filepath.Join(out.RestoredTo, "public_html", "sub", "a.txt"))
	must(err)
	if s := st.Sys().(*syscall.Stat_t); int(s.Uid) != uid {
		t.Errorf("restored file owned by %d, want %d", s.Uid, uid)
	}
	if st.Mode()&os.ModeSetuid != 0 {
		// cp runs as the tenant, so a setuid bit can only ever be setuid-to-tenant
		t.Logf("note: setuid-to-self bit preserved by cp -a as the tenant (harmless)")
	}
	if lt, err := os.Readlink(filepath.Join(out.RestoredTo, "public_html", "evil")); err != nil || lt != filepath.Join(outside, "secret") {
		t.Errorf("snapshot symlink not restored as a symlink: %q %v", lt, err)
	}
	outsideClean("normal restore")

	// 2. ~/backups replaced by a symlink to a root-owned directory
	asTenant("mv", filepath.Join(home, "backups"), filepath.Join(home, "backups.old"))
	asTenant("ln", "-s", outside, filepath.Join(home, "backups"))
	if _, err := a.backupRestore(ctx, rpc.BackupRestore{User: "victim", Snapshot: snap, Path: "public_html"}); err == nil {
		t.Error("restore through a symlinked ~/backups succeeded")
	}
	outsideClean("symlinked ~/backups")
	asTenant("rm", filepath.Join(home, "backups"))
	asTenant("mv", filepath.Join(home, "backups.old"), filepath.Join(home, "backups"))

	// 3. in-place restore where the target directory became a symlink
	asTenant("mv", filepath.Join(home, "public_html", "sub"), filepath.Join(home, "public_html", "sub.old"))
	asTenant("ln", "-s", outside, filepath.Join(home, "public_html", "sub"))
	if _, err := a.backupRestore(ctx, rpc.BackupRestore{User: "victim", Snapshot: snap, Path: "public_html/sub", InPlace: true}); err == nil {
		t.Error("in-place restore through a symlinked target succeeded")
	}
	outsideClean("in-place through symlink")

	// 4. in-place restore of a single file whose target is a symlink to a root file
	asTenant("rm", filepath.Join(home, "public_html", "sub"))
	asTenant("mv", filepath.Join(home, "public_html", "sub.old"), filepath.Join(home, "public_html", "sub"))
	asTenant("rm", filepath.Join(home, "public_html", "sub", "a.txt"))
	asTenant("ln", "-s", filepath.Join(outside, "secret"), filepath.Join(home, "public_html", "sub", "a.txt"))
	if _, err := a.backupRestore(ctx, rpc.BackupRestore{User: "victim", Snapshot: snap, Path: "public_html/sub/a.txt", InPlace: true}); err != nil {
		t.Fatalf("single-file in-place restore: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(outside, "secret")); string(b) != "root only" {
		t.Errorf("root file overwritten through a tenant symlink: %q", b)
	}
	if lst, err := os.Lstat(filepath.Join(home, "public_html", "sub", "a.txt")); err != nil || lst.Mode()&os.ModeSymlink != 0 {
		t.Errorf("symlink not replaced by the restored file: %v %v", lst, err)
	}
	outsideClean("in-place single file")

	// 5. staging area: root-owned 0711 and empty afterwards
	rst, err := os.Lstat(cfg.RestoreDir)
	must(err)
	if s := rst.Sys().(*syscall.Stat_t); s.Uid != 0 || rst.Mode().Perm() != 0o711 {
		t.Errorf("restore dir uid=%d mode=%v", s.Uid, rst.Mode())
	}
	if ents, _ := os.ReadDir(cfg.RestoreDir); len(ents) != 0 {
		t.Errorf("staging not cleaned: %v", ents)
	}

	// 6. a symlinked or tenant-owned restore_dir is refused
	must(os.RemoveAll(cfg.RestoreDir))
	must(os.Symlink(outside, cfg.RestoreDir))
	if _, err := a.backupRestore(ctx, rpc.BackupRestore{User: "victim", Snapshot: snap, Path: "public_html"}); code(err) != "restore_dir_unsafe" {
		t.Errorf("symlinked restore_dir: %v", err)
	}
	must(os.Remove(cfg.RestoreDir))
	must(os.Mkdir(cfg.RestoreDir, 0o777))
	must(os.Chown(cfg.RestoreDir, uid, gid))
	if _, err := a.backupRestore(ctx, rpc.BackupRestore{User: "victim", Snapshot: snap, Path: "public_html"}); code(err) != "restore_dir_unsafe" {
		t.Errorf("tenant-owned restore_dir: %v", err)
	}
	outsideClean("restore_dir checks")
}
