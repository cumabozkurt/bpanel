//go:build realstorage

package backup

// Real remote-storage tests for the restic engine (opt-in):
//
//	BPANEL_RESTIC=/path/restic BPANEL_RCLONE=/path/rclone \
//	  go test -tags realstorage -count=1 -v -run RealStorage ./internal/backup
//
// S3:   `rclone serve s3` (MIT, free) is a real S3-compatible HTTP server
//       (SigV4 auth). MinIO's community server binaries are no longer
//       distributed (dl.min.io answers 410 Gone), so rclone replaces it.
// SFTP: no sshd/ssh client exists in this sandbox, so restic's SFTP backend
//       is driven against a real SFTP server (`rclone serve sftp --stdio`)
//       through `-o sftp.command=...`. This exercises restic's SFTP protocol
//       and the Engine plumbing, NOT the SSH transport/host-key handling.
// Each test skips with a reason when a binary is missing.

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func findBin(t *testing.T, env string, names ...string) string {
	cands := append([]string{os.Getenv(env)}, names...)
	for _, p := range cands {
		if p == "" {
			continue
		}
		if _, err := exec.Command(p, "version").Output(); err == nil {
			return p
		}
	}
	t.Skipf("%s binary not found (set %s)", names[len(names)-1], env)
	return ""
}

func seedHome(t *testing.T, base string) (string, map[string][]byte) {
	home := filepath.Join(base, "home", "alice")
	files := map[string][]byte{
		"public_html/index.php":      []byte("<?php echo 'hi';"),
		"public_html/big.bin":        bytes.Repeat([]byte{1, 2, 3, 4, 5, 6, 7}, 400000),
		"db/shop.sql":                []byte("CREATE TABLE t(id int);\n"),
		"public_html/assets/app.css": bytes.Repeat([]byte("a{b:c}\n"), 3000),
	}
	for rel, b := range files {
		p := filepath.Join(home, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return home, files
}

func checkRestored(t *testing.T, root, home string, files map[string][]byte) {
	for rel, b := range files {
		got, err := os.ReadFile(filepath.Join(root, home, rel))
		if err != nil || !bytes.Equal(got, b) {
			t.Fatalf("restore mismatch %s: %v", rel, err)
		}
	}
}

func TestRealStorageS3(t *testing.T) {
	restic := findBin(t, "BPANEL_RESTIC", "/usr/local/lib/bpanel/bin/restic", "restic")
	rclone := findBin(t, "BPANEL_RCLONE", "rclone")
	base := t.TempDir()
	data := filepath.Join(base, "s3data")
	os.MkdirAll(filepath.Join(data, "bpanel-backups"), 0o700) // bucket = top-level dir
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	const ak, sk = "BPANELTESTKEY", "bpanel-test-secret-key-0123456789"
	srv := exec.Command(rclone, "serve", "s3", "--addr", "127.0.0.1:"+strconv.Itoa(port), "--auth-key", ak+","+sk,
		"--config", "/dev/null", data)
	var slog bytes.Buffer
	srv.Stdout, srv.Stderr = &slog, &slog
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Process.Kill(); srv.Wait() })
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port)); err == nil {
			c.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	home, files := seedHome(t, base)
	tgt := Target{Kind: KindS3, Endpoint: "http://127.0.0.1:" + strconv.Itoa(port), Bucket: "bpanel-backups", Path: "node1", Region: "us-east-1"}
	if err := tgt.Validate(); err != nil {
		t.Fatal(err)
	}
	e := &Engine{Bin: restic, Target: tgt, Creds: Creds{S3AccessKey: ak, S3SecretKey: sk}, Password: "repo-pass-alice-123",
		CacheDir: filepath.Join(base, "cache"), ManifestDir: filepath.Join(base, "man"), SecretUID: os.Getuid(), Timeout: 5 * time.Minute}
	ctx := t.Context()
	id, m, err := e.BackupDir(ctx, "alice", home, nil)
	if err != nil {
		t.Fatalf("s3 backup: %v\nserver log:\n%s", err, slog.String())
	}
	t.Logf("s3 backup ok: snapshot=%s files=%d", id[:8], len(m.Files))
	// a second backup is deduplicated
	if _, _, err := e.BackupDir(ctx, "alice", home, nil); err != nil {
		t.Fatal(err)
	}
	snaps, err := e.Snapshots(ctx, "alice", "files")
	if err != nil || len(snaps) != 2 {
		t.Fatalf("snapshots: %d %v", len(snaps), err)
	}
	r := filepath.Join(base, "restore")
	if err := e.Restore(ctx, "alice", id, "", r); err != nil {
		t.Fatal(err)
	}
	checkRestored(t, r, home, files)
	if err := e.Check(ctx, "alice", "100%"); err != nil {
		t.Fatal("check:", err)
	}
	// objects really landed in the bucket under <prefix>/<account>
	if _, err := os.Stat(filepath.Join(data, "bpanel-backups", "node1", "alice", "config")); err != nil {
		t.Fatalf("repo not in bucket: %v", err)
	}
	// wrong secret key: fails and the error never contains the key
	bad := *e
	bad.Creds = Creds{S3AccessKey: ak, S3SecretKey: "WRONG-secret-key-abcdef"}
	_, err = bad.Snapshots(ctx, "alice", "files")
	if err == nil {
		t.Fatal("wrong S3 secret accepted")
	}
	if strings.Contains(err.Error(), "WRONG-secret-key-abcdef") || strings.Contains(err.Error(), sk) {
		t.Fatalf("secret leaked in error: %v", err)
	}
	t.Logf("s3 (rclone serve s3): backup x2, snapshots=2, full restore identical, check 100%% ok, bad-key rejected without leak")
}

func TestRealStorageSFTP(t *testing.T) {
	restic := findBin(t, "BPANEL_RESTIC", "/usr/local/lib/bpanel/bin/restic", "restic")
	rclone := findBin(t, "BPANEL_RCLONE", "rclone")
	base := t.TempDir()
	remote := filepath.Join(base, "sftproot")
	os.MkdirAll(remote, 0o700)
	home, files := seedHome(t, base)
	tgt := Target{Kind: KindSFTP, Host: "backup.example.net", User: "bpbackup", Port: 2222, Path: "/srv/restic"}
	repo, err := tgt.RepoURL("alice")
	if err != nil || repo != "sftp://bpbackup@backup.example.net:2222//srv/restic/alice" {
		t.Fatalf("repo url %q %v", repo, err)
	}
	// rclone's SFTP root is `remote`, so the repo path /srv/restic/alice lands
	// at remote/srv/restic/alice.
	sftpCmd := "sftp.command=" + rclone + " serve sftp --stdio --config /dev/null " + remote
	e := &Engine{Bin: restic, Target: tgt, Password: "repo-pass-sftp-123",
		CacheDir: filepath.Join(base, "cache"), ManifestDir: filepath.Join(base, "man"), SecretUID: os.Getuid(), Timeout: 5 * time.Minute}
	ctx := t.Context()
	run := func(args ...string) string {
		t.Helper()
		out, err := e.Run(ctx, "alice", append([]string{"-o", sftpCmd}, args...)...)
		if err != nil {
			t.Fatalf("restic %v: %v\n%s", args, err, out)
		}
		return out
	}
	run("init")
	run("backup", "--tag", "files", home)
	run("backup", "--tag", "files", home)
	out := run("snapshots", "--json")
	if strings.Count(out, `"short_id"`) != 2 {
		t.Fatalf("want 2 snapshots: %s", out)
	}
	r := filepath.Join(base, "restore")
	run("restore", "latest", "--target", r)
	checkRestored(t, r, home, files)
	run("check", "--read-data")
	if _, err := os.Stat(filepath.Join(remote, "srv", "restic", "alice", "config")); err != nil {
		t.Fatalf("repo not on sftp server: %v", err)
	}
	t.Logf("sftp (rclone serve sftp --stdio): init, backup x2, snapshots=2, restore identical, check --read-data ok; SSH transport not exercised")
}
