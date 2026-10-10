package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepoURL(t *testing.T) {
	cases := []struct {
		t    Target
		want string
	}{
		{Target{Kind: KindLocal, Path: "/var/backups/bpanel"}, "/var/backups/bpanel/alice"},
		{Target{Kind: KindSFTP, Host: "bk.example.com", User: "bpanel", Path: "/srv/restic"}, "sftp:bpanel@bk.example.com:/srv/restic/alice"},
		{Target{Kind: KindSFTP, Host: "bk.example.com", User: "bpanel", Port: 2222, Path: "/srv/restic"}, "sftp://bpanel@bk.example.com:2222//srv/restic/alice"},
		{Target{Kind: KindS3, Endpoint: "https://s3.eu.example.com", Bucket: "bp-backups", Path: "host1"}, "s3:https://s3.eu.example.com/bp-backups/host1/alice"},
		{Target{Kind: KindS3, Endpoint: "http://127.0.0.1:9000", Bucket: "bpb"}, "s3:http://127.0.0.1:9000/bpb/alice"},
	}
	for _, c := range cases {
		got, err := c.t.RepoURL("alice")
		if err != nil || got != c.want {
			t.Errorf("%+v: got %q %v want %q", c.t, got, err, c.want)
		}
	}
	bad := []Target{
		{Kind: KindLocal, Path: "relative"},
		{Kind: KindLocal, Path: "/a/../b;rm"},
		{Kind: KindSFTP, Host: "-oProxyCommand=x", Path: "/x"},
		{Kind: KindS3, Endpoint: "https://k:s@h", Bucket: "bucket"},
		{Kind: KindS3, Endpoint: "ftp://h", Bucket: "bucket"},
		{Kind: KindS3, Endpoint: "https://h", Bucket: "B"},
		{Kind: "nfs", Path: "/x"},
	}
	for _, b := range bad {
		if _, err := b.RepoURL("alice"); err == nil {
			t.Errorf("accepted %+v", b)
		}
	}
	if _, err := (Target{Kind: KindLocal, Path: "/x"}).RepoURL("../etc"); err == nil {
		t.Error("accepted bad account")
	}
}

func TestS3CredsOnlyInEnv(t *testing.T) {
	tg := Target{Kind: KindS3, Endpoint: "https://s3.example.com", Bucket: "bpb", Region: "eu-1"}
	c := Creds{S3AccessKey: "AKIAEXAMPLEKEY", S3SecretKey: "superSecretValue123"}
	url, _ := tg.RepoURL("alice")
	if strings.Contains(url, c.S3AccessKey) || strings.Contains(url, c.S3SecretKey) {
		t.Fatal("credentials in repo url")
	}
	env := strings.Join(tg.Env(c), "\n")
	if !strings.Contains(env, "AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEY") || !strings.Contains(env, "AWS_SECRET_ACCESS_KEY=superSecretValue123") {
		t.Fatal(env)
	}
	e := &Engine{Creds: c}
	if s := e.scrub("fail AKIAEXAMPLEKEY superSecretValue123"); strings.Contains(s, "superSecret") || strings.Contains(s, "AKIA") {
		t.Fatal(s)
	}
}

func TestRetention(t *testing.T) {
	a, err := DefaultRetention.ForgetArgs()
	if err != nil || strings.Join(a, " ") != "forget --prune --group-by host,paths --keep-daily 7 --keep-weekly 4 --keep-monthly 6" {
		t.Fatal(a, err)
	}
	if _, err := (Retention{}).ForgetArgs(); err == nil {
		t.Fatal("empty policy accepted")
	}
	if _, err := (Retention{Daily: -1}).ForgetArgs(); err == nil {
		t.Fatal("negative accepted")
	}
}

func TestSecretFilePerms(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "repo.pass")
	uid := os.Getuid()
	if err := EnsurePasswordFile(p, uid); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatal(fi.Mode())
	}
	os.Chmod(p, 0o640)
	if err := CheckSecretFile(p, uid); err != ErrInsecureSecret {
		t.Fatal("group-readable accepted", err)
	}
	os.Chmod(p, 0o600)
	if err := CheckSecretFile(p, uid+1); err != ErrInsecureSecret {
		t.Fatal("wrong owner accepted", err)
	}
	e := &Engine{Bin: "/bin/true", Target: Target{Kind: KindLocal, Path: d}, PasswordFile: p, SecretUID: uid}
	if _, err := e.Run(t.Context(), "alice", "check", "--no-lock"); err == nil {
		t.Fatal("--no-lock accepted")
	}
}

func TestManifestAndSample(t *testing.T) {
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, "a", "skip"), 0o755)
	os.WriteFile(filepath.Join(d, "a", "x.txt"), []byte("hello"), 0o644)
	os.WriteFile(filepath.Join(d, "a", "skip", "y"), []byte("no"), 0o644)
	os.Symlink("/etc/passwd", filepath.Join(d, "link"))
	m, err := BuildManifest(d, []string{filepath.Join(d, "a", "skip")})
	if err != nil || len(m.Files) != 1 || m.Files["a/x.txt"].SHA256 != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatal(m.Files, err)
	}
	os.WriteFile(filepath.Join(d, "a", "x.txt"), []byte("hello world"), 0o644)
	m.DropChanged()
	if len(m.Files) != 0 {
		t.Fatal("changed file kept")
	}
	keys := make([]string, 1000)
	for i := range keys {
		keys[i] = string(rune('a'+i%26)) + strings.Repeat("x", i%7)
	}
	if got := sample(keys, 500, 100); len(got) != 100 {
		t.Fatal(len(got))
	}
	if got := sample(keys[:10], 500, 100); len(got) != 10 {
		t.Fatal(len(got))
	}
}
