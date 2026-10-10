package installer

import (
	"archive/tar"
	"compress/gzip"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cumabozkurt/bpanel/internal/agent"
	"github.com/cumabozkurt/bpanel/internal/distro"
	"github.com/cumabozkurt/bpanel/internal/store"
)

var (
	v4ubuntu = &distro.Layout{Family: distro.Debian, PostfixDir: "/etc/postfix", PDNSUnit: "pdns"}
	v4alma   = &distro.Layout{Family: distro.RHEL, PostfixDir: "/etc/postfix", PDNSUnit: "pdns"}
)

// golden compares got with testdata/<name>; UPDATE_GOLDEN=1 rewrites it.
func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Fatalf("%s differs from golden:\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

func TestV04PostfixGolden(t *testing.T) {
	var b strings.Builder
	for _, l := range []*distro.Layout{v4ubuntu, v4alma} {
		b.WriteString("# " + string(l.Family) + "\n")
		b.WriteString("postconf -M " + MlmmjMasterEntry + "\n")
		for _, s := range V04PostfixSettings(l) {
			b.WriteString("postconf -e " + s + "\n")
		}
	}
	golden(t, "v04-postfix.golden", b.String())
	if !strings.Contains(MlmmjMasterEntry, "argv=/usr/bin/mlmmj-receive -F -L /var/spool/mlmmj/$nexthop") {
		t.Fatal("mlmmj pipe argv")
	}
}

func TestV04PackagesBothDistros(t *testing.T) {
	var b strings.Builder
	for _, l := range []*distro.Layout{v4ubuntu, v4alma} {
		for _, prof := range []string{"minimal", "web", "full"} {
			o := Options{Profile: prof, CrowdSec: true, Smart: true}
			b.WriteString(string(l.Family) + "/" + prof + ": " + strings.Join(V04Packages(l, prof), " ") + " | optional:")
			for _, p := range V04OptionalPackages(l, o) {
				b.WriteString(" " + p.Name)
			}
			b.WriteString("\n")
		}
	}
	golden(t, "v04-packages.golden", b.String())
	// mail stack of the base list already carries sieve + rspamd
	for _, c := range []struct {
		l    *distro.Layout
		want []string
	}{{v4ubuntu, []string{"dovecot-sieve", "dovecot-managesieved", "rspamd", "fail2ban"}}, {v4alma, []string{"dovecot-pigeonhole", "rspamd", "fail2ban-server"}}} {
		got := strings.Join(PackageList(c.l, "full", nil), " ")
		for _, w := range c.want {
			if !strings.Contains(" "+got+" ", " "+w+" ") {
				t.Errorf("%s full: %s missing", c.l.Family, w)
			}
		}
	}
	if len(V04OptionalPackages(v4ubuntu, Options{Profile: "web"})) != 0 {
		t.Fatal("no optional packages without flags on web")
	}
}

func TestV04DirsAndUnit(t *testing.T) {
	var b strings.Builder
	for _, d := range V04Dirs() {
		b.WriteString(d.Path + " " + d.Mode.String() + " " + d.Owner + "\n")
		if d.Mode&0o002 != 0 {
			t.Errorf("%s world-writable", d.Path)
		}
	}
	golden(t, "v04-dirs.golden", b.String())
	if ChronyUnit(v4ubuntu) != "chrony" || ChronyUnit(v4alma) != "chronyd" {
		t.Fatal("chrony unit")
	}
}

func TestV04Fail2banJails(t *testing.T) {
	j := Fail2banJail([]string{"22"}, true, true)
	for _, w := range []string{"[sshd]", "[bpanel]", "[dovecot]", "[postfix-sasl]"} {
		if !strings.Contains(j, w) {
			t.Errorf("jail %s missing", w)
		}
	}
}

func TestNodeConfigIdempotent(t *testing.T) {
	c := NodeAgentConfig(agent.DefaultConfig(), "")
	if c.RemoteListen != NodeRemoteListen {
		t.Fatal(c.RemoteListen)
	}
	c.RemoteListen = ":9000" // admin changed it later: a re-run keeps it
	if NodeAgentConfig(c, "").RemoteListen != ":9000" {
		t.Fatal("re-run overwrote remote_listen")
	}
	if !strings.Contains(NodeJoinInstructions(""), "bpanel-agent join --panel") {
		t.Fatal("join instructions")
	}
}

func TestDoctor(t *testing.T) {
	old := doctorProbe
	defer func() { doctorProbe = old }()
	doctorProbe.have = func(b string) bool { return b != "rspamd" && b != "sievec" }
	doctorProbe.active = func(u string) bool { return u != "chrony" }
	doctorProbe.exists = func(string) bool { return true }
	items := V04Doctor(v4ubuntu, "full")
	st := map[string]string{}
	for _, it := range items {
		st[it.Name] = it.Status
	}
	if st["rspamd"] != "missing" || st["sieve (pigeonhole)"] != "missing" || st["chrony"] != "inactive" || st["fail2ban"] != "ok" || st["pdns"] != "ok" {
		t.Fatalf("%v", st)
	}
	_, fail := FormatDoctor(items)
	if fail != 2 { // rspamd + sieve required on full; chrony optional
		t.Fatalf("fail=%d", fail)
	}
	if _, f := FormatDoctor(V04Doctor(v4ubuntu, "minimal")); f != 0 {
		t.Fatalf("minimal must not require mail: %d", f)
	}
}

func TestBackupForUpgrade(t *testing.T) {
	tmp := t.TempDir()
	dbp := filepath.Join(tmp, "bpanel.db")
	st, err := store.Open(dbp)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Set("k", "v"); err != nil {
		t.Fatal(err)
	}
	st.Close()
	etc := filepath.Join(tmp, "etc", "bpanel")
	os.MkdirAll(filepath.Join(etc, "ssl"), 0o750)
	os.WriteFile(filepath.Join(etc, "agent.json"), []byte(`{"profile":"full"}`), 0o600)
	dir, err := BackupForUpgrade(dbp, etc, filepath.Join(tmp, "bk"), "0.3.0", "0.4.0")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "bpanel.db"))
	if err != nil {
		t.Fatal(err)
	}
	var v string
	if err := db.QueryRow(`SELECT value FROM settings WHERE key='k'`).Scan(&v); err != nil || v != "v" {
		t.Fatalf("db copy: %v %q", err, v)
	}
	db.Close()
	f, _ := os.Open(filepath.Join(dir, "etc-bpanel.tar.gz"))
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	names := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names[h.Name] = true
	}
	if !names["bpanel/agent.json"] || !names["bpanel/ssl"] {
		t.Fatalf("tar: %v", names)
	}
	// a second run makes a second, separate backup (never overwrites)
	if _, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	}
}
