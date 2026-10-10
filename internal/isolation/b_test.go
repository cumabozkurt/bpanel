// SPDX-License-Identifier: Apache-2.0

package isolation

import (
	"strings"
	"testing"
)

const fstabIn = "# /etc/fstab\nUUID=abc / ext4 errors=remount-ro 0 1\nproc /proc proc defaults 0 0\ntmpfs /tmp tmpfs defaults 0 0\n"

func TestRenderFstabIdempotent(t *testing.T) {
	out, ch, err := RenderFstab(fstabIn, 4100)
	if err != nil || !ch {
		t.Fatal(err, ch)
	}
	if err := ValidateFstab(out, 4100); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "#bpanel-replaced: proc /proc proc defaults 0 0") || !strings.Contains(out, "UUID=abc / ext4") {
		t.Fatal(out)
	}
	out2, ch2, _ := RenderFstab(out, 4100)
	if ch2 || out2 != out {
		t.Fatalf("not idempotent:\n%s\n---\n%s", out, out2)
	}
	out3, ch3, _ := RenderFstab(out, 4200) // gid changed
	if !ch3 || ValidateFstab(out3, 4200) != nil || strings.Count(out3, FstabMarker) != 1 {
		t.Fatal(out3)
	}
	if _, _, err := RenderFstab(fstabIn, 0); err == nil {
		t.Fatal("gid 0 accepted")
	}
	if ValidateFstab(fstabIn, 4100) == nil || ValidateFstab("a b\n", 1) == nil {
		t.Fatal("bad fstab validated")
	}
	empty, _, _ := RenderFstab("", 5)
	if ValidateFstab(empty, 5) != nil {
		t.Fatal(empty)
	}
}

func TestParseProcMount(t *testing.T) {
	mi := "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n" +
		"23 22 0:5 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw,gid=4100,hidepid=invisible\n"
	m := ParseProcMount(mi)
	if !m.Found || !m.Hidden() || m.GID != 4100 {
		t.Fatalf("%+v", m)
	}
	m = ParseProcMount("23 22 0:5 / /proc rw - proc proc rw\n")
	if !m.Found || m.Hidden() || m.GID != -1 {
		t.Fatalf("%+v", m)
	}
	if got := RemountProcArgv(7); strings.Join(got, " ") != "mount -o remount,hidepid=2,gid=7 /proc" {
		t.Fatal(got)
	}
}

func TestCronArgvAndCronD(t *testing.T) {
	a, err := CronCommandArgv("alice", 1001, 1001, "7", true, "/sys/fs/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	j := strings.Join(a, " ")
	for _, w := range []string{"--slice=bpanel-u-alice.slice", "--uid=1001", "--gid=1001", "-- /bin/sh /var/lib/bpanel/cron/alice/7.sh"} {
		if !strings.Contains(j, w) {
			t.Fatalf("%s missing %s", j, w)
		}
	}
	a, _ = CronCommandArgv("alice", 1001, 1001, "7", false, "/sys/fs/cgroup")
	if a[0] != CageExecBin || a[1] != "cage-exec" || !strings.Contains(strings.Join(a, " "), "--cgroup /sys/fs/cgroup/bpanel.slice/bpanel-u.slice/bpanel-u-alice.slice") {
		t.Fatal(a)
	}
	for _, bad := range []struct {
		u        string
		uid, gid int
		id       string
	}{{"root", 1001, 1001, "1"}, {"alice", 0, 1001, "1"}, {"alice", 1001, 1001, "1;rm"}, {"a;b", 1001, 1001, "1"}} {
		if _, err := CronCommandArgv(bad.u, bad.uid, bad.gid, bad.id, true, "/c"); err == nil && bad.u != "root" {
			t.Fatalf("accepted %+v", bad)
		}
	}
	jobs := []CronJob{{ID: "7", Schedule: "*/5 * * * *", Command: "php ~/artisan schedule:run; echo $(id) > /tmp/x"}}
	out, err := RenderCronD("alice", 1001, 1001, jobs, true, "/sys/fs/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "artisan") || !strings.Contains(out, "*/5 * * * * root /usr/bin/systemd-run") {
		t.Fatalf("user command leaked into cron.d or bad line:\n%s", out)
	}
	if s := RenderCronScript(jobs[0]); !strings.HasSuffix(s, jobs[0].Command+"\n") {
		t.Fatal(s)
	}
	for _, bj := range []CronJob{
		{ID: "1", Schedule: "* * * * * root", Command: "x"},
		{ID: "1", Schedule: "* * * *", Command: "x"},
		{ID: "1", Schedule: "@daily", Command: "x\n* * * * * root evil"},
		{ID: "1", Schedule: "* * * * $(x)", Command: "x"},
		{ID: "x", Schedule: "@daily", Command: "x"},
		{ID: "1", Schedule: "@daily", Command: " "},
	} {
		if _, err := RenderCronD("alice", 1001, 1001, []CronJob{bj}, true, "/c"); err == nil {
			t.Fatalf("accepted %+v", bj)
		}
	}
}

func TestRenderSSHJail(t *testing.T) {
	out, err := RenderSSHJail([]string{"bob", "alice", "bob"}, SSHModeCage)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, "Match User") != 2 || strings.Index(out, "alice") > strings.Index(out, "bob") ||
		!strings.Contains(out, "AllowTcpForwarding no") || !strings.Contains(out, "X11Forwarding no") ||
		!strings.Contains(out, "ForceCommand "+CageShellBin) || !strings.HasSuffix(out, "Match all\n") {
		t.Fatal(out)
	}
	out, _ = RenderSSHJail([]string{"alice"}, SSHModeSFTP)
	if !strings.Contains(out, "ChrootDirectory /var/lib/bpanel/jail/%u") || !strings.Contains(out, "ForceCommand internal-sftp") {
		t.Fatal(out)
	}
	if _, err := RenderSSHJail([]string{"alice\nMatch all"}, SSHModeCage); err == nil {
		t.Fatal("injection accepted")
	}
	if _, err := RenderSSHJail(nil, "shell"); err == nil {
		t.Fatal("bad mode accepted")
	}
	if s := RenderCageShell(); !strings.Contains(s, "exit 126") || !strings.Contains(s, "--bind \"$H\" \"$H\"") {
		t.Fatal(s)
	}
}

func TestParseCageArgs(t *testing.T) {
	ok := []string{"--cgroup", "/sys/fs/cgroup/bpanel.slice/bpanel-u.slice/bpanel-u-alice.slice", "--uid", "1001", "--gid", "1001", "--chdir", "/home/alice", "--", "/bin/sh", "/x.sh"}
	c, err := ParseCageArgs(ok, "/sys/fs/cgroup")
	if err != nil || c.UID != 1001 || len(c.Argv) != 2 {
		t.Fatal(c, err)
	}
	bad := [][]string{
		{"--cgroup", "/sys/fs/cgroup/bpanel.slice/bpanel-u.slice/bpanel-u-alice.slice", "--uid", "0", "--gid", "1001", "--", "/bin/sh"},
		{"--cgroup", "/sys/fs/cgroup/bpanel.slice/bpanel-u.slice/bpanel-u-alice.slice/../../x", "--uid", "1001", "--gid", "1001", "--", "/bin/sh"},
		{"--cgroup", "/sys/fs/cgroup/system.slice", "--uid", "1001", "--gid", "1001", "--", "/bin/sh"},
		{"--cgroup", "/sys/fs/cgroup/bpanel.slice/bpanel-u.slice/bpanel-u-alice.slice", "--uid", "1001", "--gid", "1001"},
		{"--evil", "x", "--", "/bin/sh"},
	}
	for _, b := range bad {
		if _, err := ParseCageArgs(b, "/sys/fs/cgroup"); err == nil {
			t.Fatalf("accepted %v", b)
		}
	}
}
