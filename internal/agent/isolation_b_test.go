// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// fakeSSHD installs an sshd that fails when the jail file contains marker.
func fakeSSHD(t *testing.T, conf string, fail bool) {
	dir := t.TempDir()
	code := "0"
	if fail {
		code = "1"
	}
	script := "#!/bin/sh\n[ \"$1\" = -t ] || exit 2\ngrep -q 'Match User' " + conf + " || exit 3\nexit " + code + "\n"
	bin := filepath.Join(dir, "sshd")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	old := sshdBin
	sshdBin = bin
	t.Cleanup(func() { sshdBin = old })
}

func TestIsolationSSHApplyValidateRollback(t *testing.T) {
	e, _, _ := isoEnv(t)
	conf := filepath.Join(t.TempDir(), "60-bpanel-jail.conf")
	old := sshJailConf
	sshJailConf = conf
	t.Cleanup(func() { sshJailConf = old })

	fakeSSHD(t, conf, false)
	out, err := callIso(t, e, rpc.MIsolationSSHApply, rpc.IsolationSSHApply{Users: []string{"tenant"}, Mode: "cage"})
	if err != nil || out.(rpc.IsolationSSHResult).Status != "applied" {
		t.Fatal(out, err)
	}
	good, _ := os.ReadFile(conf)
	if !strings.Contains(string(good), "Match User tenant") || !strings.Contains(string(good), "AllowTcpForwarding no") {
		t.Fatal(string(good))
	}
	fakeSSHD(t, conf, true) // sshd -t rejects: previous file must come back
	if _, err := callIso(t, e, rpc.MIsolationSSHApply, rpc.IsolationSSHApply{Users: []string{"tenant"}, Mode: "sftp"}); err == nil {
		t.Fatal("rejected config accepted")
	}
	now, _ := os.ReadFile(conf)
	if string(now) != string(good) {
		t.Fatalf("not rolled back:\n%s", now)
	}
	os.Remove(conf) // no previous file: a rejected one must be removed
	if _, err := callIso(t, e, rpc.MIsolationSSHApply, rpc.IsolationSSHApply{Users: []string{"tenant"}, Mode: "cage"}); err == nil {
		t.Fatal("accepted")
	}
	if _, err := os.Stat(conf); !os.IsNotExist(err) {
		t.Fatal("rejected file left in place")
	}
	for _, p := range []rpc.IsolationSSHApply{{Users: []string{"root"}, Mode: "cage"}, {Users: []string{"opsuser"}, Mode: "cage"},
		{Users: []string{"tenant"}, Mode: "shell"}, {Users: []string{"tenant\nMatch all"}, Mode: "cage"}} {
		if _, err := callIso(t, e, rpc.MIsolationSSHApply, p); err == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
}

func TestIsolationHidepidStatus(t *testing.T) {
	e, _, _ := isoEnv(t)
	dir := t.TempDir()
	mi, fs := filepath.Join(dir, "mountinfo"), filepath.Join(dir, "fstab")
	oldM, oldF := hidepidMountinfo, hidepidFstabPath
	hidepidMountinfo, hidepidFstabPath = mi, fs
	t.Cleanup(func() { hidepidMountinfo, hidepidFstabPath = oldM, oldF })
	gr, _ := os.ReadFile(groupFile)
	os.WriteFile(groupFile, append(gr, []byte("bpanel-proc:x:4100:bpanel\n")...), 0o644)

	check := func(mount, fstab, want string) {
		t.Helper()
		os.WriteFile(mi, []byte("23 22 0:5 / /proc rw,nosuid - proc proc "+mount+"\n"), 0o644)
		os.WriteFile(fs, []byte(fstab), 0o644)
		out, err := callIso(t, e, rpc.MIsolationHidepidStatus, struct{}{})
		if err != nil {
			t.Fatal(err)
		}
		if r := out.(rpc.HidepidStatus); r.Status != want {
			t.Fatalf("want %s got %+v", want, r)
		}
	}
	line := "proc /proc proc defaults,nosuid,nodev,noexec,hidepid=2,gid=4100 0 0\n"
	check("rw,hidepid=invisible,gid=4100", line, "active")
	check("rw", line, "configured_reboot_pending")
	check("rw", "proc /proc proc defaults 0 0\n", "not_configured")
	check("rw,hidepid=invisible,gid=1", "", "not_configured")
}
