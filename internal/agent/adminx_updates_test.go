// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

func TestParseAptUpgradable(t *testing.T) {
	out := "Listing... Done\nopenssl/noble-updates,noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.1]\nvim/noble-updates 2:9.1 amd64 [upgradable from: 2:9.0]\n\n"
	n, sec := parseAptUpgradable(out)
	if len(n) != 2 || sec != 1 || n[0] != "openssl" {
		t.Fatalf("%v %d", n, sec)
	}
	d := parseDNFCheckUpdate("\nkernel.x86_64  5.14.0-427  baseos\nopenssl.x86_64 1:3.0.7 appstream\nObsoleting Packages\n")
	if len(d) != 2 {
		t.Fatal(d)
	}
}

func TestUpdatesNotInstalled(t *testing.T) {
	old := updLookPath
	updLookPath = func(string) (string, error) { return "", errors.New("nope") }
	defer func() { updLookPath = old }()
	a := &Agent{}
	st, err := a.updatesStatus(context.Background(), rpc.UpdatesStatusReq{})
	if err != nil || st.Status != "not_installed" {
		t.Fatalf("%+v %v", st, err)
	}
	ap, err := a.updatesApply(context.Background(), rpc.UpdatesApply{})
	if err != nil || ap.Status != "not_installed" {
		t.Fatalf("%+v %v", ap, err)
	}
}

// fake apt in a temp dir: status parses its output and reads the reboot flag.
func TestUpdatesStatusFakeApt(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("apt-get", "exit 0\n")
	write("apt", "echo 'Listing... Done'\necho 'curl/noble-security 8.5 amd64 [upgradable from: 8.4]'\n")
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	oldL, oldR := updLookPath, updRebootFile
	updLookPath = func(n string) (string, error) {
		p := filepath.Join(dir, n)
		if _, err := os.Stat(p); err != nil {
			return "", err
		}
		return p, nil
	}
	updRebootFile = filepath.Join(dir, "reboot-required")
	defer func() { updLookPath, updRebootFile = oldL, oldR }()
	os.WriteFile(updRebootFile, nil, 0o644)
	st, err := (&Agent{}).updatesStatus(context.Background(), rpc.UpdatesStatusReq{})
	if err != nil || st.Status != "ok" || st.Upgradable != 1 || st.Security != 1 || !st.RebootRequired || !st.RebootKnown {
		t.Fatalf("%+v %v", st, err)
	}
}
