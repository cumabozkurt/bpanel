// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cumabozkurt/bpanel/internal/obsx"
)

func TestObsxAgentFIMAndHealth(t *testing.T) {
	root := t.TempDir()
	oldRoot, oldHave, oldT := obsxRoot, obsxHave, obsxFIMTargetsFor
	defer func() { obsxRoot, obsxHave, obsxFIMTargetsFor = oldRoot, oldHave, oldT }()
	obsxRoot = root
	obsxHave = func(string) bool { return false }
	os.MkdirAll(filepath.Join(root, "etc/bpanel"), 0o755)
	os.MkdirAll(filepath.Join(root, "proc"), 0o755)
	os.MkdirAll(filepath.Join(root, "var/run"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/bpanel/bpanel.toml"), []byte("a=1"), 0o600)
	os.WriteFile(filepath.Join(root, "etc/shadow"), []byte("root:x"), 0o600)
	os.WriteFile(filepath.Join(root, "proc/mdstat"), []byte("md0 : active raid1 sdb1[1] sda1[0]\n  100 blocks [2/2] [UU]\n"), 0o644)
	os.WriteFile(filepath.Join(root, "var/run/reboot-required"), nil, 0o644)
	a := &Agent{}
	res, err := a.obsxFIMScan(context.Background(), struct{}{})
	if err != nil || len(res.Entries) != 2 {
		t.Fatalf("scan: %v %+v", err, res)
	}
	for _, e := range res.Entries {
		if filepath.Base(e.Path) == "shadow" && e.SHA256 != "" {
			t.Fatal("shadow must be metadata only")
		}
	}
	h, _ := a.obsxOSHealth(context.Background(), struct{}{})
	got := map[string]string{}
	for _, c := range h.Checks {
		got[c.ID] = c.Status
	}
	want := map[string]string{"reboot_required": obsx.HWarn, "raid": obsx.HOK, "smart": obsx.HNotInstalled, "log_rotation": obsx.HNotInstalled,
		"failed_units": obsx.HNotInstalled, "time_sync": obsx.HNotInstalled}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %s, want %s", k, got[k], v)
		}
	}
}
