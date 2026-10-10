// SPDX-License-Identifier: Apache-2.0

package installer

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cumabozkurt/bpanel/internal/isolation"
)

func TestHidepidFstabIdempotent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "fstab")
	orig := "UUID=x / ext4 defaults 0 1\nproc /proc proc defaults 0 0\n"
	if err := os.WriteFile(p, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	old := hidepidFstab
	hidepidFstab = p
	t.Cleanup(func() { hidepidFstab = old })
	in := &Installer{S: &State{Disabled: map[string]string{}}, log: io.Discard, out: io.Discard}
	ch, err := in.writeHidepidFstab(context.Background(), 4321)
	if err != nil || !ch {
		t.Fatal(ch, err)
	}
	b, _ := os.ReadFile(p)
	if isolation.ValidateFstab(string(b), 4321) != nil || !strings.Contains(string(b), "hidepid=2,gid=4321") {
		t.Fatal(string(b))
	}
	if bk, err := os.ReadFile(p + ".bpanel-orig"); err != nil || string(bk) != orig {
		t.Fatalf("backup: %v %q", err, bk)
	}
	ch, err = in.writeHidepidFstab(context.Background(), 4321)
	if err != nil || ch {
		t.Fatalf("second run changed=%v err=%v", ch, err)
	}
	b2, _ := os.ReadFile(p)
	if string(b2) != string(b) {
		t.Fatal("content changed on re-run")
	}
	if a := HidepidArgv(4321); strings.Join(a[3], " ") != "mount -o remount,hidepid=2,gid=4321 /proc" {
		t.Fatal(a)
	}
}
