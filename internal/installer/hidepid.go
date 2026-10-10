// SPDX-License-Identifier: Apache-2.0

package installer

import (
	"context"
	"fmt"
	"os"

	"github.com/cumabozkurt/bpanel/internal/isolation"
)

// hidepid=2 on /proc: accounts cannot see each other's processes (command
// lines often carry DB passwords). Members of isolation.ProcGroup are exempt.

// Overridable in tests.
var (
	hidepidFstab = "/etc/fstab"
	// hidepidMembers are the service users added to bpanel-proc when they
	// exist: the panel API, the apps runner, and common monitoring/polkit
	// daemons that break under hidepid=2 otherwise.
	hidepidMembers = []string{"bpanel", "bpanel-apps", "polkitd", "netdata", "prometheus", "node-exp", "node_exporter", "zabbix", "telegraf", "nagios"}
)

// HidepidArgv lists the fixed commands the step runs (logged, for docs/tests).
func HidepidArgv(gid int) [][]string {
	return [][]string{
		{"groupadd", "--system", isolation.ProcGroup},
		{"usermod", "-aG", isolation.ProcGroup, "<member>"},
		{"findmnt", "--verify", "--tab-file", "<temp file with the /proc line>"},
		isolation.RemountProcArgv(gid),
	}
}

// writeHidepidFstab installs the /proc line idempotently. The original is
// kept once as <fstab>.bpanel-orig (writeFile); the new content is validated
// (structure + `findmnt --verify` when available) and the previous content is
// put back if validation fails. Returns whether the file changed.
func (in *Installer) writeHidepidFstab(ctx context.Context, gid int) (bool, error) {
	old, err := os.ReadFile(hidepidFstab)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	next, changed, err := isolation.RenderFstab(string(old), gid)
	if err != nil {
		return false, err
	}
	if !changed {
		return false, nil
	}
	if err := isolation.ValidateFstab(next, gid); err != nil {
		return false, err
	}
	if err := in.writeFile(hidepidFstab, next, 0o644); err != nil {
		return false, err
	}
	// findmnt checks only our line (written to a temp tab file): unrelated
	// pre-existing entries (a detached disk) must not block the install; the
	// whole file passed ValidateFstab above.
	if have("findmnt") {
		line, _ := isolation.ProcFstabLine(gid)
		tmp, err := os.CreateTemp("", "bpanel-fstab-*")
		if err == nil {
			_, _ = tmp.WriteString(line + "\n")
			_ = tmp.Close()
			err = in.sh(ctx, "findmnt", "--verify", "--tab-file", tmp.Name())
			_ = os.Remove(tmp.Name())
		}
		if err != nil {
			if old != nil {
				_ = os.WriteFile(hidepidFstab, old, 0o644)
			}
			return false, fmt.Errorf("fstab validation failed, original restored: %w", err)
		}
	}
	return true, nil
}

// hidepid is the installer step. A failed live remount (containers, old
// kernels) is a warning: the fstab line still applies at the next boot.
func (in *Installer) hidepid(ctx context.Context) error {
	if err := in.ensureGroup(ctx, isolation.ProcGroup); err != nil {
		return err
	}
	gid := lookupGID(isolation.ProcGroup)
	if gid <= 0 {
		return fmt.Errorf("group %s has no gid", isolation.ProcGroup)
	}
	for _, u := range hidepidMembers {
		if userExists(u) {
			if err := in.sh(ctx, "usermod", "-aG", isolation.ProcGroup, u); err != nil {
				return err
			}
		}
	}
	if _, err := in.writeHidepidFstab(ctx, gid); err != nil {
		return err
	}
	if err := in.sh(ctx, isolation.RemountProcArgv(gid)...); err != nil {
		in.warn("hidepid: live remount of /proc failed (applies after reboot): " + err.Error())
	}
	return nil
}
