// SPDX-License-Identifier: Apache-2.0

package isolation

import (
	"fmt"
	"sort"
	"strings"
)

// SSH jail for accounts with shell access.
//
//	SSHModeSFTP: ChrootDirectory /var/lib/bpanel/jail/%u + ForceCommand internal-sftp
//	            (sshd requires the chroot path root-owned and not group/world writable).
//	SSHModeCage: ForceCommand CageShellBin, which runs the session (or
//	            $SSH_ORIGINAL_COMMAND) inside bwrap with only the account home writable.
const (
	SSHModeSFTP  = "sftp"
	SSHModeCage  = "cage"
	CageShellBin = "/usr/local/lib/bpanel/bpanel-cage-shell"
	JailRoot     = "/var/lib/bpanel/jail"
	SSHJailConf  = "/etc/ssh/sshd_config.d/60-bpanel-jail.conf"
)

// RenderSSHJail renders one Match User block per jailed account (sorted,
// de-duplicated). An empty list renders a header-only file (no jail).
func RenderSSHJail(users []string, mode string) (string, error) {
	if mode != SSHModeSFTP && mode != SSHModeCage {
		return "", fmt.Errorf("invalid ssh jail mode %q", mode)
	}
	seen := map[string]bool{}
	var us []string
	for _, u := range users {
		if !UserRe.MatchString(u) {
			return "", fmt.Errorf("invalid user %q", u)
		}
		if !seen[u] {
			seen[u] = true
			us = append(us, u)
		}
	}
	sort.Strings(us)
	var b strings.Builder
	b.WriteString("# Managed by BOZKURT PANEL (isolation). Validated with sshd -t before use.\n")
	for _, u := range us {
		fmt.Fprintf(&b, "Match User %s\n", u)
		b.WriteString("    AllowTcpForwarding no\n    AllowStreamLocalForwarding no\n    X11Forwarding no\n    AllowAgentForwarding no\n    PermitTunnel no\n    PermitTTY ")
		if mode == SSHModeSFTP {
			b.WriteString("no\n")
			fmt.Fprintf(&b, "    ChrootDirectory %s/%%u\n    ForceCommand internal-sftp -d /home\n", JailRoot)
		} else {
			b.WriteString("yes\n")
			fmt.Fprintf(&b, "    ForceCommand %s\n", CageShellBin)
		}
	}
	if len(us) > 0 {
		b.WriteString("Match all\n")
	}
	return b.String(), nil
}

// RenderCageShell is the ForceCommand script. It runs as the account user;
// bwrap needs unprivileged user namespaces. The command interpreted is the
// user's own ($SSH_ORIGINAL_COMMAND), as that user. Without bwrap it fails
// closed rather than giving an unjailed shell.
func RenderCageShell() string {
	return `#!/bin/sh
# Managed by BOZKURT PANEL. SSH ForceCommand cage for jailed accounts.
set -eu
BW=/usr/bin/bwrap
[ -x "$BW" ] || { echo "bpanel: shell jail unavailable (bubblewrap not installed)" >&2; exit 126; }
H="$HOME"
case "$H" in /home/*) ;; *) echo "bpanel: refusing home $H" >&2; exit 126;; esac
set -- --die-with-parent --unshare-pid --unshare-ipc --unshare-uts --new-session \
  --ro-bind /usr /usr --ro-bind /etc /etc --symlink usr/bin /bin --symlink usr/lib /lib \
  --symlink usr/lib64 /lib64 --symlink usr/sbin /sbin --proc /proc --dev /dev \
  --tmpfs /tmp --tmpfs /home --bind "$H" "$H" --chdir "$H" --setenv HOME "$H"
if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
  exec "$BW" "$@" /bin/sh -c "$SSH_ORIGINAL_COMMAND"
fi
exec "$BW" "$@" /bin/bash -l
`
}
