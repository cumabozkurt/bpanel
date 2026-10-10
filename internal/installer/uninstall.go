package installer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Uninstall removes the panel (API, agent, binaries, panel-only files) and
// leaves the server in a working state (SYS-8):
//
//   - Websites, mail, DNS and databases keep running: nginx, Apache, PHP-FPM,
//     PowerDNS, Postfix, Dovecot, Rspamd, Pure-FTPd and their configuration are
//     kept exactly as the panel left them. Stock files are NOT restored on top
//     of them, because that is what breaks things (Apache's stock ports.conf
//     takes port 80 from nginx; the stock pdns.conf drops the zone database).
//     The originals stay next to them as *.bpanel-orig.
//   - A firewall stays active: the one that was active before the install
//     (firewalld/ufw, with the site ports opened) or else the panel's
//     nftables table without the panel ports.
//   - systemd-resolved's stub listener stays off while PowerDNS is installed
//     (both cannot own port 53); otherwise resolv.conf is restored.
//   - fail2ban keeps protecting SSH (and mail when installed); the panel jail goes.
//
// With purge, the panel's own data is deleted too (database, configuration,
// secrets, ACME account, phpMyAdmin). Files that running services still use
// are kept and listed: /etc/bpanel/ssl, /etc/bpanel/nftables.conf (when it is
// still the active firewall), /var/lib/bpanel/acme, the Roundcube data.
func (in *Installer) Uninstall(ctx context.Context, purgeData bool) error {
	var kept []string
	note := func(s string) { kept = append(kept, s) }
	if in.S.Profile != "" {
		in.O.Profile = in.S.Profile // the profile that was installed, not the flag default
	}

	for _, u := range []string{"bpanel-api", "bpanel-agent"} {
		_ = in.systemctl(ctx, "disable", "--now", u)
		_ = os.Remove("/etc/systemd/system/" + u + ".service")
		_ = os.Remove("/etc/systemd/system/" + u + ".service.bpanel-orig")
	}
	_ = os.RemoveAll("/run/bpanel")

	in.uninstallFirewall(ctx, note)
	in.uninstallFail2ban(ctx)
	in.uninstallResolved(ctx, note)
	in.uninstallSFTP(ctx, note)
	in.uninstallPMA(ctx)

	_ = in.systemctl(ctx, "daemon-reload")
	for _, b := range []string{"bpanel-api", "bpanel-agent", "bpanel"} {
		_ = os.Remove("/usr/local/bin/" + b)
	}

	if purgeData {
		// R2-SYS-14: also the restic repository passwords, the agent's
		// account/owner registries, the capability flags and the restic binary.
		for _, p := range []string{"/etc/bpanel/api.json", "/etc/bpanel/agent.json", "/etc/bpanel/secrets", "/etc/bpanel/acme",
			"/etc/bpanel/restic", "/etc/bpanel/accounts", "/etc/bpanel/owners", CapabilitiesFile,
			"/var/lib/bpanel/db", legacyDBPath, legacyDBPath + "-wal", legacyDBPath + "-shm", "/usr/share/bpanel/suspended", CacheDir} {
			_ = os.RemoveAll(p)
		}
		if t, err := os.Readlink(resticLegacyBin); err == nil && t == ResticBin {
			_ = os.Remove(resticLegacyBin)
		}
		_ = os.RemoveAll(LibDir)
		if _, err := os.Stat("/var/backups/bpanel"); err == nil {
			note("/var/backups/bpanel (restic backups; their passwords were in /etc/bpanel/restic and are deleted, so the repositories can no longer be opened: delete them too unless you saved the passwords)")
		}
		for _, f := range []string{"/etc/tmpfiles.d/bpanel.conf", "/etc/systemd/journald.conf.d/50-bpanel.conf"} {
			_ = os.Remove(f)
			_ = os.Remove(f + ".bpanel-orig")
		}
		note("/etc/bpanel/ssl (certificate used by nginx, Postfix, Dovecot and Pure-FTPd)")
		note("/var/lib/bpanel/acme (ACME challenges of the catch-all server)")
		if _, err := os.Stat(rcDir); err == nil {
			note("/usr/share/bpanel/roundcube and /var/lib/bpanel/apps (webmail on port 2096)")
		}
	}
	if len(in.S.Disabled) > 0 {
		var l []string
		for orig, moved := range in.S.Disabled {
			l = append(l, orig+" -> "+moved)
		}
		sort.Strings(l)
		note("stock files moved aside by the installer (not restored, they would conflict): " + strings.Join(l, "; "))
	}
	var bools []string
	for k, v := range in.S.Prev {
		if strings.HasPrefix(k, "sebool:") {
			bools = append(bools, strings.TrimPrefix(k, "sebool:")+"="+v)
		}
	}
	if len(bools) > 0 {
		sort.Strings(bools)
		note("SELinux booleans and file contexts (still needed by the sites); values before the install: " + strings.Join(bools, " "))
	}

	// self-test debris (R2-SYS-14)
	if logs, _ := filepath.Glob(filepath.Join(domlogDir, "*.selftest.invalid.*")); len(logs) > 0 {
		for _, f := range logs {
			_ = os.Remove(f)
		}
	}
	_ = os.Remove(StateFile)
	// binaries kept for later upgrades/uninstalls; restic stays without
	// --purge so the backups in /var/backups/bpanel can still be restored
	if t, err := os.Readlink(installerLink); err == nil && strings.HasPrefix(t, LibDir+"/") {
		_ = os.Remove(installerLink)
	}
	for _, b := range releaseBinaries {
		_ = os.Remove(filepath.Join(LibDir, b))
	}
	if !purgeData {
		if _, err := os.Stat(ResticBin); err == nil {
			note(ResticBin + " and /etc/bpanel/restic (restic and the repository passwords, to restore the backups in /var/backups/bpanel)")
		}
	}

	fmt.Fprintln(in.out, "BOZKURT PANEL removed. Websites, mail, DNS, databases, packages and their configuration were kept and keep running.")
	for _, k := range kept {
		fmt.Fprintln(in.out, "  kept: "+k)
	}
	if !purgeData {
		fmt.Fprintln(in.out, "Run with --purge to also delete the panel database, configuration and secrets.")
	}
	return nil
}

// uninstallFirewall brings back the firewall that was active before the
// install, with the site ports open, or keeps the panel's nftables table
// without the panel ports. The server is never left without a firewall.
func (in *Installer) uninstallFirewall(ctx context.Context, note func(string)) {
	ports := FirewallPorts(in.sshPorts(ctx), in.full(), in.web(), false)
	restored := false
	switch in.S.Prev["firewall"] {
	case "firewalld":
		if have("firewall-offline-cmd") {
			args := []string{"firewall-offline-cmd"}
			for _, p := range ports {
				args = append(args, "--add-port="+p+"/tcp")
			}
			if in.web() {
				args = append(args, "--add-port=53/udp")
			}
			if err := in.sh(ctx, args...); err == nil && in.systemctl(ctx, "enable", "--now", "firewalld") == nil {
				restored = true
			}
		}
	case "ufw":
		if have("ufw") {
			ok := true
			for _, p := range ports {
				if err := in.sh(ctx, "ufw", "allow", strings.Replace(p, "-", ":", 1)+"/tcp"); err != nil {
					ok = false
				}
			}
			if in.web() {
				_ = in.sh(ctx, "ufw", "allow", "53/udp")
			}
			if ok && in.sh(ctx, "ufw", "--force", "enable") == nil {
				restored = true
			}
		}
	}
	if restored {
		_ = in.systemctl(ctx, "disable", "--now", "bpanel-firewall")
		_ = os.Remove("/etc/systemd/system/bpanel-firewall.service")
		_ = os.Remove("/etc/systemd/system/bpanel-firewall.service.bpanel-orig")
		_ = os.Remove("/etc/bpanel/nftables.conf")
		note(in.S.Prev["firewall"] + " re-enabled with ports " + strings.Join(ports, ","))
		return
	}
	if _, err := os.Stat("/etc/bpanel/nftables.conf"); err != nil {
		return
	}
	rules := firewallRules(ports, in.web())
	if err := os.WriteFile("/etc/bpanel/nftables.conf", []byte(rules), 0o600); err == nil {
		if in.sh(ctx, "nft", "-c", "-f", "/etc/bpanel/nftables.conf") == nil {
			_ = in.systemctl(ctx, "reload-or-restart", "bpanel-firewall")
		}
	}
	note("firewall bpanel-firewall.service (/etc/bpanel/nftables.conf) stays active without the panel ports; replace it with your own before disabling it")
}

func (in *Installer) uninstallFail2ban(ctx context.Context) {
	_ = os.Remove(fail2banFilterPath)
	if _, err := os.Stat(fail2banJailPath); err != nil {
		return
	}
	j := Fail2banJail(in.sshPorts(ctx), in.full(), false)
	if err := os.WriteFile(fail2banJailPath, []byte(j), 0o644); err == nil {
		_ = in.systemctl(ctx, "try-reload-or-restart", "fail2ban")
	}
}

func (in *Installer) uninstallResolved(ctx context.Context, note func(string)) {
	const dropIn = "/etc/systemd/resolved.conf.d/bpanel.conf"
	if _, err := os.Stat(dropIn); err != nil {
		return
	}
	if have("pdns_server") {
		note("systemd-resolved stub listener stays off: PowerDNS still answers on port 53")
		return
	}
	_ = os.Remove(dropIn)
	switch prev := in.S.Prev["resolv.conf"]; {
	case strings.HasPrefix(prev, "link:"):
		tmp := resolvConf + ".bpanel-new"
		_ = os.Remove(tmp)
		if os.Symlink(strings.TrimPrefix(prev, "link:"), tmp) == nil {
			_ = os.Rename(tmp, resolvConf)
		}
	case prev == "file":
		if moved, ok := in.S.Disabled[resolvConf]; ok && moveFile(moved, resolvConf) == nil {
			delete(in.S.Disabled, resolvConf)
		}
	}
	_ = in.systemctl(ctx, "restart", "systemd-resolved")
}

// uninstallSFTP keeps the SFTP jail while hosting accounts exist (removing it
// would hand them an unjailed SFTP/SSH session).
func (in *Installer) uninstallSFTP(ctx context.Context, note func(string)) {
	const p = "/etc/ssh/sshd_config.d/50-bpanel.conf"
	if _, err := os.Stat(p); err != nil {
		return
	}
	if groupHasMembers("bpanel-sftp") {
		note(p + " (SFTP jail for the hosting accounts that still exist)")
		return
	}
	_ = os.Remove(p)
	if in.sh(ctx, "sshd", "-t") == nil {
		_ = in.reloadSSH(ctx)
	}
}

// uninstallPMA removes phpMyAdmin, whose sign-on needs the panel API.
func (in *Installer) uninstallPMA(ctx context.Context) {
	const conf = "/etc/nginx/bpanel-apps.d/apps.conf"
	if _, err := os.Stat(conf); err != nil {
		return
	}
	full := false
	if _, err := os.Stat(rcDir + "/index.php"); err == nil {
		full = true
	}
	s := AppsNginx(AppsNginxOpts{Socket: in.appsSocket(), PMADir: pmaDir, RCDir: rcDir, Cert: panelCert, Key: panelKey,
		Webmail: full, HTTP2On: in.nginxHTTP2On(ctx)})
	if i := strings.Index(s, "\n# Webmail"); i >= 0 {
		s = "# Managed by BOZKURT PANEL (panel removed; webmail kept)\n" + s[i:]
	} else {
		s = "# Managed by BOZKURT PANEL (panel removed)\n"
	}
	old, _ := os.ReadFile(conf)
	if err := os.WriteFile(conf, []byte(s), 0o644); err != nil {
		return
	}
	if in.sh(ctx, "nginx", "-t") != nil {
		_ = os.WriteFile(conf, old, 0o644)
		return
	}
	_ = in.systemctl(ctx, "reload", "nginx")
	_ = os.RemoveAll(pmaDir)
}

func groupHasMembers(name string) bool {
	b, _ := os.ReadFile("/etc/group")
	for _, l := range strings.Split(string(b), "\n") {
		p := strings.Split(l, ":")
		if len(p) == 4 && p[0] == name {
			return strings.TrimSpace(p[3]) != ""
		}
	}
	return false
}
