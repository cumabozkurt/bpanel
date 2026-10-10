package installer

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/cumabozkurt/bpanel/internal/distro"
	"github.com/cumabozkurt/bpanel/internal/sysinfo"
)

func (in *Installer) ensureGroup(ctx context.Context, name string) error {
	if groupExists(name) {
		return nil
	}
	return in.sh(ctx, "groupadd", "--system", name)
}

func groupExists(name string) bool {
	b, _ := os.ReadFile("/etc/group")
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, name+":") {
			return true
		}
	}
	return false
}

func userExists(name string) bool {
	b, _ := os.ReadFile("/etc/passwd")
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, name+":") {
			return true
		}
	}
	return false
}

// Dir is one directory the installer owns, with its mode and owner.
type Dir struct {
	Path  string
	Mode  os.FileMode
	Owner string
}

// Dirs returns the panel's directories (SYS-3). /var/lib/bpanel is root-owned
// and 0751: every service can traverse into the subdirectory meant for it
// (nginx -> acme, bpanel-apps -> apps, bpanel -> db) but nobody can list it,
// and the unprivileged API cannot rename root's directories (acme/ is written
// by the root agent, so a bpanel-owned parent would let a compromised API
// swap it for a symlink).
func Dirs(l *distro.Layout, profile string) []Dir {
	d := []Dir{
		{"/etc/bpanel", 0o750, "root:bpanel"},
		{"/etc/bpanel/ssl", 0o750, "root:bpanel"},
		{"/etc/bpanel/ssl/panel", 0o750, "root:bpanel"},
		{"/etc/bpanel/acme", 0o700, "root:root"},
		{"/etc/bpanel/secrets", 0o700, "root:root"},
		// agent state (handoff-backend I-1, CODE-27): ownership markers of
		// panel-created accounts, the domain/zone/mail-domain owner registry,
		// restic repository passwords
		{"/etc/bpanel/accounts", 0o700, "root:root"},
		{"/etc/bpanel/owners", 0o700, "root:root"},
		{"/etc/bpanel/restic", 0o700, "root:root"},
		{"/var/lib/bpanel", 0o751, "root:bpanel"},
		{"/var/lib/bpanel/db", 0o700, "bpanel:bpanel"},
		{"/var/lib/bpanel/apps", 0o750, "bpanel-apps:bpanel-apps"},
		{"/var/lib/bpanel/acme", 0o755, "root:root"},
		{"/var/lib/bpanel/acme/.well-known", 0o755, "root:root"},
		{"/var/lib/bpanel/acme/.well-known/acme-challenge", 0o755, "root:root"},
		{"/var/lib/bpanel/disabled", 0o700, "root:root"},
		// root-owned restic restore staging; the agent refuses it unless it is
		// a real root-owned 0711 directory (SEC-3)
		{"/var/lib/bpanel/restore", 0o711, "root:root"},
		{"/var/log/bpanel", 0o750, "root:bpanel"},
		{"/var/log/bpanel/domlogs", 0o750, "root:bpanel"},
		{"/var/backups/bpanel", 0o700, "root:root"},
		{CacheDir, 0o700, "root:root"},
		{"/usr/share/bpanel", 0o755, "root:root"},
		// homes are chroot targets for SFTP (ChrootDirectory /home needs a
		// root-owned /home); 0711 so tenants cannot list other accounts (I-5)
		{"/home", 0o711, "root:root"},
		{l.NginxVhosts, 0o755, "root:root"},
	}
	if profile != "minimal" {
		d = append(d, Dir{l.ApacheVhosts, 0o755, "root:root"})
	}
	if profile == "full" {
		d = append(d, Dir{l.PostfixDir + "/bpanel", 0o755, "root:root"}, Dir{l.DovecotDir + "/bpanel", 0o750, "root:dovecot"})
	}
	return d
}

func (in *Installer) system(ctx context.Context) error {
	for _, g := range []string{"bpanel-web", "bpanel-users", "bpanel-sftp"} {
		if err := in.ensureGroup(ctx, g); err != nil {
			return err
		}
	}
	nologin := "/usr/sbin/nologin"
	if _, err := os.Stat(nologin); err != nil {
		nologin = "/sbin/nologin"
	}
	for _, u := range []struct{ name, home string }{{"bpanel", "/var/lib/bpanel/db"}, {"bpanel-apps", "/var/lib/bpanel/apps"}} {
		if !userExists(u.name) {
			if err := in.sh(ctx, "useradd", "--system", "--user-group", "--no-create-home", "--home-dir", u.home, "--shell", nologin, u.name); err != nil {
				return err
			}
		}
	}
	// web servers read docroots through the bpanel-web group
	for _, u := range []string{in.L.ApacheUser, "nginx", "www-data", "apache"} {
		if userExists(u) {
			if err := in.sh(ctx, "usermod", "-aG", "bpanel-web", u); err != nil {
				return err
			}
		}
	}
	for _, d := range Dirs(in.L, in.O.Profile) {
		if d.Owner == "root:dovecot" && !groupExists("dovecot") {
			d.Owner = "root:root"
		}
		if err := os.MkdirAll(d.Path, d.Mode); err != nil {
			return err
		}
		if err := os.Chmod(d.Path, d.Mode); err != nil {
			return err
		}
		if err := in.sh(ctx, "chown", d.Owner, d.Path); err != nil {
			return err
		}
	}
	in.setupQuota(ctx)
	in.setupSwap(ctx)
	if err := in.cronPAMSystemd(); err != nil {
		in.warn("cron pam_systemd: " + err.Error())
	}
	for p, c := range map[string]string{
		"/etc/systemd/journald.conf.d/50-bpanel.conf": JournaldDropIn,
		"/etc/tmpfiles.d/bpanel.conf":                 Tmpfiles,
	} {
		if err := in.writeFile(p, c, 0o644); err != nil {
			return err
		}
	}
	apache := ""
	if in.web() {
		apache = in.L.ApacheUnit
	}
	if err := in.writeFile("/etc/logrotate.d/bpanel", Logrotate(apache), 0o644); err != nil {
		return err
	}
	if have("logrotate") {
		if err := in.sh(ctx, "logrotate", "-d", "/etc/logrotate.d/bpanel"); err != nil {
			return err
		}
	}
	if err := in.step("system:hidepid", func() error { return in.hidepid(ctx) }); err != nil { // isolation
		return err
	}
	return in.setupSELinux(ctx)
}

// selinuxEnabled reports whether SELinux is enforcing or permissive.
func selinuxEnabled() bool {
	return have("selinuxenabled") && exec.Command("selinuxenabled").Run() == nil
}

// setupSELinux labels the panel's paths and enables the booleans the stack
// needs on AlmaLinux/Rocky (SYS-7). The previous value of every boolean is
// recorded so uninstall can restore it.
func (in *Installer) setupSELinux(ctx context.Context) error {
	if in.L.Family != distro.RHEL || !selinuxEnabled() {
		return nil
	}
	if !have("semanage") {
		return fmt.Errorf("SELinux is enabled but semanage is missing (install policycoreutils-python-utils)")
	}
	plan := SELinux(in.full(), in.web())
	var set []string
	for _, b := range plan.Booleans {
		out, err := in.shOut(ctx, nil, "getsebool", b)
		if err != nil {
			in.warn("SELinux boolean " + b + ": " + err.Error())
			continue
		}
		if _, ok := in.S.Prev["sebool:"+b]; !ok {
			v := "off"
			if strings.Contains(out, "--> on") {
				v = "on"
			}
			in.S.Prev["sebool:"+b] = v
		}
		set = append(set, b+"=1")
	}
	in.save()
	if len(set) > 0 {
		if err := in.sh(ctx, append([]string{"setsebool", "-P"}, set...)...); err != nil {
			return err
		}
	}
	for _, fc := range plan.FContexts {
		if err := in.sh(ctx, "semanage", "fcontext", "-a", "-t", fc.Type, fc.Spec); err != nil {
			if err := in.sh(ctx, "semanage", "fcontext", "-m", "-t", fc.Type, fc.Spec); err != nil {
				return err
			}
		}
	}
	for _, p := range plan.Ports {
		if err := in.sh(ctx, "semanage", "port", "-a", "-t", "http_port_t", "-p", "tcp", p); err != nil {
			// already defined (8080 is http_cache_port_t): modify instead
			if err := in.sh(ctx, "semanage", "port", "-m", "-t", "http_port_t", "-p", "tcp", p); err != nil {
				return err
			}
		}
	}
	for _, p := range plan.Relabel {
		if _, err := os.Stat(p); err == nil {
			if err := in.sh(ctx, "restorecon", "-R", p); err != nil {
				in.warn("restorecon " + p + ": " + err.Error())
			}
		}
	}
	return nil
}

// setupQuota enables user quotas on the filesystem holding /home (best effort).
func (in *Installer) setupQuota(ctx context.Context) {
	if in.O.NoSystemd {
		in.warn("quota: not configured in --no-systemd test mode")
		return
	}
	mnt, fstype := mountOf("/home")
	switch fstype {
	case "ext4":
		if err := addFstabOption(mnt, "usrquota"); err != nil {
			in.warn("quota: " + err.Error())
			return
		}
		in.sh(ctx, "modprobe", "quota_v2")
		if err := in.sh(ctx, "mount", "-o", "remount", mnt); err != nil {
			in.warn("quota: remount failed; reboot to activate")
			in.S.Reboot = true
			return
		}
		if err := in.sh(ctx, "quotacheck", "-cum", mnt); err != nil {
			in.warn("quota: quotacheck failed (kernel module missing? install linux-modules-extra): " + err.Error())
			return
		}
		if err := in.sh(ctx, "quotaon", mnt); err != nil {
			in.warn("quota: quotaon failed: " + err.Error())
		}
	case "xfs":
		if mnt == "/" {
			if have("grubby") {
				if err := in.sh(ctx, "grubby", "--update-kernel=ALL", "--args=rootflags=uquota"); err != nil {
					in.warn("quota: " + err.Error())
					return
				}
				in.S.Reboot = true
			} else {
				in.warn("quota: add rootflags=uquota to the kernel command line to enable XFS quotas on /")
			}
		} else {
			if err := addFstabOption(mnt, "uquota"); err != nil {
				in.warn("quota: " + err.Error())
				return
			}
			in.S.Reboot = true
		}
	default:
		in.warn("quota: filesystem " + fstype + " on " + mnt + " is not supported; disk limits are reported but not enforced")
	}
}

func mountOf(path string) (string, string) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "/", ""
	}
	defer f.Close()
	best, typ := "/", ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 3 {
			continue
		}
		m := fl[1]
		if (path == m || strings.HasPrefix(path, strings.TrimSuffix(m, "/")+"/")) && len(m) >= len(best) {
			best, typ = m, fl[2]
		}
	}
	return best, typ
}

// addFstabOption adds a mount option to the fstab line of mountpoint (idempotent).
func addFstabOption(mountpoint, opt string) error {
	b, err := os.ReadFile("/etc/fstab")
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	found := false
	for i, l := range lines {
		fl := strings.Fields(l)
		if len(fl) >= 4 && !strings.HasPrefix(fl[0], "#") && fl[1] == mountpoint {
			found = true
			if !strings.Contains(fl[3], opt) {
				fl[3] += "," + opt
				lines[i] = strings.Join(fl, "\t")
			}
		}
	}
	if !found {
		return fmt.Errorf("no fstab entry for %s", mountpoint)
	}
	if _, err := os.Stat("/etc/fstab.bpanel-orig"); os.IsNotExist(err) {
		if err := os.WriteFile("/etc/fstab.bpanel-orig", b, 0o644); err != nil {
			return err
		}
	}
	if err := os.WriteFile("/etc/fstab.bpanel-new", []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return err
	}
	return os.Rename("/etc/fstab.bpanel-new", "/etc/fstab")
}

func (in *Installer) setupSwap(ctx context.Context) {
	si := sysinfo.Collect()
	if si.SwapTotal > 0 || si.MemTotal > 2200<<20 || in.O.NoSystemd {
		return
	}
	if _, err := os.Stat("/swapfile-bpanel"); err == nil {
		return
	}
	for _, c := range [][]string{{"fallocate", "-l", "1G", "/swapfile-bpanel"}, {"chmod", "600", "/swapfile-bpanel"}, {"mkswap", "/swapfile-bpanel"}, {"swapon", "/swapfile-bpanel"}} {
		if err := in.sh(ctx, c...); err != nil {
			in.warn("swap: " + err.Error())
			return
		}
	}
	f, err := os.OpenFile("/etc/fstab", os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		in.warn("swap: " + err.Error())
		return
	}
	if _, err := f.WriteString("/swapfile-bpanel none swap sw 0 0\n"); err != nil {
		in.warn("swap: " + err.Error())
	}
	_ = f.Close()
}

// cronPAMFile is the PAM stack of the cron daemon per family.
func cronPAMFile(l *distro.Layout) string {
	if l.Family == distro.RHEL {
		return "/etc/pam.d/crond"
	}
	return "/etc/pam.d/cron"
}

// CronPAMWithSystemd adds "session optional pam_systemd.so" to a cron PAM
// stack so cron jobs run in user-<uid>.slice and get the account's CPU,
// memory and task limits (handoff-backend I-4a). Idempotent.
func CronPAMWithSystemd(orig string) string {
	for _, l := range strings.Split(orig, "\n") {
		f := strings.Fields(l)
		if len(f) >= 3 && f[0] == "session" && strings.Contains(l, "pam_systemd.so") && !strings.HasPrefix(strings.TrimSpace(l), "#") {
			return orig
		}
	}
	if orig != "" && !strings.HasSuffix(orig, "\n") {
		orig += "\n"
	}
	return orig + "# BOZKURT PANEL: cron jobs run in the account's user slice (resource limits)\nsession    optional   pam_systemd.so\n"
}

func (in *Installer) cronPAMSystemd() error {
	p := cronPAMFile(in.L)
	orig, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no cron PAM stack (cron not installed yet)
		}
		return err
	}
	if next := CronPAMWithSystemd(string(orig)); next != string(orig) {
		return in.writeFile(p, next, 0o644)
	}
	return nil
}
