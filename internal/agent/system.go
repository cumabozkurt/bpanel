package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/distro"
	"github.com/cumabozkurt/bpanel/internal/sysinfo"
	"github.com/cumabozkurt/bpanel/internal/validate"
)

// sysInfo caches the host metrics for a few seconds (R2-PERF-16): Collect
// samples the CPU for 200 ms, and every dashboard load asked for it.
func (a *Agent) sysInfo(ctx context.Context, _ rpc.Empty) (rpc.SysInfo, error) {
	sysInfoMu.Lock()
	defer sysInfoMu.Unlock()
	if !sysInfoAt.IsZero() && time.Since(sysInfoAt) < 5*time.Second {
		return sysInfoVal, nil
	}
	sysInfoVal, sysInfoAt = sysinfo.Collect(), time.Now()
	return sysInfoVal, nil
}

var (
	sysInfoMu  sync.Mutex
	sysInfoAt  time.Time
	sysInfoVal rpc.SysInfo
)

const defaultIndex = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%[1]s</title><style>body{font-family:system-ui,sans-serif;background:#f7f8fa;color:#1b2333;display:grid;place-items:center;min-height:100vh;margin:0}
main{text-align:center}small{color:#64748b}</style></head>
<body><main><h1>%[1]s</h1><p>This site is hosted with BOZKURT PANEL. Upload your files to <code>public_html</code>.</p>
<p><small>Bu site BOZKURT PANEL ile barındırılıyor. Dosyalarınızı <code>public_html</code> klasörüne yükleyin.</small></p></main></body></html>
`

// accountExists tells the API whether a name is already used on the host.
func (a *Agent) accountExists(ctx context.Context, p rpc.AccountRef) (rpc.AccountExistsResult, error) {
	var res rpc.AccountExistsResult
	e, err := lookupUser(p.User)
	if err != nil {
		var re *rpc.Error
		if errors.As(err, &re) && re.Code == "no_such_user" {
			return res, nil
		}
		return res, err
	}
	res.Exists = true
	res.Managed = a.isManaged(e)
	return res, nil
}

// accountCreate makes a NEW Linux user for a hosting account. It refuses any
// name that already exists on the host (SEC-5 / CODE-2): an existing account
// (the cloud image's sudo user, an operator login, a service account) must
// never be adopted, re-passworded, or later deleted by a rollback. The call
// is atomic: if any step after useradd fails, the new user is removed again.
func (a *Agent) accountCreate(ctx context.Context, p rpc.AccountCreate) (rpc.AccountCreateResult, error) {
	var res rpc.AccountCreateResult
	if err := validate.Username(p.User); err != nil && err.Error() == "invalid_username" {
		return res, errf(err.Error(), "%s", p.User)
	}
	defer a.lock("accounts")()
	if ex, err := lookupUser(p.User); err == nil {
		// R2-PERF-15: an account this panel created (marker present) but
		// whose creation was interrupted is adopted when the API asks for
		// it; anything else is never touched (SEC-5).
		if p.Adopt && a.isManaged(ex) {
			return a.adoptAccount(ctx, p)
		}
		return res, errf("user_exists", "a system user named %s already exists on this server", p.User)
	}
	if err := validate.Username(p.User); err != nil {
		return res, errf(err.Error(), "%s", p.User)
	}
	if err := validate.Password(p.Password); err != nil {
		return res, errf(err.Error(), "password")
	}
	if _, err := groupID(p.User); err == nil {
		return res, errf("user_exists", "a group named %s already exists on this server", p.User)
	}
	home := filepath.Join(a.Cfg.HomeBase, p.User)
	if _, err := os.Lstat(home); err == nil {
		return res, errf("home_exists", "%s already exists", home)
	}
	argv := []string{"useradd", "--create-home", "--home-dir", home, "--shell", "/usr/sbin/nologin", "--user-group", "-K", "UMASK=0027"}
	var groups []string
	if _, gerr := groupID("bpanel-users"); gerr == nil {
		groups = append(groups, "bpanel-users")
	}
	if p.ShellSFTP {
		if _, gerr := groupID("bpanel-sftp"); gerr == nil {
			groups = append(groups, "bpanel-sftp")
		}
	}
	if len(groups) > 0 {
		argv = append(argv, "-G", strings.Join(groups, ","))
	}
	argv = append(argv, p.User)
	// The ownership marker is written BEFORE useradd (R2-PERF-15): a crash
	// between the two used to leave a user without a marker that nothing
	// could adopt or remove. A marker without a user is harmless.
	if err := writeAtomic(a.markerPath(p.User), []byte("created-by=bpanel\n"), 0o600, -1, -1); err != nil {
		return res, errf("marker_failed", "%v", err)
	}
	if _, err := run(ctx, nil, argv...); err != nil {
		_ = os.Remove(a.markerPath(p.User))
		return res, err
	}
	// From here on the user is ours: undo everything on failure.
	ok := false
	defer func() {
		if !ok {
			a.removeCreatedUser(context.WithoutCancel(ctx), p.User, home)
		}
	}()
	e, err := a.home(p.User)
	if err != nil {
		return res, err
	}
	if _, err := run(ctx, []byte(p.User+":"+p.Password+"\n"), "chpasswd"); err != nil {
		return res, err
	}
	if err := a.layoutHome(e); err != nil {
		return res, err
	}
	if err := a.applyLimits(ctx, e, rpc.AccountQuota{User: p.User, QuotaMB: p.QuotaMB, CPUQuota: p.CPUQuota, MemoryMB: p.MemoryMB, MaxTasks: p.MaxTasks}); err != nil {
		a.Log.Warn("limits not fully applied", "user", p.User, "err", err)
	}
	ok = true
	return rpc.AccountCreateResult{UID: e.uid, GID: e.gid, Home: e.home, Created: true}, nil
}

// adoptAccount finishes an interrupted creation of a panel-managed account:
// new password, standard layout, limits. The caller holds the accounts lock.
func (a *Agent) adoptAccount(ctx context.Context, p rpc.AccountCreate) (rpc.AccountCreateResult, error) {
	var res rpc.AccountCreateResult
	if err := validate.Password(p.Password); err != nil {
		return res, errf(err.Error(), "password")
	}
	e, err := a.managedHome(p.User)
	if err != nil {
		return res, err
	}
	if _, err := os.Lstat(e.home); err != nil {
		if _, err := run(ctx, nil, "mkhomedir_helper", p.User); err != nil {
			if err := os.Mkdir(e.home, homeMode); err != nil && !os.IsExist(err) {
				return res, err
			}
			if err := os.Chown(e.home, e.uid, e.gid); err != nil {
				return res, err
			}
		}
	}
	if _, err := run(ctx, []byte(p.User+":"+p.Password+"\n"), "chpasswd"); err != nil {
		return res, err
	}
	if err := a.layoutHome(e); err != nil {
		return res, err
	}
	if err := a.applyLimits(ctx, e, rpc.AccountQuota{User: p.User, QuotaMB: p.QuotaMB, CPUQuota: p.CPUQuota, MemoryMB: p.MemoryMB, MaxTasks: p.MaxTasks}); err != nil {
		a.Log.Warn("limits not fully applied", "user", p.User, "err", err)
	}
	a.Log.Warn("adopted an interrupted panel account", "user", p.User)
	// Created stays true: the account is the panel's, a rollback may remove it
	return rpc.AccountCreateResult{UID: e.uid, GID: e.gid, Home: e.home, Created: true}, nil
}

// layoutHome creates the standard directories of a fresh home without ever
// following a symlink.
func (a *Agent) layoutHome(e passwdEntry) error {
	webGID, err := groupID(a.L.WebGroup)
	if err != nil {
		webGID = e.gid
	}
	st, err := os.Lstat(e.home)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errf("home_unavailable", "%s", e.home)
	}
	// R2-E2E-10: user:<web group> 0710 instead of 0711, skeleton files 0600
	if err := a.secureHome(e); err != nil {
		return err
	}
	root, err := openHome(e)
	if err != nil {
		return err
	}
	defer root.Close()
	dirs := []struct {
		name string
		mode os.FileMode
		gid  int
	}{
		{"public_html", 0o750, webGID}, {"logs", 0o700, e.gid}, {"tmp", 0o700, e.gid},
		{"mail", 0o750, e.gid}, {".bpanel", 0o700, e.gid}, {"etc", 0o750, e.gid}, {"backups", 0o700, e.gid},
	}
	for _, d := range dirs {
		if err := mkdirOwned(root, d.name, d.mode, e.uid, d.gid, true); err != nil {
			return err
		}
	}
	err = createFileOwned(root, "public_html/index.html", []byte(fmt.Sprintf(defaultIndex, e.name)), 0o644, e.uid, e.gid)
	if err != nil {
		var re *rpc.Error
		if errors.As(err, &re) && re.Code == "already_exists" {
			return nil
		}
		return err
	}
	return nil
}

// removeCreatedUser undoes a half-finished accountCreate.
func (a *Agent) removeCreatedUser(ctx context.Context, user, home string) {
	if _, err := run(ctx, nil, "userdel", "--remove", user); err != nil {
		a.Log.Warn("rollback userdel", "user", user, "err", err)
	}
	if st, err := os.Lstat(home); err == nil && st.IsDir() {
		if err := os.RemoveAll(home); err != nil {
			a.Log.Warn("rollback remove home", "user", user, "err", err)
		}
	}
	if err := os.Remove(a.markerPath(user)); err != nil && !os.IsNotExist(err) {
		a.Log.Warn("rollback marker", "user", user, "err", err)
	}
}

func (a *Agent) accountQuota(ctx context.Context, p rpc.AccountQuota) (rpc.Empty, error) {
	e, err := a.managedHome(p.User)
	if err != nil {
		return rpc.Empty{}, err
	}
	return rpc.Empty{}, a.applyLimits(ctx, e, p)
}

// quotaUnsupported recognises setquota failures that mean "this filesystem
// has no user quotas", which is a configuration fact, not an action failure.
func quotaUnsupported(out string) bool {
	o := strings.ToLower(out)
	for _, s := range []string{"no filesystem with quota", "cannot find mountpoint", "quota format not supported",
		"not supported", "quotas are not enabled", "no such process", "cannot open quotafile", "mountpoint with quota"} {
		if strings.Contains(o, s) {
			return true
		}
	}
	return false
}

// homeMount returns the mount point holding home (for setquota), or "".
func homeMount(ctx context.Context, home string) string {
	if !have("findmnt") {
		return ""
	}
	out, err := run(ctx, nil, "findmnt", "-n", "-o", "TARGET", "--target", home)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// applyLimits sets the disk quota (if the filesystem has quotas on) and a
// systemd drop-in for user-<uid>.slice (cgroups v2: CPU, memory, tasks).
// A filesystem without quota support is logged, not treated as a failure.
func (a *Agent) applyLimits(ctx context.Context, e passwdEntry, p rpc.AccountQuota) error {
	if err := a.applyLimitsNoReload(ctx, e, p); err != nil {
		return err
	}
	if !a.Cfg.NoSystemd {
		if _, err := run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
			return errf("limits_failed", "daemon-reload: %v", err)
		}
	}
	return nil
}

// applyLimitsNoReload writes the quota and the slice drop-in; the caller
// runs systemctl daemon-reload (once, for a batch).
func (a *Agent) applyLimitsNoReload(ctx context.Context, e passwdEntry, p rpc.AccountQuota) error {
	if p.QuotaMB < 0 || p.CPUQuota < 0 || p.MemoryMB < 0 || p.MaxTasks < 0 {
		return errf("invalid_limit", "negative limit")
	}
	var errs []string
	if have("setquota") {
		kb := strconv.FormatInt(p.QuotaMB*1024, 10)
		target := []string{"-a"}
		if m := homeMount(ctx, e.home); m != "" {
			target = []string{m}
		}
		args := append([]string{"setquota", "-u", e.name, kb, kb, "0", "0"}, target...)
		if out, err := run(ctx, nil, args...); err != nil {
			if quotaUnsupported(out + err.Error()) {
				a.Log.Warn("disk quotas are not enabled on the home filesystem; quota not applied", "user", e.name)
			} else {
				errs = append(errs, "quota: "+err.Error())
			}
		}
	} else if p.QuotaMB > 0 {
		a.Log.Warn("setquota not installed; disk quota not applied", "user", e.name)
	}
	dropDir := fmt.Sprintf("/etc/systemd/system/user-%d.slice.d", e.uid)
	var b strings.Builder
	b.WriteString("# Managed by BOZKURT PANEL\n[Slice]\n")
	if p.CPUQuota > 0 {
		fmt.Fprintf(&b, "CPUQuota=%d%%\n", p.CPUQuota)
	}
	if p.MemoryMB > 0 {
		fmt.Fprintf(&b, "MemoryMax=%dM\n", p.MemoryMB)
	}
	if p.MaxTasks > 0 {
		fmt.Fprintf(&b, "TasksMax=%d\n", p.MaxTasks)
	}
	if !a.Cfg.NoSystemd {
		if err := writeAtomic(filepath.Join(dropDir, "50-bpanel.conf"), []byte(b.String()), 0o644, -1, -1); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errf("limits_failed", "%s", strings.Join(errs, "; "))
	}
	return nil
}

func (a *Agent) accountSuspend(ctx context.Context, p rpc.AccountSuspend) (rpc.Empty, error) {
	if _, err := a.managedHome(p.User); err != nil {
		return rpc.Empty{}, err
	}
	if p.Suspend {
		// Lock the password and expire the account so key logins and cron stop too.
		if _, err := run(ctx, nil, "usermod", "-L", "-e", "1", p.User); err != nil {
			return rpc.Empty{}, err
		}
		// pkill exits 1 when no process matched; that is fine.
		if _, err := run(ctx, nil, "pkill", "-u", p.User); err != nil {
			a.Log.Info("suspend: pkill", "user", p.User, "err", err)
		}
	} else {
		if _, err := run(ctx, nil, "usermod", "-U", "-e", "", p.User); err != nil {
			return rpc.Empty{}, err
		}
	}
	return rpc.Empty{}, nil
}

// accountTerminate deletes a panel-created account and its home. It refuses
// accounts the panel did not create (no ownership marker), so neither a
// rollback nor "Terminate" can ever delete an operator or system user.
func (a *Agent) accountTerminate(ctx context.Context, p rpc.AccountRef) (rpc.Empty, error) {
	if err := validate.Username(p.User); err != nil && err.Error() == "invalid_username" {
		return rpc.Empty{}, errf(err.Error(), "%s", p.User)
	}
	e, err := a.homeAny(p.User)
	if err != nil {
		var re *rpc.Error
		if errors.As(err, &re) && re.Code == "no_such_user" {
			_ = os.Remove(a.markerPath(p.User))
			return rpc.Empty{}, nil // already gone: idempotent
		}
		return rpc.Empty{}, err
	}
	if !a.isManaged(e) {
		return rpc.Empty{}, errf("not_managed", "user %s was not created by the panel; refusing to delete it", p.User)
	}
	defer a.lock("accounts")()
	if _, err := run(ctx, nil, "pkill", "-KILL", "-u", p.User); err != nil {
		a.Log.Info("terminate: pkill", "user", p.User, "err", err)
	}
	if _, err := run(ctx, nil, "crontab", "-r", "-u", p.User); err != nil {
		a.Log.Info("terminate: crontab -r", "user", p.User, "err", err)
	}
	if _, err := run(ctx, nil, "userdel", "--remove", p.User); err != nil {
		// userdel exits 12 when the mail spool is missing; home removal is what matters
		if _, lerr := lookupUser(p.User); lerr == nil {
			return rpc.Empty{}, err
		}
	}
	if st, serr := os.Lstat(e.home); serr == nil && st.IsDir() {
		if err := os.RemoveAll(e.home); err != nil {
			return rpc.Empty{}, errf("io_error", "remove home: %v", err)
		}
	}
	if err := os.RemoveAll(fmt.Sprintf("/etc/systemd/system/user-%d.slice.d", e.uid)); err != nil {
		a.Log.Warn("terminate: slice drop-in", "err", err)
	}
	if err := os.Remove(a.markerPath(p.User)); err != nil && !os.IsNotExist(err) {
		a.Log.Warn("terminate: marker", "err", err)
	}
	a.releaseAll(p.User) // CODE-27
	return rpc.Empty{}, nil
}

func (a *Agent) accountPassword(ctx context.Context, p rpc.AccountPassword) (rpc.Empty, error) {
	if _, err := a.managedHome(p.User); err != nil {
		return rpc.Empty{}, err
	}
	if err := validate.Password(p.Password); err != nil {
		return rpc.Empty{}, errf(err.Error(), "password")
	}
	_, err := run(ctx, []byte(p.User+":"+p.Password+"\n"), "chpasswd")
	return rpc.Empty{}, err
}

// ---- services ---------------------------------------------------------------

func (a *Agent) allowedUnits() map[string]string {
	l := a.L
	m := map[string]string{
		l.NginxUnit: "Nginx", l.ApacheUnit: "Apache", l.MariaDBUnit: "MariaDB", l.PDNSUnit: "PowerDNS",
		"postfix": "Postfix", "dovecot": "Dovecot", l.RspamdUnit: "Rspamd", l.RedisUnit: "Redis",
		l.FTPUnit: "Pure-FTPd", l.SSHUnit: "OpenSSH", "bpanel-api": "BPANEL API",
	}
	if l.Family == distro.RHEL {
		m["crond"] = "Cron"
	} else {
		m["cron"] = "Cron"
	}
	for _, v := range distro.KnownPHP {
		ph := l.PHPFor(v)
		if _, err := os.Stat(ph.Binary); err == nil {
			m[ph.Unit] = "PHP " + v + " FPM"
		}
	}
	// Services the install profile does not ship are neither listed nor
	// controllable (handoff-installer H-2): no "Apache failed" on minimal.
	for _, u := range l.UnitsNotInProfile(a.Cfg.Profile) {
		delete(m, u)
	}
	for _, u := range a.Cfg.ExtraUnits {
		if extraUnitOK(u) {
			m[u] = u
		} else if a.Log != nil {
			a.Log.Warn("ignoring extra_units entry", "unit", u)
		}
	}
	return m
}

func (a *Agent) serviceStatus(ctx context.Context, p rpc.ServiceStatusReq) (rpc.ServiceStatus, error) {
	allowed := a.allowedUnits()
	units := p.Units
	if len(units) == 0 {
		for u := range allowed {
			units = append(units, u)
		}
	}
	sort.Strings(units)
	var out rpc.ServiceStatus
	for _, u := range units {
		name, ok := allowed[u]
		if !ok {
			continue
		}
		st := rpc.ServiceState{Unit: u, Name: name, Active: "unknown"}
		if !a.Cfg.NoSystemd {
			s, _ := run(ctx, nil, "systemctl", "show", u, "--timestamp=unix",
				"-p", "ActiveState,SubState,UnitFileState,MemoryCurrent,ActiveEnterTimestamp,LoadState")
			kv := map[string]string{}
			for _, line := range strings.Split(s, "\n") {
				k, v, _ := strings.Cut(line, "=")
				kv[k] = v
			}
			if kv["LoadState"] == "not-found" {
				continue
			}
			st.Active, st.Sub, st.Enabled = kv["ActiveState"], kv["SubState"], kv["UnitFileState"]
			st.MemoryBytes, _ = strconv.ParseUint(kv["MemoryCurrent"], 10, 64)
			st.SinceUnix, _ = strconv.ParseInt(strings.TrimPrefix(kv["ActiveEnterTimestamp"], "@"), 10, 64)
		}
		out.Services = append(out.Services, st)
	}
	return out, nil
}

func (a *Agent) serviceAction(ctx context.Context, p rpc.ServiceAction) (rpc.Empty, error) {
	if err := validate.Unit(p.Unit); err != nil {
		return rpc.Empty{}, errf("invalid_unit", "%s", p.Unit)
	}
	if _, ok := a.allowedUnits()[p.Unit]; !ok {
		return rpc.Empty{}, errf("unit_not_allowed", "%s", p.Unit)
	}
	switch p.Action {
	case "start", "stop", "restart", "reload":
	default:
		return rpc.Empty{}, errf("invalid_action", "%s", p.Action)
	}
	if p.Action == "stop" && a.criticalUnit(p.Unit) {
		// R2-WB-14: stopping these from the panel locks the operator out
		// (SSH) or kills the panel itself; restart/reload stay allowed
		return rpc.Empty{}, errf("refused", "stopping %s from the panel is not allowed", p.Unit)
	}
	// Validate configuration before a restart/reload where we can.
	if p.Action != "stop" {
		if err := a.configTest(ctx, p.Unit); err != nil {
			return rpc.Empty{}, err
		}
	}
	return rpc.Empty{}, a.systemctl(ctx, p.Action, p.Unit)
}

// criticalUnit: units the panel may restart but never stop.
func (a *Agent) criticalUnit(u string) bool {
	switch u {
	case "bpanel-api", "bpanel-agent", a.L.SSHUnit, "ssh", "sshd", "ssh.socket":
		return true
	}
	return false
}

// extraUnitOK filters agent.json extra_units (R2-WB-14): a unit name, never
// one of systemd's own units, the agent, SSH, or a target/socket/mount.
func extraUnitOK(u string) bool {
	if validate.Unit(u) != nil || strings.HasPrefix(u, "systemd-") || strings.HasPrefix(u, "dbus") || strings.HasPrefix(u, "getty") ||
		strings.HasPrefix(u, "user@") || u == "bpanel-agent" || u == "ssh" || u == "sshd" || strings.ContainsAny(u, "@") {
		return false
	}
	for _, suf := range []string{".target", ".socket", ".mount", ".slice", ".scope", ".device", ".swap", ".path", ".timer", ".automount"} {
		if strings.HasSuffix(u, suf) {
			return false
		}
	}
	return true
}

func (a *Agent) configTest(ctx context.Context, unit string) error {
	if a.configTestFn != nil {
		return a.configTestFn(ctx, unit)
	}
	switch unit {
	case a.L.NginxUnit:
		if have("nginx") {
			_, err := run(ctx, nil, "nginx", "-t")
			return err
		}
	case a.L.ApacheUnit:
		for _, b := range []string{"apache2ctl", "apachectl"} {
			if have(b) {
				_, err := run(ctx, nil, b, "configtest")
				return err
			}
		}
	case "postfix":
		if have("postfix") {
			_, err := run(ctx, nil, "postfix", "check")
			return err
		}
	case a.L.SSHUnit:
		// a broken sshd_config + restart locks every operator out
		if have("sshd") {
			_, err := run(ctx, nil, "sshd", "-t")
			return err
		}
	default:
		for _, v := range distro.KnownPHP {
			ph := a.L.PHPFor(v)
			if unit == ph.Unit {
				if _, err := os.Stat(ph.Binary); err == nil {
					_, err := run(ctx, nil, ph.Binary, "-t")
					return err
				}
			}
		}
	}
	return nil
}

// ---- logs & disk ------------------------------------------------------------

func (a *Agent) logTail(ctx context.Context, p rpc.LogTail) (rpc.LogLines, error) {
	var out rpc.LogLines
	if err := validate.Domain(p.Domain); err != nil {
		return out, errf("invalid_domain", "%s", p.Domain)
	}
	if err := a.ownsAny(p.Domain, p.User, kindWeb); err != nil { // CODE-27
		return out, err
	}
	kind := "access"
	if p.Kind == "error" {
		kind = "error"
	}
	n := p.Lines
	if n <= 0 || n > 1000 {
		n = 300
	}
	path := filepath.Join("/var/log/bpanel/domlogs", p.Domain+"."+kind+".log")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return out, err
	}
	const max = 512 << 10
	off := int64(0)
	if st.Size() > max {
		off = st.Size() - max
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return out, err
	}
	b, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil {
		return out, err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if off > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	// newest first, like the classic Errors screen
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}
	out.Lines = lines
	return out, nil
}

func (a *Agent) diskUsage(ctx context.Context, p rpc.DiskUsageReq) (rpc.DiskUsage, error) {
	var out rpc.DiskUsage
	e, err := a.home(p.User)
	if err != nil {
		return out, err
	}
	return walkUsage(ctx, e.home)
}

// walkUsage sums allocated bytes per top-level entry without following symlinks.
func walkUsage(ctx context.Context, root string) (rpc.DiskUsage, error) {
	var out rpc.DiskUsage
	per := map[string]int64{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		sz := info.Size()
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			sz = st.Blocks * 512
		}
		out.Inodes++
		out.TotalBytes += sz
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil || rel == "." {
			return nil
		}
		top, _, _ := strings.Cut(rel, string(filepath.Separator))
		per[top] += sz
		return nil
	})
	for k, v := range per {
		out.Entries = append(out.Entries, rpc.DiskEntry{Path: k, Bytes: v})
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Bytes > out.Entries[j].Bytes })
	return out, err
}
