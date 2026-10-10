package installer

// v0.4 provisioning (worker "instx"): the packages, directories, Postfix
// transport, systemd template, time sync and optional profiles that the v0.4
// modules (mailx/dnsx mailing lists, appx, webx, xfer, shield FIM, clusterx
// plugins, msrv nodes, obsx) expect. Everything here is free software from the
// distribution repositories (Ubuntu 24.04 main/universe, AlmaLinux 9 BaseOS/
// AppStream/EPEL) plus the free official rspamd repository already added by
// repos(). Nothing is linked into the binary; every program runs as a
// separate process.

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cumabozkurt/bpanel/internal/agent"
	"github.com/cumabozkurt/bpanel/internal/appx"
	"github.com/cumabozkurt/bpanel/internal/distro"
)

// AppUnitPath is where the appx template unit is installed.
const AppUnitPath = "/etc/systemd/system/bpanel-app@.service"

// NodeRemoteListen is the default mTLS listener of a --node install (msrv).
const NodeRemoteListen = ":8445"

// MlmmjSpool is the mlmmj list spool (matches internal/agent/dnsx.go).
const MlmmjSpool = "/var/spool/mlmmj"

// V04Packages returns the extra packages v0.4 needs that every install gets
// (failure aborts the packages stage, like the base list).
func V04Packages(l *distro.Layout, profile string) []string {
	// chrony: time sync (obsx health "time_sync", TOTP, TLS); traceroute:
	// obsx network diagnostics; git: devx deploy-from-git. All free, in the
	// base repositories of both distributions.
	return []string{"chrony", "traceroute", "git"}
}

// OptionalPackage is installed one by one; a failure is a warning, never an
// abort, and the feature that needs it reports not_installed.
type OptionalPackage struct {
	Name   string
	Reason string
}

// V04OptionalPackages lists packages whose availability differs between the
// distributions or which are opt-in (--with-crowdsec, --with-smart).
func V04OptionalPackages(l *distro.Layout, o Options) []OptionalPackage {
	var p []OptionalPackage
	if o.Profile == "full" {
		// mlmmj: Ubuntu universe; AlmaLinux 9 via EPEL when available.
		p = append(p, OptionalPackage{"mlmmj", "mailing lists (dnsx)"})
	}
	if o.Smart {
		p = append(p, OptionalPackage{"smartmontools", "disk health (obsx)"})
	}
	if o.CrowdSec {
		// CrowdSec engine (MIT) + nftables bouncer (MIT). Free community
		// blocklists only; no paid console/subscription is configured.
		if l.Family == distro.Debian {
			p = append(p, OptionalPackage{"crowdsec", "CrowdSec engine"}, OptionalPackage{"crowdsec-firewall-bouncer", "CrowdSec nftables bouncer"})
		}
	}
	return p
}

// V04Dirs are the directories of the v0.4 modules. All root-owned: only the
// root agent writes them.
func V04Dirs() []Dir {
	return []Dir{
		{"/var/lib/bpanel/xfer", 0o700, "root:root"},    // migrations/transfers (xfer)
		{"/var/lib/bpanel/webx", 0o700, "root:root"},    // per-domain web extras state (webx)
		{"/var/lib/bpanel/appx", 0o750, "root:root"},    // app units + proxy maps (appx)
		{"/var/lib/bpanel/fim", 0o700, "root:root"},     // file-integrity baselines (shield)
		{"/var/lib/bpanel/plugins", 0o750, "root:root"}, // plugin state (clusterx)
		{"/usr/local/bpanel", 0o755, "root:root"},
		{"/usr/local/bpanel/plugins", 0o755, "root:root"}, // installed plugins (clusterx)
	}
}

// MlmmjMasterEntry is the Postfix master.cf service (postconf -M) for mlmmj.
// $nexthop is "<domain>/<list>" (dnsx.TransportMap).
const MlmmjMasterEntry = "mlmmj/unix=mlmmj unix - n n - - pipe flags=ORhu user=mlmmj argv=/usr/bin/mlmmj-receive -F -L " + MlmmjSpool + "/$nexthop"

// MlmmjTransportPath is the managed transport map (written by the agent).
func MlmmjTransportPath(l *distro.Layout) string {
	return filepath.Join(l.PostfixDir, "bpanel_mlmmj_transport")
}

// V04PostfixSettings are the main.cf settings for the mailing-list transport.
func V04PostfixSettings(l *distro.Layout) []string {
	return []string{
		"transport_maps=" + PostfixMapType(l) + ":" + MlmmjTransportPath(l),
		"recipient_delimiter=+",
		"mlmmj_destination_recipient_limit=1",
	}
}

// ChronyUnit is the chrony service name.
func ChronyUnit(l *distro.Layout) string {
	if l.Family == distro.RHEL {
		return "chronyd"
	}
	return "chrony"
}

// v04Packages installs the optional packages (warning on failure).
func (in *Installer) v04Optional(ctx context.Context) {
	for _, p := range V04OptionalPackages(in.L, in.O) {
		var err error
		if in.L.Family == distro.Debian {
			err = in.apt(ctx, "install", p.Name)
		} else {
			err = in.sh(ctx, "dnf", "-y", "install", p.Name)
		}
		if err != nil {
			in.warn(fmt.Sprintf("optional package %s (%s) could not be installed; the feature reports not_installed", p.Name, p.Reason))
			continue
		}
		in.S.Packages = appendUnique(in.S.Packages, p.Name)
	}
	if in.O.CrowdSec && in.L.Family != distro.Debian {
		in.warn("--with-crowdsec: CrowdSec is not in the AlmaLinux 9 base/EPEL repositories; add the free official CrowdSec repository manually (see docs/installation.md)")
	}
}

// cfgV04 is the configs sub-step for v0.4. Idempotent: postconf -e/-M
// replace values, files are rewritten with identical content.
func (in *Installer) cfgV04(ctx context.Context) error {
	for _, d := range V04Dirs() {
		if err := os.MkdirAll(d.Path, d.Mode); err != nil {
			return err
		}
		if err := os.Chmod(d.Path, d.Mode); err != nil {
			return err
		}
	}
	// appx template unit (the agent re-writes it too; same content)
	if err := in.writeFile(AppUnitPath, appx.UnitTemplate, 0o644); err != nil {
		return err
	}
	if !in.O.NoSystemd {
		_ = in.systemctl(ctx, "daemon-reload")
	}
	if in.full() && have("postconf") {
		if err := in.cfgMlmmj(ctx); err != nil {
			return err
		}
	}
	if have("chronyc") {
		if err := in.systemctl(ctx, "enable", "--now", ChronyUnit(in.L)); err != nil {
			in.warn("chrony could not be enabled: time sync reports not_installed")
		}
	}
	if in.O.CrowdSec && have("cscli") {
		for _, u := range []string{"crowdsec", "crowdsec-firewall-bouncer"} {
			if err := in.systemctl(ctx, "enable", "--now", u); err != nil {
				in.warn(u + " could not be enabled")
			}
		}
	}
	return nil
}

func (in *Installer) cfgMlmmj(ctx context.Context) error {
	if !userExists("mlmmj") {
		if err := in.sh(ctx, "useradd", "--system", "--home-dir", MlmmjSpool, "--no-create-home", "--shell", "/usr/sbin/nologin", "mlmmj"); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(MlmmjSpool, 0o700); err != nil {
		return err
	}
	if err := in.sh(ctx, "chown", "mlmmj:mlmmj", MlmmjSpool); err != nil {
		return err
	}
	tp := MlmmjTransportPath(in.L)
	if _, err := os.Stat(tp); os.IsNotExist(err) { // never clobber the agent's map
		if err := in.writeFile(tp, "# Managed by BOZKURT PANEL (mailing lists, mlmmj). Do not edit.\n", 0o644); err != nil {
			return err
		}
	}
	if err := in.sh(ctx, "postmap", PostfixMapType(in.L)+":"+tp); err != nil {
		return err
	}
	if err := in.sh(ctx, "postconf", "-M", MlmmjMasterEntry); err != nil {
		return err
	}
	if err := in.sh(ctx, append([]string{"postconf", "-e"}, V04PostfixSettings(in.L)...)...); err != nil {
		return err
	}
	if !have("mlmmj-receive") {
		in.warn("mlmmj is not installed: mailing lists report not_installed (transport is configured)")
	}
	if !in.O.NoSystemd {
		return in.systemctl(ctx, "reload", "postfix")
	}
	return nil
}

// ---------------------------------------------------------------- node ----

// NodeAgentConfig turns an agent config into a multi-server node config.
func NodeAgentConfig(c agent.Config, listen string) agent.Config {
	if listen == "" {
		listen = NodeRemoteListen
	}
	if c.RemoteListen == "" {
		c.RemoteListen = listen
	}
	return c
}

// NodeJoinInstructions is printed at the end of a --node install.
func NodeJoinInstructions(listen string) string {
	if listen == "" {
		listen = NodeRemoteListen
	}
	return fmt.Sprintf(`Node mode: this server runs the BOZKURT PANEL agent only (no panel UI/API).
1. On the main panel open Servers -> Add server and copy the one-time join token.
2. Here run:  bpanel-agent join --panel https://<main-panel-host>:2083 --token bpj_...
3. Restart the agent: systemctl restart bpanel-agent
The agent's mTLS listener is %s (open it only to the main panel's IP).
`, listen)
}

// nodeMode runs after "panel" for --node: remote_listen set, the API and
// web UI units disabled, join instructions printed. Idempotent.
func (in *Installer) nodeMode(ctx context.Context) error {
	if !in.O.Node {
		return nil
	}
	const p = "/etc/bpanel/agent.json"
	c := agent.DefaultConfig()
	if b, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	c = NodeAgentConfig(c, in.O.RemoteListen)
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := in.writeFile(p, string(b)+"\n", 0o600); err != nil {
		return err
	}
	if !in.O.NoSystemd {
		_ = in.systemctl(ctx, "disable", "--now", "bpanel-api")
		_ = in.systemctl(ctx, "restart", "bpanel-agent")
	}
	fmt.Fprint(in.out, NodeJoinInstructions(c.RemoteListen))
	return nil
}

// ------------------------------------------------------------- upgrade ----

// UpgradeBackupDir is where the pre-upgrade backup goes.
var UpgradeBackupDir = "/var/backups/bpanel"

// BackupForUpgrade copies the panel database (a consistent VACUUM INTO
// snapshot, safe while the API runs) and a tar.gz of etcDir into a new
// directory under dest. Returns that directory.
func BackupForUpgrade(dbPath, etcDir, dest, from, to string) (string, error) {
	dir := filepath.Join(dest, fmt.Sprintf("upgrade-%s-to-%s-%s", from, to, time.Now().UTC().Format("20060102T150405Z")))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if _, err := os.Stat(dbPath); err == nil {
		db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
		if err != nil {
			return "", err
		}
		_, err = db.Exec(`VACUUM INTO ?`, filepath.Join(dir, "bpanel.db"))
		db.Close()
		if err != nil {
			return "", fmt.Errorf("database backup: %w", err)
		}
	}
	if fi, err := os.Stat(etcDir); err == nil && fi.IsDir() {
		if err := tarDir(etcDir, filepath.Join(dir, "etc-bpanel.tar.gz")); err != nil {
			return "", fmt.Errorf("config backup: %w", err)
		}
	}
	return dir, nil
}

func tarDir(src, out string) error {
	f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	base := filepath.Dir(src)
	var paths []string
	err = filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		paths = append(paths, p)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(paths)
	for _, p := range paths {
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		link := ""
		if fi.Mode()&os.ModeSymlink != 0 {
			link, _ = os.Readlink(p)
		}
		h, err := tar.FileInfoHeader(fi, link)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(base, p)
		h.Name = rel
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			r, err := os.Open(p)
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, r)
			r.Close()
			if err != nil {
				return err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func (in *Installer) upgradeBackup(ctx context.Context) error {
	from := in.S.Version
	if from == "" {
		from = "unknown"
	}
	dir, err := BackupForUpgrade("/var/lib/bpanel/db/bpanel.db", "/etc/bpanel", UpgradeBackupDir, from, in.Version)
	if err != nil {
		return err
	}
	in.logf("pre-upgrade backup in %s", dir)
	fmt.Fprintf(in.out, "  backup: %s\n", dir)
	return nil
}

// -------------------------------------------------------------- doctor ----

// DoctorItem is one v0.4 service check of `bpanel selftest`/doctor.
type DoctorItem struct {
	Name     string
	Status   string // ok | missing | inactive
	Detail   string
	Required bool // by the installed profile
}

// doctorProbe is swapped in tests.
var doctorProbe = struct {
	have   func(string) bool
	active func(string) bool
	exists func(string) bool
}{
	have:   have,
	active: func(u string) bool { return osexec.Command("systemctl", "is-active", "--quiet", u).Run() == nil },
	exists: func(p string) bool { _, err := os.Stat(p); return err == nil },
}

// V04Doctor checks the services the v0.4 modules depend on.
func V04Doctor(l *distro.Layout, profile string) []DoctorItem {
	full, web := profile == "full", profile != "minimal"
	svc := func(name, bin, unit string, req bool) DoctorItem {
		it := DoctorItem{Name: name, Required: req}
		switch {
		case !doctorProbe.have(bin):
			it.Status, it.Detail = "missing", bin+" not installed"
		case unit != "" && !doctorProbe.active(unit):
			it.Status, it.Detail = "inactive", unit+" is not running"
		default:
			it.Status = "ok"
		}
		return it
	}
	out := []DoctorItem{
		svc("fail2ban", "fail2ban-client", "fail2ban", true),
		svc("chrony", "chronyc", ChronyUnit(l), false),
		svc("pdns", "pdns_server", l.PDNSUnit, web),
		svc("rspamd", "rspamd", "rspamd", full),
		svc("mlmmj", "mlmmj-receive", "", false),
		svc("restic", "restic", "", false),
	}
	sieve := DoctorItem{Name: "sieve (pigeonhole)", Required: full, Status: "ok"}
	if !doctorProbe.have("sievec") {
		sieve.Status, sieve.Detail = "missing", "dovecot sieve/managesieve (pigeonhole) not installed"
	}
	out = append(out, sieve)
	unit := DoctorItem{Name: "bpanel-app@ template", Status: "ok"}
	if !doctorProbe.exists(AppUnitPath) {
		unit.Status, unit.Detail = "missing", AppUnitPath+" not installed"
	}
	return append(out, unit)
}

// FormatDoctor renders the items; failures counts required items not ok.
func FormatDoctor(items []DoctorItem) (string, int) {
	var b strings.Builder
	fail := 0
	for _, it := range items {
		mark := "✓"
		if it.Status != "ok" {
			mark = "·"
			if it.Required {
				mark = "✗"
				fail++
			}
		}
		line := fmt.Sprintf("  %s %-24s %s", mark, it.Name, it.Status)
		if it.Detail != "" {
			line += " (" + it.Detail + ")"
		}
		b.WriteString(line + "\n")
	}
	return b.String(), fail
}
