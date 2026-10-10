package installer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cumabozkurt/bpanel/internal/agent"
	"github.com/cumabozkurt/bpanel/internal/distro"
)

// LibDir keeps a copy of the release binaries, the installer included, so
// `bpanel-installer upgrade|uninstall` works without the original archive
// (R2-SYS-17). /usr/local/sbin/bpanel-installer links to it.
const (
	LibDir        = "/usr/local/lib/bpanel"
	installerLink = "/usr/local/sbin/bpanel-installer"
)

// releaseBinaries are the files of a release archive.
var releaseBinaries = []string{"bpanel-installer", "bpanel-api", "bpanel-agent", "bpanel"}

// keepInstaller copies the release binaries to LibDir (unless they already
// run from there) and links bpanel-installer into /usr/local/sbin.
func (in *Installer) keepInstaller(ctx context.Context, src string) error {
	if err := os.MkdirAll(LibDir, 0o755); err != nil {
		return err
	}
	exe, _ := os.Executable()
	for _, b := range releaseBinaries {
		p := filepath.Join(src, b)
		if _, err := os.Stat(p); err != nil {
			if b != "bpanel-installer" || exe == "" {
				continue
			}
			p = exe
		}
		dst := filepath.Join(LibDir, b)
		if same(p, dst) {
			continue
		}
		if err := in.sh(ctx, "install", "-m", "0755", "-o", "root", "-g", "root", p, dst); err != nil {
			return err
		}
	}
	if t, err := os.Readlink(installerLink); err == nil && t == filepath.Join(LibDir, "bpanel-installer") {
		return nil
	}
	if fi, err := os.Lstat(installerLink); err == nil && fi.Mode().IsRegular() {
		return nil // an administrator's own file: leave it
	}
	tmp := installerLink + ".bpanel-new"
	_ = os.Remove(tmp)
	if err := os.Symlink(filepath.Join(LibDir, "bpanel-installer"), tmp); err != nil {
		return err
	}
	return os.Rename(tmp, installerLink)
}

// same reports whether a and b are the same file (also through symlinks).
func same(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}

// ------------------------------------------------------------------ PHP ----

var phpVersionRE = regexp.MustCompile(`^[5-9]\.[0-9]{1,2}$`)

func (in *Installer) phpInstalled(v string) bool {
	if !phpVersionRE.MatchString(v) {
		return false
	}
	_, err := os.Stat(in.L.PHPFor(v).Binary)
	return err == nil
}

// detectPHP returns the PHP version new accounts should use: the
// distribution's PHP when its FPM is installed, else the first installed of
// the extra and common versions; "" when none is (test mode).
func (in *Installer) detectPHP() string {
	cands := appendUnique([]string{in.L.DefaultPHP}, in.O.ExtraPHP...)
	cands = appendUnique(cands, "8.4", "8.3", "8.2", "8.1", "8.5")
	for _, v := range cands {
		if in.phpInstalled(v) {
			return v
		}
	}
	return ""
}

// --------------------------------------------------------- capabilities ----

// CapabilitiesFile tells the API (and operators) which features the
// installed profile provides. It is root:bpanel 0640, rewritten by every
// install and upgrade. The same flags are stored as settings in the panel
// database (feature_apache, feature_dns, feature_ftp, feature_mail,
// feature_webmail), which is what the API reads today. See
// docs/capabilities.md.
const CapabilitiesFile = "/etc/bpanel/capabilities.json"

// Capabilities of an installation.
type Capabilities struct {
	Version  string          `json:"version"`
	Profile  string          `json:"profile"`
	Features map[string]bool `json:"features"`
	// DefaultPHP is the PHP version installed as the distribution default.
	DefaultPHP string `json:"default_php,omitempty"`
	// DovecotSyntax is "2.3" or "2.4" (full profile). Dovecot 2.4 reads the
	// mailbox quota from userdb_quota_storage_size=<N>M instead of
	// userdb_quota_rule=*:storage=<N>M.
	DovecotSyntax string `json:"dovecot_syntax,omitempty"`
}

// ProfileFeatures returns the features of a profile.
func ProfileFeatures(profile string) map[string]bool {
	web, full := profile != "minimal", profile == "full"
	return map[string]bool{
		"web": true, "php": true, "mysql": true, "phpmyadmin": true, "sftp": true, "backups": true, "cron": true,
		"apache": web, "dns": web, "ftp": web,
		"mail": full, "webmail": full, "spamfilter": full,
	}
}

// Settings returns the panel-database settings for the flags the API reads.
func (c Capabilities) Settings() map[string]string {
	b := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	m := map[string]string{}
	for _, k := range []string{"apache", "dns", "ftp", "mail", "webmail"} {
		m["feature_"+k] = b(c.Features[k])
	}
	if c.DovecotSyntax != "" {
		m["dovecot_syntax"] = c.DovecotSyntax
	}
	return m
}

func (in *Installer) capabilities(ctx context.Context) Capabilities {
	c := Capabilities{Version: in.Version, Profile: in.O.Profile, Features: ProfileFeatures(in.O.Profile), DefaultPHP: in.detectPHP()}
	if in.full() {
		c.DovecotSyntax = "2.3"
		if DovecotVersion24(in.dovecotVersion(ctx)) {
			c.DovecotSyntax = "2.4"
		}
	}
	return c
}

func (in *Installer) writeCapabilities(ctx context.Context, c Capabilities) error {
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := in.writeFile(CapabilitiesFile, string(b)+"\n", 0o640); err != nil {
		return err
	}
	return in.sh(ctx, "chown", "root:bpanel", CapabilitiesFile)
}

// -------------------------------------------------------------- upgrade ----

// VersionLess compares dotted versions ("0.1.0" < "0.2.0"; a suffix such
// as "-rc1" or "+dev" is ignored).
func VersionLess(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func versionParts(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+ "); i >= 0 {
		v = v[:i]
	}
	for i, p := range strings.SplitN(v, ".", 3) {
		n, _ := strconv.Atoi(p)
		out[i] = n
	}
	return out
}

// installed reports whether a previous installation reached the panel stage.
func (in *Installer) installed() bool { return in.done("panel") }

// Upgrade brings an existing installation to this release (R2-SYS-10):
// missing packages, the system hardening of the new release, the service
// configuration, new binaries and units, database migrations (run by the
// API bootstrap) and file migrations, then the self-test. Every step is
// recorded as "upgrade-<version>:<step>", so an interrupted upgrade resumes
// and a repeated one changes nothing. Websites, mail and data keep running.
func (in *Installer) Upgrade(ctx context.Context) error {
	if !in.installed() {
		return fmt.Errorf(T(in.O.Lang, "upgrade_none"), StateFile)
	}
	from := in.S.Version
	if from == "" {
		from = "0.1.0"
	}
	if VersionLess(in.Version, from) && !in.O.Force {
		return fmt.Errorf(T(in.O.Lang, "upgrade_newer"), from, in.Version)
	}
	in.upgrading = true
	if in.S.Profile != "" {
		in.O.Profile = in.S.Profile // the installed profile, not the flag default
	}
	if in.O.Hostname == "" {
		in.O.Hostname = in.S.Hostname
	}
	if in.O.Email == "" {
		if c, err := agent.LoadConfig("/etc/bpanel/agent.json"); err == nil {
			in.O.Email = c.ACMEEmail
		}
	}
	if from == in.Version {
		in.say("upgrade_current", in.Version)
	} else {
		in.say("upgrade_start", from, in.Version, in.O.Profile)
	}
	prefix := "upgrade-" + in.Version + ":"
	if in.O.Force {
		var keep []string
		for _, d := range in.S.Done {
			if !strings.HasPrefix(d, prefix) {
				keep = append(keep, d)
			}
		}
		in.S.Done = keep
	}
	steps := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"preflight", in.upgradePreflight},
		{"backup", in.upgradeBackup}, // v0.4 instx: DB + /etc/bpanel before anything changes
		{"packages", in.upgradePackages},
		{"restic", in.installRestic},
		{"system", in.system},
		{"configs", in.configs},
		{"panel", in.panel},
	}
	for i, s := range steps {
		label := T(in.O.Lang, "stage.upgrade") + ": " + s.name
		if in.done(prefix + s.name) {
			in.say("stage_skip", i+1, len(steps), label)
			continue
		}
		in.say("stage_start", i+1, len(steps), label)
		start := time.Now()
		if err := in.step(prefix+s.name, func() error { return s.fn(ctx) }); err != nil {
			in.save()
			in.say("stage_fail", label, err)
			in.say("resume_hint", LogFile)
			return err
		}
		in.say("stage_ok", label, time.Since(start).Round(time.Second))
	}
	in.S.Version = in.Version
	for _, st := range []string{"hostname-ssl", "selftest"} {
		in.S.Done = appendUnique(in.S.Done, st)
	}
	in.save()
	in.say("stage_start", len(steps), len(steps), T(in.O.Lang, "stage.selftest"))
	if err := in.selftest(ctx); err != nil {
		in.say("stage_fail", T(in.O.Lang, "stage.selftest"), err)
		return err
	}
	fmt.Fprintf(in.out, T(in.O.Lang, "upgrade_done")+"\n", in.Version)
	return in.summary(ctx)
}

func (in *Installer) upgradePreflight(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("%s", T(in.O.Lang, "not_root"))
	}
	if !in.L.Supported() && !in.O.AllowUnsupported {
		return fmt.Errorf(T(in.O.Lang, "unsupported"), in.L.Pretty)
	}
	return nil
}

// missingPackages returns the packages of list that are not installed.
func (in *Installer) missingPackages(list []string) []string {
	var miss []string
	for _, p := range list {
		var err error
		if in.L.Family == distro.Debian {
			var out []byte
			out, err = exec.Command("dpkg-query", "-W", "-f=${Status}", p).Output()
			if err == nil && !strings.Contains(string(out), "install ok installed") {
				err = fmt.Errorf("not installed")
			}
		} else {
			err = exec.Command("rpm", "-q", "--whatprovides", p).Run()
		}
		if err != nil {
			miss = append(miss, p)
		}
	}
	return miss
}

// upgradePackages installs only the packages a newer release added (for
// example openssh-server in 0.3); installed packages are not upgraded here.
func (in *Installer) upgradePackages(ctx context.Context) error {
	want := append(PackageList(in.L, in.O.Profile, in.O.ExtraPHP), V04Packages(in.L, in.O.Profile)...) // v0.4 instx
	miss := in.missingPackages(want)
	in.S.Packages = appendUnique(in.S.Packages, want...)
	defer in.v04Optional(ctx) // v0.4 instx: optional packages, warnings only
	if len(miss) == 0 {
		return nil
	}
	in.logf("upgrade: installing missing packages %s", strings.Join(miss, " "))
	if in.L.Family != distro.Debian {
		return in.sh(ctx, append([]string{"dnf", "-y", "install"}, miss...)...)
	}
	if err := in.aptRecover(ctx); err != nil {
		return err
	}
	if err := in.apt(ctx, "update"); err != nil {
		return err
	}
	return in.apt(ctx, append([]string{"install"}, miss...)...)
}

// ---------------------------------------------------------- restic unlock --

// ResticUnlock removes stale locks from every account's restic repository
// (R2-PERF-14). It runs as ExecStartPre of bpanel-agent.service: a backup
// killed with the agent (kill -9, OOM, power loss) leaves its lock behind
// and every later backup of that account fails until it is removed. Only
// the agent runs restic, so no lock can be live while the agent starts.
// `restic unlock` without --remove-all only removes stale locks anyway.
func ResticUnlock(ctx context.Context, agentConfig string) error {
	cfg, _ := agent.LoadConfig(agentConfig) // defaults when the file is missing
	if _, err := os.Stat(cfg.ResticBin); err != nil {
		return nil
	}
	entries, err := os.ReadDir(cfg.BackupRepo)
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var failed []string
	for _, e := range entries {
		repo := filepath.Join(cfg.BackupRepo, e.Name())
		pw := filepath.Join(cfg.ResticPassDir, e.Name()+".pass")
		locks, _ := os.ReadDir(filepath.Join(repo, "locks"))
		if !e.IsDir() || len(locks) == 0 {
			continue
		}
		if _, err := os.Stat(pw); err != nil {
			continue
		}
		cctx, c := context.WithTimeout(ctx, 15*time.Second)
		cmd := exec.CommandContext(cctx, cfg.ResticBin, "unlock")
		cmd.Env = []string{"RESTIC_REPOSITORY=" + repo, "RESTIC_PASSWORD_FILE=" + pw, "RESTIC_CACHE_DIR=" + ResticCacheDir,
			"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/root"}
		out, err := cmd.CombinedOutput()
		c()
		if err != nil {
			failed = append(failed, e.Name())
			fmt.Fprintf(os.Stderr, "restic unlock %s: %v: %s\n", e.Name(), err, strings.TrimSpace(string(out)))
		} else if s := strings.TrimSpace(string(out)); s != "" {
			fmt.Printf("restic unlock %s: %s\n", e.Name(), s)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("restic unlock failed for %s", strings.Join(failed, ", "))
	}
	return nil
}
