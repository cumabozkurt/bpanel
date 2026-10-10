// Package installer is the staged, resumable installation engine behind
// `bpanel-installer` (started by install.sh). Every stage checks, applies,
// verifies and records itself in /var/lib/bpanel/install-state.json, so a
// re-run continues where the previous run stopped.
package installer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cumabozkurt/bpanel/internal/distro"
)

const (
	StateFile = "/var/lib/bpanel/install-state.json"
	LogFile   = "/var/log/bpanel/install.log"
)

// Options come from the command line.
type Options struct {
	Hostname         string
	Email            string
	Profile          string // minimal | web | full
	Lang             string // en | tr (installer output + panel default)
	Yes              bool
	Force            bool
	AllowUnsupported bool
	NoSystemd        bool   // test mode: do not start/enable services
	Stages           string // comma list to run only these (development)
	AdminUser        string
	ExtraPHP         []string
	BinDir           string // where the bpanel binaries are
	SkipRepos        bool
	PostgreSQL       bool   // v0.4 dbx: optional PostgreSQL engine (--with-postgresql)
	CrowdSec         bool   // v0.4 instx: optional CrowdSec engine + nftables bouncer (--with-crowdsec)
	Smart            bool   // v0.4 instx: optional smartmontools (--with-smart)
	Node             bool   // v0.4 instx: multi-server node (agent only, --node)
	RemoteListen     string // v0.4 instx: node mTLS listener (default :8445)
}

// State is persisted between runs.
type State struct {
	Version   string            `json:"version"`
	Started   time.Time         `json:"started"`
	Updated   time.Time         `json:"updated"`
	Profile   string            `json:"profile"`
	Hostname  string            `json:"hostname"`
	Done      []string          `json:"done"`
	Packages  []string          `json:"packages"`
	Files     []string          `json:"files"`
	Repos     []string          `json:"repos"`
	Secrets   map[string]string `json:"-"`
	Warnings  []string          `json:"warnings"`
	Reboot    bool              `json:"reboot_required"`
	AdminPass string            `json:"-"`
	ServerIP  string            `json:"server_ip"`
	// Prev records what the system looked like before the installer changed
	// it (firewall, resolv.conf, SELinux booleans) so uninstall can restore it.
	Prev map[string]string `json:"prev,omitempty"`
	// Disabled maps a stock file the installer moved out of the way to where
	// it was moved (outside every include glob).
	Disabled map[string]string `json:"disabled,omitempty"`
}

// CacheDir is the root-only download directory (never the shared /tmp).
const CacheDir = "/var/cache/bpanel"

type Installer struct {
	O       Options
	L       *distro.Layout
	S       *State
	log     io.Writer
	out     io.Writer
	Version string
	// upgrading is set by Upgrade: settings the administrator changed
	// after the install are kept.
	upgrading bool
}

type stage struct {
	name string
	run  func(context.Context) error
}

func New(o Options, version string) (*Installer, error) {
	l, err := distro.Detect()
	if err != nil {
		return nil, err
	}
	if o.Profile == "" {
		o.Profile = "full"
	}
	if o.Lang == "" {
		o.Lang = "en"
	}
	if o.AdminUser == "" {
		o.AdminUser = "bpadmin"
	}
	if err := ValidateOptions(o); err != nil { // R2-WB-15
		return nil, err
	}
	in := &Installer{O: o, L: l, out: os.Stdout, Version: version}
	if err := os.MkdirAll(filepath.Dir(LogFile), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	in.log = f
	in.S = in.loadState()
	return in, nil
}

func (in *Installer) loadState() *State {
	s := &State{Version: in.Version, Started: time.Now(), Profile: in.O.Profile, Hostname: in.O.Hostname}
	if b, err := os.ReadFile(StateFile); err == nil {
		if err := json.Unmarshal(b, s); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s is corrupt (%v); starting a fresh state\n", StateFile, err)
		}
		if in.O.Hostname == "" {
			in.O.Hostname = s.Hostname
		}
	}
	if s.Prev == nil {
		s.Prev = map[string]string{}
	}
	if s.Disabled == nil {
		s.Disabled = map[string]string{}
	}
	return s
}

// save writes the state atomically (a crash mid-write must not lose it).
func (in *Installer) save() {
	in.S.Updated = time.Now()
	if err := os.MkdirAll(filepath.Dir(StateFile), 0o751); err != nil {
		in.logf("save state: %v", err)
		return
	}
	b, _ := json.MarshalIndent(in.S, "", "  ")
	tmp := StateFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		in.logf("save state: %v", err)
		return
	}
	if err := os.Rename(tmp, StateFile); err != nil {
		in.logf("save state: %v", err)
	}
}

// step runs fn once per installation: sub-steps of a long stage are recorded
// as "<stage>:<step>" so a re-run after an interruption skips finished work.
func (in *Installer) step(name string, fn func() error) error {
	if in.done(name) {
		in.logf("step %s already done", name)
		return nil
	}
	if err := fn(); err != nil {
		return err
	}
	in.S.Done = append(in.S.Done, name)
	in.save()
	return nil
}

func appendUnique(list []string, v ...string) []string {
	for _, x := range v {
		found := false
		for _, y := range list {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			list = append(list, x)
		}
	}
	return list
}

func (in *Installer) done(name string) bool {
	for _, d := range in.S.Done {
		if d == name {
			return true
		}
	}
	return false
}

func (in *Installer) logf(format string, a ...any) {
	fmt.Fprintf(in.log, time.Now().Format("2006-01-02T15:04:05 ")+format+"\n", a...)
}

// say prints a translated progress line.
func (in *Installer) say(key string, a ...any) {
	msg := fmt.Sprintf(T(in.O.Lang, key), a...)
	fmt.Fprintln(in.out, msg)
	in.logf("%s", msg)
}

func (in *Installer) warn(msg string) {
	in.S.Warnings = append(in.S.Warnings, msg)
	fmt.Fprintln(in.out, "  ! "+msg)
	in.logf("WARN %s", msg)
}

// sh runs argv with output going to the log; never through a shell.
func (in *Installer) sh(ctx context.Context, argv ...string) error {
	_, err := in.shOut(ctx, nil, argv...)
	return err
}

func (in *Installer) shOut(ctx context.Context, stdin []byte, argv ...string) (string, error) {
	in.logf("$ %s", strings.Join(argv, " "))
	cctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C.UTF-8")
	if stdin != nil {
		cmd.Stdin = strings.NewReader(string(stdin))
	}
	var buf strings.Builder
	cmd.Stdout = io.MultiWriter(in.log, &buf)
	cmd.Stderr = io.MultiWriter(in.log, &buf)
	err := cmd.Run()
	if err != nil {
		tail := buf.String()
		if len(tail) > 800 {
			tail = tail[len(tail)-800:]
		}
		return buf.String(), fmt.Errorf("%s: %v\n%s", argv[0], err, strings.TrimSpace(tail))
	}
	return buf.String(), nil
}

// systemctl is skipped in --no-systemd test mode.
func (in *Installer) systemctl(ctx context.Context, args ...string) error {
	if in.O.NoSystemd {
		in.logf("no-systemd: skip systemctl %s", strings.Join(args, " "))
		return nil
	}
	return in.sh(ctx, append([]string{"systemctl"}, args...)...)
}

// writeFile writes a managed file atomically, remembering it in the
// manifest. The first time an existing file is replaced, its content is kept
// as <path>.bpanel-orig (mode 0600) and its owner/group are carried over to
// the new file (e.g. root:pdns on pdns.conf). The mode is set explicitly so
// the process umask cannot widen or narrow it.
func (in *Installer) writeFile(path string, data string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".bpanel-new"
	if err := os.WriteFile(tmp, []byte(data), mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	if fi, err := os.Lstat(path); err == nil && fi.Mode().IsRegular() {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			_ = os.Lchown(tmp, int(st.Uid), int(st.Gid))
		}
		// Back up the distribution's file once; never a file the installer
		// wrote itself in an earlier (interrupted) run, nor its own config.
		_, ours := in.manifest()[path]
		if _, err := os.Stat(path + ".bpanel-orig"); os.IsNotExist(err) && !ours && !strings.HasPrefix(path, "/etc/bpanel/") {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if err := os.WriteFile(path+".bpanel-orig", b, 0o600); err != nil {
				return err
			}
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	in.S.Files = appendUnique(in.S.Files, path)
	return nil
}

func (in *Installer) manifest() map[string]bool {
	m := make(map[string]bool, len(in.S.Files))
	for _, f := range in.S.Files {
		m[f] = true
	}
	return m
}

// disable moves a stock file out of the way, outside every include glob
// (sites-enabled/*, conf.d/*.conf, pdns.d/*.conf), and records where it went
// so uninstall can put it back.
func (in *Installer) disable(path string) error {
	if _, err := os.Lstat(path); err != nil {
		return nil
	}
	dst := filepath.Join("/var/lib/bpanel/disabled", path)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if err := moveFile(path, dst); err != nil {
		return err
	}
	in.S.Disabled[path] = dst
	in.save()
	return nil
}

func (in *Installer) stages() []stage {
	return []stage{
		{"preflight", in.preflight},
		{"repos", in.repos},
		{"packages", in.packages},
		{"postgresql", in.postgresSetup}, // v0.4 dbx: no-op without --with-postgresql
		{"system", in.system},
		{"configs", in.configs},
		{"panel", in.panel},
		{"node", in.nodeMode}, // v0.4 instx: no-op without --node
		{"hostname-ssl", in.hostnameSSL},
		{"selftest", in.selftest},
	}
}

// Run executes the pending stages and prints the summary.
func (in *Installer) Run(ctx context.Context) error {
	in.say("banner", in.Version, in.L.Pretty, in.O.Profile)
	only := map[string]bool{}
	for _, s := range strings.Split(in.O.Stages, ",") {
		if s = strings.TrimSpace(s); s != "" {
			only[s] = true
		}
	}
	// An existing older installation is upgraded, never "already done,
	// skipping" with the old binaries left in place (R2-SYS-10).
	if len(only) == 0 && in.installed() && VersionLess(in.S.Version, in.Version) {
		return in.Upgrade(ctx)
	}
	list := in.stages()
	for i, st := range list {
		if len(only) > 0 && !only[st.name] {
			continue
		}
		if in.done(st.name) && len(only) == 0 && st.name != "preflight" && st.name != "selftest" {
			in.say("stage_skip", i, len(list)-1, T(in.O.Lang, "stage."+st.name))
			continue
		}
		in.say("stage_start", i, len(list)-1, T(in.O.Lang, "stage."+st.name))
		start := time.Now()
		if err := st.run(ctx); err != nil {
			in.save()
			in.say("stage_fail", T(in.O.Lang, "stage."+st.name), err)
			in.say("resume_hint", LogFile)
			return err
		}
		if !in.done(st.name) {
			in.S.Done = append(in.S.Done, st.name)
		}
		in.save()
		in.say("stage_ok", T(in.O.Lang, "stage."+st.name), time.Since(start).Round(time.Second))
	}
	if len(only) == 0 {
		in.S.Version = in.Version
		in.save()
		return in.summary(ctx)
	}
	return nil
}

func have(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// moveFile renames src to dst, falling back to copy+remove across file
// systems (/etc and /var can be separate mounts). Symlinks are moved as links.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t, err := os.Readlink(src)
		if err != nil {
			return err
		}
		_ = os.Remove(dst)
		if err := os.Symlink(t, dst); err != nil {
			return err
		}
		return os.Remove(src)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, b, fi.Mode().Perm()); err != nil {
		return err
	}
	return os.Remove(src)
}
