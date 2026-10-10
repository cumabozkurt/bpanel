// Command bpanel-installer is the staged, resumable installer started by install.sh.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/cumabozkurt/bpanel/internal/distro"
	"github.com/cumabozkurt/bpanel/internal/installer"
	"github.com/cumabozkurt/bpanel/internal/version"
)

func main() {
	args := os.Args[1:]
	cmd := "install"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("bpanel-installer", flag.ExitOnError)
	var o installer.Options
	var php string
	var purge bool
	fs.StringVar(&o.Hostname, "hostname", "", "fully qualified hostname of this server (default: current hostname)")
	fs.StringVar(&o.Email, "email", "", "administrator / Let's Encrypt contact email")
	fs.StringVar(&o.Profile, "profile", "full", "minimal | web | full")
	fs.BoolVar(&o.PostgreSQL, "with-postgresql", false, "also install PostgreSQL (optional database engine for accounts)")
	fs.BoolVar(&o.CrowdSec, "with-crowdsec", false, "also install CrowdSec (free, MIT) with the nftables bouncer (Ubuntu; AlmaLinux: manual repo)")
	fs.BoolVar(&o.Smart, "with-smart", false, "also install smartmontools (disk health in Monitoring)")
	fs.BoolVar(&o.Node, "node", false, "multi-server node: agent only with an mTLS remote listener; join it from the main panel")
	fs.StringVar(&o.RemoteListen, "remote-listen", "", "node mode: agent mTLS listen address (default :8445)")
	fs.StringVar(&o.Lang, "lang", "en", "installer output and panel default language: en | tr")
	fs.StringVar(&o.AdminUser, "admin", "bpadmin", "name of the first panel administrator")
	fs.StringVar(&php, "php", "", "extra PHP versions, e.g. 8.2,8.4 (needs ondrej/php on Ubuntu, Remi on AlmaLinux)")
	fs.StringVar(&o.BinDir, "bin-dir", "", "directory holding bpanel-api, bpanel-agent and bpanel (default: next to the installer)")
	fs.StringVar(&o.Stages, "stages", "", "run only these stages (comma separated; for development)")
	fs.BoolVar(&o.Yes, "yes", false, "do not ask for confirmation")
	fs.BoolVar(&o.Force, "force", false, "install: continue even if the server is not fresh; upgrade: re-apply every upgrade step")
	fs.BoolVar(&o.AllowUnsupported, "allow-unsupported", false, "try on an unsupported distribution")
	fs.BoolVar(&o.NoSystemd, "no-systemd", false, "test mode: never start or enable services")
	fs.BoolVar(&o.SkipRepos, "skip-repos", false, "do not add third-party repositories")
	fs.BoolVar(&purge, "purge", false, "uninstall: also delete panel configuration and data")
	showVersion := fs.Bool("version", false, "print version")
	outDir := fs.String("out", "", "render: write the generated files under this directory instead of printing their paths")
	distroID := fs.String("distro", "", "render: os-release ID to render for (default: this system), e.g. ubuntu, almalinux")
	_ = fs.Parse(args) // ExitOnError: never returns an error
	if *showVersion || cmd == "version" {
		fmt.Println("bpanel-installer", version.Version)
		return
	}
	for _, v := range strings.Split(php, ",") {
		if v = strings.TrimSpace(v); v != "" {
			o.ExtraPHP = append(o.ExtraPHP, v)
		}
	}
	switch o.Profile {
	case "minimal", "web", "full":
	default:
		fmt.Fprintln(os.Stderr, "unknown profile:", o.Profile)
		os.Exit(2)
	}
	if cmd == "render" {
		if err := render(o, *distroID, *outDir); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	if cmd == "restic-unlock" {
		// ExecStartPre of bpanel-agent.service (R2-PERF-14); never blocks the agent
		if err := installer.ResticUnlock(context.Background(), "/etc/bpanel/agent.json"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if (cmd == "install" || cmd == "uninstall" || cmd == "upgrade") && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "error: bpanel-installer must run as root (sudo)")
		os.Exit(1)
	}
	in, err := installer.New(o, version.Version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch cmd {
	case "install":
		if !o.Yes && isTTY() {
			fmt.Printf("Install BOZKURT PANEL on %s (profile %s)? This changes system configuration. [y/N] ", o.Hostname, o.Profile)
			var a string
			_, _ = fmt.Scanln(&a)
			if a != "y" && a != "Y" && a != "e" && a != "E" {
				os.Exit(1)
			}
		}
		if err := in.Run(ctx); err != nil {
			os.Exit(1)
		}
	case "upgrade":
		if err := in.Upgrade(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "uninstall":
		if err := in.Uninstall(ctx, purge); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "status":
		fmt.Println(installer.StateFile)
		b, _ := os.ReadFile(installer.StateFile)
		_, _ = os.Stdout.Write(b)
	default:
		fmt.Fprintln(os.Stderr, "usage: bpanel-installer [install|upgrade|uninstall|status|render|version] [flags]")
		os.Exit(2)
	}
}

// render writes the configuration files the installer would generate, for
// review or for checking them with nginx -t, apache2ctl, sshd -t, etc.
func render(o installer.Options, id, out string) error {
	var l *distro.Layout
	var err error
	if id != "" {
		l, err = distro.ForRelease(map[string]string{"ID": id})
	} else {
		l, err = distro.Detect()
	}
	if err != nil {
		return err
	}
	if o.Hostname == "" {
		o.Hostname = "panel.example.com"
	}
	stock, _ := os.ReadFile("/etc/nginx/nginx.conf")
	nv, _ := exec.Command("nginx", "-v").CombinedOutput()
	aliases, _ := os.ReadFile("/etc/aliases")
	files := installer.Render(l, installer.RenderOpts{Profile: o.Profile, Hostname: o.Hostname, Email: o.Email,
		NginxStock: string(stock), NginxHTTP2: installer.NginxHTTP2On(string(nv)), AliasesOrig: string(aliases)})
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if out != "" {
		// the documented `render --out /tmp/cfg` must work without a pre-created directory
		if err := os.MkdirAll(out, 0o755); err != nil {
			return err
		}
	}
	if out != "" && o.Profile == "full" {
		// not a file the installer writes: the `postconf -e` settings it applies
		pc := strings.Join(installer.PostfixSettings(o.Hostname, installer.PostfixMapType(l), l.PostfixDir+"/bpanel",
			"/etc/bpanel/ssl/panel/fullchain.pem", "/etc/bpanel/ssl/panel/privkey.pem"), "\n") + "\n"
		if err := os.WriteFile(filepath.Join(out, "postconf-e.txt"), []byte(pc), 0o644); err != nil {
			return err
		}
	}
	for _, p := range paths {
		if out == "" {
			fmt.Printf("==> %s\n%s\n", p, files[p])
			continue
		}
		dst := filepath.Join(out, p)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, []byte(files[p]), 0o644); err != nil {
			return err
		}
		fmt.Println(dst)
	}
	return nil
}

func isTTY() bool {
	st, err := os.Stdin.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
