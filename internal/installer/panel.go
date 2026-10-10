package installer

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cumabozkurt/bpanel/internal/agent"
	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/api"
	"github.com/cumabozkurt/bpanel/internal/auth"
	"github.com/cumabozkurt/bpanel/internal/store"
	"github.com/cumabozkurt/bpanel/templates"
)

const (
	apiConfigPath = "/etc/bpanel/api.json"
	// DBPath is where new installs keep the panel database: a directory owned
	// by the API user inside the root-owned /var/lib/bpanel.
	DBPath       = "/var/lib/bpanel/db/bpanel.db"
	legacyDBPath = "/var/lib/bpanel/bpanel.db"
)

// apiConfig returns the installed API configuration (defaults if missing).
func apiConfig() api.Config {
	cfg := api.DefaultConfig()
	if b, err := os.ReadFile(apiConfigPath); err == nil {
		_ = json.Unmarshal(b, &cfg)
	}
	return cfg
}

// migrateDB moves a v0.1 database (/var/lib/bpanel/bpanel.db) into db/.
func (in *Installer) migrateDB(ctx context.Context, dst string) error {
	if dst == legacyDBPath {
		return nil
	}
	if _, err := os.Stat(legacyDBPath); err != nil {
		return nil
	}
	if _, err := os.Stat(dst); err == nil {
		return nil
	}
	_ = in.systemctl(ctx, "stop", "bpanel-api")
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	for _, sfx := range []string{"", "-wal", "-shm"} {
		if _, err := os.Stat(legacyDBPath + sfx); err == nil {
			if err := moveFile(legacyDBPath+sfx, dst+sfx); err != nil {
				return err
			}
		}
	}
	in.logf("moved %s to %s", legacyDBPath, dst)
	return nil
}

func lookupGID(name string) int {
	b, _ := os.ReadFile("/etc/group")
	for _, l := range strings.Split(string(b), "\n") {
		p := strings.Split(l, ":")
		if len(p) > 2 && p[0] == name {
			n, _ := strconv.Atoi(p[2])
			return n
		}
	}
	return -1
}

func lookupUID(name string) int {
	b, _ := os.ReadFile("/etc/passwd")
	for _, l := range strings.Split(string(b), "\n") {
		p := strings.Split(l, ":")
		if len(p) > 3 && p[0] == name {
			n, _ := strconv.Atoi(p[2])
			return n
		}
	}
	return -1
}

func (in *Installer) panel(ctx context.Context) error {
	// binaries
	src := in.O.BinDir
	if src == "" {
		exe, _ := os.Executable()
		src = filepath.Dir(exe)
	}
	for _, b := range []string{"bpanel-api", "bpanel-agent", "bpanel"} {
		p := filepath.Join(src, b)
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("binary %s not found next to the installer (%s)", b, src)
		}
		if filepath.Clean(p) != "/usr/local/bin/"+b {
			if err := in.sh(ctx, "install", "-m", "0755", p, "/usr/local/bin/"+b); err != nil {
				return err
			}
		}
	}
	if err := in.keepInstaller(ctx, src); err != nil {
		return err
	}
	// suspended page
	if err := os.MkdirAll("/usr/share/bpanel/suspended", 0o755); err != nil {
		return err
	}
	if b, err := fs.ReadFile(templates.FS, "suspended/index.html"); err == nil {
		if err := os.WriteFile("/usr/share/bpanel/suspended/index.html", b, 0o644); err != nil {
			return err
		}
	}
	// configuration
	pdnsKey, err := secret("pdns-api-key")
	if err != nil {
		return err
	}
	acfg := agent.DefaultConfig()
	if b, err := os.ReadFile("/etc/bpanel/agent.json"); err == nil {
		_ = json.Unmarshal(b, &acfg) // keep settings made after a previous install
	}
	acfg.AllowedUIDs = []int{lookupUID("bpanel")}
	acfg.PDNSKey = pdnsKey
	if in.O.Hostname != "" {
		acfg.Hostname = in.O.Hostname
	}
	if in.O.Email != "" || !in.upgrading {
		acfg.ACMEEmail = in.O.Email
	}
	acfg.Profile = in.O.Profile
	acfg.NoSystemd = in.O.NoSystemd
	// R2-SYS-6: restic moved out of /usr/local/bin (old default) next to the panel binaries.
	if acfg.ResticBin == "" || acfg.ResticBin == resticLegacyBin {
		acfg.ResticBin = ResticBin
	}
	ab, _ := json.MarshalIndent(acfg, "", "  ")
	if err := in.writeFile("/etc/bpanel/agent.json", string(ab)+"\n", 0o600); err != nil {
		return err
	}

	pcfg := api.DefaultConfig()
	if b, err := os.ReadFile(apiConfigPath); err == nil {
		_ = json.Unmarshal(b, &pcfg)
	}
	if pcfg.DBPath == "" || pcfg.DBPath == legacyDBPath {
		pcfg.DBPath = DBPath
	}
	pcfg.Hostname = in.O.Hostname
	pcfg.ServerIP = in.S.ServerIP
	pb, _ := json.MarshalIndent(pcfg, "", "  ")
	if err := in.writeFile(apiConfigPath, string(pb)+"\n", 0o640); err != nil {
		return err
	}
	if err := in.sh(ctx, "chown", "root:bpanel", apiConfigPath); err != nil {
		return err
	}
	if err := in.migrateDB(ctx, pcfg.DBPath); err != nil {
		return err
	}

	// database
	st, err := store.Open(pcfg.DBPath)
	if err != nil {
		return err
	}
	if err := api.Bootstrap(st); err != nil {
		st.Close()
		return err
	}
	settings := map[string]string{"server_ip": in.S.ServerIP}
	// An upgrade keeps what the administrator chose since the install.
	keep := func(k, v string) {
		if !in.upgrading || st.Get(k, "") == "" {
			settings[k] = v
		}
	}
	keep("default_lang", in.O.Lang)
	if in.O.Email != "" {
		keep("contact_email", in.O.Email)
		keep("acme_email", in.O.Email)
	}
	// R2-E2E-2: the default PHP is the version that is really installed
	// (8.4 on Debian 13), not the API's fallback "8.3". An existing choice
	// is kept while its PHP-FPM is still installed.
	if php := in.detectPHP(); php != "" {
		if cur := st.Get("default_php", ""); cur == "" || !in.phpInstalled(cur) {
			settings["default_php"] = php
		}
	}
	// Feature flags of the installed profile (R2-SYS-16): see Capabilities.
	caps := in.capabilities(ctx)
	for k, v := range caps.Settings() {
		settings[k] = v
	}
	if in.O.Profile == "minimal" {
		settings["web_mode"] = "nginx" // SYS-5: no Apache: every vhost is nginx -> PHP-FPM
	}
	for k, v := range settings {
		if err := st.Set(k, v); err != nil {
			st.Close()
			return err
		}
	}
	if err := in.writeCapabilities(ctx, caps); err != nil {
		st.Close()
		return err
	}
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE username=?`, in.O.AdminUser).Scan(&n); err != nil {
		st.Close()
		return err
	}
	if n == 0 {
		in.S.AdminPass = auth.RandomPassword(20)
		if _, err := api.EnsureAdmin(ctx, st, in.O.AdminUser, in.S.AdminPass, in.O.Email); err != nil {
			st.Close()
			return err
		}
	}
	st.Close()
	for _, sfx := range []string{"", "-wal", "-shm"} {
		if _, err := os.Stat(pcfg.DBPath + sfx); err == nil {
			if err := os.Chmod(pcfg.DBPath+sfx, 0o600); err != nil {
				return err
			}
		}
	}
	// Only the database directory belongs to the API user (SYS-3).
	if err := in.sh(ctx, "chown", "-R", "bpanel:bpanel", filepath.Dir(pcfg.DBPath)); err != nil {
		return err
	}
	if err := in.sh(ctx, "chmod", "0751", "/var/lib/bpanel"); err != nil {
		return err
	}

	// units
	if err := in.writeFile("/etc/systemd/system/bpanel-agent.service", UnitAgent, 0o644); err != nil {
		return err
	}
	if err := in.writeFile("/etc/systemd/system/bpanel-api.service", UnitAPI, 0o644); err != nil {
		return err
	}
	if err := in.systemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	// restart, not only start: an upgrade has just replaced the binaries
	// and the unit files (R2-SYS-10)
	for _, u := range []string{"bpanel-agent", "bpanel-api"} {
		if err := in.systemctl(ctx, "enable", u); err != nil {
			return err
		}
		if err := in.systemctl(ctx, "restart", u); err != nil {
			return err
		}
	}
	if in.O.NoSystemd {
		return nil
	}
	return waitFor(ctx, func() bool {
		c, err := net.DialTimeout("tcp", "127.0.0.1:2083", time.Second)
		if err == nil {
			c.Close()
			return true
		}
		return false
	}, 30*time.Second)
}

func waitFor(ctx context.Context, ok func() bool, d time.Duration) error {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if ok() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("timed out waiting for the panel to start")
}

// hostnameSSL tries Let's Encrypt for the hostname through the agent; on
// failure the self-signed certificate stays and a warning is recorded.
func (in *Installer) hostnameSSL(ctx context.Context) error {
	if in.O.NoSystemd || strings.Count(in.O.Hostname, ".") < 2 {
		in.warn("hostname certificate: self-signed (no FQDN or test mode)")
		return nil
	}
	addrs, err := net.LookupHost(in.O.Hostname)
	match := false
	for _, a := range addrs {
		match = match || a == in.S.ServerIP
	}
	if err != nil || !match {
		in.warn(fmt.Sprintf("hostname %s does not point to %s yet: keeping the self-signed certificate; run AutoSSL later", in.O.Hostname, in.S.ServerIP))
		return nil
	}
	cl := rpc.NewClient("/run/bpanel/agent.sock")
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	var info rpc.SSLInfo
	if err := cl.Call(cctx, rpc.MSSLIssue, rpc.SSLIssue{Domain: in.O.Hostname, Email: in.O.Email}, &info); err != nil {
		in.warn("Let's Encrypt for the hostname failed: " + err.Error())
		return nil
	}
	// the agent stores it under ssl/<hostname>; the services use ssl/panel
	srcDir := "/etc/bpanel/ssl/" + in.O.Hostname
	for _, f := range []string{"fullchain.pem", "privkey.pem"} {
		b, err := os.ReadFile(filepath.Join(srcDir, f))
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if f == "privkey.pem" {
			mode = 0o640
		}
		if err := os.WriteFile("/etc/bpanel/ssl/panel/"+f+".new", b, mode); err != nil {
			return err
		}
		if err := os.Rename("/etc/bpanel/ssl/panel/"+f+".new", "/etc/bpanel/ssl/panel/"+f); err != nil {
			return err
		}
	}
	if err := in.sh(ctx, "chown", "root:bpanel", panelKey, panelCert); err != nil {
		return err
	}
	units := []string{"nginx", "bpanel-api"}
	if in.web() {
		if err := in.writeFTPCert(); err != nil {
			return err
		}
		units = append(units, in.L.FTPUnit)
	}
	if in.full() {
		units = append(units, "postfix", "dovecot")
	}
	for _, u := range units {
		if err := in.systemctl(ctx, "try-reload-or-restart", u); err != nil {
			in.warn("reload " + u + ": " + err.Error())
		}
	}
	return nil
}
