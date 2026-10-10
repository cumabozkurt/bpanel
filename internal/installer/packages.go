package installer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cumabozkurt/bpanel/internal/distro"
)

// Pinned third-party sources (verified 2026-10-09). Keys are checked by fingerprint.
const (
	PDNSKeyURL   = "https://repo.powerdns.com/FD380FBB-pub.asc"
	PDNSKeyFPR   = "9FAAA5577E8FCF62093D036C1B0C6205FD380FBB"
	PDNSSeries   = "auth-50"
	RspamdKeyURL = "https://rspamd.com/apt-stable/gpg.key"
	RspamdKeyFPR = "3FA347D5E599BE4595CA2576FFA232EDBF21E25E"

	// Extra PHP versions (R2-WB-16): the Ondřej Surý PPA key is checked by
	// fingerprint (Launchpad signing_key_fingerprint, verified 2026-10-09)
	// and the Remi release RPM by SHA-256 (it carries Remi's signing keys).
	OndrejKeyFPR = "B8DC7E53946656EFBCE4C1DD71DAEAAB4AD4CAB6"
	OndrejKeyURL = "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x" + OndrejKeyFPR
	RemiRelease  = "https://rpms.remirepo.net/enterprise/remi-release-9.8.rpm"
	RemiSHA      = "21100d93098f5821ff21d7ed511c99d874ba895438c2b78d8c73937133158d73"

	ResticVersion = "0.19.1"
	// ResticBin is where the pinned restic lives (R2-SYS-6 / R2-E2E-1). It
	// used to be unpacked to /var/cache/bpanel/restic, the path the agent
	// uses as RESTIC_CACHE_DIR, which broke every backup. The binary now sits
	// with the other panel binaries and the cache has its own directory.
	ResticBin = "/usr/local/lib/bpanel/bin/restic"
	// ResticCacheDir is the agent's RESTIC_CACHE_DIR (agent.New uses the same path).
	ResticCacheDir = CacheDir + "/restic-cache"
	// resticLegacyBin is where v0.1/v0.2 installed restic.
	resticLegacyBin = "/usr/local/bin/restic"
	RoundcubeVer    = "1.6.19"
	RoundcubeURL    = "https://github.com/roundcube/roundcubemail/releases/download/1.6.19/roundcubemail-1.6.19-complete.tar.gz"
	RoundcubeSHA    = "c47fd99cd7cbb7aee2557d8ca614a4c51e91f6fa3767ca4ce32c6126f9ebff5b"
	PMAVer          = "5.2.3"
	PMAURL          = "https://files.phpmyadmin.net/phpMyAdmin/5.2.3/phpMyAdmin-5.2.3-all-languages.tar.gz"
	PMASHA          = "12ba1c425fa4071abbd4e7668c9ebdeac0b0755a467a6d6d5026122bb47c102b"
)

var resticSHA = map[string]string{
	"amd64": "f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c",
	"arm64": "a5f64aaab53d51e311fa3829124c5b703f2d14cf187d8640b6be3b2b49376465",
}

// download fetches url to path with retries and verifies its SHA-256. The
// file only appears at path once the checksum matched.
func download(ctx context.Context, url, path, sha string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var last error
	for attempt := 1; attempt <= 4; attempt++ {
		last = func() error {
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				return err
			}
			cl := &http.Client{Timeout: 10 * time.Minute}
			resp, err := cl.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
			}
			f, err := os.OpenFile(path+".part", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			h := sha256.New()
			if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			if sha != "" && hex.EncodeToString(h.Sum(nil)) != sha {
				_ = os.Remove(path + ".part")
				return fmt.Errorf("checksum mismatch for %s", url)
			}
			return os.Rename(path+".part", path)
		}()
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt*3) * time.Second):
		}
	}
	return last
}

// ---------------------------------------------------------------- apt ------

// aptLocks are the locks apt/dpkg/unattended-upgrades hold (fcntl locks).
var aptLocks = []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock", "/var/lib/apt/lists/lock", "/var/cache/apt/archives/lock"}

// lockHeld reports whether another process holds an fcntl write lock on path.
func lockHeld(path string) bool {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	lk := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &lk); err != nil {
		return false
	}
	return lk.Type != syscall.F_UNLCK
}

// waitApt waits (up to 15 minutes) for cloud-init and unattended-upgrades to
// release the apt/dpkg locks, which they usually hold on a fresh VM.
func (in *Installer) waitApt(ctx context.Context) error {
	if have("cloud-init") && !in.done("cloud-init-wait") {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		_, _ = in.shOut(cctx, nil, "cloud-init", "status", "--wait")
		cancel()
		in.S.Done = append(in.S.Done, "cloud-init-wait")
	}
	end := time.Now().Add(15 * time.Minute)
	said := false
	for {
		busy := ""
		for _, l := range aptLocks {
			if lockHeld(l) {
				busy = l
				break
			}
		}
		if busy == "" {
			return nil
		}
		if !said {
			in.say("apt_wait", busy)
			said = true
		}
		if time.Now().After(end) {
			return fmt.Errorf("apt/dpkg is still locked (%s) after 15 minutes; another package manager is running", busy)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// aptArgs are passed to every apt-get call: wait for the dpkg lock instead of
// failing, never prompt, keep locally changed config files.
var aptArgs = []string{"-y", "-o", "DPkg::Lock::Timeout=900", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}

func (in *Installer) apt(ctx context.Context, args ...string) error {
	if err := in.waitApt(ctx); err != nil {
		return err
	}
	return in.sh(ctx, append(append([]string{"apt-get"}, aptArgs...), args...)...)
}

// aptRecover finishes an interrupted dpkg run (installer killed, SSH
// dropped, reboot) so the package stage can simply be run again.
func (in *Installer) aptRecover(ctx context.Context) error {
	if err := in.waitApt(ctx); err != nil {
		return err
	}
	if err := in.sh(ctx, "dpkg", "--configure", "-a", "--force-confdef", "--force-confold"); err != nil {
		return err
	}
	return in.apt(ctx, "-f", "install")
}

// importKey downloads an ASCII-armoured key, checks its fingerprint and stores it dearmored.
func (in *Installer) importKey(ctx context.Context, url, fpr, dest string) error {
	tmp := filepath.Join(CacheDir, filepath.Base(dest)+".asc")
	if err := download(ctx, url, tmp, ""); err != nil {
		return err
	}
	out, err := in.shOut(ctx, nil, "gpg", "--show-keys", "--with-colons", tmp)
	if err != nil {
		return err
	}
	if err := checkKeyListing(out, fpr); err != nil {
		return fmt.Errorf("key %s: %w", url, err)
	}
	if in.L.Family == distro.RHEL {
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		b, err := os.ReadFile(tmp)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dest, b, 0o644); err != nil {
			return err
		}
		return in.sh(ctx, "rpm", "--import", dest)
	}
	if err := os.MkdirAll("/etc/apt/keyrings", 0o755); err != nil {
		return err
	}
	_ = os.Remove(dest)
	if err := in.sh(ctx, "gpg", "--batch", "--dearmor", "-o", dest, tmp); err != nil {
		return err
	}
	return os.Chmod(dest, 0o644)
}

func (in *Installer) repos(ctx context.Context) error {
	if in.O.SkipRepos {
		return nil
	}
	if in.L.Family == distro.Debian {
		codename := "noble"
		if m, err := distro.OSRelease("/"); err == nil && m["VERSION_CODENAME"] != "" {
			codename = m["VERSION_CODENAME"]
		}
		if err := in.apt(ctx, "update"); err != nil {
			return err
		}
		if err := in.apt(ctx, "install", "ca-certificates", "curl", "gnupg", "lsb-release"); err != nil {
			return err
		}
		if in.web() {
			if err := in.importKey(ctx, PDNSKeyURL, PDNSKeyFPR, "/etc/apt/keyrings/powerdns.gpg"); err != nil {
				return err
			}
			if err := in.writeFile("/etc/apt/sources.list.d/bpanel-powerdns.list",
				fmt.Sprintf("deb [signed-by=/etc/apt/keyrings/powerdns.gpg] https://repo.powerdns.com/%s %s-%s main\n", in.L.ID, codename, PDNSSeries), 0o644); err != nil {
				return err
			}
			if err := in.writeFile("/etc/apt/preferences.d/bpanel-powerdns", "Package: pdns-*\nPin: origin repo.powerdns.com\nPin-Priority: 600\n", 0o644); err != nil {
				return err
			}
			in.S.Repos = appendUnique(in.S.Repos, "powerdns-"+PDNSSeries)
		}
		if in.full() {
			if err := in.importKey(ctx, RspamdKeyURL, RspamdKeyFPR, "/etc/apt/keyrings/rspamd.gpg"); err != nil {
				return err
			}
			if err := in.writeFile("/etc/apt/sources.list.d/bpanel-rspamd.list",
				fmt.Sprintf("deb [signed-by=/etc/apt/keyrings/rspamd.gpg] https://rspamd.com/apt-stable/ %s main\n", codename), 0o644); err != nil {
				return err
			}
			in.S.Repos = appendUnique(in.S.Repos, "rspamd-stable")
		}
		if len(in.O.ExtraPHP) > 0 && in.L.ID == "ubuntu" {
			// no add-apt-repository: it trusts whatever key Launchpad serves
			if err := in.importKey(ctx, OndrejKeyURL, OndrejKeyFPR, "/etc/apt/keyrings/ondrej-php.gpg"); err != nil {
				return err
			}
			if err := in.writeFile("/etc/apt/sources.list.d/bpanel-ondrej-php.list",
				fmt.Sprintf("deb [signed-by=/etc/apt/keyrings/ondrej-php.gpg] https://ppa.launchpadcontent.net/ondrej/php/ubuntu %s main\n", codename), 0o644); err != nil {
				return err
			}
			in.S.Repos = appendUnique(in.S.Repos, "ppa:ondrej/php")
		}
		return in.apt(ctx, "update")
	}
	// AlmaLinux 9
	steps := [][]string{
		// No "curl" here: EL9 minimal/GenericCloud images ship curl-minimal,
		// which provides /usr/bin/curl and conflicts with the full curl
		// package (R2-SYS-1). curl is only installed when neither is present.
		{"dnf", "-y", "install", "epel-release", "dnf-plugins-core", "ca-certificates", "gnupg2", "tar", "bzip2"},
		{"dnf", "config-manager", "--set-enabled", "crb"},
		{"dnf", "-y", "module", "reset", "nginx", "php", "mariadb"},
		{"dnf", "-y", "module", "enable", "nginx:1.26", "php:8.3", "mariadb:10.11"},
	}
	for _, s := range steps {
		if err := in.sh(ctx, s...); err != nil {
			return err
		}
	}
	if !have("curl") {
		if err := in.sh(ctx, "dnf", "-y", "install", "curl"); err != nil {
			return err
		}
	}
	in.S.Repos = appendUnique(in.S.Repos, "epel")
	if in.web() {
		if err := in.importKey(ctx, PDNSKeyURL, PDNSKeyFPR, "/etc/pki/rpm-gpg/RPM-GPG-KEY-powerdns"); err != nil {
			return err
		}
		if err := in.writeFile("/etc/yum.repos.d/bpanel-powerdns.repo", fmt.Sprintf(`[powerdns-%[1]s]
name=PowerDNS Authoritative %[1]s (BOZKURT PANEL)
baseurl=https://repo.powerdns.com/el/$basearch/$releasever/%[1]s
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-powerdns
gpgcheck=1
enabled=1
priority=90
includepkgs=pdns*
`, PDNSSeries), 0o644); err != nil {
			return err
		}
		in.S.Repos = appendUnique(in.S.Repos, "powerdns-"+PDNSSeries)
	}
	if in.full() {
		if err := in.importKey(ctx, RspamdKeyURL, RspamdKeyFPR, "/etc/pki/rpm-gpg/RPM-GPG-KEY-rspamd"); err != nil {
			return err
		}
		if err := in.writeFile("/etc/yum.repos.d/bpanel-rspamd.repo", `[rspamd]
name=Rspamd stable (BOZKURT PANEL)
baseurl=https://rspamd.com/rpm-stable/centos-9/$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rspamd
`, 0o644); err != nil {
			return err
		}
		in.S.Repos = appendUnique(in.S.Repos, "rspamd-stable")
	}
	if len(in.O.ExtraPHP) > 0 {
		rpm := filepath.Join(CacheDir, filepath.Base(RemiRelease))
		if err := download(ctx, RemiRelease, rpm, RemiSHA); err != nil {
			return err
		}
		if err := in.sh(ctx, "dnf", "-y", "install", rpm); err != nil {
			return err
		}
		in.S.Repos = appendUnique(in.S.Repos, "remi")
	}
	return nil
}

// PackageList returns the packages for a profile (exported for tests/docs).
func PackageList(l *distro.Layout, profile string, extraPHP []string) []string {
	var p []string
	if l.Family == distro.Debian {
		p = []string{"nginx", "mariadb-server", "mariadb-client", "quota", "acl", "cron", "nftables", "fail2ban", "python3-systemd",
			"unzip", "zip", "bzip2", "logrotate", "openssl", "sqlite3", "openssh-server"}
		if profile != "minimal" {
			p = append(p, "apache2", "pdns-server", "pdns-backend-sqlite3", "pure-ftpd", "php"+l.DefaultPHP+"-sqlite3")
		}
		if profile == "full" {
			p = append(p, "postfix", "postfix-lmdb", "dovecot-imapd", "dovecot-pop3d", "dovecot-lmtpd", "dovecot-sieve", "dovecot-managesieved", "rspamd", "redis-server")
		}
	} else {
		// fail2ban-server + fail2ban-systemd, not the "fail2ban" meta package:
		// it pulls fail2ban-firewalld, whose firewallcmd ban actions fail
		// once firewalld is replaced by the panel's nftables table.
		p = []string{"nginx", "mariadb-server", "mariadb", "quota", "acl", "cronie", "nftables", "fail2ban-server", "fail2ban-systemd",
			"unzip", "zip", "bzip2", "logrotate", "openssl", "sqlite", "policycoreutils-python-utils", "openssh-server"}
		if profile != "minimal" {
			p = append(p, "httpd", "pdns", "pdns-backend-sqlite", "pure-ftpd", "php-pdo")
		}
		if profile == "full" {
			p = append(p, "postfix", "postfix-lmdb", "dovecot", "dovecot-pigeonhole", "rspamd", "redis")
		}
	}
	p = append(p, PHPPackages(l, l.DefaultPHP)...)
	for _, v := range extraPHP {
		if v != l.DefaultPHP {
			p = append(p, PHPPackages(l, v)...)
		}
	}
	return p
}

// packages is resumable: an interrupted dpkg run is completed first, every
// sub-step is recorded, and finished downloads are not repeated.
func (in *Installer) packages(ctx context.Context) error {
	pkgs := PackageList(in.L, in.O.Profile, in.O.ExtraPHP)
	if in.O.PostgreSQL { // v0.4 dbx postgres.go
		pkgs = append(pkgs, PostgresPackages(in.L)...)
	}
	pkgs = append(pkgs, V04Packages(in.L, in.O.Profile)...) // v0.4 instx
	in.S.Packages = pkgs
	if err := os.MkdirAll(CacheDir, 0o700); err != nil {
		return err
	}
	if in.L.Family == distro.Debian {
		if err := in.aptRecover(ctx); err != nil {
			return err
		}
		// Package lists may be missing (fresh image, --skip-repos) or stale.
		if err := in.apt(ctx, "update"); err != nil {
			return err
		}
		// Keep services from auto-starting with distro defaults until
		// configured. An existing policy-rc.d (containers) is left alone.
		const prc = "/usr/sbin/policy-rc.d"
		if _, err := os.Lstat(prc); os.IsNotExist(err) {
			if err := os.WriteFile(prc, []byte("#!/bin/sh\n# BOZKURT PANEL installer (temporary)\nexit 101\n"), 0o755); err != nil {
				return err
			}
			defer os.Remove(prc)
		}
		if err := in.apt(ctx, append([]string{"install"}, pkgs...)...); err != nil {
			return err
		}
		// Services blocked by policy-rc.d are enabled but stopped; the
		// configs stage starts each one it needs (cron: R2-SYS-8).
		if b, err := os.ReadFile(prc); err == nil && strings.Contains(string(b), "BOZKURT PANEL installer (temporary)") {
			_ = os.Remove(prc)
		}
	} else {
		if err := in.sh(ctx, append([]string{"dnf", "-y", "install"}, pkgs...)...); err != nil {
			return err
		}
	}
	in.v04Optional(ctx) // v0.4 instx: warnings only
	return in.step("packages:restic", func() error { return in.installRestic(ctx) })
}

// installRestic installs the pinned upstream restic binary at ResticBin.
// The download is unpacked in a private temporary directory that is removed
// afterwards, so nothing is left in the cache (R2-SYS-6).
func (in *Installer) installRestic(ctx context.Context) error {
	if err := in.migrateRestic(); err != nil {
		return err
	}
	if out, err := exec.Command(ResticBin, "version").Output(); err == nil && strings.Contains(string(out), "restic "+ResticVersion+" ") {
		return in.linkRestic()
	}
	// Upgrade from v0.1/v0.2: the pinned binary is already at the old path.
	if fi, err := os.Lstat(resticLegacyBin); err == nil && fi.Mode().IsRegular() {
		if out, err := exec.Command(resticLegacyBin, "version").Output(); err == nil && strings.Contains(string(out), "restic "+ResticVersion+" ") {
			if err := os.MkdirAll(filepath.Dir(ResticBin), 0o755); err != nil {
				return err
			}
			if err := in.sh(ctx, "install", "-m", "0755", "-o", "root", "-g", "root", resticLegacyBin, ResticBin); err != nil {
				return err
			}
			return in.linkRestic()
		}
	}
	arch := goarch()
	sha, ok := resticSHA[arch]
	if !ok {
		in.warn("restic: no pinned build for " + arch + "; backups are unavailable")
		return nil
	}
	url := fmt.Sprintf("https://github.com/restic/restic/releases/download/v%[1]s/restic_%[1]s_linux_%[2]s.bz2", ResticVersion, arch)
	if err := os.MkdirAll(CacheDir, 0o700); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(CacheDir, "restic-dl-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	bz := filepath.Join(tmp, "restic.bz2")
	if err := download(ctx, url, bz, sha); err != nil {
		return err
	}
	if err := in.sh(ctx, "bunzip2", "-f", bz); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(ResticBin), 0o755); err != nil {
		return err
	}
	if err := in.sh(ctx, "install", "-m", "0755", "-o", "root", "-g", "root", filepath.Join(tmp, "restic"), ResticBin); err != nil {
		return err
	}
	return in.linkRestic()
}

// linkRestic keeps `restic` on the admin's PATH: /usr/local/bin/restic points
// at ResticBin. A restic binary there that the panel did not install is left alone.
func (in *Installer) linkRestic() error {
	fi, err := os.Lstat(resticLegacyBin)
	switch {
	case err == nil && fi.Mode()&os.ModeSymlink != 0:
		return nil // ours already, or someone else's link
	case err == nil && fi.Mode().IsRegular():
		// v0.1/v0.2 installed the pinned binary here (step packages:restic)
		if !in.done("packages:restic") {
			return nil
		}
	case err != nil && !os.IsNotExist(err):
		return err
	}
	tmp := resticLegacyBin + ".bpanel-new"
	_ = os.Remove(tmp)
	if err := os.Symlink(ResticBin, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, resticLegacyBin)
}

// migrateRestic repairs installs made by v0.2: the restic binary left at
// /var/cache/bpanel/restic blocked the agent's cache directory. A regular
// file at either cache path is removed and the cache directory created.
func (in *Installer) migrateRestic() error {
	for _, p := range []string{CacheDir + "/restic", CacheDir + "/restic.bz2", ResticCacheDir} {
		if fi, err := os.Lstat(p); err == nil && !fi.IsDir() {
			if err := os.Remove(p); err != nil {
				return err
			}
			in.logf("removed stale %s (R2-SYS-6)", p)
		}
	}
	if err := os.MkdirAll(ResticCacheDir, 0o700); err != nil {
		return err
	}
	return os.Chmod(ResticCacheDir, 0o700)
}

func goarch() string {
	out, _ := exec.Command("uname", "-m").Output()
	switch strings.TrimSpace(string(out)) {
	case "x86_64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	}
	return strings.TrimSpace(string(out))
}

// checkKeyListing accepts `gpg --show-keys --with-colons` output only when it
// holds exactly one primary key and that key has the pinned fingerprint. A
// download that adds a second key next to the expected one is refused
// (it would otherwise be trusted for the repository too).
func checkKeyListing(out, fpr string) error {
	lines := strings.Split(out, "\n")
	pubs := 0
	primary := ""
	for i, l := range lines {
		if strings.HasPrefix(l, "pub:") {
			pubs++
			if i+1 < len(lines) && strings.HasPrefix(lines[i+1], "fpr:") {
				f := strings.Split(lines[i+1], ":")
				if len(f) > 9 {
					primary = f[9]
				}
			}
		}
	}
	if pubs != 1 {
		return fmt.Errorf("expected exactly one key, found %d", pubs)
	}
	if !strings.EqualFold(primary, fpr) {
		return fmt.Errorf("fingerprint %s, expected %s", primary, fpr)
	}
	return nil
}
