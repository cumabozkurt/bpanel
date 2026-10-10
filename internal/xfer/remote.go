// SPDX-License-Identifier: Apache-2.0

package xfer

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Remote pull: fetch an archive from another server over SFTP (scp -s) with
// argv only. The remote path is validated strictly and SFTP mode is forced,
// so the remote side never expands it in a shell.

var (
	ErrRemoteInvalid = errors.New("xfer_remote_invalid")
	ErrRemoteBlocked = errors.New("xfer_remote_blocked")
)

type Remote struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user"`
	RemotePath string `json:"remote_path"`
	Auth       string `json:"auth"` // key | password
}

var (
	hostRe  = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	userRe  = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
	rpathRe = regexp.MustCompile(`^/[A-Za-z0-9._/@+-]+$`)
)

// Validate checks the shape of a remote spec (not reachability).
func (r *Remote) Validate() error {
	r.Host = strings.TrimSpace(strings.Trim(r.Host, "[]"))
	if r.Port == 0 {
		r.Port = 22
	}
	if ip := net.ParseIP(r.Host); ip == nil && !hostRe.MatchString(r.Host) {
		return errf(ErrRemoteInvalid, "host")
	}
	if r.Port < 1 || r.Port > 65535 {
		return errf(ErrRemoteInvalid, "port")
	}
	if !userRe.MatchString(r.User) {
		return errf(ErrRemoteInvalid, "user")
	}
	if len(r.RemotePath) > 1024 || !rpathRe.MatchString(r.RemotePath) || strings.Contains(r.RemotePath, "..") || strings.Contains(r.RemotePath, "//") {
		return errf(ErrRemoteInvalid, "remote_path")
	}
	if !strings.HasSuffix(r.RemotePath, ".tar.gz") && !strings.HasSuffix(r.RemotePath, ".tgz") && !strings.HasSuffix(r.RemotePath, ".tar") {
		return errf(ErrRemoteInvalid, "remote_path must be a .tar.gz, .tgz or .tar archive")
	}
	if r.Auth != "key" && r.Auth != "password" {
		return errf(ErrRemoteInvalid, "auth")
	}
	return nil
}

// Resolver is net.DefaultResolver in production (tests replace it).
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// blockedIP reports addresses a pull must never reach (SSRF guard):
// loopback, link-local (incl. cloud metadata), unspecified, multicast and,
// unless allowPrivate, RFC1918/ULA/CGNAT ranges.
func blockedIP(ip net.IP, allowPrivate bool) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 0 {
		return true
	}
	if !allowPrivate {
		if ip.IsPrivate() {
			return true
		}
		_, cgnat, _ := net.ParseCIDR("100.64.0.0/10")
		if cgnat.Contains(ip) {
			return true
		}
	}
	return false
}

// ResolveSafe resolves the host and returns one permitted IP to connect to
// (pinning it defeats DNS rebinding between check and connect).
func ResolveSafe(ctx context.Context, res Resolver, host string, allowPrivate bool) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if blockedIP(ip, allowPrivate) {
			return "", errf(ErrRemoteBlocked, "address not allowed")
		}
		return ip.String(), nil
	}
	addrs, err := res.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return "", errf(ErrRemoteInvalid, "host does not resolve")
	}
	for _, a := range addrs {
		if blockedIP(a.IP, allowPrivate) {
			return "", errf(ErrRemoteBlocked, "host resolves to a forbidden address")
		}
	}
	return addrs[0].IP.String(), nil
}

// ScpArgv builds the argv for fetching r.RemotePath from the pinned ip into
// dest. keyFile is used for key auth; for password auth the caller runs the
// argv under `sshpass -e` with SSHPASS in the environment (never argv).
func ScpArgv(r Remote, ip, keyFile, knownHosts, dest string, timeoutSec int) []string {
	host := ip
	if strings.Contains(ip, ":") {
		host = "[" + ip + "]"
	}
	argv := []string{"scp", "-s", "-q", "-P", strconv.Itoa(r.Port),
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-o", "ConnectTimeout=" + strconv.Itoa(timeoutSec),
		"-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
		"-o", "HostKeyAlias=" + r.Host,
	}
	if r.Auth == "key" {
		argv = append(argv, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no", "-i", keyFile)
	} else {
		argv = append(argv, "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "NumberOfPasswordPrompts=1")
	}
	return append(argv, "--", r.User+"@"+host+":"+r.RemotePath, dest)
}
