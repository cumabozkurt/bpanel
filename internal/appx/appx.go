// SPDX-License-Identifier: Apache-2.0

// Package appx holds the pure logic of the v0.4 application tools: the
// Application Manager (Node.js / Python apps run as systemd services behind
// an nginx reverse-proxy location), the free app installer catalogue
// (WordPress first) and the WordPress toolkit. Everything here is
// side-effect free except Extract and VerifyFile, which work inside an
// os.Root so no archive entry can leave the target directory.
package appx

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Error carries a stable error code (internal/api/errcodes.go).
type Error struct{ Code, Msg string }

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func errf(code, format string, a ...any) error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

const (
	RuntimeNode   = "node"
	RuntimePython = "python"
	RuntimeRuby   = "ruby"
	// DefaultPortLo/Hi: the per-server port range used when the admin has
	// not stored one (appx_settings port_lo / port_hi).
	DefaultPortLo = 30000
	DefaultPortHi = 30999
	MaxEnv        = 50
	MaxApps       = 20
)

var (
	nameRe    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	relSegRe  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	envKeyRe  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	versionRe = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,4}){0,2}$`)
)

// App is one managed application.
type App struct {
	ID      int64             `json:"id"`
	User    string            `json:"user"`
	Name    string            `json:"name"`
	Runtime string            `json:"runtime"`
	Version string            `json:"version"` // major[.minor[.patch]] of a detected binary
	Root    string            `json:"root"`    // relative to the account home
	Startup string            `json:"startup"` // relative to Root
	Domain  string            `json:"domain,omitempty"`
	URLPath string            `json:"url_path,omitempty"`
	Port    int               `json:"port"`
	Env     map[string]string `json:"env,omitempty"`
}

// Proxy is one nginx location of a domain: URLPath -> 127.0.0.1:Port.
type Proxy struct {
	URLPath string `json:"url_path"`
	Port    int    `json:"port"`
}

func ValidName(n string) bool { return nameRe.MatchString(n) }

// CleanRel validates a path relative to the account home (or to an app
// root): no absolute path, no "..", only plain segments. "" is refused.
func CleanRel(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || strings.HasPrefix(p, "/") || strings.ContainsRune(p, '\\') {
		return "", errf("appx_invalid_path", "path must be relative to your home directory")
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	for _, s := range parts {
		if s == "" || s == "." || s == ".." || !relSegRe.MatchString(s) {
			return "", errf("appx_invalid_path", "invalid path segment %q", s)
		}
	}
	if len(parts) > 16 {
		return "", errf("appx_invalid_path", "path too deep")
	}
	return path.Join(parts...), nil
}

// Within reports whether rel (already CleanRel'd) is base or below it.
func Within(base, rel string) bool {
	return rel == base || strings.HasPrefix(rel, base+"/")
}

// CleanURLPath validates the public URL path of an app ("/" or "/a/b").
func CleanURLPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return "/", nil
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	for _, s := range strings.Split(strings.Trim(p, "/"), "/") {
		if s == "" || s == "." || s == ".." || !relSegRe.MatchString(s) {
			return "", errf("appx_invalid_url_path", "invalid URL path %q", p)
		}
	}
	p = "/" + strings.Trim(p, "/")
	if p == "/.well-known" || strings.HasPrefix(p, "/.well-known/") || len(p) > 200 {
		return "", errf("appx_invalid_url_path", "reserved URL path %q", p)
	}
	return p, nil
}

// Validate normalises and checks an app (port excluded: AllocPort).
func (a *App) Validate() error {
	if !ValidName(a.Name) {
		return errf("appx_invalid_name", "name: lowercase letters, digits and '-', 1-32 chars")
	}
	if a.Runtime != RuntimeNode && a.Runtime != RuntimePython && a.Runtime != RuntimeRuby {
		return errf("appx_invalid_runtime", "runtime must be node, python or ruby")
	}
	if !versionRe.MatchString(a.Version) {
		return errf("appx_invalid_runtime", "invalid runtime version %q", a.Version)
	}
	var err error
	if a.Root, err = CleanRel(a.Root); err != nil {
		return err
	}
	if a.Startup, err = CleanRel(a.Startup); err != nil {
		return err
	}
	if a.Domain != "" {
		if a.URLPath, err = CleanURLPath(a.URLPath); err != nil {
			return err
		}
	} else {
		a.URLPath = ""
	}
	if len(a.Env) > MaxEnv {
		return errf("appx_invalid_env", "at most %d environment variables", MaxEnv)
	}
	for k, v := range a.Env {
		if !envKeyRe.MatchString(k) || k == "PORT" || strings.HasPrefix(k, "LD_") || k == "NODE_OPTIONS" || k == "PYTHONPATH" || k == "RUBYOPT" || k == "RUBYLIB" {
			return errf("appx_invalid_env", "invalid or reserved variable %q", k)
		}
		if len(v) > 4096 || strings.ContainsAny(v, "\x00\r\n") {
			return errf("appx_invalid_env", "invalid value for %q", k)
		}
	}
	return nil
}

// AllocPort returns the lowest port in [lo,hi] not in used.
func AllocPort(used map[int]bool, lo, hi int) (int, error) {
	if lo < 1024 || hi > 65535 || lo > hi {
		return 0, errf("appx_port_range", "invalid port range %d-%d", lo, hi)
	}
	for p := lo; p <= hi; p++ {
		if !used[p] {
			return p, nil
		}
	}
	return 0, errf("appx_no_free_port", "no free port in %d-%d", lo, hi)
}

// UnitName is the systemd instance of an app.
func UnitName(id int64) string { return "bpanel-app@" + strconv.FormatInt(id, 10) + ".service" }

// UnitTemplate is /etc/systemd/system/bpanel-app@.service: the hardening
// shared by every app. The per-app drop-in adds User/Slice/ExecStart.
const UnitTemplate = `# Managed by BOZKURT PANEL — changes are overwritten.
[Unit]
Description=BPANEL application %i
After=network.target

[Service]
Type=simple
Restart=on-failure
RestartSec=3
TimeoutStopSec=20
UMask=0027
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
TemporaryFileSystem=/home:ro
`

func unitQuote(s string) (string, error) {
	if strings.ContainsAny(s, "\x00\r\n\"\\$%' ;") {
		return "", errf("appx_invalid_path", "unsafe value %q", s)
	}
	return s, nil
}

// RenderDropIn renders /etc/systemd/system/bpanel-app@<id>.service.d/bpanel.conf.
// home/bin/startup are absolute paths checked by the caller; they are
// still refused here when they carry unit-file metacharacters.
func RenderDropIn(a App, home, slice, bin, envFile string) (string, error) {
	for _, s := range []string{home, slice, bin, envFile, a.User} {
		if _, err := unitQuote(s); err != nil {
			return "", err
		}
	}
	root := path.Join(home, a.Root)
	start := path.Join(root, a.Startup)
	if !strings.HasPrefix(root, home+"/") || !strings.HasPrefix(start, root+"/") {
		return "", errf("appx_invalid_path", "app outside the home directory")
	}
	if _, err := unitQuote(start); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by BOZKURT PANEL — app %q of %s\n[Service]\n", a.Name, a.User)
	fmt.Fprintf(&b, "User=%s\nGroup=%s\nSlice=%s\n", a.User, a.User, slice)
	fmt.Fprintf(&b, "BindPaths=%s\nReadWritePaths=%s\nWorkingDirectory=%s\n", home, root, root)
	fmt.Fprintf(&b, "Environment=PORT=%d HOST=127.0.0.1\n", a.Port)
	switch a.Runtime {
	case RuntimeNode:
		b.WriteString("Environment=NODE_ENV=production\n")
	case RuntimeRuby:
		fmt.Fprintf(&b, "Environment=RACK_ENV=production RAILS_ENV=production GEM_HOME=%s/.gem BUNDLE_PATH=vendor/bundle\n", root)
	default:
		b.WriteString("Environment=PYTHONUNBUFFERED=1\n")
	}
	fmt.Fprintf(&b, "EnvironmentFile=-%s\nExecStart=%s %s\n", envFile, bin, start)
	return b.String(), nil
}

// RenderEnvFile renders the EnvironmentFile (values double-quoted, escaped).
func RenderEnvFile(env map[string]string) string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		v := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", `\$`).Replace(env[k])
		fmt.Fprintf(&b, "%s=\"%s\"\n", k, v)
	}
	return b.String()
}

// RenderProxy renders the nginx include of one domain (every path except
// "/", which the vhost template serves itself through AppXRootPort).
func RenderProxy(entries []Proxy) (string, error) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].URLPath < entries[j].URLPath })
	var b strings.Builder
	b.WriteString("# Managed by BOZKURT PANEL — application proxy locations.\n")
	seen := map[string]bool{}
	for _, e := range entries {
		p, err := CleanURLPath(e.URLPath)
		if err != nil {
			return "", err
		}
		if e.Port < 1024 || e.Port > 65535 {
			return "", errf("appx_port_range", "invalid port %d", e.Port)
		}
		if p == "/" {
			continue
		}
		if seen[p] {
			return "", errf("appx_url_path_taken", "%s is used twice", p)
		}
		seen[p] = true
		fmt.Fprintf(&b, "location = %s { return 301 %s/$is_args$args; }\n", p, p)
		fmt.Fprintf(&b, "location ^~ %s/ {\n    proxy_pass http://127.0.0.1:%d/;\n", p, e.Port)
		b.WriteString("    proxy_http_version 1.1;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection $http_connection;\n")
		b.WriteString("    proxy_set_header Host $host;\n    proxy_set_header X-Real-IP $remote_addr;\n")
		b.WriteString("    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n    proxy_set_header X-Forwarded-Proto $scheme;\n")
		fmt.Fprintf(&b, "    proxy_set_header X-Forwarded-Prefix %s;\n    proxy_read_timeout 300;\n}\n", p)
	}
	return b.String(), nil
}

// RootPort returns the port of the "/" entry (0 when none).
func RootPort(entries []Proxy) int {
	for _, e := range entries {
		if p, err := CleanURLPath(e.URLPath); err == nil && p == "/" {
			return e.Port
		}
	}
	return 0
}
