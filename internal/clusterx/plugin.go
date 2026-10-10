// SPDX-License-Identifier: Apache-2.0

package clusterx

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// Plugin archive limits.
const (
	MaxArchiveBytes   = 8 << 20  // compressed upload
	MaxUnpackedBytes  = 32 << 20 // sum of all file sizes
	MaxFileBytes      = 8 << 20
	MaxFiles          = 512
	ManifestFile      = "plugin.json"
	SignatureFile     = "plugin.sig"
	signaturePreamble = "bpanel-plugin-v1\n"
)

// Permissions a plugin may request. Anything else is rejected at install.
// They are reviewed by the admin on the capability screen; the panel grants
// nothing outside this list (there is no plugin runtime with root access).
var Permissions = map[string]string{
	"ui.page":          "Show its own page (static files, sandboxed iframe, no access to the panel session)",
	"events.subscribe": "Receive the internal events it lists as signed webhooks (HMAC, same delivery as admin webhooks)",
	"agent.read":       "Declare read-only agent actions it relies on (from the fixed allowlist below)",
}

// AgentActions is the fixed list of existing, read-only, server-level agent
// methods a plugin may declare. Plugins cannot add or call anything else.
var AgentActions = map[string]bool{
	rpc.MSysInfo: true, rpc.MServiceStatus: true, rpc.MUpdatesStatus: true,
	rpc.MAppxRuntimes: true, rpc.MPGStatus: true, rpc.MShieldStatus: true, rpc.MF2BStatus: true,
}

var (
	reName    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)
	reVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]{1,32})?$`)
	reEvent   = regexp.MustCompile(`^(\*|[a-z][a-z0-9_]*(\.[a-z0-9_]+)*(\.\*)?)$`)
	reSPDX    = regexp.MustCompile(`^[A-Za-z0-9.+-]{2,64}( (AND|OR|WITH) [A-Za-z0-9.+-]{2,64})*$`)
	reFile    = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// ValidName reports whether name is an acceptable plugin (directory) name.
func ValidName(name string) bool { return reName.MatchString(name) }

// Hook is one declarative webhook subscription.
type Hook struct {
	Events []string `json:"events"`
	URL    string   `json:"url"`
}

// Manifest is plugin.json.
type Manifest struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Author       string   `json:"author"`
	License      string   `json:"license"`
	Description  string   `json:"description,omitempty"`
	Permissions  []string `json:"permissions"`
	UIEntry      string   `json:"ui_entry,omitempty"` // path below ui/, e.g. "index.html"
	AgentActions []string `json:"agent_actions,omitempty"`
	Hooks        []Hook   `json:"hooks,omitempty"`
}

func (m *Manifest) has(p string) bool {
	for _, x := range m.Permissions {
		if x == p {
			return true
		}
	}
	return false
}

// Validate checks the manifest against the fixed allowlists. files is the
// set of archive paths (used to check ui_entry exists); nil skips that.
func (m *Manifest) Validate(files map[string][]byte) error {
	if !reName.MatchString(m.Name) {
		return errf("plugin_invalid_manifest", "name must match %s", reName)
	}
	if !reVersion.MatchString(m.Version) {
		return errf("plugin_invalid_manifest", "version must be semantic (1.2.3)")
	}
	if a := strings.TrimSpace(m.Author); a == "" || len(a) > 128 {
		return errf("plugin_invalid_manifest", "author required (max 128 chars)")
	}
	if !reSPDX.MatchString(m.License) {
		return errf("plugin_invalid_manifest", "license must be an SPDX identifier")
	}
	if len(m.Description) > 512 {
		return errf("plugin_invalid_manifest", "description too long")
	}
	seen := map[string]bool{}
	for _, p := range m.Permissions {
		if _, ok := Permissions[p]; !ok {
			return errf("plugin_permission_denied", "permission %q is not in the allowed list", p)
		}
		if seen[p] {
			return errf("plugin_invalid_manifest", "duplicate permission %q", p)
		}
		seen[p] = true
	}
	if m.UIEntry != "" {
		if !m.has("ui.page") {
			return errf("plugin_permission_denied", "ui_entry needs the ui.page permission")
		}
		if err := checkRelPath(m.UIEntry); err != nil {
			return err
		}
		if files != nil {
			if _, ok := files["ui/"+m.UIEntry]; !ok {
				return errf("plugin_invalid_manifest", "ui_entry ui/%s is not in the archive", m.UIEntry)
			}
		}
	}
	if len(m.AgentActions) > 0 && !m.has("agent.read") {
		return errf("plugin_permission_denied", "agent_actions need the agent.read permission")
	}
	for _, a := range m.AgentActions {
		if !AgentActions[a] {
			return errf("plugin_unknown_action", "agent action %q is not an allowed existing read-only action", a)
		}
	}
	if len(m.Hooks) > 0 && !m.has("events.subscribe") {
		return errf("plugin_permission_denied", "hooks need the events.subscribe permission")
	}
	if len(m.Hooks) > 8 {
		return errf("plugin_invalid_manifest", "at most 8 hooks")
	}
	for _, h := range m.Hooks {
		u, err := url.Parse(h.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || len(h.URL) > 2048 {
			return errf("plugin_invalid_manifest", "hook url must be http(s) without credentials")
		}
		if len(h.Events) == 0 || len(h.Events) > 32 {
			return errf("plugin_invalid_manifest", "a hook needs 1..32 events")
		}
		for _, e := range h.Events {
			if !reEvent.MatchString(e) || len(e) > 64 {
				return errf("plugin_invalid_manifest", "invalid event filter %q", e)
			}
		}
	}
	return nil
}

func checkRelPath(p string) error {
	if p == "" || len(p) > 200 || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || strings.ContainsRune(p, 0) {
		return errf("plugin_unsafe_path", "unsafe path %q", p)
	}
	if path.Clean(p) != p {
		return errf("plugin_unsafe_path", "non-canonical path %q", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." || !reFile.MatchString(seg) {
			return errf("plugin_unsafe_path", "unsafe path %q", p)
		}
	}
	return nil
}

// Extract reads a .tar.gz plugin archive fully into memory. Only regular
// files and directories are accepted; symlinks, hard links, devices, FIFOs,
// absolute paths, ".." segments, odd characters, oversized files and too
// many entries are rejected. Files must be plugin.json, plugin.sig or below
// ui/. A leading "./" is tolerated. Nothing touches the disk.
func Extract(archive []byte) (map[string][]byte, error) {
	if len(archive) > MaxArchiveBytes {
		return nil, errf("plugin_too_large", "archive larger than %d bytes", MaxArchiveBytes)
	}
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, errf("plugin_invalid_archive", "not a gzip file")
	}
	tr := tar.NewReader(zr)
	files := map[string][]byte{}
	total := int64(0)
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errf("plugin_invalid_archive", "corrupt tar")
		}
		if n >= MaxFiles {
			return nil, errf("plugin_too_large", "more than %d entries", MaxFiles)
		}
		name := strings.TrimPrefix(h.Name, "./")
		switch h.Typeflag {
		case tar.TypeDir:
			name = strings.TrimSuffix(name, "/")
			if name == "" || name == "." {
				continue
			}
			if err := checkRelPath(name); err != nil {
				return nil, err
			}
			continue
		case tar.TypeReg:
		case tar.TypeSymlink, tar.TypeLink:
			return nil, errf("plugin_unsafe_path", "links are not allowed (%q)", h.Name)
		default:
			return nil, errf("plugin_unsafe_path", "entry type %q not allowed (%q)", string(h.Typeflag), h.Name)
		}
		if err := checkRelPath(name); err != nil {
			return nil, err
		}
		if name != ManifestFile && name != SignatureFile && !strings.HasPrefix(name, "ui/") {
			return nil, errf("plugin_unsafe_path", "unexpected file %q (only plugin.json, plugin.sig, ui/...)", name)
		}
		if _, dup := files[name]; dup {
			return nil, errf("plugin_invalid_archive", "duplicate entry %q", name)
		}
		if h.Size < 0 || h.Size > MaxFileBytes {
			return nil, errf("plugin_too_large", "file %q too large", name)
		}
		total += h.Size
		if total > MaxUnpackedBytes {
			return nil, errf("plugin_too_large", "unpacked size over %d bytes", MaxUnpackedBytes)
		}
		b, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil || int64(len(b)) != h.Size {
			return nil, errf("plugin_invalid_archive", "short read %q", name)
		}
		files[name] = b
	}
	if _, ok := files[ManifestFile]; !ok {
		return nil, errf("plugin_invalid_manifest", "plugin.json missing")
	}
	return files, nil
}

// ParseManifest decodes plugin.json strictly.
func ParseManifest(b []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, errf("plugin_invalid_manifest", "plugin.json: %v", err)
	}
	return &m, nil
}

// SigningPayload is what the ed25519 signature covers: a preamble and the
// sha256 of every file except plugin.sig, sorted by path.
func SigningPayload(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for n := range files {
		if n != SignatureFile {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var b bytes.Buffer
	b.WriteString(signaturePreamble)
	for _, n := range names {
		sum := sha256.Sum256(files[n])
		b.WriteString(hex.EncodeToString(sum[:]) + "  " + n + "\n")
	}
	return b.Bytes()
}

// ParsePublicKey accepts a base64 (std or raw) 32-byte ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
	}
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errf("plugin_invalid_key", "expected a base64 32-byte ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

// KeyID is a short fingerprint shown in the UI.
func KeyID(k ed25519.PublicKey) string {
	s := sha256.Sum256(k)
	return hex.EncodeToString(s[:8])
}

// Verify checks plugin.sig against the trusted keys and returns the id of
// the key that signed it.
func Verify(files map[string][]byte, trusted []ed25519.PublicKey) (string, error) {
	raw, ok := files[SignatureFile]
	if !ok {
		return "", errf("plugin_bad_signature", "plugin.sig missing")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", errf("plugin_bad_signature", "plugin.sig is not a base64 ed25519 signature")
	}
	if len(trusted) == 0 {
		return "", errf("plugin_untrusted", "no trusted signing keys configured")
	}
	payload := SigningPayload(files)
	for _, k := range trusted {
		if ed25519.Verify(k, payload, sig) {
			return KeyID(k), nil
		}
	}
	return "", errf("plugin_bad_signature", "signature does not match any trusted key")
}

// Sign produces plugin.sig content (used by tests and examples/plugins/sign).
func Sign(files map[string][]byte, priv ed25519.PrivateKey) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, SigningPayload(files))) + "\n")
}

// Load = Extract + ParseManifest + Validate (no signature check).
func Load(archive []byte) (map[string][]byte, *Manifest, error) {
	files, err := Extract(archive)
	if err != nil {
		return nil, nil, err
	}
	m, err := ParseManifest(files[ManifestFile])
	if err != nil {
		return nil, nil, err
	}
	if err := m.Validate(files); err != nil {
		return nil, nil, err
	}
	return files, m, nil
}

// PackTarGz builds an archive from files (tests, examples).
func PackTarGz(files map[string][]byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), Typeflag: tar.TypeReg})
		_, _ = tw.Write(files[n])
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

// ValidRelPath reports whether p is a safe relative file path (no "..",
// no absolute path, conservative characters).
func ValidRelPath(p string) bool { return checkRelPath(p) == nil }
