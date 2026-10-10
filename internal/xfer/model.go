// SPDX-License-Identifier: Apache-2.0

package xfer

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path"
	"sort"
	"strings"
)

// Formats recognised by Analyse.
const (
	FormatBPanel = "bpanel"
	FormatCPanel = "cpanel"
	FormatHestia = "hestia"

	ManifestName    = "manifest.json"
	ManifestFormat  = "bpanel-xfer"
	ManifestVersion = 1
)

// Model is the format-independent description of one account to import.
// It never carries password hashes or key material in JSON (json:"-").
type Model struct {
	Format        string       `json:"format"`
	FormatVersion int          `json:"format_version,omitempty"`
	Root          string       `json:"root,omitempty"` // archive top directory ("" or "cpmove-alice")
	Account       Account      `json:"account"`
	Domains       []Domain     `json:"domains"`
	Databases     []Database   `json:"databases"`
	Zones         []Zone       `json:"zones"`
	Mailboxes     []Mailbox    `json:"mailboxes"`
	Forwarders    []Forwarder  `json:"forwarders"`
	Certs         []Cert       `json:"certs"`
	Home          HomeInfo     `json:"home"`
	Unsupported   []ReportItem `json:"unsupported"`
	Warnings      []string     `json:"warnings"`
}

type Account struct {
	Username   string `json:"username"`
	Email      string `json:"email,omitempty"`
	MainDomain string `json:"main_domain"`
	Plan       string `json:"plan,omitempty"`
}

type Domain struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"` // main | addon | parked | sub
	DocRoot string `json:"docroot,omitempty"`
}

type Database struct {
	Name  string `json:"name"`
	Dump  string `json:"dump"` // archive member (relative to Root)
	Bytes int64  `json:"bytes"`
}

type Zone struct {
	Domain string `json:"domain"`
	Member string `json:"member"`
	Text   string `json:"-"`
}

type Mailbox struct {
	Address string `json:"address"`
	QuotaMB int64  `json:"quota_mb"`
	HasHash bool   `json:"has_hash"`
	Hash    string `json:"-"`
}

type Forwarder struct {
	From string   `json:"from"`
	To   []string `json:"to"`
}

type Cert struct {
	Domain  string   `json:"domain"`
	HasKey  bool     `json:"has_key"`
	Members []string `json:"-"`
}

type HomeInfo struct {
	Prefix string `json:"prefix"` // archive dir holding the home directory
	Files  int    `json:"files"`
	Bytes  int64  `json:"bytes"`
}

type ReportItem struct {
	Part   string `json:"part"`
	Reason string `json:"reason"`
}

// ---- BPanel manifest ----------------------------------------------------------

type ManifestFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest is manifest.json of a BPanel account archive.
type Manifest struct {
	Format        string         `json:"format"`
	Version       int            `json:"version"`
	CreatedAt     int64          `json:"created_at"`
	SourceHost    string         `json:"source_host,omitempty"`
	BPanelVersion string         `json:"bpanel_version,omitempty"`
	Account       Account        `json:"account"`
	Domains       []Domain       `json:"domains"`
	Databases     []Database     `json:"databases"`
	Zones         []Zone         `json:"zones"`
	Forwarders    []Forwarder    `json:"forwarders"`
	Certs         []Cert         `json:"certs"`
	Files         []ManifestFile `json:"files"`
}

// Writer builds a BPanel account archive: members first, manifest.json last
// (with the size and SHA-256 of every member).
type Writer struct {
	tw    *tar.Writer
	files []ManifestFile
	seen  map[string]bool
}

func NewWriter(w io.Writer) *Writer { return &Writer{tw: tar.NewWriter(w), seen: map[string]bool{}} }

// AddFile adds a regular member of exactly size bytes.
func (w *Writer) AddFile(name string, mode int64, size int64, r io.Reader) error {
	c, err := CleanName(name)
	if err != nil || c == ManifestName || w.seen[c] {
		return errf(ErrManifest, "bad or duplicate member %q", trunc(name))
	}
	w.seen[c] = true
	if err := w.tw.WriteHeader(&tar.Header{Name: c, Mode: mode & 0o777, Size: size, Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(w.tw, io.TeeReader(io.LimitReader(r, size), h))
	if err != nil {
		return err
	}
	if n != size {
		return errf(ErrManifest, "short member %q", trunc(name))
	}
	w.files = append(w.files, ManifestFile{Path: c, Size: size, SHA256: hex.EncodeToString(h.Sum(nil))})
	return nil
}

// AddBytes is AddFile for in-memory content.
func (w *Writer) AddBytes(name string, b []byte) error {
	return w.AddFile(name, 0o600, int64(len(b)), strings.NewReader(string(b)))
}

// AddDir and AddSymlink add structure members (checked by name only).
func (w *Writer) AddDir(name string, mode int64) error {
	c, err := CleanName(name)
	if err != nil {
		return err
	}
	return w.tw.WriteHeader(&tar.Header{Name: c + "/", Mode: mode & 0o777, Typeflag: tar.TypeDir, Format: tar.FormatPAX})
}

func (w *Writer) AddSymlink(name, target string) error {
	c, err := CleanName(name)
	if err != nil {
		return err
	}
	if !LinkInside(c, target) {
		return nil // links leaving the account are not exported
	}
	return w.tw.WriteHeader(&tar.Header{Name: c, Linkname: target, Typeflag: tar.TypeSymlink, Mode: 0o777, Format: tar.FormatPAX})
}

// Close writes manifest.json (Files filled in) and closes the tar stream.
func (w *Writer) Close(m Manifest) error {
	m.Format, m.Version = ManifestFormat, ManifestVersion
	m.Files = w.files
	b, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	if err := w.tw.WriteHeader(&tar.Header{Name: ManifestName, Mode: 0o600, Size: int64(len(b)), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
		return err
	}
	if _, err := w.tw.Write(b); err != nil {
		return err
	}
	return w.tw.Close()
}

// ---- Analyse --------------------------------------------------------------------

// scan is what one pass over an archive collects.
type scan struct {
	names  []string
	meta   map[string][]byte // small metadata members by name
	sizes  map[string]int64
	sums   map[string]string // sha256 of every regular member
	topDir string
}

func wantMeta(name string) bool {
	rel := name
	if i := strings.IndexByte(name, '/'); i > 0 && (strings.HasPrefix(name, "cpmove-") || strings.HasPrefix(name, "backup-")) {
		rel = name[i+1:]
	}
	if rel == ManifestName || strings.HasPrefix(rel, "mail/") || strings.HasPrefix(rel, "dnszones/") ||
		strings.HasPrefix(rel, "cp/") || strings.HasPrefix(rel, "userdata/") || strings.HasPrefix(rel, "va/") ||
		strings.HasPrefix(rel, "sslcerts/") || strings.HasPrefix(rel, "sslkeys/") || strings.HasPrefix(rel, "ssl/") ||
		rel == "version" || rel == "pam/passwd" || rel == "hestia/user.conf" {
		return true
	}
	if strings.HasPrefix(rel, "etc/") {
		b := path.Base(rel)
		return b == "passwd" || b == "shadow" || b == "quota"
	}
	return false
}

func collect(archive string, lim Limits) (*scan, error) {
	s := &scan{meta: map[string][]byte{}, sizes: map[string]int64{}, sums: map[string]string{}}
	err := WalkFile(archive, lim, func(e Entry, body io.Reader) error {
		s.names = append(s.names, e.Name)
		if e.Type != tar.TypeReg {
			return nil
		}
		s.sizes[e.Name] = e.Size
		h := sha256.New()
		var r io.Reader = body
		if wantMeta(e.Name) && e.Size <= lim.MaxMetaBytes {
			b, err := io.ReadAll(io.TeeReader(body, h))
			if err != nil {
				return err
			}
			s.meta[e.Name] = b
		} else if _, err := io.Copy(h, r); err != nil {
			return err
		}
		s.sums[e.Name] = hex.EncodeToString(h.Sum(nil))
		return nil
	})
	return s, err
}

// Analyse reads an archive once and returns its import model. A BPanel
// archive is verified against its manifest (sizes, SHA-256, no extra or
// missing members).
func Analyse(archive string, lim Limits) (*Model, error) {
	if lim.MaxMetaBytes == 0 {
		lim.MaxMetaBytes = DefaultLimits.MaxMetaBytes
	}
	s, err := collect(archive, lim)
	if err != nil {
		return nil, err
	}
	switch {
	case s.meta[ManifestName] != nil:
		return analyseBPanel(s)
	case isCPanel(s):
		return analyseCPanel(s)
	case isHestia(s):
		return analyseHestia(s)
	}
	return nil, errf(ErrFormat, "not a BPanel, cPanel or HestiaCP account backup")
}

func analyseBPanel(s *scan) (*Model, error) {
	var m Manifest
	if err := json.Unmarshal(s.meta[ManifestName], &m); err != nil {
		return nil, errf(ErrManifest, "manifest.json: %v", err)
	}
	if m.Format != ManifestFormat || m.Version < 1 || m.Version > ManifestVersion {
		return nil, errf(ErrManifest, "format %q version %d not supported", m.Format, m.Version)
	}
	listed := map[string]bool{}
	for _, f := range m.Files {
		c, err := CleanName(f.Path)
		if err != nil || listed[c] {
			return nil, errf(ErrManifest, "bad file entry %q", trunc(f.Path))
		}
		listed[c] = true
		sum, ok := s.sums[c]
		if !ok {
			return nil, errf(ErrChecksum, "%q listed in manifest but missing", trunc(c))
		}
		if s.sizes[c] != f.Size || !strings.EqualFold(sum, f.SHA256) {
			return nil, errf(ErrChecksum, "%q does not match the manifest", trunc(c))
		}
	}
	for n := range s.sums {
		if n != ManifestName && !listed[n] {
			return nil, errf(ErrChecksum, "%q is not listed in the manifest", trunc(n))
		}
	}
	md := &Model{Format: FormatBPanel, FormatVersion: m.Version, Account: m.Account, Domains: m.Domains,
		Databases: m.Databases, Forwarders: m.Forwarders, Certs: m.Certs, Home: HomeInfo{Prefix: "homedir"}}
	for _, z := range m.Zones {
		z.Text = string(s.meta[z.Member])
		md.Zones = append(md.Zones, z)
	}
	if b := s.meta["mail/mailboxes.json"]; b != nil {
		var mbs []struct {
			Address string `json:"address"`
			QuotaMB int64  `json:"quota_mb"`
			Hash    string `json:"hash"`
		}
		if err := json.Unmarshal(b, &mbs); err != nil {
			return nil, errf(ErrManifest, "mail/mailboxes.json: %v", err)
		}
		for _, x := range mbs {
			md.Mailboxes = append(md.Mailboxes, Mailbox{Address: x.Address, QuotaMB: x.QuotaMB, Hash: x.Hash, HasHash: x.Hash != ""})
		}
	}
	homeStats(md, s)
	return md.normalise(), nil
}

func homeStats(md *Model, s *scan) {
	pre := strings.Trim(path.Join(md.Root, md.Home.Prefix), "/") + "/"
	for n, sz := range s.sizes {
		if strings.HasPrefix(n, pre) {
			md.Home.Files++
			md.Home.Bytes += sz
		}
	}
}

func (m *Model) normalise() *Model {
	if m.Domains == nil {
		m.Domains = []Domain{}
	}
	if m.Databases == nil {
		m.Databases = []Database{}
	}
	if m.Zones == nil {
		m.Zones = []Zone{}
	}
	if m.Mailboxes == nil {
		m.Mailboxes = []Mailbox{}
	}
	if m.Forwarders == nil {
		m.Forwarders = []Forwarder{}
	}
	if m.Certs == nil {
		m.Certs = []Cert{}
	}
	if m.Unsupported == nil {
		m.Unsupported = []ReportItem{}
	}
	if m.Warnings == nil {
		m.Warnings = []string{}
	}
	sort.Slice(m.Databases, func(i, j int) bool { return m.Databases[i].Name < m.Databases[j].Name })
	sort.Slice(m.Zones, func(i, j int) bool { return m.Zones[i].Domain < m.Zones[j].Domain })
	sort.Slice(m.Mailboxes, func(i, j int) bool { return m.Mailboxes[i].Address < m.Mailboxes[j].Address })
	sort.Slice(m.Forwarders, func(i, j int) bool { return m.Forwarders[i].From < m.Forwarders[j].From })
	return m
}

// Member returns the archive member path of a model-relative path.
func (m *Model) Member(rel string) string {
	if m.Root == "" {
		return rel
	}
	return m.Root + "/" + rel
}

// HomePrefix is the archive directory to extract into the home directory.
func (m *Model) HomePrefix() string { return m.Member(m.Home.Prefix) }
