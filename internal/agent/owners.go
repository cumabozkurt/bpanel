package agent

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cumabozkurt/bpanel/internal/validate"
)

// Agent-side ownership registry (CODE-27).
//
// The agent no longer takes the API's word for which hosting account a
// domain, DNS zone or mail domain belongs to. Every name is recorded in a
// root-owned registry (<owners_dir>/<kind>/<name>, JSON {"owner","parent"})
// when it is first claimed, and every later action on it must name the same
// owner. The rules:
//
//   - a name can be held by one account only, across all kinds (web, zone,
//     mail): another account's claim fails with owned_by_another_account;
//   - a name below or above a name another account holds cannot be claimed
//     (agent-side mirror of the API's SEC-6 rule);
//   - edits and deletes of a registered name by another owner fail; edits
//     of an unregistered name adopt it for the caller (migration from v0.1/
//     v0.2-pre installs, see inferOwner for the vhost-based import);
//   - removing a vhost, zone or mail domain releases its entry; terminating
//     an account releases everything it held.
//
// Limits: a fully compromised API user can still name the right owner for
// a victim's domain (the API is the identity provider). What the registry
// prevents is an API bug or a compromised API redirecting one tenant's
// name to another, re-pointing an existing zone/mail domain at a new owner,
// and acting on names no account holds without claiming them.

const (
	kindWeb  = "web"
	kindZone = "zone"
	kindMail = "mail"
)

var allKinds = []string{kindWeb, kindZone, kindMail}

type ownerEntry struct {
	Owner  string `json:"owner"`
	Parent string `json:"parent,omitempty"` // web aliases: the vhost they belong to
}

func (a *Agent) ownersDir() string {
	if a.Cfg.OwnersDir != "" {
		return a.Cfg.OwnersDir
	}
	return "/etc/bpanel/owners"
}

func normName(n string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".") }

func (a *Agent) ownerPath(kind, name string) (string, error) {
	n := normName(name)
	if validate.Domain(n) != nil || strings.ContainsAny(n, "/\\") {
		return "", errf("invalid_domain", "%s", name)
	}
	return filepath.Join(a.ownersDir(), kind, n), nil
}

func (a *Agent) readOwner(kind, name string) (ownerEntry, bool, error) {
	var e ownerEntry
	p, err := a.ownerPath(kind, name)
	if err != nil {
		return e, false, err
	}
	st, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return e, false, nil
	}
	if err != nil {
		return e, false, err
	}
	if !st.Mode().IsRegular() {
		return e, false, errf("owner_registry_corrupt", "%s is not a regular file", p)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return e, false, err
	}
	if err := json.Unmarshal(b, &e); err != nil || e.Owner == "" {
		return e, false, errf("owner_registry_corrupt", "%s", p)
	}
	return e, true, nil
}

func (a *Agent) writeOwner(kind, name string, e ownerEntry) error {
	p, err := a.ownerPath(kind, name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(e)
	return writeAtomic(p, append(b, '\n'), 0o600, -1, -1)
}

func (a *Agent) dropOwner(kind, name string) error {
	p, err := a.ownerPath(kind, name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// conflict reports another account holding name (any kind) or a name
// directly related to it (parent or child label chain).
func (a *Agent) conflict(name, owner string) error {
	n := normName(name)
	for _, k := range allKinds {
		if e, ok, err := a.readOwner(k, n); err != nil {
			return err
		} else if ok && e.Owner != owner {
			return errf("owned_by_another_account", "%s belongs to another account", n)
		}
		// parents: a.b.example.com -> b.example.com -> example.com
		for p := n; ; {
			_, rest, ok := strings.Cut(p, ".")
			if !ok || !strings.Contains(rest, ".") {
				break
			}
			p = rest
			if validate.IsPublicSuffix(p) {
				continue // a stale public-suffix entry never blocks (R2-WB-4)
			}
			if e, ok, err := a.readOwner(k, p); err != nil {
				return err
			} else if ok && e.Owner != owner {
				return errf("owned_by_another_account", "%s is below %s, which belongs to another account", n, p)
			}
		}
		// children
		ents, err := os.ReadDir(filepath.Join(a.ownersDir(), k))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		for _, de := range ents {
			if !strings.HasSuffix(de.Name(), "."+n) {
				continue
			}
			if e, ok, err := a.readOwner(k, de.Name()); err != nil {
				return err
			} else if ok && e.Owner != owner {
				return errf("owned_by_another_account", "%s is above %s, which belongs to another account", n, de.Name())
			}
		}
	}
	return nil
}

// claim registers name for owner (idempotent for the same owner).
func (a *Agent) claim(kind, name, owner, parent string) error {
	if owner == "" {
		return errf("owner_required", "%s %s: no owning account given", kind, name)
	}
	if validate.IsPublicSuffix(normName(name)) {
		// R2-WB-4: "com.tr" would make the account the parent of every *.com.tr
		return errf("public_suffix", "%s is a public suffix", normName(name))
	}
	defer a.lock("owners")()
	if err := a.conflict(name, owner); err != nil {
		return err
	}
	e, ok, err := a.readOwner(kind, name)
	if err != nil {
		return err
	}
	if ok && e.Owner == owner && e.Parent == parent {
		return nil
	}
	if !ok {
		if inferred := a.inferOwner(name); inferred != "" && inferred != owner {
			return errf("owned_by_another_account", "%s is served for another account", normName(name))
		}
	}
	return a.writeOwner(kind, name, ownerEntry{Owner: owner, Parent: parent})
}

// mustOwn checks that owner holds name in kind. An unregistered name is
// adopted for owner when nobody else holds it or anything related to it
// (or, for web/zone, when the existing nginx vhost proves who serves it).
func (a *Agent) mustOwn(kind, name, owner string) error {
	if owner == "" {
		return errf("owner_required", "%s %s: no owning account given", kind, name)
	}
	e, ok, err := a.readOwner(kind, name)
	if err != nil {
		return err
	}
	if ok {
		if e.Owner != owner {
			return errf("owned_by_another_account", "%s belongs to another account", normName(name))
		}
		return nil
	}
	if inferred := a.inferOwner(name); inferred != "" && inferred != owner {
		return errf("owned_by_another_account", "%s is served for another account", normName(name))
	}
	a.Log.Info("owner registry: adopting unregistered name", "kind", kind, "name", normName(name), "owner", owner)
	return a.claim(kind, name, owner, "")
}

// ownsAny is true when owner holds name in any kind (used for FTP logins
// and mailboxes on a domain, which must belong to the account).
func (a *Agent) ownsAny(name, owner, adoptKind string) error {
	if owner == "" {
		return errf("owner_required", "%s: no owning account given", name)
	}
	held := false
	for _, k := range allKinds {
		e, ok, err := a.readOwner(k, name)
		if err != nil {
			return err
		}
		if ok && e.Owner != owner {
			return errf("owned_by_another_account", "%s belongs to another account", normName(name))
		}
		held = held || ok
	}
	if held {
		return nil
	}
	// www.example.com is covered by example.com: accept without registering
	// a separate (and later stale) entry.
	if err := a.conflict(name, owner); err != nil {
		return err
	}
	for p := normName(name); ; {
		_, rest, ok := strings.Cut(p, ".")
		if !ok || !strings.Contains(rest, ".") {
			break
		}
		p = rest
		if validate.IsPublicSuffix(p) {
			continue // owning "com.tr" proves nothing about x.com.tr (R2-WB-4)
		}
		for _, k := range allKinds {
			if e, ok, err := a.readOwner(k, p); err == nil && ok && e.Owner == owner {
				return nil
			}
		}
	}
	return a.mustOwn(adoptKind, name, owner)
}

// release drops an entry if (and only if) owner holds it.
func (a *Agent) release(kind, name, owner string) error {
	defer a.lock("owners")()
	e, ok, err := a.readOwner(kind, name)
	if err != nil || !ok {
		return err
	}
	if e.Owner != owner {
		return errf("owned_by_another_account", "%s belongs to another account", normName(name))
	}
	return a.dropOwner(kind, name)
}

// releaseChildren drops web aliases recorded under parent that are not in keep.
func (a *Agent) releaseChildren(parent, owner string, keep map[string]bool) {
	defer a.lock("owners")()
	ents, _ := os.ReadDir(filepath.Join(a.ownersDir(), kindWeb))
	for _, de := range ents {
		e, ok, err := a.readOwner(kindWeb, de.Name())
		if err != nil || !ok || e.Owner != owner || e.Parent != normName(parent) || keep[de.Name()] {
			continue
		}
		if err := a.dropOwner(kindWeb, de.Name()); err != nil {
			a.Log.Warn("owner registry: release alias", "name", de.Name(), "err", err)
		}
	}
}

// releaseAll drops every entry owner holds (account termination).
func (a *Agent) releaseAll(owner string) {
	defer a.lock("owners")()
	for _, k := range allKinds {
		ents, _ := os.ReadDir(filepath.Join(a.ownersDir(), k))
		for _, de := range ents {
			if e, ok, err := a.readOwner(k, de.Name()); err == nil && ok && e.Owner == owner {
				if err := a.dropOwner(k, de.Name()); err != nil {
					a.Log.Warn("owner registry: release", "kind", k, "name", de.Name(), "err", err)
				}
			}
		}
	}
}

var reVhostOwner = regexp.MustCompile(`^# account: ([a-z][a-z0-9]{1,15})\b`)

// inferOwner reads the owner the agent itself wrote into an existing nginx
// vhost (header comment, or the PHP-FPM socket / home path of a v0.1 file).
// Used to import names created before the registry existed.
func (a *Agent) inferOwner(name string) string {
	n := normName(name)
	if validate.Domain(n) != nil {
		return ""
	}
	f, err := os.Open(filepath.Join(a.L.NginxVhosts, n+".conf"))
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	base := strings.TrimSuffix(a.Cfg.HomeBase, "/") + "/"
	for i := 0; sc.Scan() && i < 400; i++ {
		line := sc.Text()
		if m := reVhostOwner.FindStringSubmatch(line); m != nil {
			return m[1]
		}
		if j := strings.Index(line, base); j >= 0 && strings.Contains(line, "root") {
			rest := line[j+len(base):]
			if k := strings.IndexAny(rest, "/\";"); k > 0 {
				if validate.Username(rest[:k]) == nil {
					return rest[:k]
				}
			}
		}
	}
	return ""
}
