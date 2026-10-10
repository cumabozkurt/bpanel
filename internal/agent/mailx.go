// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/mailx"
)

// DovecotHomeDir is the Dovecot home inside each mailbox directory (the
// installer's userdb sets home=<box>/bpanel-home, mail=<box>): with
// home == Maildir root, Maildir++ lists Dovecot's own ~/.dovecot.lda-dupes as
// a folder and fileinto fails ("stat(.dovecot.lda-dupes/tmp): Not a
// directory"). The name has no leading dot, so Maildir++ ignores it.
const DovecotHomeDir = "bpanel-home"

// v0.4 user mail tools. Sieve scripts live in the mailbox home
// (/home/<user>/mail/<domain>/<local>/sieve/bpanel.sieve, owned by the
// account) and are activated through ~/dovecot.sieve, matching the
// installer's "sieve = file:~/sieve;active=~/dovecot.sieve" (before v1.1 the
// link was ~/.dovecot.sieve, which Maildir++ mistook for a folder). Spam rules are
// Rspamd settings-module files under RspamdBpanelDir, included from
// local.d/settings.conf. Track Delivery reads the Postfix log.

var (
	RspamdConfDir   = "/etc/rspamd"
	RspamdBpanelDir = "/etc/rspamd/bpanel.d"
	MailLogFiles    = []string{"/var/log/mail.log", "/var/log/maillog"}
	mailLogMaxBytes = int64(8 << 20)
	mailLogMaxLines = 50000
	lookPathFn      = have // tests
)

const managedMark = "# Managed by BOZKURT PANEL"

func init() {
	for _, m := range []string{rpc.MMailSieveApply, rpc.MMailSpamApply, rpc.MMailLogSearch} {
		accountField[m] = struct {
			key      string
			optional bool
		}{"user", false}
	}
}

func (a *Agent) mailxRoutes() map[string]handler {
	return map[string]handler{
		rpc.MMailSieveApply: bind(a.mailSieveApply),
		rpc.MMailSpamApply:  bind(a.mailSpamApply),
		rpc.MMailLogSearch:  bind(a.mailLogSearch),
	}
}

func mailxErr(err error) error {
	var me *mailx.Error
	if errors.As(err, &me) {
		return errf(me.Code, "%s", me.Field)
	}
	return err
}

// hasMailbox reports whether addr is a Dovecot user of this panel.
func (a *Agent) hasMailbox(addr string) bool {
	m, _ := readMap(a.dovecotPasswd(), ":")
	for _, kv := range m {
		if kv[0] == addr {
			return true
		}
	}
	return false
}

func (a *Agent) mailSieveApply(ctx context.Context, p rpc.MailSieveReq) (rpc.MailxStatus, error) {
	var res rpc.MailxStatus
	local, domain, err := splitEmail(p.Email)
	if err != nil {
		return res, err
	}
	e, err := a.home(p.User)
	if err != nil {
		return res, err
	}
	if err := a.mustOwn(kindMail, domain, p.User); err != nil {
		return res, err
	}
	addr := local + "@" + domain
	script, err := mailx.GenerateFull(addr, p.Vacation, p.Rules, p.BoxTrapper)
	if err != nil {
		return res, mailxErr(err)
	}
	defer a.lock("mail")()
	if !a.hasMailbox(addr) {
		return res, errf("not_found", "%s", addr)
	}
	root, err := openHome(e)
	if err != nil {
		return res, err
	}
	defer root.Close()
	box := "mail/" + domain + "/" + local
	if err := checkNoSymlinks(root, box); err != nil {
		return res, err
	}
	if st, err := root.Lstat(box); err != nil || !st.IsDir() {
		return res, errf("not_found", "%s", addr)
	}
	active, script0 := box+"/dovecot.sieve", box+"/sieve/bpanel.sieve"
	// pre-v1.1 activation link (a Maildir++ "folder" by name): drop it.
	if t, err := root.Readlink(box + "/.dovecot.sieve"); err == nil && t == "sieve/bpanel.sieve" {
		_ = root.Remove(box + "/.dovecot.sieve")
		_ = root.Remove(box + "/.dovecot.svbin")
	}
	if script == "" {
		_ = root.Remove(script0)
		_ = root.Remove(box + "/sieve/bpanel.svbin")
		if t, err := root.Readlink(active); err == nil && t == "sieve/bpanel.sieve" {
			_ = root.Remove(active)
		}
		return rpc.MailxStatus{Status: "inactive"}, nil
	}
	if err := mkdirOwned(root, box+"/"+DovecotHomeDir, 0o700, e.uid, e.gid, false); err != nil {
		return res, err
	}
	if err := mkdirOwned(root, box+"/sieve", 0o700, e.uid, e.gid, false); err != nil {
		return res, err
	}
	tmp := box + "/sieve/.bpanel.sieve.tmp"
	_ = root.Remove(tmp)
	if err := createFileOwned(root, tmp, []byte(script), 0o600, e.uid, e.gid); err != nil {
		return res, err
	}
	if err := root.Rename(tmp, script0); err != nil {
		_ = root.Remove(tmp)
		return res, mapFSErr(err, script0)
	}
	// activate: a script the tenant activated elsewhere (Roundcube managesieve)
	// is replaced by the panel script; a regular file is kept as a backup.
	if st, err := root.Lstat(active); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			_ = root.Remove(active)
		} else if st.Mode().IsRegular() {
			_ = root.Rename(active, box+"/sieve/previous-active.sieve")
		} else {
			return res, errf("invalid_path", "%s is not a file", active)
		}
	}
	if err := root.Symlink("sieve/bpanel.sieve", active); err != nil {
		return res, mapFSErr(err, active)
	}
	_ = root.Lchown(active, e.uid, e.gid)
	if !lookPathFn("sievec") {
		return rpc.MailxStatus{Status: "not_installed", Reason: "sievec not found: install dovecot-sieve (Debian/Ubuntu) or dovecot-pigeonhole (RHEL); the script is saved and takes effect once Pigeonhole is installed"}, nil
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if out, err := runAs(cctx, e, "sievec", filepath.Join(e.home, script0)); err != nil {
		_ = root.Remove(active) // never leave a broken script active
		return res, errf("sieve_compile_failed", "%s", strings.TrimSpace(lastLines(out, 3)))
	}
	return rpc.MailxStatus{Status: "active"}, nil
}

func (a *Agent) mailSpamApply(ctx context.Context, p rpc.MailSpamReq) (rpc.MailxStatus, error) {
	var res rpc.MailxStatus
	for _, d := range p.Domains {
		if err := a.mustOwn(kindMail, strings.ToLower(d), p.User); err != nil {
			return res, err
		}
	}
	content, err := mailx.RenderRspamd(p.User, p.Domains, p.Policy)
	if err != nil {
		return res, mailxErr(err)
	}
	if st, err := os.Stat(RspamdConfDir); err != nil || !st.IsDir() || !lookPathFn("rspamd") {
		return rpc.MailxStatus{Status: "not_installed", Reason: "rspamd is not installed on this server"}, nil
	}
	defer a.lock("rspamd")()
	incl := filepath.Join(RspamdConfDir, "local.d", "settings.conf")
	line := `.include(try=true,priority=1,duplicate=merge,glob=true) "` + RspamdBpanelDir + `/*.conf"`
	if b, err := os.ReadFile(incl); err == nil {
		if !strings.Contains(string(b), line) {
			if !strings.HasPrefix(string(b), managedMark) {
				return res, errf("rspamd_settings_conflict", "%s is not managed by the panel", incl)
			}
			if err := writeAtomic(incl, []byte(managedMark+": includes the per-account spam rules.\n"+line+"\n"), 0o644, -1, -1); err != nil {
				return res, err
			}
		}
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(incl), 0o755); err != nil {
			return res, err
		}
		if err := writeAtomic(incl, []byte(managedMark+": includes the per-account spam rules.\n"+line+"\n"), 0o644, -1, -1); err != nil {
			return res, err
		}
	} else {
		return res, err
	}
	if err := os.MkdirAll(RspamdBpanelDir, 0o755); err != nil {
		return res, err
	}
	f := filepath.Join(RspamdBpanelDir, p.User+".conf")
	if path.Base(f) != p.User+".conf" || filepath.Dir(f) != filepath.Clean(RspamdBpanelDir) {
		return res, errf("invalid_username", "%s", p.User)
	}
	old, oldErr := os.ReadFile(f)
	if content == "" {
		_ = os.Remove(f)
	} else if err := writeAtomic(f, []byte(content), 0o644, -1, -1); err != nil {
		return res, err
	}
	if lookPathFn("rspamadm") {
		cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		out, err := run(cctx, nil, "rspamadm", "configtest")
		cancel()
		if err != nil {
			if oldErr == nil {
				_ = writeAtomic(f, old, 0o644, -1, -1)
			} else {
				_ = os.Remove(f)
			}
			return res, errf("rspamd_config_invalid", "%s", strings.TrimSpace(lastLines(out, 3)))
		}
	}
	if err := a.systemctl(ctx, "reload", a.L.RspamdUnit); err != nil {
		return res, errf("action_failed", "rspamd reload failed")
	}
	if content == "" {
		return rpc.MailxStatus{Status: "inactive", Reason: "no mail domain"}, nil
	}
	return rpc.MailxStatus{Status: "active"}, nil
}

// tailLines returns the last lines of a file, reading at most max bytes.
func tailLines(p string, maxBytes int64, maxLines int) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	off := int64(0)
	if st.Size() > maxBytes {
		off = st.Size() - maxBytes
	}
	b, err := io.ReadAll(io.LimitReader(io.NewSectionReader(f, off, st.Size()-off), maxBytes))
	if err != nil {
		return nil, err
	}
	ls := strings.Split(string(b), "\n")
	if off > 0 && len(ls) > 0 {
		ls = ls[1:] // partial first line
	}
	if len(ls) > maxLines {
		ls = ls[len(ls)-maxLines:]
	}
	return ls, nil
}

func (a *Agent) mailLogSearch(ctx context.Context, p rpc.MailLogReq) (rpc.MailLogResult, error) {
	res := rpc.MailLogResult{Entries: []mailx.Delivery{}}
	owned := map[string]bool{}
	for _, d := range p.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if err := a.mustOwn(kindMail, d, p.User); err != nil {
			return res, err
		}
		owned[d] = true
	}
	if len(p.Query) > 100 || strings.ContainsAny(p.Query, "\x00\r\n") {
		return res, errf("bad_params", "query")
	}
	limit := p.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var lines []string
	for _, f := range MailLogFiles {
		if ls, err := tailLines(f, mailLogMaxBytes, mailLogMaxLines); err == nil {
			lines, res.Source = ls, "file:"+f
			break
		}
	}
	if res.Source == "" {
		if !lookPathFn("journalctl") {
			return rpc.MailLogResult{Status: "not_installed", Reason: "no mail log (/var/log/mail.log) and no journald", Entries: []mailx.Delivery{}}, nil
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		out, err := run(cctx, nil, "journalctl", "-u", "postfix*", "--no-pager", "-q", "-o", "short-iso", "-n", "50000")
		cancel()
		if err != nil {
			return rpc.MailLogResult{Status: "not_installed", Reason: "the postfix journal could not be read", Entries: []mailx.Delivery{}}, nil
		}
		if int64(len(out)) > mailLogMaxBytes {
			out = out[int64(len(out))-mailLogMaxBytes:]
		}
		lines, res.Source = strings.Split(out, "\n"), "journal"
	}
	res.Status, res.Scanned = "ok", len(lines)
	res.Entries = mailx.ParseLog(lines, owned, p.Query, limit)
	if res.Entries == nil {
		res.Entries = []mailx.Delivery{}
	}
	return res, nil
}
