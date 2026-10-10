package agent

import (
	"strconv"
	"strings"
)

// mailLockPrefix marks a suspended mailbox in the Dovecot passwd-file. The
// stored hash is kept after the prefix so unsuspending restores it exactly.
// "{CRYPT}!..." is a crypt(3) hash that can never match, so Dovecot answers
// a clean "auth failed" for IMAP/POP3 and for Postfix SMTP AUTH alike. (The
// passdb "nologin" extra field was tried in the E2E container: it does not
// stop SMTP AUTH and IMAP reports an internal failure instead.)
const mailLockPrefix = "{CRYPT}!"

// setMailLock locks (or unlocks) every mailbox owned by uid. It only
// rewrites the passwd-file when something changed.
func (a *Agent) setMailLock(uid int, lock bool) error {
	path := a.dovecotPasswd()
	defer a.lock("mail")()
	m, err := readMap(path, ":")
	if err != nil || len(m) == 0 {
		return err
	}
	id := strconv.Itoa(uid)
	changed := false
	for i := range m {
		f := strings.SplitN(m[i][1], ":", 3)
		if len(f) < 3 || f[1] != id {
			continue
		}
		locked := strings.HasPrefix(f[0], mailLockPrefix)
		switch {
		case lock && !locked:
			f[0] = mailLockPrefix + f[0]
		case !lock && locked:
			f[0] = strings.TrimPrefix(f[0], mailLockPrefix)
		default:
			continue
		}
		m[i][1] = strings.Join(f, ":")
		changed = true
	}
	if !changed {
		return nil
	}
	if err := writeMap(path, ":", m, 0o640); err != nil {
		return err
	}
	a.fixDovecotPerms()
	return nil
}

// mailLocked reports whether any mailbox of uid is currently locked, so a
// mailbox created or re-passworded while the account is suspended stays locked.
func (a *Agent) mailLocked(uid int) bool {
	m, _ := readMap(a.dovecotPasswd(), ":")
	id := strconv.Itoa(uid)
	for _, kv := range m {
		f := strings.SplitN(kv[1], ":", 3)
		if len(f) == 3 && f[1] == id && strings.HasPrefix(f[0], mailLockPrefix) {
			return true
		}
	}
	return false
}
