// Package validate holds the input rules shared by the API and the root agent.
// Both sides validate: the API for good error messages, the agent as the
// last line of defence before anything touches the system.
package validate

import (
	"errors"
	"fmt"
	"net"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	reUser     = regexp.MustCompile(`^[a-z][a-z0-9]{1,15}$`)
	reLabel    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	reLocal    = regexp.MustCompile(`^[a-z0-9]([a-z0-9._+-]{0,62})$`)
	reFTPLocal = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	reDBSuffix = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
	rePHP      = regexp.MustCompile(`^[78]\.[0-9]$`)
	reUnit     = regexp.MustCompile(`^[a-z0-9@._-]{1,64}$`)
	reCronFld  = regexp.MustCompile(`^[0-9*/,\-A-Za-z]{1,40}$`)
	reSnap     = regexp.MustCompile(`^[0-9a-f]{8,64}$`)
	reLang     = regexp.MustCompile(`^[a-z]{2}(-[A-Z]{2})?$`)
	rePkgName  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
)

// PackageName validates a hosting package name (UX-40: emoji, padding,
// leading dashes and "a..b" used to be stored): letters, digits, '_', '.',
// '-', starting with a letter or digit, at most 64 characters, no "..".
// Errors: too_long, invalid_name.
func PackageName(s string) error {
	if len(s) > 64 {
		return errors.New("too_long")
	}
	if !rePkgName.MatchString(s) || strings.Contains(s, "..") {
		return errors.New("invalid_name")
	}
	return nil
}

// Reserved system user names that may never become hosting accounts.
var reservedUsers = map[string]bool{
	"root": true, "bin": true, "daemon": true, "adm": true, "lp": true, "sync": true, "shutdown": true,
	"halt": true, "mail": true, "news": true, "uucp": true, "operator": true, "games": true, "ftp": true,
	"nobody": true, "www": true, "wwwdata": true, "apache": true, "nginx": true, "mysql": true, "postfix": true,
	"dovecot": true, "pdns": true, "redis": true, "rspamd": true, "bpanel": true, "bpadmin": true, "admin": true,
	"sshd": true, "systemd": true, "messagebus": true, "syslog": true, "test": true, "all": true, "virtfs": true,
	"vmail": true, "clamav": true, "postgres": true, "named": true, "polkitd": true, "chrony": true,
	// common cloud-image / operator login accounts (SEC-5 / CODE-2): never adopt them
	"ubuntu": true, "debian": true, "almalinux": true, "rocky": true, "centos": true, "fedora": true, "opc": true,
	"azureuser": true, "ec2user": true, "cloud": true, "cloudadmin": true, "alpine": true, "arch": true, "pi": true,
	"vagrant": true, "oracle": true, "git": true, "user": true, "guest": true, "support": true, "backup": true,
	"list": true, "irc": true, "gnats": true, "proxy": true, "man": true, "tss": true, "uuidd": true, "tcpdump": true,
	"landscape": true, "pollinate": true, "lxd": true, "dnsmasq": true, "sssd": true, "unbound": true, "memcache": true,
	"opendkim": true, "spamd": true, "amavis": true, "dovenull": true, "postdrop": true, "roundcube": true,
	"phpmyadmin": true, "restic": true, "acme": true, "webmail": true, "cpanel": true, "whm": true, "bpanelapi": true,
	"bpanelagent": true, "hostmaster": true, "postmaster": true, "abuse": true, "webmaster": true,
}

// ReservedUsernames returns the sorted reserved list (exported for /meta so the UI can mirror it).
func ReservedUsernames() []string {
	out := make([]string, 0, len(reservedUsers))
	for k := range reservedUsers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func Username(s string) error {
	if !reUser.MatchString(s) {
		return errors.New("invalid_username")
	}
	if reservedUsers[s] || strings.HasPrefix(s, "bp") && len(s) <= 3 {
		return errors.New("reserved_username")
	}
	return nil
}

// Domain validates a fully qualified domain name (lower-case, IDN must be punycode).
func Domain(s string) error {
	if len(s) < 3 || len(s) > 253 || strings.HasSuffix(s, ".") {
		return errors.New("invalid_domain")
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return errors.New("invalid_domain")
	}
	for _, p := range parts {
		if !reLabel.MatchString(p) {
			return errors.New("invalid_domain")
		}
	}
	if net.ParseIP(s) != nil {
		return errors.New("invalid_domain")
	}
	return nil
}

func Label(s string) error {
	if !reLabel.MatchString(s) {
		return errors.New("invalid_label")
	}
	return nil
}

func EmailLocal(s string) error {
	if !reLocal.MatchString(s) || strings.Contains(s, "..") {
		return errors.New("invalid_email_local")
	}
	return nil
}

func Email(s string) error {
	i := strings.LastIndex(s, "@")
	if i <= 0 {
		return errors.New("invalid_email")
	}
	if err := EmailLocal(strings.ToLower(s[:i])); err != nil {
		return errors.New("invalid_email")
	}
	return Domain(strings.ToLower(s[i+1:]))
}

// DBName validates a prefixed MariaDB identifier like "user_blog".
func DBName(owner, s string) error {
	if !strings.HasPrefix(s, owner+"_") {
		return errors.New("db_prefix_required")
	}
	if !reDBSuffix.MatchString(strings.TrimPrefix(s, owner+"_")) || len(s) > 64 {
		return errors.New("invalid_db_name")
	}
	return nil
}

// DBUser validates a prefixed MariaDB user (max 80 chars in MariaDB 10.11, we keep 32).
func DBUser(owner, s string) error {
	if !strings.HasPrefix(s, owner+"_") || len(s) > 32 || !reDBSuffix.MatchString(strings.TrimPrefix(s, owner+"_")) {
		return errors.New("invalid_db_user")
	}
	return nil
}

func PHPVersion(s string) error {
	if !rePHP.MatchString(s) {
		return errors.New("invalid_php_version")
	}
	return nil
}

func Unit(s string) error {
	if !reUnit.MatchString(s) {
		return errors.New("invalid_unit")
	}
	return nil
}

// UILanguages are the interface languages shipped with BPANEL (web/src/lib/i18n).
var UILanguages = []string{"en", "tr"}

// Lang accepts a language tag ("tr", "en-US") whose base language has a
// shipped translation; any other well-formed tag is refused, so a stored
// preference can never point at a language the UI cannot show.
func Lang(s string) error {
	if !reLang.MatchString(s) {
		return errors.New("invalid_language")
	}
	for _, l := range UILanguages {
		if s[:2] == l {
			return nil
		}
	}
	return errors.New("invalid_language")
}

func Snapshot(s string) error {
	if !reSnap.MatchString(s) {
		return errors.New("invalid_snapshot")
	}
	return nil
}

// Password enforces a minimum strength without being annoying.
func Password(s string) error {
	if len(s) < 10 {
		return errors.New("password_too_short")
	}
	if len(s) > 256 {
		return errors.New("password_too_long")
	}
	var lower, upper, digit bool
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		case c == '\n' || c == '\r' || c == 0 || c == ':':
			return errors.New("password_bad_char")
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit} {
		if b {
			n++
		}
	}
	if n < 2 {
		return errors.New("password_too_weak")
	}
	return nil
}

// cronField describes the numeric range of one crontab time field.
type cronField struct {
	min, max int
	names    map[string]int
}

var cronFields = [5]cronField{
	{0, 59, nil},
	{0, 23, nil},
	{1, 31, nil},
	{1, 12, map[string]int{"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}},
	{0, 7, map[string]int{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}},
}

func cronValue(f cronField, s string) (int, bool) {
	if f.names != nil {
		if v, ok := f.names[strings.ToLower(s)]; ok {
			return v, true
		}
	}
	if s == "" || len(s) > 2 {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < f.min || n > f.max {
		return 0, false
	}
	return n, true
}

// cronItem validates one list element: "*", "*/n", "a", "a-b", "a-b/n" (n in 1..max).
func cronItem(f cronField, s string) bool {
	rng, step, hasStep := strings.Cut(s, "/")
	if hasStep {
		n, err := strconv.Atoi(step)
		if err != nil || n < 1 || n > f.max+1 || len(step) > 2 {
			return false
		}
	}
	if rng == "*" {
		return true
	}
	lo, hi, isRange := strings.Cut(rng, "-")
	a, ok := cronValue(f, lo)
	if !ok {
		return false
	}
	if !isRange {
		return true
	}
	b, ok := cronValue(f, hi)
	return ok && a <= b
}

// CronSchedule validates the five time fields of a crontab line, including
// numeric ranges (minute 0-59, hour 0-23, day 1-31, month 1-12/jan-dec,
// weekday 0-7/sun-sat), lists, ranges and steps.
func CronSchedule(fields []string) error {
	if len(fields) != 5 {
		return errors.New("invalid_cron")
	}
	for i, f := range fields {
		if !reCronFld.MatchString(f) {
			return errors.New("invalid_cron")
		}
		for _, item := range strings.Split(f, ",") {
			if !cronItem(cronFields[i], item) {
				return errors.New("invalid_cron")
			}
		}
	}
	return nil
}

// CronCommand rejects line breaks, NULs and other control characters: a
// command must stay on one crontab line. A '%' is allowed; the agent writes it
// escaped (see EscapeCronPercent) because cron turns a bare '%' into a newline.
func CronCommand(s string) error {
	if strings.TrimSpace(s) == "" || len(s) > 1000 || hasControl(s) {
		return errors.New("invalid_cron_command")
	}
	return nil
}

// EscapeCronPercent escapes every '%' that is not already escaped, so cron
// passes it to the shell literally instead of starting stdin (CODE-17).
func EscapeCronPercent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && (i == 0 || s[i-1] != '\\') {
			b.WriteString(`\%`)
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hasControl(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// rePathSeg is the strict grammar for path segments that end up in web
// server, PHP-FPM or Pure-FTPd configuration files (SEC-1 / SEC-9 / CODE-1):
// letters, digits, '.', '_' and '-', not starting with '.'.
var rePathSeg = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$`)

// RelPath validates a path relative to a home directory that will be written
// into a configuration file (docroots, FTP directories). It refuses escapes,
// hidden segments and every character outside [A-Za-z0-9._-/], so the value
// can never break out of a quoted or unquoted config token. It returns the
// cleaned relative path ("" for the home itself).
func RelPath(p string) (string, error) {
	if len(p) > 255 {
		return "", errors.New("invalid_path")
	}
	c := strings.Trim(p, "/")
	if c == "" {
		return "", nil
	}
	for _, seg := range strings.Split(c, "/") {
		if seg == "" {
			continue // tolerate "a//b"
		}
		if !rePathSeg.MatchString(seg) {
			return "", errors.New("invalid_path")
		}
	}
	return path.Clean(c), nil
}

// FilePath cleans a File Manager path (any file name the user may have,
// including spaces) relative to a home and refuses escapes and control
// characters. Never use it for values that are rendered into config files.
func FilePath(p string) (string, error) {
	if strings.ContainsRune(p, 0) || len(p) > 4096 {
		return "", errors.New("invalid_path")
	}
	c := path.Clean("/" + p)
	if c == "/" {
		return "", nil
	}
	c = strings.TrimPrefix(c, "/")
	for _, seg := range strings.Split(c, "/") {
		if seg == ".." {
			return "", errors.New("invalid_path")
		}
	}
	return c, nil
}

// privateTop are home sub-directories that must never be served by the web server (CODE-18).
var privateTop = map[string]bool{"mail": true, "etc": true, "logs": true, "tmp": true, "backups": true, "ssl": true}

// DocRoot validates a document root: RelPath's strict grammar, not the home
// itself and not inside a private directory (mail, etc, logs, tmp, backups).
// Errors: too_long (whole path > 255 or a segment > 128), private_dir,
// invalid_docroot (grammar, empty, home itself).
func DocRoot(p string) (string, error) {
	if err := pathTooLong(p); err != nil {
		return "", err
	}
	rel, err := RelPath(p)
	if err != nil || rel == "" {
		return "", errors.New("invalid_docroot")
	}
	if PrivateDir(rel) {
		return "", errors.New("private_dir")
	}
	return rel, nil
}

// PrivateDir reports whether rel (cleaned, relative to the home) is or lies
// below a private top-level directory (mail, etc, logs, tmp, backups, ssl).
func PrivateDir(rel string) bool {
	top, _, _ := strings.Cut(strings.TrimPrefix(rel, "/"), "/")
	return privateTop[top]
}

// FTPDir validates an FTP account's directory: RelPath's grammar and, like
// docroots, never a private directory: ~/etc holds the per-domain mail
// password files, ~/mail the mailboxes (R2-UX-13). "" is the home itself.
// Errors: too_long, invalid_path, private_dir.
func FTPDir(p string) (string, error) {
	if err := pathTooLong(p); err != nil {
		return "", err
	}
	rel, err := RelPath(p)
	if err != nil {
		return "", err
	}
	if rel != "" && PrivateDir(rel) {
		return "", errors.New("private_dir")
	}
	return rel, nil
}

func pathTooLong(p string) error {
	if len(p) > 255 {
		return errors.New("too_long")
	}
	for _, seg := range strings.Split(p, "/") {
		if len(seg) > MaxDocRootSegment {
			return errors.New("too_long")
		}
	}
	return nil
}

// FileOpPath checks the path of a File Manager operation that creates or
// names an entry: every segment at most 255 bytes (NAME_MAX; a longer name
// used to come back as 502 io_error) and the last segment not "." or "..".
// Errors: invalid_filename.
func FileOpPath(p string) error {
	if strings.ContainsRune(p, 0) {
		return errors.New("invalid_filename")
	}
	segs := strings.Split(strings.TrimRight(p, "/"), "/")
	for _, seg := range segs {
		if len(seg) > 255 {
			return errors.New("invalid_filename")
		}
	}
	if last := segs[len(segs)-1]; last == "." || last == ".." {
		return errors.New("invalid_filename")
	}
	return nil
}

// ConfigSafe reports whether s can be interpolated into an nginx, Apache or
// PHP-FPM configuration file: no control characters, quotes, braces,
// semicolons, '$', '\\' or whitespace.
func ConfigSafe(s string) bool {
	if s == "" {
		return true
	}
	return !hasControl(s) && !strings.ContainsAny(s, "\"'`;{}$\\ \t#<>")
}

// FileName validates a single path component.
func FileName(s string) error {
	if s == "" || s == "." || s == ".." || len(s) > 255 || strings.ContainsAny(s, "/\x00") {
		return errors.New("invalid_filename")
	}
	return nil
}

func Mode(m uint32) error {
	if m > 0o777 {
		return fmt.Errorf("invalid_mode")
	}
	return nil
}

// DNSType is the set of record types the zone editor accepts.
var DNSTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "TXT": true, "SRV": true, "CAA": true, "NS": true}

func RecordName(zone, name string) error {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == zone {
		return nil
	}
	if !strings.HasSuffix(name, "."+zone) {
		return errors.New("record_outside_zone")
	}
	for _, p := range strings.Split(strings.TrimSuffix(name, "."+zone), ".") {
		if p == "*" || p == "_dmarc" || p == "_domainkey" || strings.HasPrefix(p, "_") && reLabel.MatchString(p[1:]) {
			continue
		}
		if !reLabel.MatchString(p) {
			return errors.New("invalid_record_name")
		}
	}
	return nil
}

func RecordContent(t, c string) error {
	if c == "" || len(c) > 4000 || hasControl(c) {
		return errors.New("invalid_record_content")
	}
	switch t {
	case "A":
		if ip := net.ParseIP(c); ip == nil || ip.To4() == nil {
			return errors.New("invalid_ipv4")
		}
	case "AAAA":
		if ip := net.ParseIP(c); ip == nil || ip.To4() != nil {
			return errors.New("invalid_ipv6")
		}
	}
	return nil
}

// Limits returns the input rules in a machine-readable form so clients (the
// web UI) can mirror them exactly (CODE-24 validation parity). Served by
// GET /api/v1/meta under "limits".
// MaxFavorites is the number of dashboard favorites stored per user.
const MaxFavorites = 24

var reToolID = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,39}$`)

// Favorites validates a dashboard favorites list (tool ids).
func Favorites(ids []string) error {
	if len(ids) > MaxFavorites {
		return errors.New("invalid_favorites")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !reToolID.MatchString(id) || seen[id] {
			return errors.New("invalid_favorites")
		}
		seen[id] = true
	}
	return nil
}

// FTPLocal validates the local part of an FTP login (login@domain). The
// same rule is used by the API, the agent and GET /meta (handoff-ui H-5):
// 1-32 characters, no '+', no "..".
func FTPLocal(s string) error {
	if !reFTPLocal.MatchString(s) || strings.Contains(s, "..") {
		return errors.New("invalid_ftp_login")
	}
	return nil
}

// FTPLoginPattern is the agent-side full-login rule (local@domain).
var FTPLoginPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}@[a-z0-9.-]{3,253}$`)

// DBPrivileges are the MariaDB privileges a tenant may grant on its own
// databases (besides ["ALL"]).
var DBPrivileges = map[string]bool{"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true, "CREATE": true,
	"DROP": true, "INDEX": true, "ALTER": true, "CREATE TEMPORARY TABLES": true, "LOCK TABLES": true,
	"EXECUTE": true, "CREATE VIEW": true, "SHOW VIEW": true, "CREATE ROUTINE": true, "ALTER ROUTINE": true,
	"EVENT": true, "TRIGGER": true, "REFERENCES": true}

// UploadMaxFile and UploadMaxRequest are the File Manager upload limits.
const (
	UploadMaxFile    = 256 << 20
	UploadMaxRequest = 1 << 30
)

func Limits() map[string]any {
	privs := make([]string, 0, len(DBPrivileges))
	for p := range DBPrivileges {
		privs = append(privs, p)
	}
	sort.Strings(privs)
	return map[string]any{
		"username":           map[string]any{"pattern": reUser.String(), "reserved": ReservedUsernames()},
		"password":           map[string]any{"min": 10, "max": 256, "min_classes": 2, "classes": []string{"lower", "upper", "digit"}, "forbidden_chars": []string{":", "\\n", "\\r", "\\u0000"}},
		"email_local":        map[string]any{"pattern": reLocal.String(), "no_double_dot": true, "max": 63},
		"ftp_login":          map[string]any{"pattern": reFTPLocal.String(), "max": 32, "no_plus": true, "no_double_dot": true},
		"db_name":            map[string]any{"suffix_pattern": reDBSuffix.String(), "max_total": 64, "prefix": "<username>_"},
		"db_user":            map[string]any{"suffix_pattern": reDBSuffix.String(), "max_total": 32, "prefix": "<username>_", "reserved_suffixes": []string{"pma"}},
		"docroot":            map[string]any{"segment_pattern": rePathSeg.String(), "max": 255, "segment_max": MaxDocRootSegment, "private_top_dirs": []string{"backups", "etc", "logs", "mail", "ssl", "tmp"}},
		"ftp_dir":            map[string]any{"segment_pattern": rePathSeg.String(), "max": 255, "segment_max": MaxDocRootSegment, "private_top_dirs": []string{"backups", "etc", "logs", "mail", "ssl", "tmp"}},
		"domain":             map[string]any{"label_pattern": reLabel.String(), "max": MaxDomain, "lowercase": true, "trailing_dot": "stripped (FQDN)", "idn": "punycode; IDNA2008 letters/digits/marks only (no emoji or symbols)", "public_suffix": "refused"},
		"file_name":          map[string]any{"max_bytes": 255, "forbidden": []string{"/", "NUL", ".", ".."}},
		"package_name":       map[string]any{"pattern": rePkgName.String(), "max": 64},
		"suspend_reason":     map[string]any{"max": 500},
		"totp_code":          map[string]any{"digits": 6, "ignored": []string{" ", "-"}},
		"limit_values":       map[string]any{"unlimited": -1, "unlimited_alt": nil, "none": 0, "count_max": 1000000, "size_zero_allowed": false},
		"cron":               map[string]any{"minute": "0-59", "hour": "0-23", "dom": "1-31", "month": "1-12|jan-dec", "dow": "0-7|sun-sat", "command_max": 1000, "percent": "escaped automatically"},
		"dns_ttl":            map[string]any{"min": 60, "max": 604800},
		"chmod":              map[string]any{"max": "0777"},
		"upload_max_file":    UploadMaxFile,
		"upload_max_request": UploadMaxRequest,
		"db_privileges":      map[string]any{"all": "ALL", "allowed": privs, "empty_allowed": false},
		"favorites_max":      MaxFavorites,
	}
}
