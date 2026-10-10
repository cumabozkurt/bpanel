package shield

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// FileEvent is one file-system event fed to the behaviour engine.
type FileEvent struct {
	Path    string    `json:"path"`
	Account string    `json:"account"`
	Op      string    `json:"op"` // create | write | move | delete | chmod
	TS      time.Time `json:"ts"`
	Content []byte    `json:"-"` // optional head of the file (.htaccess / crontab rules)
}

// Alert raised by a behaviour rule.
type Alert struct {
	Rule     string    `json:"rule"`
	Severity string    `json:"severity"`
	Account  string    `json:"account"`
	Path     string    `json:"path"`
	TS       time.Time `json:"ts"`
	Detail   string    `json:"detail"`
}

// Behaviour rule ids.
const (
	RuleMassChange    = "BHV.MassChange"
	RulePHPSpread     = "BHV.PHPSpread"
	RulePHPInUploads  = "BHV.PHPInUploads"
	RuleHtaccessInj   = "BHV.HtaccessInjection"
	RuleCrontabChange = "BHV.CrontabChange"
)

// BehaviorConfig thresholds.
type BehaviorConfig struct {
	MassN        int           // files changed ...
	MassWindow   time.Duration // ... within this window (per account)
	SpreadK      int           // PHP files in >= K unrelated dirs ...
	SpreadWindow time.Duration // ... within this window
	Cooldown     time.Duration // same rule+account not re-raised within
}

// DefaultBehaviorConfig returns conservative defaults.
func DefaultBehaviorConfig() BehaviorConfig {
	return BehaviorConfig{MassN: 500, MassWindow: 60 * time.Second, SpreadK: 5, SpreadWindow: 10 * time.Minute, Cooldown: 10 * time.Minute}
}

type acctState struct {
	changes []time.Time
	phpDirs map[string]time.Time
	last    map[string]time.Time // rule -> last alert
}

// Behavior is a deterministic detector (time comes only from events).
type Behavior struct {
	cfg BehaviorConfig
	mu  sync.Mutex
	st  map[string]*acctState
}

// NewBehavior returns an engine with cfg (zero fields => defaults).
func NewBehavior(cfg BehaviorConfig) *Behavior {
	d := DefaultBehaviorConfig()
	if cfg.MassN <= 0 {
		cfg.MassN = d.MassN
	}
	if cfg.MassWindow <= 0 {
		cfg.MassWindow = d.MassWindow
	}
	if cfg.SpreadK <= 0 {
		cfg.SpreadK = d.SpreadK
	}
	if cfg.SpreadWindow <= 0 {
		cfg.SpreadWindow = d.SpreadWindow
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = d.Cooldown
	}
	return &Behavior{cfg: cfg, st: map[string]*acctState{}}
}

var (
	phpExts     = map[string]bool{".php": true, ".phtml": true, ".php3": true, ".php4": true, ".php5": true, ".php7": true, ".php8": true, ".phar": true, ".pht": true, ".phps": true}
	uploadDirs  = map[string]bool{"uploads": true, "upload": true, "images": true, "image": true, "img": true, "imgs": true, "media": true, "pictures": true, "photos": true, "gallery": true, "thumbnails": true, "thumbs": true}
	htCritical  = regexp.MustCompile(`(?im)^\s*php_value\s+auto_(prepend|append)_file\b|^\s*php_admin_value\s+auto_(prepend|append)_file\b`)
	htHigh      = regexp.MustCompile(`(?im)^\s*(php_value|php_flag|php_admin_value|php_admin_flag)\s+|^\s*(AddHandler|AddType|SetHandler)\s+.*(php|x-httpd)`)
	cronSuspect = regexp.MustCompile(`(?i)(curl|wget|base64|/tmp/|/dev/shm|\bnc\b|bash\s+-i|python[0-9.]*\s+-c|perl\s+-e)`)
)

// IsPHPPath reports a PHP-executable final extension.
func IsPHPPath(p string) bool { return phpExts[strings.ToLower(filepath.Ext(p))] }

func isUploadDir(p string) (bool, string) {
	for _, seg := range strings.Split(filepath.ToSlash(filepath.Dir(p)), "/") {
		if uploadDirs[strings.ToLower(seg)] {
			return true, seg
		}
	}
	return false, ""
}

// IsCrontabPath reports a crontab location.
func IsCrontabPath(p string) bool {
	p = filepath.ToSlash(filepath.Clean(p))
	return strings.HasPrefix(p, "/var/spool/cron/") || p == "/etc/crontab" || strings.HasPrefix(p, "/etc/cron.") ||
		strings.HasPrefix(p, "/etc/cron/") || filepath.Base(p) == "crontab"
}

// related: same dir, ancestor/descendant, or siblings (same parent). A plugin
// or theme install stays one group; a.php dropped in wp-admin, uploads/2024
// and wp-includes/js counts as three.
func related(a, b string) bool {
	if a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/") {
		return true
	}
	return filepath.Dir(a) == filepath.Dir(b)
}

func (b *Behavior) state(acct string) *acctState {
	s := b.st[acct]
	if s == nil {
		s = &acctState{phpDirs: map[string]time.Time{}, last: map[string]time.Time{}}
		b.st[acct] = s
	}
	return s
}

func (b *Behavior) raise(s *acctState, out []Alert, a Alert) []Alert {
	if t, ok := s.last[a.Rule]; ok && a.TS.Sub(t) < b.cfg.Cooldown {
		return out
	}
	s.last[a.Rule] = a.TS
	return append(out, a)
}

// Feed processes one event and returns the alerts it triggers.
func (b *Behavior) Feed(ev FileEvent) []Alert {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Alert
	s := b.state(ev.Account)
	p := filepath.ToSlash(filepath.Clean(ev.Path))
	isChange := ev.Op == "create" || ev.Op == "write" || ev.Op == "move"

	// mass change: N modifications in M seconds
	if ev.Op != "" {
		s.changes = append(s.changes, ev.TS)
		cut := ev.TS.Add(-b.cfg.MassWindow)
		i := 0
		for i < len(s.changes) && s.changes[i].Before(cut) {
			i++
		}
		s.changes = s.changes[i:]
		if len(s.changes) >= b.cfg.MassN {
			out = b.raise(s, out, Alert{Rule: RuleMassChange, Severity: SevHigh, Account: ev.Account, Path: p, TS: ev.TS,
				Detail: "many files changed in a short window (possible ransomware/defacement)"})
		}
	}

	if isChange && IsPHPPath(p) {
		if ok, seg := isUploadDir(p); ok {
			out = append(out, Alert{Rule: RulePHPInUploads, Severity: SevHigh, Account: ev.Account, Path: p, TS: ev.TS,
				Detail: "PHP file created in media/upload directory '" + seg + "'"})
		}
		// spreading: PHP across >= K unrelated dirs within window
		dir := filepath.ToSlash(filepath.Dir(p))
		s.phpDirs[dir] = ev.TS
		cut := ev.TS.Add(-b.cfg.SpreadWindow)
		dirs := make([]string, 0, len(s.phpDirs))
		for d, t := range s.phpDirs {
			if t.Before(cut) {
				delete(s.phpDirs, d)
				continue
			}
			dirs = append(dirs, d)
		}
		sort.Strings(dirs) // deterministic
		var groups []string
		for _, d := range dirs {
			dup := false
			for _, g := range groups {
				if related(d, g) {
					dup = true
					break
				}
			}
			if !dup {
				groups = append(groups, d)
			}
		}
		if len(groups) >= b.cfg.SpreadK {
			out = b.raise(s, out, Alert{Rule: RulePHPSpread, Severity: SevCritical, Account: ev.Account, Path: p, TS: ev.TS,
				Detail: "PHP files appearing across many unrelated directories"})
		}
	}

	if isChange && filepath.Base(p) == ".htaccess" && len(ev.Content) > 0 {
		if htCritical.Match(ev.Content) {
			out = append(out, Alert{Rule: RuleHtaccessInj, Severity: SevCritical, Account: ev.Account, Path: p, TS: ev.TS,
				Detail: ".htaccess sets auto_prepend/append_file"})
		} else if htHigh.Match(ev.Content) {
			out = append(out, Alert{Rule: RuleHtaccessInj, Severity: SevHigh, Account: ev.Account, Path: p, TS: ev.TS,
				Detail: ".htaccess sets PHP directives or handlers"})
		}
	}

	if (isChange || ev.Op == "delete") && IsCrontabPath(p) {
		sev := SevMedium
		d := "crontab changed"
		if cronSuspect.Match(ev.Content) {
			sev, d = SevHigh, "crontab changed and contains download/encoded/shell patterns"
		}
		out = append(out, Alert{Rule: RuleCrontabChange, Severity: sev, Account: ev.Account, Path: p, TS: ev.TS, Detail: d})
	}
	return out
}
