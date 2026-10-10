// SPDX-License-Identifier: Apache-2.0

package obsx

import (
	"errors"
	"sync"
	"time"
)

// Severities (same strings as internal/events).
const (
	SevInfo     = "info"
	SevWarning  = "warning"
	SevCritical = "critical"
)

// SevRank orders severities; unknown = 0.
func SevRank(s string) int {
	switch s {
	case SevInfo:
		return 1
	case SevWarning:
		return 2
	case SevCritical:
		return 3
	}
	return 0
}

// Rule ids of the built-in rule set.
const (
	RuleBackupFailed = "backup_failed"
	RuleCertExpiring = "cert_expiring"
	RuleDiskFull     = "disk_full"
	RuleServiceDown  = "service_down"
	RuleShield       = "shield_detection"
	RuleLoginBurst   = "failed_login_burst"
	RuleJobFailures  = "job_failures"
	RuleFIMChange    = "fim_change"
)

// Rule is one alert rule. Threshold meaning depends on the rule:
// cert_expiring = days, disk_full = percent, failed_login_burst = failures
// in 10 minutes, job_failures = failed jobs in the last check window.
type Rule struct {
	ID        string  `json:"id"`
	Enabled   bool    `json:"enabled"`
	Severity  string  `json:"severity"`
	Threshold float64 `json:"threshold"`
	Cooldown  int64   `json:"cooldown_sec"`
	Events    string  `json:"events,omitempty"` // event types that trigger it (event rules)
}

// DefaultRules is the built-in rule catalogue.
func DefaultRules() []Rule {
	return []Rule{
		{ID: RuleBackupFailed, Enabled: true, Severity: SevCritical, Cooldown: 3600, Events: "backup.failed,backup.retention_failed"},
		{ID: RuleCertExpiring, Enabled: true, Severity: SevWarning, Threshold: 14, Cooldown: 86400},
		{ID: RuleDiskFull, Enabled: true, Severity: SevCritical, Threshold: 90, Cooldown: 3600},
		{ID: RuleServiceDown, Enabled: true, Severity: SevCritical, Cooldown: 900},
		{ID: RuleShield, Enabled: true, Severity: SevWarning, Cooldown: 900, Events: "shield.detection,shield.malware_found,shield.quarantine"},
		{ID: RuleLoginBurst, Enabled: true, Severity: SevWarning, Threshold: 20, Cooldown: 1800},
		{ID: RuleJobFailures, Enabled: true, Severity: SevWarning, Threshold: 1, Cooldown: 3600},
		{ID: RuleFIMChange, Enabled: true, Severity: SevCritical, Cooldown: 3600, Events: "obsx.fim_change"},
	}
}

// ShouldNotify implements the cooldown: a repeat of an already-open alert is
// counted on the incident but notifies only once per cooldown window.
func ShouldNotify(lastNotified int64, now time.Time, cooldownSec int64) bool {
	if lastNotified == 0 {
		return true
	}
	return now.Unix()-lastNotified >= cooldownSec
}

// Deduper is the in-memory form of the dedup + cooldown rule (the API keeps
// the same state in obsx_incidents). Fire returns whether to notify.
type Deduper struct {
	mu   sync.Mutex
	last map[string]int64
	cnt  map[string]int
}

func NewDeduper() *Deduper { return &Deduper{last: map[string]int64{}, cnt: map[string]int{}} }

func (d *Deduper) Fire(key string, now time.Time, cooldownSec int64) (notify bool, count int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cnt[key]++
	if ShouldNotify(d.last[key], now, cooldownSec) {
		d.last[key] = now.Unix()
		return true, d.cnt[key]
	}
	return false, d.cnt[key]
}

// Resolve forgets a key so the next occurrence opens a new incident.
func (d *Deduper) Resolve(key string) {
	d.mu.Lock()
	delete(d.last, key)
	delete(d.cnt, key)
	d.mu.Unlock()
}

// ---- incident state machine ------------------------------------------------

const (
	IncOpen         = "open"
	IncAcknowledged = "acknowledged"
	IncResolved     = "resolved"
)

// ErrBadTransition is returned for an action not allowed in the current state.
var ErrBadTransition = errors.New("incident_bad_transition")

// Transition returns the state after action (ack | assign | resolve |
// reopen | note). assign and note keep the state.
func Transition(state, action string) (string, error) {
	switch action {
	case "note":
		return state, nil
	case "ack":
		if state == IncOpen {
			return IncAcknowledged, nil
		}
	case "assign":
		if state == IncOpen || state == IncAcknowledged {
			return state, nil
		}
	case "resolve":
		if state == IncOpen || state == IncAcknowledged {
			return IncResolved, nil
		}
	case "reopen":
		if state == IncResolved {
			return IncOpen, nil
		}
	}
	return state, ErrBadTransition
}
