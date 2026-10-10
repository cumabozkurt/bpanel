// Package shield is BPanel Shield, the malware protection module (master
// spec §6). It is a library used by the root agent (real-time watcher, scan
// queue, quarantine, safe upload pipeline) and, for pure helpers such as the
// policy engine, by the API.
//
// Nothing here pretends: an engine that is not installed or not reachable
// reports not_installed / unavailable with a reason, and the policy engine
// decides what happens to a file when an engine could not give an answer.
// No antivirus catches everything; Shield layers several independent
// engines (ClamAV signatures, YARA rules, BPANEL's own heuristics,
// behaviour rules) to raise the bar, not to promise completeness.
package shield

import (
	"context"
	"errors"
	"time"
)

// Verdict of one engine (or of a combined scan) for one file.
type Verdict string

const (
	Clean      Verdict = "clean"
	Suspicious Verdict = "suspicious"
	Infected   Verdict = "infected"
)

// Outcome is what the policy engine is asked to decide on: the combined
// verdict, or why no verdict could be reached.
type Outcome string

const (
	OutClean       Outcome = "clean"
	OutSuspicious  Outcome = "suspicious"
	OutInfected    Outcome = "infected"
	OutUnavailable Outcome = "scanner_unavailable"
	OutTimeout     Outcome = "timeout"
)

// Severity of a detection.
const (
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"
)

// Detection is one hit of one engine.
type Detection struct {
	Engine    string  `json:"engine"`
	Signature string  `json:"signature"`
	Verdict   Verdict `json:"verdict"`
	Severity  string  `json:"severity"`
	Detail    string  `json:"detail,omitempty"`
	Entry     string  `json:"entry,omitempty"` // archive member, when inside an archive
}

// EngineResult is what one provider returned for one file.
type EngineResult struct {
	Engine     string        `json:"engine"`
	Version    string        `json:"version,omitempty"`
	Verdict    Verdict       `json:"verdict"`
	Detections []Detection   `json:"detections,omitempty"`
	Error      string        `json:"error,omitempty"` // engine failed: unavailable / timeout / reason
	Took       time.Duration `json:"took_ns"`
}

// Target is one file to scan. Path must be readable by the scanning process
// (the agent's staging file or a file opened inside an account home); Name
// is the logical name used for extension rules (upload file name, or the
// path relative to the account home).
type Target struct {
	Path string
	Name string
	Size int64
}

// Provider status values (API + UI).
const (
	StatusOK            = "ok"
	StatusNotInstalled  = "not_installed"
	StatusUnavailable   = "unavailable"    // installed but not answering
	StatusDisabled      = "disabled"       // installed, switched off by the admin
	StatusNotConfigured = "not_configured" // commercial, needs a licence/setup BPANEL cannot provide
	StatusDegraded      = "degraded"       // answering, but e.g. signature DB is old
)

// Provider kinds.
const (
	KindBuiltin    = "builtin"             // part of BPANEL, always available
	KindExternal   = "external"            // free/open-source program BPANEL drives
	KindCommercial = "commercial_optional" // licensed product, optional integration only
)

// ProviderStatus is the health of one engine.
type ProviderStatus struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	License     string `json:"license"`
	Status      string `json:"status"`
	Reason      string `json:"reason,omitempty"`
	Version     string `json:"version,omitempty"`
	SigVersion  string `json:"signature_version,omitempty"`
	DBTimeUnix  int64  `json:"db_time,omitempty"`
	DBAgeHours  int64  `json:"db_age_hours,omitempty"`
	RealTime    bool   `json:"realtime"` // used by the upload pipeline / watcher
	OnDemand    bool   `json:"on_demand"`
	CheckedUnix int64  `json:"checked"`
}

// MalwareScannerProvider is one scanning engine.
type MalwareScannerProvider interface {
	Name() string
	Kind() string
	// Status probes the engine (cheap: PING/VERSION or a binary lookup).
	Status(ctx context.Context) ProviderStatus
	// Available is true when Scan can be expected to work.
	Available(ctx context.Context) bool
	// SignatureVersion identifies the engine + signature/rule set; it is part
	// of the result-cache key, so a new signature DB invalidates old results.
	SignatureVersion(ctx context.Context) string
	// Scan scans one file. A non-nil error means "no verdict" (engine down,
	// timeout, protocol error), never "clean".
	Scan(ctx context.Context, t Target) (EngineResult, error)
}

// Errors that map to policy outcomes.
var (
	ErrUnavailable = errors.New("scanner unavailable")
	ErrTimeout     = errors.New("scan timed out")
	ErrTooLarge    = errors.New("file larger than the scan limit")
)

// worst returns the more severe of two verdicts.
func worst(a, b Verdict) Verdict {
	rank := map[Verdict]int{"": 0, Clean: 1, Suspicious: 2, Infected: 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}
