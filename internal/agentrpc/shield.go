// SPDX-License-Identifier: Apache-2.0

package agentrpc

import "github.com/cumabozkurt/bpanel/internal/shield"

// BPanel Shield (v0.4): malware scanning, quarantine, upload pipeline.
const (
	MShieldScan        = "shield.scan"                     // on-demand scan of one path inside an account home
	MShieldQList       = "shield.quarantine.list"          // quarantined items (one account, or all when user is empty)
	MShieldQRestore    = "shield.quarantine.restore"       // restore an item to its original path (rescan must be clean)
	MShieldQDelete     = "shield.quarantine.delete"        // delete an item permanently
	MShieldQFP         = "shield.quarantine.falsepositive" // mark an item false positive (account|global allowlist) and restore it
	MShieldStatus      = "shield.status"                   // engines, versions, DB age, coverage, queue depth
	MShieldEvents      = "shield.events"                   // journal entries after a sequence number
	MShieldStageChunk  = "shield.stage.chunk"              // append one upload chunk to a root-owned staging file
	MShieldStageCommit = "shield.stage.commit"             // scan + policy, then place as the account user or block
	MShieldStageAbort  = "shield.stage.abort"              // discard a staging file
)

// ShieldScanReq scans Path (relative to, or absolute inside, the account home).
type ShieldScanReq struct {
	User string `json:"user"`
	Path string `json:"path"`
}

// ShieldScanResult is the scan result plus what happened to the file.
type ShieldScanResult struct {
	Result       shield.Result `json:"result"`
	QuarantineID string        `json:"quarantine_id,omitempty"`
	EventSeq     int64         `json:"event_seq,omitempty"`
}

// ShieldQRef names one quarantine item of one account.
type ShieldQRef struct {
	User  string `json:"user"`
	ID    string `json:"id"`
	Scope string `json:"scope,omitempty"` // falsepositive: account | global
}

// ShieldQListReq lists one account's items ("" = all accounts).
type ShieldQListReq struct {
	User string `json:"user"`
}

type ShieldQListResult struct {
	Items []shield.QuarantineMeta `json:"items"`
}

// ShieldStatusResult is the engine/coverage health.
type ShieldStatusResult struct {
	Engines    []shield.ProviderStatus `json:"engines"`
	Version    string                  `json:"version"`
	Realtime   string                  `json:"realtime"` // on | off | degraded | unsupported
	Reason     string                  `json:"reason,omitempty"`
	Coverage   *shield.Coverage        `json:"coverage,omitempty"`
	Queue      *shield.QueueStats      `json:"queue,omitempty"`
	Fanotify   bool                    `json:"fanotify"`
	FanReason  string                  `json:"fanotify_reason,omitempty"`
	Quarantine int                     `json:"quarantine_items"`
	LastSeq    int64                   `json:"last_seq"`
}

// ShieldEventsReq asks for journal entries with Seq > Since (at most Limit, default 500).
type ShieldEventsReq struct {
	Since int64 `json:"since"`
	Limit int   `json:"limit,omitempty"`
}

// ShieldEvent is one journal line.
type ShieldEvent struct {
	Seq          int64              `json:"seq"`
	UID          string             `json:"uid"` // unique id (dedupe in the panel DB)
	TS           int64              `json:"ts"`
	Kind         string             `json:"kind"`   // upload | scan | realtime | behavior | quarantine | restore | delete | falsepositive
	Source       string             `json:"source"` // upload | on_demand | realtime | behavior | admin
	Account      string             `json:"account"`
	Path         string             `json:"path"`
	SHA256       string             `json:"sha256,omitempty"`
	Outcome      string             `json:"outcome,omitempty"`
	Action       string             `json:"action,omitempty"`
	Reason       string             `json:"reason,omitempty"`
	Detections   []shield.Detection `json:"detections,omitempty"`
	QuarantineID string             `json:"quarantine_id,omitempty"`
}

type ShieldEventsResult struct {
	Events  []ShieldEvent `json:"events"`
	LastSeq int64         `json:"last_seq"`
}

// ShieldStageChunk appends Content (base64) at Offset of staging upload ID.
type ShieldStageChunk struct {
	User    string `json:"user"`
	ID      string `json:"id"`
	Offset  int64  `json:"offset"`
	Content string `json:"content"`
}

// ShieldStageCommit scans staging upload ID (Name = the uploaded file name,
// used for extension rules) and places it at Path (relative to the home).
// Policy is the account's effective policy (zero = server default).
type ShieldStageCommit struct {
	User   string               `json:"user"`
	ID     string               `json:"id"`
	Path   string               `json:"path"`
	Name   string               `json:"name"`
	Policy shield.AccountPolicy `json:"policy"`
}

// ShieldStageCommitResult: Placed=false means the file was not written to
// the account (Action block | quarantine | hold).
type ShieldStageCommitResult struct {
	Placed       bool               `json:"placed"`
	Action       string             `json:"action"`
	Reason       string             `json:"reason"`
	Outcome      string             `json:"outcome"`
	Class        string             `json:"class"`
	SHA256       string             `json:"sha256,omitempty"`
	Detections   []shield.Detection `json:"detections,omitempty"`
	QuarantineID string             `json:"quarantine_id,omitempty"`
	EventUID     string             `json:"event_uid,omitempty"`
}

// ShieldStageRef names a staging upload.
type ShieldStageRef struct {
	User string `json:"user"`
	ID   string `json:"id"`
}
