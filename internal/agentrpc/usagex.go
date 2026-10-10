// SPDX-License-Identifier: Apache-2.0

package agentrpc

// v0.4 usagex: bandwidth accounting from nginx domain logs and the
// fail2ban (brute-force protection) bridge.
const (
	MUsageBandwidthScan = "usage.bandwidth.scan" // bounded incremental parse of /var/log/bpanel/domlogs/<domain>.access.log
	MF2BStatus          = "f2b.status"           // fail2ban-client status (+ per-jail banned IPs)
	MF2BUnban           = "f2b.unban"            // fail2ban-client set <jail> unbanip <ip>
	MF2BIgnore          = "f2b.ignore"           // fail2ban-client set <jail> addignoreip|delignoreip <ip>
)

// BWCursor is where the previous scan of one domain log stopped.
type BWCursor struct {
	Domain string `json:"domain"`
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

type BWScanParams struct {
	Cursors  []BWCursor `json:"cursors"`
	MaxBytes int64      `json:"max_bytes,omitempty"` // per domain per scan; 0 = default (32 MiB)
}

// BWDay is the traffic of one domain on one (UTC) day found by a scan.
type BWDay struct {
	Day   string `json:"day"` // YYYY-MM-DD (UTC)
	Bytes int64  `json:"bytes"`
	Hits  int64  `json:"hits"`
}

type BWDomainResult struct {
	Domain  string  `json:"domain"`
	Inode   uint64  `json:"inode"`
	Offset  int64   `json:"offset"`
	Days    []BWDay `json:"days"`
	Skipped int64   `json:"skipped"`          // unparsable lines
	More    bool    `json:"more"`             // bound hit: more data waiting
	Status  string  `json:"status"`           // ok | no_log | rotated
	Reason  string  `json:"reason,omitempty"` // when not ok
}

type BWScanResult struct {
	Domains []BWDomainResult `json:"domains"`
}

type F2BStatusParams struct{}

type F2BJail struct {
	Name            string   `json:"name"`
	CurrentlyBanned int      `json:"currently_banned"`
	TotalBanned     int      `json:"total_banned"`
	CurrentlyFailed int      `json:"currently_failed"`
	Banned          []string `json:"banned"`
}

type F2BStatusResult struct {
	Status string    `json:"status"` // ok | not_installed | not_running
	Reason string    `json:"reason,omitempty"`
	Jails  []F2BJail `json:"jails"`
}

type F2BUnbanParams struct {
	Jail string `json:"jail"`
	IP   string `json:"ip"`
}

type F2BIgnoreParams struct {
	Jails  []string `json:"jails"`
	IP     string   `json:"ip"`
	Remove bool     `json:"remove,omitempty"`
}

type F2BActionResult struct {
	Status string `json:"status"` // done | not_installed | not_running
	Reason string `json:"reason,omitempty"`
}
