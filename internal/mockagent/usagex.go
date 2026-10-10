//go:build dev

// SPDX-License-Identifier: Apache-2.0

package mockagent

import (
	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// F2B makes the mock report fail2ban as installed with these jails (nil = not_installed).
var F2BJails []rpc.F2BJail

func (m *Mock) mockUsagex(method string, params any) (any, error) {
	switch method {
	case rpc.MUsageBandwidthScan:
		var p rpc.BWScanParams
		conv(params, &p)
		out := rpc.BWScanResult{Domains: []rpc.BWDomainResult{}}
		for _, c := range p.Cursors {
			r := rpc.BWDomainResult{Domain: c.Domain, Inode: 1, Offset: c.Offset, Status: "ok", Days: []rpc.BWDay{}}
			if c.Offset == 0 { // first scan of a domain: one day of fake-but-deterministic traffic
				r.Offset = 100
				r.Days = append(r.Days, rpc.BWDay{Day: "2026-10-10", Bytes: 1 << 20, Hits: 10})
			}
			out.Domains = append(out.Domains, r)
		}
		return out, nil
	case rpc.MF2BStatus:
		if F2BJails == nil {
			return rpc.F2BStatusResult{Status: "not_installed", Reason: "fail2ban-client was not found", Jails: []rpc.F2BJail{}}, nil
		}
		return rpc.F2BStatusResult{Status: "ok", Jails: F2BJails}, nil
	case rpc.MF2BUnban:
		var p rpc.F2BUnbanParams
		conv(params, &p)
		if F2BJails == nil {
			return rpc.F2BActionResult{Status: "not_installed"}, nil
		}
		for i := range F2BJails {
			if F2BJails[i].Name == p.Jail {
				kept := []string{}
				for _, ip := range F2BJails[i].Banned {
					if ip != p.IP {
						kept = append(kept, ip)
					}
				}
				F2BJails[i].Banned = kept
				F2BJails[i].CurrentlyBanned = len(kept)
			}
		}
		return rpc.F2BActionResult{Status: "done"}, nil
	default: // MF2BIgnore
		if F2BJails == nil {
			return rpc.F2BActionResult{Status: "not_installed"}, nil
		}
		return rpc.F2BActionResult{Status: "done"}, nil
	}
}
