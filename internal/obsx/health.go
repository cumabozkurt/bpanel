// SPDX-License-Identifier: Apache-2.0

package obsx

import (
	"strings"
)

// Check statuses for the OS health page.
const (
	HOK           = "ok"
	HWarn         = "warning"
	HFail         = "failed"
	HNotInstalled = "not_installed"
	HUnsupported  = "unsupported"
	HUnknown      = "unknown"
)

// HealthCheck is one row of the OS health page.
type HealthCheck struct {
	ID      string   `json:"id"`
	Status  string   `json:"status"`
	Reason  string   `json:"reason,omitempty"`
	Details []string `json:"details,omitempty"`
}

// ParseMdstat inspects /proc/mdstat: an array with "_" in its [UU_] map is
// degraded.
func ParseMdstat(s string) HealthCheck {
	c := HealthCheck{ID: "raid", Status: HOK}
	arrays := 0
	for _, ln := range strings.Split(s, "\n") {
		f := strings.Fields(ln)
		if len(f) > 2 && strings.HasPrefix(f[0], "md") && f[1] == ":" {
			arrays++
			c.Details = append(c.Details, strings.TrimSpace(ln))
		}
		tl := strings.TrimSpace(ln)
		if i := strings.LastIndex(tl, "["); i >= 0 && strings.HasSuffix(tl, "]") {
			m := tl[i:]
			if strings.Contains(m, "_") && strings.Trim(m, "[]U_") == "" {
				c.Status = HFail
				c.Reason = "degraded array"
			}
		}
	}
	if arrays == 0 {
		return HealthCheck{ID: "raid", Status: HUnsupported, Reason: "no software RAID arrays (/proc/mdstat)"}
	}
	return c
}

// ParseTimedatectl parses `timedatectl show` key=value output.
func ParseTimedatectl(s string) HealthCheck {
	kv := map[string]string{}
	for _, ln := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(ln), "="); ok {
			kv[k] = v
		}
	}
	c := HealthCheck{ID: "time_sync"}
	switch kv["NTPSynchronized"] {
	case "yes":
		c.Status = HOK
	case "no":
		c.Status = HWarn
		c.Reason = "clock not synchronised (NTP=" + kv["NTP"] + ")"
	default:
		c.Status = HUnknown
		c.Reason = "timedatectl gave no NTPSynchronized"
	}
	if tz := kv["Timezone"]; tz != "" {
		c.Details = append(c.Details, "timezone="+tz)
	}
	return c
}

// ParseChrony parses `chronyc tracking`.
func ParseChrony(s string) HealthCheck {
	c := HealthCheck{ID: "time_sync", Status: HUnknown, Reason: "chronyc tracking unparsed"}
	for _, ln := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "Leap status" {
			if v == "Normal" {
				c.Status, c.Reason = HOK, ""
			} else {
				c.Status, c.Reason = HWarn, "leap status "+v
			}
		}
		if k == "System time" || k == "Reference ID" {
			c.Details = append(c.Details, k+": "+v)
		}
	}
	return c
}

// ParseSmart parses `smartctl -H <dev>` output for one device.
func ParseSmart(dev, s string) (status, line string) {
	for _, ln := range strings.Split(s, "\n") {
		l := strings.TrimSpace(ln)
		if strings.Contains(l, "overall-health") || strings.HasPrefix(l, "SMART Health Status") {
			if strings.HasSuffix(l, "PASSED") || strings.HasSuffix(l, "OK") {
				return HOK, dev + ": " + l
			}
			return HFail, dev + ": " + l
		}
	}
	return HUnknown, dev + ": no SMART health line (unsupported device?)"
}

// ParseFailedUnits parses `systemctl --failed --no-legend --plain`.
func ParseFailedUnits(s string) HealthCheck {
	c := HealthCheck{ID: "failed_units", Status: HOK}
	for _, ln := range strings.Split(s, "\n") {
		f := strings.Fields(strings.TrimLeft(ln, "●* "))
		if len(f) > 0 && strings.Contains(f[0], ".") {
			c.Details = append(c.Details, f[0])
		}
	}
	if len(c.Details) > 0 {
		c.Status = HFail
		c.Reason = "failed systemd units"
	}
	return c
}
