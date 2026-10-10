package shield

import (
	"sync"
	"time"
)

// CachedVerdict is a stored scan result for one content hash.
type CachedVerdict struct {
	Outcome    Outcome     `json:"outcome"`
	Detections []Detection `json:"detections,omitempty"`
	Version    string      `json:"version"`
	At         time.Time   `json:"at"`
}

// VerdictCache maps sha256 -> verdict. An entry only counts for the exact
// engine/ruleset version string it was produced with, so a signature or
// rule update invalidates it automatically.
type VerdictCache struct {
	mu  sync.Mutex
	m   map[string]CachedVerdict
	Max int           // entries (default 100k); oldest evicted
	TTL time.Duration // 0 = no expiry
}

func NewVerdictCache() *VerdictCache {
	return &VerdictCache{m: map[string]CachedVerdict{}, Max: 100000}
}

func (c *VerdictCache) Get(sha, version string) (CachedVerdict, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[sha]
	if !ok {
		return v, false
	}
	if v.Version != version || (c.TTL > 0 && time.Since(v.At) > c.TTL) {
		delete(c.m, sha)
		return CachedVerdict{}, false
	}
	return v, true
}

// Put stores only definitive outcomes (never unavailable/timeout).
func (c *VerdictCache) Put(sha, version string, out Outcome, dets []Detection) {
	if out != OutClean && out != OutSuspicious && out != OutInfected {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]CachedVerdict{}
	}
	if c.Max > 0 && len(c.m) >= c.Max {
		var oldK string
		var oldT time.Time
		for k, v := range c.m {
			if oldK == "" || v.At.Before(oldT) {
				oldK, oldT = k, v.At
			}
		}
		delete(c.m, oldK)
	}
	c.m[sha] = CachedVerdict{Outcome: out, Detections: dets, Version: version, At: time.Now()}
}

// Invalidate drops everything (e.g. after a false-positive report).
func (c *VerdictCache) Invalidate() { c.mu.Lock(); c.m = map[string]CachedVerdict{}; c.mu.Unlock() }

func (c *VerdictCache) Len() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.m) }
