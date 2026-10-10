// SPDX-License-Identifier: Apache-2.0

package api

// Usage sampler (v0.4 isolation): every minute reads isolation.stats of each
// active hosting account (at most 2 agent calls at once), adds the counter
// deltas into 5-minute usage_samples buckets, prunes buckets older than 30
// days and publishes iso.limit_hit when memory high/max, OOM kill or
// pids-max counters grew since the previous sample.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/events"
	"github.com/cumabozkurt/bpanel/internal/isolation"
)

const (
	usageBucket    = 300 // seconds per usage_samples row
	usageRetention = 30 * 86400
	usageInterval  = time.Minute
	usageParallel  = 2
)

type samplerState struct {
	mu          sync.Mutex
	prev        map[int64]isolation.Stats
	unsupported string // reason; "" = supported or unknown
	lastRun     int64
	lastProbe   int64
}

var samplerStates sync.Map // *Server -> *samplerState

func samplerStateOf(s *Server) *samplerState {
	v, _ := samplerStates.LoadOrStore(s, &samplerState{prev: map[int64]isolation.Stats{}})
	return v.(*samplerState)
}

func (st *samplerState) status() map[string]any {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.unsupported != "" {
		return map[string]any{"status": "unsupported", "reason": st.unsupported, "last_run": st.lastRun}
	}
	return map[string]any{"status": "ok", "last_run": st.lastRun}
}

// runUsageSampler is started next to housekeeping in Run.
func (s *Server) runUsageSampler(ctx context.Context) {
	t := time.NewTicker(usageInterval)
	defer t.Stop()
	lastPrune := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := s.Now()
			s.sampleUsage(ctx, now)
			if now.Sub(lastPrune) >= time.Hour {
				lastPrune = now
				s.pruneUsage(ctx, now)
			}
		}
	}
}

// pruneUsage drops buckets older than the retention window.
func (s *Server) pruneUsage(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.Store.DB.ExecContext(ctx, `DELETE FROM usage_samples WHERE bucket_ts < ?`, now.Unix()-usageRetention)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func isUnsupported(err error) (string, bool) {
	var re *rpc.Error
	if errors.As(err, &re) && (re.Code == "unknown_method" || re.Code == "unsupported") {
		return "agent: " + re.Code, true
	}
	return "", false
}

// sampleUsage takes one sample of every active hosting account.
func (s *Server) sampleUsage(ctx context.Context, now time.Time) {
	st := samplerStateOf(s)
	st.mu.Lock()
	unsup, lastProbe := st.unsupported, st.lastProbe
	st.lastRun = now.Unix()
	st.mu.Unlock()
	if unsup != "" && now.Unix()-lastProbe < 3600 {
		return // re-check hourly, no spam
	}
	type acct struct {
		id   int64
		user string
	}
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT id, username FROM users WHERE system_user=1 AND status='active' AND role!='admin'`)
	if err != nil {
		return
	}
	var list []acct
	for rows.Next() {
		var a acct
		if rows.Scan(&a.id, &a.user) == nil {
			list = append(list, a)
		}
	}
	rows.Close()
	sem := make(chan struct{}, usageParallel)
	var wg sync.WaitGroup
	var unsupOnce sync.Once
	gotUnsup := ""
	for _, a := range list {
		wg.Add(1)
		sem <- struct{}{}
		go func(a acct) {
			defer wg.Done()
			defer func() { <-sem }()
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			var out rpc.IsolationStatsResult
			err := s.Agent.Call(cctx, rpc.MIsolationStats, rpc.IsolationUser{User: a.user}, &out)
			if reason, ok := isUnsupported(err); ok {
				unsupOnce.Do(func() { gotUnsup = reason })
				return
			}
			if err != nil {
				return
			}
			switch out.Status {
			case "unsupported":
				unsupOnce.Do(func() { gotUnsup = out.Reason })
				return
			case "ok":
				s.recordUsage(ctx, a.id, a.user, out.Stats, now)
			}
		}(a)
	}
	wg.Wait()
	st.mu.Lock()
	st.lastProbe = now.Unix()
	if gotUnsup != "" && st.unsupported == "" && s.Log != nil {
		s.Log.Warn("usage sampler: isolation unsupported, sampling paused", "reason", gotUnsup)
	}
	if gotUnsup == "" && len(list) > 0 {
		st.unsupported = ""
	} else if gotUnsup != "" {
		st.unsupported = gotUnsup
	}
	st.mu.Unlock()
}

func delta(cur, prev uint64) int64 {
	if cur < prev { // counter reset (slice recreated)
		return int64(cur)
	}
	return int64(cur - prev)
}

// recordUsage adds the deltas since the previous sample into the bucket of now.
func (s *Server) recordUsage(ctx context.Context, id int64, user string, cur isolation.Stats, now time.Time) error {
	st := samplerStateOf(s)
	st.mu.Lock()
	prev, had := st.prev[id]
	st.prev[id] = cur
	st.mu.Unlock()
	ev := map[string]int64{}
	var cpu, ior, iow int64
	if had {
		cpu, ior, iow = delta(cur.CPUUsageUsec, prev.CPUUsageUsec), delta(cur.IORBytes, prev.IORBytes), delta(cur.IOWBytes, prev.IOWBytes)
		for k, d := range map[string]int64{
			"mem_high": delta(cur.MemHighEvents, prev.MemHighEvents),
			"mem_max":  delta(cur.MemMaxEvents, prev.MemMaxEvents),
			"oom_kill": delta(cur.OOMKills, prev.OOMKills),
		} {
			if d > 0 {
				ev[k] = d
			}
		}
		if cur.PidsMax > 0 && cur.PidsCurrent >= uint64(cur.PidsMax) && prev.PidsCurrent < uint64(cur.PidsMax) {
			ev["pids_max"] = 1
		}
	}
	bucket := now.Unix() / usageBucket * usageBucket
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var old string
	if err := tx.QueryRowContext(ctx, `SELECT events FROM usage_samples WHERE account_id=? AND bucket_ts=?`, id, bucket).Scan(&old); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	merged := map[string]int64{}
	_ = json.Unmarshal([]byte(old), &merged)
	for k, v := range ev {
		merged[k] += v
	}
	evb, _ := json.Marshal(merged)
	if _, err := tx.ExecContext(ctx, `INSERT INTO usage_samples(account_id, bucket_ts, cpu_usec, mem_bytes, io_r, io_w, pids, events)
		VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(account_id, bucket_ts) DO UPDATE SET cpu_usec=cpu_usec+excluded.cpu_usec,
		mem_bytes=MAX(mem_bytes, excluded.mem_bytes), io_r=io_r+excluded.io_r, io_w=io_w+excluded.io_w, pids=MAX(pids, excluded.pids), events=excluded.events`,
		id, bucket, cpu, int64(cur.MemCurrent), ior, iow, int64(cur.PidsCurrent), string(evb)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if len(ev) > 0 {
		sev := events.Warning
		if ev["oom_kill"] > 0 {
			sev = events.Critical
		}
		data := map[string]any{"user": user}
		for k, v := range ev {
			data[k] = v
		}
		events.Publish(ctx, events.Event{Type: "iso.limit_hit", Severity: sev, AccountID: id, Data: data})
	}
	return nil
}
