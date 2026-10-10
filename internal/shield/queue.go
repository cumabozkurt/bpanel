package shield

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// QueueItem is one pending scan job.
type QueueItem struct {
	Account   string    `json:"account"`
	Path      string    `json:"path"`
	Enqueued  time.Time `json:"enqueued"`
	NotBefore time.Time `json:"not_before"` // debounce / retry backoff
	Attempts  int       `json:"attempts"`
	LastError string    `json:"last_error,omitempty"`
}

func (it *QueueItem) key() string { return it.Account + "\x00" + it.Path }

// QueueHandler processes one item. A returned error (or panic) triggers a retry.
type QueueHandler func(ctx context.Context, it QueueItem) error

// QueueConfig tunes the fair queue. Zero values get sane defaults.
type QueueConfig struct {
	Workers       int
	PerAccountCap int           // pending items per account (default 5000)
	GlobalCap     int           // pending items overall (default 50000)
	Debounce      time.Duration // a path is held this long after its last event
	JobTimeout    time.Duration // default 2m
	MaxRetries    int           // retries after the first attempt (default 3)
	Backoff       time.Duration // base backoff, doubled per attempt (default 1s)
	StatePath     string        // JSON persistence of pending items ("" = none)
	SaveInterval  time.Duration // periodic persistence (default 2s)
	Poll          time.Duration // idle worker poll (default 20ms)
}

// QueueStats are the queue metrics.
type QueueStats struct {
	Depth     map[string]int `json:"depth"` // pending per account
	Pending   int            `json:"pending"`
	InFlight  int            `json:"in_flight"`
	Processed uint64         `json:"processed"`
	Failed    uint64         `json:"failed"` // gave up after retries
	Retried   uint64         `json:"retried"`
	Dropped   uint64         `json:"dropped"` // cap reached
	Deduped   uint64         `json:"deduped"`
	Panics    uint64         `json:"panics"`
}

// ErrQueueFull is returned when a per-account or global cap is reached.
var ErrQueueFull = errors.New("shield queue full")

// Queue is a per-account fair (round-robin) work queue with dedupe by path,
// debounce, bounded size, retries and JSON persistence.
type Queue struct {
	cfg     QueueConfig
	handler QueueHandler

	mu       sync.Mutex
	perAcct  map[string][]*QueueItem // FIFO per account
	accounts []string                // round-robin ring
	rr       int
	pending  map[string]*QueueItem
	inflight map[string]*QueueItem
	redo     map[string]bool // re-enqueued while in flight
	stats    QueueStats
	dirty    bool

	wake    chan struct{}
	stop    chan struct{}
	wg      sync.WaitGroup
	started bool
	now     func() time.Time
}

// NewQueue creates a queue and reloads persisted items from cfg.StatePath.
func NewQueue(cfg QueueConfig, h QueueHandler) (*Queue, error) {
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	if cfg.PerAccountCap <= 0 {
		cfg.PerAccountCap = 5000
	}
	if cfg.GlobalCap <= 0 {
		cfg.GlobalCap = 50000
	}
	if cfg.JobTimeout <= 0 {
		cfg.JobTimeout = 2 * time.Minute
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	} else if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = time.Second
	}
	if cfg.SaveInterval <= 0 {
		cfg.SaveInterval = 2 * time.Second
	}
	if cfg.Poll <= 0 {
		cfg.Poll = 20 * time.Millisecond
	}
	q := &Queue{cfg: cfg, handler: h, perAcct: map[string][]*QueueItem{}, pending: map[string]*QueueItem{},
		inflight: map[string]*QueueItem{}, redo: map[string]bool{}, wake: make(chan struct{}, 1),
		stop: make(chan struct{}), now: time.Now}
	if cfg.StatePath != "" {
		if err := q.load(); err != nil {
			return nil, err
		}
	}
	return q, nil
}

// Enqueue adds (account, path). An already pending path is coalesced and its
// debounce window restarted; a path being processed is scanned again after.
func (q *Queue) Enqueue(account, path string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	it := &QueueItem{Account: account, Path: path, Enqueued: now, NotBefore: now.Add(q.cfg.Debounce)}
	k := it.key()
	if p, ok := q.pending[k]; ok {
		if p.Attempts == 0 { // don't shorten a retry backoff
			p.NotBefore = it.NotBefore
		}
		q.stats.Deduped++
		return nil
	}
	if _, ok := q.inflight[k]; ok {
		q.redo[k] = true
		q.stats.Deduped++
		return nil
	}
	return q.insertLocked(it)
}

func (q *Queue) insertLocked(it *QueueItem) error {
	if len(q.perAcct[it.Account]) >= q.cfg.PerAccountCap || len(q.pending) >= q.cfg.GlobalCap {
		q.stats.Dropped++
		return ErrQueueFull
	}
	if _, ok := q.perAcct[it.Account]; !ok {
		q.accounts = append(q.accounts, it.Account)
	}
	q.perAcct[it.Account] = append(q.perAcct[it.Account], it)
	q.pending[it.key()] = it
	q.dirty = true
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return nil
}

// next picks the next ready item round-robin across accounts.
func (q *Queue) next() *QueueItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	n := len(q.accounts)
	for i := 0; i < n; i++ {
		idx := (q.rr + i) % n
		acct := q.accounts[idx]
		list := q.perAcct[acct]
		lim := len(list)
		if lim > 64 { // bounded look-ahead past debounced heads
			lim = 64
		}
		for j := 0; j < lim; j++ {
			it := list[j]
			if it.NotBefore.After(now) {
				continue
			}
			if j == 0 {
				list[0] = nil
				q.perAcct[acct] = list[1:]
			} else {
				q.perAcct[acct] = append(list[:j], list[j+1:]...)
			}
			delete(q.pending, it.key())
			q.inflight[it.key()] = it
			q.rr = idx + 1
			if len(q.perAcct[acct]) == 0 {
				delete(q.perAcct, acct)
				q.accounts = append(q.accounts[:idx:idx], q.accounts[idx+1:]...)
				q.rr = idx
			}
			if n2 := len(q.accounts); n2 > 0 {
				q.rr %= n2
			} else {
				q.rr = 0
			}
			q.dirty = true
			return it
		}
	}
	return nil
}

// Start launches the worker pool.
func (q *Queue) Start() {
	q.mu.Lock()
	if q.started {
		q.mu.Unlock()
		return
	}
	q.started = true
	q.mu.Unlock()
	for i := 0; i < q.cfg.Workers; i++ {
		q.wg.Add(1)
		go q.worker()
	}
	if q.cfg.StatePath != "" {
		q.wg.Add(1)
		go q.saver()
	}
}

// Stop stops workers (in-flight jobs finish or time out) and persists state.
func (q *Queue) Stop() error {
	q.mu.Lock()
	started := q.started
	q.mu.Unlock()
	if started {
		close(q.stop)
		q.wg.Wait()
	}
	return q.Save()
}

func (q *Queue) saver() {
	defer q.wg.Done()
	t := time.NewTicker(q.cfg.SaveInterval)
	defer t.Stop()
	for {
		select {
		case <-q.stop:
			return
		case <-t.C:
			q.mu.Lock()
			d := q.dirty
			q.mu.Unlock()
			if d {
				_ = q.Save()
			}
		}
	}
}

func (q *Queue) worker() {
	defer q.wg.Done()
	for {
		select {
		case <-q.stop:
			return
		default:
		}
		it := q.next()
		if it == nil {
			select {
			case <-q.stop:
				return
			case <-q.wake:
			case <-time.After(q.cfg.Poll):
			}
			continue
		}
		err := q.run(it)
		q.finish(it, err)
	}
}

func (q *Queue) run(it *QueueItem) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), q.cfg.JobTimeout)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			q.mu.Lock()
			q.stats.Panics++
			q.mu.Unlock()
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	done := make(chan error, 1)
	cp := *it
	go func() {
		defer func() {
			if r := recover(); r != nil {
				q.mu.Lock()
				q.stats.Panics++
				q.mu.Unlock()
				done <- fmt.Errorf("panic: %v", r)
			}
		}()
		done <- q.handler(ctx, cp)
	}()
	select {
	case err = <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("job timeout after %s", q.cfg.JobTimeout)
	}
}

func (q *Queue) finish(it *QueueItem, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	k := it.key()
	delete(q.inflight, k)
	redo := q.redo[k]
	delete(q.redo, k)
	q.dirty = true
	if err == nil {
		q.stats.Processed++
		if redo {
			now := q.now()
			_ = q.insertLocked(&QueueItem{Account: it.Account, Path: it.Path, Enqueued: now, NotBefore: now.Add(q.cfg.Debounce)})
		}
		return
	}
	it.Attempts++
	it.LastError = err.Error()
	if it.Attempts > q.cfg.MaxRetries {
		q.stats.Failed++
		return
	}
	q.stats.Retried++
	it.NotBefore = q.now().Add(q.cfg.Backoff << (it.Attempts - 1))
	_ = q.insertLocked(it)
}

// Stats returns a snapshot of the metrics.
func (q *Queue) Stats() QueueStats {
	q.mu.Lock()
	defer q.mu.Unlock()
	s := q.stats
	s.Depth = map[string]int{}
	for a, l := range q.perAcct {
		s.Depth[a] = len(l)
	}
	s.Pending = len(q.pending)
	s.InFlight = len(q.inflight)
	return s
}

type queueState struct {
	Version int          `json:"version"`
	Items   []*QueueItem `json:"items"`
}

// Save persists pending and in-flight items (atomic write: tmp+fsync+rename).
func (q *Queue) Save() error {
	if q.cfg.StatePath == "" {
		return nil
	}
	q.mu.Lock()
	st := queueState{Version: 1}
	for _, it := range q.pending {
		c := *it
		st.Items = append(st.Items, &c)
	}
	for _, it := range q.inflight { // not finished => must survive a crash/restart
		c := *it
		st.Items = append(st.Items, &c)
	}
	q.dirty = false
	q.mu.Unlock()
	sort.Slice(st.Items, func(i, j int) bool { return st.Items[i].Enqueued.Before(st.Items[j].Enqueued) })
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return atomicWrite(q.cfg.StatePath, b, 0600)
}

func (q *Queue) load() error {
	b, err := os.ReadFile(q.cfg.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var st queueState
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("shield queue state corrupt: %w", err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, it := range st.Items {
		if it == nil || it.Path == "" {
			continue
		}
		if _, dup := q.pending[it.key()]; dup {
			continue
		}
		_ = q.insertLocked(it)
	}
	q.dirty = false
	return nil
}

// atomicWrite writes data to path via a temp file in the same dir, fsyncs it,
// renames it into place and fsyncs the directory.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}
