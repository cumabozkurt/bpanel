// Package jobs is BPANEL's DB-backed background job runner (v0.4).
//
// Jobs live in the `jobs` table with status queued → running →
// succeeded|failed. A bounded pool of worker goroutines claims queued jobs.
// On Start, rows left `running` by a crashed process go back to `queued`
// (handlers must therefore be idempotent / safe to re-run).
package jobs

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const (
	Queued    = "queued"
	Running   = "running"
	Succeeded = "succeeded"
	Failed    = "failed"
)

var ErrNotFound = errors.New("not_found")

// Job is one row.
type Job struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Status    string          `json:"status"`
	OwnerID   int64           `json:"owner_id"`
	Payload   json.RawMessage `json:"-"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
	CreatedAt int64           `json:"created_at"`
	UpdatedAt int64           `json:"updated_at"`
}

// Spec describes a job to enqueue.
type Spec struct {
	Kind    string
	ActorID int64 // owner: who may read the job besides admins
	Payload any
}

// Handler runs a job; its result is stored as JSON.
type Handler func(ctx context.Context, j *Job) (any, error)

// Runner executes jobs.
type Runner struct {
	db       *sql.DB
	log      *slog.Logger
	workers  int
	mu       sync.RWMutex
	handlers map[string]Handler
	wake     chan struct{}
	poll     time.Duration
	timeout  time.Duration
	now      func() time.Time
	wg       sync.WaitGroup
}

// New returns a runner with at most `workers` concurrent jobs (1..16).
func New(db *sql.DB, log *slog.Logger, workers int) *Runner {
	if workers < 1 {
		workers = 1
	}
	if workers > 16 {
		workers = 16
	}
	if log == nil {
		log = slog.Default()
	}
	return &Runner{db: db, log: log, workers: workers, handlers: map[string]Handler{}, wake: make(chan struct{}, 1),
		poll: 2 * time.Second, timeout: 30 * time.Minute, now: time.Now}
}

// Register installs the handler for kind (replacing any earlier one).
func (r *Runner) Register(kind string, h Handler) {
	r.mu.Lock()
	r.handlers[kind] = h
	r.mu.Unlock()
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "job_" + hex.EncodeToString(b)
}

// Enqueue stores a queued job and wakes a worker.
func (r *Runner) Enqueue(ctx context.Context, s Spec) (string, error) {
	if s.Kind == "" {
		return "", errors.New("jobs: empty kind")
	}
	p := []byte("")
	if s.Payload != nil {
		b, err := json.Marshal(s.Payload)
		if err != nil {
			return "", err
		}
		p = b
	}
	id := newID()
	now := r.now().UnixNano()
	if _, err := r.db.ExecContext(ctx, `INSERT INTO jobs(id,kind,status,owner_id,payload,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
		id, s.Kind, Queued, s.ActorID, string(p), now, now); err != nil {
		return "", err
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return id, nil
}

// Get returns one job.
func (r *Runner) Get(ctx context.Context, id string) (*Job, error) {
	var j Job
	var p, res string
	err := r.db.QueryRowContext(ctx, `SELECT id,kind,status,owner_id,payload,result,error,created_at,updated_at FROM jobs WHERE id=?`, id).
		Scan(&j.ID, &j.Kind, &j.Status, &j.OwnerID, &p, &res, &j.Error, &j.CreatedAt, &j.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	j.Payload = json.RawMessage(p)
	if res != "" {
		j.Result = json.RawMessage(res)
	}
	// timestamps are stored in ns for ordering; expose seconds
	j.CreatedAt /= int64(time.Second)
	j.UpdatedAt /= int64(time.Second)
	return &j, nil
}

// Recover moves jobs left `running` by a dead process back to `queued`.
func (r *Runner) Recover(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE jobs SET status=?, updated_at=? WHERE status=?`, Queued, r.now().UnixNano(), Running)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Start recovers crashed jobs and launches the workers; they stop with ctx.
func (r *Runner) Start(ctx context.Context) {
	if n, err := r.Recover(ctx); err != nil {
		r.log.Warn("jobs: recover", "err", err)
	} else if n > 0 {
		r.log.Info("jobs: requeued interrupted jobs", "count", n)
	}
	for i := 0; i < r.workers; i++ {
		r.wg.Add(1)
		go r.worker(ctx)
	}
}

// Wait blocks until every worker has exited (after ctx is cancelled).
func (r *Runner) Wait() { r.wg.Wait() }

func (r *Runner) worker(ctx context.Context) {
	defer r.wg.Done()
	t := time.NewTicker(r.poll)
	defer t.Stop()
	for {
		for r.RunOnce(ctx) {
			if ctx.Err() != nil {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
		case <-t.C:
		}
	}
}

// claim atomically moves the oldest queued job to running.
func (r *Runner) claim(ctx context.Context) (*Job, error) {
	for i := 0; i < 5; i++ {
		var id string
		err := r.db.QueryRowContext(ctx, `SELECT id FROM jobs WHERE status=? ORDER BY created_at LIMIT 1`, Queued).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		res, err := r.db.ExecContext(ctx, `UPDATE jobs SET status=?, updated_at=? WHERE id=? AND status=?`, Running, r.now().UnixNano(), id, Queued)
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return r.Get(ctx, id)
		}
	}
	return nil, nil
}

// RunOnce claims and runs one job; it reports whether a job ran.
func (r *Runner) RunOnce(ctx context.Context) bool {
	j, err := r.claim(ctx)
	if err != nil {
		if ctx.Err() == nil {
			r.log.Warn("jobs: claim", "err", err)
		}
		return false
	}
	if j == nil {
		return false
	}
	r.mu.RLock()
	h := r.handlers[j.Kind]
	r.mu.RUnlock()
	var out any
	if h == nil {
		err = fmt.Errorf("unknown_job_kind")
	} else {
		out, err = r.safeRun(ctx, h, j)
	}
	status, res, msg := Succeeded, "", ""
	if err != nil {
		status, msg = Failed, err.Error()
	} else if out != nil {
		b, e := json.Marshal(out)
		if e != nil {
			status, msg = Failed, "result_not_serialisable"
		} else {
			res = string(b)
		}
	}
	if _, e := r.db.ExecContext(context.Background(), `UPDATE jobs SET status=?, result=?, error=?, updated_at=? WHERE id=?`,
		status, res, msg, r.now().UnixNano(), j.ID); e != nil {
		r.log.Warn("jobs: finish", "id", j.ID, "err", e)
	}
	return true
}

func (r *Runner) safeRun(ctx context.Context, h Handler, j *Job) (out any, err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("job_panic")
			r.log.Error("jobs: handler panic", "id", j.ID, "kind", j.Kind, "panic", fmt.Sprint(v))
		}
	}()
	c, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	return h(c, j)
}

// Prune deletes finished jobs older than age.
func (r *Runner) Prune(ctx context.Context, age time.Duration) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM jobs WHERE status IN (?,?) AND updated_at<?`, Succeeded, Failed, r.now().Add(-age).UnixNano())
	return err
}
