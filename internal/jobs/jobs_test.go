package jobs

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cumabozkurt/bpanel/internal/store"
)

func newRunner(t *testing.T, workers int) (*Runner, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st.DB, nil, workers), st
}

func TestRunSucceedFail(t *testing.T) {
	r, _ := newRunner(t, 2)
	ctx := context.Background()
	r.Register("ok", func(ctx context.Context, j *Job) (any, error) { return map[string]int{"n": 1}, nil })
	r.Register("bad", func(ctx context.Context, j *Job) (any, error) { return nil, errors.New("boom") })
	r.Register("panic", func(ctx context.Context, j *Job) (any, error) { panic("x") })
	a, _ := r.Enqueue(ctx, Spec{Kind: "ok", ActorID: 7})
	b, _ := r.Enqueue(ctx, Spec{Kind: "bad"})
	c, _ := r.Enqueue(ctx, Spec{Kind: "panic"})
	d, _ := r.Enqueue(ctx, Spec{Kind: "nohandler"})
	for r.RunOnce(ctx) {
	}
	want := map[string][2]string{a: {Succeeded, ""}, b: {Failed, "boom"}, c: {Failed, "job_panic"}, d: {Failed, "unknown_job_kind"}}
	for id, w := range want {
		j, err := r.Get(ctx, id)
		if err != nil || j.Status != w[0] || j.Error != w[1] {
			t.Fatalf("%s: %+v %v", id, j, err)
		}
	}
	j, _ := r.Get(ctx, a)
	if string(j.Result) != `{"n":1}` || j.OwnerID != 7 {
		t.Fatal(string(j.Result))
	}
}

func TestCrashRecovery(t *testing.T) {
	r, st := newRunner(t, 1)
	ctx := context.Background()
	id, _ := r.Enqueue(ctx, Spec{Kind: "k"})
	// simulate a process that died mid-job
	st.DB.Exec(`UPDATE jobs SET status='running' WHERE id=?`, id)
	var ran atomic.Int32
	r2 := New(st.DB, nil, 1)
	r2.Register("k", func(ctx context.Context, j *Job) (any, error) { ran.Add(1); return nil, nil })
	c, cancel := context.WithCancel(ctx)
	r2.Start(c)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if j, _ := r2.Get(ctx, id); j.Status == Succeeded {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	r2.Wait()
	if j, _ := r2.Get(ctx, id); j.Status != Succeeded || ran.Load() != 1 {
		t.Fatalf("status=%s ran=%d", j.Status, ran.Load())
	}
}

func TestBoundedWorkers(t *testing.T) {
	r, _ := newRunner(t, 2)
	ctx, cancel := context.WithCancel(context.Background())
	var cur, max atomic.Int32
	done := make(chan struct{}, 6)
	r.Register("slow", func(ctx context.Context, j *Job) (any, error) {
		n := cur.Add(1)
		for {
			m := max.Load()
			if n <= m || max.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		cur.Add(-1)
		done <- struct{}{}
		return nil, nil
	})
	for i := 0; i < 6; i++ {
		r.Enqueue(ctx, Spec{Kind: "slow"})
	}
	r.Start(ctx)
	for i := 0; i < 6; i++ {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("timeout")
		}
	}
	cancel()
	r.Wait()
	if max.Load() > 2 {
		t.Fatalf("concurrency %d > 2", max.Load())
	}
}
