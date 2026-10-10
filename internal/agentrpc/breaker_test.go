package agentrpc

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeCaller struct {
	mu    sync.Mutex
	err   error
	calls atomic.Int64
	delay time.Duration
}

func (f *fakeCaller) Call(ctx context.Context, method string, params, result any) error {
	f.calls.Add(1)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return &Error{Code: "agent_timeout", Message: "timeout"}
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

func (f *fakeCaller) set(err error) { f.mu.Lock(); f.err = err; f.mu.Unlock() }

// R2-PERF-6: the circuit opens after Threshold transport failures and
// fails fast; application errors and successes close it.
func TestR2BreakerOpensAndCloses(t *testing.T) {
	now := time.Unix(1000, 0)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	f := &fakeCaller{err: &Error{Code: "agent_unreachable"}}
	b := NewBreaker(f)
	b.Now = clock
	for i := 0; i < 3; i++ {
		_ = b.Call(context.Background(), "x", nil, nil)
	}
	if !b.IsOpen() {
		t.Fatal("not open after 3 failures")
	}
	n := f.calls.Load()
	err := b.Call(context.Background(), "x", nil, nil)
	var re *Error
	if !errors.As(err, &re) || re.Code != "agent_unreachable" || f.calls.Load() != n {
		t.Fatalf("open circuit called the agent: %v", err)
	}
	// after the cooldown one trial goes through; success closes the circuit
	mu.Lock()
	now = now.Add(11 * time.Second)
	mu.Unlock()
	f.set(nil)
	if err := b.Call(context.Background(), "x", nil, nil); err != nil {
		t.Fatal(err)
	}
	if b.IsOpen() {
		t.Fatal("still open after a good call")
	}
	// an application error is a sign of life
	f.set(&Error{Code: "not_found"})
	for i := 0; i < 5; i++ {
		_ = b.Call(context.Background(), "x", nil, nil)
	}
	if b.IsOpen() {
		t.Fatal("opened on application errors")
	}
}

// R2-PERF-6: a hung agent is detected by the probe within its timeout.
func TestR2BreakerProbeHungAgent(t *testing.T) {
	f := &fakeCaller{delay: time.Hour}
	b := NewBreaker(f)
	b.PingTimeout = 50 * time.Millisecond
	start := time.Now()
	if err := b.Probe(context.Background()); err == nil {
		t.Fatal("probe of a hung agent succeeded")
	}
	if time.Since(start) > time.Second || !b.IsOpen() {
		t.Fatalf("probe took %v, open=%v", time.Since(start), b.IsOpen())
	}
	f.delay = 0
	if err := b.Probe(context.Background()); err != nil || b.IsOpen() {
		t.Fatalf("recovered probe: %v open=%v", err, b.IsOpen())
	}
}

func TestR2BreakerRace(t *testing.T) {
	f := &fakeCaller{}
	b := NewBreaker(f)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%3 == 0 {
				f.set(&Error{Code: "agent_io"})
			} else {
				f.set(nil)
			}
			_ = b.Call(context.Background(), "x", nil, nil)
			_ = b.Probe(context.Background())
			_ = b.IsOpen()
		}(i)
	}
	wg.Wait()
}
