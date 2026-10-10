package agentrpc

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Breaker wraps a Caller with a circuit breaker and a health probe
// (R2-PERF-6). A hung or dead agent used to hold every request for the full
// method timeout (2-10 minutes). Now:
//
//   - after Threshold consecutive transport failures (agent_unreachable,
//     agent_timeout, agent_io) the circuit opens for Cooldown and calls fail
//     at once with agent_unreachable;
//   - Probe (run by the API every few seconds) pings the agent with a short
//     timeout; a failed ping opens the circuit, a good one closes it, so a
//     hung agent is detected within one probe interval;
//   - while open, one call per Cooldown is let through as a trial.
//
// Application errors (validation, not_found, ...) prove the agent is alive
// and reset the failure count.
type Breaker struct {
	Next        Caller
	Threshold   int
	Cooldown    time.Duration
	PingMethod  string
	PingTimeout time.Duration
	Now         func() time.Time

	mu        sync.Mutex
	failures  int
	openUntil time.Time
	trialAt   time.Time
}

// NewBreaker returns a breaker with the default policy (3 failures, 10 s).
func NewBreaker(next Caller) *Breaker {
	return &Breaker{Next: next, Threshold: 3, Cooldown: 10 * time.Second, PingMethod: MPing, PingTimeout: 3 * time.Second, Now: time.Now}
}

// circuitOpen is returned (as agent_unreachable) while the circuit is open.
func circuitOpen() error {
	return &Error{Code: "agent_unreachable", Message: "agent circuit open (recent calls failed or timed out)"}
}

// transportFailure reports errors that say nothing about the action but
// show the agent is not answering.
func transportFailure(err error) bool {
	var re *Error
	if !errors.As(err, &re) {
		return false
	}
	switch re.Code {
	case "agent_unreachable", "agent_timeout", "agent_io":
		return true
	}
	return false
}

// IsOpen reports whether calls are currently refused.
func (b *Breaker) IsOpen() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Now().Before(b.openUntil)
}

func (b *Breaker) admit() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.Now()
	if !now.Before(b.openUntil) {
		return true
	}
	if now.Sub(b.trialAt) >= b.Cooldown { // one trial call per cooldown while open
		b.trialAt = now
		return true
	}
	return false
}

func (b *Breaker) record(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil && transportFailure(err) {
		b.failures++
		if b.failures >= b.Threshold {
			b.trialAt = b.Now() // the first trial comes after a full cooldown
			b.openUntil = b.trialAt.Add(b.Cooldown)
		}
		return
	}
	b.failures = 0
	b.openUntil = time.Time{}
}

// Call forwards to Next unless the circuit is open.
func (b *Breaker) Call(ctx context.Context, method string, params any, result any) error {
	if !b.admit() {
		return circuitOpen()
	}
	err := b.Next.Call(ctx, method, params, result)
	if err != nil && ctx.Err() != nil && transportFailure(err) {
		return err // the caller gave up (browser closed): not the agent's fault
	}
	b.record(err)
	return err
}

// Probe pings the agent with a short timeout and updates the circuit:
// a failed ping opens it immediately, a good one closes it.
func (b *Breaker) Probe(ctx context.Context) error {
	pctx, cancel := context.WithTimeout(ctx, b.PingTimeout)
	defer cancel()
	err := b.Next.Call(pctx, b.PingMethod, Empty{}, nil)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil && (transportFailure(err) || pctx.Err() != nil) {
		b.failures = max(b.failures, b.Threshold)
		b.trialAt = b.Now()
		b.openUntil = b.trialAt.Add(b.Cooldown)
		return err
	}
	b.failures = 0
	b.openUntil = time.Time{}
	return nil
}
