// Package events is the in-process security/operations event bus of BPANEL
// (v0.4 security foundation). Any package may publish; the API process
// installs a sink that persists events and fans them out to admin-defined
// webhooks. Publish never blocks and never fails the caller.
//
//	events.Publish(ctx, events.Event{Type: "shield.quarantine", Severity: events.Warning, AccountID: 7, Data: map[string]any{"path": p}})
//
// Event data must never carry secrets (passwords, tokens, keys).
package events

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"sync"
	"time"
)

// Severities.
const (
	Info     = "info"
	Warning  = "warning"
	Critical = "critical"
)

// Event is one occurrence. ID and At are filled by Publish when empty.
type Event struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Severity  string         `json:"severity"`
	AccountID int64          `json:"account_id,omitempty"`
	At        int64          `json:"at"` // unix seconds
	Data      map[string]any `json:"data,omitempty"`
}

// Sink receives every published event (synchronously, from a single
// dispatcher goroutine; it must not block for long).
type Sink func(ctx context.Context, e Event)

var reType = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$`)

// ValidType reports whether t is a dotted lowercase event type.
func ValidType(t string) bool { return len(t) <= 64 && reType.MatchString(t) }

const bufMax = 512

var (
	mu      sync.Mutex
	sink    Sink
	pending []Event
	subs    = map[int]func(Event){}
	subSeq  int
	queue   = make(chan Event, 4096)
	started sync.Once
	dropped int64
	now     = time.Now
)

// NewID returns a random event id.
func NewID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "evt_" + hex.EncodeToString(b)
}

// Publish records an event. It is safe from any goroutine and returns at once.
func Publish(ctx context.Context, e Event) {
	if e.ID == "" {
		e.ID = NewID()
	}
	if e.At == 0 {
		e.At = now().Unix()
	}
	switch e.Severity {
	case Info, Warning, Critical:
	default:
		e.Severity = Info
	}
	if !ValidType(e.Type) {
		e.Type = "invalid.type"
	}
	started.Do(func() { go dispatch() })
	select {
	case queue <- e:
	default:
		mu.Lock()
		dropped++
		mu.Unlock()
	}
}

func dispatch() {
	for e := range queue {
		deliver(e)
	}
}

func deliver(e Event) {
	mu.Lock()
	s := sink
	if e.Type == "events.flush_marker" {
		s = nil
	} else if s == nil {
		pending = append(pending, e)
		if len(pending) > bufMax {
			pending = pending[len(pending)-bufMax:]
		}
	}
	fs := make([]func(Event), 0, len(subs))
	for _, f := range subs {
		fs = append(fs, f)
	}
	mu.Unlock()
	if s != nil {
		s(context.Background(), e)
	}
	for _, f := range fs {
		f(e)
	}
}

// SetSink installs the sink and flushes what was published before it.
// Passing nil removes it (events are buffered again).
func SetSink(s Sink) {
	mu.Lock()
	sink = s
	p := pending
	pending = nil
	mu.Unlock()
	if s != nil {
		for _, e := range p {
			s(context.Background(), e)
		}
	}
}

// Subscribe registers an in-process listener (tests, live UI streams) and
// returns the function that removes it.
func Subscribe(f func(Event)) func() {
	mu.Lock()
	defer mu.Unlock()
	subSeq++
	id := subSeq
	subs[id] = f
	return func() {
		mu.Lock()
		delete(subs, id)
		mu.Unlock()
	}
}

// Dropped returns how many events were dropped because the queue was full.
func Dropped() int64 {
	mu.Lock()
	defer mu.Unlock()
	return dropped
}

// Flush waits until every event published before the call was delivered
// (tests and shutdown).
func Flush() {
	done := make(chan struct{})
	started.Do(func() { go dispatch() })
	var once sync.Once
	unsub := Subscribe(func(e Event) {
		if e.Type == "events.flush_marker" {
			once.Do(func() { close(done) })
		}
	})
	defer unsub()
	queue <- Event{ID: NewID(), Type: "events.flush_marker", Severity: Info, At: now().Unix()}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}
