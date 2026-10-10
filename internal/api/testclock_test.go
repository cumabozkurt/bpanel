// SPDX-License-Identifier: Apache-2.0

package api

import (
	"sync"
	"time"
)

// testClock is a goroutine-safe fake clock for Server.Now. Events are
// delivered on background goroutines (events.Publish) which read Server.Now
// while a test advances the time, so a plain captured variable is a data race
// under `go test -race`.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock(t time.Time) *testClock { return &testClock{t: t} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}
