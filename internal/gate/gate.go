// Package gate bounds how many expensive operations run at once.
//
// A server that starts every request's work immediately has a memory bound that
// is the per-operation cost times however many requests arrive. A gate makes it
// the per-operation cost times a number the operator chose: the rest wait their
// turn, holding only a goroutine, and give up when their client does.
package gate

import (
	"context"
	"sync/atomic"
	"time"
)

// Gate lets at most N holders in at a time.
type Gate struct {
	slots chan struct{}

	running, waiting         atomic.Int64
	peakRunning, peakWaiting atomic.Int64
	admitted                 atomic.Int64
	waitedNanos              atomic.Int64
	longestWaitNanos         atomic.Int64
}

// New returns a gate of size n (at least 1).
func New(n int) *Gate {
	if n < 1 {
		n = 1
	}
	return &Gate{slots: make(chan struct{}, n)}
}

// Size is the number of holders allowed at once.
func (g *Gate) Size() int { return cap(g.slots) }

// Acquire waits for a slot. It returns ctx.Err() if the context ends first. The
// returned function gives the slot back and is safe to call more than once.
func (g *Gate) Acquire(ctx context.Context) (release func(), err error) {
	start := time.Now()
	// Take a free slot without queueing when there is one.
	select {
	case g.slots <- struct{}{}:
	default:
		w := g.waiting.Add(1)
		raise(&g.peakWaiting, w)
		select {
		case g.slots <- struct{}{}:
			g.waiting.Add(-1)
		case <-ctx.Done():
			g.waiting.Add(-1)
			return func() {}, ctx.Err()
		}
	}
	waited := time.Since(start).Nanoseconds()
	g.waitedNanos.Add(waited)
	raise(&g.longestWaitNanos, waited)
	g.admitted.Add(1)
	raise(&g.peakRunning, g.running.Add(1))

	var done atomic.Bool
	return func() {
		if done.CompareAndSwap(false, true) {
			g.running.Add(-1)
			<-g.slots
		}
	}, nil
}

func raise(a *atomic.Int64, v int64) {
	for {
		old := a.Load()
		if v <= old || a.CompareAndSwap(old, v) {
			return
		}
	}
}

// Stats is a snapshot of the gate, for logs and tests.
type Stats struct {
	Size        int
	Running     int
	Waiting     int
	PeakRunning int
	PeakWaiting int
	Admitted    int64
	// TotalWait is the time admitted holders spent queued, summed.
	TotalWait   time.Duration
	LongestWait time.Duration
}

// Stats returns the current counters.
func (g *Gate) Stats() Stats {
	return Stats{
		Size:        g.Size(),
		Running:     int(g.running.Load()),
		Waiting:     int(g.waiting.Load()),
		PeakRunning: int(g.peakRunning.Load()),
		PeakWaiting: int(g.peakWaiting.Load()),
		Admitted:    g.admitted.Load(),
		TotalWait:   time.Duration(g.waitedNanos.Load()),
		LongestWait: time.Duration(g.longestWaitNanos.Load()),
	}
}
