package client_path_traversal_confirm

import (
	"context"
	"sync"
	"sync/atomic"
)

// Defaults are conservative — each confirm round spawns a real browser process,
// which is dramatically more expensive than a regular HTTP scan request.
const (
	defaultPerHostBrowsers = 1
	defaultMaxScanProbes   = 100
)

// Budget bounds how often the module escalates to a real browser probe, across
// both per-host concurrency and per-scan total. Replicated from
// active/xss_dom_confirm rather than imported, so the two browser-confirm
// modules stay independently tunable.
type Budget struct {
	maxPerScan int32 // hard cap on the TOTAL browser probes launched per scan

	mu             sync.Mutex
	hostSemaphores map[string]chan struct{}
	perHost        int

	// launched is a MONOTONIC count of probes launched this scan. It is never
	// decremented on release, so maxPerScan bounds the total number of browser
	// processes for the whole scan. (The previous `remaining` counter was restored
	// on release, which made it only a per-instant concurrency limit — sequential
	// confirmations could launch an unbounded number of browsers.)
	launched atomic.Int32
}

// NewBudget returns a fresh budget. Pass <= 0 to use defaults.
func NewBudget(perHost, totalPerScan int) *Budget {
	if perHost <= 0 {
		perHost = defaultPerHostBrowsers
	}
	if totalPerScan <= 0 {
		totalPerScan = defaultMaxScanProbes
	}
	return &Budget{
		maxPerScan:     int32(totalPerScan),
		perHost:        perHost,
		hostSemaphores: make(map[string]chan struct{}),
	}
}

// Reserve consumes one probe slot for host. The returned release must be called
// once the probe is done. ok=false means the per-scan total cap is exhausted or
// ctx was cancelled while waiting on the per-host concurrency semaphore.
func (b *Budget) Reserve(ctx context.Context, host string) (release func(), ok bool) {
	if b == nil {
		return func() {}, true
	}

	// Claim one of the scan's total probe tokens (monotonic). A rejected or
	// cancelled reserve returns its token since it never actually launched a probe.
	if b.launched.Add(1) > b.maxPerScan {
		b.launched.Add(-1)
		return nil, false
	}

	sem := b.hostSem(host)
	select {
	case sem <- struct{}{}:
		return func() {
			<-sem
			// Intentionally do NOT decrement launched: the probe ran and counts
			// against the scan's total budget for good.
		}, true
	case <-ctx.Done():
		b.launched.Add(-1) // never launched — return the total token
		return nil, false
	}
}

func (b *Budget) hostSem(host string) chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	sem, ok := b.hostSemaphores[host]
	if !ok {
		sem = make(chan struct{}, b.perHost)
		b.hostSemaphores[host] = sem
	}
	return sem
}
