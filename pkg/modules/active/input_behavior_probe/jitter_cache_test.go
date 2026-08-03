package input_behavior_probe

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func jitterTestItem(path string) *httpmsg.HttpRequestResponse {
	raw := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true), raw)
	return httpmsg.NewHttpRequestResponse(req, nil)
}

// The whole point of the cache: every insertion point on a record re-fetches the
// same unmodified request, so the calibration must happen once, not once per
// point.
func TestJitterCache_MeasuresOncePerEndpoint(t *testing.T) {
	c := newJitterCache()
	item := jitterTestItem("/a")

	var calls atomic.Int32
	measure := func() int {
		calls.Add(1)
		return 7
	}

	for i := 0; i < 20; i++ {
		if got := c.get(item, measure); got != 7 {
			t.Fatalf("call %d returned %d, want 7", i, got)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("measured %d times, want exactly 1", n)
	}
}

// Distinct endpoints must not share a measurement.
func TestJitterCache_SeparatesEndpoints(t *testing.T) {
	c := newJitterCache()

	if got := c.get(jitterTestItem("/a"), func() int { return 1 }); got != 1 {
		t.Fatalf("endpoint /a = %d, want 1", got)
	}
	if got := c.get(jitterTestItem("/b"), func() int { return 2 }); got != 2 {
		t.Fatalf("endpoint /b = %d, want 2", got)
	}
	// /a must still read its own value, not /b's.
	if got := c.get(jitterTestItem("/a"), func() int { return 99 }); got != 1 {
		t.Fatalf("endpoint /a re-read = %d, want cached 1", got)
	}
}

// The executor dispatches a record's insertion points concurrently, so the
// misses all land at the same instant. Without singleflight each would run its
// own control fetches — the exact cost this cache removes.
func TestJitterCache_CoalescesConcurrentMeasurements(t *testing.T) {
	c := newJitterCache()
	item := jitterTestItem("/concurrent")

	var calls atomic.Int32
	measure := func() int {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond) // hold the flight open so others pile on
		return 3
	}

	var wg sync.WaitGroup
	results := make([]int, 20)
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = c.get(item, measure)
		}(i)
	}
	wg.Wait()

	if n := calls.Load(); n != 1 {
		t.Fatalf("measured %d times under concurrency, want exactly 1", n)
	}
	for i, got := range results {
		if got != 3 {
			t.Fatalf("goroutine %d got %d, want 3", i, got)
		}
	}
}

// An unidentifiable request must fall back to measuring rather than sharing a
// bogus empty key with every other such request.
func TestJitterCache_NilRequestFallsBackToMeasure(t *testing.T) {
	c := newJitterCache()
	var calls atomic.Int32
	measure := func() int {
		calls.Add(1)
		return 5
	}

	for i := 0; i < 3; i++ {
		if got := c.get(nil, measure); got != 5 {
			t.Fatalf("nil ctx returned %d, want 5", got)
		}
	}
	if n := calls.Load(); n != 3 {
		t.Fatalf("nil ctx measured %d times, want 3 (no shared key)", n)
	}
}

// A stale measurement must not outlive the baseline it was measured against.
func TestJitterCache_ExpiredEntryRemeasures(t *testing.T) {
	c := newJitterCache()
	item := jitterTestItem("/stale")

	c.entries.Add(jitterKey(item), jitterEntry{
		value:      1,
		measuredAt: time.Now().Add(-2 * jitterTTL),
	})

	if got := c.get(item, func() int { return 42 }); got != 42 {
		t.Fatalf("expired entry returned %d, want a fresh 42", got)
	}
}
