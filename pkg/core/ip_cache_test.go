package core

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// nestedRequest returns a urlencoded POST whose single "payload" parameter holds
// a JSON document with n children, i.e. a request that expands into n nested
// insertion points. Child count is the lever on entry weight.
func nestedRequest(n int) []byte {
	var doc strings.Builder
	doc.WriteString("{")
	for i := 0; i < n; i++ {
		if i > 0 {
			doc.WriteString(",")
		}
		fmt.Fprintf(&doc, `"field_%d":"value_%d_padding_padding_padding_padding"`, i, i)
	}
	doc.WriteString("}")

	body := "payload=" + doc.String()
	return []byte("POST /submit HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"\r\n" + body)
}

func mustPoints(t *testing.T, raw []byte) []httpmsg.InsertionPoint {
	t.Helper()
	pts, err := httpmsg.CreateAllInsertionPoints(raw, true)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints: %v", err)
	}
	return pts
}

func TestInsertionPointCacheGetAddAndStats(t *testing.T) {
	c := NewInsertionPointCache(8)
	pts := mustPoints(t, nestedRequest(5))

	if _, ok := c.Get("absent"); ok {
		t.Error("Get on empty cache reported a hit")
	}

	c.Add("k", pts)

	got, ok := c.Get("k")
	if !ok {
		t.Fatal("Get after Add reported a miss")
	}
	if len(got) != len(pts) {
		t.Errorf("Get returned %d points, want %d", len(got), len(pts))
	}

	stats := c.Stats()
	if stats.Entries != 1 {
		t.Errorf("Entries = %d, want 1", stats.Entries)
	}
	if stats.RetainedBytes <= 0 {
		t.Errorf("RetainedBytes = %d, want > 0", stats.RetainedBytes)
	}
	if stats.Hits != 1 {
		t.Errorf("Hits = %d, want 1", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("Misses = %d, want 1", stats.Misses)
	}
}

// A re-Add under the same key must not double-count its weight, or the byte
// budget drifts upward on every rescan of a repeated request.
func TestInsertionPointCacheReplaceDoesNotDoubleCount(t *testing.T) {
	c := NewInsertionPointCache(8)
	pts := mustPoints(t, nestedRequest(20))

	c.Add("k", pts)
	first := c.Stats().RetainedBytes

	for i := 0; i < 5; i++ {
		c.Add("k", pts)
	}

	stats := c.Stats()
	if stats.Entries != 1 {
		t.Fatalf("Entries = %d after repeated Add of one key, want 1", stats.Entries)
	}
	if stats.RetainedBytes != first {
		t.Errorf("RetainedBytes = %d after 6 Adds of the same key, want %d (weight double-counted)",
			stats.RetainedBytes, first)
	}
}

// Evicting by entry count must discount the evicted weight, so the byte counter
// tracks what is actually retained rather than everything ever admitted.
func TestInsertionPointCacheCountEvictionDiscountsBytes(t *testing.T) {
	const capacity = 4
	c := NewInsertionPointCache(capacity)

	for i := 0; i < capacity*3; i++ {
		c.Add(fmt.Sprintf("k%d", i), mustPoints(t, nestedRequest(10)))
	}

	stats := c.Stats()
	if stats.Entries != capacity {
		t.Fatalf("Entries = %d, want %d (entry cap)", stats.Entries, capacity)
	}

	// Retained bytes must reflect ~capacity entries, not all 12 that were added.
	perEntry := float64(stats.RetainedBytes) / float64(stats.Entries)
	oneEntry := float64(httpmsg.EstimateRetainedBytes(mustPoints(t, nestedRequest(10))))
	if perEntry > oneEntry*1.5 {
		t.Errorf("retained bytes per entry = %.0f, want about %.0f; evicted weight is not being discounted",
			perEntry, oneEntry)
	}
}

// An entry above the per-entry ceiling is not cached at all — it must not be
// admitted and then immediately evict everything else to get back under budget.
func TestInsertionPointCacheRejectsOversizedEntry(t *testing.T) {
	c := NewInsertionPointCache(64)

	small := mustPoints(t, nestedRequest(5))
	c.Add("small", small)
	beforeBytes := c.Stats().RetainedBytes

	// Fabricate an entry whose estimated weight exceeds the per-entry ceiling by
	// pointing many insertion points at a very large request.
	hugeBody := strings.Repeat("A", ipCacheMaxEntryBytes)
	hugeRaw := []byte("POST /big HTTP/1.1\r\nHost: example.test\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len("q=")+len(hugeBody)) +
		"\r\n" + "q=" + hugeBody)
	huge := mustPoints(t, hugeRaw)
	if w := httpmsg.EstimateRetainedBytes(huge); w <= ipCacheMaxEntryBytes {
		t.Skipf("fixture weight %d did not exceed the per-entry ceiling %d", w, ipCacheMaxEntryBytes)
	}

	c.Add("huge", huge)

	if _, ok := c.Get("huge"); ok {
		t.Error("oversized entry was cached; it should have been rejected")
	}
	stats := c.Stats()
	if stats.Rejected != 1 {
		t.Errorf("Rejected = %d, want 1", stats.Rejected)
	}
	if stats.RetainedBytes != beforeBytes {
		t.Errorf("RetainedBytes = %d after rejected Add, want %d (unchanged)",
			stats.RetainedBytes, beforeBytes)
	}
	// The pre-existing small entry must survive a rejected oversized Add.
	if _, ok := c.Get("small"); !ok {
		t.Error("rejected oversized entry evicted an existing entry")
	}
}

// The whole point of the byte bound: an entry cap large enough to hold many
// heavy entries must not let retained bytes run past the budget.
func TestInsertionPointCacheEnforcesByteBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("fills the cache byte budget; skipped under -short")
	}

	// Entry cap far larger than the byte budget allows, so bytes are the binding
	// limit — the configuration the auto-sizing path can produce (25,000 entries).
	c := NewInsertionPointCache(25000)

	heavy := mustPoints(t, nestedRequest(1500))
	weight := httpmsg.EstimateRetainedBytes(heavy)
	if weight <= 0 {
		t.Fatal("fixture produced a zero-weight entry")
	}

	// Add enough entries to exceed the budget several times over. The same slice
	// is reused under distinct keys: the cache stores it by reference and charges
	// the same weight either way, so re-parsing the fixture per iteration would
	// only make the test slower.
	needed := (ipCacheMaxBytes / weight) * 3
	if needed < 4 {
		needed = 4
	}
	for i := 0; i < needed; i++ {
		c.Add(fmt.Sprintf("k%d", i), heavy)
	}

	stats := c.Stats()
	t.Logf("entries=%d retained=%.1f MiB budget=%.1f MiB evictions=%d (added %d entries of %.2f MiB)",
		stats.Entries, float64(stats.RetainedBytes)/(1<<20), float64(ipCacheMaxBytes)/(1<<20),
		stats.Evictions, needed, float64(weight)/(1<<20))

	if stats.RetainedBytes > ipCacheMaxBytes {
		t.Errorf("retained bytes = %d, over the %d budget", stats.RetainedBytes, ipCacheMaxBytes)
	}
	if stats.Entries >= needed {
		t.Errorf("Entries = %d after adding %d heavy entries; the byte budget never bound", stats.Entries, needed)
	}
	if stats.Evictions == 0 {
		t.Error("Evictions = 0; byte-budget evictions were not counted")
	}
}

// The byte counter and the LRU are updated together under one mutex, including
// from the eviction callback. Run under -race.
func TestInsertionPointCacheConcurrentAccess(t *testing.T) {
	c := NewInsertionPointCache(32)
	pts := mustPoints(t, nestedRequest(10))

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				key := fmt.Sprintf("k%d", (w*100+i)%64)
				c.Add(key, pts)
				c.Get(key)
				c.Stats()
			}
		}(w)
	}
	wg.Wait()

	stats := c.Stats()
	if stats.Entries > 32 {
		t.Errorf("Entries = %d, over the 32 entry cap", stats.Entries)
	}
	if stats.RetainedBytes < 0 {
		t.Errorf("RetainedBytes = %d, went negative", stats.RetainedBytes)
	}
}

// A nil cache must behave as a no-op rather than panicking: executorIPProvider
// already tolerates a nil cache and falls back to computing directly.
func TestInsertionPointCacheNilReceiver(t *testing.T) {
	var c *InsertionPointCache

	if _, ok := c.Get("k"); ok {
		t.Error("nil cache reported a hit")
	}
	c.Add("k", mustPoints(t, nestedRequest(3))) // must not panic
	if stats := c.Stats(); stats.Entries != 0 {
		t.Errorf("nil cache Stats().Entries = %d, want 0", stats.Entries)
	}
}
