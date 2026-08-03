package input_behavior_probe

import (
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"golang.org/x/sync/singleflight"
)

const (
	// jitterCacheSize bounds the per-endpoint jitter memo. The module instance is
	// a registry singleton that outlives any one scan (and, in server mode, any
	// one run), so this cannot be an unbounded map.
	jitterCacheSize = 4096
	// jitterTTL matches modkit's baseline TTL: the jitter is measured relative to
	// a specific cached baseline, so it must not outlive the baseline it describes.
	jitterTTL = 5 * time.Minute
)

// jitterEntry is a memoized natural tag-variance measurement for one endpoint.
type jitterEntry struct {
	value      int
	measuredAt time.Time
}

func (e jitterEntry) expired() bool { return time.Since(e.measuredAt) > jitterTTL }

// jitterCache memoizes per-endpoint tag jitter across the insertion points of a
// record.
//
// Concurrency is the point, not just reuse: the executor dispatches every
// insertion point of a record as a separate concurrent task, so a plain
// check-then-measure would have all ~20 miss at the same instant and each run its
// own control fetches — exactly the cost being removed. The singleflight group
// collapses concurrent measurements for the same endpoint into one.
type jitterCache struct {
	entries *lru.Cache[string, jitterEntry]
	flight  singleflight.Group
}

func newJitterCache() *jitterCache {
	// lru.New only errors on a non-positive size, and jitterCacheSize is a
	// positive constant, so this cannot fail.
	entries, _ := lru.New[string, jitterEntry](jitterCacheSize)
	return &jitterCache{entries: entries}
}

// key identifies the endpoint a jitter measurement belongs to. The unmodified
// raw request is what gets re-fetched, so its hash is exactly the right
// identity — every insertion point on a record shares it, and two records that
// differ in any request byte do not.
func jitterKey(ctx *httpmsg.HttpRequestResponse) string {
	if ctx == nil || ctx.Request() == nil {
		return ""
	}
	return ctx.Request().ID()
}

// get returns the memoized jitter for ctx's endpoint, calling measure at most
// once per endpoint per TTL even under concurrent callers. An unidentifiable
// request falls back to measuring directly rather than sharing a bogus key.
func (c *jitterCache) get(ctx *httpmsg.HttpRequestResponse, measure func() int) int {
	key := jitterKey(ctx)
	if key == "" {
		return measure()
	}

	if entry, ok := c.entries.Get(key); ok && !entry.expired() {
		return entry.value
	}

	v, _, _ := c.flight.Do(key, func() (any, error) {
		// Re-check inside the group: a concurrent caller may have just populated it.
		if entry, ok := c.entries.Get(key); ok && !entry.expired() {
			return entry.value, nil
		}
		measured := measure()
		c.entries.Add(key, jitterEntry{value: measured, measuredAt: time.Now()})
		return measured, nil
	})

	jitter, ok := v.(int)
	if !ok {
		return 0
	}
	return jitter
}
