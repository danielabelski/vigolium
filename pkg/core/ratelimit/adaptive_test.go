package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"
)

// currentLimit reads a host's adaptive limit (0 if the host/entry isn't adaptive).
func (h *HostRateLimiter) currentLimit(host string) int {
	shard := h.shardFor(host)
	shard.mu.RLock()
	entry, ok := shard.hosts[host]
	shard.mu.RUnlock()
	if !ok || entry.tokens == nil {
		return 0
	}
	return int(entry.limit.Load())
}

func TestAdaptive_StartsAtMaxPerHost(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 8, Adaptive: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	h.Release(host)

	if got := h.currentLimit(host); got != 8 {
		t.Fatalf("adaptive host should start at MaxPerHost=8, got %d", got)
	}
	// Default ceiling = MaxPerHost; floor = max(1, 8/10) = 1.
	if h.ceilingPerHost != 8 || h.minPerHost != 1 {
		t.Fatalf("defaults: ceiling=%d min=%d, want 8/1", h.ceilingPerHost, h.minPerHost)
	}
}

func TestAdaptive_RespectsCurrentLimit(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 2, Adaptive: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	// Acquire both slots; a third must block (the resizable pool caps at the limit).
	for i := 0; i < 2; i++ {
		if err := h.Acquire(context.Background(), host); err != nil {
			t.Fatalf("Acquire #%d: %v", i, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := h.Acquire(ctx, host); err == nil {
		t.Fatal("expected Acquire to block past the current adaptive limit")
	}
	h.Release(host)
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("Acquire after Release: %v", err)
	}
}

func TestAdaptive_BacksOffOnDistress(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 16, Adaptive: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	// Materialize the entry.
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	h.Release(host)

	// A 429 halves the limit (16 -> 8).
	h.Feedback(host, 429, nil, false)
	if got := h.currentLimit(host); got != 8 {
		t.Fatalf("after 429, limit = %d, want 8", got)
	}

	// A second distress within the cooldown is coalesced (no further drop).
	h.Feedback(host, 503, nil, false)
	if got := h.currentLimit(host); got != 8 {
		t.Fatalf("distress within cooldown should not drop again, got %d", got)
	}

	// A transport error (timeout) also counts as distress after the cooldown.
	time.Sleep(decreaseCooldown + 20*time.Millisecond)
	h.Feedback(host, 0, errors.New("dial tcp: i/o timeout"), false)
	if got := h.currentLimit(host); got != 4 {
		t.Fatalf("after timeout, limit = %d, want 4", got)
	}
}

func TestAdaptive_BackoffFlooredAtMin(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 4, MinPerHost: 2, Adaptive: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	_ = h.Acquire(context.Background(), host)
	h.Release(host)

	for i := 0; i < 5; i++ {
		h.Feedback(host, 503, nil, false)
		time.Sleep(decreaseCooldown + 10*time.Millisecond)
	}
	if got := h.currentLimit(host); got != 2 {
		t.Fatalf("limit should floor at MinPerHost=2, got %d", got)
	}
}

func TestAdaptive_RecoversWhenHealthy(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 8, Adaptive: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	_ = h.Acquire(context.Background(), host)
	h.Release(host)

	// Drop to 4.
	h.Feedback(host, 429, nil, false)
	if got := h.currentLimit(host); got != 4 {
		t.Fatalf("setup: expected 4, got %d", got)
	}

	// Feed plenty of healthy completions; the limit ramps back toward the ceiling
	// (one +1 step per increaseAfterHealthy+limit clean responses).
	for i := 0; i < 500; i++ {
		h.Feedback(host, 200, nil, false)
	}
	if got := h.currentLimit(host); got <= 4 {
		t.Fatalf("expected ramp-up above 4 after healthy traffic, got %d", got)
	}
	if got := h.currentLimit(host); got > 8 {
		t.Fatalf("ramp-up must not exceed the ceiling 8, got %d", got)
	}
}

func TestAdaptive_ContextCancelNotDistress(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 8, Adaptive: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	_ = h.Acquire(context.Background(), host)
	h.Release(host)

	h.Feedback(host, 0, context.Canceled, false)
	h.Feedback(host, 0, context.DeadlineExceeded, false)
	if got := h.currentLimit(host); got != 8 {
		t.Fatalf("context cancellation must not back off; got %d, want 8", got)
	}
}

func TestAdaptive_ConcurrentAcquireReleaseFeedback(t *testing.T) {
	// Hammer one host with concurrent acquires/releases while feedback resizes the
	// pool, then verify the invariant once quiescent: available tokens + zero
	// in-flight == current limit (no leaked or duplicated tokens).
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 12, MinPerHost: 2, Adaptive: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "stress.example"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	worker := func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			actx, acancel := context.WithTimeout(ctx, 100*time.Millisecond)
			if err := h.Acquire(actx, host); err == nil {
				h.Release(host)
			}
			acancel()
		}
	}
	for i := 0; i < 24; i++ {
		go worker()
	}
	// Drive resizes from multiple goroutines.
	feeder := func(status int) {
		for {
			select {
			case <-done:
				return
			default:
			}
			h.Feedback(host, status, nil, false)
			time.Sleep(time.Millisecond)
		}
	}
	go feeder(503) // back-off pressure
	go feeder(200) // recovery pressure

	time.Sleep(1 * time.Second)
	close(done)
	time.Sleep(150 * time.Millisecond) // let workers drain

	// Quiescent invariant: all tokens returned, none in flight.
	shard := h.shardFor(host)
	shard.mu.RLock()
	entry := shard.hosts[host]
	shard.mu.RUnlock()
	if entry == nil {
		t.Fatal("entry vanished")
	}
	if inflight := entry.inflight.Load(); inflight != 0 {
		t.Fatalf("inflight should be 0 at rest, got %d", inflight)
	}
	limit := int(entry.limit.Load())
	avail := len(entry.tokens)
	if avail != limit {
		t.Fatalf("token-pool invariant broken: available=%d limit=%d (debt=%d)", avail, limit, entry.debt.Load())
	}
	if limit < h.minPerHost || limit > h.ceilingPerHost {
		t.Fatalf("limit %d out of bounds [%d,%d]", limit, h.minPerHost, h.ceilingPerHost)
	}
}

func TestStaticMode_NoFeedbackEffect(t *testing.T) {
	// Feedback is a no-op in static mode and must not panic or change behavior.
	h := NewHostRateLimiter(HostRateLimiterConfig{MaxPerHost: 4, EvictInterval: time.Hour})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	h.Feedback(host, 429, nil, false) // no-op
	if got := h.currentLimit(host); got != 0 {
		t.Fatalf("static entry has no adaptive limit, got %d", got)
	}
	h.Release(host)
}

func TestWafAutoArm_StaysPinnedUntilBlock(t *testing.T) {
	// WAF-auto-arm mode must behave exactly like the static limiter until a WAF block
	// arms the host: ordinary 429/5xx/transport distress does NOT throttle it.
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 16, WafAutoArm: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	h.Release(host)

	// Pinned at MaxPerHost from the start (adaptive entry, not a static semaphore).
	if got := h.currentLimit(host); got != 16 {
		t.Fatalf("unarmed WAF-auto-arm host should be pinned at MaxPerHost=16, got %d", got)
	}
	// A burst of ordinary distress (429/503/timeout) must not change the limit while
	// the host is unarmed — that's the "no behavior change for non-WAF targets" rule.
	for i := 0; i < 5; i++ {
		time.Sleep(decreaseCooldown + 5*time.Millisecond)
		h.Feedback(host, 429, nil, false)
		h.Feedback(host, 503, nil, false)
		h.Feedback(host, 0, errors.New("dial tcp: i/o timeout"), false)
	}
	if got := h.currentLimit(host); got != 16 {
		t.Fatalf("unarmed host throttled by ordinary distress: limit=%d, want 16", got)
	}
}

func TestWafAutoArm_ArmsAndBacksOffOnWAFBlock(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 16, WafAutoArm: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	h.Release(host)

	// A confirmed WAF block (wafBlocked=true) arms the host and halves the limit.
	h.Feedback(host, 403, nil, true)
	if got := h.currentLimit(host); got != 8 {
		t.Fatalf("WAF block should arm + halve 16→8, got %d", got)
	}
	// Now armed, an ordinary 429 backs off further (past the cooldown).
	time.Sleep(decreaseCooldown + 5*time.Millisecond)
	h.Feedback(host, 429, nil, false)
	if got := h.currentLimit(host); got != 4 {
		t.Fatalf("armed host should back off 8→4 on 429, got %d", got)
	}
	// Healthy completions ramp it back up toward the MaxPerHost ceiling.
	for i := 0; i < 200; i++ {
		h.Feedback(host, 200, nil, false)
	}
	if got := h.currentLimit(host); got <= 4 || got > 16 {
		t.Fatalf("armed host should recover toward ceiling 16, got %d", got)
	}
}

func TestPreArm_DropsToStartThenRamps(t *testing.T) {
	// A proactive pre-arm (edge fingerprinted, no block yet) must arm the host and
	// drop it to preArmStart (MaxPerHost/4) so the active phase paces from the first
	// request, then ramp back toward the ceiling on healthy completions.
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 16, WafAutoArm: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	if !h.PreArmable() {
		t.Fatal("a WafAutoArm limiter must report PreArmable")
	}

	const host = "edge.example"

	// The once-per-host operator notice fires on the arming call, carrying the drop.
	var notices []PreArmNotice
	h.SetPreArmNotifier(func(n PreArmNotice) { notices = append(notices, n) })

	h.PreArm(host, "cloudfront")
	if got := h.currentLimit(host); got != 4 {
		t.Fatalf("pre-arm should drop 16→4 (MaxPerHost/4), got %d", got)
	}
	if len(notices) != 1 {
		t.Fatalf("want exactly 1 pre-arm notice, got %d", len(notices))
	}
	if n := notices[0]; n.Host != host || n.Vendor != "cloudfront" || n.From != 16 || n.Start != 4 {
		t.Fatalf("notice = %+v, want host=%s vendor=cloudfront from=16 start=4", n, host)
	}

	// A second fingerprint on the same host must not re-arm or re-notify.
	h.PreArm(host, "cloudfront")
	if len(notices) != 1 {
		t.Fatalf("pre-arm notice must fire once per host, got %d", len(notices))
	}

	// A healthy run ramps the paced host back up toward the MaxPerHost ceiling.
	for i := 0; i < 400; i++ {
		h.Feedback(host, 200, nil, false)
	}
	if got := h.currentLimit(host); got <= 4 || got > 16 {
		t.Fatalf("pre-armed host should ramp back toward ceiling 16, got %d", got)
	}
}

func TestPreArm_LeavesBlockArmedHostAlone(t *testing.T) {
	// A real WAF block backs a host off toward the floor; a later edge fingerprint
	// must NOT bump that host back up to preArmStart. The arm-once guard keeps the
	// lower (block-driven) limit.
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 16, MinPerHost: 2, WafAutoArm: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "edge.example"
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	h.Release(host)

	for i := 0; i < 6; i++ {
		time.Sleep(decreaseCooldown + 5*time.Millisecond)
		h.Feedback(host, 403, nil, true)
	}
	blocked := h.currentLimit(host)
	if blocked >= 16 || blocked > 4 {
		t.Fatalf("repeated blocks should back off below preArmStart(4), got %d", blocked)
	}

	h.PreArm(host, "cloudfront") // already armed — must be a no-op, not a bump up to 4
	if got := h.currentLimit(host); got != blocked {
		t.Fatalf("PreArm bumped a block-armed host: %d → %d", blocked, got)
	}
}

func TestPreArm_DisabledKeepsReactiveBackoff(t *testing.T) {
	// --no-waf-pacing (DisablePreArm) turns off the proactive pre-arm but must
	// leave the reactive WAF-block back-off intact.
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 16, WafAutoArm: true, DisablePreArm: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	if h.PreArmable() {
		t.Fatal("DisablePreArm must make the limiter non-PreArmable")
	}

	const host = "edge.example"
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	h.Release(host)

	var notices []PreArmNotice
	h.SetPreArmNotifier(func(n PreArmNotice) { notices = append(notices, n) })

	h.PreArm(host, "cloudfront") // must be a no-op — no throttle, no notice
	if got := h.currentLimit(host); got != 16 {
		t.Fatalf("proactive pre-arm should be disabled (pinned at 16), got %d", got)
	}
	if len(notices) != 0 {
		t.Fatalf("disabled pre-arm must not notify, got %d", len(notices))
	}

	// Reactive path still works: a confirmed WAF block arms + halves.
	h.Feedback(host, 403, nil, true)
	if got := h.currentLimit(host); got != 8 {
		t.Fatalf("reactive WAF back-off must still apply (16→8), got %d", got)
	}
}

func TestPreArm_NoOpInStaticMode(t *testing.T) {
	// The static limiter has no adaptive token pool, so PreArm is a no-op and never
	// throttles — a scan without WafAutoArm/Adaptive is unaffected.
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 16, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	if h.PreArmable() {
		t.Fatal("a static limiter must not report PreArmable")
	}
	const host = "edge.example"
	h.PreArm(host, "cloudfront") // must not panic and must not create/throttle an adaptive entry

	// Full static concurrency is still available: MaxPerHost non-blocking acquires.
	for i := 0; i < 16; i++ {
		if !h.tryAcquire(host) {
			t.Fatalf("static host throttled after PreArm: slot %d unavailable", i)
		}
	}
	for i := 0; i < 16; i++ {
		h.Release(host)
	}
}
