package core

import (
	"context"
	"sync"

	"github.com/sourcegraph/conc"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

func (e *Executor) runActivePerHost(ctx context.Context, reqClient *http.Requester, item *httpmsg.HttpRequestResponse, filter *moduleFilter, elig *requestEligibility, g *conc.WaitGroup) {
	if len(e.perHostActive) == 0 {
		return
	}

	origin := originKeyFromItem(item)

	for _, module := range e.perHostActive {
		if !filter.allows(module.ID()) {
			continue
		}
		if !e.passesTechFilter(module, item) {
			continue
		}
		e.moduleMetrics.MarkConsidered(module.ID())
		if !activeModuleCanProcess(module, item, elig) {
			continue
		}

		// Claim this (module, origin) pair — skip if another worker already claimed
		// it. ContainsOrAdd is atomic (single lock) so two concurrent workers
		// can't both win the claim; ok==true means the pair was already claimed.
		claimKey := hostClaimKey{moduleID: module.ID(), origin: origin}
		if ok, _ := e.caches.perHostActiveClaimed.ContainsOrAdd(claimKey, struct{}{}); ok {
			continue
		}

		mod := module // capture loop variable
		e.goActiveTask(ctx, g, func(releaseSlot func()) {
			results, completed := e.runActiveWithTimeout(ctx,
				func(runCtx context.Context) ([]*output.ResultEvent, error) {
					if contextual, ok := mod.(modules.ContextualActiveModule); ok {
						return contextual.ScanPerHostContext(runCtx, item, reqClient, e.scanCtx)
					}
					return mod.ScanPerHost(item, reqClient, e.scanCtx)
				},
				mod, item, releaseSlot, 0)
			if completed && len(results) > 0 {
				e.processResults(ctx, results, mod, item)
			}
		})
	}
}

func (e *Executor) runActivePerRequest(ctx context.Context, reqClient *http.Requester, item *httpmsg.HttpRequestResponse, filter *moduleFilter, elig *requestEligibility, g *conc.WaitGroup) {
	if len(e.perRequestActive) == 0 {
		return
	}

	// A ScanPerRequest module loops over every insertion point in one call, so its
	// timeout is scaled by the point count (see runActiveWithTimeout). Compute it
	// once per item — the count is shared across all per-request modules.
	workUnits := e.itemInsertionPointCount(item)

	for _, module := range e.perRequestActive {
		if !filter.allows(module.ID()) {
			continue
		}
		if !e.passesTechFilter(module, item) {
			continue
		}
		e.moduleMetrics.MarkConsidered(module.ID())
		if !activeModuleCanProcess(module, item, elig) {
			continue
		}

		mod := module // capture loop variable
		e.goActiveTask(ctx, g, func(releaseSlot func()) {
			results, completed := e.runActiveWithTimeout(ctx,
				func(runCtx context.Context) ([]*output.ResultEvent, error) {
					if contextual, ok := mod.(modules.ContextualActiveModule); ok {
						return contextual.ScanPerRequestContext(runCtx, item, reqClient, e.scanCtx)
					}
					return mod.ScanPerRequest(item, reqClient, e.scanCtx)
				},
				mod, item, releaseSlot, workUnits)
			if completed && len(results) > 0 {
				e.processResults(ctx, results, mod, item)
			}
		})
	}
}

// itemInsertionPointCount returns the number of insertion points a whole-request
// module will cover for item, used to scale that module's per-module timeout. It
// goes through the shared insertion-point provider, which hits/populates the same
// ipCache the per-insertion-point stage uses, so the request is parsed at most once.
// Returns 0 when the request is empty or unparseable, leaving the base timeout unscaled.
func (e *Executor) itemInsertionPointCount(item *httpmsg.HttpRequestResponse) int {
	if item == nil || item.Request() == nil || len(item.Request().Raw()) == 0 {
		return 0
	}
	pts, err := e.scanCtx.GetInsertionPoints(item.Request().Raw(), item.Request().ID(), true)
	if err != nil {
		return 0
	}
	return len(pts)
}

func (e *Executor) runActivePerInsertionPoint(ctx context.Context, reqClient *http.Requester, item *httpmsg.HttpRequestResponse, filter *moduleFilter, elig *requestEligibility, g *conc.WaitGroup) {
	if len(e.perIPActive) == 0 {
		return
	}

	if item.Request() == nil || len(item.Request().Raw()) == 0 {
		return
	}

	// Cache lookup by request hash (same SHA-256 used by HttpRequest.ID())
	key := item.Request().ID()
	allPoints, ok := e.caches.ipCache.Get(key)
	if !ok {
		var err error
		allPoints, err = httpmsg.CreateAllInsertionPoints(item.Request().Raw(), true)
		if err != nil {
			zap.L().Debug("Failed to create insertion points", zap.Error(err))
			return
		}
		e.caches.ipCache.Add(key, allPoints)
	}

	// Pre-compute host+path for cross-module finding dedup
	itemHostPath := ""
	if e.scanCtx != nil && e.scanCtx.ParamFindings != nil {
		itemHostPath = paramFindingLocationKeyFromItem(item)
	}

	// Module-outer, insertion-point-inner: the module-level gates
	// (filter / tech-filter / MarkConsidered / CanProcess) don't depend on the
	// insertion point, so evaluate them once per module rather than once per
	// (module × insertion-point). Only the type check and the cross-module
	// vuln-class dedup are point-dependent and stay in the inner loop.
	for _, module := range e.perIPActive {
		if !filter.allows(module.ID()) {
			continue
		}
		if !e.passesTechFilter(module, item) {
			continue
		}
		e.moduleMetrics.MarkConsidered(module.ID())
		if !activeModuleCanProcess(module, item, elig) {
			continue
		}

		allowedTypes := module.AllowedInsertionPointTypes()
		vc, isVulnClassifier := module.(modules.VulnClassifier)
		dedupByParam := isVulnClassifier && e.scanCtx != nil && e.scanCtx.ParamFindings != nil

		for _, ip := range allPoints {
			if !allowedTypes.Contains(ip.Type()) {
				continue
			}

			// Cross-module dedup: skip if another module already found this vuln
			// class on this param.
			if dedupByParam && e.scanCtx.ParamFindings.HasFinding(itemHostPath, ip.Name(), vc.VulnClass()) {
				continue
			}

			mod, pt := module, ip // capture loop variables
			e.goActiveTask(ctx, g, func(releaseSlot func()) {
				results, completed := e.runActiveWithTimeout(ctx,
					func(runCtx context.Context) ([]*output.ResultEvent, error) {
						if contextual, ok := mod.(modules.ContextualActiveModule); ok {
							return contextual.ScanPerInsertionPointContext(runCtx, item, pt, reqClient, e.scanCtx)
						}
						return mod.ScanPerInsertionPoint(item, pt, reqClient, e.scanCtx)
					},
					mod, item, releaseSlot, 0)
				if completed && len(results) > 0 {
					e.processResults(ctx, results, mod, item)
				}
			})
		}
	}
}

// goActiveTask runs fn on the shared WaitGroup, gated by the active-task
// semaphore. Semaphore acquisition is context-aware: if ctx is cancelled (scan
// shutdown or max-duration timeout) while every slot is occupied, the task is
// abandoned instead of blocking the dispatcher until a slot frees up.
//
// Slot release is NOT tied to fn returning. fn hands releaseSlot to
// runActiveWithTimeout, which frees the slot only when the module's real work
// finishes — even if that work outlives a per-module timeout the wrapper gave up
// waiting for. Releasing on fn return instead would let the pool admit
// replacement tasks while abandoned scans still hold connections, so the
// concurrency cap would understate true in-flight work. sync.Once keeps the
// release idempotent so a stray double-call can never over-drain the semaphore.
func (e *Executor) goActiveTask(ctx context.Context, g *conc.WaitGroup, fn func(releaseSlot func())) {
	select {
	case e.pool.activeTaskSem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	var once sync.Once
	releaseSlot := func() { once.Do(func() { <-e.pool.activeTaskSem }) }
	g.Go(func() {
		fn(releaseSlot)
	})
}
