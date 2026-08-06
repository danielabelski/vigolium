package crawler

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"go.uber.org/zap"
)

// pageStateScript reports the page's URL and whether it still looks mid-render,
// in ONE round-trip. Both values are needed on every executed action, and
// location.href is already in-page, so asking for them separately would double
// the CDP traffic on the crawler's hottest path.
//
// "Busy" means the document has not finished loading, a region is explicitly
// marked aria-busy, or a VISIBLE spinner / skeleton / progressbar is on screen.
// Frameworks render one of those while a route's data is in flight, so it is the
// cheapest reliable "this DOM is not final yet" signal short of instrumenting
// fetch.
//
// Visibility is required deliberately: apps ship spinner markup that stays in
// the DOM permanently with display:none, and treating that as busy would make
// every state pay the deep settle. checkVisibility does that test inside the
// engine; the rect+style fallback covers engines without it. Returns JSON
// pageState. No backticks: embedded as a Go raw string.
const pageStateScript = `(() => {
  const out = {url: '', busy: false};
  try { out.url = location.href; } catch (e) {}
  try {
    if (document.readyState !== 'complete') { out.busy = true; return JSON.stringify(out); }
    if (document.querySelector('[aria-busy="true"]')) { out.busy = true; return JSON.stringify(out); }
    const SEL = '[class*="spinner" i],[class*="skeleton" i],[class*="loading" i],' +
      '[class*="loader" i],[data-loading],[role="progressbar"]';
    let els; try { els = document.querySelectorAll(SEL); } catch (e) { els = []; }
    let checked = 0;
    for (const el of els) {
      if (++checked > 40) break;
      try {
        if (el.checkVisibility) {
          if (el.checkVisibility({checkOpacity: true, checkVisibilityCSS: true})) { out.busy = true; break; }
          continue;
        }
        const r = el.getBoundingClientRect();
        if (r.width <= 0 || r.height <= 0) continue;
        const st = getComputedStyle(el);
        if (st.display === 'none' || st.visibility === 'hidden' || st.opacity === '0') continue;
        out.busy = true;
        break;
      } catch (e) {}
    }
  } catch (e) {}
  return JSON.stringify(out);
})()`

// pageState is the one-round-trip page probe used before a state snapshot.
type pageState struct {
	URL  string `json:"url"`
	Busy bool   `json:"busy"`
}

// readPageState runs the combined URL + busy probe. Any failure reports a zero
// value, so a probe error never buys the state an unnecessary multi-second
// settle.
func (c *Crawler) readPageState(page *browser.Page) pageState {
	var st pageState
	raw, err := page.Eval(pageStateScript)
	if err != nil {
		return st
	}
	s, ok := raw.(string)
	if !ok || s == "" || s == "<nil>" {
		return st
	}
	if jerr := json.Unmarshal([]byte(s), &st); jerr != nil {
		return pageState{}
	}
	return st
}

// settleBeforeCapture waits out an in-progress render BEFORE the DOM is
// snapshotted for state identity.
//
// This is separate from settleNewState, which runs after a state has been
// accepted and prepares it for extraction. The snapshot itself has to be of a
// settled DOM for a different reason: it is what decides whether the state is
// new at all. An action that starts a client route change returns while the app
// is still showing the previous route's skeleton, so an immediate snapshot
// compares as a duplicate of the current state and the route is dropped outright
// — the crawler never reaches the point where the later settle would have run.
// A stale snapshot also becomes the state's stored identity, so two genuinely
// different routes captured mid-spinner can collapse into one.
//
// The settle is expensive (a network-idle wait plus a DOM-quiescence wait, both
// with a floor of one poll window) and this runs on every executed action, so it
// is gated: it only happens when the action moved the URL or the page reports
// itself busy. previousURL == "" means the caller has just navigated
// deliberately and does not want the URL compare — the answer would be a
// foregone "yes", which would make the gate unconditional. Those callers are
// decided by the busy probe alone.
//
// Reports whether it settled, so a caller that settles again shortly afterwards
// can skip the repeat.
func (c *Crawler) settleBeforeCapture(ctx context.Context, page *browser.Page, previousURL string) bool {
	if page == nil || c.config == nil || ctx.Err() != nil {
		return false
	}

	st := c.readPageState(page)
	navigated := previousURL != "" && st.URL != "" && !sameDocumentURL(st.URL, previousURL)

	if !navigated && !st.Busy {
		return false
	}

	zap.L().Debug("Settling page before state capture",
		zap.Bool("navigated", navigated), zap.Bool("busy", st.Busy),
		zap.String("previous_url", previousURL))
	c.settleSPA(ctx, page)
	return true
}

// evalAwaitCtx runs an awaited in-page script under the crawl context.
//
// page.EvalAwait is bounded by its own timeout but is not cancellable, so a slow
// CDP round-trip would otherwise outlive a cancelled crawl. Running it on a
// goroutine and selecting on ctx lets the caller return promptly; the eval is
// abandoned, still bounded by timeout. ok is false when the context won the race
// or the eval errored, so callers get one condition to check instead of two.
func evalAwaitCtx(ctx context.Context, page *browser.Page, script string, timeout time.Duration, what string) (interface{}, bool) {
	done := make(chan struct{})
	var result interface{}
	var evalErr error
	go func() {
		defer close(done)
		result, evalErr = page.EvalAwait(script, timeout)
	}()

	select {
	case <-ctx.Done():
		zap.L().Debug("In-page eval aborted by context", zap.String("what", what))
		return nil, false
	case <-done:
	}

	if evalErr != nil {
		zap.L().Debug("In-page eval failed", zap.String("what", what), zap.Error(evalErr))
		return nil, false
	}
	return result, true
}

// sameDocumentURL reports whether two URLs address the same application state
// for the purposes of "did this action navigate". A trailing empty fragment is
// ignored ("/app" and "/app#" are the same view) but a non-empty fragment is
// significant, because a hash router uses it to express the route.
func sameDocumentURL(a, b string) bool {
	return strings.TrimSuffix(a, "#") == strings.TrimSuffix(b, "#")
}
