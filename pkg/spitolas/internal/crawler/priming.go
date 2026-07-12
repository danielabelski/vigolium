package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"go.uber.org/zap"
)

// destructivePathRe matches URL paths that commonly end a session or mutate state
// (logout, delete, unsubscribe, close-account). It mirrors the DESTRUCTIVE guard the
// DOM-side POST-form enumeration applies to form controls, so no in-page primer
// fetches such an endpoint with the browser's live credentials.
var destructivePathRe = regexp.MustCompile(`(?i)log\s*out|sign\s*out|logout|signout|delete|destroy|(?:^|[^a-z])remove|deactivate|unsubscribe|close[-_]?account|cancel[-_]?account`)

// filterDestructiveURLs returns urls with any whose path reads as destructive
// removed. A URL that fails to parse is kept — it was already same-origin-validated
// by the discovery script that produced it.
func filterDestructiveURLs(urls []string) []string {
	kept := make([]string, 0, len(urls))
	for _, raw := range urls {
		if u, err := url.Parse(raw); err == nil && destructivePathRe.MatchString(u.Path) {
			continue
		}
		kept = append(kept, raw)
	}
	return kept
}

// inPageFetchScript fetches a Go-supplied JSON array of same-origin URLs from the
// page (with credentials, following redirects) so the browser's network capture
// records each one. The %s is replaced with the JSON array. Bounded concurrency
// keeps it from flooding the target. Shared by every in-page URL primer
// (iframe sources, GET-form submits, parameterized anchor links). No backticks:
// embedded as a Go raw string.
const inPageFetchScript = `(async () => {
  const targets = %s;
  const opts = { credentials: 'include', redirect: 'follow' };
  let idx = 0, ok = 0;
  const worker = async () => {
    while (idx < targets.length) {
      const u = targets[idx++];
      try {
        const r = await fetch(u, opts);
        try { await r.arrayBuffer(); } catch (e) {}  // drain so the load finishes
        ok++;
      } catch (e) {}
    }
  };
  await Promise.all(Array.from({length: Math.min(6, targets.length)}, worker));
  return ok;
})()`

// fetchURLsInPage fetches urls in-page with bounded concurrency so the browser's
// network capture records them. The fetch eval runs on a goroutine so
// crawl-context cancellation returns promptly even if CDP is slow; the eval
// itself is bounded by iframePrimeTimeout. Best-effort: an empty list is a no-op
// and any failure is logged at debug (tagged with kind) and swallowed. This is
// the shared tail of every in-page URL primer (iframe/form/anchor).
func (c *Crawler) fetchURLsInPage(ctx context.Context, page *browser.Page, urls []string, kind string) {
	if page == nil || len(urls) == 0 || ctx.Err() != nil {
		return
	}
	// Drop destructive endpoints before priming with live credentials. Applied here
	// — the shared tail of every in-page URL primer (iframe, GET-form, anchor) — so
	// all priming paths inherit one guard instead of each script filtering its own.
	urls = filterDestructiveURLs(urls)
	if len(urls) == 0 {
		return
	}
	payload, err := json.Marshal(urls)
	if err != nil {
		return
	}
	script := fmt.Sprintf(inPageFetchScript, string(payload))

	done := make(chan struct{})
	var primed interface{}
	var evalErr error
	go func() {
		defer close(done)
		primed, evalErr = page.EvalAwait(script, iframePrimeTimeout)
	}()

	select {
	case <-ctx.Done():
		zap.L().Debug("In-page priming aborted by context", zap.String("kind", kind))
		return
	case <-done:
	}

	if evalErr != nil {
		zap.L().Debug("In-page priming failed", zap.String("kind", kind), zap.Error(evalErr))
		return
	}
	zap.L().Debug("In-page URLs primed",
		zap.String("kind", kind),
		zap.Int("fetched", len(urls)),
		zap.Any("ok", primed))
}
