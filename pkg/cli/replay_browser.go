package cli

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// browserSessionHeaders lists the request headers carried into a browser
// navigation so the retrieval runs under the captured session. Everything else
// is dropped: a browser sets its own transport headers, and forwarding the
// original Accept/Content-Length would fight the navigation.
var browserSessionHeaders = []string{"Authorization", "Cookie", "User-Agent"}

// browserReplaySummary is the browser path's stand-in for replay.Result.
//
// A browser navigation exposes no status code and no response body (see
// spitolas.ProbeResult), so there is nothing to hash, measure, or diff against
// the stored baseline. Rather than synthesize a hollow replay.Summary whose
// zero-valued status and length would read as a real comparison, browser runs
// report what a navigation actually observes and leave replayOutput.Result nil.
type browserReplaySummary struct {
	RequestedURL string   `json:"requested_url"`
	FinalURL     string   `json:"final_url,omitempty"`
	Title        string   `json:"title,omitempty"`
	Dialogs      []string `json:"dialogs,omitempty"`

	// OriginalMethod is set only when the record's method was not GET, since a
	// navigation can only issue a GET. Carrying the method (rather than a
	// rendered warning) keeps the phrasing out of the JSON contract and lets a
	// consumer see which method was dropped.
	OriginalMethod string `json:"original_method,omitempty"`
}

// browserReplaySource loads src's URL in a real browser routed through --proxy,
// so an intercepting proxy captures genuine browser traffic — real TLS
// fingerprint, JS execution, and subresource loads.
//
// Only the URL is replayed: a browser navigation is a GET, so a non-GET
// record's method and body are not reproduced. The header overlay (-H,
// --auth-session) is applied over the record's own session headers, which is
// how a browser replay runs as a different user.
func browserReplaySource(ctx context.Context, src *replaySource, overlay map[string]string) (*browserReplaySummary, error) {
	if src.URL == "" {
		return nil, fmt.Errorf("no URL to load in the browser")
	}

	method, headers := browserReplayRequest(src.BaselineRequest)
	// -H / --auth-session win over the record's stored session headers so
	// `--with-browser -H 'Cookie: ...'` genuinely re-browses as someone else.
	if len(overlay) > 0 {
		if headers == nil {
			headers = make(map[string]string, len(overlay))
		}
		maps.Copy(headers, overlay)
	}

	res, err := spitolas.ProbeURL(ctx, spitolas.ProbeConfig{
		URL:      src.URL,
		ProxyURL: globalProxy,
		// The point of browser replay is to feed an intercepting proxy, so
		// route loopback targets through it too (Chrome bypasses them by default).
		ProxyAllowLoopback: true,
		Headers:            headers,
		NavTimeout:         replayTimeout,
	})
	if err != nil {
		return nil, err
	}

	out := &browserReplaySummary{RequestedURL: src.URL}
	if method != "" && method != http.MethodGet {
		out.OriginalMethod = method
	}
	if res != nil {
		if res.FinalURL != src.URL {
			out.FinalURL = res.FinalURL
		}
		out.Title = res.Title
		for _, d := range res.Dialogs {
			out.Dialogs = append(out.Dialogs, fmt.Sprintf("%s: %s", d.Type, d.Message))
		}
	}
	return out, nil
}

// browserReplayRequest reads the request method and the session-bearing headers
// off a raw request. Both come from one httpmsg.NewHttpRequest — a wrapper that
// parses the header block in place, with no string copy of the body and no URL
// resolution, unlike ParseRawRequestWithURL. Header lookups are
// case-insensitive, because stored header casing varies (HTTP/2 lowercases).
func browserReplayRequest(rawRequest []byte) (method string, headers map[string]string) {
	if len(rawRequest) == 0 {
		return "", nil
	}
	req := httpmsg.NewHttpRequest(rawRequest)
	if req == nil {
		return "", nil
	}

	out := map[string]string{}
	for _, name := range browserSessionHeaders {
		if v := req.Header(name); v != "" {
			out[name] = v
		}
	}
	if len(out) == 0 {
		out = nil
	}
	return strings.ToUpper(req.Method()), out
}

// emitBrowserReplayPretty renders one browser navigation to w. There is no
// baseline-vs-replay table to print — see browserReplaySummary. The shared
// source/target preamble is written by the caller (emitReplayPretty).
func emitBrowserReplayPretty(w io.Writer, out *replayOutput) error {
	b := out.Browser
	if b == nil {
		return fmt.Errorf("no browser result")
	}
	if b.OriginalMethod != "" {
		_, _ = fmt.Fprintf(w, "  %s browser replay issues a GET navigation; original %s method/body not reproduced\n",
			terminal.WarnPrefix(), b.OriginalMethod)
	}
	if b.FinalURL != "" {
		_, _ = fmt.Fprintf(w, "  %s redirected to %s\n", terminal.InfoSymbol(), b.FinalURL)
	}
	if b.Title != "" {
		_, _ = fmt.Fprintf(w, "  title: %s\n", clicommon.Truncate(b.Title, 60))
	}
	for _, d := range b.Dialogs {
		_, _ = fmt.Fprintf(w, "  %s JS dialog fired (%s)\n", terminal.WarnPrefix(), clicommon.Truncate(d, 80))
	}
	return nil
}
