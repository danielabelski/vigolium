package harvester

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// urlscanPageSize is how many results to request per page. urlscan caps an
// authenticated search well below the 10000 this used to ask for, and an
// over-large size is rejected outright rather than clamped.
const urlscanPageSize = 1000

type urlscanResponse struct {
	Results []urlscanResult `json:"results"`
	HasMore bool            `json:"has_more"`
}

type urlscanResult struct {
	Page urlscanPage `json:"page"`
	Task urlscanTask `json:"task"`
	// Sort is kept as raw JSON. Decoding it into `any` turns the millisecond
	// timestamp into a float64, and reformatting that number is how a
	// search_after cursor becomes a 400 — or, when the field is a string rather
	// than a number, a panic on the type assertion.
	Sort []json.RawMessage `json:"sort"`
}

type urlscanPage struct {
	URL string `json:"url"`
}

type urlscanTask struct {
	// URL is what was submitted for scanning, which can differ from the URL
	// that finally loaded after redirects.
	URL string `json:"url"`
}

const urlscanSearchURL = "https://urlscan.io/api/v1/search/"

// URLScanSource collects URLs from the URLScan.io API.
type URLScanSource struct {
	apiKey string
	client *http.Client
	// baseURL is overridable so tests can stand in for the live service, the
	// same seam CommonCrawlSource and ArquivoSource use; production callers take
	// the default.
	baseURL string
}

// NewURLScanSource creates a new URLScan.io harvester source.
// proxyURL is optional; pass "" for no proxy.
func NewURLScanSource(apiKey string, proxyURL ...string) *URLScanSource {
	var proxy string
	if len(proxyURL) > 0 {
		proxy = proxyURL[0]
	}
	return &URLScanSource{
		apiKey:  apiKey,
		client:  NewHTTPClient(60*time.Second, proxy),
		baseURL: urlscanSearchURL,
	}
}

func (s *URLScanSource) Name() string   { return "urlscan" }
func (s *URLScanSource) NeedsKey() bool { return true }

// Run fetches URLs for the domain from URLScan.io.
func (s *URLScanSource) Run(ctx context.Context, domain string) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		var searchAfter string
		// page.domain, not domain. urlscan's bare `domain:` operator matches every
		// domain a scan *contacted*, so a scan of an unrelated site that merely
		// loaded a script from this one is a hit. Those pages are then discarded
		// downstream for being out of scope, after their pagination has already
		// been paid for — and against a busy domain that is enough to hit the
		// 10000-result ceiling before the in-scope results are exhausted.
		baseURL := fmt.Sprintf("%s?q=page.domain:%s&size=%d", s.baseURL, domain, urlscanPageSize)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			apiURL := baseURL
			if searchAfter != "" {
				apiURL = fmt.Sprintf("%s&search_after=%s", apiURL, searchAfter)
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
			if err != nil {
				results <- Result{Source: s.Name(), Error: err}
				return
			}
			req.Header.Set("API-Key", s.apiKey)

			resp, err := s.client.Do(req)
			if err != nil {
				results <- Result{Source: s.Name(), Error: err}
				return
			}

			if resp.StatusCode == http.StatusTooManyRequests {
				_ = resp.Body.Close()
				results <- Result{Source: s.Name(), Error: fmt.Errorf("urlscan rate limited")}
				return
			}

			var data urlscanResponse
			if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
				_ = resp.Body.Close()
				results <- Result{Source: s.Name(), Error: err}
				return
			}
			_ = resp.Body.Close()

			if len(data.Results) == 0 {
				return
			}

			for _, r := range data.Results {
				// Both URLs are taken: the task URL is what was submitted and the
				// page URL is where it ended up, so a redirect chain contributes
				// its start as well as its destination.
				for _, candidate := range []string{r.Page.URL, r.Task.URL} {
					if candidate != "" {
						emit(ctx, results, Result{Source: s.Name(), URL: candidate})
					}
				}
			}

			// Pagination is cursor-based: the last result's sort values become the
			// search_after of the next request, preserved exactly as the server
			// sent them.
			next := urlscanCursor(data.Results[len(data.Results)-1].Sort)
			if !data.HasMore || next == "" || next == searchAfter {
				return
			}
			searchAfter = next
		}
	}()

	return results
}

// urlscanCursor joins urlscan's sort values into a search_after cursor. A string
// value arrives quoted and the cursor takes the bare text; a number is passed
// through byte for byte, because reformatting it is what turns a valid cursor
// into a rejected one.
func urlscanCursor(sort []json.RawMessage) string {
	if len(sort) == 0 {
		return ""
	}

	parts := make([]string, 0, len(sort))
	for _, raw := range sort {
		value := strings.TrimSpace(string(raw))
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		}
		parts = append(parts, value)
	}
	return strings.Join(parts, ",")
}
