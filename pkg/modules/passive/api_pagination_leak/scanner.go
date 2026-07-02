package api_pagination_leak

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// minSensitiveCount is the smallest pagination total that plausibly reveals a
// business-sensitive collection size. Standard REST envelopes on small or public
// collections (a help center with 5 categories, a blog with a dozen posts)
// expose tiny counts that disclose nothing — flagging those was the systematic
// false positive. Below this, the count is not a meaningful information exposure.
const minSensitiveCount = 1000

// paginationPattern defines a JSON field pattern that reveals record counts.
type paginationPattern struct {
	name    string
	pattern *regexp.Regexp
}

var paginationPatterns = []paginationPattern{
	// Total count fields
	{name: "total_count", pattern: regexp.MustCompile(`"total_count"\s*:\s*(\d+)`)},
	{name: "totalCount", pattern: regexp.MustCompile(`"totalCount"\s*:\s*(\d+)`)},
	{name: "total", pattern: regexp.MustCompile(`"total"\s*:\s*(\d+)`)},
	{name: "totalItems", pattern: regexp.MustCompile(`"totalItems"\s*:\s*(\d+)`)},
	{name: "total_items", pattern: regexp.MustCompile(`"total_items"\s*:\s*(\d+)`)},
	{name: "totalResults", pattern: regexp.MustCompile(`"totalResults"\s*:\s*(\d+)`)},
	{name: "total_results", pattern: regexp.MustCompile(`"total_results"\s*:\s*(\d+)`)},
	{name: "totalRecords", pattern: regexp.MustCompile(`"totalRecords"\s*:\s*(\d+)`)},
	{name: "total_records", pattern: regexp.MustCompile(`"total_records"\s*:\s*(\d+)`)},
	{name: "totalElements", pattern: regexp.MustCompile(`"totalElements"\s*:\s*(\d+)`)},
	{name: "record_count", pattern: regexp.MustCompile(`"record_count"\s*:\s*(\d+)`)},
	{name: "recordCount", pattern: regexp.MustCompile(`"recordCount"\s*:\s*(\d+)`)},
	{name: "count", pattern: regexp.MustCompile(`"count"\s*:\s*(\d+)`)},

	// Page count fields
	{name: "total_pages", pattern: regexp.MustCompile(`"total_pages"\s*:\s*(\d+)`)},
	{name: "totalPages", pattern: regexp.MustCompile(`"totalPages"\s*:\s*(\d+)`)},
	{name: "page_count", pattern: regexp.MustCompile(`"page_count"\s*:\s*(\d+)`)},
	{name: "pageCount", pattern: regexp.MustCompile(`"pageCount"\s*:\s*(\d+)`)},
	{name: "last_page", pattern: regexp.MustCompile(`"last_page"\s*:\s*(\d+)`)},
	{name: "lastPage", pattern: regexp.MustCompile(`"lastPage"\s*:\s*(\d+)`)},
	{name: "num_pages", pattern: regexp.MustCompile(`"num_pages"\s*:\s*(\d+)`)},
}

// contextPatterns help confirm this is actually a paginated API response.
// Deliberately excludes the bare `"next"`/`"previous"` tokens: those are common
// navigation labels (menus, GraphQL relay edges, carousels) and a stray one
// alongside a generic `"count"` produced false positives. The pagination-
// specific variants (`"next_page"`, `"next_cursor"`, ...) are kept.
var contextPatterns = []string{
	`"page"`, `"per_page"`, `"perPage"`, `"page_size"`, `"pageSize"`,
	`"limit"`, `"offset"`, `"cursor"`, `"next_page"`, `"nextPage"`,
	`"next_cursor"`, `"nextCursor"`, `"has_more"`, `"hasMore"`,
	`"has_next"`, `"hasNext"`,
}

// Module implements the API Pagination Leak passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new API Pagination Leak module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_api_pagination_leak"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes JSON responses for pagination metadata leaks.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	if ctx.Response() == nil {
		return nil, nil
	}
	// A WAF/CDN edge block's JSON error body is the edge talking, not the
	// application — pagination-shaped fields in it are not an app leak.
	if modkit.IsEdgeBlockedResponse(ctx.Response()) {
		return nil, nil
	}

	// Only inspect JSON responses
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "json") {
		return nil, nil
	}

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if body == "" {
		return nil, nil
	}

	// Check for pagination fields, tracking the largest count value seen.
	var matches []string
	var maxVal int64
	for _, pat := range paginationPatterns {
		if m := pat.pattern.FindStringSubmatch(body); len(m) > 1 {
			matches = append(matches, fmt.Sprintf("%s = %s", pat.name, m[1]))
			if v, err := strconv.ParseInt(m[1], 10, 64); err == nil {
				if v > maxVal {
					maxVal = v
				}
			} else {
				// Digits that overflow int64 are, definitionally, a huge collection.
				maxVal = math.MaxInt64
			}
		}
	}

	if len(matches) == 0 {
		return nil, nil
	}

	// A count is only a meaningful disclosure when it reveals a genuinely large
	// collection. Tiny totals (a public help center's 5 categories, one page of
	// results) expose nothing sensitive, so suppress them entirely.
	if maxVal < minSensitiveCount {
		return nil, nil
	}

	// Require at least TWO distinct context patterns to confirm this is genuinely
	// a paginated response. A single generic count field plus one loose token
	// (e.g. a lone `"limit"` or `"cursor"`) is too weak — real pagination
	// envelopes carry multiple markers (page + per_page, limit + offset, ...).
	contextHits := 0
	for _, cp := range contextPatterns {
		if strings.Contains(body, cp) {
			contextHits++
			if contextHits >= 2 {
				break
			}
		}
	}
	if contextHits < 2 {
		return nil, nil
	}

	extracted := make([]string, 0, len(matches))
	for _, match := range matches {
		extracted = append(extracted, fmt.Sprintf("Pagination field: %s", match))
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "API Pagination Metadata Exposed",
				Description: fmt.Sprintf("API response at %s exposes pagination metadata revealing total record counts", urlx.String()),
			},
		},
	}, nil
}
