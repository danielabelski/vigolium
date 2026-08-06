package dependent_response

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Body-difference thresholds: two responses are "materially different" only when
// they diverge by both an absolute and a relative margin, so timestamps / CSRF
// tokens / small dynamic fragments do not count.
const (
	minAbsoluteDelta = 100
	minRelativeDelta = 0.30
)

// dimension is one spoofable header tested by comparing two distinct values.
type dimension struct {
	header string
	valueA string
	descA  string
	valueB string // "" means the header is removed for this variant
	descB  string
}

var dimensions = []dimension{
	{
		header: "User-Agent",
		valueA: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		descA:  "a search-engine crawler User-Agent",
		valueB: "curl/8.0.1",
		descB:  "a generic client User-Agent",
	},
	{
		header: "Referer",
		valueA: "https://www.google.com/",
		descA:  "an external Referer",
		valueB: "",
		descB:  "no Referer",
	},
}

// probe is one response reduced to what the differential needs: status and body
// length. full/raw are populated only for the first (reported) fetch of a variant;
// the reproduction fetch is signature-only.
type probe struct {
	status  int
	bodyLen int
	full    string
	raw     []byte
	ok      bool
}

// Module implements the Referer/User-Agent dependent-response scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new dependent-response module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID, ModuleName, ModuleDesc, ModuleShort, ModuleConfirmation,
			ModuleSeverity, ModuleConfidence,
			modkit.ScanScopeRequest, modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("dependent_response"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess restricts to GET requests with a response (idempotent, so re-sending
// with different headers is side-effect-free) and skips media/asset URLs.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil || ctx.Response() == nil {
		return false
	}
	if !strings.EqualFold(ctx.Request().Method(), "GET") {
		return false
	}
	return true
}

// ScanPerRequest compares two values of each spoofable header, requiring each
// variant to reproduce stably before reporting a material difference.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	key := "GET|" + urlx.Host + "|" + urlx.Path
	if diskSet != nil && diskSet.IsSeen(key) {
		return nil, nil
	}

	var results []*output.ResultEvent
	for _, d := range dimensions {
		result, abort := m.testDimension(ctx, httpClient, urlx.String(), d)
		if abort {
			return results, nil
		}
		if result != nil {
			results = append(results, result)
		}
	}
	return results, nil
}

// testDimension compares the two header values, requiring each variant to reproduce
// stably (deterministic) and the two to differ materially.
func (m *Module) testDimension(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	urlStr string,
	d dimension,
) (*output.ResultEvent, bool) {
	a, aStable, abort := m.stableVariant(ctx, httpClient, d.header, d.valueA)
	if abort {
		return nil, true
	}
	b, bStable, abort := m.stableVariant(ctx, httpClient, d.header, d.valueB)
	if abort {
		return nil, true
	}
	if !aStable || !bStable || !differs(a, b) {
		return nil, false
	}

	return &output.ResultEvent{
		URL:      urlStr,
		Matched:  urlStr,
		Request:  string(a.raw),
		Response: a.full,
		AdditionalEvidence: []string{
			output.BuildEvidence(d.header+" = "+d.descB, string(b.raw), b.full),
		},
		ExtractedResults: []string{
			fmt.Sprintf("header=%s", d.header),
			fmt.Sprintf("variant_a=%q status=%d len=%d", d.valueA, a.status, a.bodyLen),
			fmt.Sprintf("variant_b=%q status=%d len=%d", d.valueB, b.status, b.bodyLen),
		},
		Info: output.Info{
			Name: ModuleName,
			Description: fmt.Sprintf(
				"The response varies with the %s header: %s produced status %d / %d bytes, while %s produced status %d / %d bytes. Each variant reproduced stably, so the difference is caused by the header, not dynamic content. Because the %s header is client-controlled, any behaviour that depends on it is spoofable.",
				d.header, d.descA, a.status, a.bodyLen, d.descB, b.status, b.bodyLen, d.header,
			),
			Severity:   ModuleSeverity,
			Confidence: ModuleConfidence,
			Tags:       ModuleTags,
		},
	}, false
}

// stableVariant fetches header=value twice and reports whether the two responses match
// (the variant is deterministic). The first fetch carries evidence (full response +
// raw request) for reporting; the reproduction fetch is signature-only. abort is true
// only when the host became unresponsive.
func (m *Module) stableVariant(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	header, value string,
) (rep probe, stableOK, abort bool) {
	p1, abort := m.fetch(ctx, httpClient, header, value, true)
	if abort {
		return probe{}, false, true
	}
	p2, abort := m.fetch(ctx, httpClient, header, value, false)
	if abort {
		return probe{}, false, true
	}
	return p1, p1.ok && p2.ok && stable(p1, p2), false
}

// fetch sends the request with the header set to value (or removed when value is ""),
// returning a compact response view. full/raw are populated only when evidence is
// true. abort is true only when the host became unresponsive.
func (m *Module) fetch(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	header, value string,
	evidence bool,
) (probe, bool) {
	raw := ctx.Request().Raw()
	var err error
	if value == "" {
		raw, err = httpmsg.RemoveHeader(raw, header)
	} else {
		raw, err = httpmsg.AddOrReplaceHeader(raw, header, value)
	}
	if err != nil {
		return probe{}, false
	}

	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, execErr := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if execErr != nil {
		if errors.Is(execErr, hosterrors.ErrUnresponsiveHost) {
			return probe{}, true
		}
		return probe{}, false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return probe{}, false
	}
	p := probe{
		status:  resp.Response().StatusCode,
		bodyLen: len(resp.Body().String()),
		ok:      true,
	}
	if evidence {
		p.full = resp.FullResponseString()
		p.raw = raw
	}
	return p, false
}

// stable reports whether two same-variant responses match (same status, no material
// body difference).
func stable(a, b probe) bool {
	return a.status == b.status && !bodyDiffers(a, b)
}

// differs reports whether two responses diverge materially — a status change or a
// substantial body-size difference.
func differs(a, b probe) bool {
	return a.status != b.status || bodyDiffers(a, b)
}

// bodyDiffers reports a substantial body-size difference by both an absolute and a
// relative margin. A size delta of 0 (identical length, hence identical enough for
// this cloaking check) is never substantial, so no body hash is needed.
func bodyDiffers(a, b probe) bool {
	diff := a.bodyLen - b.bodyLen
	if diff < 0 {
		diff = -diff
	}
	if diff <= minAbsoluteDelta {
		return false
	}
	maxLen := max(a.bodyLen, b.bodyLen)
	return maxLen > 0 && float64(diff)/float64(maxLen) >= minRelativeDelta
}
