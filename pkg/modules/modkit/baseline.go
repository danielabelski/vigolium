package modkit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

const baselineTTL = 5 * time.Minute

// BaselineEntry caches a clean baseline response for a given endpoint.
type BaselineEntry struct {
	Response   *httpmsg.HttpResponse
	StatusCode int
	BodyLen    int
	FetchedAt  time.Time
}

// Expired returns true if the baseline entry is older than the TTL.
func (e *BaselineEntry) Expired() bool {
	return time.Since(e.FetchedAt) > baselineTTL
}

// GetOrFetchBaseline returns a cached baseline or fetches and caches one.
// The cache key includes the effective origin, full request target, content
// type, canonical body, and an opaque authentication fingerprint. This keeps
// responses from different users or request shapes from becoming each other's
// clean control. Concurrent calls for the same key are coalesced via
// singleflight.
func (sc *ScanContext) GetOrFetchBaseline(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) (*BaselineEntry, error) {
	if sc == nil {
		return nil, fmt.Errorf("nil ScanContext")
	}
	if ctx == nil || ctx.Request() == nil || ctx.Service() == nil {
		return nil, fmt.Errorf("incomplete baseline request")
	}

	key := baselineRequestKey(ctx)

	cache := sc.getBaselineCache()
	if entry, ok := cache.Get(key); ok && !entry.Expired() {
		return entry, nil
	}

	// Use singleflight to coalesce concurrent fetches for the same endpoint.
	// This prevents duplicate HTTP requests when multiple modules request
	// the baseline for the same URL concurrently.
	result, err, _ := sc.baselineFlight.Do(key, func() (interface{}, error) {
		// Double-check cache inside singleflight (another goroutine may have populated it)
		if entry, ok := cache.Get(key); ok && !entry.Expired() {
			return entry, nil
		}

		respChain, _, err := httpClient.Execute(ctx, http.Options{})
		if err != nil {
			return nil, err
		}

		fullResp := respChain.FullResponseBytes()
		rawCopy := make([]byte, len(fullResp))
		copy(rawCopy, fullResp)
		respChain.Close()

		resp := httpmsg.NewHttpResponse(rawCopy)
		entry := &BaselineEntry{
			Response:   resp,
			StatusCode: resp.StatusCode(),
			BodyLen:    len(resp.Body()),
			FetchedAt:  time.Now(),
		}

		cache.Add(key, entry)
		return entry, nil
	})

	if err != nil {
		return nil, err
	}
	return result.(*BaselineEntry), nil
}

// baselineRequestKey intentionally returns only a digest. Request bodies,
// cookies, and authorization values must never leak into cache diagnostics.
func baselineRequestKey(ctx *httpmsg.HttpRequestResponse) string {
	if ctx == nil || ctx.Request() == nil || ctx.Service() == nil {
		return "baseline-v2:invalid"
	}

	req := ctx.Request()
	service := ctx.Service()
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(req.Header("Content-Type"), ";")[0]))
	body := canonicalBaselineBody(contentType, req.Body())

	h := sha256.New()
	for _, dimension := range []string{
		strings.ToUpper(req.Method()),
		service.Protocol(),
		service.Host(),
		strconv.Itoa(service.Port()),
		req.Path(),
		contentType,
		req.IdentityFingerprint(),
		body,
	} {
		_, _ = h.Write([]byte(strconv.Itoa(len(dimension))))
		_, _ = h.Write([]byte(":"))
		_, _ = h.Write([]byte(dimension))
		_, _ = h.Write([]byte("|"))
	}
	return "baseline-v2:" + hex.EncodeToString(h.Sum(nil))
}

// canonicalBaselineBody removes serialization-only differences while retaining
// values that may materially alter the response. JSON object keys and form
// fields are therefore ordered deterministically; opaque bodies are hashed.
func canonicalBaselineBody(contentType string, body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return ""
	}

	switch {
	case contentType == "application/json" || strings.HasSuffix(contentType, "+json"):
		if json.Valid([]byte(trimmed)) {
			var value any
			decoder := json.NewDecoder(strings.NewReader(trimmed))
			decoder.UseNumber()
			if err := decoder.Decode(&value); err == nil {
				if canonical, err := json.Marshal(value); err == nil {
					return "json:" + string(canonical)
				}
			}
		}
	case contentType == "application/x-www-form-urlencoded":
		if values, err := url.ParseQuery(trimmed); err == nil {
			return "form:" + values.Encode()
		}
	}

	sum := sha256.Sum256(body)
	return "opaque:" + hex.EncodeToString(sum[:])
}
