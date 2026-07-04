package spider

import (
	"net/url"

	"github.com/vigolium/vigolium/pkg/deparos/jsvendor"
)

// The vendor/analytics/CDN classifier now lives in pkg/deparos/jsvendor so the
// passive js-beautify module can share one source of truth.

// ShouldSkipJSPathExtraction checks if a JS URL should skip path extraction.
// Returns true for CDN domains and known library files that don't contain
// application-specific endpoints. The JS file will still be recorded as a finding,
// but path extraction will be skipped.
func ShouldSkipJSPathExtraction(jsURL *url.URL) bool {
	return jsvendor.ShouldSkipJSPathExtraction(jsURL.Host, jsURL.Path)
}
