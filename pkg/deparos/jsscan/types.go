// Package jsscan provides a JavaScript analysis scanner that extracts endpoints,
// secrets, and other security-relevant information from JavaScript files.
//
// jsscan wraps an embedded binary tool, providing automatic extraction,
// caching, and a clean Go API. The binary is embedded at build time and
// extracted on first use. Checksum validation ensures the cached binary
// is updated when a new version is embedded.
//
// # Quick Start
//
//	scanner, err := jsscan.NewScanner(jsscan.DefaultConfig())
//	if err != nil {
//	    log.Fatal(err)
//	}
//	result, err := scanner.Scan(ctx, jsContent)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, req := range result.Requests {
//	    fmt.Printf("Request: %s %s\n", req.Method, req.URL)
//	}
//
// # Binary Caching
//
// The jsscan binary is cached at ~/.cache/jsscan/ by default.
// The cache includes the binary and a checksum file. If the embedded
// binary's checksum differs from the cached version, the cache is
// automatically updated.
//
// # Thread Safety
//
// Both Scanner and Extractor are thread-safe for concurrent use.
// Multiple goroutines can safely call Scan() concurrently.
package jsscan

import (
	"errors"
	"time"
)

const (
	// MaxScanTimeout is the maximum timeout for a single scan operation.
	MaxScanTimeout = 5 * time.Minute
)

// Common errors for the jsscan package.
var (
	// ErrBinaryNotFound indicates the jsscan binary could not be extracted.
	ErrBinaryNotFound = errors.New("jsscan binary not found")

	// ErrExtractionFailed indicates binary extraction to cache failed.
	ErrExtractionFailed = errors.New("failed to extract jsscan binary")

	// ErrScanFailed indicates the jsscan scan command failed.
	ErrScanFailed = errors.New("jsscan scan failed")

	// ErrUnsupportedPlatform indicates the current OS/arch is not supported.
	ErrUnsupportedPlatform = errors.New("unsupported platform for jsscan")
)

// ExtractedRequest represents an HTTP request extracted from JavaScript.
type ExtractedRequest struct {
	URL     string   `json:"url"`
	Method  string   `json:"method"`
	Params  string   `json:"params"`
	Body    string   `json:"body"`
	Headers []string `json:"headers"`
	Cookies []string `json:"cookies"`
}

// CodeRecord represents extracted/transformed JavaScript code.
type CodeRecord struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
}

// DomFlow is a DOM-XSS source→sink taint flow reported by jsscan. Unlike a
// "source and sink both present" heuristic, each DomFlow means the analyzer
// traced the same data from a DOM-controlled source into a dangerous sink.
type DomFlow struct {
	Source  string `json:"source"`
	Sink    string `json:"sink"`
	Snippet string `json:"snippet"`
	Line    int    `json:"line"`
}

// BeautifiedCode is the unminified + bundle-unpacked document jsscan produces
// under the --beautify flag (webcrack, no eval-based deobfuscation).
//
// When Format != "none" the script was a detected bundle (webpack, browserify,
// ...) and Content is a single module-annotated document — each section headed
// by its recovered path (e.g. ./src/api.js) — with ModulePaths listing those
// paths. When not a bundle, Content is the plain unminified source and
// ModuleCount is 0. Changed reports whether the document differs from the input
// (false means beautification was a no-op and callers should skip persisting it).
type BeautifiedCode struct {
	Filename    string   `json:"filename"`
	Format      string   `json:"format"`
	ModuleCount int      `json:"moduleCount"`
	ModulePaths []string `json:"modulePaths"`
	Changed     bool     `json:"changed"`
	Content     string   `json:"content"`
}

// ScanOptions tunes a single scan invocation.
type ScanOptions struct {
	// Beautify enables the unminify + bundle-unpack pass (jsscan --beautify),
	// populating ScanResult.Beautified. Off by default: it runs a heavier
	// webcrack pass, so only the passive js-beautify module opts in.
	Beautify bool
}

// ScanResult contains the complete output from a jsscan analysis.
type ScanResult struct {
	Requests     []ExtractedRequest `json:"requests"`
	Code         *CodeRecord        `json:"code,omitempty"`
	DomFlows     []DomFlow          `json:"dom_flows,omitempty"`
	Beautified   *BeautifiedCode    `json:"beautified,omitempty"`
	ScanDuration time.Duration      `json:"scan_duration"`
	BytesScanned int                `json:"bytes_scanned"`
}

// HasRequests returns true if any requests were extracted.
func (r *ScanResult) HasRequests() bool {
	return len(r.Requests) > 0
}

// HasCode returns true if code was extracted.
func (r *ScanResult) HasCode() bool {
	return r.Code != nil
}

// HasDomFlows returns true if any DOM-XSS taint flows were reported.
func (r *ScanResult) HasDomFlows() bool {
	return len(r.DomFlows) > 0
}

// HasBeautified returns true if a beautified document was produced and it
// actually differs from the input (a no-op beautification is not reported).
func (r *ScanResult) HasBeautified() bool {
	return r.Beautified != nil && r.Beautified.Changed && r.Beautified.Content != ""
}

// Config configures the jsscan scanner behavior.
type Config struct {
	// CacheDir overrides the default cache directory (~/.cache/jsscan/).
	// If empty, uses the default location.
	CacheDir string
}

// DefaultConfig returns the default scanner configuration.
func DefaultConfig() *Config {
	return &Config{
		CacheDir: "",
	}
}

// CachedBinary holds information about a cached jsscan binary.
type CachedBinary struct {
	Path        string
	Checksum    string
	ExtractedAt time.Time
}
