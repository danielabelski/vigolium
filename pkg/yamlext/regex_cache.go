package yamlext

import (
	"regexp"

	lru "github.com/hashicorp/golang-lru/v2"
)

// Matcher patterns are compiled once and reused.
//
// The evaluators used to call regexp.Compile on each pattern for every response
// they inspected and throw the result away — ~4.4 µs and 7.8 KB per matcher, per
// response, for a pattern set that is fixed the moment extensions are loaded.
//
// The cache is keyed by pattern text rather than attached to MatcherDef/
// RuleMatchDef because those are plain YAML-unmarshaled structs, and both are
// exported and evaluated through exported entry points (EvalMatcher,
// EvalRuleMatch) that must keep working on a caller-built literal. A key-based
// cache covers every path without a preparation step a caller could skip.

// regexCacheMaxEntries bounds the cache. The real bound is the number of distinct
// patterns across loaded extensions, which is small and fixed, so this is a
// backstop rather than a working limit.
const regexCacheMaxEntries = 4096

// regexCacheEntry memoizes a compile result, including failure. Caching the
// error matters: an invalid pattern makes its matcher return false forever, and
// without memoization it would re-attempt the compile on every response.
type regexCacheEntry struct {
	re  *regexp.Regexp
	err error
}

// regexCache is bounded and internally synchronized. The size is a positive
// constant, which is the only thing lru.New rejects, so the error is provably nil.
var regexCache, _ = lru.New[string, regexCacheEntry](regexCacheMaxEntries)

// compileCached returns the compiled form of pattern, compiling it at most once
// per distinct pattern. The returned *regexp.Regexp is shared; regexp.Regexp is
// safe for concurrent use, and callers must treat it as read-only.
func compileCached(pattern string) (*regexp.Regexp, error) {
	if entry, ok := regexCache.Get(pattern); ok {
		return entry.re, entry.err
	}

	re, err := regexp.Compile(pattern)
	regexCache.Add(pattern, regexCacheEntry{re: re, err: err})
	return re, err
}
