package infra

import "math"

// opaqueBodyMinLen is the smallest body worth entropy-testing: below it a high ratio
// is just small-sample noise, and a genuine short XPath/HTML page is still worth
// probing.
const opaqueBodyMinLen = 512

// opaqueEntropyBitsPerByte is the Shannon-entropy threshold (bits per byte) above
// which a body is treated as opaque. Natural-language and markup bodies sit around
// 4.0–4.8; base64/hex-encoded data ~5–6; compressed/encrypted bytes approach 8. A
// cutoff of 5.6 clears dense-but-textual content (minified JS/CSS, JSON) while
// catching the encrypted, per-request CDN-challenge blobs that carry no stable
// structure for a boolean/differential oracle to read.
const opaqueEntropyBitsPerByte = 5.6

// opaqueSampleLen caps how many leading bytes are scanned: the entropy of a large
// blob is well-estimated from a prefix, keeping the check off the hot path's tail.
const opaqueSampleLen = 8192

// LooksOpaqueBody reports whether body is a high-entropy, structureless blob
// (compressed, encrypted, or otherwise binary/encoded) rather than the text or
// markup an application renders. Differential and boolean-oracle detectors use it to
// fail closed on such bodies: their content carries no stable, input-dependent
// structure, so any observed "difference" between probes is per-request noise, not a
// signal the injected logic produced.
func LooksOpaqueBody(body string) bool {
	if len(body) < opaqueBodyMinLen {
		return false
	}
	sample := body
	if len(sample) > opaqueSampleLen {
		sample = sample[:opaqueSampleLen]
	}
	return ShannonEntropyBits(sample) > opaqueEntropyBitsPerByte
}

// ShannonEntropyBits returns the Shannon entropy of s in bits per byte (0–8),
// computed over the raw byte distribution. Returns 0 for the empty string.
func ShannonEntropyBits(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
