package jsframework

import (
	"regexp"
	"strings"
	"sync"
)

// BuildIDRegex extracts the buildId from __NEXT_DATA__ JSON.
var BuildIDRegex = regexp.MustCompile(`"buildId"\s*:\s*"([^"]+)"`)

// UseClientDirectiveRe matches the "use client" directive in JS/TS source.
var UseClientDirectiveRe = regexp.MustCompile(`(?:'use client'|"use client")`)

// HasNextJSMarkers returns true if the body contains Next.js markers.
func HasNextJSMarkers(body string) bool {
	return strings.Contains(body, "__NEXT_DATA__") || strings.Contains(body, "/_next/")
}

// IsClientBuildArtifact reports whether a path is under a JS framework's
// immutable client build-output directory (Next.js `/_next/static/`, Nuxt
// `/_nuxt/`). Server-only data-fetching / caching / server-action code is
// compiled OUT of these bundles by the bundler, so a passive detector that
// greps a served chunk for server-side constructs only finds framework-machinery
// strings — the same bundle hash appears across every site using that framework,
// producing one false positive per host. Source-analysis detectors should skip
// these paths. NOTE: server_only_boundary_audit is the deliberate exception — it
// scans exactly these paths to catch server code that leaked into the client
// bundle — so it must NOT call this.
func IsClientBuildArtifact(path string) bool {
	p := strings.ToLower(path)
	return strings.Contains(p, "/_next/static/") || strings.Contains(p, "/_nuxt/")
}

// LooksLikeNextJS returns true if the host is fingerprinted as Next.js,
// or the body contains Next.js markers as a fallback.
func LooksLikeNextJS(host, body string) bool {
	if IsNextJS(host) {
		return true
	}
	return HasNextJSMarkers(body)
}

// FrameworkType identifies a JavaScript framework.
type FrameworkType string

const (
	NextJS    FrameworkType = "nextjs"
	NuxtJS    FrameworkType = "nuxtjs"
	Angular   FrameworkType = "angular"
	ReactCRA  FrameworkType = "react-cra"
	Remix     FrameworkType = "remix"
	SvelteKit FrameworkType = "sveltekit"
	Gatsby    FrameworkType = "gatsby"
	Unknown   FrameworkType = ""
)

// HostFingerprint stores detected framework metadata for a given host.
type HostFingerprint struct {
	Framework FrameworkType
	BuildID   string
	AppRouter bool // Next.js App Router vs Pages Router
	ExtraData map[string]string
}

// cache stores per-host fingerprint data using a sync.Map for thread safety.
var cache sync.Map

// Get returns the cached fingerprint for a host, or nil if not found.
func Get(host string) *HostFingerprint {
	val, ok := cache.Load(host)
	if !ok {
		return nil
	}
	fp, _ := val.(*HostFingerprint)
	return fp
}

// Set stores a fingerprint for a host.
func Set(host string, fp *HostFingerprint) {
	cache.Store(host, fp)
}

// IsNextJS returns true if the host has been fingerprinted as Next.js.
func IsNextJS(host string) bool {
	fp := Get(host)
	return fp != nil && fp.Framework == NextJS
}

// GetBuildID returns the build ID for a host, or "" if not available.
func GetBuildID(host string) string {
	fp := Get(host)
	if fp == nil {
		return ""
	}
	return fp.BuildID
}
