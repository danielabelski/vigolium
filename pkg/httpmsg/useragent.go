package httpmsg

import (
	"math/rand"
	"os"
	"strings"
	"sync"
)

// BuiltinUserAgent is a realistic Chrome User-Agent string. It is one entry in
// the random-rotation pool and a concrete fallback for callers that need a
// browser string directly. It is no longer the default — see PresetUserAgent.
const BuiltinUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"

// PresetUserAgent is the honest, self-identifying User-Agent Vigolium sends by
// default. The {version} placeholder is replaced with the running binary
// version at request time so the value stays correct across upgrades. Selected
// via the "preset" keyword (the default) or any literal containing {version}.
const PresetUserAgent = "Mozilla/5.0 (compatible; Vigolium/{version}; +https://github.com/vigolium/vigolium)"

// versionPlaceholder is replaced with the running binary version inside a
// configured User-Agent. Lets operators pin a stable identifier
// (e.g. "Vigolium/{version}") that stays correct across upgrades.
const versionPlaceholder = "{version}"

// User-Agent selector keywords accepted by the
// scanning_strategy.http.user_agent config value and the VIGOLIUM_DEFAULT_UA
// environment variable. Matched case-insensitively.
const (
	// UserAgentPreset selects the self-identifying Vigolium string. Default.
	UserAgentPreset = "preset"
	// UserAgentRandom rotates a realistic browser string per request. A blank
	// value ("") behaves identically.
	UserAgentRandom = "random"
)

// DefaultUserAgentEnvVar overrides the configured User-Agent from the
// environment. When present it wins over scanning_strategy.http.user_agent and
// accepts the same values: "preset", "random", "" (blank == random), or any
// literal ({version} still expands).
const DefaultUserAgentEnvVar = "VIGOLIUM_DEFAULT_UA"

// randomUserAgentPool is a small set of realistic, current desktop browser
// User-Agents rotated when "random" (or a blank selector) is in effect.
var randomUserAgentPool = []string{
	BuiltinUserAgent,
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
}

var (
	uaMu sync.RWMutex
	// uaOverride is the configured User-Agent selector. It defaults to "preset"
	// so code paths that never load a config file still send the
	// self-identifying string rather than a random one.
	uaOverride   = UserAgentPreset
	buildVersion string // set once at startup from the CLI layer
)

// SetDefaultUserAgent installs the process-global User-Agent selector applied to
// every outgoing HTTP request across all scan phases. Accepts a selector
// keyword ("preset" / "random"), a blank string (== "random"), or any literal
// User-Agent (with {version} expansion). Safe for concurrent use; last writer
// wins.
func SetDefaultUserAgent(ua string) {
	ua = strings.TrimSpace(ua)
	uaMu.Lock()
	uaOverride = ua
	uaMu.Unlock()
}

// SetBuildVersion records the running binary version so a configured
// User-Agent containing the {version} placeholder resolves correctly. Called
// once from the CLI layer (httpmsg cannot import the version, that would cycle).
func SetBuildVersion(v string) {
	v = strings.TrimSpace(v)
	uaMu.Lock()
	buildVersion = v
	uaMu.Unlock()
}

// DefaultUserAgent returns the effective User-Agent for the next outgoing
// request. The VIGOLIUM_DEFAULT_UA environment variable (when present) takes
// precedence over the configured selector; the selector is then resolved:
// "preset" -> the self-identifying Vigolium string, "random"/"" -> a rotating
// browser string (a fresh pick per call), any other value -> that literal.
// {version} is expanded throughout.
func DefaultUserAgent() string {
	uaMu.RLock()
	selector, ver := uaOverride, buildVersion
	uaMu.RUnlock()

	// The env var overrides the configured selector when set (even to blank).
	if env, ok := os.LookupEnv(DefaultUserAgentEnvVar); ok {
		selector = env
	}
	return resolveUserAgent(selector, ver)
}

// effectiveUserAgentSelector returns the User-Agent selector that is actually in
// effect for outgoing requests: the VIGOLIUM_DEFAULT_UA environment variable
// when set, otherwise the configured scanning_strategy.http.user_agent value.
// The result is the raw selector keyword ("preset"/"random"/""/literal), not a
// resolved User-Agent — callers compare it against UserAgentPreset to decide
// whether the operator has opted away from the honest self-identifying default.
func effectiveUserAgentSelector() string {
	uaMu.RLock()
	sel := uaOverride
	uaMu.RUnlock()
	if env, ok := os.LookupEnv(DefaultUserAgentEnvVar); ok {
		sel = env
	}
	return strings.TrimSpace(sel)
}

// UserAgentIsHonestPreset reports whether the effective User-Agent selector is
// the self-identifying "preset" default. When true the operator has not opted
// into stealth (random/custom), so browser-harvested User-Agents should not be
// silently pinned onto downstream requests.
func UserAgentIsHonestPreset() bool {
	return strings.EqualFold(effectiveUserAgentSelector(), UserAgentPreset)
}

// resolveUserAgent maps a selector value to a concrete User-Agent string.
func resolveUserAgent(selector, ver string) string {
	selector = strings.TrimSpace(selector)
	switch {
	case selector == "" || strings.EqualFold(selector, UserAgentRandom):
		return randomUserAgent()
	case strings.EqualFold(selector, UserAgentPreset):
		selector = PresetUserAgent
	}
	return expandVersion(selector, ver)
}

// expandVersion replaces the {version} placeholder with the running binary
// version, falling back to "dev" when the version was never recorded.
func expandVersion(ua, ver string) string {
	if strings.Contains(ua, versionPlaceholder) {
		if ver == "" {
			ver = "dev"
		}
		ua = strings.ReplaceAll(ua, versionPlaceholder, ver)
	}
	return ua
}

// randomUserAgent returns a randomly chosen realistic browser User-Agent.
func randomUserAgent() string {
	return randomUserAgentPool[rand.Intn(len(randomUserAgentPool))]
}
