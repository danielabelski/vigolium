package httpmsg

import (
	"os"
	"strings"
	"testing"
)

// reset restores the process-global UA state to its package defaults so each
// subtest is independent (uaOverride defaults to the "preset" selector). It
// also clears VIGOLIUM_DEFAULT_UA, which would otherwise override the selector
// when set in the invoking shell (t.Setenv registers the restore).
func reset(t *testing.T) {
	t.Helper()
	t.Setenv(DefaultUserAgentEnvVar, "")
	if err := os.Unsetenv(DefaultUserAgentEnvVar); err != nil {
		t.Fatalf("unset %s: %v", DefaultUserAgentEnvVar, err)
	}
	uaMu.Lock()
	uaOverride = UserAgentPreset
	buildVersion = ""
	uaMu.Unlock()
}

func inRandomPool(ua string) bool {
	for _, p := range randomUserAgentPool {
		if p == ua {
			return true
		}
	}
	return false
}

func TestUserAgentIsHonestPreset(t *testing.T) {
	t.Run("preset default is honest", func(t *testing.T) {
		reset(t)
		if !UserAgentIsHonestPreset() {
			t.Error("expected preset default to be reported honest")
		}
	})

	t.Run("random selector is not honest", func(t *testing.T) {
		reset(t)
		SetDefaultUserAgent(UserAgentRandom)
		if UserAgentIsHonestPreset() {
			t.Error("random selector should not be honest preset")
		}
	})

	t.Run("literal selector is not honest", func(t *testing.T) {
		reset(t)
		SetDefaultUserAgent("Mozilla/5.0 (custom)")
		if UserAgentIsHonestPreset() {
			t.Error("custom literal should not be honest preset")
		}
	})

	t.Run("env random overrides preset config", func(t *testing.T) {
		reset(t)
		// config stays preset, env forces random → effective selector is random.
		t.Setenv(DefaultUserAgentEnvVar, "random")
		if UserAgentIsHonestPreset() {
			t.Error("VIGOLIUM_DEFAULT_UA=random should override preset config")
		}
		if got := effectiveUserAgentSelector(); got != "random" {
			t.Errorf("effectiveUserAgentSelector = %q, want random", got)
		}
	})

	t.Run("env preset overrides random config", func(t *testing.T) {
		reset(t)
		SetDefaultUserAgent(UserAgentRandom)
		t.Setenv(DefaultUserAgentEnvVar, "preset")
		if !UserAgentIsHonestPreset() {
			t.Error("VIGOLIUM_DEFAULT_UA=preset should override random config")
		}
	})
}

func TestDefaultUserAgent_PresetIsDefault(t *testing.T) {
	reset(t)
	SetBuildVersion("v9.9.9")
	const want = "Mozilla/5.0 (compatible; Vigolium/v9.9.9; +https://github.com/vigolium/vigolium)"
	if got := DefaultUserAgent(); got != want {
		t.Fatalf("default (preset): got %q, want %q", got, want)
	}
}

func TestDefaultUserAgent_PresetKeyword(t *testing.T) {
	reset(t)
	SetBuildVersion("v1.2.3")
	SetDefaultUserAgent("  PRESET  ") // case-insensitive, whitespace-trimmed
	const want = "Mozilla/5.0 (compatible; Vigolium/v1.2.3; +https://github.com/vigolium/vigolium)"
	if got := DefaultUserAgent(); got != want {
		t.Fatalf("preset keyword: got %q, want %q", got, want)
	}
}

func TestDefaultUserAgent_RandomKeyword(t *testing.T) {
	reset(t)
	SetDefaultUserAgent("random")
	if got := DefaultUserAgent(); !inRandomPool(got) {
		t.Fatalf("random keyword: got %q, want a value from the rotation pool", got)
	}
}

func TestDefaultUserAgent_BlankIsRandom(t *testing.T) {
	reset(t)
	SetDefaultUserAgent("   ") // blank == random
	if got := DefaultUserAgent(); !inRandomPool(got) {
		t.Fatalf("blank selector: got %q, want a value from the rotation pool", got)
	}
}

func TestSetDefaultUserAgent_LiteralOverrideWins(t *testing.T) {
	reset(t)
	const ua = "Mozilla/5.0 (compatible; Acme; +https://example.com)"
	SetDefaultUserAgent("  " + ua + "  ") // surrounding whitespace is trimmed
	if got := DefaultUserAgent(); got != ua {
		t.Fatalf("literal override: got %q, want %q", got, ua)
	}
}

func TestDefaultUserAgent_VersionPlaceholderExpansion(t *testing.T) {
	reset(t)
	SetBuildVersion("v9.9.9")
	SetDefaultUserAgent("Mozilla/5.0 (compatible; Vigolium/{version}; +https://github.com/vigolium/vigolium)")
	want := "Mozilla/5.0 (compatible; Vigolium/v9.9.9; +https://github.com/vigolium/vigolium)"
	if got := DefaultUserAgent(); got != want {
		t.Fatalf("version expansion: got %q, want %q", got, want)
	}
}

func TestDefaultUserAgent_VersionPlaceholderFallsBackToDev(t *testing.T) {
	reset(t)
	SetDefaultUserAgent("Vigolium/{version}")
	if got := DefaultUserAgent(); got != "Vigolium/dev" {
		t.Fatalf("empty build version: got %q, want %q", got, "Vigolium/dev")
	}
}

// The VIGOLIUM_DEFAULT_UA env var overrides the configured selector, accepting
// the same selector keywords and literals.
func TestDefaultUserAgent_EnvVarOverridesConfig(t *testing.T) {
	reset(t)
	SetBuildVersion("v9.9.9")
	SetDefaultUserAgent("random") // config says random...

	const literal = "Mozilla/5.0 (compatible; EnvWins/{version})"
	t.Setenv(DefaultUserAgentEnvVar, literal)
	if got := DefaultUserAgent(); got != "Mozilla/5.0 (compatible; EnvWins/v9.9.9)" {
		t.Fatalf("env literal override: got %q", got)
	}

	t.Setenv(DefaultUserAgentEnvVar, "preset")
	const wantPreset = "Mozilla/5.0 (compatible; Vigolium/v9.9.9; +https://github.com/vigolium/vigolium)"
	if got := DefaultUserAgent(); got != wantPreset {
		t.Fatalf("env preset override: got %q, want %q", got, wantPreset)
	}
}

// A blank env var is present-but-empty and must resolve to random (not fall
// through to the configured selector).
func TestDefaultUserAgent_BlankEnvVarIsRandom(t *testing.T) {
	reset(t)
	SetDefaultUserAgent("preset") // config says preset...
	t.Setenv(DefaultUserAgentEnvVar, "")
	got := DefaultUserAgent()
	if strings.Contains(got, "Vigolium/") || !inRandomPool(got) {
		t.Fatalf("blank env override: got %q, want a rotation-pool value", got)
	}
}
