package config

import (
	"slices"
	"testing"
)

func TestKnownIssueScanConfig_Validate_SeverityOverrides(t *testing.T) {
	tests := []struct {
		name    string
		cfg     KnownIssueScanConfig
		wantErr bool
	}{
		{
			name:    "valid override",
			cfg:     KnownIssueScanConfig{SeverityOverrides: map[string]string{"config-json-exposure-fuzz": "medium"}},
			wantErr: false,
		},
		{
			name:    "valid override mixed case + spaces",
			cfg:     KnownIssueScanConfig{SeverityOverrides: map[string]string{"some-template": " HIGH "}},
			wantErr: false,
		},
		{
			name:    "invalid override severity",
			cfg:     KnownIssueScanConfig{SeverityOverrides: map[string]string{"some-template": "spicy"}},
			wantErr: true,
		},
		{
			name:    "nil overrides ok",
			cfg:     KnownIssueScanConfig{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultKnownIssueScanConfig_ConfigJSONIsMedium(t *testing.T) {
	cfg := DefaultKnownIssueScanConfig()
	if got := cfg.SeverityOverrides["config-json-exposure-fuzz"]; got != "medium" {
		t.Errorf("default config-json-exposure-fuzz override = %q, want %q", got, "medium")
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("default config must validate: %v", err)
	}
}

func TestDefaultFindingGrouping_GroupsSourcemapByModule(t *testing.T) {
	gc := DefaultKnownIssueScanConfig().ResolveGroupByValue()
	if !gc.Enabled || !gc.PerHost {
		t.Fatalf("default grouping should be enabled per-host, got %+v", gc)
	}
	set := make(map[string]bool, len(gc.ByModule))
	for _, m := range gc.ByModule {
		set[m] = true
	}
	// sourcemap-detect plus the per-asset source-analysis / hygiene family collapse
	// to one finding per host regardless of per-URL value.
	for _, want := range []string{
		"sourcemap-detect",
		"js-beautify",
		"unsafe-html-sink",
		"dom-xss-taint",
		"cookie-security-detect",
		"server-action-auth",
		// CORS hygiene + the multi-technique misconfiguration probes (reflected /
		// null / subdomain / prefix / suffix / port / scheme) collapse per host —
		// one broken-CORS finding per asset, not one row per probe technique.
		"cors-headers-detect",
		"cors-misconfiguration",
		// Active probe / behavior Info leads + postMessage source analysis: one
		// per-host fact, not one row per probed URL / JS bundle.
		"cache-deception",
		"ssti-detection",
		"input-behavior-probe",
		"smart-behavior-detection",
		"rails-info-exposure",
		"postmessage-handler-detect",
		// Sensitive URL params: one per-host hygiene finding (constant module_name),
		// not one row per crawled URL that carries a query key/token.
		"sensitive-url-params",
		// Confirmed per-URL/param findings whose module_name embeds a payload/param
		// token (so by-rule can't fold them) — by-module collapses per host.
		"crlf-injection",
		"api-key-url-exposure",
		// Per-response hygiene siblings of csp-weakness-audit / cache-data-leak.
		"clickjacking-detect",
		"cache-auth-misconfiguration",
		// Per-response / per-page hygiene that fires once per URL: reverse-tabnabbing
		// (unsafe target=_blank page), sensitive data leaked in a response header, and
		// Nginx path-escape behavior — one per-host finding, affected URLs/headers unioned.
		"reverse-tabnabbing-detect",
		"sensitive-header-leak",
		"nginx-path-escape",
	} {
		if !set[want] {
			t.Errorf("default ByModule should include %q, got %v", want, gc.ByModule)
		}
	}

	// By-rule modules fold repeats of one rule/variant per host while keeping
	// distinct variants apart — the per-endpoint / per-param injection findings that
	// share one module_id but carry the header/technique in module_name.
	for _, want := range []string{"secret-detect", "host-header-injection", "ldap-injection", "proxy-header-trust", "csti-detection", "express-trust-proxy-misconfig", "aspnet-viewstate-scan"} {
		if !slices.Contains(gc.ByRule, want) {
			t.Errorf("default ByRule should include %q, got %v", want, gc.ByRule)
		}
	}
	// The multi-vector injection modules must be by-RULE (module_name kept), never
	// by-MODULE: by-module would conflate distinct header vectors / techniques on one host.
	for _, banned := range []string{"host-header-injection", "ldap-injection", "proxy-header-trust"} {
		if set[banned] {
			t.Errorf("%s must be by-rule, not by-module (by-module conflates variants), got ByModule %v", banned, gc.ByModule)
		}
	}
	// Secret-bearing modules stay value-grouped so distinct leaked secrets remain
	// distinct findings — they must NOT collapse by module. crypto-weakness-detect
	// is excluded too: one module_id spans distinct weakness classes (weak-hash vs
	// encrypted-cookie-without-MAC), so a per-host by-module collapse would conflate
	// them — it stays value-grouped (identical digests still collapse).
	for _, banned := range []string{"env-secret-exposure", "crypto-weakness-detect", "info-disclosure-detect", "error-message-detect", "directory-listing-detect"} {
		if set[banned] {
			t.Errorf("%s must not be in default ByModule (value is signal), got %v", banned, gc.ByModule)
		}
	}
}
