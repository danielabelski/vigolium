package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// ExternalHarvesterConfig holds configuration for pre-scan external intelligence harvesting.
type ExternalHarvesterConfig struct {
	Sources []string                 `yaml:"sources"`
	APIKeys ExternalHarvesterAPIKeys `yaml:"api_keys"`
}

// ExternalHarvesterAPIKeys holds API keys for external harvester sources that require authentication.
type ExternalHarvesterAPIKeys struct {
	URLScan    string `yaml:"urlscan"`
	VirusTotal string `yaml:"virustotal"`
}

// DefaultExternalHarvesterConfig returns default external harvester configuration.
//
// Only keyless sources are enabled by default, so the phase runs the same way
// whether or not any credential is configured. urlscan and virustotal join in
// only when their key is set.
func DefaultExternalHarvesterConfig() *ExternalHarvesterConfig {
	return &ExternalHarvesterConfig{
		Sources: []string{"wayback", "commoncrawl", "alienvault", "arquivo"},
	}
}

var validExternalHarvesterSources = map[string]bool{
	"wayback":     true,
	"commoncrawl": true,
	"arquivo":     true,
	"urlscan":     true,
	"alienvault":  true,
	"virustotal":  true,
}

// keyedSources maps each source that cannot run without a credential to the
// config field supplying it. One table drives both the "is a key required" test
// and the "which key is missing" message, so a source cannot end up in one and
// not the other.
var keyedSources = map[string]struct {
	field string
	value func(ExternalHarvesterAPIKeys) string
}{
	"urlscan":    {"api_keys.urlscan", func(k ExternalHarvesterAPIKeys) string { return k.URLScan }},
	"virustotal": {"api_keys.virustotal", func(k ExternalHarvesterAPIKeys) string { return k.VirusTotal }},
}

// Validate checks external harvester configuration for errors.
func (c *ExternalHarvesterConfig) Validate() error {
	for _, s := range c.Sources {
		if !validExternalHarvesterSources[s] {
			// The list is derived rather than written out, so it cannot drift
			// from the map that actually decides.
			valid := slices.Sorted(maps.Keys(validExternalHarvesterSources))
			return fmt.Errorf("external_harvester.sources: unknown source %q (valid: %s)",
				s, strings.Join(valid, ", "))
		}

		if keyed, ok := keyedSources[s]; ok && keyed.value(c.APIKeys) == "" {
			return fmt.Errorf("external_harvester: source %q requires %s to be set", s, keyed.field)
		}
	}

	return nil
}
