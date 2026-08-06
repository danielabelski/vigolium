package config

import (
	"fmt"
	"time"
)

// SpideringConfig configures the browser-based spidering phase.
type SpideringConfig struct {
	MaxDepth            int    `yaml:"max_depth"`             // default: 6 (0 = unlimited)
	MaxStates           int    `yaml:"max_states"`            // default: 1500 (0 = unlimited)
	MaxDuration         string `yaml:"max_duration"`          // default: "30m"
	MaxConsecutiveFails int    `yaml:"max_consecutive_fails"` // default: 100
	Headless            bool   `yaml:"headless"`              // default: true
	BrowserCount        int    `yaml:"browser_count"`         // default: 1
	Strategy            string `yaml:"strategy"`              // default: "adaptive"
	IncludeResponseBody bool   `yaml:"include_response_body"` // default: true
	BrowserEngine       string `yaml:"browser_engine"`        // "chromium" (default), "ungoogled", or "fingerprint"
	BrowserPath         string `yaml:"browser_path"`          // explicit path to browser binary (overrides auto-detection)
	NoCDP               bool   `yaml:"no_cdp"`                // disable CDP event listener detection
	NoForms             bool   `yaml:"no_forms"`              // disable automatic form filling

	// SelfRegister lets the crawl complete a public signup form and continue as
	// the account it creates. On an app with open registration this is the
	// difference between crawling the marketing shell and crawling the product.
	// Off by default because registering is a write; the runner turns it on at
	// deep intensity, and this setting forces it on at any intensity.
	SelfRegister bool `yaml:"self_register"`

	// GraphOutputDir, when set, is a directory the crawl graph is written into
	// (one file per host). The graph records which action on which state led
	// where, so a run can be reproduced and a specific state re-reached without
	// rediscovering the path to it. Empty disables.
	GraphOutputDir string `yaml:"graph_output_dir"`
}

// DefaultSpideringConfig returns sensible defaults for spidering.
func DefaultSpideringConfig() *SpideringConfig {
	return &SpideringConfig{
		// Bound how the crawl spends its clock. Unbounded, a link-dense site can
		// sink the whole max_duration into one deep branch and never revisit the
		// breadth near the seed; and a template that mints a state per row (a
		// paginated table, a calendar) can spend it on near-identical pages. Both
		// are generous enough that a normal application finishes well inside them.
		MaxDepth:            6,
		MaxStates:           1500,
		MaxDuration:         "30m",
		MaxConsecutiveFails: 100,
		Headless:            true,
		BrowserCount:        1,
		Strategy:            "adaptive",
		IncludeResponseBody: true,
		BrowserEngine:       "chromium",
		NoCDP:               false,
		NoForms:             false,
	}
}

// MaxDurationParsed parses the max_duration string into time.Duration.
func (c *SpideringConfig) MaxDurationParsed() time.Duration {
	if c.MaxDuration == "" {
		return 30 * time.Minute
	}
	d, err := time.ParseDuration(c.MaxDuration)
	if err != nil {
		return 30 * time.Minute
	}
	return d
}

// Validate checks spidering configuration for errors.
func (c *SpideringConfig) Validate() error {
	if c.MaxDepth < 0 {
		return fmt.Errorf("spidering.max_depth must be >= 0")
	}
	if c.MaxStates < 0 {
		return fmt.Errorf("spidering.max_states must be >= 0")
	}
	if c.MaxConsecutiveFails < 0 {
		return fmt.Errorf("spidering.max_consecutive_fails must be >= 0")
	}
	if c.BrowserCount < 0 {
		return fmt.Errorf("spidering.browser_count must be >= 0")
	}
	if c.MaxDuration != "" {
		if _, err := time.ParseDuration(c.MaxDuration); err != nil {
			return fmt.Errorf("spidering.max_duration: invalid duration %q: %w", c.MaxDuration, err)
		}
	}
	validStrategies := map[string]bool{
		"normal": true, "random": true, "oldest_first": true, "shallow_first": true, "adaptive": true,
	}
	if c.Strategy != "" && !validStrategies[c.Strategy] {
		return fmt.Errorf("spidering.strategy must be normal/random/oldest_first/shallow_first/adaptive, got: %s", c.Strategy)
	}
	validEngines := map[string]bool{
		"": true, "chromium": true, "ungoogled": true, "fingerprint": true,
	}
	if !validEngines[c.BrowserEngine] {
		return fmt.Errorf("spidering.browser_engine must be 'chromium', 'ungoogled', or 'fingerprint', got: %s", c.BrowserEngine)
	}
	return nil
}
