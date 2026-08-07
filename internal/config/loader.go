package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"gopkg.in/yaml.v3"
)

// Settings holds all configuration settings
type Settings struct {
	Server            ServerConfig            `yaml:"server"`
	Database          DatabaseConfig          `yaml:"database"`
	Notify            NotifyConfig            `yaml:"notify"`
	DynamicAssessment DynamicAssessmentConfig `yaml:"dynamic-assessment"`
	MutationStrategy  MutationStrategyConfig  `yaml:"mutation_strategy"`
	Scope             ScopeConfig             `yaml:"scope"`
	Discovery         DiscoveryConfig         `yaml:"discovery"`
	KnownIssueScan    KnownIssueScanConfig    `yaml:"known_issue_scan"`
	ExternalHarvester ExternalHarvesterConfig `yaml:"external_harvester"`
	ScanningStrategy  ScanningStrategyConfig  `yaml:"scanning_strategy"`
	ScanningPace      ScanningPaceConfig      `yaml:"scanning_pace"`
	Spidering         SpideringConfig         `yaml:"spidering"`
	Agent             AgentConfig             `yaml:"agent"`
	OAST              OASTConfig              `yaml:"oast"`
	Storage           StorageConfig           `yaml:"storage"`
}

// ProfileScanningStrategy is the allowlist of ScanningStrategyConfig keys a
// profile is permitted to override: it selects WHICH strategy applies
// (DefaultStrategy) and tunes the heuristics check, and nothing else. The
// per-strategy phase tables (Lite/Balanced/Deep), session, scan_logs, http, and
// port_sweep are deliberately excluded — a profile picks a strategy, it does not
// redefine WHAT each strategy means or touch global-config concerns. This is why
// ApplyProfile merges scanning_strategy field-by-field (below) rather than through
// the general key-preserving section overlay: the general path would faithfully
// apply any strategy sub-key a profile set, widening this authorization boundary.
type ProfileScanningStrategy struct {
	DefaultStrategy string `yaml:"default_strategy,omitempty"`
	HeuristicsCheck string `yaml:"heuristics_check,omitempty"`
}

// ProfileSettings is the subset of Settings that a scanning profile can override.
// Only non-nil pointer fields are applied; nil fields leave the main config unchanged.
type ProfileSettings struct {
	ScanningStrategy  *ProfileScanningStrategy `yaml:"scanning_strategy,omitempty"`
	ScanningPace      *ScanningPaceConfig      `yaml:"scanning_pace,omitempty"`
	Discovery         *DiscoveryConfig         `yaml:"discovery,omitempty"`
	Spidering         *SpideringConfig         `yaml:"spidering,omitempty"`
	KnownIssueScan    *KnownIssueScanConfig    `yaml:"known_issue_scan,omitempty"`
	DynamicAssessment *DynamicAssessmentConfig `yaml:"dynamic-assessment,omitempty"`
	ExternalHarvester *ExternalHarvesterConfig `yaml:"external_harvester,omitempty"`
	MutationStrategy  *MutationStrategyConfig  `yaml:"mutation_strategy,omitempty"`
	Scope             *ScopeConfig             `yaml:"scope,omitempty"`
	Notify            *NotifyConfig            `yaml:"notify,omitempty"`

	// raw holds the profile document's top-level section value-nodes, keyed by
	// their YAML key, captured by LoadProfile and consumed by ApplyProfile (see
	// there for why). Unexported, so it never round-trips through YAML; nil for a
	// ProfileSettings built programmatically rather than loaded from a file.
	raw map[string]*yaml.Node
}

// LoadProfile reads and parses a scanning profile YAML file.
func LoadProfile(path string) (*ProfileSettings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read profile file %s: %w", path, err)
	}

	content := ExpandEnvVars(string(data))

	// Parse once into a node, then derive both the typed struct and the per-section
	// raw nodes from it. ApplyProfile overlays each present section from the raw
	// nodes so it applies only the keys the file actually set (key-preserving).
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil, fmt.Errorf("failed to parse profile file %s: %w", path, err)
	}
	var profile ProfileSettings
	if err := doc.Decode(&profile); err != nil {
		return nil, fmt.Errorf("failed to parse profile file %s: %w", path, err)
	}
	profile.raw = topLevelSectionNodes(&doc)

	return &profile, nil
}

// topLevelSectionNodes returns the value node for each top-level mapping key in a
// parsed YAML document, keyed by the key string; these are what make ApplyProfile
// key-preserving. Returns nil for an empty or non-mapping document.
func topLevelSectionNodes(doc *yaml.Node) map[string]*yaml.Node {
	root := doc
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			return nil
		}
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return nil
	}
	sections := make(map[string]*yaml.Node, len(root.Content)/2)
	for i := 0; i+1 < len(root.Content); i += 2 {
		sections[root.Content[i].Value] = root.Content[i+1]
	}
	return sections
}

// ApplyProfile overlays non-nil profile sections onto settings.
//
// Each section is overlaid KEY-PRESERVINGLY: the section's raw YAML node (captured
// by LoadProfile) is decoded onto the live settings section, so only the keys the
// profile file actually set are written and an omitted sub-key (e.g.
// discovery.jstangle) keeps its global/default value. This replaces an earlier
// marshal→unmarshal round-trip that emitted every non-omitempty field as its zero
// value — which is how --intensity deep once silently zeroed
// discovery.jstangle.memory_budget_mb and aborted the whole Discovery phase.
//
// ScanningStrategy is handled specially via the ProfileScanningStrategy allowlist
// (merged field-by-field above) and never flows through the section overlay. Only
// sections present as raw nodes are overlaid, so a programmatically-built
// ProfileSettings (no raw nodes, e.g. tests) applies only ScanningStrategy here;
// every current caller of the section overlay goes through LoadProfile.
func ApplyProfile(settings *Settings, profile *ProfileSettings) error {
	if profile.ScanningStrategy != nil {
		if v := profile.ScanningStrategy.DefaultStrategy; v != "" {
			settings.ScanningStrategy.DefaultStrategy = v
		}
		if v := profile.ScanningStrategy.HeuristicsCheck; v != "" {
			settings.ScanningStrategy.HeuristicsCheck = v
		}
	}

	// Each entry pairs a section's YAML key (matching its ProfileSettings/Settings
	// yaml tag) with the live destination. Presence is decided by the raw node
	// alone: a key the file omitted is left untouched — defaults intact, never
	// re-zeroed — and a key written as an explicit null decodes as a no-op. The
	// matching ProfileSettings pointer fields are not consulted here; they exist
	// so LoadProfile type-checks the document up front.
	type overlay struct {
		key  string
		dest any
	}

	for _, o := range []overlay{
		{"scanning_pace", &settings.ScanningPace},
		{"discovery", &settings.Discovery},
		{"spidering", &settings.Spidering},
		{"known_issue_scan", &settings.KnownIssueScan},
		{"dynamic-assessment", &settings.DynamicAssessment},
		{"external_harvester", &settings.ExternalHarvester},
		{"mutation_strategy", &settings.MutationStrategy},
		{"scope", &settings.Scope},
		{"notify", &settings.Notify},
	} {
		node, ok := profile.raw[o.key]
		if !ok {
			continue
		}
		if err := node.Decode(o.dest); err != nil {
			return fmt.Errorf("failed to apply profile section %q: %w", o.key, err)
		}
	}

	return nil
}

// LoadSettings loads configuration from YAML file
// Search paths (in order):
//  1. --config flag path (if specified)
//  2. $HOME/.vigolium/vigolium-configs.yaml
//  3. ./vigolium-configs.yaml
func LoadSettings(configPath string) (*Settings, error) {
	var path string

	// If config path is explicitly provided, use it
	if configPath != "" {
		path = ExpandPath(configPath)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil, fmt.Errorf("config file not found: %s", path)
		}
	} else {
		// Try default locations
		paths := []string{
			ExpandPath("~/.vigolium/vigolium-configs.yaml"),
			"./vigolium-configs.yaml",
		}

		found := false
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				path = p
				found = true
				break
			}
		}

		// If no config file found, return default settings
		if !found {
			return DefaultSettings(), nil
		}
	}

	// Read config file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables in YAML content
	content := ExpandEnvVars(string(data))

	// Parse YAML on top of defaults so unspecified sections keep sensible values
	settings := *DefaultSettings()
	if err := yaml.Unmarshal([]byte(content), &settings); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Install the configured global User-Agent selector so every scan phase that
	// resolves httpmsg.DefaultUserAgent() at request time picks it up. The
	// selector is "preset" (default, self-identifying string), "random"/"" (a
	// rotating browser string), or a literal; VIGOLIUM_DEFAULT_UA still wins at
	// resolution time.
	httpmsg.SetDefaultUserAgent(settings.ScanningStrategy.HTTP.UserAgent)

	return &settings, nil
}

// DefaultSettings returns default configuration
func DefaultSettings() *Settings {
	return &Settings{
		Server:            *DefaultServerConfig(),
		Database:          *DefaultDatabaseConfig(),
		Notify:            *DefaultNotifyConfig(),
		DynamicAssessment: *DefaultDynamicAssessmentConfig(),
		MutationStrategy:  *DefaultMutationStrategyConfig(),
		Scope:             *DefaultScopeConfig(),
		Discovery:         *DefaultDiscoveryConfig(),
		KnownIssueScan:    *DefaultKnownIssueScanConfig(),
		ExternalHarvester: *DefaultExternalHarvesterConfig(),
		ScanningStrategy:  *DefaultScanningStrategyConfig(),
		ScanningPace:      *DefaultScanningPaceConfig(),
		Spidering:         *DefaultSpideringConfig(),
		Agent:             *DefaultAgentConfig(),
		OAST:              *DefaultOASTConfig(),
		Storage:           *DefaultStorageConfig(),
	}
}

// ExpandPath handles ~ expansion and environment variables
func ExpandPath(path string) string {
	// Expand environment variables
	path = ExpandEnvVars(path)

	// Expand ~ to home directory
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		path = filepath.Join(home, path[2:])
	}

	return path
}

// ContractPath replaces the user's home directory prefix with ~ — the inverse of ExpandPath.
func ContractPath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if strings.HasPrefix(path, home) {
		return "~" + path[len(home):]
	}
	return path
}

// ExpandEnvVars replaces environment variable references in s.
//
// Supported syntax (follows bash/Docker Compose conventions):
//
//	${VAR}            — value of VAR; empty string if unset
//	${VAR:-default}   — value of VAR if set and non-empty, otherwise "default"
//	$VAR              — same as ${VAR} (no default support)
func ExpandEnvVars(s string) string {
	return os.Expand(s, func(key string) string {
		if name, defaultVal, ok := parseDefault(key); ok {
			if v := os.Getenv(name); v != "" {
				return v
			}
			return defaultVal
		}
		return os.Getenv(key)
	})
}

// parseDefault splits "VAR:-default" into ("VAR", "default", true).
// Returns ("", "", false) if the separator is not present.
func parseDefault(key string) (name, defaultVal string, ok bool) {
	idx := strings.Index(key, ":-")
	if idx < 0 {
		return "", "", false
	}
	return key[:idx], key[idx+2:], true
}

// ProjectConfigDir returns the directory for a project's config files.
// Layout: ~/.vigolium/projects/<uuid>/
func ProjectConfigDir(projectUUID string) string {
	return ExpandPath("~/.vigolium/projects/" + projectUUID)
}

// ActiveProjectFilePath returns the path to the file that records the
// shell-independent active project (used as a fallback when no flag/env var
// is set). Layout: ~/.vigolium/active-project
func ActiveProjectFilePath() string {
	return ExpandPath("~/.vigolium/active-project")
}

// ReadActiveProject returns the persisted active project UUID, or "" if the
// file does not exist or is empty. Read errors other than not-exist surface
// to the caller.
func ReadActiveProject() (string, error) {
	data, err := os.ReadFile(ActiveProjectFilePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// WriteActiveProject persists the active project UUID to disk so that future
// shells/commands resolve to it without needing VIGOLIUM_PROJECT_UUID.
func WriteActiveProject(projectUUID string) error {
	path := ActiveProjectFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create vigolium config dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(projectUUID+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write active project file: %w", err)
	}
	return nil
}

// ProjectConfigPath returns the path to a project's config overlay file.
func ProjectConfigPath(projectUUID string) string {
	return filepath.Join(ProjectConfigDir(projectUUID), "config.yaml")
}

// LoadProjectConfig loads the project-specific config overlay if it exists.
// Returns nil (no error) if the file doesn't exist.
func LoadProjectConfig(projectUUID string) (*ProfileSettings, error) {
	profile, err := LoadProfile(ProjectConfigPath(projectUUID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return profile, nil
}

// LoadSettingsWithProject loads global settings, then overlays project-specific
// config on top. This implements the merge strategy: global → project → CLI flags.
// CLI flag overrides happen after this function returns.
func LoadSettingsWithProject(configPath string, projectUUID string) (*Settings, error) {
	settings, err := LoadSettings(configPath)
	if err != nil {
		return nil, err
	}

	if projectUUID == "" {
		return settings, nil
	}

	profile, err := LoadProjectConfig(projectUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to load project config for %s: %w", projectUUID, err)
	}
	if profile == nil {
		return settings, nil
	}

	if err := ApplyProfile(settings, profile); err != nil {
		return nil, fmt.Errorf("failed to apply project config: %w", err)
	}

	return settings, nil
}

// SaveProjectConfig writes a project config overlay to its config directory.
func SaveProjectConfig(projectUUID string, profile *ProfileSettings) error {
	dir := ProjectConfigDir(projectUUID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create project config directory: %w", err)
	}

	data, err := yaml.Marshal(profile)
	if err != nil {
		return fmt.Errorf("failed to marshal project config: %w", err)
	}

	path := ProjectConfigPath(projectUUID)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write project config: %w", err)
	}

	return nil
}

// ConfigFilePath returns the resolved path to the config file.
// It searches the same locations as LoadSettings but only returns the path.
// If no config file exists, returns the default path.
func ConfigFilePath() string {
	paths := []string{
		ExpandPath("~/.vigolium/vigolium-configs.yaml"),
		"./vigolium-configs.yaml",
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ExpandPath("~/.vigolium/vigolium-configs.yaml")
}

// SaveSettings writes settings to YAML file
func SaveSettings(path string, settings *Settings) error {
	path = ExpandPath(path)

	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	// Write to file
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
