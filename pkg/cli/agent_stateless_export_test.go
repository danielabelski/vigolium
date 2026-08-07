package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// newFormatCmd builds a throwaway command carrying just the flags
// planAgentStateless inspects (--format, changed-tracking), so the tests can
// drive the resolver without the full autopilot command.
func newFormatCmd(t *testing.T, formatVal string, formatChanged bool) *cobra.Command {
	t.Helper()
	c := &cobra.Command{Use: "autopilot"}
	c.Flags().String("format", "console", "")
	if formatChanged {
		if err := c.Flags().Set("format", formatVal); err != nil {
			t.Fatalf("set format: %v", err)
		}
	}
	return c
}

// withGlobals snapshots and restores the process globals planAgentStateless
// reads, so each case starts clean regardless of order.
func withGlobals(t *testing.T, format, db string, isolate bool) {
	t.Helper()
	sf, sdb, siso := globalFormat, globalDB, globalDBIsolate
	globalFormat, globalDB, globalDBIsolate = format, db, isolate
	t.Cleanup(func() { globalFormat, globalDB, globalDBIsolate = sf, sdb, siso })
}

func TestPlanAgentStateless(t *testing.T) {
	tests := []struct {
		name          string
		format        string
		formatChanged bool
		stateless     bool
		db            string
		dbIsolate     bool
		output        string
		wantErr       string
		wantActive    bool
		wantOutput    string
		wantFormats   []string // nil = don't assert
	}{
		{
			name:      "not stateless, default console format is a normal persisted run",
			format:    "console",
			stateless: false,
		},
		{
			name:          "file format without -S is a hard error, not a silent ignore",
			format:        "html",
			formatChanged: true,
			stateless:     false,
			wantErr:       "requires -S/--stateless",
		},
		{
			name:          "file format list without -S errors and echoes the whole list",
			format:        "sqlite,html,console",
			formatChanged: true,
			stateless:     false,
			wantErr:       "sqlite,html,console",
		},
		{
			name:          "stateless with file formats and -o resolves that base",
			format:        "sqlite,html,console",
			formatChanged: true,
			stateless:     true,
			output:        "run/scan",
			wantActive:    true,
			wantOutput:    "run/scan",
		},
		{
			name:          "stateless with file formats and no -o defaults the base",
			format:        "html",
			formatChanged: true,
			stateless:     true,
			wantActive:    true,
			wantOutput:    agentStatelessDefaultBase,
		},
		{
			name:       "stateless with only console and no -o writes nothing",
			format:     "console",
			stateless:  true,
			wantActive: true,
			wantOutput: "",
		},
		{
			name:       "stateless with only console but an -o still exports console",
			format:     "console",
			stateless:  true,
			output:     "run/scan",
			wantActive: true,
			wantOutput: "run/scan",
		},
		{
			name:          "stateless rejects an explicit --db",
			format:        "html",
			formatChanged: true,
			stateless:     true,
			db:            "acme.sqlite",
			wantErr:       "cannot be combined with --db",
		},
		{
			name:          "stateless rejects --db-isolate",
			format:        "html",
			formatChanged: true,
			stateless:     true,
			dbIsolate:     true,
			wantErr:       "cannot be combined with --db-isolate",
		},
		{
			// planAgentStateless shares normalizeScanFormats with the scan
			// commands, so the sqlite aliases resolve identically here and a
			// format `scan -S` accepts is never rejected by `autopilot -S`.
			name:          "sqlite aliases normalize like scan -S",
			format:        "db,sqlite3",
			formatChanged: true,
			stateless:     true,
			output:        "run/scan",
			wantActive:    true,
			wantOutput:    "run/scan",
			wantFormats:   []string{"sqlite", "sqlite"},
		},
		{
			name:          "unknown format is rejected",
			format:        "html,bogus",
			formatChanged: true,
			stateless:     true,
			output:        "run",
			wantErr:       `invalid --format value "bogus"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withGlobals(t, tt.format, tt.db, tt.dbIsolate)
			cmd := newFormatCmd(t, tt.format, tt.formatChanged)

			plan, err := planAgentStateless(cmd, "agent autopilot", tt.stateless, tt.output)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("planAgentStateless() = nil error, want %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %q, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if plan.active != tt.wantActive {
				t.Errorf("plan.active = %v, want %v", plan.active, tt.wantActive)
			}
			if plan.output != tt.wantOutput {
				t.Errorf("plan.output = %q, want %q", plan.output, tt.wantOutput)
			}
			if tt.wantFormats != nil && !slices.Equal(plan.formats, tt.wantFormats) {
				t.Errorf("plan.formats = %v, want %v", plan.formats, tt.wantFormats)
			}
		})
	}
}

func TestAgentStatelessWantsFiles(t *testing.T) {
	tests := []struct {
		formats []string
		want    bool
	}{
		{[]string{"console"}, false},
		{[]string{"console", "jsonl"}, true},
		{[]string{"sqlite"}, true},
		{[]string{"html", "console"}, true},
		{[]string{"fs"}, true},
	}
	for _, tt := range tests {
		if got := agentStatelessWantsFiles(tt.formats); got != tt.want {
			t.Errorf("agentStatelessWantsFiles(%v) = %v, want %v", tt.formats, got, tt.want)
		}
	}
}
