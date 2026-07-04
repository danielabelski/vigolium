package cli

import (
	"reflect"
	"testing"
)

// setModuleFlags sets the package-level module-selection globals for a test and
// restores them afterward.
func setModuleFlags(t *testing.T, ids []string, passiveOnly bool) {
	t.Helper()
	prevIDs, prevPO := globalModuleIDs, globalPassiveOnly
	globalModuleIDs, globalPassiveOnly = ids, passiveOnly
	t.Cleanup(func() { globalModuleIDs, globalPassiveOnly = prevIDs, prevPO })
}

func TestApplyModuleSelectionOverrides(t *testing.T) {
	all := func() []string { return []string{"all"} }

	cases := []struct {
		name        string
		ids         []string
		passiveOnly bool
		noPassive   bool
		wantActive  []string
		wantPassive []string
	}{
		{"defaults untouched", nil, false, false, []string{"x", "y"}, []string{"all"}},
		{"module-id both", []string{"js-beautify"}, false, false, []string{"js-beautify"}, []string{"js-beautify"}},
		{"passive-only", nil, true, false, nil, []string{"all"}},
		{"passive-only + module-id", []string{"js-beautify"}, true, false, nil, []string{"js-beautify"}},
		{"module-id + no-passive", []string{"secret-detect"}, false, true, []string{"secret-detect"}, nil},
		{"no-passive alone", nil, false, true, []string{"x", "y"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setModuleFlags(t, c.ids, c.passiveOnly)
			// Callers seed the defaults before applying overrides.
			active := []string{"x", "y"}
			passive := all()
			applyModuleSelectionOverrides(&active, &passive, c.noPassive)
			if !reflect.DeepEqual(active, c.wantActive) {
				t.Errorf("active = %v, want %v", active, c.wantActive)
			}
			if !reflect.DeepEqual(passive, c.wantPassive) {
				t.Errorf("passive = %v, want %v", passive, c.wantPassive)
			}
		})
	}
}

func TestResolveModuleSelection(t *testing.T) {
	// No flags: active = all (resolveModules default), passive = all.
	setModuleFlags(t, nil, false)
	if a, p := resolveModuleSelection(false); !reflect.DeepEqual(a, []string{"all"}) || !reflect.DeepEqual(p, []string{"all"}) {
		t.Errorf("default = %v/%v, want all/all", a, p)
	}
	// --passive-only: no active, all passive.
	setModuleFlags(t, nil, true)
	if a, p := resolveModuleSelection(false); a != nil || !reflect.DeepEqual(p, []string{"all"}) {
		t.Errorf("passive-only = %v/%v, want nil/all", a, p)
	}
	// --module-id: exact IDs both categories.
	setModuleFlags(t, []string{"js-beautify"}, false)
	if a, p := resolveModuleSelection(false); !reflect.DeepEqual(a, []string{"js-beautify"}) || !reflect.DeepEqual(p, []string{"js-beautify"}) {
		t.Errorf("module-id = %v/%v", a, p)
	}
}

func TestValidateModuleSelectionFlags(t *testing.T) {
	// --passive-only + --no-passive is a hard error.
	setModuleFlags(t, nil, true)
	if err := validateModuleSelectionFlags(true); err == nil {
		t.Error("expected error for --passive-only + --no-passive")
	}
	// --passive-only alone is fine.
	if err := validateModuleSelectionFlags(false); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// A known module id validates cleanly.
	setModuleFlags(t, []string{"js-beautify"}, false)
	if err := validateModuleSelectionFlags(false); err != nil {
		t.Errorf("unexpected error for known module id: %v", err)
	}
	// An unknown id only warns (no error).
	setModuleFlags(t, []string{"totally-unknown-module"}, false)
	if err := validateModuleSelectionFlags(false); err != nil {
		t.Errorf("unknown module id should warn, not error: %v", err)
	}
}

func TestSelectModulesByIDs(t *testing.T) {
	// All → non-empty active and passive.
	a, p := selectModulesByIDs([]string{"all"}, []string{"all"})
	if len(a) == 0 || len(p) == 0 {
		t.Fatalf("expected all active+passive, got %d/%d", len(a), len(p))
	}

	// Passive-only exact id → zero active, exactly the one passive module.
	a, p = selectModulesByIDs(nil, []string{"js-beautify"})
	if len(a) != 0 {
		t.Errorf("expected 0 active, got %d", len(a))
	}
	if len(p) != 1 || p[0].ID() != "js-beautify" {
		t.Errorf("expected only js-beautify passive, got %d", len(p))
	}

	// Unknown ids → nothing.
	a, p = selectModulesByIDs([]string{"nope"}, []string{"nope"})
	if len(a) != 0 || len(p) != 0 {
		t.Errorf("expected nothing for unknown ids, got %d/%d", len(a), len(p))
	}
}
