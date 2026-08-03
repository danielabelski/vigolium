package runner

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/modules"
)

func TestIntensityTierCeiling(t *testing.T) {
	cases := map[string]int{
		"":         modules.TierRankIntrusive, // default (balanced)
		"balanced": modules.TierRankIntrusive,
		"standard": modules.TierRankIntrusive,
		"quick":    modules.TierRankModerate,
		"lite":     modules.TierRankModerate,
		"deep":     modules.TierRankIntrusive,
		"full":     modules.TierRankIntrusive,
		"DEEP":     modules.TierRankIntrusive,
		"unknown":  modules.TierRankIntrusive, // unknown falls back to balanced
	}
	for in, want := range cases {
		if got := intensityTierCeiling(in); got != want {
			t.Errorf("intensityTierCeiling(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestLoginCredsIntensityGating(t *testing.T) {
	cases := []struct {
		intensity string
		enabled   bool
		full      bool
	}{
		{"", true, false},         // default → balanced: on, minimal
		{"balanced", true, false}, // balanced: on, minimal
		{"standard", true, false},
		{"deep", true, true}, // deep: on, full
		{"full", true, true},
		{"DEEP", true, true}, // case-insensitive
		{"quick", false, false},
		{"lite", false, false},
		{"unknown", true, false}, // unknown → balanced
	}
	for _, c := range cases {
		enabled, full := loginCredsPolicy(c.intensity)
		if enabled != c.enabled || full != c.full {
			t.Errorf("loginCredsPolicy(%q) = (%v, %v), want (%v, %v)",
				c.intensity, enabled, full, c.enabled, c.full)
		}
	}
}

// stubActive is a minimal ActiveModule used to test tier filtering without
// pulling in the real registry.
type tierStubActive struct {
	modules.ActiveModule
	id   string
	tags []string
}

func (s tierStubActive) ID() string     { return s.id }
func (s tierStubActive) Tags() []string { return s.tags }

func TestFilterActiveModulesByTier(t *testing.T) {
	mods := []modules.ActiveModule{
		tierStubActive{id: "untagged", tags: []string{"xss"}},
		tierStubActive{id: "light", tags: []string{"light"}},
		tierStubActive{id: "moderate", tags: []string{"moderate"}},
		tierStubActive{id: "heavy", tags: []string{"heavy"}},
		tierStubActive{id: "intrusive", tags: []string{"intrusive"}},
	}
	r := &Runner{}

	ids := func(in []modules.ActiveModule) []string {
		out := make([]string, len(in))
		for i, m := range in {
			out[i] = m.ID()
		}
		return out
	}

	// quick ceiling = moderate: drops heavy + intrusive, keeps untagged.
	got := ids(r.filterActiveModulesByTier(mods, modules.TierRankModerate))
	want := []string{"untagged", "light", "moderate"}
	if !equalStrings(got, want) {
		t.Errorf("quick ceiling = %v, want %v", got, want)
	}

	// heavy ceiling: drops only intrusive (no intensity maps here anymore, but
	// the filter must still honor an explicit heavy ceiling correctly).
	got = ids(r.filterActiveModulesByTier(mods, modules.TierRankHeavy))
	want = []string{"untagged", "light", "moderate", "heavy"}
	if !equalStrings(got, want) {
		t.Errorf("heavy ceiling = %v, want %v", got, want)
	}

	// balanced/deep ceiling = intrusive: keeps everything.
	got = ids(r.filterActiveModulesByTier(mods, modules.TierRankIntrusive))
	if len(got) != len(mods) {
		t.Errorf("intrusive ceiling dropped modules: %v", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The costliest modules in the registry must be tagged so that --intensity quick
// actually drops them. Measured on a real 1.8s-RTT target, these four dominated
// dynamic-assessment wall clock (input-behavior-probe alone: 22h58m aggregate
// across 452 invocations, ~3m03s each) while producing zero findings on that run.
// Tagged "moderate" they survived even the quick ceiling, which made a "quick"
// scan anything but.
//
// This pins the tier only. It deliberately does NOT assert they are dropped at
// balanced/deep — heavy (rank 3) is below the intrusive ceiling (rank 4), so the
// default scan still runs all four. Retagging trades quick-scan coverage for
// quick-scan speed and changes nothing else.
func TestCostliestModulesAreHeavyTier(t *testing.T) {
	costly := []string{
		"input-behavior-probe",
		"reflected-ssti",
		"suspect-transform",
		"smart-behavior-detection",
		"ssti-blind",
	}

	byID := make(map[string]modules.ActiveModule)
	for _, m := range modules.GetActiveModules() {
		byID[m.ID()] = m
	}

	quick := intensityTierCeiling("quick")
	balanced := intensityTierCeiling("balanced")

	for _, id := range costly {
		m, ok := byID[id]
		if !ok {
			t.Errorf("module %q not found in the active registry", id)
			continue
		}
		rank := modules.ModuleTierRank(m.Tags())
		if rank != modules.TierRankHeavy {
			t.Errorf("module %q tier rank = %d, want heavy (%d); tags=%v",
				id, rank, modules.TierRankHeavy, m.Tags())
		}
		if rank <= quick {
			t.Errorf("module %q (rank %d) must be dropped by the quick ceiling %d", id, rank, quick)
		}
		if rank > balanced {
			t.Errorf("module %q (rank %d) must still run at the balanced ceiling %d", id, rank, balanced)
		}
	}
}
