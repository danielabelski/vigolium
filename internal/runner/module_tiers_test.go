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
