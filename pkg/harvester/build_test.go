package harvester

import "testing"

func sourceNames(sources []Source) []string {
	names := make([]string, len(sources))
	for i, s := range sources {
		names[i] = s.Name()
	}
	return names
}

func TestBuildSourcesKeylessDefaults(t *testing.T) {
	got := sourceNames(BuildSources(
		[]string{"wayback", "commoncrawl", "alienvault", "arquivo"},
		SourceKeys{}, ""))
	want := []string{"wayback", "commoncrawl", "alienvault", "arquivo"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("position %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestBuildSourcesSkipsKeyedWithoutKey(t *testing.T) {
	// urlscan/virustotal must be dropped when their credential is empty rather
	// than constructed with no key.
	got := sourceNames(BuildSources(
		[]string{"wayback", "urlscan", "virustotal"},
		SourceKeys{}, ""))
	if len(got) != 1 || got[0] != "wayback" {
		t.Fatalf("expected only wayback, got %v", got)
	}
}

func TestBuildSourcesIncludesKeyedWithKey(t *testing.T) {
	got := sourceNames(BuildSources(
		[]string{"urlscan", "virustotal"},
		SourceKeys{URLScan: "k1", VirusTotal: "k2"}, ""))
	if len(got) != 2 {
		t.Fatalf("expected both keyed sources, got %v", got)
	}
}

func TestBuildSourcesIgnoresUnknown(t *testing.T) {
	got := sourceNames(BuildSources([]string{"wayback", "nope", ""}, SourceKeys{}, ""))
	if len(got) != 1 || got[0] != "wayback" {
		t.Fatalf("expected only wayback, got %v", got)
	}
}
