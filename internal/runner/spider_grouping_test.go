package runner

import (
	"reflect"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestGroupByHostTargets(t *testing.T) {
	tests := []struct {
		name    string
		targets []string
		want    [][]string
	}{
		{
			name:    "empty",
			targets: nil,
			want:    nil,
		},
		{
			name:    "single host stays one group",
			targets: []string{"https://a.test/", "https://a.test/admin", "https://a.test/app"},
			want:    [][]string{{"https://a.test/", "https://a.test/admin", "https://a.test/app"}},
		},
		{
			name: "hosts keep first-appearance order and their own target order",
			targets: []string{
				"https://a.test/one",
				"https://b.test/x",
				"https://a.test/two",
				"https://b.test/y",
			},
			want: [][]string{
				{"https://a.test/one", "https://a.test/two"},
				{"https://b.test/x", "https://b.test/y"},
			},
		},
		{
			name:    "port does not split a host",
			targets: []string{"https://a.test/one", "https://a.test:8443/two"},
			want:    [][]string{{"https://a.test/one", "https://a.test:8443/two"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := groupByHost(tt.targets, httpmsg.HostnameFromURL); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("groupByHost(%v) = %v, want %v", tt.targets, got, tt.want)
			}
		})
	}
}

// A target whose host cannot be parsed must still be crawled — dropping it would
// silently shrink the target list.
func TestGroupByHostKeepsUnparseableTarget(t *testing.T) {
	targets := []string{"https://a.test/one", "not a url", "https://a.test/two"}
	groups := groupByHost(targets, httpmsg.HostnameFromURL)

	total := 0
	for _, g := range groups {
		total += len(g)
	}
	if total != len(targets) {
		t.Fatalf("grouping lost targets: %d in, %d out (%v)", len(targets), total, groups)
	}

	var sawUnparseable bool
	for _, g := range groups {
		for _, target := range g {
			if target == "not a url" {
				sawUnparseable = true
			}
		}
	}
	if !sawUnparseable {
		t.Errorf("unparseable target was dropped: %v", groups)
	}
}

// Grouping must never reorder within a host: the first target of a group seeds
// the shared browser session, and callers rely on the operator's ordering.
func TestGroupByHostPreservesOrderWithinHost(t *testing.T) {
	targets := []string{"https://a.test/3", "https://a.test/1", "https://a.test/2"}
	groups := groupByHost(targets, httpmsg.HostnameFromURL)
	if len(groups) != 1 {
		t.Fatalf("expected one group, got %d", len(groups))
	}
	if !reflect.DeepEqual(groups[0], targets) {
		t.Errorf("order within a host changed: got %v, want %v", groups[0], targets)
	}
}
