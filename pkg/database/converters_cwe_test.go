package database

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestCWEFromMetadata(t *testing.T) {
	cases := []struct {
		name string
		meta map[string]interface{}
		want string
	}{
		{"nil map", nil, ""},
		{"absent key", map[string]interface{}{"other": "x"}, ""},
		{"string value", map[string]interface{}{"cwe": "CWE-79"}, "CWE-79"},
		{"trimmed", map[string]interface{}{"cwe": "  CWE-862 "}, "CWE-862"},
		{"string slice", map[string]interface{}{"cwe": []string{"CWE-79", "CWE-80"}}, "CWE-79, CWE-80"},
		{"iface slice", map[string]interface{}{"cwe": []interface{}{"CWE-200", "", "CWE-201"}}, "CWE-200, CWE-201"},
		{"wrong type", map[string]interface{}{"cwe": 79}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cweFromMetadata(tc.meta); got != tc.want {
				t.Errorf("cweFromMetadata(%v) = %q, want %q", tc.meta, got, tc.want)
			}
		})
	}
}

// TestFinding_FromResultEvent_PopulatesCWE verifies native module results now
// carry their CWE into the finding's cwe_id column (previously dropped: the
// column existed but FromResultEvent never read Metadata["cwe"]).
func TestFinding_FromResultEvent_PopulatesCWE(t *testing.T) {
	event := &output.ResultEvent{
		ModuleID: "client-auth-guard",
		Info: output.Info{
			Name:       "Client Auth Guard",
			Severity:   severity.Medium,
			Confidence: severity.Firm,
		},
		URL:      "https://app.example.com/",
		Metadata: map[string]interface{}{"cwe": "CWE-862"},
	}

	var f Finding
	if err := f.FromResultEvent(event); err != nil {
		t.Fatalf("FromResultEvent: %v", err)
	}
	if f.CWEID != "CWE-862" {
		t.Errorf("CWEID = %q, want CWE-862", f.CWEID)
	}

	// A result with no CWE metadata leaves the column empty (no regression).
	var f2 Finding
	if err := f2.FromResultEvent(&output.ResultEvent{
		ModuleID: "x",
		Info:     output.Info{Name: "x", Severity: severity.Info, Confidence: severity.Firm},
		URL:      "https://app.example.com/",
	}); err != nil {
		t.Fatalf("FromResultEvent (no cwe): %v", err)
	}
	if f2.CWEID != "" {
		t.Errorf("CWEID = %q, want empty", f2.CWEID)
	}
}
