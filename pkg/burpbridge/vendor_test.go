package burpbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

// vendorListener stands in for a bridge listener that echoes (or omits) an
// implementation identity on /search and /inspect.
type vendorListener struct {
	searchImplementation  string
	inspectImplementation string
	searches              int
	inspects              int
}

func (l *vendorListener) start(t *testing.T) *Client {
	t.Helper()
	raw := "GET /live HTTP/1.1\r\nHost: example.test\r\n\r\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/burp-bridge/search":
			l.searches++
			body := map[string]any{
				"total": 1,
				"records": []map[string]any{{
					"ref": "ref-1", "method": "GET", "url": "https://example.test/live",
					"request_hash": "hash-1", "status": 200,
				}},
			}
			if l.searchImplementation != "" {
				body["implementation"] = l.searchImplementation
			}
			_ = json.NewEncoder(w).Encode(body)
		case "/api/burp-bridge/inspect":
			l.inspects++
			body := map[string]any{
				"url":            "https://example.test/live",
				"request_base64": base64.StdEncoding.EncodeToString([]byte(raw)),
			}
			if l.inspectImplementation != "" {
				body["implementation"] = l.inspectImplementation
			}
			_ = json.NewEncoder(w).Encode(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestQueryLabelsRecordsWithReportedVendor(t *testing.T) {
	for _, tc := range []struct {
		name           string
		implementation string
		want           string
	}{
		{"caido", ImplementationCaido, database.RecordSourceCaido},
		{"burp", ImplementationBurp, database.RecordSourceBurp},
		// A listener too old to echo the field is the pre-change Burp jar, which
		// is exactly what every bridge record used to be labelled as.
		{"absent", "", database.RecordSourceBurp},
		// A newer build, or something else entirely on loopback. Falling back
		// rather than trusting it is what keeps a listener from naming a source
		// label with scan-pipeline meaning.
		{"unknown", "vigolium-something-else", database.RecordSourceBurp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := (&vendorListener{searchImplementation: tc.implementation}).start(t)
			result, err := client.Query(context.Background(), Query{ProjectUUID: "p1", Limit: 10})
			if err != nil {
				t.Fatal(err)
			}
			if result.Source != tc.want {
				t.Errorf("Result.Source = %q, want %q", result.Source, tc.want)
			}
			if got := result.Records[0].Source; got != tc.want {
				t.Errorf("record source = %q, want %q", got, tc.want)
			}
			// The vendor rides in the Source column, not the UUID: the prefix is
			// a routing token every bridge record shares.
			if got := result.Records[0].UUID; got != UUIDPrefix+"ref-1" {
				t.Errorf("UUID = %q, want the shared %q prefix", got, UUIDPrefix)
			}
		})
	}
}

// A single-record read has no preceding search to learn the vendor from, so the
// identity has to travel on the inspect reply itself.
func TestStandaloneInspectLabelsFromItsOwnReply(t *testing.T) {
	client := (&vendorListener{inspectImplementation: ImplementationCaido}).start(t)
	record, err := client.Inspect(context.Background(), UUIDPrefix+"ref-1", "p1")
	if err != nil {
		t.Fatal(err)
	}
	if record.Source != database.RecordSourceCaido {
		t.Fatalf("source = %q, want %q", record.Source, database.RecordSourceCaido)
	}
}

// A listener that echoes on /search but not /inspect still labels correctly for
// the rest of the session, which is what the import loop relies on.
func TestInspectInheritsVendorFromEarlierSearch(t *testing.T) {
	client := (&vendorListener{searchImplementation: ImplementationCaido}).start(t)
	if _, err := client.Query(context.Background(), Query{ProjectUUID: "p1", Limit: 10}); err != nil {
		t.Fatal(err)
	}
	record, err := client.Inspect(context.Background(), UUIDPrefix+"ref-1", "p1")
	if err != nil {
		t.Fatal(err)
	}
	if record.Source != database.RecordSourceCaido {
		t.Fatalf("source = %q, want %q", record.Source, database.RecordSourceCaido)
	}
}

func TestInspectWithNothingReportedFallsBackToBurp(t *testing.T) {
	client := (&vendorListener{}).start(t)
	record, err := client.Inspect(context.Background(), UUIDPrefix+"ref-1", "p1")
	if err != nil {
		t.Fatal(err)
	}
	if record.Source != database.RecordSourceBurp {
		t.Fatalf("source = %q, want %q", record.Source, database.RecordSourceBurp)
	}
}

// A reply that omits the field must not erase a vendor an earlier reply
// established — otherwise a mixed-build listener would flip labels mid-import.
func TestOmittedImplementationDoesNotClearResolvedVendor(t *testing.T) {
	client := (&vendorListener{searchImplementation: ImplementationCaido}).start(t)
	if _, err := client.Query(context.Background(), Query{ProjectUUID: "p1", Limit: 10}); err != nil {
		t.Fatal(err)
	}
	if got := client.cachedSource(); got != database.RecordSourceCaido {
		t.Fatalf("cachedSource = %q before inspect", got)
	}
	if _, err := client.Inspect(context.Background(), UUIDPrefix+"ref-1", "p1"); err != nil {
		t.Fatal(err)
	}
	if got := client.cachedSource(); got != database.RecordSourceCaido {
		t.Fatalf("cachedSource = %q after an inspect that reported nothing", got)
	}
}

// Eligibility runs before the request, so it cannot know which vendor will
// answer. Narrowing it to one would make --source caido never issue the query
// that would have proved the listener is Caido.
func TestEligibleAdmitsEveryBridgeVendor(t *testing.T) {
	for _, tc := range []struct {
		source string
		want   bool
	}{
		{"", true},
		{database.RecordSourceBurp, true},
		{database.RecordSourceCaido, true},
		{"CAIDO", true},
		{database.RecordSourceScanner, false},
		{database.RecordSourceIngestCLI, false},
	} {
		if got := Eligible(database.QueryFilters{Source: tc.source}); got != tc.want {
			t.Errorf("Eligible(source=%q) = %v, want %v", tc.source, got, tc.want)
		}
	}
}

func TestMatchesSourceFilter(t *testing.T) {
	for _, tc := range []struct {
		filter, resolved string
		want             bool
	}{
		{"", database.RecordSourceCaido, true},
		{database.RecordSourceCaido, database.RecordSourceCaido, true},
		{"CaIdO", database.RecordSourceCaido, true},
		{database.RecordSourceCaido, database.RecordSourceBurp, false},
		{database.RecordSourceBurp, database.RecordSourceCaido, false},
		// An unresolved vendor is Burp, matching how records are labelled.
		{database.RecordSourceBurp, "", true},
		{database.RecordSourceCaido, "", false},
	} {
		if got := MatchesSourceFilter(tc.filter, tc.resolved); got != tc.want {
			t.Errorf("MatchesSourceFilter(%q, %q) = %v, want %v", tc.filter, tc.resolved, got, tc.want)
		}
	}
}

// Records and Total have to be discarded together: MergePage pages over
// localTotal+liveTotal, so a set dropped without its total reports more records
// than it can show.
func TestFilterBySourceDropsRecordsAndTotalTogether(t *testing.T) {
	live := Result{
		Records: []*database.HTTPRecord{{UUID: UUIDPrefix + "ref-1"}},
		Total:   7,
		Source:  database.RecordSourceCaido,
	}

	if got := live.FilterBySource(database.RecordSourceCaido); got.Total != 7 || len(got.Records) != 1 {
		t.Errorf("matching filter altered the result: %+v", got)
	}
	if got := live.FilterBySource(""); got.Total != 7 || len(got.Records) != 1 {
		t.Errorf("absent filter altered the result: %+v", got)
	}
	dropped := live.FilterBySource(database.RecordSourceBurp)
	if len(dropped.Records) != 0 {
		t.Errorf("records survived a mismatched filter: %+v", dropped.Records)
	}
	if dropped.Total != 0 {
		t.Errorf("Total = %d after a mismatched filter, want 0 — a counted-but-dropped set inflates paging", dropped.Total)
	}
}

func TestVendorNameForSource(t *testing.T) {
	if got := VendorNameForSource(database.RecordSourceCaido); got != "Caido" {
		t.Errorf("caido → %q", got)
	}
	for _, source := range []string{database.RecordSourceBurp, "", "nonsense"} {
		if got := VendorNameForSource(source); got != "Burp" {
			t.Errorf("%q → %q, want Burp", source, got)
		}
	}
}

// Bridge traffic must stay eligible for scan-on-receive. The failure this
// guards is silent: the rows land in the database and the poller simply never
// selects them, with no error explaining why nothing was scanned.
func TestBridgeSourcesAreScanOnReceiveEligible(t *testing.T) {
	eligible := make(map[string]bool, len(database.IngestRecordSources))
	for _, source := range database.IngestRecordSources {
		eligible[source] = true
	}
	for _, source := range database.BridgeRecordSources {
		if !eligible[source] {
			t.Errorf("%q is missing from database.IngestRecordSources", source)
		}
	}
}
