package fuzz

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/replay"
)

func TestParseAnomalyThreshold(t *testing.T) {
	for name, want := range map[string]int{
		"":       AnomalyThresholdMedium,
		"low":    AnomalyThresholdLow,
		"medium": AnomalyThresholdMedium,
		"HIGH":   AnomalyThresholdHigh,
	} {
		got, ok := ParseAnomalyThreshold(name)
		if !ok || got != want {
			t.Errorf("ParseAnomalyThreshold(%q) = %d,%v; want %d,true", name, got, ok, want)
		}
	}
	if _, ok := ParseAnomalyThreshold("nonsense"); ok {
		t.Error("unknown threshold name should not parse")
	}
}

// canonicalSQLError is a real MySQL error string. The shared catalog
// (modkit.MatchSQLError) matches on the full phrasing rather than a bare "SQL
// syntax" substring, which is what keeps it from firing on prose.
const canonicalSQLError = "You have an error in your SQL syntax; check the manual that " +
	"corresponds to your MySQL server version for the right syntax to use near '' at line 1"

func TestDetectorScoresErrorSignature(t *testing.T) {
	base := Baseline{Status: 200, Length: 100}
	d := newDetector(DefaultAnomalyConfig(), base, nil, []byte("all fine here"))

	r := Result{Status: 200, Length: 120}
	score, reasons := d.baselineSignals(&r, []byte(canonicalSQLError), nil)

	if score < AnomalyThresholdMedium {
		t.Errorf("an error signature alone should clear the medium threshold, got %d", score)
	}
	if !hasSignal(reasons, "error_signature") {
		t.Errorf("expected an error_signature reason, got %+v", reasons)
	}
}

// An error string already present in the baseline is the endpoint's normal
// output, not a signal the payload produced.
func TestDetectorIgnoresPreexistingErrorSignature(t *testing.T) {
	body := []byte("Warning: mysql_fetch() failed")
	d := newDetector(DefaultAnomalyConfig(), Baseline{Status: 200, Length: 30}, nil, body)

	r := Result{Status: 200, Length: 30}
	_, reasons := d.baselineSignals(&r, body, nil)
	if hasSignal(reasons, "error_signature") {
		t.Errorf("baseline already carried the signature; it is not an anomaly: %+v", reasons)
	}
}

func TestDetectorScoresStatusTransitions(t *testing.T) {
	cases := []struct {
		name       string
		base, got  int
		wantSignal string
	}{
		{"server error", 200, 500, "server_error"},
		{"denied to allowed", 403, 200, "status_now_ok"},
		{"redirect", 200, 302, "status_redirect"},
		{"other change", 200, 404, "status_changed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newDetector(DefaultAnomalyConfig(), Baseline{Status: tc.base, Length: 10}, nil, nil)
			r := Result{Status: tc.got, Length: 10}
			_, reasons := d.baselineSignals(&r, nil, nil)
			if !hasSignal(reasons, tc.wantSignal) {
				t.Errorf("want %s, got %+v", tc.wantSignal, reasons)
			}
		})
	}
}

func TestDetectorHeaderChange(t *testing.T) {
	baseHeaders := http.Header{"Content-Type": {"text/html"}}
	d := newDetector(DefaultAnomalyConfig(), Baseline{Status: 200, Length: 10}, baseHeaders, nil)

	r := Result{Status: 200, Length: 10}
	_, reasons := d.baselineSignals(&r, nil, http.Header{
		"Content-Type": {"text/html"},
		"Location":     {"https://evil.example/"},
	})
	if !hasSignal(reasons, "header_changed") {
		t.Errorf("a new Location header should register, got %+v", reasons)
	}
}

// Population signals must stay quiet until enough samples exist — "rare" among
// three responses is meaningless.
func TestDetectorSuppressesPopulationSignalsWhileSmall(t *testing.T) {
	d := newDetector(AnomalyConfig{Threshold: AnomalyThresholdMedium, MinPopulation: 20},
		Baseline{Status: 200, Length: 100}, nil, nil)

	for i := 0; i < 5; i++ {
		r := Result{Status: 200, Length: 100, ContentHash: "same"}
		d.observe(&r)
	}
	odd := Result{Status: 200, Length: 100000, ContentHash: "unique"}
	_, reasons := d.populationSignals(&odd, d.snapshot(true))
	for _, sig := range []string{"rare_status", "unique_body", "size_outlier"} {
		if hasSignal(reasons, sig) {
			t.Errorf("%s fired below MinPopulation: %+v", sig, reasons)
		}
	}
}

func TestDetectorFlagsSizeOutlierInLargePopulation(t *testing.T) {
	d := newDetector(AnomalyConfig{Threshold: AnomalyThresholdMedium, MinPopulation: 10},
		Baseline{Status: 200, Length: 100}, nil, nil)

	for i := 0; i < 40; i++ {
		r := Result{Status: 200, Length: 100 + i%3, ContentHash: "common"}
		d.observe(&r)
	}
	odd := Result{Status: 200, Length: 90000, ContentHash: "odd"}
	d.observe(&odd)
	_, reasons := d.populationSignals(&odd, d.snapshot(true))
	if !hasSignal(reasons, "size_outlier") {
		t.Errorf("a 900x size deviation should register: %+v", reasons)
	}
}

func TestReflectionDistinguishesRawFromEncoded(t *testing.T) {
	payload := `<script>alert(1)</script>`

	_, raw, where := reflectionOf([]byte("prefix "+payload+" suffix"), nil, payload)
	if !raw {
		t.Error("a verbatim echo should be reported as raw")
	}
	if len(where) != 1 || where[0] != "body" {
		t.Errorf("want [body], got %v", where)
	}

	escaped := "&lt;script&gt;alert(1)&lt;/script&gt;"
	any2, raw2, where2 := reflectionOf([]byte(escaped), nil, payload)
	if !any2 {
		t.Error("an escaped echo is still a reflection")
	}
	if raw2 {
		t.Error("an escaped echo must not be reported as raw — that is the app defending itself")
	}
	if len(where2) != 1 || where2[0] != "body" {
		t.Errorf("want [body], got %v", where2)
	}
}

func TestReflectionFindsHeaderEcho(t *testing.T) {
	payload := "https://evil.example/"
	headers := http.Header{"Location": {payload}}

	any3, raw, where := reflectionOf(nil, headers, payload)
	if !any3 || !raw {
		t.Fatalf("a Location echo should be a raw reflection (any=%v raw=%v)", any3, raw)
	}
	if len(where) != 1 || where[0] != "header:Location" {
		t.Errorf("want [header:Location], got %v", where)
	}
}

func TestReflectionIgnoresShortPayloads(t *testing.T) {
	if any4, _, _ := reflectionOf([]byte("1234"), nil, "1"); any4 {
		t.Error("single-character payloads are reflection noise, not signal")
	}
}

// End to end: one payload out of many produces a 500 with a SQL error, and
// --anomaly finds it with no matchers written at all.
func TestRunAnomalyDetectionEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("q"), "'") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, canonicalSQLError)
			return
		}
		_, _ = fmt.Fprintf(w, "<html><body>normal page for %s</body></html>", r.URL.Query().Get("q"))
	}))
	defer srv.Close()

	host, port := hostPort(t, srv.URL)
	raw := []byte("GET /?q=FUZZ HTTP/1.1\r\nHost: " + host + "\r\n\r\n")

	payloads := []string{"'"}
	for i := 0; i < 20; i++ {
		payloads = append(payloads, fmt.Sprintf("benign%02d", i))
	}

	positions, err := ResolvePositions(raw, Selectors{})
	if err != nil {
		t.Fatalf("ResolvePositions: %v", err)
	}

	cfg := AnomalyConfig{Threshold: AnomalyThresholdMedium, MinPopulation: 10}
	var (
		mu      sync.Mutex
		results []Result
	)
	report, err := Run(context.Background(), Job{
		Raw:         raw,
		Scheme:      "http",
		Hostname:    host,
		Port:        port,
		Positions:   positions,
		Payloads:    payloads,
		Anomaly:     &cfg,
		Client:      replay.NewDefaultClient(nil, 5*time.Second),
		Concurrency: 4,
		OnResult: func(r Result) {
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(payloads) {
		t.Fatalf("streamed %d results, want %d", len(results), len(payloads))
	}

	if len(report.Anomalies) == 0 {
		t.Fatal("expected the SQL-error payload to be flagged")
	}
	top := report.Anomalies[0]
	if top.Payload != "'" {
		t.Errorf("top anomaly should be the quote payload, got %q", top.Payload)
	}
	if !hasSignal(top.AnomalyReasons, "error_signature") {
		t.Errorf("expected an error_signature reason, got %+v", top.AnomalyReasons)
	}
	if !hasSignal(top.AnomalyReasons, "server_error") {
		t.Errorf("expected a server_error reason, got %+v", top.AnomalyReasons)
	}

	// The benign payloads all render a near-identical page; none should clear
	// the threshold, or the detector is just reporting everything.
	for _, a := range report.Anomalies {
		if a.Payload != "'" {
			t.Errorf("benign payload %q was flagged: %+v", a.Payload, a.AnomalyReasons)
		}
	}
	// With no matchers configured, matched tracks the anomaly verdict.
	if report.Matched != len(report.Anomalies) {
		t.Errorf("matched=%d should equal anomalies=%d when no matchers are set",
			report.Matched, len(report.Anomalies))
	}
}

func hasSignal(reasons []AnomalyReason, signal string) bool {
	for _, r := range reasons {
		if r.Signal == signal {
			return true
		}
	}
	return false
}
