package harvester

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestURLScanSource_QueriesPageDomain(t *testing.T) {
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = fmt.Fprint(w, `{"results":[],"has_more":false}`)
	}))
	defer server.Close()

	src := &URLScanSource{apiKey: "k", client: server.Client(), baseURL: server.URL}

	for range src.Run(context.Background(), "example.com") { //nolint:revive // draining
	}

	// A bare `domain:` matches every domain a scan contacted, so a page that
	// merely loaded a script from the target is a hit — paid for in pagination,
	// then discarded downstream for being out of scope.
	if !strings.Contains(gotQuery, "page.domain%3Aexample.com") && !strings.Contains(gotQuery, "page.domain:example.com") {
		t.Errorf("expected a page.domain query, got %q", gotQuery)
	}
	if strings.Contains(gotQuery, "size=10000") {
		t.Errorf("page size above the API ceiling: %q", gotQuery)
	}
}

func TestURLScanSource_EmitsPageAndTaskURLs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"results":[
			{"page":{"url":"https://example.com/landed"},"task":{"url":"https://example.com/submitted"},"sort":[1700000000000,"abc"]}
		],"has_more":false}`)
	}))
	defer server.Close()

	src := &URLScanSource{apiKey: "k", client: server.Client(), baseURL: server.URL}

	got := make(map[string]bool)
	for r := range src.Run(context.Background(), "example.com") {
		if r.Error != nil {
			t.Fatalf("unexpected error: %v", r.Error)
		}
		got[r.URL] = true
	}

	// A redirect chain contributes both ends: what was submitted and where it
	// ended up.
	for _, want := range []string{"https://example.com/landed", "https://example.com/submitted"} {
		if !got[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
}

// TestURLScanCursor covers the sort values urlscan actually returns. The
// previous implementation asserted the first value was a float64, so a string
// there panicked the whole harvest rather than ending one source.
func TestURLScanCursor(t *testing.T) {
	tests := []struct {
		name string
		sort string
		want string
	}{
		{"number and string", `[1700000000000,"abc"]`, "1700000000000,abc"},
		{"all strings", `["2023-11-14","abc"]`, "2023-11-14,abc"},
		{"single value", `[1700000000000]`, "1700000000000"},
		{"empty", `[]`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sort []json.RawMessage
			if err := json.Unmarshal([]byte(tt.sort), &sort); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := urlscanCursor(sort); got != tt.want {
				t.Errorf("urlscanCursor(%s) = %q, want %q", tt.sort, got, tt.want)
			}
		})
	}
}

// TestURLScanSource_StopsOnRepeatedCursor guards the pagination loop: a server
// that keeps reporting has_more while returning the same cursor would otherwise
// spin forever.
func TestURLScanSource_StopsOnRepeatedCursor(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = fmt.Fprint(w, `{"results":[
			{"page":{"url":"https://example.com/a"},"sort":[1,"x"]}
		],"has_more":true}`)
	}))
	defer server.Close()

	src := &URLScanSource{apiKey: "k", client: server.Client(), baseURL: server.URL}

	for range src.Run(context.Background(), "example.com") { //nolint:revive // draining
	}

	if calls > 2 {
		t.Errorf("made %d requests, want at most 2", calls)
	}
}
