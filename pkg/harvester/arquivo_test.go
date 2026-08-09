package harvester

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestArquivoSource_Run(t *testing.T) {
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = fmt.Fprintln(w, `{"url":"https://www.example.com/","mime":"text/html","status":"200"}`)
		_, _ = fmt.Fprintln(w, `{"url":"https://shop.example.com/cart","mime":"text/html","status":"200"}`)
		// A wildcard query returns neighbours that merely sort nearby, so each
		// row is re-checked rather than trusted.
		_, _ = fmt.Fprintln(w, `{"url":"https://notexample.com/","mime":"text/html","status":"200"}`)
		_, _ = fmt.Fprintln(w, `not json`)
		_, _ = fmt.Fprintln(w, `{"url":""}`)
	}))
	defer server.Close()

	src := &ArquivoSource{client: server.Client(), baseURL: server.URL}

	var got []string
	for r := range src.Run(context.Background(), "example.com") {
		if r.Error != nil {
			t.Fatalf("unexpected error: %v", r.Error)
		}
		got = append(got, r.URL)
	}

	want := []string{"https://www.example.com/", "https://shop.example.com/cart"}
	if len(got) != len(want) {
		t.Fatalf("got %d URLs, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("URL[%d] = %q, want %q", i, got[i], w)
		}
	}

	// The wildcard and slash are load-bearing: the CDX API infers its match type
	// from them, so encoding either changes what the query means.
	if !strings.Contains(gotQuery, "url=*.example.com/*") {
		t.Errorf("scope was encoded away: %s", gotQuery)
	}
}

func TestArquivoSource_ReportsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	src := &ArquivoSource{client: server.Client(), baseURL: server.URL}

	var sawError bool
	for r := range src.Run(context.Background(), "example.com") {
		if r.Error != nil {
			sawError = true
		}
	}
	if !sawError {
		t.Error("expected an error result for a 502")
	}
}

func TestArquivoSource_EmptyDomain(t *testing.T) {
	src := NewArquivoSource()

	for r := range src.Run(context.Background(), "") {
		t.Fatalf("expected no results for an empty domain, got %+v", r)
	}
}

func TestArquivoSource_Metadata(t *testing.T) {
	src := NewArquivoSource()
	if src.Name() != "arquivo" {
		t.Errorf("Name() = %q, want \"arquivo\"", src.Name())
	}
	if src.NeedsKey() {
		t.Error("arquivo should need no API key")
	}
}
