package harvester

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaybackClient_Fetch_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "url=*.example.com/*") {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}

		_, _ = fmt.Fprintln(w, "http://example.com/page1")
		_, _ = fmt.Fprintln(w, "http://example.com/page2")
		_, _ = fmt.Fprintln(w, "http://sub.example.com/api/v1")
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 100 * time.Millisecond,
		maxBackoff: 400 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got []string
	for r := range results {
		got = append(got, r.URL)
	}

	expected := []string{
		"http://example.com/page1",
		"http://example.com/page2",
		"http://sub.example.com/api/v1",
	}

	if len(got) != len(expected) {
		t.Errorf("got %d URLs, want %d", len(got), len(expected))
	}

	for i, want := range expected {
		if i >= len(got) {
			break
		}
		if got[i] != want {
			t.Errorf("URL[%d] = %q, want %q", i, got[i], want)
		}
	}
}

func TestWaybackClient_Fetch_StreamsLineByLine(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 1000; i++ {
			_, _ = fmt.Fprintf(w, "http://example.com/page%d\n", i)
		}
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 100 * time.Millisecond,
		maxBackoff: 400 * time.Millisecond,
	}

	results := make(chan Result, 1100)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lineCount := 0
	for range results {
		lineCount++
	}

	if lineCount != 1000 {
		t.Errorf("got %d lines, want 1000", lineCount)
	}
}

func TestWaybackClient_Fetch_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 10000; i++ {
			_, _ = fmt.Fprintf(w, "http://example.com/page%d\n", i)
		}
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 100 * time.Millisecond,
		maxBackoff: 400 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())

	results := make(chan Result, 200)
	go func() {
		count := 0
		for range results {
			count++
			if count >= 100 {
				cancel()
				return
			}
		}
	}()

	err := client.fetch(ctx, "example.com", results, "wayback")
	close(results)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestWaybackClient_Fetch_RateLimit_Retry(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attempts, 1)
		if count < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = fmt.Fprintln(w, "http://example.com/success")
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 50 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got []string
	for r := range results {
		got = append(got, r.URL)
	}

	if len(got) != 1 || got[0] != "http://example.com/success" {
		t.Errorf("unexpected result: %v", got)
	}

	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestWaybackClient_Fetch_MaxRetriesExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 2,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 50 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "max retries exceeded") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWaybackClient_Fetch_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 50 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var apiErr *waybackAPIError
	if !errors.As(err, &apiErr) {
		t.Errorf("expected waybackAPIError, got: %T", err)
	}

	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", apiErr.StatusCode)
	}
}

func TestWaybackClient_Fetch_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 50 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := 0
	for range results {
		count++
	}

	if count != 0 {
		t.Errorf("expected 0 URLs, got %d", count)
	}
}

func TestWaybackClient_Fetch_EmptyLines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "http://example.com/page1")
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintln(w, "http://example.com/page2")
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintln(w, "")
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 50 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got []string
	for r := range results {
		got = append(got, r.URL)
	}

	if len(got) != 2 {
		t.Errorf("expected 2 URLs, got %d: %v", len(got), got)
	}
}

func TestWaybackClient_Fetch_EmptyDomain(t *testing.T) {
	client := newWaybackClient()

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "", results, "wayback")
	close(results)

	if err == nil {
		t.Fatal("expected error for empty domain")
	}

	if !strings.Contains(err.Error(), "domain cannot be empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWaybackClient_BackoffCapped(t *testing.T) {
	var attempts int32
	var timestamps []time.Time

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timestamps = append(timestamps, time.Now())
		count := atomic.AddInt32(&attempts, 1)
		if count < 4 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = fmt.Fprintln(w, "http://example.com/success")
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 5,
		retryDelay: 50 * time.Millisecond,
		maxBackoff: 100 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(timestamps) < 3 {
		t.Fatalf("expected at least 3 attempts, got %d", len(timestamps))
	}

	delay2 := timestamps[2].Sub(timestamps[1])
	delay3 := timestamps[3].Sub(timestamps[2])

	if delay3 > delay2*2 {
		t.Errorf("backoff should be capped: delay2=%v, delay3=%v", delay2, delay3)
	}
}

func TestWaybackSource_Run(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "http://example.com/page1")
		_, _ = fmt.Fprintln(w, "http://example.com/page2")
	}))
	defer server.Close()

	src := &WaybackSource{
		client: &waybackClient{
			httpClient: server.Client(),
			baseURL:    server.URL,
			userAgent:  "test-agent",
			maxRetries: 3,
			retryDelay: 10 * time.Millisecond,
			maxBackoff: 50 * time.Millisecond,
		},
	}

	results := src.Run(context.Background(), "example.com")

	var urls []string
	for r := range results {
		if r.Error != nil {
			t.Fatalf("unexpected error: %v", r.Error)
		}
		urls = append(urls, r.URL)
	}

	if len(urls) != 2 {
		t.Errorf("expected 2 URLs, got %d", len(urls))
	}
}

func TestNewWaybackClient_Defaults(t *testing.T) {
	client := newWaybackClient()

	if client.maxRetries != 3 {
		t.Errorf("expected max retries 3, got %d", client.maxRetries)
	}

	if client.maxBackoff != 4*time.Second {
		t.Errorf("expected max backoff 4s, got %v", client.maxBackoff)
	}

	if client.retryDelay != 1*time.Second {
		t.Errorf("expected retry delay 1s, got %v", client.retryDelay)
	}
}

// --- mining ---------------------------------------------------------------

// waybackMineServer stands in for the archive: a CDX endpoint that answers both
// the domain query and the per-host robots.txt history, plus an `id_` replay
// endpoint serving raw captured bodies.
func waybackMineServer(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/cdx/search/cdx"):
			if strings.Contains(r.URL.RawQuery, "robots.txt") {
				// Two distinct versions, which is what collapse=digest buys.
				_, _ = fmt.Fprintln(w, "https://example.com/robots.txt 20150101000000")
				_, _ = fmt.Fprintln(w, "https://example.com/robots.txt 20230101000000")
				return
			}
			_, _ = fmt.Fprintln(w, "https://example.com/app.js 20200101000000 application/javascript 200")
			_, _ = fmt.Fprintln(w, "https://example.com/ 20200102000000 text/html 200")
			_, _ = fmt.Fprintln(w, "https://example.com/logo.png 20200103000000 image/png 200")

		case strings.Contains(r.URL.Path, "id_/"):
			switch {
			case strings.HasSuffix(r.URL.Path, "robots.txt"):
				_, _ = fmt.Fprint(w, "User-agent: *\nDisallow: /legacy-admin/\nSitemap: https://example.com/sitemap.xml\n")
			case strings.HasSuffix(r.URL.Path, "sitemap.xml"):
				_, _ = fmt.Fprint(w, `<urlset><url><loc>https://example.com/from-sitemap</loc></url></urlset>`)
			case strings.HasSuffix(r.URL.Path, "app.js"):
				_, _ = fmt.Fprint(w, `var api = "/api/v3/internal"; fetch("/api/v3/internal");`)
			default:
				_, _ = fmt.Fprint(w, `<a href="/linked-from-html">x</a>`)
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestWaybackClient_MinesArchivedBodies(t *testing.T) {
	server := waybackMineServer(t)
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 1,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 20 * time.Millisecond,
	}

	results := make(chan Result, 500)
	if err := client.fetch(context.Background(), "example.com", results, "wayback"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	close(results)

	got := make(map[string]Result)
	for r := range results {
		if r.Error != nil {
			t.Fatalf("unexpected result error: %v", r.Error)
		}
		got[r.URL] = r
	}

	// The index rows are still emitted exactly as before.
	for _, want := range []string{
		"https://example.com/app.js",
		"https://example.com/",
		"https://example.com/logo.png",
	} {
		if r, ok := got[want]; !ok {
			t.Errorf("index URL %q missing", want)
		} else if r.Source != "wayback" || r.Mined {
			t.Errorf("index URL %q = %+v, want source \"wayback\" and Mined false", want, r)
		}
	}

	// Everything below exists in no CDX index: a path only robots.txt ever
	// named, a sitemap entry, and an endpoint written inside a script.
	for _, want := range []string{
		"https://example.com/legacy-admin/",
		"https://example.com/from-sitemap",
		"https://example.com/api/v3/internal",
		"https://example.com/linked-from-html",
	} {
		r, ok := got[want]
		if !ok {
			t.Errorf("mined URL %q missing", want)
			continue
		}
		// Provenance is a field, not a synthetic source name: every
		// Result.Source stays equal to some Source.Name().
		if r.Source != "wayback" || !r.Mined {
			t.Errorf("mined URL %q = %+v, want source \"wayback\" and Mined true", want, r)
		}
	}
}

// TestWaybackClient_SkipsMiningWithoutTimestamps locks in the gate that keeps a
// mining pass from firing against an index response that carries no timestamps.
// A replay is addressed by timestamp, so without one there is nothing to fetch —
// and firing anyway would spend a request per host to learn that.
func TestWaybackClient_SkipsMiningWithoutTimestamps(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		_, _ = fmt.Fprintln(w, "https://example.com/page1")
		_, _ = fmt.Fprintln(w, "https://example.com/page2")
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 1,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 20 * time.Millisecond,
	}

	results := make(chan Result, 50)
	if err := client.fetch(context.Background(), "example.com", results, "wayback"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	close(results)

	var count int
	for range results {
		count++
	}

	if count != 2 {
		t.Errorf("got %d URLs, want 2", count)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Errorf("made %d requests, want 1 (mining should not have run)", got)
	}
}

func TestParseCDXLine(t *testing.T) {
	tests := []struct {
		line string
		want cdxRow
	}{
		{
			line: "https://example.com/a 20200101000000 text/html 200",
			want: cdxRow{URL: "https://example.com/a", Timestamp: "20200101000000", MIME: "text/html", Status: "200"},
		},
		// A field list is a request, not a guarantee: a URL-only row still parses.
		{
			line: "https://example.com/a",
			want: cdxRow{URL: "https://example.com/a"},
		},
		{
			line: "https://example.com/a 20200101000000",
			want: cdxRow{URL: "https://example.com/a", Timestamp: "20200101000000"},
		},
		{line: "", want: cdxRow{}},
		{line: "   ", want: cdxRow{}},
	}

	for _, tt := range tests {
		if got := parseCDXLine(tt.line); got != tt.want {
			t.Errorf("parseCDXLine(%q) = %+v, want %+v", tt.line, got, tt.want)
		}
	}
}

func TestSelectRobotsHosts(t *testing.T) {
	rows := []cdxRow{
		{URL: "https://api.example.com/a"},
		{URL: "https://www.example.com/b"},
		{URL: "https://cdn.example.com/c"},
		{URL: "https://elsewhere.net/d"},
	}

	got := selectRobotsHosts(rows, "example.com")

	if len(got) != mineMaxRobotsHosts {
		t.Fatalf("got %d hosts, want %d: %v", len(got), mineMaxRobotsHosts, got)
	}
	// The apex leads: it is the host most likely to have been archived longest.
	if got[0] != "example.com" {
		t.Errorf("expected the apex first, got %v", got)
	}
	for _, host := range got {
		if host == "elsewhere.net" {
			t.Errorf("out-of-scope host selected: %v", got)
		}
	}
}
