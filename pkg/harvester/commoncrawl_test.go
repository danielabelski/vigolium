package harvester

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// gzipWARCRecord builds one gzip member holding a WARC response record, which is
// exactly what a ranged read of a real WARC file returns.
func gzipWARCRecord(t *testing.T, targetURI, body string) []byte {
	t.Helper()

	record := "WARC/1.0\r\n" +
		"WARC-Type: response\r\n" +
		"WARC-Target-URI: " + targetURI + "\r\n" +
		"Content-Type: application/http; msgtype=response\r\n" +
		"\r\n" +
		"HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		body

	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write([]byte(record)); err != nil {
		t.Fatalf("write record: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return buf.Bytes()
}

func TestWARCResponseBody(t *testing.T) {
	record := []byte("WARC/1.0\r\nWARC-Type: response\r\n\r\nHTTP/1.1 200 OK\r\nX: y\r\n\r\n<html>body</html>")
	if got := string(warcResponseBody(record)); got != "<html>body</html>" {
		t.Errorf("got %q, want %q", got, "<html>body</html>")
	}

	// Some writers emit bare LF rather than CRLF.
	lf := []byte("WARC/1.0\nWARC-Type: response\n\nHTTP/1.1 200 OK\n\n<html>lf</html>")
	if got := string(warcResponseBody(lf)); got != "<html>lf</html>" {
		t.Errorf("got %q, want %q", got, "<html>lf</html>")
	}

	// A truncated record has no second block, and returning its headers as a
	// body would mine the WARC's own metadata.
	if got := warcResponseBody([]byte("WARC/1.0\r\nWARC-Type: response\r\n\r\nHTTP/1.1 200 OK")); got != nil {
		t.Errorf("expected nil for a truncated record, got %q", got)
	}
	if got := warcResponseBody([]byte("no separators at all")); got != nil {
		t.Errorf("expected nil for a malformed record, got %q", got)
	}
}

func TestCommonCrawlSource_MinesWARCRecords(t *testing.T) {
	warc := gzipWARCRecord(t, "https://example.com/",
		`<a href="/only-in-the-body">x</a><script src="https://cdn.example.com/app.js"></script>`)

	var rangeHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "collinfo.json"):
			_, _ = fmt.Fprintf(w, `[{"id":"CC-MAIN-%d-01","cdx-api":"%s/index"}]`,
				time.Now().Year(), "http://"+r.Host)

		case strings.HasSuffix(r.URL.Path, "/index"):
			_, _ = fmt.Fprintf(w,
				`{"url":"https://example.com/","mime":"text/html","status":"200","filename":"crawl/seg.warc.gz","offset":"0","length":"%d"}`+"\n",
				len(warc))
			_, _ = fmt.Fprintln(w,
				`{"url":"https://example.com/logo.png","mime":"image/png","status":"200","filename":"crawl/seg.warc.gz","offset":"0","length":"10"}`)
			_, _ = fmt.Fprintln(w, `{"error":"no captures"}`)

		case strings.Contains(r.URL.Path, "seg.warc.gz"):
			rangeHeader = r.Header.Get("Range")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(warc)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	src := &CommonCrawlSource{
		client:   server.Client(),
		indexURL: server.URL + "/collinfo.json",
		dataURL:  server.URL + "/",
	}

	got := make(map[string]Result)
	for r := range src.Run(context.Background(), "example.com") {
		if r.Error != nil {
			t.Fatalf("unexpected error: %v", r.Error)
		}
		got[r.URL] = r
	}

	// A ranged read is the whole point: without it the request would pull the
	// entire multi-gigabyte WARC file.
	if want := fmt.Sprintf("bytes=0-%d", len(warc)-1); rangeHeader != want {
		t.Errorf("Range header = %q, want %q", rangeHeader, want)
	}

	if r, ok := got["https://example.com/"]; !ok || r.Source != "commoncrawl" || r.Mined {
		t.Errorf("index URL missing or mistagged: %+v", r)
	}
	// An index row carrying an error field is bookkeeping, not a capture.
	if _, ok := got[""]; ok {
		t.Error("error row emitted as a capture")
	}

	for _, want := range []string{
		"https://example.com/only-in-the-body",
		"https://cdn.example.com/app.js",
	} {
		r, ok := got[want]
		if !ok {
			t.Errorf("mined URL %q missing (got %v)", want, got)
			continue
		}
		if r.Source != "commoncrawl" || !r.Mined {
			t.Errorf("mined URL %q = %+v, want source \"commoncrawl\" and Mined true", want, r)
		}
	}
}

func TestCommonCrawlSource_IgnoresNonPartialResponse(t *testing.T) {
	// A server that ignores the Range header answers 200 with the whole file.
	// Reading that as a record would be a multi-gigabyte transfer, so it is
	// refused rather than parsed.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("whole file"))
	}))
	defer server.Close()

	src := &CommonCrawlSource{client: server.Client(), dataURL: server.URL + "/"}

	got := src.fetchWARCRecord(context.Background(), cdxRow{
		URL:      "https://example.com/",
		Filename: "seg.warc.gz",
		Offset:   "0",
		Length:   "10",
	})
	if got != nil {
		t.Errorf("expected nil for a non-206 response, got %q", got)
	}
}

func TestCommonCrawlSource_RejectsUnusableRanges(t *testing.T) {
	src := &CommonCrawlSource{client: http.DefaultClient, dataURL: "http://127.0.0.1:1/"}

	tests := []cdxRow{
		{Filename: "a.warc.gz", Offset: "not-a-number", Length: "10"},
		{Filename: "a.warc.gz", Offset: "0", Length: "not-a-number"},
		{Filename: "a.warc.gz", Offset: "0", Length: "0"},
		// A length beyond the body ceiling would be truncated on read, leaving a
		// gzip stream that cannot inflate.
		{Filename: "a.warc.gz", Offset: "0", Length: strconv.Itoa(mineMaxBodyBytes + 1)},
	}

	for _, row := range tests {
		if got := src.fetchWARCRecord(context.Background(), row); got != nil {
			t.Errorf("expected nil for %+v, got %q", row, got)
		}
	}
}
