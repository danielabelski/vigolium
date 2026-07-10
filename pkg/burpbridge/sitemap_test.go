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

func TestAddToSiteMapUsesIngestCompatiblePayload(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/burp-bridge/sitemap" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"added": 1, "url": payload["url"]})
	}))
	defer server.Close()

	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	request := []byte("GET /saved HTTP/1.1\r\nHost: example.test\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	if err := client.AddToSiteMap(context.Background(), "https://example.test/saved", request, response, "test"); err != nil {
		t.Fatal(err)
	}
	if payload["input_mode"] != "burp_base64" || payload["source"] != "test" {
		t.Fatalf("payload = %+v", payload)
	}
	if payload["http_request_base64"] != base64.StdEncoding.EncodeToString(request) ||
		payload["http_response_base64"] != base64.StdEncoding.EncodeToString(response) {
		t.Fatalf("encoded payload = %+v", payload)
	}
}

func TestSaveRecordsToSiteMapContinuesAfterInvalidRecord(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"added": 1})
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	result := client.SaveRecordsToSiteMap(context.Background(), []*database.HTTPRecord{
		{URL: "https://example.test/ok", RawRequest: []byte("GET /ok HTTP/1.1\r\nHost: example.test\r\n\r\n")},
		{URL: "https://example.test/missing"},
	})
	if result.Selected != 2 || result.Added != 1 || result.Skipped != 1 {
		t.Fatalf("result = %+v", result)
	}
}
