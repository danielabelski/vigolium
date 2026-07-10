package vigtool

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExecuteBurpCommandCallsLoopbackListener(t *testing.T) {
	var gotPath string
	var gotArgs map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotArgs); err != nil {
			t.Errorf("decode args: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"returned":1,"records":[{"ref":"r1"}]}`))
	}))
	defer server.Close()
	t.Setenv("VIGOLIUM_BURP_BRIDGE_URL", server.URL)

	result, err := executeBurpCommand(
		context.Background(), nil, "search_burp_items", map[string]any{"host": "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content)
	}
	if gotPath != "/api/burp-bridge/search" || gotArgs["host"] != "example.test" {
		t.Fatalf("path=%q args=%v", gotPath, gotArgs)
	}
}

func TestBurpBridgeBaseURLRejectsNonLoopback(t *testing.T) {
	t.Setenv("VIGOLIUM_BURP_BRIDGE_URL", "http://example.com:9009")
	if _, err := burpBridgeBaseURL(); err == nil {
		t.Fatal("expected non-loopback URL to be rejected")
	}
}
