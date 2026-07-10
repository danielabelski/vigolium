package burpbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientQueryAndInspect(t *testing.T) {
	rawRequest := "GET /live HTTP/1.1\r\nHost: example.test\r\n\r\n"
	rawResponse := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/burp-bridge/search":
			var args map[string]any
			if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
				t.Fatal(err)
			}
			if args["location"] != "proxy_history" {
				t.Errorf("location = %v", args["location"])
			}
			_, _ = w.Write([]byte(`{"total":1,"records":[{"ref":"ref-1","method":"GET","url":"https://example.test/live","request_hash":"hash-1","status":200,"mime_type":"TEXT"}]}`))
		case "/api/burp-bridge/inspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"url":             "https://example.test/live",
				"request_base64":  base64.StdEncoding.EncodeToString([]byte(rawRequest)),
				"response_base64": base64.StdEncoding.EncodeToString([]byte(rawResponse)),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Query(context.Background(), Query{ProjectUUID: "p1", IncludeRaw: true, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 || len(result.Records) != 1 {
		t.Fatalf("result = %+v", result)
	}
	record := result.Records[0]
	if record.Source != Source || !strings.HasPrefix(record.UUID, UUIDPrefix) {
		t.Fatalf("source=%q uuid=%q", record.Source, record.UUID)
	}
	if record.RequestHash == "" {
		t.Fatalf("request hash = %q", record.RequestHash)
	}
	if record.Hostname != "example.test" || record.Path != "/live" || string(record.RawRequest) != rawRequest {
		t.Fatalf("record = %+v raw=%q", record, record.RawRequest)
	}
}

func TestValidateURLRejectsNonLoopback(t *testing.T) {
	if _, err := ValidateURL("http://example.com:9009"); err == nil {
		t.Fatal("expected non-loopback URL rejection")
	}
}

func TestClientInspectAcceptsLegacyTextFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"url":      "http://legacy.test/path",
			"request":  "GET /path HTTP/1.1\r\nHost: legacy.test\r\n\r\n",
			"response": "HTTP/1.1 204 No Content\r\n\r\n",
		})
	}))
	defer server.Close()

	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	record, err := client.Inspect(context.Background(), UUIDPrefix+"legacy", "p1")
	if err != nil {
		t.Fatal(err)
	}
	if record.Source != Source || record.Hostname != "legacy.test" || record.StatusCode != 204 {
		t.Fatalf("record = %+v", record)
	}
}
