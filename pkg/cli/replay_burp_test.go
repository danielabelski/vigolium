package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vigolium/vigolium/pkg/burpbridge"
	"github.com/vigolium/vigolium/pkg/replay"
)

func TestSaveReplayResultToBurpSendsMutatedExchange(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"added": 1})
	}))
	defer server.Close()
	client, err := burpbridge.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	rawRequest := []byte("POST /replayed HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\n\r\nx")
	result := &replay.Result{
		RawMutatedRequest: rawRequest,
		Replay: &replay.Summary{
			Status:  201,
			Headers: http.Header{"Content-Type": []string{"text/plain"}},
			RawBody: []byte("saved"),
		},
	}
	src := &replaySource{Scheme: "https", Hostname: "example.test", Port: 443}
	if err := saveReplayResultToBurp(context.Background(), client, src, result); err != nil {
		t.Fatal(err)
	}
	if payload["url"] != "https://example.test:443" || payload["source"] != "vigolium-replay" {
		t.Fatalf("payload = %+v", payload)
	}
	decodedRequest, _ := base64.StdEncoding.DecodeString(payload["http_request_base64"].(string))
	decodedResponse, _ := base64.StdEncoding.DecodeString(payload["http_response_base64"].(string))
	if string(decodedRequest) != string(rawRequest) || string(decodedResponse) != "HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\n\r\nsaved" {
		t.Fatalf("request=%q response=%q", decodedRequest, decodedResponse)
	}
}
