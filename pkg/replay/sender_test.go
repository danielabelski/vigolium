package replay

import (
	"context"
	"testing"
)

// TestDoUsesSenderWithoutClient verifies the Sender seam: when a Sender is set,
// Do routes both baseline and replay through it and needs no *http.Client, so a
// via-Burp send reuses the identical mutation/diff logic.
func TestDoUsesSenderWithoutClient(t *testing.T) {
	var sent [][]byte
	opts := Options{
		BaselineRequest: []byte("GET /a?id=1 HTTP/1.1\r\nHost: acme.test\r\n\r\n"),
		Mutations:       []Mutation{{Name: "id", Payload: "9"}},
		Hostname:        "acme.test",
		Scheme:          "https",
		Sender: func(_ context.Context, raw []byte) *Summary {
			sent = append(sent, raw)
			return &Summary{Status: 200, ResponseLen: 2, RawBody: []byte("ok")}
		},
	}
	result, err := Do(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	// Baseline + mutated replay both go through the sender.
	if len(sent) != 2 {
		t.Fatalf("expected 2 sends via Sender, got %d", len(sent))
	}
	if result.Replay == nil || result.Replay.Status != 200 {
		t.Fatalf("replay = %+v", result.Replay)
	}
}

// TestDoRequiresClientOrSender keeps the guard honest: neither set is an error.
func TestDoRequiresClientOrSender(t *testing.T) {
	_, err := Do(context.Background(), Options{
		BaselineRequest: []byte("GET / HTTP/1.1\r\nHost: acme.test\r\n\r\n"),
		Hostname:        "acme.test",
	})
	if err == nil {
		t.Fatal("expected an error when neither Client nor Sender is set")
	}
}

func TestSummaryFromRawResponse(t *testing.T) {
	raw := []byte("HTTP/1.1 201 Created\r\nContent-Length: 3\r\n\r\nabc")
	sum := SummaryFromRawResponse(raw, 201, 7, "", 0)
	if sum.Status != 201 || sum.ResponseLen != 3 || string(sum.RawBody) != "abc" || sum.ResponseTimeMs != 7 {
		t.Fatalf("summary = %+v", sum)
	}
	fail := SummaryFromRawResponse(nil, 0, 5, "boom", 0)
	if fail.Error != "boom" || fail.Status != 0 {
		t.Fatalf("failed summary = %+v", fail)
	}
}
