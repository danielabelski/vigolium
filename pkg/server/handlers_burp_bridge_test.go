package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func TestHandleBurpSiteMapSnapshotIsIdempotentAndRefreshesResponse(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Post("/api/burp/sitemap/snapshot", h.HandleBurpSiteMapSnapshot)

	request := base64.StdEncoding.EncodeToString([]byte("GET /api HTTP/1.1\r\nHost: example.test\r\n\r\n"))
	firstResponse := base64.StdEncoding.EncodeToString([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nfirst"))
	secondResponse := base64.StdEncoding.EncodeToString([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nchanged"))

	post := func(response string) siteMapSnapshotResponse {
		body, _ := json.Marshal(siteMapSnapshotRequest{Records: []siteMapSnapshotRecord{{
			URL:            "https://example.test/api",
			RequestBase64:  request,
			ResponseBase64: response,
		}}})
		status, raw := doReq(t, app, http.MethodPost, "/api/burp/sitemap/snapshot", string(body), nil)
		if status != http.StatusOK {
			t.Fatalf("snapshot status=%d body=%s", status, raw)
		}
		var result siteMapSnapshotResponse
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}

	if first := post(firstResponse); first.Inserted != 1 {
		t.Fatalf("first snapshot = %+v", first)
	}
	if second := post(secondResponse); second.Updated != 1 {
		t.Fatalf("changed snapshot = %+v", second)
	}
	if third := post(secondResponse); third.Unchanged != 1 {
		t.Fatalf("unchanged snapshot = %+v", third)
	}
}
