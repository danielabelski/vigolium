package burpbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

type fakeRecordUpserter struct {
	calls   int
	sources []string
}

func (f *fakeRecordUpserter) UpsertSnapshotRecord(
	_ context.Context,
	_ *httpmsg.HttpRequestResponse,
	source string,
	_ string,
) (string, string, error) {
	f.calls++
	f.sources = append(f.sources, source)
	if f.calls == 1 {
		return "db-1", "inserted", nil
	}
	return "db-2", "unchanged", nil
}

func TestImportIntoRepositoryPagesInspectsAndUpserts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/burp-bridge/search":
			var args map[string]any
			if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
				t.Fatal(err)
			}
			offset := int(args["offset"].(float64))
			if offset >= 2 {
				_, _ = w.Write([]byte(`{"total":2,"records":[]}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"total": 2,
				"records": []map[string]any{{
					"ref":          "ref-" + string(rune('1'+offset)),
					"method":       "GET",
					"url":          "https://example.test/item",
					"request_hash": "hash",
					"status":       200,
				}},
			})
		case "/api/burp-bridge/inspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"url": "https://example.test/item",
				"request_base64": base64.StdEncoding.EncodeToString(
					[]byte("GET /item HTTP/1.1\r\nHost: example.test\r\n\r\n")),
				"response_base64": base64.StdEncoding.EncodeToString(
					[]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")),
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
	repo := &fakeRecordUpserter{}
	result, err := ImportIntoRepository(context.Background(), client, repo, Query{}, "project-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Matched != 2 || result.Selected != 2 || result.Inserted != 1 || result.Unchanged != 1 {
		t.Fatalf("result = %+v", result)
	}
	if repo.calls != 2 || repo.sources[0] != Source || repo.sources[1] != Source {
		t.Fatalf("calls=%d sources=%v", repo.calls, repo.sources)
	}
}
