package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"

	"github.com/vigolium/vigolium/pkg/database"
)

// ingestOne pushes one record through POST /api/ingest-http with the given
// headers and returns the source label the row was stored with.
func ingestOne(t *testing.T, path string, headers map[string]string) string {
	t.Helper()
	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{DisableFetchResponse: true}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Post("/api/ingest-http", h.HandleIngestHTTP)

	raw := "GET " + path + " HTTP/1.1\r\nHost: ingest.test\r\n\r\n"
	body, _ := json.Marshal(map[string]any{
		"input_mode":          "burp_base64",
		"http_request_base64": base64.StdEncoding.EncodeToString([]byte(raw)),
		"http_response_base64": base64.StdEncoding.EncodeToString(
			[]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")),
	})
	if status, out := doReq(t, app, http.MethodPost, "/api/ingest-http", string(body), headers); status != http.StatusOK {
		t.Fatalf("ingest status=%d body=%s", status, out)
	}

	records, err := repo.GetRecordsByHostname(context.Background(), database.DefaultProjectUUID, "ingest.test", 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if record.Path == path {
			return record.Source
		}
	}
	t.Fatalf("no record stored for %s (got %d records)", path, len(records))
	return ""
}

func TestIngestSourceHeaderLabelsThePushingTool(t *testing.T) {
	if got := ingestOne(t, "/caido", map[string]string{IngestSourceHeader: "caido"}); got != database.RecordSourceCaido {
		t.Errorf("source = %q, want %q", got, database.RecordSourceCaido)
	}
	// Case-insensitive: the header is written by plugins, not typed by hand,
	// but a vendor spelling it Caido should not silently fall back.
	if got := ingestOne(t, "/caido-caps", map[string]string{IngestSourceHeader: "CAIDO"}); got != database.RecordSourceCaido {
		t.Errorf("source = %q, want %q", got, database.RecordSourceCaido)
	}
}

func TestIngestWithoutSourceHeaderKeepsIngestServer(t *testing.T) {
	if got := ingestOne(t, "/plain", nil); got != database.RecordSourceIngestServer {
		t.Errorf("source = %q, want %q", got, database.RecordSourceIngestServer)
	}
}

// The allowlist is the point of the header, not a formality: http_records.source
// decides which rows scan-on-receive feeds back into a running scan and which
// the executor treats as its own artefacts. A client able to claim "scanner"
// could silently exclude its own traffic from the scan it just asked for.
func TestIngestSourceHeaderRejectsPipelineMeaningfulLabels(t *testing.T) {
	for _, declared := range []string{
		database.RecordSourceScanner,
		database.RecordSourceFinding,
		database.RecordSourceIngestProxy,
		database.RecordSourceIngestCLI,
		"../../etc/passwd",
		"seed",
	} {
		got := ingestOne(t, "/rejected-"+declared, map[string]string{IngestSourceHeader: declared})
		if got != database.RecordSourceIngestServer {
			t.Errorf("declared %q → stored %q, want the %q fallback",
				declared, got, database.RecordSourceIngestServer)
		}
	}
}
