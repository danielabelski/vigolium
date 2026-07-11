package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestSaveAnalysisArtifactPreservesRawRecord(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	rr, err := httpmsg.ParseRawRequest("GET /app.js HTTP/1.1\r\nHost: example.test\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	rr = rr.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nminified()")))
	recordUUID, err := repo.SaveRecord(ctx, rr, "test", DefaultProjectUUID)
	if err != nil {
		t.Fatal(err)
	}
	original, err := repo.GetRecordByUUID(ctx, recordUUID)
	if err != nil {
		t.Fatal(err)
	}
	rawBefore := append([]byte(nil), original.RawResponse...)

	content := []byte("function readable() { return true; }\n")
	digest := sha256.Sum256(content)
	artifact := &AnalysisArtifact{
		HTTPRecordUUID: recordUUID,
		Kind:           "beautified-source",
		Filename:       "app.js.beautified.js",
		MediaType:      "application/javascript",
		SHA256:         fmt.Sprintf("%x", digest),
		Content:        content,
		Metadata:       `{"format":"webpack"}`,
	}
	if err := repo.SaveAnalysisArtifactForRecord(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	// A repeated content-addressed write must be idempotent.
	if err := repo.SaveAnalysisArtifactForRecord(ctx, artifact); err != nil {
		t.Fatal(err)
	}

	var artifacts []AnalysisArtifact
	if err := db.NewSelect().Model(&artifacts).Where("http_record_uuid = ?", recordUUID).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 1 {
		t.Fatalf("stored %d artifacts, want 1", len(artifacts))
	}
	if !bytes.Equal(artifacts[0].Content, content) || artifacts[0].ProjectUUID != DefaultProjectUUID {
		t.Fatalf("unexpected stored artifact: %#v", artifacts[0])
	}

	after, err := repo.GetRecordByUUID(ctx, recordUUID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after.RawResponse, rawBefore) {
		t.Fatal("derived artifact write mutated the captured raw response")
	}
}
