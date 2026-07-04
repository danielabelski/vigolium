package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// TestOverwriteRecordResponseBody verifies the response body is replaced in
// place and every derived field (hash, norm hash, words, content length) is
// recomputed consistently.
func TestOverwriteRecordResponseBody(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	// Seed a JS record with a minified response body.
	minBody := `var a=1;var b=2;function f(x){return x*a+b}console.log(f(3),f(4),f(5));var q="/api/users";fetch(q);`
	rr, err := httpmsg.ParseRawRequest("GET /static/app.js HTTP/1.1\r\nHost: t.example.com\r\n\r\n")
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}
	origResp := httpmsg.NewHttpResponse([]byte(
		"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Encoding: gzip\r\n\r\n" + minBody))
	rr = rr.WithResponse(origResp)
	uuid, err := repo.SaveRecord(ctx, rr, "test", DefaultProjectUUID)
	if err != nil {
		t.Fatalf("SaveRecord: %v", err)
	}

	before, err := repo.GetRecordByUUID(ctx, uuid)
	if err != nil {
		t.Fatalf("GetRecordByUUID(before): %v", err)
	}

	// Overwrite with a beautified, multi-line body (Content-Encoding dropped).
	beaut := "var a = 1;\nvar b = 2;\n\nfunction f(x) {\n  return x * a + b;\n}\n\nconsole.log(f(3), f(4), f(5));\nvar q = \"/api/users\";\nfetch(q);\n"
	newResp := origResp.WithRemovedHeader("Content-Encoding").WithBody([]byte(beaut))
	newRaw := newResp.Raw()

	if err := repo.OverwriteRecordResponseBody(ctx, uuid, newRaw); err != nil {
		t.Fatalf("OverwriteRecordResponseBody: %v", err)
	}

	after, err := repo.GetRecordByUUID(ctx, uuid)
	if err != nil {
		t.Fatalf("GetRecordByUUID(after): %v", err)
	}

	// Raw response replaced exactly.
	if string(after.RawResponse) != string(newRaw) {
		t.Errorf("RawResponse not replaced with the new raw")
	}
	// Response hash = sha256(newRaw).
	want := sha256.Sum256(newRaw)
	if after.ResponseHash != hex.EncodeToString(want[:]) {
		t.Errorf("ResponseHash = %q, want sha256(newRaw)", after.ResponseHash)
	}
	// Content length = new body length.
	if after.ResponseContentLength != int64(len(newResp.Body())) {
		t.Errorf("ResponseContentLength = %d, want %d", after.ResponseContentLength, len(newResp.Body()))
	}
	// Words recomputed against the new body + headers.
	wantWords := countResponseWords(newResp.Body(), newResp.Headers())
	if after.ResponseWords != wantWords {
		t.Errorf("ResponseWords = %d, want %d", after.ResponseWords, wantWords)
	}
	// Derived fields actually changed from the pre-overwrite values.
	if after.ResponseHash == before.ResponseHash {
		t.Error("ResponseHash should change after overwrite")
	}
	if after.ResponseNormHash == before.ResponseNormHash {
		t.Error("ResponseNormHash should be recomputed")
	}
	// Path/URL are preserved (used for the norm hash).
	if after.Path != before.Path || after.URL != before.URL {
		t.Errorf("Path/URL must be preserved: before %q/%q after %q/%q", before.Path, before.URL, after.Path, after.URL)
	}
	// The stored response no longer carries Content-Encoding.
	if strings.Contains(strings.ToLower(string(after.RawResponse)), "content-encoding") {
		t.Error("overwritten response should not carry Content-Encoding")
	}
}

func TestOverwriteRecordResponseBody_Errors(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	if err := repo.OverwriteRecordResponseBody(ctx, "", []byte("x")); err == nil {
		t.Error("expected error for empty uuid")
	}
	if err := repo.OverwriteRecordResponseBody(ctx, "does-not-exist", []byte("HTTP/1.1 200 OK\r\n\r\nx")); err == nil {
		t.Error("expected error for unknown uuid")
	}
}
