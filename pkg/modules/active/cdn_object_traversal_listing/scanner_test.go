package cdn_object_traversal_listing

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	objectBody = "\x89PNG\x0d\x0afake image bytes for an object that is not a listing"
	errDoc     = `<?xml version="1.0"?><Error><Code>NoSuchKey</Code><Message>no</Message></Error>`
)

// listingFor builds an S3-compatible ListBucketResult containing the given leaf,
// so the parent-directory semantic confirmation (Certain) fires.
func listingFor(leaf string) string {
	return `<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
		`<Name>bucket</Name>` +
		`<Contents><Key>` + leaf + `</Key></Contents>` +
		`<Contents><Key>sibling-one</Key></Contents>` +
		`<Contents><Key>sibling-two</Key></Contents>` +
		`</ListBucketResult>`
}

// isTraversal reports whether a raw request URI carries a parent-collapse
// (..;) payload, as opposed to a benign control suffix (zz;, not-trav).
func isTraversal(rawURI string) bool {
	u := strings.ToLower(rawURI)
	for _, tok := range []string{"..;", "%2e%2e%3b", "%252e%252e%253b", "..%3b", "%2e%2e;"} {
		if strings.Contains(u, tok) {
			return true
		}
	}
	return false
}

// TestScanPerRequest_DetectsTraversalListing simulates a GCS/TOS-backed object
// proxy where appending a ..; segment collapses to the bucket and returns a
// ListObjects response. The object's own GET is a non-listing image; only the
// ..; family lists; control suffixes 404. Expect a Certain finding.
func TestScanPerRequest_DetectsTraversalListing(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-goog-generation", "1700000000")
		if isTraversal(r.RequestURI) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, listingFor("my-object"))
			return
		}
		if r.URL.Path == "/obj/bucket/my-object" {
			w.Header().Set("Content-Type", "image/png")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, objectBody)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, errDoc)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/obj/bucket/my-object")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a traversal-listing finding")
	assert.Equal(t, "CDN Object-Storage Traversal Listing", res[0].Info.Name)
	assert.Equal(t, severity.High, res[0].Info.Severity)
	assert.Equal(t, severity.Certain, res[0].Info.Confidence, "leaf present in listing should yield Certain")
}

// TestScanPerRequest_CatchAllListingRejected covers the primary false-positive:
// an endpoint that returns a listing for ANY path containing a semicolon. The
// non-collapsing control suffix lists too, so the candidate is rejected.
func TestScanPerRequest_CatchAllListingRejected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-goog-generation", "1")
		// Blanket listing for any semicolon path (including control zz;).
		if strings.Contains(r.RequestURI, ";") {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, listingFor("whatever"))
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, objectBody)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/obj/bucket/my-object")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "catch-all listing (control suffix lists too) must be rejected")
}

// TestScanPerRequest_PublicPrefixListingRejected is the clean-canonical
// regression guard (mirrors the static-root-traversal public-file FP): a bucket
// with anonymous ListObjects enabled lists ANY real directory prefix. The object
// GET is a non-listing image and the non-collapsing control suffixes 404 (so the
// catch-all guard passes), but the ..; token merely collapses to the object's
// parent directory which is ALREADY publicly listable via a plain request to
// /obj/bucket/folder/. No access-control boundary was escaped, so the
// clean-canonical control must drop it.
func TestScanPerRequest_PublicPrefixListingRejected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-goog-generation", "1700000000")
		// A traversal token collapses to a directory prefix -> lists.
		if isTraversal(r.RequestURI) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, listingFor("my-object"))
			return
		}
		// The object itself is a plain non-listing image.
		if r.URL.Path == "/obj/bucket/folder/my-object" {
			w.Header().Set("Content-Type", "image/png")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, objectBody)
			return
		}
		// Real, already-public directory prefixes list on a plain request
		// (anonymous ListObjects enabled) — this is what the ..; token resolves to.
		if r.URL.Path == "/obj/bucket/folder/" || r.URL.Path == "/obj/bucket/" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, listingFor("my-object"))
			return
		}
		// Non-collapsing control suffixes (object keys that don't exist) 404.
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, errDoc)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/obj/bucket/folder/my-object")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a parent prefix already publicly listable via a plain request must not be reported as a traversal bypass")
}

// TestScanPerRequest_BaselineAlreadyListing rejects a path whose own GET already
// returns a listing — that is cloud-storage-listing's finding, not traversal.
func TestScanPerRequest_BaselineAlreadyListing(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("x-goog-generation", "1")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, listingFor("x"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/obj/bucket/my-object")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an already-listing baseline must not be reported as traversal")
}

// TestScanPerRequest_CleanObjectStorage: a well-behaved backend that 404s
// traversal attempts (like S3/Azure/ByteStore) yields no finding.
func TestScanPerRequest_CleanObjectStorage(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-amz-request-id", "ABC")
		if r.URL.Path == "/obj/bucket/my-object" {
			w.Header().Set("Content-Type", "image/png")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, objectBody)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, errDoc)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/obj/bucket/my-object")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a backend that 404s traversal must produce no finding")
}

func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()

	// /obj/ path shape -> processed even with no response.
	storage := modtest.Request(t, "https://cdn.example.com/obj/bucket/object")
	assert.True(t, m.CanProcess(storage))

	// Ordinary app path -> ignored.
	app := modtest.Request(t, "https://app.example.com/api/users/123")
	assert.False(t, m.CanProcess(app))

	// Storage response header on a non-/obj path -> processed.
	req := modtest.Request(t, "https://cdn.example.com/assets/a")
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nx-goog-generation: 1\r\nContent-Length: 1\r\n\r\nx"
	hdr := httpmsg.NewHttpRequestResponse(req.Request(), httpmsg.NewHttpResponse([]byte(rawResp)))
	assert.True(t, m.CanProcess(hdr))
}
