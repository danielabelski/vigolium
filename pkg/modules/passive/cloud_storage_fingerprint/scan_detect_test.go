package cloud_storage_fingerprint

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// makeCtx builds a request/response pair from raw response headers and body.
func makeCtx(path, headers, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\n%s\r\n\r\n%s", headers, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_S3HeadersOnly verifies that a response carrying only AWS S3
// provider/Server headers — with no request host or body URL naming a bucket —
// yields no finding. Header presence merely means content is served through
// S3/CloudFront, which is ubiquitous noise, so it must not raise on its own.
func TestScanPerRequest_S3HeadersOnly(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Server: AmazonS3\r\nx-amz-request-id: 1A2B3C4D5E6F\r\nContent-Type: text/plain"
	ctx := makeCtx("/object.txt", headers, "data")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_S3HostReports drives a request whose host is a raw S3 bucket
// endpoint, which discloses the bucket and should report — with the Server header
// carried along as corroboration.
func TestScanPerRequest_S3HostReports(t *testing.T) {
	t.Parallel()
	m := New()
	rawReq := []byte("GET /object.txt HTTP/1.1\r\nHost: my-bucket.s3.amazonaws.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("my-bucket.s3.amazonaws.com", 443, true),
		rawReq,
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nServer: AmazonS3\r\nContent-Type: text/plain\r\n\r\ndata"))
	ctx := httpmsg.NewHttpRequestResponse(req, resp)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "Cloud Storage Detected")
	assert.Contains(t, results[0].ExtractedResults, "Host: my-bucket.s3.amazonaws.com")
	// The Server header rides along as corroboration once a bucket is disclosed.
	assert.Contains(t, results[0].ExtractedResults, "Server: AmazonS3")
}

// TestScanPerRequest_AzureBlobURLInBody drives a body containing an Azure Blob
// Storage URL, which should detect the Azure provider.
func TestScanPerRequest_AzureBlobURLInBody(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"asset": "https://myaccount.blob.core.windows.net/container/file.png"}`
	ctx := makeCtx("/api/asset", "Content-Type: application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_NoCloudStorage verifies a benign nginx response yields no
// findings.
func TestScanPerRequest_NoCloudStorage(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeCtx("/", "Server: nginx\r\nContent-Type: text/html", "<html><body>Hello</body></html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
