package file_upload_scan

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// uploadCtx builds a multipart/form-data POST request (with a file part) aimed
// at the given server URL, suitable for driving ScanPerRequest directly.
func uploadCtx(t testing.TB, serverURL string) *httpmsg.HttpRequestResponse {
	t.Helper()
	u, err := url.Parse(serverURL)
	require.NoError(t, err)
	port, err := strconv.Atoi(u.Port())
	require.NoError(t, err)
	svc, err := httpmsg.NewService(u.Hostname(), port, u.Scheme)
	require.NoError(t, err)

	const boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"photo.jpg\"\r\n" +
		"Content-Type: image/jpeg\r\n\r\n" +
		"binary-image-data\r\n" +
		"--" + boundary + "--\r\n"
	raw := fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: %s\r\n"+
		"Content-Type: multipart/form-data; boundary=%s\r\nContent-Length: %d\r\n\r\n%s",
		u.Host, boundary, len(body), body)

	req := httpmsg.NewHttpRequestWithService(svc, []byte(raw))
	return httpmsg.NewHttpRequestResponse(req, nil)
}

// TestScanPerRequest_UnverifiedUploadDropped ensures a 2xx on the upload
// endpoint alone — with the file NOT retrievable — produces no finding. This is
// the core false-positive the strict verification gate suppresses.
func TestScanPerRequest_UnverifiedUploadDropped(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("upload received"))
			return
		}
		// File is never actually stored/served.
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(uploadCtx(t, srv.URL), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "200 upload with no retrievable file must not fire")
}

// TestScanPerRequest_VerifiedUploadReported ensures a genuinely retrievable
// upload (file served back with our marker) is reported.
func TestScanPerRequest_VerifiedUploadReported(t *testing.T) {
	t.Parallel()
	var lastUpload string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			lastUpload = string(b) // captures the uploaded body incl. the marker
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		// Serve the stored upload back from a common upload dir path.
		if strings.HasPrefix(r.URL.Path, "/uploads/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(lastUpload))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(uploadCtx(t, srv.URL), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "retrievable upload echoing the marker must fire")
	assert.Equal(t, "Arbitrary File Upload", res[0].Info.Name)
	assert.Equal(t, severity.High, res[0].Info.Severity, "a stored-but-not-executed upload is High")
}

// TestScanPerRequest_ExecutedUploadIsRCE models a server that actually executes the
// uploaded PHP: when serving the stored file it evaluates the arithmetic concat, so
// the retrieved body carries the execution signature. The finding is upgraded to
// Critical RCE rather than a plain arbitrary-upload High.
func TestScanPerRequest_ExecutedUploadIsRCE(t *testing.T) {
	t.Parallel()
	var lastUpload string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			lastUpload = string(b)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/uploads/") {
			// Simulate the PHP interpreter evaluating "<marker>".(6*7)."<marker>"
			// into "<marker>42<marker>".
			executed := strings.ReplaceAll(lastUpload, `".(6*7)."`, "42")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(executed))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(uploadCtx(t, srv.URL), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "an executing upload must fire")
	assert.Equal(t, "Arbitrary File Upload to Remote Code Execution", res[0].Info.Name)
	assert.Equal(t, severity.Critical, res[0].Info.Severity)
}
