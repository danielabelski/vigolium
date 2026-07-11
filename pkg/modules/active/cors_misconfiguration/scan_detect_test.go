package cors_misconfiguration

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

// reflectingServer echoes the request Origin into Access-Control-Allow-Origin and
// returns the given status. It models a CORS-reflecting backend.
func reflectingServer(status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
		}
		w.WriteHeader(status)
	}))
}

// TestScanPerHost_ReflectedOrigin drives a backend that reflects any Origin on a
// 200 response. The fresh-canary confirmation succeeds, so a finding is emitted.
func TestScanPerHost_ReflectedOrigin(t *testing.T) {
	t.Parallel()
	srv := reflectingServer(http.StatusOK)
	defer srv.Close()

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a 2xx backend reflecting arbitrary Origin must be reported")
	names := make([]string, 0, len(res))
	for _, r := range res {
		names = append(names, r.Info.Name)
	}
	assert.Contains(t, names, "CORS Misconfiguration: Reflected Origin")
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind, "reflection without protected credentialed content is a candidate")
}

func TestScanPerRequest_CredentialedSensitiveResponseConfirmed(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if r.Header.Get("Cookie") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("authentication required"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"account":"alice","balance":4200,"private":true}`))
	}))
	defer srv.Close()

	req := modtest.Request(t, srv.URL+"/account").Request().WithAddedHeader("Cookie", "session=secret")
	rr := httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: session=secret; Path=/; SameSite=None; Secure; HttpOnly\r\n\r\n{}")))
	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, output.RecordKindFinding, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeBypass, res[0].EvidenceGrade)
}

func TestScanPerRequest_UnknownCookiePolicyRemainsCandidate(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if r.Header.Get("Cookie") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("authentication required"))
			return
		}
		_, _ = w.Write([]byte(`{"account":"alice","private":true}`))
	}))
	defer srv.Close()

	req := modtest.Request(t, srv.URL+"/account").Request().WithAddedHeader("Cookie", "session=secret")
	rr := httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}")))
	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind)
	assert.NotEqual(t, output.EvidenceGradeBypass, res[0].EvidenceGrade)
}

func TestScanPerRequest_SameSiteSessionRemainsCandidate(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if r.Header.Get("Cookie") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("authentication required"))
			return
		}
		_, _ = w.Write([]byte(`{"account":"alice","private":true}`))
	}))
	defer srv.Close()

	req := modtest.Request(t, srv.URL+"/account").Request().WithAddedHeader("Cookie", "session=secret")
	rr := httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: session=secret; Path=/; SameSite=Lax; Secure; HttpOnly\r\n\r\n{}")))
	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind, "a browser cannot attach a Lax session cookie to the attacker's fetch")
}

func TestScanPerRequest_WildcardCredentialsIsObservation(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		_, _ = w.Write([]byte("public response body"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, output.RecordKindObservation, res[0].RecordKind)
}

// TestScanPerHost_ReflectedOnErrorOnly ensures a reflected ACAO on a non-2xx
// (error) response is NOT reported — the status gate drops it.
func TestScanPerHost_ReflectedOnErrorOnly(t *testing.T) {
	t.Parallel()
	srv := reflectingServer(http.StatusForbidden)
	defer srv.Close()

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a reflected ACAO on a 403 must not be reported")
}

// TestScanPerHost_NoCORS ensures a backend that never sets ACAO yields nothing.
func TestScanPerHost_NoCORS(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}
