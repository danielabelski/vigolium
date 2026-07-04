package dependency_confusion

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRegistryLookup_StatusMapping(t *testing.T) {
	cases := []struct {
		status int
		want   resolution
	}{
		{http.StatusOK, resolutionClaimed},
		{http.StatusNotFound, resolutionUnclaimed},
		{http.StatusTooManyRequests, resolutionIndeterminate},
		{http.StatusInternalServerError, resolutionIndeterminate},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.status)
		}))
		rc := newRegistryClient(srv.URL, 5*time.Second)
		got := rc.lookup(context.Background(), "left-pad")
		srv.Close()
		if got != c.want {
			t.Errorf("status %d -> %v, want %v", c.status, got, c.want)
		}
	}
}

func TestRegistryLookup_ScopedEncoding(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	rc := newRegistryClient(srv.URL, 5*time.Second)
	rc.lookup(context.Background(), "@acme/thing")
	if gotPath != "/@acme%2fthing" {
		t.Errorf("scoped name escaping = %q, want /@acme%%2fthing", gotPath)
	}
}

func TestRegistryLookup_NetworkErrorIndeterminate(t *testing.T) {
	// Closed server -> connection error -> indeterminate.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close()
	rc := newRegistryClient(url, 1*time.Second)
	if got := rc.lookup(context.Background(), "left-pad"); got != resolutionIndeterminate {
		t.Errorf("network error -> %v, want indeterminate", got)
	}
}
