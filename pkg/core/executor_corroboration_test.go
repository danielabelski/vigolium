package core

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/http"
)

const juiceLoginSQLErr = `{"error":{"message":"SQLITE_ERROR: unrecognized token: \"0192023a\"","name":"SequelizeDatabaseError","sql":"SELECT * FROM Users WHERE email = 'admin'' AND password = 'x'"}}`

func newObs(host, url string, req, body string, status int) http.ObservedResponse {
	return http.ObservedResponse{
		Host: host, URL: url, Status: status,
		ContentType: "application/json",
		RequestRaw:  []byte(req), Body: []byte(body),
	}
}

func TestObserveProbeResponse_HarvestsSQLError(t *testing.T) {
	e := &Executor{corroboration: newProbeCorroboration()}
	req := "POST /rest/user/login HTTP/1.1\r\nHost: h\r\n\r\n" + `{"email":"a'","password":"x"}`
	e.observeProbeResponse(newObs("h", "http://h/rest/user/login", req, juiceLoginSQLErr, 500))

	if got := len(e.corroboration.hits); got != 1 {
		t.Fatalf("expected 1 corroboration hit, got %d", got)
	}
	r := e.corroboration.hits[0]
	if r.Info.Name != "Database Error Leaked to Malformed Probe" {
		t.Errorf("unexpected finding name: %q", r.Info.Name)
	}
}

func TestObserveProbeResponse_Dedup(t *testing.T) {
	e := &Executor{corroboration: newProbeCorroboration()}
	req := "GET /rest/x HTTP/1.1\r\n\r\n"
	for i := 0; i < 3; i++ {
		e.observeProbeResponse(newObs("h", "http://h/rest/x", req, juiceLoginSQLErr, 500))
	}
	if got := len(e.corroboration.hits); got != 1 {
		t.Fatalf("expected dedup to 1 hit, got %d", got)
	}
}

func TestObserveProbeResponse_IgnoresNon5xxAndCleanBodies(t *testing.T) {
	// The 5xx gate lives in the HTTP layer (report), but a clean body must not hit.
	e := &Executor{corroboration: newProbeCorroboration()}
	e.observeProbeResponse(newObs("h", "http://h/ok", "GET /ok\r\n\r\n", `{"ok":true}`, 500))
	if got := len(e.corroboration.hits); got != 0 {
		t.Fatalf("clean body must not corroborate, got %d hits", got)
	}
}

func TestObserveProbeResponse_RejectsRequestReflection(t *testing.T) {
	// If the request itself carries the DBMS signature (reflected payload) it is not
	// a server-generated leak. Uses an Oracle-only body so the matched pattern is
	// deterministic (\bORA-\d{5}), and a request that reflects that exact token.
	e := &Executor{corroboration: newProbeCorroboration()}
	body := `<html>ORA-01756: quoted string not properly terminated</html>`
	req := "GET /x?e=ORA-01756 HTTP/1.1\r\n\r\n"
	e.observeProbeResponse(newObs("h", "http://h/x", req, body, 500))
	if got := len(e.corroboration.hits); got != 0 {
		t.Fatalf("request-reflected signature must be rejected, got %d hits", got)
	}
}
