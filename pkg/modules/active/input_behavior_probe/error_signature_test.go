package input_behavior_probe

import "testing"

func TestBodyLeaksServerError(t *testing.T) {
	// Genuine application-error disclosures — a →5xx carrying one of these is a real
	// input-handling lead and must be reported.
	leaks := []string{
		"Traceback (most recent call last):\n  File \"/app/views.py\", line 42, in handler",
		"java.lang.NullPointerException\n\tat com.snap.Web.handle(Web.java:88)",
		"at Object.<anonymous> (/srv/app/server.js:15:3)",
		"PHP Warning: include(): failed to open stream on line 12",
		"You have an error in your SQL syntax; check the manual",
		"ORA-01756: quoted string not properly terminated",
		"goroutine 17 [running]:\nmain.handler()\n\t/app/server.go:42 +0x1a3",
		"NoMethodError: undefined method `foo' for nil",
		"Whoops, looks like something went wrong.",
		"System.NullReferenceException: Object reference not set",
	}
	for _, b := range leaks {
		if !bodyLeaksServerError(b) {
			t.Errorf("expected leak to be detected: %q", b)
		}
	}

	// Generic edge/decoder 5xx bodies — these are the observed false positives and
	// must NOT be treated as an application leak.
	noLeak := []string{
		"",
		"Internal error has occurred",
		"Internal Server Error",
		"<html><body>Internal Server Error</body></html>",
		`{"status":"error","message":"URI malformed"}`,
		"Bad Request",
		"502 Bad Gateway",
		"<html><head><title>Error</title></head><body>The page could not be loaded.</body></html>",
		"Service Temporarily Unavailable",
	}
	for _, b := range noLeak {
		if bodyLeaksServerError(b) {
			t.Errorf("generic edge 5xx must not be reported as a leak: %q", b)
		}
	}
}
