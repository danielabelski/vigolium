package httpmsg

import (
	"fmt"
	"strings"
	"testing"
)

// TestCreateAllInsertionPoints_PriorityOrdering verifies that insertion points are
// returned in injection-likelihood order — query params, then body params, then
// cookies, then headers — so a whole-request module tests the highest-value points
// first (and an early-confirmed finding survives a truncated loop).
func TestCreateAllInsertionPoints_PriorityOrdering(t *testing.T) {
	raw := "POST /catalog?category=Books HTTP/1.1\r\n" +
		"Host: shop.example.com\r\n" +
		"Cookie: session=abc; category=Accompaniments\r\n" +
		"Referer: https://shop.example.com/\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"\r\n" +
		"q=widgets&sort=asc"

	points, err := CreateAllInsertionPoints([]byte(raw), true)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints() error = %v", err)
	}

	// Priority must be non-decreasing across the whole slice.
	lastPrio := -1
	sawURL, sawBody, sawCookie, sawHeader := false, false, false, false
	for i, ip := range points {
		p := insertionPointPriority(ip.Type())
		if p < lastPrio {
			t.Fatalf("point %d (%s type=%d prio=%d) is out of priority order after prio=%d",
				i, ip.Name(), ip.Type(), p, lastPrio)
		}
		lastPrio = p
		switch ip.Type() {
		case INS_PARAM_URL:
			sawURL = true
		case INS_PARAM_BODY:
			sawBody = true
		case INS_PARAM_COOKIE:
			sawCookie = true
		case INS_HEADER:
			sawHeader = true
		}
	}
	if !sawURL || !sawBody || !sawCookie || !sawHeader {
		t.Fatalf("expected all of url/body/cookie/header points; got url=%v body=%v cookie=%v header=%v",
			sawURL, sawBody, sawCookie, sawHeader)
	}

	// The very first point must be a query param (highest priority present here).
	if points[0].Type() != INS_PARAM_URL {
		t.Fatalf("expected first insertion point to be a query param, got type=%d name=%q",
			points[0].Type(), points[0].Name())
	}

	// Every header point must come after every non-header point.
	firstHeader := -1
	for i, ip := range points {
		if ip.Type() == INS_HEADER {
			firstHeader = i
			break
		}
	}
	for i := firstHeader; i < len(points); i++ {
		if points[i].Type() != INS_HEADER {
			t.Fatalf("non-header point %q (type=%d) appears at %d, after headers began at %d",
				points[i].Name(), points[i].Type(), i, firstHeader)
		}
	}
}

// TestCreateAllInsertionPoints_HeaderCap verifies the header fan-out is bounded so a
// request with an outsized header block can't multiply a module's work unboundedly.
func TestCreateAllInsertionPoints_HeaderCap(t *testing.T) {
	var b strings.Builder
	b.WriteString("GET /?x=1 HTTP/1.1\r\nHost: h.example.com\r\n")
	for i := 0; i < maxHeaderInsertionPoints*2; i++ {
		fmt.Fprintf(&b, "X-Custom-%d: v%d\r\n", i, i)
	}
	b.WriteString("\r\n")

	points, err := CreateAllInsertionPoints([]byte(b.String()), true)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints() error = %v", err)
	}

	headerCount := 0
	for _, ip := range points {
		if ip.Type() == INS_HEADER {
			headerCount++
		}
	}
	if headerCount > maxHeaderInsertionPoints {
		t.Fatalf("header insertion points = %d, want <= cap %d", headerCount, maxHeaderInsertionPoints)
	}
	// The query param must still be present and tested first despite the header flood.
	if points[0].Type() != INS_PARAM_URL {
		t.Fatalf("query param should remain first even with a huge header block, got type=%d", points[0].Type())
	}
}
