package aem_fingerprint

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestFingerprintDetectsAEMAndMarksTech(t *testing.T) {
	rr := modtest.Response(
		modtest.Request(t, "https://aem.example.com/"),
		"text/html",
		`<html><body>Welcome to Adobe Experience Manager</body></html>`,
	)
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}

	results, err := New().ScanPerRequest(rr, sc)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 AEM fingerprint finding, got %d (%+v)", len(results), results)
	}
	if !strings.Contains(results[0].Info.Name, "Adobe Experience Manager") {
		t.Fatalf("unexpected finding name: %q", results[0].Info.Name)
	}
	if !sc.TechStack.Has("aem.example.com", "aem") {
		t.Fatal("expected host to be marked with tech tag aem")
	}
}

func TestFingerprintIgnoresNonAEM(t *testing.T) {
	rr := modtest.Response(
		modtest.Request(t, "https://plain.example.com/"),
		"text/html",
		`<html><body>Just a normal website</body></html>`,
	)
	results, err := New().ScanPerRequest(rr, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("non-AEM page must not fingerprint, got %+v", results)
	}
}
