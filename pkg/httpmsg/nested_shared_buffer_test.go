package httpmsg

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Nested insertion points share one materialized parent-value buffer across
// every child of that parent (newEncodedInsertionPointShared). These tests pin
// the two properties that makes correct: BuildRequest stays byte-identical to
// the per-child-clone behavior, and retained memory stays linear in the child
// count rather than quadratic.

// buildNestedJSONRequest returns a urlencoded POST whose single "payload"
// parameter carries a JSON document with n scalar children.
func buildNestedJSONRequest(n int) []byte {
	var doc strings.Builder
	doc.WriteString("{")
	for i := 0; i < n; i++ {
		if i > 0 {
			doc.WriteString(",")
		}
		fmt.Fprintf(&doc, `"field_%d":"value_%d_padding_padding_padding"`, i, i)
	}
	doc.WriteString("}")

	body := "payload=" + doc.String()
	return []byte("POST /api/v1/submit HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"\r\n" + body)
}

// buildCloningEquivalent rebuilds a nested insertion point the old way — the
// child owning a private clone of the parent value — so the shared-buffer
// output can be compared against it byte for byte.
func buildCloningEquivalent(raw []byte, parentParam *Param, child *Param, enc Encoder, ipType InsertionPointType) *NestedInsertionPoint {
	shared := newSharedBaseRequest(append([]byte(nil), raw...))
	parentIP := newParameterInsertionPointShared(shared, parentParam)
	childIP := NewEncodedInsertionPoint(
		child.Name(),
		[]byte(parentParam.Value()), // private clone, as before
		child.ValueStart(),
		child.ValueEnd(),
		enc,
		nil,
		ipType,
	)
	return newNestedInsertionPointShared(shared, parentIP, childIP)
}

// TestNestedSharedBufferBuildsIdenticalRequests asserts the shared parent buffer
// produces exactly the bytes the per-child clone produced, for every child and
// for payloads that exercise the encoder.
func TestNestedSharedBufferBuildsIdenticalRequests(t *testing.T) {
	raw := buildNestedJSONRequest(12)

	info, err := AnalyzeRequest(raw)
	if err != nil {
		t.Fatalf("AnalyzeRequest: %v", err)
	}

	var parentParam *Param
	for _, p := range info.Parameters {
		if p.Name() == "payload" {
			parentParam = p
			break
		}
	}
	if parentParam == nil {
		t.Fatal("payload parameter not found")
	}

	shared := newSharedBaseRequest(append([]byte(nil), raw...))
	nested := createNestedShared(shared, parentParam, FormatJSON)
	if len(nested) == 0 {
		t.Fatal("no nested insertion points discovered")
	}

	children, err := ParseJSONBody([]byte(parentParam.Value()), 0)
	if err != nil {
		t.Fatalf("ParseJSONBody: %v", err)
	}
	if len(children) != len(nested) {
		t.Fatalf("child count mismatch: parsed %d, nested %d", len(children), len(nested))
	}

	payloads := [][]byte{
		[]byte("plain"),
		[]byte(`quote"inside`),
		[]byte(`back\slash`),
		[]byte("<script>alert(1)</script>"),
		[]byte(""),
	}

	for i, nip := range nested {
		want := buildCloningEquivalent(raw, parentParam, children[i], &JSONEscapeEncoder{}, INS_PARAM_JSON)

		if nip.Name() != want.Name() {
			t.Errorf("child %d: name = %q, want %q", i, nip.Name(), want.Name())
		}
		if nip.BaseValue() != want.BaseValue() {
			t.Errorf("child %d: base value = %q, want %q", i, nip.BaseValue(), want.BaseValue())
		}

		for _, payload := range payloads {
			got := nip.BuildRequest(payload)
			expected := want.BuildRequest(payload)
			if !bytes.Equal(got, expected) {
				t.Fatalf("child %d payload %q: request differs\n got: %q\nwant: %q",
					i, payload, got, expected)
			}
		}
	}
}

// TestNestedSharedBufferAcrossFormats covers the XML, URL-encoded and base64
// discovery paths, which share the same buffer-hoisting change as JSON.
func TestNestedSharedBufferAcrossFormats(t *testing.T) {
	inner := `{"user":"admin","role":"guest"}`

	cases := []struct {
		name  string
		value string
	}{
		{"xml", `<root><user>admin</user><role>guest</role></root>`},
		{"urlencoded", "user%3Dadmin%26role%3Dguest"},
		{"base64", base64.StdEncoding.EncodeToString([]byte(inner))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := "payload=" + tc.value
			raw := []byte("POST /submit HTTP/1.1\r\n" +
				"Host: example.test\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
				"\r\n" + body)

			points, err := CreateAllInsertionPoints(raw, true)
			if err != nil {
				t.Fatalf("CreateAllInsertionPoints: %v", err)
			}

			var nestedCount int
			for _, ip := range points {
				nip, ok := ip.(*NestedInsertionPoint)
				if !ok {
					continue
				}
				nestedCount++

				// Every child must still build a well-formed request that
				// carries the payload and leaves the rest of the message intact.
				built := nip.BuildRequest([]byte("INJECTED"))
				if !bytes.HasPrefix(built, []byte("POST /submit HTTP/1.1\r\n")) {
					t.Errorf("child %q: request line corrupted: %q", nip.Name(), built)
				}
				if !bytes.Contains(built, []byte("Host: example.test")) {
					t.Errorf("child %q: Host header lost", nip.Name())
				}
			}

			if nestedCount == 0 {
				t.Fatalf("no nested insertion points discovered for %s", tc.name)
			}
		})
	}
}

// TestNestedChildrenShareOneParentBuffer is the direct, deterministic form of the
// property TestNestedInsertionPointsRetainLinearMemory measures end-to-end: every
// child of one parent must reference the same backing array.
func TestNestedChildrenShareOneParentBuffer(t *testing.T) {
	raw := buildNestedJSONRequest(50)

	points, err := CreateAllInsertionPoints(raw, true)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints: %v", err)
	}

	var base *byte
	seen := 0
	for _, ip := range points {
		nip, ok := ip.(*NestedInsertionPoint)
		if !ok {
			continue
		}
		child, ok := nip.childParam.(*EncodedInsertionPoint)
		if !ok || len(child.baseRequest) == 0 {
			continue
		}
		seen++
		ptr := &child.baseRequest[0]
		if base == nil {
			base = ptr
			continue
		}
		if ptr != base {
			t.Fatalf("child %q holds its own copy of the parent value; children must share one buffer", nip.Name())
		}
	}

	if seen < 2 {
		t.Fatalf("expected at least 2 nested children to compare, got %d", seen)
	}
}

// TestNestedSharedBufferBuildRequestDoesNotMutateSharedBuffer guards the
// precondition that makes sharing sound: no child may write into the buffer its
// siblings also reference.
func TestNestedSharedBufferBuildRequestDoesNotMutateSharedBuffer(t *testing.T) {
	raw := buildNestedJSONRequest(8)

	points, err := CreateAllInsertionPoints(raw, true)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints: %v", err)
	}

	var nested []*NestedInsertionPoint
	for _, ip := range points {
		if nip, ok := ip.(*NestedInsertionPoint); ok {
			nested = append(nested, nip)
		}
	}
	if len(nested) < 2 {
		t.Fatalf("expected at least 2 nested points, got %d", len(nested))
	}

	// Snapshot every child's un-injected build, then build through every other
	// child, then re-check. A mutating BuildRequest would corrupt the siblings.
	before := make([][]byte, len(nested))
	for i, nip := range nested {
		before[i] = append([]byte(nil), nip.BuildRequest([]byte("BASE"))...)
	}

	for _, nip := range nested {
		_ = nip.BuildRequest([]byte("OTHER_PAYLOAD_ENTIRELY"))
	}

	for i, nip := range nested {
		after := nip.BuildRequest([]byte("BASE"))
		if !bytes.Equal(before[i], after) {
			t.Fatalf("child %d (%s): build is not stable across sibling builds\nbefore: %q\n after: %q",
				i, nip.Name(), before[i], after)
		}
	}
}

// TestNestedInsertionPointsRetainLinearMemory pins the regression that motivated
// the shared buffer: cloning the parent value per child made retained memory
// grow with child_count × parent_size, so a 98 KB request with 2,000 nested
// children retained ~188 MiB — and these slices are exactly what the executor's
// insertion-point LRU holds, bounded by entry count rather than bytes.
//
// The assertion is a budget of the form `a*requestSize + b*childCount`: retention
// may scale with the message (a few shared buffers) and with the number of
// children (per-child metadata), but NOT with their product. The budget is
// wide — the point is to fail loudly on a return to quadratic, which overshoots
// it by two orders of magnitude, not to police a few bytes of metadata.
func TestNestedInsertionPointsRetainLinearMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("allocation-shape test; skipped under -short")
	}

	const children = 2000
	raw := buildNestedJSONRequest(children)

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	points, err := CreateAllInsertionPoints(raw, true)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints: %v", err)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	retained := float64(after.HeapAlloc) - float64(before.HeapAlloc)
	runtime.KeepAlive(points)

	if len(points) < children {
		t.Fatalf("expected at least %d insertion points, got %d", children, len(points))
	}
	if retained <= 0 {
		t.Skipf("heap delta unusable (%.0f bytes); GC accounting too noisy here", retained)
	}

	// Shared buffers: the request clone plus the decoded parent value, with
	// slack for the parser's own retained parameter values.
	const sharedCopies = 8
	// Per-child structural cost: the nested, parameter and encoded insertion
	// point structs, the child's base value, and the slice entry.
	const bytesPerChild = 2048

	budget := sharedCopies*float64(len(raw)) + bytesPerChild*float64(children)

	t.Logf("children=%d requestBytes=%d points=%d retained=%.2f MiB budget=%.2f MiB (%.1fx request size)",
		children, len(raw), len(points), retained/(1<<20), budget/(1<<20), retained/float64(len(raw)))

	if retained > budget {
		t.Errorf("nested insertion points retained %.2f MiB for a %d-byte request with %d children, "+
			"over the %.2f MiB linear budget; the parent value looks like it is being cloned per child again "+
			"(that made retention quadratic: ~188 MiB at this size)",
			retained/(1<<20), len(raw), children, budget/(1<<20))
	}
}
