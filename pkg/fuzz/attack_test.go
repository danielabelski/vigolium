package fuzz

import (
	"strings"
	"testing"
)

func markerPositions(names ...string) []Position {
	out := make([]Position, len(names))
	for i, n := range names {
		out[i] = Position{Name: n, Label: "MARKER", kind: kindMarker}
	}
	return out
}

func TestParseAttackMode(t *testing.T) {
	for input, want := range map[string]AttackMode{
		"":             ModeSniper,
		"sniper":       ModeSniper,
		"batteringram": ModeBatteringRam,
		"pitchfork":    ModePitchfork,
		"clusterbomb":  ModeClusterBomb,
		"CLUSTER":      ModeClusterBomb,
	} {
		got, err := ParseAttackMode(input)
		if err != nil || got != want {
			t.Errorf("ParseAttackMode(%q) = %v,%v; want %v", input, got, err, want)
		}
	}
	if _, err := ParseAttackMode("nonsense"); err == nil {
		t.Error("unknown mode should error")
	}
}

func TestBuildCasesSniper(t *testing.T) {
	positions := markerPositions("FUZZ", "FUZZ2")
	cases, err := BuildCases(ModeSniper, positions, nil, []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	// One position varies per send: 2 positions x 2 payloads.
	if len(cases) != 4 {
		t.Fatalf("got %d cases, want 4", len(cases))
	}
	for _, c := range cases {
		if len(c.Assignments) != 1 {
			t.Errorf("sniper cases vary one position, got %d", len(c.Assignments))
		}
	}
}

func TestBuildCasesBatteringRam(t *testing.T) {
	positions := markerPositions("FUZZ", "FUZZ2")
	cases, err := BuildCases(ModeBatteringRam, positions, nil, []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 2 {
		t.Fatalf("got %d cases, want 2", len(cases))
	}
	for _, c := range cases {
		if len(c.Assignments) != 2 {
			t.Fatalf("battering ram fills every position, got %d", len(c.Assignments))
		}
		if c.Assignments[0].Payload != c.Assignments[1].Payload {
			t.Errorf("battering ram uses one payload everywhere, got %q and %q",
				c.Assignments[0].Payload, c.Assignments[1].Payload)
		}
	}
}

func TestBuildCasesPitchfork(t *testing.T) {
	positions := markerPositions("FUZZ", "FUZZ2")
	sets := [][]string{{"alice", "bob", "carol"}, {"pw1", "pw2"}}

	cases, err := BuildCases(ModePitchfork, positions, sets, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Bounded by the shortest list: pairing "carol" would need an invented
	// password.
	if len(cases) != 2 {
		t.Fatalf("got %d cases, want 2 (shortest list)", len(cases))
	}
	if cases[0].Assignments[0].Payload != "alice" || cases[0].Assignments[1].Payload != "pw1" {
		t.Errorf("first pair should be alice/pw1, got %+v", cases[0].Assignments)
	}
	if cases[1].Assignments[0].Payload != "bob" || cases[1].Assignments[1].Payload != "pw2" {
		t.Errorf("second pair should be bob/pw2, got %+v", cases[1].Assignments)
	}
}

func TestBuildCasesClusterBomb(t *testing.T) {
	positions := markerPositions("FUZZ", "FUZZ2")
	sets := [][]string{{"a", "b", "c"}, {"1", "2"}}

	cases, err := BuildCases(ModeClusterBomb, positions, sets, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 6 {
		t.Fatalf("got %d cases, want 6 (3x2)", len(cases))
	}
	seen := make(map[string]bool)
	for _, c := range cases {
		seen[c.Assignments[0].Payload+c.Assignments[1].Payload] = true
	}
	for _, want := range []string{"a1", "a2", "b1", "b2", "c1", "c2"} {
		if !seen[want] {
			t.Errorf("missing combination %q", want)
		}
	}
}

// Discovered insertion points can only be varied one at a time, so a
// multi-position mode over them has to fail loudly rather than quietly
// dropping all but the last edit.
func TestBuildCasesRejectsNonMarkerMultiPosition(t *testing.T) {
	positions := []Position{
		{Name: "id", Label: "URL_PARAM", kind: kindInsertionPoint},
		{Name: "q", Label: "URL_PARAM", kind: kindInsertionPoint},
	}
	for _, mode := range []AttackMode{ModeBatteringRam, ModePitchfork, ModeClusterBomb} {
		if _, err := BuildCases(mode, positions, nil, []string{"x"}); err == nil {
			t.Errorf("%v over insertion points should error", mode)
		}
	}
	// Sniper is fine over insertion points.
	if _, err := BuildCases(ModeSniper, positions, nil, []string{"x"}); err != nil {
		t.Errorf("sniper over insertion points should work: %v", err)
	}
}

func TestFindMarkersNumbered(t *testing.T) {
	raw := []byte("POST /login HTTP/1.1\r\nHost: t\r\n\r\nuser=FUZZ&pass=FUZZ2")
	positions := findMarkers(raw, "FUZZ")
	if len(positions) != 2 {
		t.Fatalf("got %d markers, want 2: %+v", len(positions), positions)
	}
	if positions[0].Name != "FUZZ" || positions[1].Name != "FUZZ2" {
		t.Errorf("markers should be ordered FUZZ, FUZZ2; got %q, %q", positions[0].Name, positions[1].Name)
	}
}

// "FUZZ" is a prefix of "FUZZ2", so a request that only uses numbered markers
// must not report a bare one.
func TestFindMarkersIgnoresPrefixOfNumbered(t *testing.T) {
	raw := []byte("GET /?a=FUZZ2&b=FUZZ3 HTTP/1.1\r\nHost: t\r\n\r\n")
	positions := findMarkers(raw, "FUZZ")
	if len(positions) != 2 {
		t.Fatalf("got %d markers, want 2: %+v", len(positions), positions)
	}
	for _, p := range positions {
		if p.Name == "FUZZ" {
			t.Error("bare FUZZ reported for a request that only uses numbered markers")
		}
	}
}

// The substitution must not let the bare marker eat the prefix of a numbered
// one and leave a stray digit.
func TestCaseBuildSubstitutesLongestMarkerFirst(t *testing.T) {
	raw := []byte("POST /login HTTP/1.1\r\nHost: t\r\n\r\nuser=FUZZ&pass=FUZZ2")
	positions := findMarkers(raw, "FUZZ")

	c := newCase(
		CaseAssignment{Position: positions[0], Payload: "alice"},
		CaseAssignment{Position: positions[1], Payload: "s3cret"},
	)
	got := string(c.build(raw))

	if !strings.Contains(got, "user=alice") {
		t.Errorf("FUZZ not substituted:\n%s", got)
	}
	if !strings.Contains(got, "pass=s3cret") {
		t.Errorf("FUZZ2 not substituted:\n%s", got)
	}
	if strings.Contains(got, "alice2") {
		t.Errorf("bare marker ate the numbered marker's prefix:\n%s", got)
	}
	if strings.Contains(got, "FUZZ") {
		t.Errorf("a marker survived substitution:\n%s", got)
	}
}

func TestCaseLabelJoinsMultiplePositions(t *testing.T) {
	c := Case{Assignments: []CaseAssignment{
		{Position: Position{Name: "FUZZ", Label: "MARKER"}, Payload: "alice"},
		{Position: Position{Name: "FUZZ2", Label: "MARKER"}, Payload: "pw"},
	}}
	pos, typ, payload := c.label()
	if pos != "FUZZ+FUZZ2" || typ != "MARKER+MARKER" || payload != "alice | pw" {
		t.Errorf("label = %q/%q/%q", pos, typ, payload)
	}

	single := newCase(CaseAssignment{Position: Position{Name: "id", Label: "URL_PARAM"}, Payload: "1"})
	pos, typ, payload = single.label()
	if pos != "id" || typ != "URL_PARAM" || payload != "1" {
		t.Errorf("single-assignment label should stay plain, got %q/%q/%q", pos, typ, payload)
	}
}

func TestBaselineTimingStats(t *testing.T) {
	mean, sd := meanStdDev([]int64{100, 110, 120})
	if mean != 110 {
		t.Errorf("mean = %d, want 110", mean)
	}
	if sd < 8 || sd > 9 {
		t.Errorf("stddev = %f, want ~8.16", sd)
	}

	if _, sd := meanStdDev([]int64{100}); sd != 0 {
		t.Errorf("a single sample has no deviation, got %f", sd)
	}

	base := Baseline{TimeMs: 100, TimeStdDev: 10, Samples: 3}
	if z := timeZ(140, base); z != 4 {
		t.Errorf("timeZ = %f, want 4", z)
	}
	// Too few samples to have a deviation worth dividing by.
	if z := timeZ(140, Baseline{TimeMs: 100, Samples: 1}); z != 0 {
		t.Errorf("timeZ with one sample should be 0, got %f", z)
	}
	// A perfectly consistent baseline must not produce an infinite z.
	if z := timeZ(101, Baseline{TimeMs: 100, TimeStdDev: 0, Samples: 5}); z != 1 {
		t.Errorf("zero-deviation baseline should floor at 1ms, got %f", z)
	}
}

// The bare marker must not consume a numbered sibling regardless of which
// order the assignments are substituted in — the ordering used to be an
// implicit precondition on the assignment slice.
func TestMarkerSubstitutionIsOrderIndependent(t *testing.T) {
	raw := []byte("POST /login HTTP/1.1\r\nHost: t\r\n\r\nuser=FUZZ&pass=FUZZ2")
	positions := findMarkers(raw, "FUZZ")

	forward := newCase(
		CaseAssignment{Position: positions[0], Payload: "alice"},
		CaseAssignment{Position: positions[1], Payload: "s3cret"},
	)
	reversed := newCase(
		CaseAssignment{Position: positions[1], Payload: "s3cret"},
		CaseAssignment{Position: positions[0], Payload: "alice"},
	)

	want := "user=alice&pass=s3cret"
	for name, c := range map[string]Case{"forward": forward, "reversed": reversed} {
		got := string(c.build(raw))
		if !strings.Contains(got, want) {
			t.Errorf("%s order produced:\n%s\nwant it to contain %q", name, got, want)
		}
	}
}

// Assignments stay in position order so the Result label reads the way the
// operator wrote the markers.
func TestCaseKeepsPositionOrder(t *testing.T) {
	positions := markerPositions("FUZZ", "FUZZ2")
	cases, err := BuildCases(ModeClusterBomb, positions,
		[][]string{{"a"}, {"1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := cases[0].Assignments[0].Position.Name; got != "FUZZ" {
		t.Errorf("first assignment should be FUZZ, got %q", got)
	}
	_, _, payload := cases[0].label()
	if payload != "a | 1" {
		t.Errorf("label payload = %q, want \"a | 1\"", payload)
	}
}

func TestClusterBombRejectsRunawayExpansion(t *testing.T) {
	big := make([]string, 2000)
	for i := range big {
		big[i] = "p"
	}
	positions := markerPositions("FUZZ", "FUZZ2", "FUZZ3")
	_, err := BuildCases(ModeClusterBomb, positions, [][]string{big, big, big}, nil)
	if err == nil {
		t.Fatal("8 billion combinations should be refused, not allocated")
	}
	if !strings.Contains(err.Error(), "pitchfork") {
		t.Errorf("the error should point at the alternative mode, got: %v", err)
	}
}
