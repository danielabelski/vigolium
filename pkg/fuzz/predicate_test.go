package fuzz

import "testing"

func TestParseNumPredicates(t *testing.T) {
	cases := []struct {
		expr  string
		match []int64
		miss  []int64
	}{
		{"200", []int64{200}, []int64{199, 201}},
		{"100-200", []int64{100, 150, 200}, []int64{99, 201}},
		{">500", []int64{501, 9999}, []int64{500, 0}},
		{">=500", []int64{500, 501}, []int64{499}},
		{"<10", []int64{0, 9}, []int64{10, 11}},
		{"<=10", []int64{10, 9}, []int64{11}},
		{"!404", []int64{200, 500}, []int64{404}},
		{"200,301,>500", []int64{200, 301, 501}, []int64{302, 500}},
		{"-5--1", []int64{-5, -3, -1}, []int64{0, -6}},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			ps, err := ParseNumPredicates([]string{tc.expr}, "--match-size")
			if err != nil {
				t.Fatalf("parse %q: %v", tc.expr, err)
			}
			for _, v := range tc.match {
				if !ps.Match(v) {
					t.Errorf("%q should match %d", tc.expr, v)
				}
			}
			for _, v := range tc.miss {
				if ps.Match(v) {
					t.Errorf("%q should not match %d", tc.expr, v)
				}
			}
		})
	}
}

func TestParseNumPredicatesErrors(t *testing.T) {
	for _, expr := range []string{"abc", ">x", "200-abc", "300-100"} {
		if _, err := ParseNumPredicates([]string{expr}, "--match-size"); err == nil {
			t.Errorf("expected an error for %q", expr)
		}
	}
}

func TestNumPredicatesEmptyMatchesNothing(t *testing.T) {
	var ps NumPredicates
	if !ps.Empty() {
		t.Fatal("nil predicates should be empty")
	}
	if ps.Match(200) {
		t.Fatal("empty predicates should not match")
	}
}

func TestCriteriaMatchModes(t *testing.T) {
	r := Result{Status: 200, Length: 5000}
	body := []byte("hello")

	// Under "any", one satisfied category is enough.
	anyC := Criteria{Status: mustPreds(t, "200"), Sizes: mustPreds(t, ">9000"), Mode: MatchAny}
	if !anyC.match(r, body, nil) {
		t.Error("MatchAny should keep when the status matches")
	}

	// Under "all", every configured category has to hold.
	allC := Criteria{Status: mustPreds(t, "200"), Sizes: mustPreds(t, ">9000"), Mode: MatchAll}
	if allC.match(r, body, nil) {
		t.Error("MatchAll should drop when the size doesn't match")
	}

	allOK := Criteria{Status: mustPreds(t, "200"), Sizes: mustPreds(t, ">1000"), Mode: MatchAll}
	if !allOK.match(r, body, nil) {
		t.Error("MatchAll should keep when both match")
	}
}

func mustPreds(t *testing.T, expr string) NumPredicates {
	t.Helper()
	ps, err := ParseNumPredicates([]string{expr}, "test")
	if err != nil {
		t.Fatal(err)
	}
	return ps
}
