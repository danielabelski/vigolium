package fuzz

import (
	"fmt"
	"strconv"
	"strings"
)

// NumPredicate matches a numeric response signal. Exact equality is nearly
// useless for sizes — a page whose body carries a timestamp or a CSRF token is
// never byte-identical twice — so the grammar accepts ranges and comparisons
// alongside it:
//
//	500      exactly 500
//	100-200  inclusive range
//	>500     greater than
//	<10      less than
//	>=500    at least
//	<=10     at most
//	!404     anything but
//
// Several may be comma-separated in one flag value; the set matches when any
// member does.
type NumPredicate struct {
	op   string
	lo   int64
	hi   int64
	text string
}

// String returns the predicate as written, so reports can echo the operator's
// own syntax back.
func (p NumPredicate) String() string { return p.text }

// Match reports whether v satisfies the predicate.
func (p NumPredicate) Match(v int64) bool {
	switch p.op {
	case "eq":
		return v == p.lo
	case "ne":
		return v != p.lo
	case "range":
		return v >= p.lo && v <= p.hi
	case "gt":
		return v > p.lo
	case "ge":
		return v >= p.lo
	case "lt":
		return v < p.lo
	case "le":
		return v <= p.lo
	}
	return false
}

// NumPredicates is a set combined with OR.
type NumPredicates []NumPredicate

// Match reports whether any predicate in the set matches.
func (ps NumPredicates) Match(v int64) bool {
	for _, p := range ps {
		if p.Match(v) {
			return true
		}
	}
	return false
}

// Empty reports whether nothing was configured.
func (ps NumPredicates) Empty() bool { return len(ps) == 0 }

// String renders the set for help and report output.
func (ps NumPredicates) String() string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.text
	}
	return strings.Join(parts, ",")
}

// ParseNumPredicates parses the comma-separated predicate grammar. Values are
// also accepted pre-split, so both `--match-size 1-2,5` and
// `--match-size 1-2 --match-size 5` work.
func ParseNumPredicates(values []string, flag string) (NumPredicates, error) {
	return ParseNumPredicatesDefaultOp(values, "", flag)
}

// ParseNumPredicatesDefaultOp is ParseNumPredicates with an operator applied to
// bare numbers. `--match-time 500` has always meant "at least 500ms", and
// turning it into an exact-millisecond match would make it essentially never
// fire; passing defaultOp=">=" keeps that reading without a second tokenizer at
// the call site.
func ParseNumPredicatesDefaultOp(values []string, defaultOp, flag string) (NumPredicates, error) {
	var out NumPredicates
	for _, value := range values {
		for _, tok := range strings.Split(value, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if defaultOp != "" && isBareNumber(tok) {
				tok = defaultOp + tok
			}
			p, err := parseNumPredicate(tok)
			if err != nil {
				return nil, fmt.Errorf("%s %q: %w", flag, tok, err)
			}
			out = append(out, p)
		}
	}
	return out, nil
}

// isBareNumber reports whether tok carries no operator or range.
func isBareNumber(tok string) bool {
	_, err := strconv.ParseInt(tok, 10, 64)
	return err == nil
}

func parseNumPredicate(tok string) (NumPredicate, error) {
	p := NumPredicate{text: tok}

	parseInt := func(s string) (int64, error) {
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("want a number, a range (100-200), or a comparison (>500, <10, !404)")
		}
		return n, nil
	}

	// Two-character prefixes first: ">=" would otherwise parse as ">" of "=5".
	// Keeping the order in one ordered table makes that constraint visible
	// rather than implicit in the arrangement of a switch.
	for _, pfx := range []struct{ text, op string }{
		{">=", "ge"}, {"<=", "le"}, {">", "gt"}, {"<", "lt"}, {"!", "ne"},
	} {
		rest, ok := strings.CutPrefix(tok, pfx.text)
		if !ok {
			continue
		}
		n, err := parseInt(rest)
		if err != nil {
			return p, err
		}
		p.op, p.lo = pfx.op, n
		return p, nil
	}

	// A range needs a '-' that isn't the leading sign of a negative number.
	if idx := strings.Index(tok[1:], "-"); idx >= 0 {
		lo, err := parseInt(tok[:idx+1])
		if err != nil {
			return p, err
		}
		hi, err := parseInt(tok[idx+2:])
		if err != nil {
			return p, err
		}
		if lo > hi {
			return p, fmt.Errorf("range %d-%d is inverted", lo, hi)
		}
		p.op, p.lo, p.hi = "range", lo, hi
		return p, nil
	}

	n, err := parseInt(tok)
	p.op, p.lo = "eq", n
	return p, err
}
