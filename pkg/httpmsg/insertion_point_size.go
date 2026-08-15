package httpmsg

// Retained-size estimation for insertion-point sets.
//
// A []InsertionPoint is a poor fit for a count-bounded cache: two entries can
// differ in retained size by four orders of magnitude. One insertion point on a
// 200-byte GET retains a few hundred bytes; a POST whose body parameter holds a
// large JSON document produces thousands of nested points that all reference the
// same buffers. EstimateRetainedBytes lets a cache bound bytes instead of entries.

const (
	// ipEstimateStructBytes approximates the fixed per-insertion-point cost: the
	// struct itself, its interface header in the slice, the name/base-value
	// strings, and allocator rounding. Deliberately generous — understating the
	// per-point cost is what lets a large set slip past a byte budget.
	ipEstimateStructBytes = 256

	// ipEstimateParamBytes approximates the *Param a ParameterInsertionPoint
	// references (name, value, offsets). Params are shared with the analysis that
	// produced them, so this is an attribution, not an exact retention figure.
	ipEstimateParamBytes = 128
)

// EstimateRetainedBytes approximates the heap retained by a set of insertion
// points produced by one CreateAllInsertionPoints call.
//
// Byte buffers are counted once per distinct backing array. That is the whole
// point of the function: insertion points from a single call deliberately share
// their base request and parent-value buffers (see sharedBaseRequest and
// newEncodedInsertionPointShared), so summing len(baseRequest) per point would
// overstate retention by the child count — reproducing, in the estimate, exactly
// the quadratic blowup the sharing removed.
//
// The result is an estimate for budgeting, not an exact measurement: it attributes
// shared Params per-point and ignores allocator overhead. It is intended to be
// stable and cheap (one pass, no allocation beyond the seen-set), not precise.
func EstimateRetainedBytes(points []InsertionPoint) int {
	if len(points) == 0 {
		return 0
	}

	var seen seenBuffers

	total := 0
	for _, ip := range points {
		total += seen.estimateOne(ip)
	}

	return total
}

// seenBuffers tracks which distinct backing arrays have already been charged,
// identified by their first element's address (buffers reaching here are
// immutable for the set's lifetime, so the address is a stable identity).
//
// A fixed array with a linear scan rather than a map: one call's points share
// only a handful of buffers in practice — the request plus one materialized
// parent value per structured parameter — while count is invoked three times per
// nested point, so the scan is over a 1-2 element list on the hot path. Past
// maxSeenBuffers the excess is charged every time, which overstates; that is the
// safe direction for a budget, and is not reachable from CreateAllInsertionPoints.
type seenBuffers struct {
	ptrs [maxSeenBuffers]*byte
	n    int
}

const maxSeenBuffers = 16

func (s *seenBuffers) count(buf []byte) int {
	if len(buf) == 0 {
		return 0
	}
	key := &buf[0]
	for i := 0; i < s.n; i++ {
		if s.ptrs[i] == key {
			return 0
		}
	}
	if s.n < len(s.ptrs) {
		s.ptrs[s.n] = key
		s.n++
	}
	return cap(buf)
}

// estimateOne sizes a single insertion point, recursing through a nested chain's
// parent and child — which are separate insertion points reached by reference
// rather than as slice elements, and can nest arbitrarily.
//
// This is the only type switch: the top-level loop delegates here so a case can
// never be handled two different ways depending on where the point was reached
// from. An unrecognized type falls through to the struct constant alone, which
// UNDERSTATES it — so any insertion point type that CreateAllInsertionPoints can
// emit must have a case here.
//
// A method rather than a function taking a countBuf closure: the closure form
// allocated a bound method value per point and blocked inlining of the buffer
// check, which cost more than the map it was meant to replace.
func (s *seenBuffers) estimateOne(ip InsertionPoint) int {
	switch p := ip.(type) {
	case *ParameterInsertionPoint:
		return ipEstimateStructBytes + s.count(p.baseRequest) + ipEstimateParamBytes
	case *EncodedInsertionPoint:
		return ipEstimateStructBytes + s.count(p.baseRequest) + cap(p.prefix) + len(p.baseValue)
	case *HeaderInsertionPoint:
		return ipEstimateStructBytes + s.count(p.baseRequest) + len(p.baseValue) + len(p.linePrefix)
	case *NestedInsertionPoint:
		return ipEstimateStructBytes + s.count(p.baseRequest) +
			s.estimateOne(p.parentParam) +
			s.estimateOne(p.childParam)
	case nil:
		return 0
	default:
		return ipEstimateStructBytes
	}
}
