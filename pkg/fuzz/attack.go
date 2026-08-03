package fuzz

import (
	"fmt"
	"strings"
)

// AttackMode selects how payloads map onto positions when there is more than
// one position. The names follow Burp Intruder's, which is the vocabulary
// operators already have for this.
type AttackMode int

const (
	// ModeSniper varies one position at a time, leaving the others at their
	// original value. This is the default and the only mode that makes sense
	// for automatically-discovered insertion points: with N params it answers
	// "which param is injectable", not "what combination breaks it".
	ModeSniper AttackMode = iota
	// ModeBatteringRam puts the same payload in every position at once —
	// for when a value has to agree across places (a parameter that also
	// appears in a header, say).
	ModeBatteringRam
	// ModePitchfork advances every position's list in lockstep: the k-th
	// payload of each set together. This is how you test credential pairs,
	// where user[k] must go with password[k] and the cartesian product would
	// be both wrong and enormous.
	ModePitchfork
	// ModeClusterBomb tries every combination. Exhaustive and multiplicative —
	// two 100-item lists are 10,000 sends.
	ModeClusterBomb
)

// String renders the mode as its flag spelling.
func (m AttackMode) String() string {
	switch m {
	case ModeBatteringRam:
		return "batteringram"
	case ModePitchfork:
		return "pitchfork"
	case ModeClusterBomb:
		return "clusterbomb"
	default:
		return "sniper"
	}
}

// ParseAttackMode maps a flag value to a mode.
func ParseAttackMode(s string) (AttackMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "sniper":
		return ModeSniper, nil
	case "batteringram", "battering-ram", "ram":
		return ModeBatteringRam, nil
	case "pitchfork", "fork":
		return ModePitchfork, nil
	case "clusterbomb", "cluster-bomb", "cluster":
		return ModeClusterBomb, nil
	}
	return ModeSniper, fmt.Errorf("unknown attack mode %q (want sniper|batteringram|pitchfork|clusterbomb)", s)
}

// CaseAssignment places one payload at one position.
type CaseAssignment struct {
	Position Position
	Payload  string
}

// Case is one send: every position that gets a payload, and what it gets.
// Sniper cases carry a single assignment; the multi-position modes carry one
// per position.
type Case struct {
	Assignments []CaseAssignment
}

// build produces the request bytes for this case.
//
// Assignments are applied in sequence to the same buffer. That is safe for
// marker positions, which each own a distinct literal keyword, and it is why
// the multi-position modes are restricted to markers: an httpmsg insertion
// point builds from the request it was analyzed against, so applying a second
// one would discard the first one's edit.
func (c Case) build(raw []byte) []byte {
	out := raw
	for _, a := range c.Assignments {
		out = a.Position.build(out, a.Payload)
	}
	return out
}

// newCase builds a Case, keeping assignments in position order so that order
// carries through to the Result label and to pitchfork's pairing. Substitution
// order does not matter: replaceKeyword refuses to match a numbered sibling,
// so "FUZZ" can never eat the prefix of "FUZZ2" whichever runs first.
func newCase(assignments ...CaseAssignment) Case {
	return Case{Assignments: assignments}
}

// label renders the case's positions and payloads for the Result. Single
// assignments keep the plain "name"/"payload" shape callers already parse.
func (c Case) label() (position, positionType, payload string) {
	if len(c.Assignments) == 1 {
		a := c.Assignments[0]
		return a.Position.Name, a.Position.Label, a.Payload
	}
	names := make([]string, len(c.Assignments))
	types := make([]string, len(c.Assignments))
	payloads := make([]string, len(c.Assignments))
	for i, a := range c.Assignments {
		names[i] = a.Position.Name
		types[i] = a.Position.Label
		payloads[i] = a.Payload
	}
	return strings.Join(names, "+"), strings.Join(types, "+"), strings.Join(payloads, " | ")
}

// MaxCases bounds how many sends one invocation may expand to. Clusterbomb is
// multiplicative — three markers against 500-word lists is 125 million sends —
// and the whole plan is materialized before the first byte goes out, so
// without a bound the failure mode is an unexplained OOM rather than a number
// the operator can react to.
const MaxCases = 2_000_000

// BuildCases expands positions and payload sets into the concrete sends a mode
// implies.
//
// sets[i] belongs to positions[i] for pitchfork and clusterbomb. Sniper and
// battering ram use one list: sets[0] if present, else the shared fallback.
func BuildCases(mode AttackMode, positions []Position, sets [][]string, fallback []string) ([]Case, error) {
	if len(positions) == 0 {
		return nil, fmt.Errorf("no positions to fuzz")
	}

	listFor := func(i int) []string {
		if i < len(sets) && len(sets[i]) > 0 {
			return sets[i]
		}
		return fallback
	}

	if mode != ModeSniper && len(positions) > 1 {
		for _, p := range positions {
			if p.kind != kindMarker {
				return nil, fmt.Errorf(
					"%s needs marker positions: place %s/%s2/... in the request, "+
						"because a discovered insertion point can only be varied one at a time (sniper)",
					mode, DefaultKeyword, DefaultKeyword)
			}
		}
	}

	switch mode {
	case ModeBatteringRam:
		list := listFor(0)
		if len(list) == 0 {
			return nil, fmt.Errorf("no payloads")
		}
		cases := make([]Case, 0, len(list))
		for _, payload := range list {
			assignments := make([]CaseAssignment, len(positions))
			for i, p := range positions {
				assignments[i] = CaseAssignment{Position: p, Payload: payload}
			}
			cases = append(cases, newCase(assignments...))
		}
		return cases, nil

	case ModePitchfork:
		// The shortest list bounds the run: pairing beyond it would have to
		// invent a partner, and a wrong pair is worse than a missing one.
		shortest := -1
		for i := range positions {
			n := len(listFor(i))
			if n == 0 {
				return nil, fmt.Errorf("pitchfork: position %q has no payloads", positions[i].Name)
			}
			if shortest < 0 || n < shortest {
				shortest = n
			}
		}
		cases := make([]Case, 0, shortest)
		for k := 0; k < shortest; k++ {
			assignments := make([]CaseAssignment, len(positions))
			for i, p := range positions {
				assignments[i] = CaseAssignment{Position: p, Payload: listFor(i)[k]}
			}
			cases = append(cases, newCase(assignments...))
		}
		return cases, nil

	case ModeClusterBomb:
		total := 1
		for i, p := range positions {
			n := len(listFor(i))
			if n == 0 {
				return nil, fmt.Errorf("clusterbomb: position %q has no payloads", p.Name)
			}
			total *= n
			if total > MaxCases {
				return nil, fmt.Errorf(
					"clusterbomb over %d positions would expand to more than %d sends; "+
						"shorten a list, or use --mode pitchfork to pair them instead",
					len(positions), MaxCases)
			}
		}
		cases := []Case{{}}
		for i, p := range positions {
			list := listFor(i)
			next := make([]Case, 0, len(cases)*len(list))
			for _, base := range cases {
				for _, payload := range list {
					assignments := make([]CaseAssignment, len(base.Assignments), len(base.Assignments)+1)
					copy(assignments, base.Assignments)
					assignments = append(assignments, CaseAssignment{Position: p, Payload: payload})
					next = append(next, newCase(assignments...))
				}
			}
			cases = next
		}
		return cases, nil

	default: // sniper
		var cases []Case
		for i, p := range positions {
			list := listFor(i)
			if len(list) == 0 {
				return nil, fmt.Errorf("no payloads")
			}
			for _, payload := range list {
				cases = append(cases, newCase(CaseAssignment{Position: p, Payload: payload}))
			}
		}
		return cases, nil
	}
}
