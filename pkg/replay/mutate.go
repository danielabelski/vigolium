package replay

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// applyMutations resolves mutations against the insertion points of
// raw, returns the mutated bytes for the first non-conflicting payload
// group, and surfaces unmatched names plus the count of leftover
// groups so the caller can decide whether to re-fire.
//
// Unmatched names are returned as data, not errors — callers often
// want to act on partial matches rather than abort.
func applyMutations(raw []byte, mutations []Mutation) (mutated []byte, payloads []string, unmatched []string, additionalGroups int, err error) {
	points, err := httpmsg.CreateAllInsertionPoints(raw, false)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("parse insertion points: %w", err)
	}
	payloadMap := httpmsg.PayloadMap{}
	for _, m := range mutations {
		ip := findInsertionPoint(points, m.Name, m.Type)
		if ip == nil {
			unmatched = append(unmatched, m.Name)
			continue
		}
		payloadMap[ip] = []byte(m.Payload)
		payloads = append(payloads, m.Payload)
	}
	if len(payloadMap) == 0 {
		return nil, payloads, unmatched, 0, fmt.Errorf("no insertion points matched")
	}
	built, err := httpmsg.BuildRequestWithPayloads(raw, payloadMap)
	if err != nil {
		return nil, payloads, unmatched, 0, fmt.Errorf("build mutated request: %w", err)
	}
	additionalGroups = len(built) - 1
	return built[0], payloads, unmatched, additionalGroups, nil
}

func findInsertionPoint(points []httpmsg.InsertionPoint, name, typeStr string) httpmsg.InsertionPoint {
	for _, p := range points {
		if p.Name() != name {
			continue
		}
		if typeStr == "" || strings.EqualFold(p.Type().String(), typeStr) {
			return p
		}
	}
	return nil
}

// overlayHeaders rewrites raw's header block, replacing each named header
// outright (case-insensitively) and appending the ones that aren't present.
//
// Uses httpmsg.AddOrReplaceHeader, not utils.AddOrReplaceHeader: the utils
// variant's GetHeaderOffsets never matches a header name, so replacing an
// existing header silently *appended a duplicate* instead — a `-H 'Cookie: ...'`
// override left the original Cookie first on the wire, where servers read it.
//
// A header that fails to apply is skipped rather than aborting the overlay: the
// caller's other overrides are still worth sending, and the assembled request is
// reported back in the result for inspection.
func overlayHeaders(raw []byte, overlay map[string]string) []byte {
	// Sorted so a multi-header overlay assembles deterministically; map order
	// would otherwise shuffle appended headers between runs.
	names := make([]string, 0, len(overlay))
	for k := range overlay {
		names = append(names, k)
	}
	sort.Strings(names)

	for _, name := range names {
		updated, err := httpmsg.AddOrReplaceHeader(raw, name, overlay[name])
		if err != nil {
			continue
		}
		raw = updated
	}
	return raw
}

// ParseMutationFlag parses one CLI mutation value into a Mutation.
// Supports two forms:
//   - "name=...,type=...,payload=..." — explicit key=value pairs (commas
//     inside a payload can be escaped as \,).
//   - "name:type:payload" or "name:payload" — colon-separated shorthand.
//
// The forms are disambiguated by the relative position of '=' and ':'
// in the input — shorthand wins when ':' comes first.
func ParseMutationFlag(s string) (Mutation, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Mutation{}, fmt.Errorf("empty mutation")
	}
	firstEq := strings.IndexByte(s, '=')
	firstCol := strings.IndexByte(s, ':')
	keyValueForm := firstEq >= 0 && (firstCol < 0 || firstEq < firstCol)
	if keyValueForm {
		var m Mutation
		for _, p := range splitFlagPairs(s) {
			kv := strings.SplitN(p, "=", 2)
			if len(kv) != 2 {
				return Mutation{}, fmt.Errorf("expected key=value in %q", p)
			}
			key := strings.ToLower(strings.TrimSpace(kv[0]))
			val := kv[1]
			switch key {
			case "name":
				m.Name = strings.TrimSpace(val)
			case "type":
				m.Type = strings.TrimSpace(val)
			case "payload":
				m.Payload = val
			default:
				return Mutation{}, fmt.Errorf("unknown mutation key %q (want name|type|payload)", key)
			}
		}
		if m.Name == "" || m.Payload == "" {
			return Mutation{}, fmt.Errorf("mutation requires both name= and payload= (got %q)", s)
		}
		return m, nil
	}
	parts := strings.SplitN(s, ":", 3)
	switch len(parts) {
	case 2:
		return Mutation{Name: strings.TrimSpace(parts[0]), Payload: parts[1]}, nil
	case 3:
		return Mutation{Name: strings.TrimSpace(parts[0]), Type: strings.TrimSpace(parts[1]), Payload: parts[2]}, nil
	}
	return Mutation{}, fmt.Errorf("could not parse mutation %q (use name=...,payload=... or name:type:payload)", s)
}

// splitFlagPairs splits on top-level commas only, treating a backslash
// before a comma as an escape so payloads can contain commas as a\,b.
func splitFlagPairs(s string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) && s[i+1] == ',' {
			cur.WriteByte(',')
			i++
			continue
		}
		if c == ',' {
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

// ParseHeaderFlag parses a "Name: value" or "Name=value" CLI flag.
func ParseHeaderFlag(s string) (name, value string, err error) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ":"); i > 0 {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), nil
	}
	if i := strings.Index(s, "="); i > 0 {
		return strings.TrimSpace(s[:i]), s[i+1:], nil
	}
	return "", "", fmt.Errorf("expected 'Name: value' or 'Name=value', got %q", s)
}
