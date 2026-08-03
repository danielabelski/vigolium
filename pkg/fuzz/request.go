package fuzz

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/replay"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Overrides are curl-style edits applied to the resolved baseline request
// before positions are worked out. They exist so -X/-H/-d mean the same thing
// no matter where the request came from: a request pasted with -i is exactly
// as likely to need an added auth header or a swapped verb as one built from a
// positional URL, and silently dropping the flags for the -i case makes the
// tool lie about what it sent.
//
// Because overrides land before insertion-point analysis, a marker placed by
// an override (-H 'X-Forwarded-For: FUZZ') is discovered like any other.
type Overrides struct {
	Method      string   // replaces the request-line verb
	Headers     []string // "Name: value", added or replaced
	Body        string   // replaces the body, refreshing Content-Length
	QueryAppend string   // appended to the request-line query string (curl's -G)
}

// Empty reports whether there is nothing to apply.
func (o Overrides) Empty() bool {
	return o.Method == "" && len(o.Headers) == 0 && o.Body == "" && o.QueryAppend == ""
}

// Apply returns raw with the overrides applied.
func (o Overrides) Apply(raw []byte) ([]byte, error) {
	if o.Empty() {
		return raw, nil
	}
	out := raw
	if o.Method != "" {
		out = rewriteMethod(out, strings.ToUpper(o.Method))
	}
	if o.QueryAppend != "" {
		out = utils.AppendToQuery(out, o.QueryAppend)
	}
	for _, h := range o.Headers {
		// replay.ParseHeaderFlag, so `fuzz -H` and `replay -H` accept exactly
		// the same syntax rather than drifting.
		name, value, err := replay.ParseHeaderFlag(h)
		if err != nil {
			return nil, err
		}
		// httpmsg.AddOrReplaceHeader, not utils.AddOrReplaceHeader: the utils
		// variant's GetHeaderOffsets never matches a name, so it appends
		// unconditionally — which would leave a request carrying two
		// Content-Length or two Cookie headers. pkg/replay routes around it for
		// the same reason.
		replaced, err := httpmsg.AddOrReplaceHeader(out, name, value)
		if err != nil {
			return nil, fmt.Errorf("set header %q: %w", name, err)
		}
		out = replaced
	}
	if o.Body != "" {
		replaced, err := httpmsg.SetBodyString(out, o.Body)
		if err != nil {
			return nil, fmt.Errorf("set body: %w", err)
		}
		out = replaced
	}
	return out, nil
}

// BuildAt returns the exact bytes that would be sent for one payload at one
// position, and BuildCase the same for a whole case. Both exist so callers can
// show an operator what a run will do (--dry-run) without reimplementing the
// injection rules.
func BuildAt(pos Position, raw []byte, payload string) []byte {
	return pos.build(raw, payload)
}

// BuildCase returns the exact bytes one case would send.
func BuildCase(c Case, raw []byte) []byte {
	return c.build(raw)
}
