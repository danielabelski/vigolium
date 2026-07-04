package graphqlx

import (
	"bytes"
	"encoding/json"
	"strings"
)

// IntrospectionQuery is the canonical full introspection query (fragment-free,
// depth-bounded ofType chain) used to enumerate the complete schema. It matches
// the OWASP WSTG reference query and the depth used by the jsext helper.
const IntrospectionQuery = `query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name fields(includeDeprecated: true) { name args { name defaultValue type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } inputFields { name defaultValue type { kind name ofType { kind name ofType { kind name } } } } enumValues(includeDeprecated: true) { name } } } }`

// IntrospectionBody returns the JSON request body carrying the full
// introspection query, ready to POST with Content-Type application/json.
func IntrospectionBody() string {
	b, _ := json.Marshal(map[string]string{"query": IntrospectionQuery})
	return string(b)
}

// wire types mirror the introspection JSON so we can decode with the standard
// library and then flatten into the exported Schema model.
type wireIntrospection struct {
	Data struct {
		Schema wireSchema `json:"__schema"`
	} `json:"data"`
}

type wireSchema struct {
	QueryType        *wireNamed `json:"queryType"`
	MutationType     *wireNamed `json:"mutationType"`
	SubscriptionType *wireNamed `json:"subscriptionType"`
	Types            []wireType `json:"types"`
}

type wireNamed struct {
	Name string `json:"name"`
}

type wireType struct {
	Kind        string          `json:"kind"`
	Name        string          `json:"name"`
	Fields      []wireField     `json:"fields"`
	InputFields []wireInputVal  `json:"inputFields"`
	EnumValues  []wireEnumValue `json:"enumValues"`
}

type wireField struct {
	Name string         `json:"name"`
	Args []wireInputVal `json:"args"`
	Type wireTypeRef    `json:"type"`
}

type wireInputVal struct {
	Name         string      `json:"name"`
	DefaultValue *string     `json:"defaultValue"`
	Type         wireTypeRef `json:"type"`
}

type wireEnumValue struct {
	Name string `json:"name"`
}

type wireTypeRef struct {
	Kind   string       `json:"kind"`
	Name   string       `json:"name"`
	OfType *wireTypeRef `json:"ofType"`
}

func (w *wireTypeRef) toTypeRef() *TypeRef {
	if w == nil {
		return nil
	}
	return &TypeRef{Kind: w.Kind, Name: w.Name, OfType: w.OfType.toTypeRef()}
}

// ParseSchema decodes an introspection response body into a Schema. It returns
// (nil, false) when the body is not a usable introspection result (no
// __schema, or no types) so callers can cheaply gate on the boolean.
func ParseSchema(body []byte) (*Schema, bool) {
	var wire wireIntrospection
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, false
	}
	ws := wire.Data.Schema
	if len(ws.Types) == 0 {
		return nil, false
	}

	s := &Schema{Types: make([]*Type, 0, len(ws.Types))}
	if ws.QueryType != nil {
		s.QueryType = ws.QueryType.Name
	}
	if ws.MutationType != nil {
		s.MutationType = ws.MutationType.Name
	}
	if ws.SubscriptionType != nil {
		s.SubscriptionType = ws.SubscriptionType.Name
	}

	for _, wt := range ws.Types {
		t := &Type{Kind: wt.Kind, Name: wt.Name}
		for _, wf := range wt.Fields {
			f := &Field{Name: wf.Name, Type: wf.Type.toTypeRef()}
			for _, wa := range wf.Args {
				f.Args = append(f.Args, toInputValue(wa))
			}
			t.Fields = append(t.Fields, f)
		}
		for _, wi := range wt.InputFields {
			t.InputFields = append(t.InputFields, toInputValue(wi))
		}
		for _, we := range wt.EnumValues {
			t.EnumValues = append(t.EnumValues, we.Name)
		}
		s.Types = append(s.Types, t)
	}

	// A query root is the minimum required to build anything useful.
	if s.rootType(KindQuery) == nil && s.rootType(KindMutation) == nil {
		return nil, false
	}
	return s, true
}

func toInputValue(w wireInputVal) *InputValue {
	iv := &InputValue{Name: w.Name, Type: w.Type.toTypeRef()}
	if w.DefaultValue != nil {
		iv.DefaultValue = strings.TrimSpace(*w.DefaultValue)
	}
	return iv
}

// LooksLikeIntrospection reports whether a response body is a GraphQL
// introspection result, cheaply (substring), without full parsing. Requires the
// __schema marker plus a structural companion so a request that merely echoes
// "__schema" as a string does not match.
func LooksLikeIntrospection(body []byte) bool {
	if !bytes.Contains(body, []byte(`"__schema"`)) {
		return false
	}
	return containsAny(body, `"queryType"`, `"types"`, `"mutationType"`)
}
