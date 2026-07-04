package graphqlx

import (
	"encoding/json"
	"sort"
	"strings"
)

// OpKind is the GraphQL root operation kind.
type OpKind string

const (
	KindQuery    OpKind = "query"
	KindMutation OpKind = "mutation"
)

// Operation is a concrete, ready-to-send GraphQL operation synthesized from the
// schema. Body is the JSON request body ({"query":"..."}).
type Operation struct {
	Kind      OpKind
	RootField string   // the root field this operation invokes
	Query     string   // the raw GraphQL document
	Body      string   // JSON POST body
	ArgNames  []string // required argument names filled (for reporting)
}

// BuildOptions tunes operation generation.
type BuildOptions struct {
	// IncludeMutations enables synthesizing mutation operations. Off by default:
	// mutations change state, so they are only exercised under an explicit
	// aggressive/deep opt-in.
	IncludeMutations bool
	// MaxOperations caps the number of operations returned (0 → DefaultMaxOperations).
	MaxOperations int
	// MaxSelectionFields caps leaf fields selected per object return type
	// (0 → DefaultMaxSelectionFields).
	MaxSelectionFields int
	// OnlyArgless restricts generation to root fields with no required args —
	// the safest, most data-yielding subset (pure enumeration).
	OnlyArgless bool
}

const (
	// DefaultMaxOperations bounds fed traffic so an enormous schema cannot flood
	// the pipeline.
	DefaultMaxOperations = 40
	// DefaultMaxSelectionFields bounds selection-set width per operation.
	DefaultMaxSelectionFields = 6
	// maxLiteralDepth bounds recursive input-object literal rendering.
	maxLiteralDepth = 4
	// maxSelectionDepth bounds nested selection sets (object → object → …).
	maxSelectionDepth = 3
)

// BuildOperations enumerates the root query (and optionally mutation) fields and
// synthesizes a minimal valid operation for each: required arguments filled with
// typed example literals, and a leaf-biased selection set for object returns. A
// root field is skipped when any required argument cannot be confidently
// rendered, so every emitted operation is well-formed rather than garbage.
func BuildOperations(s *Schema, opts BuildOptions) []Operation {
	if s == nil {
		return nil
	}
	if opts.MaxOperations <= 0 {
		opts.MaxOperations = DefaultMaxOperations
	}
	if opts.MaxSelectionFields <= 0 {
		opts.MaxSelectionFields = DefaultMaxSelectionFields
	}

	kinds := []OpKind{KindQuery}
	if opts.IncludeMutations {
		kinds = append(kinds, KindMutation)
	}

	var ops []Operation
	for _, kind := range kinds {
		root := s.rootType(kind)
		if root == nil {
			continue
		}
		fields := append([]*Field(nil), root.Fields...)
		// Stable order: argless fields first (highest signal, lowest risk), then
		// alphabetical, so the operation cap keeps the most useful ones.
		sort.SliceStable(fields, func(i, j int) bool {
			ri, rj := hasRequiredArgs(fields[i]), hasRequiredArgs(fields[j])
			if ri != rj {
				return !ri
			}
			return fields[i].Name < fields[j].Name
		})

		for _, f := range fields {
			if len(ops) >= opts.MaxOperations {
				return ops
			}
			if f == nil || isInternalName(f.Name) {
				continue
			}
			if opts.OnlyArgless && hasRequiredArgs(f) {
				continue
			}
			op, ok := buildOperation(s, kind, f, opts)
			if !ok {
				continue
			}
			ops = append(ops, op)
		}
	}
	return ops
}

// buildOperation renders one root field into an Operation, or (zero, false) if
// a required argument cannot be rendered.
func buildOperation(s *Schema, kind OpKind, f *Field, opts BuildOptions) (Operation, bool) {
	var argParts []string
	var argNames []string
	for _, a := range f.Args {
		if a == nil {
			continue
		}
		// Only fill required args (NON_NULL with no default). Optional args are
		// omitted to keep the operation minimal and valid.
		if !a.Type.IsRequired() || a.DefaultValue != "" {
			continue
		}
		lit, ok := renderLiteral(s, a.Type, 0)
		if !ok {
			return Operation{}, false // cannot satisfy a required arg → skip field
		}
		argParts = append(argParts, a.Name+": "+lit)
		argNames = append(argNames, a.Name)
	}

	sel := buildSelection(s, f.Type, opts.MaxSelectionFields, 0)

	var sb strings.Builder
	sb.WriteString(string(kind))
	sb.WriteString(" { ")
	sb.WriteString(f.Name)
	if len(argParts) > 0 {
		sb.WriteString("(")
		sb.WriteString(strings.Join(argParts, ", "))
		sb.WriteString(")")
	}
	if sel != "" {
		sb.WriteString(" ")
		sb.WriteString(sel)
	}
	sb.WriteString(" }")
	query := sb.String()

	body, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return Operation{}, false
	}
	return Operation{
		Kind:      kind,
		RootField: f.Name,
		Query:     query,
		Body:      string(body),
		ArgNames:  argNames,
	}, true
}

// buildSelection returns a selection set (including braces) for the given return
// type, or "" for leaf (scalar/enum) returns which take no selection set.
func buildSelection(s *Schema, ref *TypeRef, maxFields, depth int) string {
	named := ref.Named()
	t := s.TypeByName(named)
	if t == nil {
		return ""
	}
	if isLeafKind(t.Kind) {
		return ""
	}
	if t.Kind == KindUnion {
		// Unions require inline fragments; __typename is always valid and enough
		// to make the operation well-formed.
		return "{ __typename }"
	}
	if t.Kind != KindObject && t.Kind != KindInterface {
		return ""
	}

	// Collect leaf fields (scalar/enum, no required args) first.
	var leaves []string
	var objs []*Field
	for _, f := range t.Fields {
		if f == nil || isInternalName(f.Name) || hasRequiredArgs(f) {
			continue
		}
		switch {
		case s.isLeafType(f.Type.Named()):
			leaves = append(leaves, f.Name)
		case s.isCompositeType(f.Type.Named()):
			objs = append(objs, f)
		}
		if len(leaves) >= maxFields {
			break
		}
	}

	parts := leaves
	// Descend into at most one nested object to give detectors realistic nested
	// data, bounded by depth to avoid runaway documents.
	if len(parts) < maxFields && depth+1 < maxSelectionDepth {
		for _, of := range objs {
			nested := buildSelection(s, of.Type, maxFields, depth+1)
			if nested != "" {
				parts = append(parts, of.Name+" "+nested)
				break
			}
		}
	}

	if len(parts) == 0 {
		return "{ __typename }"
	}
	return "{ " + strings.Join(parts, " ") + " }"
}

// DepthProbe builds a deeply-nested query by following a self-referential object
// relationship reachable from an argument-free root query field, to the given
// depth. It returns ("", false) when the schema has no usable cycle. The probe
// is a single non-amplified query (no aliasing, no large list arguments) — its
// only purpose is to observe whether the server enforces a depth/complexity
// limit, never to exhaust resources.
func (s *Schema) DepthProbe(depth int) (string, bool) {
	if depth < 1 {
		depth = 1
	}
	root := s.rootType(KindQuery)
	if root == nil {
		return "", false
	}
	for _, rf := range root.Fields {
		if rf == nil || isInternalName(rf.Name) || hasRequiredArgs(rf) {
			continue
		}
		tName := rf.Type.Named()
		t := s.TypeByName(tName)
		if t == nil || t.Kind != KindObject {
			continue
		}
		selfField := ""
		for _, f := range t.Fields {
			if f == nil || isInternalName(f.Name) || hasRequiredArgs(f) {
				continue
			}
			if f.Type.Named() == tName {
				selfField = f.Name
				break
			}
		}
		if selfField == "" {
			continue
		}
		inner := "{ __typename }"
		for i := 0; i < depth; i++ {
			inner = "{ " + selfField + " " + inner + " }"
		}
		return "query { " + rf.Name + " " + inner + " }", true
	}
	return "", false
}

// QueryFields returns the root query fields (nil-safe, introspection fields
// excluded).
func (s *Schema) QueryFields() []*Field {
	root := s.rootType(KindQuery)
	if root == nil {
		return nil
	}
	var out []*Field
	for _, f := range root.Fields {
		if f != nil && !isInternalName(f.Name) {
			out = append(out, f)
		}
	}
	return out
}

// QueryBody wraps a raw GraphQL document into a JSON POST body.
func QueryBody(query string) string {
	b, _ := json.Marshal(map[string]string{"query": query})
	return string(b)
}

// QuoteString returns query, escaped as a GraphQL string literal.
func QuoteString(s string) string { return quoteGraphQLString(s) }

// IDLookupField is a root query field that fetches a single object by an
// id-like scalar argument — the BOLA/IDOR probe surface.
type IDLookupField struct {
	Field *Field
	IDArg string // the identifier argument name
}

// IDArgType returns the named type of the identifier argument ("ID", "Int", …).
func (l IDLookupField) IDArgType() string {
	for _, a := range l.Field.Args {
		if a != nil && a.Name == l.IDArg {
			return a.Type.Named()
		}
	}
	return ""
}

// isIDArg reports whether an argument is a primary object identifier: named
// exactly "id" (case-insensitive) and typed as a scalar identifier. Kept strict
// to avoid matching incidental filter args.
func isIDArg(a *InputValue) bool {
	if a == nil {
		return false
	}
	if !strings.EqualFold(a.Name, "id") {
		return false
	}
	switch a.Type.Named() {
	case "ID", "Int", "String":
		return true
	}
	return false
}

// IDLookupFields returns root query fields that take an "id" argument and return
// a single (non-list) object — where every other required argument is
// renderable. These are the fields probed for predictable-ID object access.
func (s *Schema) IDLookupFields() []IDLookupField {
	root := s.rootType(KindQuery)
	if root == nil {
		return nil
	}
	var out []IDLookupField
	for _, f := range root.Fields {
		if f == nil || isInternalName(f.Name) {
			continue
		}
		if f.Type.IsList() || !s.isCompositeType(f.Type.Named()) {
			continue
		}
		idArg := ""
		fillable := true
		for _, a := range f.Args {
			if a == nil {
				continue
			}
			if idArg == "" && isIDArg(a) {
				idArg = a.Name
				continue
			}
			if a.Type.IsRequired() && a.DefaultValue == "" {
				if _, ok := renderLiteral(s, a.Type, 0); !ok {
					fillable = false
					break
				}
			}
		}
		if idArg != "" && fillable {
			out = append(out, IDLookupField{Field: f, IDArg: idArg})
		}
	}
	return out
}

// RenderProbe builds a query document invoking f with its id argument set to
// idLiteral (a ready GraphQL literal) and all other required args auto-filled,
// selecting leaf fields. Returns ("", false) if a required arg is unrenderable.
func (s *Schema) RenderProbe(f *Field, idArg, idLiteral string, maxSel int) (string, bool) {
	if f == nil {
		return "", false
	}
	if maxSel <= 0 {
		maxSel = DefaultMaxSelectionFields
	}
	var argParts []string
	for _, a := range f.Args {
		if a == nil {
			continue
		}
		if a.Name == idArg {
			argParts = append(argParts, a.Name+": "+idLiteral)
			continue
		}
		if !a.Type.IsRequired() || a.DefaultValue != "" {
			continue
		}
		lit, ok := renderLiteral(s, a.Type, 0)
		if !ok {
			return "", false
		}
		argParts = append(argParts, a.Name+": "+lit)
	}
	sel := buildSelection(s, f.Type, maxSel, 0)
	q := "query { " + f.Name
	if len(argParts) > 0 {
		q += "(" + strings.Join(argParts, ", ") + ")"
	}
	if sel != "" {
		q += " " + sel
	}
	q += " }"
	return q, true
}

// hasRequiredArgs reports whether the field has at least one NON_NULL argument
// without a default value.
func hasRequiredArgs(f *Field) bool {
	if f == nil {
		return false
	}
	for _, a := range f.Args {
		if a != nil && a.Type.IsRequired() && a.DefaultValue == "" {
			return true
		}
	}
	return false
}
