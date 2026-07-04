// Package graphqlx provides transport-agnostic GraphQL logic shared by the
// scanner modules: the canonical introspection query, a schema model parsed
// from an introspection response, a builder that turns a schema into concrete
// operations (mirroring how an OpenAPI spec is expanded into requests), typed
// example-value synthesis, and lightweight detection/fingerprint helpers.
//
// Nothing here performs I/O — callers own the HTTP layer — so the package is
// pure and cheaply unit-testable.
package graphqlx

import "strings"

// Kind constants for GraphQL type kinds as returned by introspection.
const (
	KindScalar      = "SCALAR"
	KindObject      = "OBJECT"
	KindInterface   = "INTERFACE"
	KindUnion       = "UNION"
	KindEnum        = "ENUM"
	KindInputObject = "INPUT_OBJECT"
	KindList        = "LIST"
	KindNonNull     = "NON_NULL"
)

// Schema is the subset of an introspection result needed to build operations.
type Schema struct {
	QueryType        string
	MutationType     string
	SubscriptionType string
	Types            []*Type

	index map[string]*Type
}

// Type is a named GraphQL type from the schema.
type Type struct {
	Kind        string
	Name        string
	Fields      []*Field
	InputFields []*InputValue
	EnumValues  []string
}

// Field is a field on an object/interface type.
type Field struct {
	Name string
	Args []*InputValue
	Type *TypeRef
}

// InputValue is a field argument or an input-object field.
type InputValue struct {
	Name         string
	Type         *TypeRef
	DefaultValue string // raw GraphQL literal, "" when absent
}

// TypeRef is a possibly-wrapped reference to a type (NON_NULL / LIST wrappers
// around a named type).
type TypeRef struct {
	Kind   string
	Name   string
	OfType *TypeRef
}

// Named resolves through NON_NULL / LIST wrappers to the underlying named type.
// Returns "" if the reference has no named base (malformed).
func (t *TypeRef) Named() string {
	for i := 0; t != nil && i < 16; i++ {
		if t.Name != "" {
			return t.Name
		}
		t = t.OfType
	}
	return ""
}

// IsRequired reports whether the outermost wrapper is NON_NULL (and the type
// has no default value — callers pass the default separately).
func (t *TypeRef) IsRequired() bool {
	return t != nil && t.Kind == KindNonNull
}

// IsList reports whether the type is a list at any wrapper level below an
// optional leading NON_NULL.
func (t *TypeRef) IsList() bool {
	cur := t
	if cur != nil && cur.Kind == KindNonNull {
		cur = cur.OfType
	}
	return cur != nil && cur.Kind == KindList
}

// elem returns the element type reference of a list, unwrapping a leading
// NON_NULL. Returns nil when the type is not a list.
func (t *TypeRef) elem() *TypeRef {
	cur := t
	if cur != nil && cur.Kind == KindNonNull {
		cur = cur.OfType
	}
	if cur == nil || cur.Kind != KindList {
		return nil
	}
	inner := cur.OfType
	if inner != nil && inner.Kind == KindNonNull {
		inner = inner.OfType
	}
	return inner
}

// TypeByName returns the named type or nil.
func (s *Schema) TypeByName(name string) *Type {
	if s == nil || name == "" {
		return nil
	}
	if s.index == nil {
		s.index = make(map[string]*Type, len(s.Types))
		for _, t := range s.Types {
			if t != nil && t.Name != "" {
				s.index[t.Name] = t
			}
		}
	}
	return s.index[name]
}

// rootType returns the object type backing the given root operation ("query" or
// "mutation"), or nil when the schema does not declare it.
func (s *Schema) rootType(kind OpKind) *Type {
	if s == nil {
		return nil
	}
	var name string
	switch kind {
	case KindQuery:
		name = s.QueryType
	case KindMutation:
		name = s.MutationType
	}
	if name == "" {
		return nil
	}
	return s.TypeByName(name)
}

// isInternalName reports whether a type/field name is a GraphQL internal
// (introspection) name that should never be exercised.
func isInternalName(name string) bool {
	return strings.HasPrefix(name, "__")
}

// isLeafKind reports whether a type kind renders without a selection set.
func isLeafKind(kind string) bool {
	return kind == KindScalar || kind == KindEnum
}

// builtinScalars are the GraphQL spec scalars, which some servers omit from the
// introspection types list. Treated as leaves regardless of index presence.
var builtinScalars = map[string]struct{}{
	"String": {}, "ID": {}, "Int": {}, "Float": {}, "Boolean": {},
}

// isLeafType reports whether a named type takes no selection set (a scalar or
// enum), resolving built-in scalars even when absent from the schema index.
func (s *Schema) isLeafType(name string) bool {
	if name == "" {
		return false
	}
	if _, ok := builtinScalars[name]; ok {
		return true
	}
	if t := s.TypeByName(name); t != nil {
		return isLeafKind(t.Kind)
	}
	// Unknown named type not in the index and not a built-in: most commonly a
	// custom scalar (which is a leaf). Treating it as a leaf keeps the operation
	// well-formed (a stray missing selection set only risks a validation error,
	// never an invalid nested descent).
	return true
}

// isCompositeType reports whether a named type requires a selection set (object
// or interface). Unions are handled separately (inline fragments).
func (s *Schema) isCompositeType(name string) bool {
	t := s.TypeByName(name)
	return t != nil && (t.Kind == KindObject || t.Kind == KindInterface)
}
