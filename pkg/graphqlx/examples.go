package graphqlx

import (
	"encoding/json"
	"strings"
)

// Example scalar literals used to fill required arguments. Kept deliberately
// benign — the goal is to reach resolvers with a valid value, not to attack
// (injection is a separate, opt-in phase).
const (
	exampleString  = "vigolium"
	exampleID      = "1"
	exampleInt     = "1"
	exampleFloat   = "1.5"
	exampleBoolean = "true"
)

// renderLiteral produces a valid GraphQL inline literal for the given type
// reference. Returns (literal, true) on success, or ("", false) when the type
// cannot be confidently rendered (e.g. an input object with an unrenderable
// required field, or excessive recursion) so the caller can skip the field.
func renderLiteral(s *Schema, ref *TypeRef, depth int) (string, bool) {
	if ref == nil || depth > maxLiteralDepth {
		return "", false
	}

	// Lists: render a single-element list of the element type.
	if ref.IsList() {
		elemLit, ok := renderLiteral(s, ref.elem(), depth+1)
		if !ok {
			return "", false
		}
		return "[" + elemLit + "]", true
	}

	named := ref.Named()
	if named == "" {
		return "", false
	}

	switch named {
	case "String":
		return quoteGraphQLString(exampleString), true
	case "ID":
		return quoteGraphQLString(exampleID), true
	case "Int":
		return exampleInt, true
	case "Float":
		return exampleFloat, true
	case "Boolean":
		return exampleBoolean, true
	}

	t := s.TypeByName(named)
	if t == nil {
		// Unknown/custom scalar — a JSON string is the safest broadly-valid form.
		return quoteGraphQLString(exampleString), true
	}

	switch t.Kind {
	case KindScalar:
		// Custom scalars (DateTime, JSON, Upload, …) accept a string in practice.
		return quoteGraphQLString(exampleString), true
	case KindEnum:
		if len(t.EnumValues) > 0 {
			return t.EnumValues[0], true // enum literals are bare identifiers
		}
		return "", false
	case KindInputObject:
		return renderInputObject(s, t, depth)
	}
	return "", false
}

// renderInputObject renders an input object literal, filling only its required
// fields (recursively). Returns false if any required field is unrenderable.
func renderInputObject(s *Schema, t *Type, depth int) (string, bool) {
	if depth+1 > maxLiteralDepth {
		return "", false
	}
	var parts []string
	for _, in := range t.InputFields {
		if in == nil {
			continue
		}
		if !in.Type.IsRequired() || in.DefaultValue != "" {
			continue // optional or defaulted → omit
		}
		lit, ok := renderLiteral(s, in.Type, depth+1)
		if !ok {
			return "", false
		}
		parts = append(parts, in.Name+": "+lit)
	}
	return "{" + strings.Join(parts, ", ") + "}", true
}

// quoteGraphQLString returns a GraphQL string literal. GraphQL string escaping
// matches JSON string escaping, so json.Marshal produces a valid literal.
func quoteGraphQLString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return string(b)
}
