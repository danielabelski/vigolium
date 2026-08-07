package wsdl

import (
	"strings"
)

// XSD structs. Only the subset needed to synthesize a representative sample
// document is modeled: elements, complex/simple types, the sequence/all/choice
// compositors, complexContent extension, attributes, and enumeration/base
// restrictions. Imports/includes are intentionally not resolved — a WCF
// `?singleWsdl` (which we fetch for .svc) inlines every schema, and for hand-fed
// multi-file WSDLs the generator degrades to placeholder leaves rather than
// failing. Resolution is by local name (prefix stripped), which is robust to the
// many prefix conventions in the wild (xsd:/xs:/s:/tns:) at the cost of a
// theoretical collision between two same-named types in different namespaces.

type xsdSchema struct {
	TargetNamespace string           `xml:"targetNamespace,attr"`
	ElementFormQual string           `xml:"elementFormDefault,attr"`
	Elements        []xsdElement     `xml:"http://www.w3.org/2001/XMLSchema element"`
	ComplexTypes    []xsdComplexType `xml:"http://www.w3.org/2001/XMLSchema complexType"`
	SimpleTypes     []xsdSimpleType  `xml:"http://www.w3.org/2001/XMLSchema simpleType"`
}

type xsdElement struct {
	Name        string          `xml:"name,attr"`
	Ref         string          `xml:"ref,attr"`
	Type        string          `xml:"type,attr"`
	MinOccurs   string          `xml:"minOccurs,attr"`
	MaxOccurs   string          `xml:"maxOccurs,attr"`
	Nillable    string          `xml:"nillable,attr"`
	ComplexType *xsdComplexType `xml:"http://www.w3.org/2001/XMLSchema complexType"`
	SimpleType  *xsdSimpleType  `xml:"http://www.w3.org/2001/XMLSchema simpleType"`
}

type xsdComplexType struct {
	Name           string             `xml:"name,attr"`
	Sequence       *xsdGroup          `xml:"http://www.w3.org/2001/XMLSchema sequence"`
	All            *xsdGroup          `xml:"http://www.w3.org/2001/XMLSchema all"`
	Choice         *xsdGroup          `xml:"http://www.w3.org/2001/XMLSchema choice"`
	ComplexContent *xsdComplexContent `xml:"http://www.w3.org/2001/XMLSchema complexContent"`
	Attributes     []xsdAttribute     `xml:"http://www.w3.org/2001/XMLSchema attribute"`
}

type xsdComplexContent struct {
	Extension *xsdExtension `xml:"http://www.w3.org/2001/XMLSchema extension"`
}

type xsdExtension struct {
	Base       string         `xml:"base,attr"`
	Sequence   *xsdGroup      `xml:"http://www.w3.org/2001/XMLSchema sequence"`
	All        *xsdGroup      `xml:"http://www.w3.org/2001/XMLSchema all"`
	Choice     *xsdGroup      `xml:"http://www.w3.org/2001/XMLSchema choice"`
	Attributes []xsdAttribute `xml:"http://www.w3.org/2001/XMLSchema attribute"`
}

// xsdGroup models a sequence/all/choice compositor. Nested compositors are
// captured so an arbitrarily deep model still enumerates every leaf element.
type xsdGroup struct {
	Elements  []xsdElement `xml:"http://www.w3.org/2001/XMLSchema element"`
	Sequences []xsdGroup   `xml:"http://www.w3.org/2001/XMLSchema sequence"`
	Choices   []xsdGroup   `xml:"http://www.w3.org/2001/XMLSchema choice"`
	Alls      []xsdGroup   `xml:"http://www.w3.org/2001/XMLSchema all"`
}

// elements flattens a compositor tree into the ordered leaf/child elements it
// declares.
func (g *xsdGroup) elements() []xsdElement {
	if g == nil {
		return nil
	}
	out := append([]xsdElement(nil), g.Elements...)
	for i := range g.Sequences {
		out = append(out, g.Sequences[i].elements()...)
	}
	for i := range g.Choices {
		out = append(out, g.Choices[i].elements()...)
	}
	for i := range g.Alls {
		out = append(out, g.Alls[i].elements()...)
	}
	return out
}

type xsdSimpleType struct {
	Name        string          `xml:"name,attr"`
	Restriction *xsdRestriction `xml:"http://www.w3.org/2001/XMLSchema restriction"`
}

type xsdRestriction struct {
	Base         string    `xml:"base,attr"`
	Enumerations []xsdEnum `xml:"http://www.w3.org/2001/XMLSchema enumeration"`
}

type xsdEnum struct {
	Value string `xml:"value,attr"`
}

type xsdAttribute struct {
	Name    string `xml:"name,attr"`
	Type    string `xml:"type,attr"`
	Use     string `xml:"use,attr"`
	Fixed   string `xml:"fixed,attr"`
	Default string `xml:"default,attr"`
}

// schemaIndex resolves references (by local name) across all inline schemas.
type schemaIndex struct {
	elements     map[string]*xsdElement
	complexTypes map[string]*xsdComplexType
	simpleTypes  map[string]*xsdSimpleType
	// elementNS records the targetNamespace of the schema that declared each
	// global element, so a generated body root can carry the correct xmlns.
	elementNS map[string]string
}

func buildSchemaIndex(schemas []xsdSchema) *schemaIndex {
	idx := &schemaIndex{
		elements:     map[string]*xsdElement{},
		complexTypes: map[string]*xsdComplexType{},
		simpleTypes:  map[string]*xsdSimpleType{},
		elementNS:    map[string]string{},
	}
	for si := range schemas {
		s := &schemas[si]
		for ei := range s.Elements {
			el := &s.Elements[ei]
			if el.Name != "" {
				idx.elements[el.Name] = el
				idx.elementNS[el.Name] = s.TargetNamespace
			}
		}
		for ci := range s.ComplexTypes {
			ct := &s.ComplexTypes[ci]
			if ct.Name != "" {
				idx.complexTypes[ct.Name] = ct
			}
		}
		for ti := range s.SimpleTypes {
			st := &s.SimpleTypes[ti]
			if st.Name != "" {
				idx.simpleTypes[st.Name] = st
			}
		}
	}
	return idx
}

// maxGenDepth bounds recursion so a self-referential type (a tree node that
// contains children of its own type — common in real schemas) terminates with a
// finite skeleton instead of blowing the stack.
const maxGenDepth = 6

// genCtx carries generation state (caller-supplied value overrides and the
// output builder) so the recursive walkers stay parameter-light.
type genCtx struct {
	idx  *schemaIndex
	vars map[string]string
	sb   *strings.Builder
}

// generateElementBody renders the XSD global element `elemLocal` (the SOAP body
// root for a document-style operation) into an indented XML string starting at
// baseIndent spaces. The root carries xmlns="<targetNamespace>" so the operation
// resolves server-side; the value overrides in vars are applied by leaf local
// name. Returns "" when the element is unknown.
func (idx *schemaIndex) generateElementBody(elemLocal string, vars map[string]string, baseIndent int) string {
	el, ok := idx.elements[elemLocal]
	if !ok {
		return ""
	}
	var sb strings.Builder
	ctx := &genCtx{idx: idx, vars: vars, sb: &sb}
	ctx.writeElement(el, el.Name, idx.elementNS[elemLocal], baseIndent, 0)
	return sb.String()
}

// generateSyntheticElement renders an element that isn't declared globally: a
// tag of the given name whose content is derived from typeQName (an rpc-style
// <part type="…">). ns, when non-empty, is emitted as an xmlns on the tag.
func (idx *schemaIndex) generateSyntheticElement(tagName, typeQName, ns string, vars map[string]string, baseIndent int) string {
	var sb strings.Builder
	ctx := &genCtx{idx: idx, vars: vars, sb: &sb}
	ctx.writeElement(&xsdElement{Name: tagName, Type: typeQName}, tagName, ns, baseIndent, 0)
	return sb.String()
}

// writeElement emits one element node (tagName), recursing into complex types.
// ns, when non-empty, is emitted as an xmlns default declaration on this node
// (used only on the body root — children inherit it).
func (c *genCtx) writeElement(el *xsdElement, tagName, ns string, indentSpaces, depth int) {
	// An element declared as ref="qname" is a placeholder for the referenced
	// global element; render that instead, keeping the referenced name.
	if el.Ref != "" {
		refLocal := localName(el.Ref)
		if target, ok := c.idx.elements[refLocal]; ok {
			c.writeElement(target, target.Name, "", indentSpaces, depth)
			return
		}
		c.writeLeaf(refLocal, ns, indentSpaces, "")
		return
	}

	pad := strings.Repeat(" ", indentSpaces)
	openTag := tagName
	if ns != "" {
		openTag = tagName + ` xmlns="` + ns + `"`
	}

	// Resolve the element's complex model (inline or named) and attributes.
	ct := el.ComplexType
	if ct == nil && el.Type != "" {
		if named, ok := c.idx.complexTypes[localName(el.Type)]; ok {
			ct = named
		}
	}

	if ct != nil && depth < maxGenDepth {
		children, attrs := c.complexParts(ct)
		attrStr := c.renderAttributes(attrs)
		if len(children) == 0 {
			// Complex type with only attributes (or empty) → self-closed / empty.
			c.sb.WriteString(pad + "<" + openTag + attrStr + "></" + tagName + ">\n")
			return
		}
		c.sb.WriteString(pad + "<" + openTag + attrStr + ">\n")
		for i := range children {
			// writeElement resolves ref="" children to the referenced global
			// element's name itself, so passing child.Name (empty for a ref) is
			// correct — the ref branch ignores the tag name argument.
			c.writeElement(&children[i], children[i].Name, "", indentSpaces+2, depth+1)
		}
		c.sb.WriteString(pad + "</" + tagName + ">\n")
		return
	}

	// Leaf: a built-in/simple type, or a complex type past the depth cap.
	value := c.leafValue(el)
	c.writeLeaf(tagName, ns, indentSpaces, value)
}

// writeLeaf emits a single terminal element with a text value.
func (c *genCtx) writeLeaf(tagName, ns string, indentSpaces int, value string) {
	pad := strings.Repeat(" ", indentSpaces)
	openTag := tagName
	if ns != "" {
		openTag = tagName + ` xmlns="` + ns + `"`
	}
	c.sb.WriteString(pad + "<" + openTag + ">" + escapeXML(value) + "</" + tagName + ">\n")
}

// complexParts returns the child elements and attributes of a complex type,
// merging the direct compositor and any complexContent/extension.
func (c *genCtx) complexParts(ct *xsdComplexType) ([]xsdElement, []xsdAttribute) {
	var children []xsdElement
	children = append(children, ct.Sequence.elements()...)
	children = append(children, ct.All.elements()...)
	children = append(children, ct.Choice.elements()...)
	attrs := append([]xsdAttribute(nil), ct.Attributes...)

	if ct.ComplexContent != nil && ct.ComplexContent.Extension != nil {
		ext := ct.ComplexContent.Extension
		// Fold in the base type's parts first (extension semantics: base then new).
		if base, ok := c.idx.complexTypes[localName(ext.Base)]; ok {
			baseChildren, baseAttrs := c.complexParts(base)
			children = append(baseChildren, children...)
			attrs = append(baseAttrs, attrs...)
		}
		children = append(children, ext.Sequence.elements()...)
		children = append(children, ext.All.elements()...)
		children = append(children, ext.Choice.elements()...)
		attrs = append(attrs, ext.Attributes...)
	}
	return children, attrs
}

// renderAttributes builds the attribute string for an opening tag from an XSD
// attribute set. Optional attributes are still emitted so the scanner has a
// position to fuzz; fixed/default values are honored.
func (c *genCtx) renderAttributes(attrs []xsdAttribute) string {
	if len(attrs) == 0 {
		return ""
	}
	var b strings.Builder
	for _, a := range attrs {
		if a.Name == "" {
			continue
		}
		val := a.Fixed
		if val == "" {
			val = a.Default
		}
		if val == "" {
			if v, ok := c.vars[a.Name]; ok {
				val = v
			} else {
				val = sampleForType(a.Type, nil)
			}
		}
		b.WriteString(` ` + a.Name + `="` + escapeXMLAttr(val) + `"`)
	}
	return b.String()
}

// leafValue produces the text value for a terminal element: a caller override
// (by local name) wins, then an inline/named simpleType (first enum or base
// sample), then the element's built-in type sample.
func (c *genCtx) leafValue(el *xsdElement) string {
	if v, ok := c.vars[el.Name]; ok {
		return v
	}
	if el.SimpleType != nil {
		return sampleForSimpleType(el.SimpleType)
	}
	if el.Type != "" {
		if st, ok := c.idx.simpleTypes[localName(el.Type)]; ok {
			return sampleForSimpleType(st)
		}
		return sampleForType(el.Type, c.idx.simpleTypes)
	}
	return "string"
}

// sampleForSimpleType returns the first enumeration value if the type is an
// enumeration, otherwise a sample for its restriction base.
func sampleForSimpleType(st *xsdSimpleType) string {
	if st == nil || st.Restriction == nil {
		return "string"
	}
	if len(st.Restriction.Enumerations) > 0 {
		return st.Restriction.Enumerations[0].Value
	}
	return sampleForType(st.Restriction.Base, nil)
}

// sampleForType maps an XSD type QName to a representative value. Named
// simpleTypes are resolved through the provided index (nil to skip). Unknown
// types fall back to a string placeholder.
func sampleForType(qname string, simpleTypes map[string]*xsdSimpleType) string {
	local := localName(qname)
	if v, ok := builtinSamples[local]; ok {
		return v
	}
	if simpleTypes != nil {
		if st, ok := simpleTypes[local]; ok {
			return sampleForSimpleType(st)
		}
	}
	return "string"
}

// builtinSamples maps XSD built-in datatypes to representative literals. Numeric
// types use 0/0.0 so a value is always present for the scanner to mutate.
var builtinSamples = map[string]string{
	"string":             "string",
	"normalizedString":   "string",
	"token":              "string",
	"language":           "en",
	"Name":               "name",
	"NCName":             "name",
	"NMTOKEN":            "token",
	"ID":                 "id",
	"IDREF":              "id",
	"anyURI":             "http://example.com/",
	"QName":              "qname",
	"boolean":            "false",
	"byte":               "0",
	"unsignedByte":       "0",
	"short":              "0",
	"unsignedShort":      "0",
	"int":                "0",
	"integer":            "0",
	"unsignedInt":        "0",
	"long":               "0",
	"unsignedLong":       "0",
	"nonNegativeInteger": "0",
	"positiveInteger":    "1",
	"negativeInteger":    "-1",
	"nonPositiveInteger": "0",
	"decimal":            "0",
	"float":              "0.0",
	"double":             "0.0",
	"dateTime":           "2020-01-01T00:00:00",
	"date":               "2020-01-01",
	"time":               "00:00:00",
	"duration":           "P0D",
	"gYear":              "2020",
	"gYearMonth":         "2020-01",
	"gMonth":             "--01",
	"gMonthDay":          "--01-01",
	"gDay":               "---01",
	"base64Binary":       "",
	"hexBinary":          "",
	"anyType":            "",
}

// localName strips a namespace prefix from a QName ("tns:Add" -> "Add").
func localName(qname string) string {
	if i := strings.IndexByte(qname, ':'); i >= 0 {
		return qname[i+1:]
	}
	return qname
}

// escapeXML escapes text content for placement between XML tags.
func escapeXML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// escapeXMLAttr escapes a value for an XML attribute (double-quoted).
func escapeXMLAttr(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}
