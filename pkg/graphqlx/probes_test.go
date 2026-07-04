package graphqlx

import (
	"strings"
	"testing"
)

func TestIDLookupFields(t *testing.T) {
	s := mustParse(t)
	lookups := s.IDLookupFields()

	// user(id: ID!) → User is the only id-lookup returning a single object.
	// users is a list; search/role/createReport don't take an "id".
	var got []string
	for _, l := range lookups {
		got = append(got, l.Field.Name+"/"+l.IDArg+"/"+l.IDArgType())
	}
	if len(lookups) != 1 || got[0] != "user/id/ID" {
		t.Fatalf("IDLookupFields = %v, want [user/id/ID]", got)
	}
}

func TestRenderProbe(t *testing.T) {
	s := mustParse(t)
	lookups := s.IDLookupFields()
	if len(lookups) == 0 {
		t.Fatal("no lookups")
	}
	l := lookups[0]

	q, ok := s.RenderProbe(l.Field, l.IDArg, QuoteString("42"), 0)
	if !ok {
		t.Fatal("RenderProbe failed")
	}
	if !strings.Contains(q, `user(id: "42")`) {
		t.Errorf("probe missing overridden id: %s", q)
	}
	// Object return → selection set present with leaf fields.
	if !strings.Contains(q, "id") || !strings.Contains(q, "name") {
		t.Errorf("probe missing selection: %s", q)
	}
	if !strings.HasPrefix(q, "query { user") {
		t.Errorf("probe malformed: %s", q)
	}
}

func TestDepthProbe(t *testing.T) {
	s := mustParse(t)
	// User.manager: User is the self-referential cycle; users/user reach User.
	q, ok := s.DepthProbe(4)
	if !ok {
		t.Fatal("DepthProbe should find the User.manager cycle")
	}
	if strings.Count(q, "manager") != 4 {
		t.Errorf("expected depth 4 (4 manager levels): %s", q)
	}
	if !strings.Contains(q, "__typename") {
		t.Errorf("depth probe should bottom out at __typename: %s", q)
	}
}

func TestDepthProbe_NoCycle(t *testing.T) {
	body := `{"data":{"__schema":{
		"queryType":{"name":"Query"},
		"types":[
			{"kind":"OBJECT","name":"Query","fields":[
				{"name":"ping","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}}
			]}
		]
	}}}`
	s, ok := ParseSchema([]byte(body))
	if !ok {
		t.Fatal("parse")
	}
	if _, ok := s.DepthProbe(4); ok {
		t.Error("expected no depth probe without a self-referential cycle")
	}
}

func TestQueryFields_ExcludesInternal(t *testing.T) {
	s := mustParse(t)
	for _, f := range s.QueryFields() {
		if strings.HasPrefix(f.Name, "__") {
			t.Errorf("internal field leaked: %s", f.Name)
		}
	}
}

func TestQueryBody(t *testing.T) {
	got := QueryBody(`query { a }`)
	if got != `{"query":"query { a }"}` {
		t.Errorf("QueryBody = %s", got)
	}
}
