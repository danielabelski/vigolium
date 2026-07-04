package graphqlx

import (
	"encoding/json"
	"strings"
	"testing"
)

// sampleIntrospection is a compact but realistic introspection result covering
// scalars, ID args, enums, input objects, lists, nested objects and required
// vs optional args.
const sampleIntrospection = `{
  "data": {
    "__schema": {
      "queryType": {"name": "Query"},
      "mutationType": {"name": "Mutation"},
      "subscriptionType": null,
      "types": [
        {
          "kind": "OBJECT", "name": "Query",
          "fields": [
            {"name": "users", "args": [], "type": {"kind": "LIST", "name": null, "ofType": {"kind": "OBJECT", "name": "User", "ofType": null}}},
            {"name": "user", "args": [
              {"name": "id", "defaultValue": null, "type": {"kind": "NON_NULL", "name": null, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": null}}}
            ], "type": {"kind": "OBJECT", "name": "User", "ofType": null}},
            {"name": "search", "args": [
              {"name": "term", "defaultValue": null, "type": {"kind": "NON_NULL", "name": null, "ofType": {"kind": "SCALAR", "name": "String", "ofType": null}}},
              {"name": "limit", "defaultValue": "10", "type": {"kind": "SCALAR", "name": "Int", "ofType": null}}
            ], "type": {"kind": "SCALAR", "name": "String", "ofType": null}},
            {"name": "role", "args": [
              {"name": "kind", "defaultValue": null, "type": {"kind": "NON_NULL", "name": null, "ofType": {"kind": "ENUM", "name": "RoleKind", "ofType": null}}}
            ], "type": {"kind": "SCALAR", "name": "String", "ofType": null}},
            {"name": "createReport", "args": [
              {"name": "input", "defaultValue": null, "type": {"kind": "NON_NULL", "name": null, "ofType": {"kind": "INPUT_OBJECT", "name": "ReportInput", "ofType": null}}}
            ], "type": {"kind": "OBJECT", "name": "User", "ofType": null}},
            {"name": "__hidden", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": null}}
          ]
        },
        {
          "kind": "OBJECT", "name": "Mutation",
          "fields": [
            {"name": "deleteUser", "args": [
              {"name": "id", "defaultValue": null, "type": {"kind": "NON_NULL", "name": null, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": null}}}
            ], "type": {"kind": "SCALAR", "name": "Boolean", "ofType": null}}
          ]
        },
        {
          "kind": "OBJECT", "name": "User",
          "fields": [
            {"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "ID", "ofType": null}},
            {"name": "name", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": null}},
            {"name": "secret", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": null}},
            {"name": "manager", "args": [], "type": {"kind": "OBJECT", "name": "User", "ofType": null}}
          ]
        },
        {
          "kind": "ENUM", "name": "RoleKind",
          "enumValues": [{"name": "ADMIN"}, {"name": "USER"}]
        },
        {
          "kind": "INPUT_OBJECT", "name": "ReportInput",
          "inputFields": [
            {"name": "title", "defaultValue": null, "type": {"kind": "NON_NULL", "name": null, "ofType": {"kind": "SCALAR", "name": "String", "ofType": null}}},
            {"name": "note", "defaultValue": null, "type": {"kind": "SCALAR", "name": "String", "ofType": null}}
          ]
        }
      ]
    }
  }
}`

func mustParse(t *testing.T) *Schema {
	t.Helper()
	s, ok := ParseSchema([]byte(sampleIntrospection))
	if !ok {
		t.Fatal("ParseSchema failed on sample")
	}
	return s
}

func TestParseSchema_Basics(t *testing.T) {
	s := mustParse(t)
	if s.QueryType != "Query" || s.MutationType != "Mutation" {
		t.Fatalf("roots = %q/%q", s.QueryType, s.MutationType)
	}
	if s.SubscriptionType != "" {
		t.Errorf("subscription should be empty, got %q", s.SubscriptionType)
	}
	if u := s.TypeByName("User"); u == nil || len(u.Fields) != 4 {
		t.Fatalf("User type not parsed correctly: %+v", u)
	}
	if rk := s.TypeByName("RoleKind"); rk == nil || len(rk.EnumValues) != 2 {
		t.Fatalf("RoleKind enum not parsed: %+v", rk)
	}
}

func TestParseSchema_RejectsNonIntrospection(t *testing.T) {
	for _, body := range []string{
		`not json`,
		`{"data":{"user":null}}`,
		`{"data":{"__schema":{"types":[]}}}`,
	} {
		if _, ok := ParseSchema([]byte(body)); ok {
			t.Errorf("expected reject for %q", body)
		}
	}
}

func TestLooksLikeIntrospection(t *testing.T) {
	cases := map[string]bool{
		sampleIntrospection:                      true,
		`{"data":{"__schema":{"queryType":{}}}}`: true,
		`{"data":{"__typename":"Query"}}`:        false,
		`{"q":"give me the __schema please"}`:    false, // no structural companion
		`{"errors":[{"message":"no"}]}`:          false,
	}
	for body, want := range cases {
		if got := LooksLikeIntrospection([]byte(body)); got != want {
			t.Errorf("LooksLikeIntrospection(%.40q) = %v want %v", body, got, want)
		}
	}
}

func TestBuildOperations_QueriesOnly(t *testing.T) {
	s := mustParse(t)
	ops := BuildOperations(s, BuildOptions{})

	byField := map[string]Operation{}
	for _, op := range ops {
		if op.Kind != KindQuery {
			t.Fatalf("mutation leaked without IncludeMutations: %+v", op)
		}
		byField[op.RootField] = op
	}

	// Internal field must be excluded.
	if _, ok := byField["__hidden"]; ok {
		t.Error("__hidden should not be exercised")
	}
	// deleteUser is a mutation → must be absent.
	if _, ok := byField["deleteUser"]; ok {
		t.Error("mutation deleteUser must not appear in query-only build")
	}

	// Every generated query must be valid JSON and parse a "query" doc.
	for _, op := range ops {
		var m map[string]string
		if err := json.Unmarshal([]byte(op.Body), &m); err != nil {
			t.Fatalf("op body not valid JSON: %v (%s)", err, op.Body)
		}
		if !strings.HasPrefix(m["query"], "query {") {
			t.Errorf("query doc malformed: %s", m["query"])
		}
	}

	// users: argless, object return → must select leaf fields, not __typename only.
	users, ok := byField["users"]
	if !ok {
		t.Fatal("users op missing")
	}
	if !strings.Contains(users.Query, "id") || !strings.Contains(users.Query, "name") {
		t.Errorf("users selection missing leaf fields: %s", users.Query)
	}

	// user(id:): required ID arg filled with a quoted example.
	user, ok := byField["user"]
	if !ok {
		t.Fatal("user op missing")
	}
	if !strings.Contains(user.Query, `user(id: "1")`) {
		t.Errorf("user arg not rendered: %s", user.Query)
	}

	// search(term:): required String filled; optional 'limit' (has default) omitted.
	search, ok := byField["search"]
	if !ok {
		t.Fatal("search op missing")
	}
	if !strings.Contains(search.Query, `term: "vigolium"`) {
		t.Errorf("search term not rendered: %s", search.Query)
	}
	if strings.Contains(search.Query, "limit") {
		t.Errorf("optional defaulted arg 'limit' should be omitted: %s", search.Query)
	}
	// scalar return → no selection set.
	if strings.Contains(search.Query, "{ id") {
		t.Errorf("scalar return should have no selection set: %s", search.Query)
	}

	// role(kind:): enum arg rendered as a bare identifier (first value).
	role, ok := byField["role"]
	if !ok {
		t.Fatal("role op missing")
	}
	if !strings.Contains(role.Query, "kind: ADMIN") {
		t.Errorf("enum arg not rendered bare: %s", role.Query)
	}

	// createReport(input:): input object with required 'title', optional 'note'.
	rep, ok := byField["createReport"]
	if !ok {
		t.Fatal("createReport op missing")
	}
	if !strings.Contains(rep.Query, `input: {title: "vigolium"}`) {
		t.Errorf("input object not rendered minimally: %s", rep.Query)
	}
}

func TestBuildOperations_IncludeMutations(t *testing.T) {
	s := mustParse(t)
	ops := BuildOperations(s, BuildOptions{IncludeMutations: true})
	var sawMutation bool
	for _, op := range ops {
		if op.Kind == KindMutation && op.RootField == "deleteUser" {
			sawMutation = true
			if !strings.HasPrefix(mustQuery(t, op.Body), "mutation {") {
				t.Errorf("mutation doc malformed: %s", op.Query)
			}
		}
	}
	if !sawMutation {
		t.Error("deleteUser mutation not generated under IncludeMutations")
	}
}

func TestBuildOperations_OnlyArgless(t *testing.T) {
	s := mustParse(t)
	ops := BuildOperations(s, BuildOptions{OnlyArgless: true})
	for _, op := range ops {
		if op.RootField != "users" {
			t.Errorf("OnlyArgless should yield only argless root fields, got %q", op.RootField)
		}
	}
}

func TestBuildOperations_SelectionDepthBounded(t *testing.T) {
	s := mustParse(t)
	ops := BuildOperations(s, BuildOptions{})
	for _, op := range ops {
		// A recursive User.manager chain must not blow past the depth bound.
		if strings.Count(op.Query, "manager") > maxSelectionDepth {
			t.Errorf("selection recursion not bounded: %s", op.Query)
		}
	}
}

func TestBuildOperations_MaxOperations(t *testing.T) {
	s := mustParse(t)
	ops := BuildOperations(s, BuildOptions{MaxOperations: 2})
	if len(ops) > 2 {
		t.Fatalf("MaxOperations not honored: %d", len(ops))
	}
}

func TestConfirmsTypename(t *testing.T) {
	if !ConfirmsTypename([]byte(`{"data":{"__typename":"Query"}}`)) {
		t.Error("should confirm typename echo")
	}
	if ConfirmsTypename([]byte(`<html>GraphiQL</html>`)) {
		t.Error("html must not confirm typename")
	}
	if ConfirmsTypename([]byte(`{"data":null}`)) {
		t.Error("data without __typename must not confirm")
	}
}

func TestLooksLikeGraphQLResponse(t *testing.T) {
	cases := map[string]bool{
		`{"data":{"x":1}}`:             true,
		`{"errors":[{"message":"x"}]}`: true,
		`<html>hi</html>`:              false,
		`plain text graphql mentioned`: false,
		``:                             false,
	}
	for body, want := range cases {
		if got := LooksLikeGraphQLResponse([]byte(body)); got != want {
			t.Errorf("LooksLikeGraphQLResponse(%q)=%v want %v", body, got, want)
		}
	}
}

func mustQuery(t *testing.T, body string) string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("bad body json: %v", err)
	}
	return m["query"]
}
