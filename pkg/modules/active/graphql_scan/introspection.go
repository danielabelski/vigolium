package graphql_scan

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/graphqlx"
)

// graphqlPaths are common GraphQL endpoint locations to probe.
var graphqlPaths = []string{
	"/graphql",
	"/api/graphql",
	"/graphql/v1",
	"/v1/graphql",
	"/gql",
	"/query",
	"/api/query",
	"/graphql/console",
}

// typenameQuery is a simple query to detect GraphQL endpoints.
const typenameQuery = `{"query":"{ __typename }"}`

// introspectionQuery is the full introspection query to enumerate the schema.
// It uses the shared canonical query (queryType/mutationType names, deep ofType
// chains, inputFields, enumValues) so both the SQLi field-picker below and the
// operations expander can build valid documents from one fetch.
var introspectionQuery = graphqlx.IntrospectionBody()

// genericFieldNames are common GraphQL field names to try when introspection is disabled.
var genericFieldNames = []string{
	"users", "user", "search", "login", "products",
	"items", "posts", "comments", "messages",
}

// sqlErrorPatterns detect SQL errors in GraphQL responses.
var sqlErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)you have an error in your SQL syntax`),          // MySQL
	regexp.MustCompile(`(?i)ERROR:\s+syntax error at or near`),              // PostgreSQL
	regexp.MustCompile(`(?i)\[Microsoft\]\[ODBC SQL Server Driver\]`),       // MSSQL
	regexp.MustCompile(`(?i)ORA-\d{5}`),                                     // Oracle
	regexp.MustCompile(`(?i)SQLite3::query\b|near\s+".*":\s*syntax error`),  // SQLite
	regexp.MustCompile(`(?i)Unclosed quotation mark`),                       // MSSQL
	regexp.MustCompile(`(?i)mysql_fetch|pg_query|sqlite_query|mssql_query`), // PHP DB functions
}

// introspectionField represents a discovered field with string arguments.
type introspectionField struct {
	fieldName string
	argName   string
}

// parseIntrospectionResponse extracts fields with string arguments from introspection response.
func parseIntrospectionResponse(body string) []introspectionField {
	var result struct {
		Data struct {
			Schema struct {
				Types []struct {
					Name   string `json:"name"`
					Fields []struct {
						Name string `json:"name"`
						Args []struct {
							Name string `json:"name"`
							Type struct {
								Name   string `json:"name"`
								Kind   string `json:"kind"`
								OfType *struct {
									Name string `json:"name"`
								} `json:"ofType"`
							} `json:"type"`
						} `json:"args"`
					} `json:"fields"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}

	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return nil
	}

	var fields []introspectionField
	for _, t := range result.Data.Schema.Types {
		// Skip internal types (prefixed with __)
		if strings.HasPrefix(t.Name, "__") {
			continue
		}
		for _, f := range t.Fields {
			for _, arg := range f.Args {
				typeName := arg.Type.Name
				if typeName == "" && arg.Type.OfType != nil {
					typeName = arg.Type.OfType.Name
				}
				if strings.EqualFold(typeName, "String") || strings.EqualFold(typeName, "ID") {
					fields = append(fields, introspectionField{
						fieldName: f.Name,
						argName:   arg.Name,
					})
				}
			}
		}
	}

	return fields
}

// containsSQLError checks if the body contains any SQL error pattern.
func containsSQLError(body string) bool {
	for _, pattern := range sqlErrorPatterns {
		if pattern.MatchString(body) {
			return true
		}
	}
	return false
}

// isGraphQLEndpoint checks if the response indicates a valid GraphQL endpoint.
func isGraphQLEndpoint(body string) bool {
	return strings.Contains(body, "__typename") ||
		strings.Contains(body, `"data"`)
}

// hasIntrospection checks if the response contains a full introspection result.
func hasIntrospection(body string) bool {
	return strings.Contains(body, "__schema") &&
		strings.Contains(body, "types") &&
		strings.Contains(body, "fields")
}
