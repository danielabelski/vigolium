package modkit

import "testing"

// TestMatchSQLError_AddedSignatures pins the DBMS error signatures added to the
// shared catalog: each must be recognised (with its expected backend hint), and
// ordinary prose that merely mentions "syntax" or "object" must not match.
func TestMatchSQLError_AddedSignatures(t *testing.T) {
	hits := []struct {
		body string
		want string
	}{
		{"ORA-06550: line 1, column 7:\nPLS-00201: identifier 'X' must be declared", "Oracle"},
		{"Msg 102, Level 15, State 1: Incorrect syntax near ')'.", "Microsoft SQL Server"},
		{"Invalid object name 'users_backup'.", "Microsoft SQL Server"},
		{"Unclosed quotation mark before the character string ''.", "Microsoft SQL Server"},
		{"ERROR 1136 (21S01): Column count doesn't match value count at row 1", "MySQL"},
		{"ERROR: unterminated quoted string at or near \"'\"", "PostgreSQL"},
		{"ERROR: unterminated quoted identifier at or near \"\\\"\"", "PostgreSQL"},
	}
	for _, h := range hits {
		name, _, ok := MatchSQLError(h.body)
		if !ok {
			t.Errorf("expected SQL error match for %q", h.body)
			continue
		}
		if name != h.want {
			t.Errorf("MatchSQLError(%q) backend = %q, want %q", h.body, name, h.want)
		}
	}

	// Benign prose that superficially resembles the phrases must stay quiet.
	benign := []string{
		"Please check your syntax and try again.",
		"The object name field is required.",
		"Learn about our new database features today!",
		"Unterminated builds are common in CI pipelines.",
	}
	for _, b := range benign {
		if _, _, ok := MatchSQLError(b); ok {
			t.Errorf("benign text must not match as a SQL error: %q", b)
		}
	}
}
