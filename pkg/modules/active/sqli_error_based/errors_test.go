package sqli_error_based

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestCheckBodyContainsErrorMsg_SequelizeSQLite(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantDB  string
		wantHit bool
	}{
		{
			name:    "SQLITE_ERROR colon format",
			body:    `{"message":"SQLITE_ERROR: near \"z\": syntax error"}`,
			wantDB:  "SQLite",
			wantHit: true,
		},
		{
			name:    "SequelizeDatabaseError",
			body:    `{"name":"SequelizeDatabaseError","message":"near \"z\": syntax error","sql":"SELECT * FROM Users WHERE email = 'admin'z'' AND password = '123'"}`,
			wantDB:  "SQLite",
			wantHit: true,
		},
		{
			name:    "SQLITE_ERROR bracket format (existing pattern)",
			body:    `[SQLITE_ERROR] near "z": syntax error`,
			wantDB:  "SQLite",
			wantHit: true,
		},
		{
			name:    "SQLAlchemy-wrapped sqlite3 OperationalError (parenthesized, no colon)",
			body:    `sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unrecognized token: "'admin''" [SQL: SELECT * FROM users WHERE username = 'admin'']`,
			wantDB:  "SQLite",
			wantHit: true,
		},
		{
			name:    "no match",
			body:    `{"status":"ok"}`,
			wantDB:  "",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbName, _, hit := checkBodyContainsErrorMsg(tt.body)
			if hit != tt.wantHit {
				t.Errorf("hit = %v, want %v", hit, tt.wantHit)
			}
			if hit && dbName != tt.wantDB {
				t.Errorf("dbName = %q, want %q", dbName, tt.wantDB)
			}
		})
	}
}

// TestCheckBodyContainsErrorMsg_TiDBBoundaries pins the tightened TiDB patterns:
// the short "TiKV" token must still match a genuine error leak but must NOT match
// when it is glued inside a base64/hex blob (e.g. a Cloudflare challenge page's
// random per-request tokens), which is the noise that drove the original false
// positive.
func TestCheckBodyContainsErrorMsg_TiDBBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantHit bool
	}{
		{
			name:    "genuine TiKV error leak matches",
			body:    `ERROR 9005 (HY000): Region is unavailable: TiKV server is busy`,
			wantHit: true,
		},
		{
			name:    "TiDB server phrase matches",
			body:    `{"error":"TiDB server timeout, please retry"}`,
			wantHit: true,
		},
		{
			name:    "TiKV glued inside a base64 blob does not match",
			body:    `md: 'p1B_grnutDRoRTiKV6QwS.iHHlCgBWTBsSTzYs.id2UyL3g'`,
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbName, _, hit := checkBodyContainsErrorMsg(tt.body)
			if hit != tt.wantHit {
				t.Errorf("hit = %v, want %v (db=%q)", hit, tt.wantHit, dbName)
			}
			if hit && dbName != "TiDB" {
				t.Errorf("dbName = %q, want %q", dbName, "TiDB")
			}
		})
	}
}

// TestCheckBodyContainsErrorMsg_OracleDriverBoundaries pins the tightened
// "Oracle...Driver" pattern: a genuine Oracle driver error (the two tokens in one
// short phrase) must still match, but the two words occurring far apart in
// ordinary page content must NOT. The motivating false positive was a 547KB
// Salesforce Aura app shell whose inline analytics feature-flag list carried
// "...userHasAwsRdsOracleEnabled..." and a lone "enableTopDriversBreakdown" label
// ~60KB later, matched by the old unbounded "Oracle.*?Driver" as a single span and
// reported as Critical/Certain Oracle SQLi on both scanned hosts.
func TestCheckBodyContainsErrorMsg_OracleDriverBoundaries(t *testing.T) {
	// Reproduces the real Salesforce shell structure: an "Oracle" feature-flag and
	// a far-away "Driver" label separated by unrelated JSON. The gap exceeds the
	// bounded pattern's window (and the general span guard), so it must not match.
	salesforceShell := `"UnifiedAnalytics.userHasAwsRdsOracleEnabled":false,` +
		strings.Repeat(`"UnifiedAnalytics.userHasSomeConnectorEnabled":false,`, 40) +
		`"cs.businessUser.enableTopDriversBreakdown":true`

	tests := []struct {
		name    string
		body    string
		wantHit bool
	}{
		{
			name:    "genuine Oracle ODBC Driver error matches",
			body:    `Microsoft OLE DB Provider for ODBC Drivers error '80040e14' [Oracle][ODBC Driver]invalid SQL statement`,
			wantHit: true,
		},
		{
			name:    "genuine Oracle JDBC Driver phrase matches",
			body:    `Error initializing Oracle JDBC Driver: ORA-12154`,
			wantHit: true,
		},
		{
			name:    "Oracle flag and distant Drivers label do not match",
			body:    salesforceShell,
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbName, _, hit := checkBodyContainsErrorMsg(tt.body)
			if hit != tt.wantHit {
				t.Errorf("hit = %v, want %v (db=%q)", hit, tt.wantHit, dbName)
			}
			if hit && dbName != "Oracle" {
				t.Errorf("dbName = %q, want %q", dbName, "Oracle")
			}
		})
	}
}

// TestCheckBodyContainsErrorMsg_OverLongMatchSpanGuard pins the general
// over-long-match-span safety net: a loosely-anchored "X.*?Y" pattern whose lazy
// filler bridges an implausibly large span is page noise, not an error leak, and
// is rejected — while a compact, genuine error of the same DBMS still matches.
func TestCheckBodyContainsErrorMsg_OverLongMatchSpanGuard(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantHit bool
		wantDB  string
	}{
		{
			name:    "compact DB2 SQLCODE/SQLSTATE error matches",
			body:    `SQLCODE=-104, SQLSTATE=42601, SQLERRMC=;END-EXEC`,
			wantHit: true,
			wantDB:  "IBM DB2",
		},
		{
			name:    "over-long SQLCODE..SQLSTATE span is rejected",
			body:    `SQLCODE` + strings.Repeat("1", modkit.MaxErrorSignatureSpan+64) + `SQLSTATE`,
			wantHit: false,
		},
		{
			name:    "compact error still detected when surrounded by unrelated content",
			body:    strings.Repeat("benign page content ", 200) + `ORA-01756: quoted string not properly terminated`,
			wantHit: true,
			wantDB:  "Oracle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbName, _, hit := checkBodyContainsErrorMsg(tt.body)
			if hit != tt.wantHit {
				t.Errorf("hit = %v, want %v (db=%q)", hit, tt.wantHit, dbName)
			}
			if hit && tt.wantDB != "" && dbName != tt.wantDB {
				t.Errorf("dbName = %q, want %q", dbName, tt.wantDB)
			}
		})
	}
}

// TestCheckBodyContainsErrorMsg_CockroachBoundaries pins the tightened CockroachDB
// patterns: the bare "CockroachDB" token must still match a genuine error leak but
// must NOT match when it is glued inside ordinary page content — the motivating
// false positive was a Salesforce community 404 shell whose inline feature-flag
// list carried "...userHasCockroachDBEnabled...".
func TestCheckBodyContainsErrorMsg_CockroachBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantHit bool
	}{
		{
			name:    "standalone CockroachDB error matches",
			body:    `pq: syntax error at or near ")" (CockroachDB v23.1)`,
			wantHit: true,
		},
		{
			name:    "crdb_internal reference matches",
			body:    `ERROR: relation "crdb_internal.zones" does not exist`,
			wantHit: true,
		},
		{
			name:    "node-readiness error matches",
			body:    `node is not ready to accept SQL clients`,
			wantHit: true,
		},
		{
			name:    "CockroachDB glued inside a feature-flag name does not match",
			body:    `"UnifiedAnalytics.userHasCockroachDBEnabled":false,"x":1`,
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbName, _, hit := checkBodyContainsErrorMsg(tt.body)
			if hit != tt.wantHit {
				t.Errorf("hit = %v, want %v (db=%q)", hit, tt.wantHit, dbName)
			}
			if hit && dbName != "CockroachDB" {
				t.Errorf("dbName = %q, want %q", dbName, "CockroachDB")
			}
		})
	}
}
