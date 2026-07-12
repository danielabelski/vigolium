package sqli_error_based

import (
	"regexp"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// checkBodyContainsErrorMsg reports whether body leaked a DBMS error and, if so,
// returns the backend name and the matching pattern. The signature catalog now
// lives in modkit (the single source of truth shared with input-behavior-probe and
// any other consumer) so a new DBMS signature is inherited everywhere at once; this
// package-local wrapper keeps a stable entry point for the module's error-signature
// regression tests.
func checkBodyContainsErrorMsg(body string) (string, *regexp.Regexp, bool) {
	return modkit.MatchSQLError(body)
}
