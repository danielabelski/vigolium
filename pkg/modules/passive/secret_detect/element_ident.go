package secret_detect

import "bytes"

// weakPasswordRuleID is kingfisher.generic.6, the rule matching literal weak-password
// strings (`password<digit>`, `letmein…`, …). In web content those tokens are
// overwhelmingly form-field identifiers, so isIdentifierNameReference drops the ones
// used as names. Scoping on the stable rule ID (not the display name) avoids the
// name/ID drift this module has hit before.
const weakPasswordRuleID = "kingfisher.generic.6"

// elementIdentifierAttrs are the attributes / DOM-lookup functions / framework props
// whose value references an element by id or name and so never carries a credential.
// The whitelist — not the value — is what makes IsElementIdentifierMatch safe, so a
// data-*, content=, value=, or password: position (which CAN carry a secret) is
// deliberately absent. Compared case-insensitively via bytes.EqualFold.
var elementIdentifierAttrs = [][]byte{
	[]byte("id"), []byte("name"), []byte("for"), []byte("htmlfor"),
	[]byte("getelementbyid"), []byte("getelementsbyname"),
	[]byte("queryselector"), []byte("queryselectorall"),
	// ASP.NET WebForms validator/control references — a control id, never a secret.
	[]byte("controltovalidate"), []byte("associatedcontrolid"), []byte("targetcontrolid"),
}

// IsElementPositionNoise reports whether an untrusted-tier match sits in a body
// position that never carries a credential: an element-identifier attribute / prop /
// DOM-lookup value (IsElementIdentifierMatch, any rule), or — for the weak-password
// rule only — a token used as an identifier NAME (isIdentifierNameReference). It
// mirrors IsNonSecretMatch's aggregator shape and owns the rule scoping so
// GradeMatch's control flow stays flat.
func IsElementPositionNoise(body []byte, snippet string, start, end int, ruleID string) bool {
	return IsElementIdentifierMatch(body, snippet, start, end) ||
		(ruleID == weakPasswordRuleID && isIdentifierNameReference(body, snippet, start, end))
}

// IsElementIdentifierMatch reports whether the matched snippet is the value of an
// element-identifier attribute or prop (`id=`, `name=`, `for=`, `htmlFor`), an
// equivalent framework object prop (`{name:"…"}`, `{htmlFor:"…"}`), or the argument
// of a DOM lookup (`getElementById(`, `getElementsByName(`, `querySelector(`) —
// positions that reference an element by id/name and never carry a credential. It
// is the fix for a compiled change-password form whose `<input name="…password2"
// id="password2">` fields, `{name:"password2"}` props, and
// `getElementById("password2val")` calls the weak/generic rules mis-read as leaked
// passwords.
//
// Safety rests on elementIdentifierAttrs, not on the value: a secret is simply never
// the value of id=/name=/for= or the argument of getElementById. The word read back
// from before the `=`/`(`/`:` must equal one of those identifiers exactly, so a
// genuine `data-api-key="…"` or `password:"…"` leak is untouched.
func IsElementIdentifierMatch(body []byte, snippet string, start, end int) bool {
	idx, _, ok := resolveMatchSpan(body, snippet, start, end)
	if !ok {
		return false
	}
	// Step back past an optional opening quote and surrounding whitespace to the
	// attribute assignment '=', object-property ':', or call '('.
	j := skipQuoteSpaceBack(body, idx)
	if j == 0 {
		return false
	}
	if sep := body[j-1]; sep != '=' && sep != '(' && sep != ':' {
		return false
	}
	j--
	for j > 0 && (body[j-1] == ' ' || body[j-1] == '\t') {
		j--
	}
	// Read the identifier word immediately preceding the separator (letters only, so
	// a hyphen/underscore prefix like `data-` or `client_` is not part of it).
	k := j
	for k > 0 && isLetterByte(body[k-1]) {
		k--
	}
	word := body[k:j]
	for _, attr := range elementIdentifierAttrs {
		if bytes.EqualFold(word, attr) {
			return true
		}
	}
	return false
}

// isIdentifierNameReference reports whether the match is used as an identifier NAME
// rather than a credential VALUE. It covers the three ways a `password<digit>`-style
// token appears as a field/state reference in compiled web code:
//
//   - a fragment of a longer identifier — `ctl00$password2`, `password2req`;
//   - a property access — `.password1` (`n.state.password1`, `r=a.password1`);
//   - an object/state key or switch-case label — `{password1:""}`, `case "…2":`
//     (token followed by ':', excluding a `? … :` ternary whose branch is a value).
//
// A weak password used as a VALUE is deliberately NOT matched, so a genuine leak
// still surfaces: an assignment (`password:"password123"`, `da="password123"`), a
// comparison (`x==="password123"`), or a call argument (`login(u,"password2")`) all
// fall through. Gated by rule (the weak-password rule, whose capture is itself an
// identifier-shaped word): a rule that slices a secret out of a longer opaque token
// would misfire on the fragment test.
func isIdentifierNameReference(body []byte, snippet string, start, end int) bool {
	idx, matchEnd, ok := resolveMatchSpan(body, snippet, start, end)
	if !ok {
		return false
	}
	// Fragment of a longer identifier.
	if idx > 0 && isIdentByte(body[idx-1]) {
		return true
	}
	if matchEnd < len(body) && isIdentByte(body[matchEnd]) {
		return true
	}
	// Property access: `.password1`.
	if idx > 0 && body[idx-1] == '.' {
		return true
	}
	// Object/state key or case label: the value (past an optional closing quote and
	// spaces) is immediately followed by ':', and it is not a `? … :` ternary branch.
	a := skipQuoteSpaceFwd(body, matchEnd)
	return a < len(body) && body[a] == ':' && !precededByTernaryQuestion(body, idx)
}

// precededByTernaryQuestion reports whether the value at idx is the true-branch of a
// `cond ? value : other` ternary — i.e. stepping back past an optional opening quote
// and spaces lands on '?'. Such a branch is a real value, so the ':' after it must
// not be read as an object-key separator.
func precededByTernaryQuestion(body []byte, idx int) bool {
	b := skipQuoteSpaceBack(body, idx)
	return b > 0 && body[b-1] == '?'
}

// skipQuoteSpaceBack returns i moved backward past an optional string quote
// immediately before it, then past any spaces/tabs.
func skipQuoteSpaceBack(body []byte, i int) int {
	if i > 0 && isQuoteByte(body[i-1]) {
		i--
	}
	for i > 0 && (body[i-1] == ' ' || body[i-1] == '\t') {
		i--
	}
	return i
}

// skipQuoteSpaceFwd returns i moved forward past an optional string quote at it, then
// past any spaces/tabs — the forward mirror of skipQuoteSpaceBack.
func skipQuoteSpaceFwd(body []byte, i int) int {
	if i < len(body) && isQuoteByte(body[i]) {
		i++
	}
	for i < len(body) && (body[i] == ' ' || body[i] == '\t') {
		i++
	}
	return i
}

func isIdentByte(b byte) bool {
	return isLetterByte(b) || isDigitByte(b) || b == '_' || b == '$'
}

func isLetterByte(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }

func isDigitByte(b byte) bool { return b >= '0' && b <= '9' }

func isQuoteByte(b byte) bool { return b == '"' || b == '\'' || b == '`' }
