package filesig

import "testing"

// cfBlockBody is the body of the Cloudflare "Blocked Content Notification" 403
// that produced the original false positive: its embedded cf-beacon JSON carries
// "server_timing" and "location_startswith", which satisfied the former bare
// "server"/"location" nginx.conf markers. The structural confirmer must reject
// it — these are JSON keys, not anchored nginx directives.
const cfBlockBody = `<!DOCTYPE html><html><head><title>Blocked</title></head><body>
<h1>Blocked Content Notification</h1>
<p>The website you are trying to visit has been blocked.</p>
<script defer src="https://static.cloudflareinsights.com/beacon.min.js"
 data-cf-beacon='{"version":"2024.11.0","token":"bb500abe","server_timing":{"name":{"cfEdge":true,"cfOrigin":true}},"location_startswith":null}'></script>
</body></html>`

func TestConfirmNginxConf(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		baseline string
		wantOK   bool
	}{
		{
			name:     "cloudflare block page cf-beacon json is rejected",
			data:     cfBlockBody,
			baseline: "<html><body>ok</body></html>",
			wantOK:   false, // "server_timing"/"location_startswith" are JSON keys, not directives
		},
		{
			name:     "real nginx.conf is confirmed",
			data:     "user www-data;\nworker_processes auto;\nhttp {\n  server {\n    listen 80;\n    server_name example.com;\n    location / {\n      proxy_pass http://app;\n    }\n  }\n}\n",
			baseline: "<html><body>welcome</body></html>",
			wantOK:   true,
		},
		{
			name:     "prose mentioning server and location is rejected",
			data:     "<p>Our server hosts content; your location is detected automatically.</p>",
			baseline: "<html></html>",
			wantOK:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, _ := ConfirmNginxConf(tt.data, tt.baseline)
			if ok != tt.wantOK {
				t.Errorf("ConfirmNginxConf() ok = %v, want %v", ok, tt.wantOK)
			}
		})
	}
}

func TestConfirmWinIni(t *testing.T) {
	// CSP `font-src` and an "extensions" word must not confirm win.ini.
	noise := `<meta http-equiv="Content-Security-Policy" content="font-src 'self'; default-src 'self'"><p>browser extensions and fonts</p>`
	if ok, _ := ConfirmWinIni(noise, ""); ok {
		t.Errorf("ConfirmWinIni() confirmed on bare fonts/extensions words")
	}
	real := "[fonts]\nArial=arial.ttf\n[extensions]\ntxt=notepad.exe\n"
	if ok, _ := ConfirmWinIni(real, "<html></html>"); !ok {
		t.Errorf("ConfirmWinIni() failed to confirm a real win.ini with bracketed sections")
	}
}

func TestConfirmPasswd(t *testing.T) {
	// Reflected prose: a passwd line embedded in an English sentence. The shell
	// field is not terminated (" is the superuser…"), so it must NOT confirm.
	reflected := `{"note":"root:x:0:0:root:/root:/bin/bash is the superuser entry"}`
	if ok, _ := ConfirmPasswd(reflected, ""); ok {
		t.Errorf("ConfirmPasswd() confirmed on a reflected root token in prose")
	}
	// A bare `/bin/sh: not found` style error must not confirm.
	if ok, _ := ConfirmPasswd("sh: 1: /bin/sh: command failed; :0:0:", ""); ok {
		t.Errorf("ConfirmPasswd() confirmed on scattered /bin/ and :0:0: tokens")
	}
	// A single root entry (direct file read, EOF-terminated) confirms.
	single := "root:x:0:0:root:/root:/bin/bash"
	if ok, _ := ConfirmPasswd(single, "<html></html>"); !ok {
		t.Errorf("ConfirmPasswd() failed to confirm a single root entry")
	}
	// A direct multi-line /etc/passwd dump confirms.
	real := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
	if ok, n := ConfirmPasswd(real, "<html></html>"); !ok || n < 2 {
		t.Errorf("ConfirmPasswd() failed to confirm a real /etc/passwd dump (ok=%v n=%d)", ok, n)
	}
	// MCP-style: the file leaked inside a JSON-RPC envelope as a "text" value,
	// mid-line, with the entries joined by an escaped \n. Must confirm.
	mcpEnvelope := `{"jsonrpc":"2.0","id":1,"result":{"contents":[{"uri":"file:///etc/passwd",` +
		`"text":"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"}]}}`
	if ok, _ := ConfirmPasswd(mcpEnvelope, ""); !ok {
		t.Errorf("ConfirmPasswd() failed to confirm passwd leaked inside an MCP JSON-RPC envelope")
	}
	// The path reflected as a JSON value (no file content) must NOT confirm.
	echoed := `{"jsonrpc":"2.0","id":1,"result":{"contents":[{"uri":"file:///etc/passwd","text":"../../../../../../etc/passwd"}]}}`
	if ok, _ := ConfirmPasswd(echoed, ""); ok {
		t.Errorf("ConfirmPasswd() confirmed on a reflected traversal path with no file content")
	}
	// Already present in the baseline ⇒ subtracted ⇒ not confirmed.
	if ok, _ := ConfirmPasswd(real, real+"<padding>"); ok {
		t.Errorf("ConfirmPasswd() confirmed content already present in the baseline")
	}
}
