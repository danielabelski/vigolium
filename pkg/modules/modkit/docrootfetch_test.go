package modkit

import "testing"

// TestDocrootPublishableTarget pins the allowlist's two jobs: recognise the
// publishable targets through any traversal prefix, and fall through for
// everything else — above all the stream wrappers, whose downgrade would turn a
// code-execution-grade finding into an informational one.
func TestDocrootPublishableTarget(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		payload string
		want    bool
	}{
		// Publishable, at every traversal depth the LFI modules send.
		{".env", true},
		{"../.env", true},
		{"../../../../.env", true},
		{".htaccess", true},
		{"../.htaccess", true},
		{".htpasswd", true},
		{"../../../../.htpasswd", true},
		{"./web.config", true},
		{"../../web.config", true},
		{"./WEB-INF/web.xml", true},
		{"../../WEB-INF/web.xml", true},
		{"../../../../.git/HEAD", true},

		// OS-filesystem targets: no web root serves these, so reaching one is a
		// genuine escape and must keep the module's own severity.
		{"../../etc/passwd", false},
		{"/etc/passwd%00.jpg", false},
		{"../../../../windows/win.ini", false},
		{`..\..\..\..\windows\win.ini`, false},
		{"c:/windows/win.ini%00.jpg", false},
		{"../../../../proc/self/environ", false},
		{"../../../../var/log/nginx/access.log", false},
		{"./.././.././../etc/passwd", false},
		{".../.../.../etc/passwd", false},
		{"%252e%252e%252fetc%252fpasswd", false},

		// Stream wrappers need a real inclusion sink; downgrading them would be
		// far worse than the false positive the allowlist exists to fix.
		{"php://filter/convert.base64-encode/resource=index.php", false},
		{"php://filter/convert.base64-encode/resource=../index.php", false},
		{"php://input", false},
		{"expect://id", false},
		{"data://text/plain;base64,PD9waHAgZWNobyAidmlnb2xpdW0tdGVzdCI7ID8+", false},

		{"", false},
	} {
		if got := DocrootPublishableTarget(tc.payload); got != tc.want {
			t.Errorf("DocrootPublishableTarget(%q) = %v, want %v", tc.payload, got, tc.want)
		}
	}
}
