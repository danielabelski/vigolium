package procutil

import (
	"path/filepath"
	"runtime"
	"testing"
)

// TestShellArgvPassesThroughOffWindows locks in that non-Windows hosts get the
// caller's own shell verbatim. The JS extension's exec() depends on this: it
// asks for /bin/sh because minimal containers ship sh but not bash, and
// silently upgrading it to bash would break those images.
func TestShellArgvPassesThroughOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pass-through behaviour is for non-Windows hosts")
	}
	for _, tc := range []struct{ shell, flag string }{
		{"/bin/sh", "-c"},
		{"bash", "-lc"},
	} {
		name, args := ShellArgv(tc.shell, tc.flag)
		if name != tc.shell {
			t.Errorf("ShellArgv(%q, %q) shell = %q, want %q", tc.shell, tc.flag, name, tc.shell)
		}
		if len(args) != 1 || args[0] != tc.flag {
			t.Errorf("ShellArgv(%q, %q) args = %v, want [%q]", tc.shell, tc.flag, args, tc.flag)
		}
	}
}

// TestIsWSLLauncher covers the distinction the Windows fallback rests on: a
// bash.exe under System32 is Windows' WSL entry point, which would run the
// command inside a different filesystem with a different PATH — so the host's
// vigolium.exe would not be the binary it finds. An installed POSIX bash
// (Git Bash, MSYS2) must not be rejected.
func TestIsWSLLauncher(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{`C:\Windows\System32\bash.exe`, true},
		{`c:\windows\system32\bash.exe`, true},
		{`C:/Windows/System32/bash.exe`, true},
		{`C:\Program Files\Git\bin\bash.exe`, false},
		{`C:\msys64\usr\bin\bash.exe`, false},
		// A path merely containing the word "system32" deeper in a real install
		// tree is not the launcher — only the Windows directory layout is.
		{`C:\tools\system32bash\bash.exe`, false},
		{`/usr/bin/bash`, false},
	}
	for _, tc := range cases {
		if got := isWSLLauncher(tc.path); got != tc.want {
			t.Errorf("isWSLLauncher(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestShellLabelIsNotSharedAcrossCallers guards against reintroducing a single
// memoized label: the bash tool and the JS extension ask for different shells,
// and one cached value would report the wrong dialect to the model.
func TestShellLabelIsNotSharedAcrossCallers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("both callers resolve to the same substituted shell on Windows")
	}
	sh := ShellLabel("/bin/sh", "-c")
	bash := ShellLabel("bash", "-lc")
	if sh == bash {
		t.Fatalf("both callers got the same label %q — the label is being shared", sh)
	}
	if want := filepath.Base("/bin/sh") + " -c"; sh != want {
		t.Errorf("ShellLabel(/bin/sh, -c) = %q, want %q", sh, want)
	}
	if bash != "bash -lc" {
		t.Errorf("ShellLabel(bash, -lc) = %q, want %q", bash, "bash -lc")
	}
}
