package procutil

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ShellArgv returns the argv prefix for running a command *string* through a
// shell on this host. Off Windows the caller's own choice is returned verbatim,
// so existing behaviour is unchanged (the agent's bash tool wants a login bash;
// the JS extension's exec() wants a plain POSIX sh, which exists on minimal
// containers where bash does not).
//
// Windows has neither. The fallback order is deliberate:
//
//  1. A real POSIX bash when one is installed (Git Bash, MSYS2). Every prompt,
//     skill, doc example and JS extension in this project is written in POSIX
//     shell, so a POSIX shell is the only one that runs them as written.
//  2. PowerShell otherwise. It is always present, but the command string is
//     interpreted with different quoting and operators — see ShellLabel, which
//     callers surface to the model so it knows which dialect it is writing.
//
// A bash.exe that resolves inside System32 is rejected rather than used: that
// is the WSL launcher, not a Windows bash. Running through it would execute in
// a different filesystem with a different PATH, where the host's vigolium.exe
// is not the binary the command would find — a silently wrong result is worse
// than falling through to PowerShell.
func ShellArgv(unixShell, unixFlag string) (name string, args []string) {
	if runtime.GOOS != "windows" {
		return unixShell, []string{unixFlag}
	}
	if p, err := exec.LookPath("bash"); err == nil && !isWSLLauncher(p) {
		return p, []string{unixFlag}
	}
	return "powershell", []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"}
}

// isWSLLauncher reports whether a resolved bash path is Windows' own WSL entry
// point (%SystemRoot%\System32\bash.exe) rather than an installed POSIX bash.
func isWSLLauncher(path string) bool {
	// Normalize separators explicitly rather than with filepath.ToSlash, which
	// only rewrites backslashes when the *host's* separator is a backslash —
	// i.e. it is a no-op off Windows, which would make this silently unable to
	// recognize a Windows path (and untestable anywhere else).
	lower := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	return strings.Contains(lower, "/windows/system32/")
}

// ShellLabel names the shell ShellArgv would pick, for tool descriptions and
// error messages ("bash -lc", "powershell -Command"). Not memoized: callers ask
// for different shells, so a single cached value would hand one caller's label
// to another. Off Windows this is pure string work, and on Windows it is one
// PATH lookup per call.
func ShellLabel(unixShell, unixFlag string) string {
	name, args := ShellArgv(unixShell, unixFlag)
	return filepath.Base(name) + " " + strings.Join(args, " ")
}
