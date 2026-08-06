package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeScopeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

// TestReadTargetFileLinesExpandsBurpScope covers the -T/--target-file contract
// for a Burp scope export: the line reader must hand back the URLs the include
// rules describe, not the file's JSON lines.
func TestReadTargetFileLinesExpandsBurpScope(t *testing.T) {
	silent := globalSilent
	globalSilent = true
	t.Cleanup(func() { globalSilent = silent })

	path := writeScopeFile(t, "scope.json", `{"target":{"scope":{"advanced_mode":true,
	  "include":[
	    {"enabled":true,"file":"^/.*","host":"^www\\.example\\.com$","port":"^80$","protocol":"http"},
	    {"enabled":true,"file":"^/.*","host":"^www\\.example\\.com$","port":"^443$","protocol":"https"},
	    {"enabled":true,"file":"^/.*","host":"^.*\\.example\\.org$","port":"^443$","protocol":"https"},
	    {"enabled":true,"file":"^/.*","host":"^api\\.example\\.net$","port":"^443$","protocol":"https"}
	  ],
	  "exclude":[
	    {"enabled":true,"file":"^/.*","host":"^api\\.example\\.net$","port":"^443$","protocol":"https"}
	  ]}}}`)

	got, err := readTargetFileLines(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://www.example.com/"}, got)
}

// TestReadTargetFileLinesPlainListUnchanged keeps the ordinary target-file
// behaviour intact — comments and blanks skipped, everything else verbatim.
func TestReadTargetFileLinesPlainListUnchanged(t *testing.T) {
	path := writeScopeFile(t, "targets.txt", "# comment\nhttps://example.com/\n\n  https://example.org/  \n")

	got, err := readTargetFileLines(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://example.com/", "https://example.org/"}, got)
}

// TestReadTargetFileLinesBurpScopeAllWildcards errors rather than silently
// scanning nothing: a scope of only wildcard rules has no concrete host to
// send a request at, and an empty target list would look like a clean run.
func TestReadTargetFileLinesBurpScopeAllWildcards(t *testing.T) {
	silent := globalSilent
	globalSilent = true
	t.Cleanup(func() { globalSilent = silent })

	path := writeScopeFile(t, "scope.json", `{"target":{"scope":{"advanced_mode":true,"include":[
	  {"enabled":true,"file":"^/.*","host":"^.*\\.example\\.com$","port":"^443$","protocol":"https"}
	]}}}`)

	_, err := readTargetFileLines(path)
	assert.ErrorContains(t, err, "no scannable targets")
}

// TestReadTargetFilesLinesMixesScopeAndList verifies repeated -T merges an
// expanded scope file with a plain list.
func TestReadTargetFilesLinesMixesScopeAndList(t *testing.T) {
	silent := globalSilent
	globalSilent = true
	t.Cleanup(func() { globalSilent = silent })

	dir := t.TempDir()
	scope := filepath.Join(dir, "scope.json")
	require.NoError(t, os.WriteFile(scope, []byte(`{"target":{"scope":{"include":[
	  {"enabled":true,"file":"^/.*","host":"^www\\.example\\.com$","port":"^443$","protocol":"https"}
	]}}}`), 0o644))

	list := filepath.Join(dir, "targets.txt")
	require.NoError(t, os.WriteFile(list, []byte("https://example.org/\n"), 0o644))

	got, err := readTargetFilesLines([]string{scope, list})
	require.NoError(t, err)
	assert.Equal(t, []string{"https://www.example.com/", "https://example.org/"}, got)
}

// TestCountTargetFileTargets covers the scan banner's headline count: a run
// driven entirely by -T used to report "Targets: 0", which reads as though
// nothing was found.
func TestCountTargetFileTargets(t *testing.T) {
	silent := globalSilent
	globalSilent = true
	t.Cleanup(func() { globalSilent = silent })

	dir := t.TempDir()
	list := filepath.Join(dir, "targets.txt")
	require.NoError(t, os.WriteFile(list, []byte("https://example.com/\n# comment\nhttps://example.org/\n"), 0o644))

	scope := filepath.Join(dir, "scope.json")
	require.NoError(t, os.WriteFile(scope, []byte(`{"target":{"scope":{"include":[
	  {"enabled":true,"file":"^/.*","host":"^www\\.example\\.com$","port":"^80$","protocol":"http"},
	  {"enabled":true,"file":"^/.*","host":"^www\\.example\\.com$","port":"^443$","protocol":"https"},
	  {"enabled":true,"file":"^/.*","host":"^api\\.example\\.com$","port":"^443$","protocol":"https"}
	]}}}`), 0o644))

	// Cold: no cache entry yet, so the count comes from reading the files. The
	// scope file counts its expanded targets, not its JSON lines.
	assert.Equal(t, 4, countTargetFileTargets([]string{list, scope}))

	// Warm: readTargetFileLines populates the cache, and the count must agree
	// with what the scan actually seeds.
	lines, err := readTargetFilesLines([]string{list, scope})
	require.NoError(t, err)
	assert.Len(t, lines, 4)
	assert.Equal(t, 4, countTargetFileTargets([]string{list, scope}))
}

// TestCountTargetFileTargetsUnreadable keeps the banner from failing a scan: an
// unreadable file contributes 0 rather than erroring.
func TestCountTargetFileTargetsUnreadable(t *testing.T) {
	assert.Zero(t, countTargetFileTargets([]string{filepath.Join(t.TempDir(), "missing.txt")}))
}
