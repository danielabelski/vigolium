package source

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/pkg/input/formats/wsdl"
)

// TestFirstFileSourceUnwrapsMultiSource guards the fix for the dropped
// spec-format override: when -t (a TargetSource) is combined with -i (a
// FileSource) the input is a MultiSource, and a bare *FileSource assertion would
// miss the parser. FirstFileSource must reach through the MultiSource so the
// OpenAPI BaseURL / WSDL endpoint override still lands.
func TestFirstFileSourceUnwrapsMultiSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "svc.wsdl")
	if err := os.WriteFile(path, []byte("<definitions/>"), 0o600); err != nil {
		t.Fatalf("write temp wsdl: %v", err)
	}

	fs, err := NewFileSource(FileSourceConfig{FilePath: path, Format: "wsdl"})
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}

	// Direct FileSource.
	if got := FirstFileSource(fs); got != fs {
		t.Errorf("FirstFileSource(fs) = %v, want the FileSource itself", got)
	}

	// MultiSource[TargetSource, FileSource] — the -t + -i shape.
	multi := NewMultiSource(NewTargetSource([]string{"http://example.com"}, nil), fs)
	got := FirstFileSource(multi)
	if got != fs {
		t.Fatalf("FirstFileSource(multi) did not unwrap to the FileSource")
	}
	if _, ok := got.Format().(*wsdl.Format); !ok {
		t.Errorf("unwrapped FileSource has wrong parser type %T, want *wsdl.Format", got.Format())
	}

	// Nothing to find → nil (not a panic).
	if got := FirstFileSource(NewTargetSource([]string{"http://example.com"}, nil)); got != nil {
		t.Errorf("FirstFileSource(target-only) = %v, want nil", got)
	}
}
