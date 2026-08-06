package crawler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

func TestGraphOutputPathFor(t *testing.T) {
	if got := GraphOutputPathFor("", "app.test"); got != "" {
		t.Errorf("no directory should disable the dump, got %q", got)
	}
	if got := GraphOutputPathFor("/out", ""); got != filepath.Join("/out", defaultGraphFileName) {
		t.Errorf("unknown host should fall back to the default name, got %q", got)
	}
	// Two hosts in one run must not write to the same file.
	a := GraphOutputPathFor("/out", "a.test")
	b := GraphOutputPathFor("/out", "b.test")
	if a == b {
		t.Errorf("per-host paths collided: %q", a)
	}
}

func TestGraphDumpEdgeFromCarriesSelectorAndInputs(t *testing.T) {
	e := &action.Eventable{
		ID:            7,
		EventType:     action.EventTypeClick,
		SourceStateID: "src",
		TargetStateID: "dst",
		RelatedFrame:  "frame[0]",
		Identification: &action.Identification{
			How:   action.HowXPath,
			Value: "//button[@id='go']",
		},
		Element: &action.Element{
			Tag:        "button",
			Text:       "Go",
			Attributes: map[string]string{"id": "go"},
		},
		RelatedFormInputs: []*action.FormInput{
			{
				Type:           action.InputTypeText,
				Identification: &action.Identification{How: action.HowName, Value: "q"},
				InputValues:    []action.InputValue{{Value: "widgets"}},
			},
		},
	}

	got := graphDumpEdgeFrom(e)

	if got.ID != 7 || got.From != "src" || got.To != "dst" {
		t.Errorf("edge identity not carried: %+v", got)
	}
	// The selector is what makes the transition replayable — without it the dump
	// is a list of state ids rather than a route.
	if got.Selector.Value != "//button[@id='go']" || got.Selector.How != string(action.HowXPath) {
		t.Errorf("selector not carried: %+v", got.Selector)
	}
	if got.Frame != "frame[0]" || got.Tag != "button" || got.Text != "Go" {
		t.Errorf("element context not carried: %+v", got)
	}
	if len(got.FormInputs) != 1 {
		t.Fatalf("form inputs not carried: %+v", got.FormInputs)
	}
	// The submitted value matters as much as the field name: a transition that
	// only happens for a particular input cannot be reproduced without it.
	if got.FormInputs[0].Value != "q" || len(got.FormInputs[0].Inputs) != 1 || got.FormInputs[0].Inputs[0] != "widgets" {
		t.Errorf("form input value not carried: %+v", got.FormInputs[0])
	}
}

func TestGraphDumpEdgeFromToleratesSparseEventable(t *testing.T) {
	// Reload edges carry no element or identification; serializing must not panic.
	got := graphDumpEdgeFrom(&action.Eventable{ID: 1, EventType: action.EventTypeClick})
	if got.ID != 1 || got.Selector.Value != "" || got.FormInputs != nil {
		t.Errorf("sparse eventable mishandled: %+v", got)
	}
}

func TestWriteGraphDumpProducesReadableJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "graph.json")

	cfg, err := config.New("https://app.test")
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	cfg.GraphOutputPath = path

	g := state.NewGraph()
	index := state.New("https://app.test/", "<html></html>", "html", 0)
	next := state.New("https://app.test/admin", "<html>admin</html>", "html-admin", 1)
	g.AddState(index)
	g.AddState(next)
	g.AddEdge(index.ID, next.ID, action.NewEventable(
		action.NewIdentification(action.HowXPath, "//a[@id='admin']"), action.EventTypeClick))

	c := &Crawler{config: cfg, graph: g}
	c.writeGraphDump()

	data, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("graph file not written (the directory should be created): %v", rerr)
	}

	var dump GraphDump
	if jerr := json.Unmarshal(data, &dump); jerr != nil {
		t.Fatalf("graph file is not valid JSON: %v", jerr)
	}
	if dump.Version != graphDumpVersion || dump.Target != "https://app.test" {
		t.Errorf("dump header wrong: version=%d target=%q", dump.Version, dump.Target)
	}
	if dump.Stats.States != 2 || len(dump.States) != 2 {
		t.Errorf("expected 2 states, got %d (%d in stats)", len(dump.States), dump.Stats.States)
	}
	if dump.Stats.Edges != 1 || len(dump.Edges) != 1 {
		t.Errorf("expected 1 edge, got %d (%d in stats)", len(dump.Edges), dump.Stats.Edges)
	}
	if dump.Edges[0].Selector.Value != "//a[@id='admin']" {
		t.Errorf("edge selector lost through serialization: %+v", dump.Edges[0])
	}
	// The DOM is deliberately excluded — it is large and already represented by
	// the captured responses.
	if len(data) > 64*1024 {
		t.Errorf("dump is unexpectedly large (%d bytes); is the DOM leaking in?", len(data))
	}
}

func TestWriteGraphDumpNoOpWithoutPath(t *testing.T) {
	cfg, err := config.New("https://app.test")
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	c := &Crawler{config: cfg, graph: state.NewGraph()}
	c.writeGraphDump() // must not panic when no output was requested
}
