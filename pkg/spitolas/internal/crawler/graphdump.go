package crawler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"go.uber.org/zap"
)

// GraphDump is the serialized form of a finished crawl: the locations the
// crawler reached and, for each transition between them, the action that was
// taken and how to find that element again.
//
// The captured traffic already says what was requested. What it cannot say is
// how the crawler got there — which click on which page, with which form values,
// produced a given request. That is the difference between a list of URLs and a
// reproducible route, and it is what makes a state re-reachable later without
// rediscovering the whole path to it.
type GraphDump struct {
	Version   int              `json:"version"`
	Target    string           `json:"target"`
	CreatedAt time.Time        `json:"created_at"`
	Stats     GraphDumpStats   `json:"stats"`
	States    []GraphDumpState `json:"states"`
	Edges     []GraphDumpEdge  `json:"edges"`
}

// GraphDumpStats summarises the run the graph came from.
type GraphDumpStats struct {
	States          int `json:"states"`
	Edges           int `json:"edges"`
	ActionsExecuted int `json:"actions_executed"`
	ActionsFailed   int `json:"actions_failed"`
	FormsSubmitted  int `json:"forms_submitted"`
}

// GraphDumpState is one reached location. The DOM itself is deliberately not
// included: it is large, it is already represented by the captured responses,
// and the identity hash is what a later run needs in order to recognise the
// same location again.
type GraphDumpState struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	URL             string    `json:"url"`
	Depth           int       `json:"depth"`
	CreatedAt       time.Time `json:"created_at"`
	OnURL           bool      `json:"on_url"`
	IsNearDuplicate bool      `json:"is_near_duplicate,omitempty"`
	NearestStateID  string    `json:"nearest_state_id,omitempty"`
}

// GraphDumpEdge is one transition, recorded so it can be replayed.
type GraphDumpEdge struct {
	ID         int64             `json:"id"`
	From       string            `json:"from"`
	To         string            `json:"to"`
	EventType  string            `json:"event_type"`
	Selector   GraphDumpSelector `json:"selector"`
	Frame      string            `json:"frame,omitempty"`
	Tag        string            `json:"tag,omitempty"`
	Text       string            `json:"text,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	FormInputs []GraphDumpInput  `json:"form_inputs,omitempty"`
}

// GraphDumpSelector is how the element was addressed — the method (xpath, css,
// id, …) and the expression.
type GraphDumpSelector struct {
	How   string `json:"how"`
	Value string `json:"value"`
}

// GraphDumpInput is a form field the transition carried, with the value that was
// submitted. Recording the value matters as much as the field: a transition that
// only happens for a particular input is not reproducible without it.
type GraphDumpInput struct {
	Type   string   `json:"type"`
	How    string   `json:"how"`
	Value  string   `json:"value"`
	Inputs []string `json:"inputs,omitempty"`
}

// graphDumpVersion is bumped when the shape changes incompatibly.
const graphDumpVersion = 1

// writeGraphDump serializes the finished graph to config.GraphOutputPath.
//
// Best-effort: a crawl that produced traffic is a successful crawl whether or
// not the map of it could be written, so every failure here is logged and
// swallowed rather than surfaced.
func (c *Crawler) writeGraphDump() {
	if c.config == nil || c.config.GraphOutputPath == "" || c.graph == nil {
		return
	}

	dump := c.buildGraphDump()
	data, err := json.MarshalIndent(dump, "", "  ")
	if err != nil {
		zap.L().Debug("Crawl-graph serialization failed", zap.Error(err))
		return
	}

	path := c.config.GraphOutputPath
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
			zap.L().Debug("Crawl-graph directory creation failed",
				zap.String("dir", dir), zap.Error(mkErr))
			return
		}
	}
	if wErr := os.WriteFile(path, data, 0o644); wErr != nil {
		zap.L().Debug("Crawl-graph write failed", zap.String("path", path), zap.Error(wErr))
		return
	}
	zap.L().Info("Spidering: wrote crawl graph",
		zap.String("path", path),
		zap.Int("states", dump.Stats.States),
		zap.Int("edges", dump.Stats.Edges))
}

// buildGraphDump converts the live graph into its serializable form. States and
// edges are emitted in a stable order (name, then edge id) so two runs over an
// unchanged application produce diffable output.
func (c *Crawler) buildGraphDump() GraphDump {
	target := ""
	if c.config.URL != nil {
		target = c.config.URL.String()
	}

	states := c.graph.AllStates()
	edges := c.graph.AllEdges()

	dumpStates := make([]GraphDumpState, 0, len(states))
	for _, s := range states {
		if s == nil {
			continue
		}
		dumpStates = append(dumpStates, GraphDumpState{
			ID:              s.ID,
			Name:            s.Name,
			URL:             s.URL,
			Depth:           s.Depth,
			CreatedAt:       s.CreatedAt,
			OnURL:           s.OnURL,
			IsNearDuplicate: s.IsNearDuplicate,
			NearestStateID:  s.NearestStateID,
		})
	}
	sort.Slice(dumpStates, func(i, j int) bool { return dumpStates[i].Name < dumpStates[j].Name })

	dumpEdges := make([]GraphDumpEdge, 0, len(edges))
	for _, e := range edges {
		if e == nil {
			continue
		}
		dumpEdges = append(dumpEdges, graphDumpEdgeFrom(e))
	}
	sort.Slice(dumpEdges, func(i, j int) bool { return dumpEdges[i].ID < dumpEdges[j].ID })

	c.mu.Lock()
	stats := GraphDumpStats{
		States:          len(dumpStates),
		Edges:           len(dumpEdges),
		ActionsExecuted: c.stats.ActionsExecuted,
		ActionsFailed:   c.stats.ActionsFailed,
		FormsSubmitted:  c.stats.FormsSubmitted,
	}
	c.mu.Unlock()

	return GraphDump{
		Version:   graphDumpVersion,
		Target:    target,
		CreatedAt: time.Now().UTC(),
		Stats:     stats,
		States:    dumpStates,
		Edges:     dumpEdges,
	}
}

// graphDumpEdgeFrom converts one live edge into its serializable form.
func graphDumpEdgeFrom(e *action.Eventable) GraphDumpEdge {
	out := GraphDumpEdge{
		ID:        e.ID,
		From:      e.SourceStateID,
		To:        e.TargetStateID,
		EventType: string(e.EventType),
		Frame:     e.RelatedFrame,
	}
	if e.Identification != nil {
		out.Selector = GraphDumpSelector{
			How:   string(e.Identification.How),
			Value: e.Identification.Value,
		}
	}
	if e.Element != nil {
		out.Tag = e.Element.Tag
		out.Text = e.Element.Text
		if len(e.Element.Attributes) > 0 {
			out.Attributes = e.Element.Attributes
		}
	}
	for _, fi := range e.RelatedFormInputs {
		if fi == nil {
			continue
		}
		in := GraphDumpInput{Type: string(fi.Type)}
		if fi.Identification != nil {
			in.How = string(fi.Identification.How)
			in.Value = fi.Identification.Value
		}
		for _, v := range fi.InputValues {
			in.Inputs = append(in.Inputs, v.Value)
		}
		out.FormInputs = append(out.FormInputs, in)
	}
	return out
}

// defaultGraphFileName is used when the crawl's host is unknown.
const defaultGraphFileName = "crawl-graph.json"

// GraphOutputPathFor joins a directory and a per-target file name, giving each
// target in a multi-target run its own graph rather than one overwriting the
// next. host may be empty, in which case the default name is used.
func GraphOutputPathFor(dir, host string) string {
	if dir == "" {
		return ""
	}
	if host == "" {
		return filepath.Join(dir, defaultGraphFileName)
	}
	return filepath.Join(dir, fmt.Sprintf("crawl-graph-%s.json", host))
}
