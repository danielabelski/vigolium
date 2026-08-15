package state

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
)

// SwitchToStateAndCheckIfClone exists so the crawler can repair a crawl path after
// a duplicate transition without re-scanning every edge in the graph. These tests
// pin that the edge it hands back is the one AllEdges() would have been searched
// for.

func TestSwitchToStateAndCheckIfCloneReturnsExistingEdgeOnDuplicate(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()

	g := NewGraph()
	start := New("http://test.local/a", "", "DOM-A", 0)
	g.AddState(start)
	sm := NewStateMachine(g, start)

	// First transition: a new state, so a new edge is added and returned.
	target := New("http://test.local/b", "", "DOM-B", 1)
	firstEvent := createTestEventable("/body/link")
	existing, isClone, firstEdge := sm.SwitchToStateAndCheckIfClone(target, firstEvent)
	if isClone || existing != nil {
		t.Fatalf("first transition should be new, got (existing=%v, isClone=%v)", existing, isClone)
	}
	if firstEdge != firstEvent {
		t.Fatal("a new transition should return the eventable it was given")
	}

	// Go back so the duplicate transition starts from the same source state.
	sm.SetCurrentState(start)

	// Second, equivalent transition from the same source to the same target:
	// AddEdge must resolve to the edge already in the graph.
	dupTarget := New("http://test.local/b-again", "", "DOM-B", 5) // same DOM => same ID
	dupEvent := createTestEventable("/body/link")
	_, isClone, dupEdge := sm.SwitchToStateAndCheckIfClone(dupTarget, dupEvent)
	if !isClone {
		t.Fatal("second transition to an existing state should be a clone")
	}
	if dupEvent.ID != -1 {
		t.Errorf("duplicate eventable should be marked ID = -1, got %d", dupEvent.ID)
	}
	if dupEdge == nil {
		t.Fatal("duplicate transition returned no edge")
	}
	if dupEdge == dupEvent {
		t.Error("duplicate transition returned the throwaway eventable, not the graph edge")
	}
	if dupEdge != firstEdge {
		t.Errorf("duplicate transition returned edge %v, want the pre-existing edge %v", dupEdge, firstEdge)
	}

	// The resolved edge must be the one a full graph scan would have found —
	// the search this replaced.
	var found *action.Eventable
	for _, edge := range g.AllEdges() {
		if edge.Equals(dupEvent) {
			found = edge
			break
		}
	}
	if found != dupEdge {
		t.Errorf("resolved edge %v differs from the AllEdges() search result %v", dupEdge, found)
	}
}

func TestSwitchToStateAndCheckIfCloneNilCases(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()

	g := NewGraph()
	start := New("http://test.local/a", "", "DOM-A", 0)
	g.AddState(start)
	sm := NewStateMachine(g, start)

	// Nil state: nothing resolved.
	if existing, isClone, edge := sm.SwitchToStateAndCheckIfClone(nil, nil); existing != nil || isClone || edge != nil {
		t.Errorf("nil newState should return (nil,false,nil), got (%v,%v,%v)", existing, isClone, edge)
	}

	// Nil eventable: a state transition with no edge to resolve.
	target := New("http://test.local/b", "", "DOM-B", 1)
	if _, _, edge := sm.SwitchToStateAndCheckIfClone(target, nil); edge != nil {
		t.Errorf("nil eventable should resolve no edge, got %v", edge)
	}
}

// The state/clone half of the contract is covered by
// TestStateMachineSwitchToStateAndCheckIfClone in state_machine_unit_test.go;
// these tests cover only the resolved-edge return value it added.
