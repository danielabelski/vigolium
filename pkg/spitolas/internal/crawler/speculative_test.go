package crawler

import "testing"

func newPrimingCrawler() *Crawler {
	return &Crawler{
		primedLinks:      make(map[string]bool),
		primedLinkShapes: make(map[string]int),
	}
}

// The two priming sources share a dedup set but not a budget. If they shared the
// budget, whichever ran first would silently consume the other's allowance.
func TestSelectUnprimedLinksBudgetedDoesNotShareBudget(t *testing.T) {
	c := newPrimingCrawler()

	anchors := []string{
		"https://app.test/a?x=1", "https://app.test/b?x=1", "https://app.test/c?x=1",
	}
	if got := c.selectUnprimedLinks(anchors, 3, 6); len(got) != 3 {
		t.Fatalf("anchor primer took %d of 3: %v", len(got), got)
	}

	// The shared set now holds 3 URLs. A size-based cap of 2 would return nothing;
	// the budgeted selector must still grant this source its own 2.
	speculative := []string{"https://app.test/d?x=1", "https://app.test/e?x=1"}
	got := c.selectUnprimedLinksBudgeted(speculative, 2, 6)
	if len(got) != 2 {
		t.Errorf("speculative source was starved by the anchor primer: got %d, want 2 (%v)", len(got), got)
	}
}

// Sharing the dedup set is the desirable half: a URL reachable both as a link and
// as a scraped string must be fetched once.
func TestSelectUnprimedLinksBudgetedSharesDedupSet(t *testing.T) {
	c := newPrimingCrawler()
	shared := "https://app.test/dashboard?tab=1"

	if got := c.selectUnprimedLinks([]string{shared}, 10, 6); len(got) != 1 {
		t.Fatalf("first primer should take the URL, got %v", got)
	}
	if got := c.selectUnprimedLinksBudgeted([]string{shared}, 10, 6); len(got) != 0 {
		t.Errorf("already-primed URL was fetched twice: %v", got)
	}
}

func TestSelectUnprimedLinksBudgetedHonoursPerShapeCap(t *testing.T) {
	c := newPrimingCrawler()
	// An id sweep: one endpoint shape, many values. The per-shape cap is what stops
	// it spending the whole allowance on a single endpoint.
	ids := []string{
		"https://app.test/item?id=1", "https://app.test/item?id=2",
		"https://app.test/item?id=3", "https://app.test/item?id=4",
		"https://app.test/item?id=5",
	}
	got := c.selectUnprimedLinksBudgeted(ids, 100, 2)
	if len(got) != 2 {
		t.Errorf("per-shape cap not applied: got %d, want 2 (%v)", len(got), got)
	}
}

func TestSelectUnprimedLinksBudgetedBounds(t *testing.T) {
	c := newPrimingCrawler()
	if got := c.selectUnprimedLinksBudgeted(nil, 10, 6); len(got) != 0 {
		t.Errorf("no input should select nothing, got %v", got)
	}
	// A non-positive budget disables the cap, matching selectUnprimedLinks.
	c2 := newPrimingCrawler()
	in := []string{"https://app.test/a", "https://app.test/b"}
	if got := c2.selectUnprimedLinksBudgeted(in, 0, 6); len(got) != 2 {
		t.Errorf("non-positive budget should not cap, got %v", got)
	}
}
