package crawler

import "testing"

func TestSelectUnsubmittedPostFormsDedupBySignature(t *testing.T) {
	c := &Crawler{}
	// A stock-check form that recurs on every product page: same action + same field
	// names → one signature → submitted once even though it appears many times.
	descs := []postFormDescriptor{
		{Index: 0, Sig: "https://x.test/catalog/product/stock post productId,storeId"},
		{Index: 1, Sig: "https://x.test/catalog/product/stock post productId,storeId"},
		{Index: 2, Sig: "https://x.test/catalog/subscribe post email"},
	}
	got := c.selectUnsubmittedPostForms(descs, 0)
	if len(got) != 2 {
		t.Fatalf("expected 2 distinct signatures, got %d (%v)", len(got), got)
	}
	// The duplicate stock form (index 1) must be dropped; index 0 kept.
	if got[0] != 0 || got[1] != 2 {
		t.Errorf("expected indices [0 2], got %v", got)
	}
	// Re-submitting the same forms across a later page adds nothing (crawl-wide dedup).
	if again := c.selectUnsubmittedPostForms(descs, 0); len(again) != 0 {
		t.Errorf("expected 0 on re-submit, got %d (%v)", len(again), again)
	}
}

func TestSelectUnsubmittedPostFormsSharesCapWithGetForms(t *testing.T) {
	c := &Crawler{}
	// The GET-form budget and the POST-form budget share config.SubmitFormMaxVariants:
	// selectUnsubmittedForms fills two GET slots, leaving one before the cap of 3.
	if got := c.selectUnsubmittedForms([]string{"https://x.test/a?q=1", "https://x.test/b?q=1"}, 3); len(got) != 2 {
		t.Fatalf("expected 2 GET forms selected, got %d", len(got))
	}
	descs := []postFormDescriptor{
		{Index: 0, Sig: "https://x.test/one post a"},
		{Index: 1, Sig: "https://x.test/two post b"},
	}
	got := c.selectUnsubmittedPostForms(descs, 3)
	if len(got) != 1 {
		t.Fatalf("expected the shared cap (3) to leave room for exactly 1 POST form, got %d (%v)", len(got), got)
	}
}

func TestSelectUnsubmittedPostFormsSkipsEmptySignature(t *testing.T) {
	c := &Crawler{}
	descs := []postFormDescriptor{
		{Index: 0, Sig: ""},
		{Index: 1, Sig: "https://x.test/real post name"},
	}
	got := c.selectUnsubmittedPostForms(descs, 0)
	if len(got) != 1 || got[0] != 1 {
		t.Fatalf("expected only the non-empty signature (index 1), got %v", got)
	}
}
