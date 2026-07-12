package crawler

import "testing"

func TestLinkShapeKeyValueBlind(t *testing.T) {
	// Same path + same param-name set → same shape regardless of value or order.
	a := linkShapeKey("https://x.test/catalog?category=Books")
	b := linkShapeKey("https://x.test/catalog?category=Gin")
	if a != b {
		t.Errorf("category=Books and category=Gin should share a shape, got %q vs %q", a, b)
	}
	// Different param name → different shape.
	if linkShapeKey("https://x.test/catalog?searchTerm=a") == a {
		t.Errorf("searchTerm and category should be different shapes")
	}
	// Multi-param order independence.
	if linkShapeKey("https://x.test/p?b=1&a=2") != linkShapeKey("https://x.test/p?a=9&b=8") {
		t.Errorf("param order/value should not change the shape")
	}
}

func TestSelectUnprimedLinksPerShapeCap(t *testing.T) {
	c := &Crawler{}
	in := []string{
		"https://x.test/catalog?category=Accessories",
		"https://x.test/catalog?category=Accompaniments",
		"https://x.test/catalog?category=Books",
		"https://x.test/catalog?category=Gin",
		"https://x.test/catalog?category=Juice",
	}
	// perShape=3 → only 3 of the 5 category variants primed.
	got := c.selectUnprimedLinks(in, 0, 3)
	if len(got) != 3 {
		t.Fatalf("expected 3 primed under per-shape cap, got %d (%v)", len(got), got)
	}
	// Re-priming the same set adds nothing (crawl-wide dedup + shape already full).
	if again := c.selectUnprimedLinks(in, 0, 3); len(again) != 0 {
		t.Errorf("expected 0 on re-prime, got %d (%v)", len(again), again)
	}
}

func TestSelectUnprimedLinksTotalCapAndDistinctShapes(t *testing.T) {
	c := &Crawler{}
	// Distinct shapes are independent; the total cap bounds the overall count.
	in := []string{
		"https://x.test/catalog?category=Books",
		"https://x.test/catalog?searchTerm=a",
		"https://x.test/blog/post?postId=1",
		"https://x.test/blog/post?postId=2",
	}
	got := c.selectUnprimedLinks(in, 3, 6) // total cap 3
	if len(got) != 3 {
		t.Fatalf("expected total cap to limit to 3, got %d (%v)", len(got), got)
	}
}
