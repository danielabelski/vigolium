package yamlext

import (
	"fmt"
	"regexp"
	"sync"
	"testing"
)

func TestCompileCachedReturnsEquivalentRegex(t *testing.T) {
	patterns := []string{
		`admin`,
		`(?i)internal server error`,
		`\d{3}-\d{2}-\d{4}`,
		`^Bearer\s+[A-Za-z0-9._-]+$`,
		`a|b|c`,
	}

	subjects := []string{
		"admin panel",
		"Internal Server Error",
		"123-45-6789",
		"Bearer abc.def-ghi",
		"nothing here",
		"",
	}

	for _, p := range patterns {
		want := regexp.MustCompile(p)
		got, err := compileCached(p)
		if err != nil {
			t.Fatalf("compileCached(%q) error = %v", p, err)
		}
		for _, s := range subjects {
			if got.MatchString(s) != want.MatchString(s) {
				t.Errorf("pattern %q on %q: cached = %v, direct = %v",
					p, s, got.MatchString(s), want.MatchString(s))
			}
			if got.FindString(s) != want.FindString(s) {
				t.Errorf("pattern %q on %q: cached FindString = %q, direct = %q",
					p, s, got.FindString(s), want.FindString(s))
			}
		}
	}
}

// The same pattern must return the identical compiled program, or nothing is
// actually being cached.
func TestCompileCachedReusesCompiledRegex(t *testing.T) {
	const pattern = `unique-cache-reuse-probe-\d+`

	first, err := compileCached(pattern)
	if err != nil {
		t.Fatalf("compileCached error = %v", err)
	}
	second, err := compileCached(pattern)
	if err != nil {
		t.Fatalf("compileCached (second) error = %v", err)
	}
	if first != second {
		t.Error("compileCached returned a freshly compiled regex for a repeated pattern")
	}
}

// An invalid pattern must keep returning an error — and must cache the failure,
// so a bad rule doesn't re-attempt compilation on every response.
func TestCompileCachedCachesFailures(t *testing.T) {
	const bad = `([unclosed-cache-failure-probe`

	re1, err1 := compileCached(bad)
	if err1 == nil {
		t.Fatal("expected an error for an invalid pattern")
	}
	if re1 != nil {
		t.Error("expected a nil regex alongside the error")
	}

	re2, err2 := compileCached(bad)
	if err2 == nil {
		t.Fatal("expected an error on the repeated invalid pattern")
	}
	if re2 != nil {
		t.Error("expected a nil regex on the cached failure")
	}
	if err1.Error() != err2.Error() {
		t.Errorf("repeated invalid pattern gave a different error: %v vs %v", err1, err2)
	}

	// The failure must be memoized, not recomputed: an invalid pattern makes its
	// matcher return false forever, and would otherwise re-attempt the compile on
	// every response.
	entry, ok := regexCache.Get(bad)
	if !ok {
		t.Fatal("invalid pattern was not cached; the failing compile will be retried per response")
	}
	if entry.err == nil {
		t.Error("cached entry for an invalid pattern has no error recorded")
	}
}

// Matchers are evaluated from concurrent scan workers. Run under -race.
func TestCompileCachedConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				p := fmt.Sprintf(`concurrent-probe-%d-\d+`, i%16)
				re, err := compileCached(p)
				if err != nil {
					t.Errorf("compileCached(%q) error = %v", p, err)
					return
				}
				re.MatchString("concurrent-probe-3-42")
			}
		}(w)
	}
	wg.Wait()
}

// The cache is bounded: far more distinct patterns than the cap must still all
// compile correctly, with the cache evicting rather than growing.
func TestCompileCachedStaysBounded(t *testing.T) {
	for i := 0; i < regexCacheMaxEntries+256; i++ {
		p := fmt.Sprintf(`bounded-probe-%d-[0-9]+`, i)
		re, err := compileCached(p)
		if err != nil {
			t.Fatalf("compileCached(%q) error = %v", p, err)
		}
		if !re.MatchString(fmt.Sprintf("bounded-probe-%d-7", i)) {
			t.Fatalf("pattern %q did not match its own subject", p)
		}
	}

	if n := regexCache.Len(); n > regexCacheMaxEntries {
		t.Errorf("cache holds %d entries, over the %d cap", n, regexCacheMaxEntries)
	}
}

func BenchmarkMatcherRegexCompile(b *testing.B) {
	const pattern = `(?i)(internal server error|stack trace|exception in thread)`

	b.Run("direct", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			re, err := regexp.Compile(pattern)
			if err != nil {
				b.Fatal(err)
			}
			re.FindString("something Internal Server Error something")
		}
	})
	b.Run("cached", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			re, err := compileCached(pattern)
			if err != nil {
				b.Fatal(err)
			}
			re.FindString("something Internal Server Error something")
		}
	})
}
