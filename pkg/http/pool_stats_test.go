package http

import "testing"

func TestPoolStatsReuseRatio(t *testing.T) {
	if got := (PoolStatsSnapshot{}).ReuseRatio(); got != 0 {
		t.Errorf("empty reuse ratio = %v, want 0", got)
	}
	s := PoolStatsSnapshot{ConnReused: 3, ConnNew: 1}
	if got := s.ReuseRatio(); got != 0.75 {
		t.Errorf("reuse ratio = %v, want 0.75", got)
	}
}

func TestPoolStatsTraceCounts(t *testing.T) {
	ps := newPoolStats()
	// GotConn hooks feed the reused/new counters.
	ps.connReused.Add(2)
	ps.connNew.Add(2)
	r := &Requester{poolStats: ps}
	snap := r.PoolStats()
	if snap.ConnReused != 2 || snap.ConnNew != 2 {
		t.Fatalf("snapshot = %+v", snap)
	}
	if snap.ReuseRatio() != 0.5 {
		t.Errorf("reuse ratio = %v, want 0.5", snap.ReuseRatio())
	}
	// A nil-poolStats requester returns a zero snapshot, not a panic.
	if (&Requester{}).PoolStats() != (PoolStatsSnapshot{}) {
		t.Error("nil poolStats should yield a zero snapshot")
	}
}
