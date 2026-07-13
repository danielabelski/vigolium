package http

import (
	"crypto/tls"
	"net/http/httptrace"
	"sync/atomic"

	"go.uber.org/zap"
)

// poolStats accumulates connection-pool telemetry across a scan via httptrace. It
// is a pointer field on Requester so WithContext copies and anonymous views
// (CloneWithoutCredentials) share one instance and the reuse ratio is scan-wide.
// It covers the net/http (retryablehttp) path only; the rawhttp path bypasses
// net/http, so its requests are not traced (a documented blind spot). A single
// ClientTrace is built once and shared across requests — its hooks close over the
// counters, which are fixed — so tracing adds one context wrap per request, not a
// fresh closure set.
type poolStats struct {
	requests   atomic.Int64
	connReused atomic.Int64
	connNew    atomic.Int64
	tlsHands   atomic.Int64
	ct         *httptrace.ClientTrace
}

func newPoolStats() *poolStats {
	ps := &poolStats{}
	ps.ct = &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Reused {
				ps.connReused.Add(1)
			} else {
				ps.connNew.Add(1)
			}
		},
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			ps.tlsHands.Add(1)
		},
	}
	return ps
}

// PoolStatsSnapshot is a point-in-time copy of the connection-pool counters.
type PoolStatsSnapshot struct {
	Requests      int64
	ConnNew       int64
	ConnReused    int64
	TLSHandshakes int64
}

// ReuseRatio is reused / (reused + new); 0 when no connections were established.
// A low value signals connection churn — the class of regression that made
// anonymous-clone transport fragmentation invisible before this telemetry existed.
func (s PoolStatsSnapshot) ReuseRatio() float64 {
	total := s.ConnReused + s.ConnNew
	if total == 0 {
		return 0
	}
	return float64(s.ConnReused) / float64(total)
}

// PoolStats returns a snapshot of the connection-pool counters, or a zero value
// when telemetry is unavailable.
func (r *Requester) PoolStats() PoolStatsSnapshot {
	if r == nil || r.poolStats == nil {
		return PoolStatsSnapshot{}
	}
	ps := r.poolStats
	return PoolStatsSnapshot{
		Requests:      ps.requests.Load(),
		ConnNew:       ps.connNew.Load(),
		ConnReused:    ps.connReused.Load(),
		TLSHandshakes: ps.tlsHands.Load(),
	}
}

// LogPoolStats logs connection-pool telemetry at info level, a companion to the
// request clusterer's LogStats at end of scan. A no-op when nothing was traced.
func (r *Requester) LogPoolStats() {
	s := r.PoolStats()
	if s.Requests == 0 && s.ConnNew == 0 && s.ConnReused == 0 {
		return
	}
	zap.L().Info("HTTP connection pool stats",
		zap.Int64("requests_traced", s.Requests),
		zap.Int64("connections_new", s.ConnNew),
		zap.Int64("connections_reused", s.ConnReused),
		zap.Int64("tls_handshakes", s.TLSHandshakes),
		zap.Float64("reuse_ratio", s.ReuseRatio()),
	)
}
