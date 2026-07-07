package infra

import (
	"math"
	"time"
)

// MeanStdev computes the mean and population standard deviation of a set of
// durations. Shared by the time-based detection modules (sqli_time_blind,
// command_injection_timing) that derive an adaptive per-target delay threshold
// from a sample of baseline response times. Returns (0, 0) for an empty sample.
func MeanStdev(samples []time.Duration) (mean, stdev time.Duration) {
	if len(samples) == 0 {
		return 0, 0
	}
	var sum float64
	for _, s := range samples {
		sum += float64(s)
	}
	mu := sum / float64(len(samples))
	var variance float64
	for _, s := range samples {
		d := float64(s) - mu
		variance += d * d
	}
	variance /= float64(len(samples))
	return time.Duration(mu), time.Duration(math.Sqrt(variance))
}

// ScaledDelayConfirmed reports whether an injected delay scales with the requested
// sleep duration, given the no-sleep control latency and the low/high probe
// latencies measured in the SAME round. It is the shared false-positive verdict for
// the time-based modules (command_injection_timing, sqli_time_blind,
// nosqli_operator_injection): each credits a probe only with the delay it added over
// the control, then requires
//
//   - both the low and high probe to add >= their requested duration / scaleDenom
//     (a slow-but-constant host or a spike on only the high probe fails here — its
//     small sleep added ~nothing over the control);
//   - the high probe not to overshoot its requested duration by more than
//     overshootFactor× (a fixed upstream stall adds far more than the sleep asked);
//   - the high−low differential to track the requested (highWant−lowWant) span
//     (>= half), ruling out a fixed non-scaling stall that delays every probe equally.
//
// Per-module concerns (round count, block handling, DBMS payloads, an extra coarse
// floor) stay at the call site; only this numeric verdict is shared.
func ScaledDelayConfirmed(control, low, high, lowWant, highWant time.Duration, scaleDenom, overshootFactor int) bool {
	lowDelta := low - control
	highDelta := high - control
	if lowDelta < lowWant/time.Duration(scaleDenom) || highDelta < highWant/time.Duration(scaleDenom) {
		return false
	}
	if highDelta > highWant*time.Duration(overshootFactor) {
		return false
	}
	return highDelta-lowDelta >= (highWant-lowWant)/time.Duration(scaleDenom)
}
