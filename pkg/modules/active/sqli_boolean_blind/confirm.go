package sqli_boolean_blind

import (
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// confirmRounds is how many independent rounds (with fresh random operands)
// each confirmation factor is replayed. More rounds = stronger guarantee that
// the boolean condition — not request-to-request noise — drives the response.
// Three independent operands (mirroring the xpath_injection boolean oracle) make
// it far harder for per-request dynamic content to line every TRUE round into one
// cluster and every FALSE round into another by chance.
const confirmRounds = 3

// confirmLogic runs a multi-round, multi-factor logic battery in the breakout
// boundary that detection matched. It is the primary false-positive killer for
// boolean-blind: a genuine injection must satisfy *every* factor, while noisy
// or static endpoints fail at least one.
//
// Whether an AND- or an OR-combined condition produces a TRUE/FALSE divergence
// depends on whether the base value already matches a row, so the battery first
// probes which logical operator is the working oracle here, then exercises it
// across multiple rounds and comparison operators:
//   - rounds with fresh random operands, alternating the comparison operator
//     (= and <>), so the differential is proven to follow boolean truth rather
//     than a specific literal or operator the app might echo/special-case;
//   - per-branch ratio stability across rounds (TRUE pages cluster, FALSE pages
//     cluster) and per-round divergence between the two clusters;
//   - an invalid-syntax probe ("AND <n> <m>") that must NOT render the TRUE
//     page — otherwise the endpoint ignores SQL validity and the differential
//     was spurious.
func (m *Module) confirmLogic(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	baseValue, prefix, suffix string,
) (bool, error) {
	// cond builds "<base><prefix> <logic> <left><cmp><right><suffix>", e.g.
	// "1' AND 42<>17-- -". With cmp "=", a=a is TRUE and a=b is FALSE; with cmp
	// "<>", a<>b is TRUE and a<>a is FALSE.
	cond := func(logic, cmp, left, right string) string {
		return baseValue + prefix + " " + logic + " " + left + cmp + right + suffix
	}

	// Determine which logical operator is the working oracle for this row.
	logic, ok, err := m.detectLogicOp(ctx, httpClient, ip, cond)
	if err != nil || !ok {
		return false, err
	}

	type form struct {
		cmp    string
		tl, tr string // TRUE operands
		fl, fr string // FALSE operands
	}

	var trueSigs, falseSigs []responseSignature
	for i := 0; i < confirmRounds; i++ {
		a, b := distinctNums()
		// Alternate the comparison operator each round as an extra factor.
		f := form{cmp: "=", tl: a, tr: a, fl: a, fr: b}
		if i%2 == 1 {
			f = form{cmp: "<>", tl: a, tr: b, fl: a, fr: a}
		}

		_, tSig, tBlocked, err := m.sendPayload(ctx, httpClient, ip, cond(logic, f.cmp, f.tl, f.tr))
		if err != nil {
			return false, err
		}
		_, fSig, fBlocked, err := m.sendPayload(ctx, httpClient, ip, cond(logic, f.cmp, f.fl, f.fr))
		if err != nil {
			return false, err
		}

		// Factor: neither form may be a WAF/CDN block, and both must be HTTP 200
		// producing different pages. A blocked probe or a branch flipping to a
		// redirect/error is a status/edge artifact, not a 200-vs-200 boolean
		// signal — reject.
		if tBlocked || fBlocked {
			return false, nil
		}
		if !statusOK(tSig) || !statusOK(fSig) {
			return false, nil
		}
		if quickRatio(tSig, fSig) >= upperRatioBound {
			return false, nil
		}
		trueSigs = append(trueSigs, tSig)
		falseSigs = append(falseSigs, fSig)
	}

	// Factor: each branch must be stable across rounds even though the operands
	// and comparison operator changed — it is the boolean truth value that
	// decides the page, not the literal tokens (defeats apps echoing the input).
	if !roundsStable(trueSigs, falseSigs) {
		return false, nil
	}

	// Factor: a malformed expression ("AND <n> <m>" — two literals, no operator)
	// is a syntax error on every SQL dialect. If the endpoint still renders the
	// deterministic TRUE page, it does not react to SQL at all → false positive.
	c, d := distinctNums()
	_, invSig, invBlocked, err := m.sendPayload(ctx, httpClient, ip, baseValue+prefix+" AND "+c+" "+d+suffix)
	if err != nil {
		return false, err
	}
	if invBlocked {
		return false, nil
	}
	if ratioSimilar(invSig, trueSigs[0]) {
		return false, nil
	}

	return true, nil
}

// detectLogicOp probes AND then OR and returns the first whose TRUE (a=a) and
// FALSE (a=b) forms diverge — the working boolean oracle for this row. ok=false
// means neither operator produced a differential (so confirmation fails).
func (m *Module) detectLogicOp(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	cond func(logic, cmp, left, right string) string,
) (string, bool, error) {
	for _, logic := range []string{"AND", "OR"} {
		a, b := distinctNums()
		_, tSig, tBlocked, err := m.sendPayload(ctx, httpClient, ip, cond(logic, "=", a, a))
		if err != nil {
			return "", false, err
		}
		_, fSig, fBlocked, err := m.sendPayload(ctx, httpClient, ip, cond(logic, "=", a, b))
		if err != nil {
			return "", false, err
		}
		// A blocked probe proves nothing about the boolean oracle — try the other
		// operator instead of accepting an edge-induced divergence.
		if tBlocked || fBlocked {
			continue
		}
		// Require a 200-vs-200 divergence: a 200↔redirect/error split is a status
		// flip, not the boolean oracle we want.
		if statusOK(tSig) && statusOK(fSig) && quickRatio(tSig, fSig) < upperRatioBound {
			return logic, true, nil
		}
	}
	return "", false, nil
}

// confirmRepeat is the last-resort fallback for an opaque pair whose comparison
// operands could not be re-derived (so confirmRandomized cannot prove the
// differential follows boolean truth). It re-runs the matched TRUE/FALSE
// differential for confirmRounds rounds and requires the divergence and
// per-branch stability to reproduce every time. It cannot, on its own,
// distinguish a real oracle from a deterministic non-SQL differential (a WAF
// tautology signature), so confirmRandomized — which varies the operands — is
// always preferred and headers are denied this path entirely.
func (m *Module) confirmRepeat(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	truePayload, falsePayload string,
) (bool, error) {
	var trueSigs, falseSigs []responseSignature
	for i := 0; i < confirmRounds; i++ {
		_, tSig, tBlocked, err := m.sendPayload(ctx, httpClient, ip, truePayload)
		if err != nil {
			return false, err
		}
		_, fSig, fBlocked, err := m.sendPayload(ctx, httpClient, ip, falsePayload)
		if err != nil {
			return false, err
		}
		// A blocked probe or a status flip is an edge/status artifact, not a
		// 200-vs-200 boolean signal — reject.
		if tBlocked || fBlocked {
			return false, nil
		}
		if !statusOK(tSig) || !statusOK(fSig) {
			return false, nil
		}
		if quickRatio(tSig, fSig) >= upperRatioBound {
			return false, nil
		}
		trueSigs = append(trueSigs, tSig)
		falseSigs = append(falseSigs, fSig)
	}
	return roundsStable(trueSigs, falseSigs), nil
}

// roundsStable reports whether each branch's responses are mutually
// ratio-similar across rounds: every TRUE response resembles the first TRUE
// response (and likewise for FALSE). It confirms the boolean truth value, not
// the changing operands, is what decides the page.
func roundsStable(trueSigs, falseSigs []responseSignature) bool {
	for i := 1; i < len(trueSigs); i++ {
		if !ratioSimilar(trueSigs[0], trueSigs[i]) || !ratioSimilar(falseSigs[0], falseSigs[i]) {
			return false
		}
	}
	return true
}
