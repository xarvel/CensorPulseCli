package client

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// burstOptions describe one tls.burst attempt.
type burstOptions struct {
	N           int    // parallel handshakes to the same SNI
	Fingerprint string // uTLS parrot worn by every handshake ("" = Go TLS)
}

// tlsBurst reproduces the rate rule seen in the field: more than N TLS
// handshakes to one server name within a short window freezes that name for
// a while, while a single handshake to another name goes through. The
// attempt is one differential in itself:
//
//   - alpha: N handshakes with one random SNI, fired together (every window
//     is reserved first so that the ClientHellos leave within one RTT);
//   - beta: one handshake with a fresh SNI right after alpha;
//   - gamma: one handshake with an empty SNI.
//
// Every handshake carries the envelope echo, because a frozen flow may still
// receive a ServerHello and only lose the application data. The outcome is
// burst_freeze when at least one alpha handshake fails and beta passes; ok
// when everything passes; the underlying outcome of alpha otherwise.
func (c *Client) tlsBurst(ctx context.Context, a *Attempt, o burstOptions) *Attempt {
	if o.N <= 0 {
		o.N = 4
	}
	alphaSNI := "s" + randHex(6) + ".probe.invalid"
	betaSNI := "s" + randHex(6) + ".probe.invalid"
	a.Detail["sni"] = alphaSNI
	a.Detail["burst_n"] = strconv.Itoa(o.N)
	if o.Fingerprint != "" {
		a.Detail["fingerprint"] = o.Fingerprint
	}
	sub := func(variant string) *Attempt {
		s := newAttempt(a.TestID, a.Group, a.Role, variant, "tcp", a.DstPort, a.Round)
		return s
	}
	opts := func(sni string) tlsOptions {
		return tlsOptions{SNI: sni, Fingerprint: o.Fingerprint, ALPN: []string{"http/1.1"}}
	}
	// Reserve every window up front: the reservations are control-plane
	// round trips and must not spread the burst out. The controls are
	// reserved first and the alpha windows last, so that an alpha flow the
	// server could not identify (ServerHello sent, echo frozen) is matched to
	// an alpha reservation (the newest unused ones), not to beta's or gamma's.
	gamma := sub("gamma")
	if err := c.reserveTLS(ctx, gamma, opts("")); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	beta := sub("beta")
	if err := c.reserveTLS(ctx, beta, opts(betaSNI)); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	alpha := make([]*Attempt, o.N)
	var ids []string
	for i := range alpha {
		alpha[i] = sub("alpha")
		if err := c.reserveTLS(ctx, alpha[i], opts(alphaSNI)); err != nil {
			return a.fail(OutcomeServerError, err)
		}
		ids = append(ids, alpha[i].AttemptID)
	}
	a.AttemptID = alpha[0].AttemptID
	a.Detail["reservation_ids"] = strings.Join(ids, ",")
	a.restart()

	// Alpha: fire together.
	var wg sync.WaitGroup
	start := time.Now()
	for i := range alpha {
		wg.Add(1)
		go func(s *Attempt) {
			defer wg.Done()
			s.restart()
			c.tlsEchoReserved(ctx, s, opts(alphaSNI))
		}(alpha[i])
	}
	wg.Wait()
	a.Detail["burst_spread_ms"] = fmt.Sprintf("%.0f", spreadMS(alpha))
	a.Detail["burst_elapsed_ms"] = fmt.Sprintf("%.0f", float64(time.Since(start).Microseconds())/1000)
	okAlpha := 0
	outcomes := map[string]int{}
	for _, s := range alpha {
		if s.Outcome == OutcomeOK {
			okAlpha++
		}
		outcomes[s.Outcome]++
		a.BytesOut += s.BytesOut
		a.BytesIn += s.BytesIn
	}
	a.Detail["alpha_ok"] = strconv.Itoa(okAlpha)
	a.Detail["alpha_outcomes"] = joinCounts(outcomes)
	var nonces []string
	for _, s := range alpha {
		if s.Nonce != "" {
			nonces = append(nonces, s.Nonce)
		}
	}
	a.Detail["alpha_nonces"] = strings.Join(nonces, ",")
	if hs := stageCount(alpha, "handshake"); hs != okAlpha {
		a.Detail["alpha_handshakes"] = strconv.Itoa(hs)
	}

	// Beta: one handshake, other name, same everything else.
	beta.restart()
	c.tlsEchoReserved(ctx, beta, opts(betaSNI))
	a.Detail["beta_outcome"] = beta.Outcome
	a.Detail["beta_sni"] = betaSNI
	// Gamma: empty SNI.
	gamma.restart()
	c.tlsEchoReserved(ctx, gamma, opts(""))
	a.Detail["gamma_outcome"] = gamma.Outcome
	// The attempt correlates with the first alpha flow; the other alpha
	// flows are counted from their reservation ids when observations arrive.
	a.Nonce = alpha[0].Nonce
	if v, ok := alpha[0].Stages["handshake"]; ok {
		a.Stages["handshake"] = v
	}

	// A freeze stops the burst, not one connection of it: at least half of
	// the parallel handshakes must have failed. A single failed handshake
	// next to three that passed is loss, and is only recorded.
	frozen := (o.N - okAlpha) >= (o.N+1)/2
	switch {
	case okAlpha == o.N && beta.Outcome == OutcomeOK:
		return a.ok()
	case !frozen && beta.Outcome == OutcomeOK:
		a.Detail["alpha_lost"] = strconv.Itoa(o.N - okAlpha)
		return a.ok()
	case frozen && beta.Outcome == OutcomeOK:
		return a.fail(OutcomeBurstFreeze, fmt.Errorf("%d/%d parallel handshakes to %s failed (%s); a single handshake to %s passed", o.N-okAlpha, o.N, alphaSNI, joinCounts(outcomes), betaSNI))
	case okAlpha < o.N:
		// Alpha and beta both failed: either the path is down for TLS on this
		// port (the tls.sni baseline will show that) or the freeze is wider
		// than one name. Report the dominant alpha outcome; the classifier
		// needs a passing control before it says anything.
		dom := ""
		best := -1
		for k, v := range outcomes {
			if k != OutcomeOK && (v > best || (v == best && k < dom)) {
				dom, best = k, v
			}
		}
		if dom == "" {
			dom = OutcomeInconclusive
		}
		return a.fail(dom, fmt.Errorf("%d/%d parallel handshakes failed and the single handshake to %s failed too (%s)", o.N-okAlpha, o.N, betaSNI, beta.Outcome))
	default:
		// Alpha passed, beta failed: not the burst rule. Surface beta's outcome.
		return a.fail(beta.Outcome, fmt.Errorf("parallel handshakes passed but the single handshake to %s failed: %s", betaSNI, beta.Error))
	}
}

// spreadMS is the spread of the first_write stage across attempts, i.e. how
// far apart the ClientHellos actually left.
func spreadMS(as []*Attempt) float64 {
	var t []float64
	for _, a := range as {
		if v, ok := a.Stages["first_write"]; ok {
			t = append(t, v+float64(a.StartedAt.UnixMicro())/1000)
		}
	}
	if len(t) < 2 {
		return 0
	}
	sort.Float64s(t)
	return t[len(t)-1] - t[0]
}

func stageCount(as []*Attempt, stage string) int {
	n := 0
	for _, a := range as {
		if _, ok := a.Stages[stage]; ok {
			n++
		}
	}
	return n
}

func joinCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, ",")
}
