package classify

import (
	"fmt"
	"strings"

	"github.com/xarvel/CensorPulseCli/internal/client"
)

// Rules 5b-5c are about flows that start and then stop: a long transfer, a
// run of small packets, a burst of handshakes, a VPN session. Their evidence
// is read from the attempts behind the cell (offsets, packet counts).

// cellAttempts collects the attempts behind a cell for its evidence: the
// ones of the same test, port and variant that also satisfy also (nil: all).
// The rules differ in what else they ask: only ruleSessionCut compares the
// transport and only ruleBurstFreeze leaves out the transient attempts (the
// cells never hold those). That decides which attempts feed a median, which
// is evidence, so the differences are kept as they are.
func (rc *ruleCtx) cellAttempts(c Cell, also func(a *client.Attempt) bool) []*client.Attempt {
	var out []*client.Attempt
	for _, a := range rc.attempts {
		if a.TestID == c.TestID && a.DstPort == c.Port && a.Variant == c.Variant && (also == nil || also(a)) {
			out = append(out, a)
		}
	}
	return out
}

// ruleBulkCut is rule 5b, long transfers: a cut or stall after N kilobytes
// while short exchanges on the same port pass. The evidence carries the
// median offset.
func (rc *ruleCtx) ruleBulkCut() {
	for _, c := range rc.cells {
		if c.TestID != "tcp.bulk" || !c.fail() {
			continue
		}
		short, ok := rc.find("tcp.echo", c.Transport, c.Port, "")
		if !ok || !short.pass() {
			continue
		}
		off := "unknown"
		if offsets := detailInts(rc.cellAttempts(c, nil), "bulk_cut_kb"); len(offsets) > 0 {
			off = fmt.Sprintf("~%d KB", median(offsets))
		}
		kind := "bulk_transfer_cut_suspected"
		if strings.Contains(c.Variant, "trigger:") || strings.Contains(c.Variant, "list:") {
			kind = "sni_bulk_cut_suspected"
		}
		rc.add(kind, c.Key(), confidence(c, short), rc.ev(c), "transfer stopped at "+off, "short exchange on the same port passed: "+rc.ev(short))
	}
}

// rulePacketCut is rule 5b', small-packet flows: the same bytes as the echo,
// in many segments or many datagrams, stop being answered while the
// one-packet echo passes on the same port. Cross-checked against tcp.bulk on
// the same port: a byte rule cuts the 64 KB transfer and not this flow; a
// packet rule cuts this flow, and the bulk transfer only if it also crosses
// the count.
func (rc *ruleCtx) rulePacketCut() {
	for _, c := range rc.cells {
		if (c.TestID != "tcp.packets" && c.TestID != "udp.packets") || !c.fail() {
			continue
		}
		echo, ok := rc.find(echoTestFor(c.Transport), c.Transport, c.Port, "")
		if !ok || !echo.pass() {
			continue
		}
		failed := rc.cellAttempts(c, func(a *client.Attempt) bool { return a.Outcome != client.OutcomeOK })
		sent, acked, planned := detailInts(failed, "packets_sent"), detailInts(failed, "packets_acked"), detailInts(failed, "packets_planned")
		e := []string{rc.ev(c), "one-packet echo on the same port passed: " + rc.ev(echo)}
		if c.Transport == "udp" && len(acked) > 0 {
			e = append(e, fmt.Sprintf("datagrams answered before the cut: median %d of %d", median(acked), median(planned)))
		} else if len(sent) > 0 {
			e = append(e, fmt.Sprintf("segments written: median %d of %d; the reply never came", median(sent), median(planned)))
		}
		if c.Transport == "tcp" {
			bulkFail, bulkPass := false, false
			for _, o := range rc.cells {
				if o.TestID == "tcp.bulk" && o.Port == c.Port {
					if o.fail() {
						bulkFail = true
					} else if o.pass() {
						bulkPass = true
					}
				}
			}
			switch {
			case bulkFail:
				e = append(e, "tcp.bulk on the same port was cut as well: the limit is consistent with a per-flow packet count (about 16 KB of 4 KB chunks is also ~25 packets)")
			case bulkPass:
				e = append(e, "tcp.bulk (tens of KB in 4 KB chunks) passed on the same port: only a flow of many small packets trips it")
			}
		}
		rc.add("packet_count_cut_suspected", c.Key(), confidence(c, echo), e...)
	}
}

// ruleBurstFreeze is the third part of rule 5b, the TLS handshake rate rule:
// N parallel handshakes to one name fail while a single handshake to another
// name passes right after (the attempt carries its own control). The plain
// tls.sni baseline on the port is the outer control; the firefox burst says
// whether the rule is fingerprint-dependent.
func (rc *ruleCtx) ruleBurstFreeze() {
	for _, c := range rc.cells {
		if c.TestID != "tls.burst" || c.Outcomes[client.OutcomeBurstFreeze] == 0 || c.pass() {
			continue
		}
		outer, ok := rc.find("tls.sni", "tcp", c.Port, "benign")
		conf := "low"
		if ok && outer.pass() {
			conf = confidence(c, outer)
		} else if c.Measured() >= mediumMinAttempts && c.Outcomes[client.OutcomeBurstFreeze]*2 > c.Measured() {
			// No outer control: the attempt's own one carries a majority of
			// freezes to medium, never further.
			conf = "medium"
		}
		e := rc.burstEvidence(c)
		if ok {
			e = append(e, "single-handshake baseline on the same port: "+rc.ev(outer))
		}
		for _, o := range rc.cells {
			if o.TestID == "tls.burst" && o.Port == c.Port && o.Variant != c.Variant {
				if o.pass() {
					e = append(e, fmt.Sprintf("the same burst with the %s parrot passed: the rule is fingerprint-dependent (%s)", strings.SplitN(o.Variant, "-", 2)[0], rc.ev(o)))
				} else if o.fail() {
					e = append(e, fmt.Sprintf("the same burst with the %s parrot failed too: the rule does not depend on the fingerprint (%s)", strings.SplitN(o.Variant, "-", 2)[0], rc.ev(o)))
				}
			}
		}
		rc.add("tls_burst_freeze_suspected", c.Key(), conf, e...)
	}
}

// burstEvidence is the cell line and what the attempts of a frozen burst
// counted on both ends.
func (rc *ruleCtx) burstEvidence(c Cell) []string {
	as := rc.cellAttempts(c, func(a *client.Attempt) bool { return a.Detail["transient"] != "true" })
	fp, n := "", ""
	if len(as) > 0 {
		fp, n = as[len(as)-1].Detail["fingerprint"], as[len(as)-1].Detail["burst_n"]
	}
	alphaOK, seen, partial := detailInts(as, "alpha_ok"), detailInts(as, "server_alpha_seen"), detailInts(as, "server_alpha_partial")
	e := []string{rc.ev(c)}
	if len(alphaOK) > 0 {
		e = append(e, fmt.Sprintf("%s parallel handshakes (%s parrot, ClientHellos within ~%d ms): median %d passed; the single handshake to another name right after passed", n, fp, median(detailInts(as, "burst_spread_ms")), median(alphaOK)))
	}
	if len(seen) > 0 {
		// server_alpha_hello is the older name of server_alpha_answered.
		line := fmt.Sprintf("server saw median %d of %s ClientHellos and sent a ServerHello to %d", median(seen), n, median(detailInts(as, "server_alpha_answered", "server_alpha_hello")))
		if len(partial) > 0 && median(partial) > 0 {
			line += fmt.Sprintf(", %d arrived cut mid-hello", median(partial))
		}
		e = append(e, line+": "+directionFrom(c.dominant()))
	}
	return e
}

// A session cut repeats when at least sessionCutRepeatNum attempts in
// sessionCutRepeatDen were cut (two rounds in three), of at least
// highMinAttempts: with a plain baseline passing on the port that is high.
const (
	sessionCutRepeatNum = 2
	sessionCutRepeatDen = 3
)

// ruleSessionCut is rule 5c, VPN sessions: the handshake is answered on a
// port but the data that follows is not. This is the stateful-blocking
// signature ("handshake completes, no traffic flows") that a handshake-only
// test cannot see. A session test that fails together with its handshake
// test is protocol blocking and is reported by rule 4.
func (rc *ruleCtx) ruleSessionCut() {
	for _, c := range rc.cells {
		// A session cell that measured nothing (the host's own failure,
		// a fault of the server) cut nothing.
		if handshakeTestOf(c.TestID) == "" || c.pass() || c.Measured() == 0 {
			continue
		}
		init, ok := rc.handshakeCell(c)
		if !ok || !init.pass() {
			continue
		}
		kind := strings.TrimSuffix(c.TestID, ".session") + "_session_cut_suspected"
		e := rc.sessionCutEvidence(c, init)
		// Confidence: high when the cut repeats (at least two rounds in
		// three) while the handshake and a plain baseline on the same port
		// (udp.echo / udp.packets, tcp.echo / tcp.packets) pass; otherwise
		// the general rule, capped at medium when a round passed.
		conf := confidence(c, init)
		if c.OK > 0 && conf == "high" {
			conf = "medium"
		}
		cut := c.Outcomes[client.OutcomeSessionCut]
		if cut*sessionCutRepeatDen >= c.Measured()*sessionCutRepeatNum && c.Measured() >= highMinAttempts && init.pass() {
			echo, okE := rc.find(echoTestFor(c.Transport), c.Transport, c.Port, "")
			pk, okP := rc.find(plainTestFor(c.Transport, "packets"), c.Transport, c.Port, "")
			if (okE && echo.pass()) || (okP && pk.pass()) {
				conf = "high"
				if okE && echo.pass() {
					e = append(e, "baseline on the same port passed: "+rc.ev(echo))
				} else {
					e = append(e, "baseline on the same port passed: "+rc.ev(pk))
				}
			}
		}
		rc.add(kind, c.Key(), conf, e...)
	}
}

// sessionCutEvidence is the two cell lines and what the session attempts
// counted: data and control packets on both ends, and where the loss began.
func (rc *ruleCtx) sessionCutEvidence(c, init Cell) []string {
	as := rc.cellAttempts(c, func(a *client.Attempt) bool { return a.Transport == c.Transport })
	recv, sent, seen := detailInts(as, "data_recv"), detailInts(as, "data_sent"), detailInts(as, "server_data_seen")
	ctlRecv, ctlSent, ctlSeen := detailInts(as, "ctl_recv"), detailInts(as, "ctl_sent"), detailInts(as, "server_ctl_seen")
	firstLoss := detailInts(rc.cellAttempts(c, func(a *client.Attempt) bool {
		return a.Transport == c.Transport && a.Outcome == client.OutcomeSessionCut
	}), "data_first_loss")

	e := []string{rc.ev(c), "handshake on the same port passed: " + rc.ev(init)}
	if len(recv) > 0 && len(sent) > 0 {
		e = append(e, fmt.Sprintf("data packets answered: median %d of %d", median(recv), median(sent)))
	}
	// OpenVPN has a control channel between the reset and the data: say
	// which of the two was cut. The real-client signature is "control
	// passed, data cut": the TLS handshake and PUSH_REPLY go through
	// and not one P_DATA_V2 crosses in either direction.
	if len(ctlSent) > 0 && len(ctlRecv) > 0 {
		switch {
		case median(ctlRecv) == 0:
			e = append(e, fmt.Sprintf("the control channel itself was cut right after the reset: median %d of %d control packets answered", median(ctlRecv), median(ctlSent)))
		case len(recv) > 0 && median(recv) == 0:
			e = append(e, fmt.Sprintf("control channel passed (median %d of %d control packets answered), data channel cut: not one data packet came back", median(ctlRecv), median(ctlSent)))
		case len(firstLoss) > 0 && median(firstLoss) > 0:
			e = append(e, fmt.Sprintf("control channel passed (median %d of %d control packets answered), data channel cut after %d data packets", median(ctlRecv), median(ctlSent), median(firstLoss)))
		default:
			e = append(e, fmt.Sprintf("control channel: median %d of %d control packets answered", median(ctlRecv), median(ctlSent)))
		}
		if len(ctlSeen) > 0 {
			e = append(e, fmt.Sprintf("server saw median %d control packets", median(ctlSeen)))
		}
	} else if len(firstLoss) > 0 && median(firstLoss) > 0 {
		e = append(e, fmt.Sprintf("cut after %d data packets", median(firstLoss)))
	}
	if len(seen) > 0 {
		e = append(e, fmt.Sprintf("server saw median %d data packets: %s", median(seen), directionFrom(c.dominant())))
	}
	return e
}
