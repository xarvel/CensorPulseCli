package client

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/model"
)

// Remerge re-applies the merge table to attempts that already carry their
// server observation (a stored report), so that old reports benefit from a
// newer table. skew is the server clock minus the client clock at scan time;
// the burst counts that need the other alpha flows are taken from the detail
// recorded at scan time. The outcomes are brought in line with this build
// first (reinterpret).
func Remerge(attempts []*Attempt, skew time.Duration) {
	for _, a := range attempts {
		reinterpret(a)
		if a.Server != nil {
			markServerDelay(a, a.Server, skew)
		}
		a.Merged = mergeVerdict(a)
	}
}

// reinterpret brings an attempt of an older report in line with what this
// build records from the same raw data, the error text and the detail: a
// failure of the host itself is server_error and marked detail.local_error;
// a DNS disagreement is judged again from the two checks it ran (one that
// did not finish is inconclusive, not poisoning); a TLS handshake the path
// reset carries its reset timing.
func reinterpret(a *Attempt) {
	if a.Outcome == OutcomeOK {
		return
	}
	if name := LocalFailure(a); name != "" && a.Detail["local_error"] == "" {
		a.markLocal(name)
		if a.Outcome != OutcomeInconclusive && a.Outcome != OutcomeSkipped {
			a.Outcome = OutcomeServerError
		}
	}
	// A connect "timeout" that took no time was an unreachable the host's
	// own routing answered at once (older builds read "unreachable" as a
	// timeout): an IPv6 address dialled on a phone without IPv6.
	if a.Outcome == OutcomeConnectTimeout && a.Detail["local_error"] == "" && connectFailedAt(a) < float64(localSyncWithin.Microseconds())/1000 {
		a.markLocal(LocalNoRoute)
		a.Outcome = OutcomeServerError
	}
	if a.TestID == "dest.dns" && a.Outcome == OutcomeDNSMismatch && a.Detail["tamper"] == "system_address_fails" {
		sys, tr := serveResultFrom(a.Detail["verify_system"]), serveResultFrom(a.Detail["verify_trusted"])
		switch judgeDisagreement(sys, tr) {
		case disagreementGeoDNS, disagreementNeitherServes:
			delete(a.Detail, "tamper")
			a.Outcome, a.Error = OutcomeOK, ""
		case disagreementUnverified:
			delete(a.Detail, "tamper")
			a.Detail["note"] = fmt.Sprintf("the check did not finish (system address %s: %s; trusted address: %s): the disagreement is not verified", a.Detail["verify_ip"], sys.why, tr.why)
			a.Outcome, a.Error = OutcomeInconclusive, a.Detail["note"]
		}
	}
	if a.TestID == "dest.tls" && a.Detail["reset_ms"] == "" {
		markResetTiming(a)
	}
}

// connectFailedAt is how long the failed connect of an attempt took, in ms:
// from its first write mark (the dial of dest.tcp) or its start, to its end.
func connectFailedAt(a *Attempt) float64 {
	done, ok := a.Stages["done"]
	if !ok {
		return 1 << 30
	}
	return done - a.Stages["first_write"]
}

// serveResultFrom reads back a check destServes recorded as detail
// (tcp:<outcome>, tls:<outcome>, <proto>:<outcome>, cert:<reason>; <stage>:ok
// when it completed).
func serveResultFrom(why string) serveResult {
	stage, what, _ := strings.Cut(why, ":")
	switch {
	case what == "ok" && stage != "cert":
		return serveResult{handshake: true, chain: "true", why: why}
	case stage == "cert":
		return serveResult{handshake: true, chain: what, why: why}
	}
	return serveResult{why: why, outcome: what}
}

// markServerDelay records how long after the client's first write the server
// first saw the flow, in the client's clock (detail.server_delay_ms). A flow
// that reached the server only after the client had given up was retransmitted
// or held by the path, not answered too late.
func markServerDelay(a *Attempt, o *model.Observation, skew time.Duration) {
	if o.FirstSeenAt.IsZero() || a.StartedAt.IsZero() {
		return
	}
	sent, ok := a.Stages["first_write"]
	if !ok {
		sent = a.Stages["connect"]
	}
	seen := o.FirstSeenAt.Add(-skew)
	delay := float64(seen.Sub(a.StartedAt).Microseconds())/1000 - sent
	if a.Detail == nil {
		a.Detail = map[string]string{}
	}
	a.Detail["server_delay_ms"] = strconv.FormatFloat(delay, 'f', 0, 64)
}

// serverDelayPastDeadline reports whether the server first saw the flow only
// after the client had already given up on it. One second of margin absorbs
// the clock skew estimate.
func serverDelayPastDeadline(a *Attempt) bool {
	delay, err := strconv.ParseFloat(a.Detail["server_delay_ms"], 64)
	if err != nil {
		return false
	}
	done, ok := a.Stages["done"]
	if !ok {
		return false
	}
	return delay > done+1000
}

// serverWaitedForClient reports whether the server's error is the signature of
// a peer that stopped talking (a read timeout or EOF), as opposed to a fault of
// the server's own.
func serverWaitedForClient(o *model.Observation) bool {
	if o == nil {
		return false
	}
	e := o.ServerError
	return strings.Contains(e, "i/o timeout") || strings.HasSuffix(e, "EOF") || strings.Contains(e, "connection reset") || o.Close == "timeout" || o.Close == "client_eof" || o.Close == "client_reset"
}

// isTimeoutErr reports whether an attempt's error text is a deadline rather
// than a protocol failure.
func isTimeoutErr(e string) bool {
	return strings.Contains(e, "deadline exceeded") || strings.Contains(e, "i/o timeout") || strings.Contains(e, "timeout: no recent network activity") || strings.Contains(e, "Handshake did not complete in time")
}

// mergeObservations attaches the matching server observation to each attempt.
// skew is the server clock minus the client clock, used to express when the
// server saw a flow in the client's time.
func mergeObservations(attempts []*Attempt, obs []model.Observation, skew time.Duration) {
	byNonce := map[string]*model.Observation{}
	byAttempt := map[string]*model.Observation{}
	// Post-handshake packets of the session tests: one observation each on
	// UDP (detail.stage=transport for data, =control for the OpenVPN control
	// channel), counted per attempt; on TCP the handshake observation itself
	// carries data_in/data_out (and ctl_in/ctl_out).
	dataSeen := map[string]int{}
	ctlSeen := map[string]int{}
	var dnsObs []*model.Observation
	for i := range obs {
		o := &obs[i]
		if o.Nonce != "" {
			key := o.TestID + "/" + o.Nonce
			// prefer the richer record when both handshake and inner echo exist
			if prev, ok := byNonce[key]; !ok || (prev.Response == "quic_forwarded" && o.Response != "quic_forwarded") {
				byNonce[key] = o
			}
		}
		if o.AttemptID != "" {
			stage := o.Detail["stage"]
			followUp := (stage == "transport" || stage == "control") && o.Transport == "udp"
			if followUp {
				if o.Detail["auth"] != "failed" && o.Detail["parse"] != "bad_control" && o.Detail["mac"] != "invalid" {
					if stage == "control" {
						ctlSeen[o.AttemptID]++
					} else {
						dataSeen[o.AttemptID]++
					}
				}
			} else if prev, ok := byAttempt[o.AttemptID]; !ok || prev.Response == "quic_forwarded" || (prev.Parse == model.ParseEmpty && o.Parse != model.ParseEmpty) {
				// An empty flow attributed to a reservation gives way to the
				// flow that carried the reserved handshake.
				byAttempt[o.AttemptID] = o
			}
		}
		if o.Parse == model.ParseDNS {
			dnsObs = append(dnsObs, o)
		}
	}
	// attach finds the attempt's observation: by nonce, by reservation, by
	// DNS query name, then by 5-tuple.
	attach := func(a *Attempt) {
		if a.Nonce != "" {
			if o, ok := byNonce[a.TestID+"/"+a.Nonce]; ok {
				a.Server = o
				markServerDelay(a, o, skew)
				return
			}
		}
		if a.AttemptID != "" {
			if o, ok := byAttempt[a.AttemptID]; ok {
				a.Server = o
				markServerDelay(a, o, skew)
				if handshakeTestOf(a.TestID) != "" {
					n := dataSeen[a.AttemptID]
					if v, err := strconv.Atoi(o.Detail["data_in"]); err == nil && o.Transport == "tcp" {
						n = v
					}
					a.Detail["server_data_seen"] = strconv.Itoa(n)
					if a.Detail["ctl_sent"] != "" {
						m := ctlSeen[a.AttemptID]
						if v, err := strconv.Atoi(o.Detail["ctl_in"]); err == nil && o.Transport == "tcp" {
							m = v
						}
						a.Detail["server_ctl_seen"] = strconv.Itoa(m)
					}
				}
				return
			}
		}
		if strings.HasPrefix(a.TestID, "dns.") && a.Nonce != "" {
			for _, o := range dnsObs {
				if strings.HasPrefix(o.Detail["qname"], a.Nonce+".") {
					a.Server = o
					markServerDelay(a, o, skew)
					break
				}
			}
			return
		}
		// Last resort for TCP flows the server could only partly parse (an
		// envelope cut before its nonce): the 5-tuple within this session.
		if a.Transport == "tcp" && a.SrcPort != 0 {
			for i := range obs {
				o := &obs[i]
				if o.Transport == "tcp" && o.DstPort == a.DstPort && o.SrcPort == a.SrcPort && o.TestID == a.TestID && o.Detail["partial"] == "true" {
					a.Server = o
					markServerDelay(a, o, skew)
					break
				}
			}
		}
	}
	for _, a := range attempts {
		switch a.TestID {
		case "tls.burst":
			// How many of the parallel ClientHellos reached the server, and
			// how many were answered with a ServerHello.
			ids := map[string]bool{}
			for _, id := range strings.Split(a.Detail["reservation_ids"], ",") {
				if id != "" {
					ids[id] = true
				}
			}
			nonces := map[string]bool{}
			for _, n := range strings.Split(a.Detail["alpha_nonces"], ",") {
				if n != "" {
					nonces[n] = true
				}
			}
			// seen: flows that reached the server; answered: the server sent
			// bytes back (a ServerHello went out even when the handshake
			// never finished because the client's answer got lost); hello:
			// handshakes that completed; partial: the server got some bytes
			// and then waited in vain for the rest of the ClientHello.
			seen, answered, hello, partial := 0, 0, 0, 0
			for i := range obs {
				o := &obs[i]
				if (o.AttemptID != "" && ids[o.AttemptID]) || (o.TestID == a.TestID && o.Nonce != "" && nonces[o.Nonce]) {
					seen++
					if o.BytesOut > 0 || strings.HasPrefix(o.Response, "server_hello") {
						answered++
					}
					if strings.HasPrefix(o.Response, "server_hello") {
						hello++
					}
					if o.BytesOut == 0 && o.Response == "handshake_failed" && serverWaitedForClient(o) {
						partial++
					}
				}
			}
			a.Detail["server_alpha_seen"] = strconv.Itoa(seen)
			a.Detail["server_alpha_answered"] = strconv.Itoa(answered)
			a.Detail["server_alpha_hello"] = strconv.Itoa(hello)
			a.Detail["server_alpha_partial"] = strconv.Itoa(partial)
		case "udp.packets":
			// One observation per datagram, each with its own nonce. The
			// source port cannot be the key: behind NAT (every mobile
			// network) the server sees the translated one.
			seen := 0
			for _, n := range a.nonces {
				if _, ok := byNonce[a.TestID+"/"+n]; ok {
					seen++
				}
			}
			a.Detail["server_packets_seen"] = strconv.Itoa(seen)
		}
		attach(a)
		if a.TestID == "tcp.packets" && a.Server != nil {
			// packets_sent counts writes the kernel accepted; the cut position
			// is what the server received before the flow stalled. It comes
			// from the attached observation, so it is read after attach.
			if pb, err := strconv.Atoi(a.Server.Detail["partial_bytes"]); err == nil {
				if cb, err := strconv.Atoi(a.Detail["chunk_bytes"]); err == nil && cb > 0 {
					a.Detail["server_packets_seen"] = strconv.Itoa((pb + cb - 1) / cb)
				}
			}
		}
	}
}

// mergeVerdict applies the CLASSIFICATION.md merge table.
func mergeVerdict(a *Attempt) string {
	if IsDestTest(a.TestID) {
		// No server half: the merged result is the client outcome itself.
		return a.Outcome
	}
	s := a.Server
	seen := s != nil
	// A reply is anything the server sent back: RepliedAt is set by the
	// handlers that finished an exchange, but a ServerHello that went out
	// before the client's answer got lost is a reply too (the handler then
	// records handshake_failed with a read error, not a reply time).
	replied := seen && (s.RepliedAt != nil || s.BytesOut > 0)
	switch a.Outcome {
	case OutcomeOK:
		if seen && s.Detail["mac"] == "invalid" {
			return "uplink_modified"
		}
		return "ok"
	case OutcomeConnectTimeout, OutcomePayloadTimeout, OutcomeDNSTimeout, OutcomeQUICNoResponse:
		switch {
		case !seen:
			return "uplink_drop_or_route_failure"
		case a.Outcome == OutcomeConnectTimeout && a.Transport == "tcp":
			// We never completed the handshake, yet a connection from our
			// address was accepted in this reservation window and carried
			// nothing. The server cannot be blamed for silence on a
			// connection we never had: either a middlebox completed the
			// handshake upstream while its SYN-ACK to us was lost, or the
			// empty flow is another attempt's (reservations carry no source
			// port behind NAT).
			return "connect_diverged_middlebox_or_misattributed"
		case s.Detail["cookie"] == "invalid":
			return "cookie_mismatch_nat_or_multipath"
		case s.Detail["mac"] == "invalid":
			return "uplink_modified"
		case serverDelayPastDeadline(a):
			// The server saw the payload only after the client had given up:
			// the first transmissions were lost and a retransmission got
			// through, or the path held the flow. Nothing was dropped on
			// the way back; the request was late.
			return "uplink_delayed_past_deadline"
		case replied:
			return "downlink_drop"
		case a.Transport == "tcp" && s.BytesIn == 0 && s.Parse == model.ParseEmpty:
			// The connection was accepted and not one byte of the request
			// arrived before the server gave up: the SYN got through, the
			// payload did not. (Behind NAT the empty flow could be another
			// attempt's; the reservation window makes that unlikely.)
			return "uplink_drop_or_route_failure"
		case s.ServerError != "" && serverWaitedForClient(s):
			// The server got part of the request and timed out waiting for
			// the rest: cut on the way in, not a fault of the server.
			return "uplink_drop_or_route_failure"
		case s.ServerError != "":
			return "server_error"
		case s.Response == "silence" || s.Response == "refused" || s.Response == "":
			return "server_silent"
		default:
			return "downlink_drop"
		}
	case OutcomeConnectReset, OutcomeMidstreamReset:
		if seen && s.Close == "client_reset" {
			return "rst_injected_bidirectional"
		}
		return "rst_injected_or_path_reset"
	case OutcomeMidstreamEOF:
		if !seen {
			return "path_closed_before_server"
		}
		if s.Close == "client_reset" {
			return "rst_injected_or_path_reset" // the server got a RST it did not send while we got a FIN
		}
		return "server_closed"
	case OutcomeConnectRefused:
		if seen {
			return "refused_after_server_saw_it"
		}
		return "refused_by_path_or_port_closed"
	case OutcomeTLSSpoof:
		if !seen {
			return "injected"
		}
		if s.Response == "handshake_failed" {
			return "server_rejected_handshake"
		}
		return "downlink_modified"
	case OutcomeSessionCut:
		// The handshake was answered (we would not be here otherwise); what
		// matters is whether the data packets reached the server.
		if !seen {
			return "uplink_drop_after_handshake"
		}
		sent, _ := strconv.Atoi(a.Detail["data_sent"])
		saw, _ := strconv.Atoi(a.Detail["server_data_seen"])
		if sent == 0 && a.Detail["ctl_sent"] != "" {
			// Cut in the OpenVPN control channel, before any data went out:
			// the control packets are what the server did or did not see.
			sent, _ = strconv.Atoi(a.Detail["ctl_sent"])
			saw, _ = strconv.Atoi(a.Detail["server_ctl_seen"])
		}
		if saw < sent {
			return "uplink_drop_after_handshake"
		}
		return "downlink_drop_after_handshake"
	case OutcomePacketsCut:
		if !seen {
			return "uplink_drop_or_route_failure"
		}
		if a.Transport == "udp" {
			sent, _ := strconv.Atoi(a.Detail["packets_sent"])
			saw, _ := strconv.Atoi(a.Detail["server_packets_seen"])
			if saw < sent {
				return "uplink_drop_or_route_failure"
			}
			return "downlink_drop"
		}
		// TCP: what matters is whether the whole envelope arrived and was
		// echoed, not whether a ServerHello went out before the cut.
		if s.Detail["partial"] == "true" {
			return "uplink_drop_or_route_failure"
		}
		if strings.Contains(s.Response, "echo") {
			return "downlink_drop"
		}
		return "uplink_drop_or_route_failure"
	case OutcomeBurstFreeze:
		n, _ := strconv.Atoi(a.Detail["burst_n"])
		saw, _ := strconv.Atoi(a.Detail["server_alpha_seen"])
		hello, _ := strconv.Atoi(a.Detail["server_alpha_hello"])
		answered, err := strconv.Atoi(a.Detail["server_alpha_answered"])
		partial, perr := strconv.Atoi(a.Detail["server_alpha_partial"])
		if err != nil || perr != nil {
			// Reports written before these counts existed carry only the
			// first alpha flow's observation: read what it says.
			answered = hello
			if seen && s.BytesOut > 0 {
				answered = max(answered, 1)
			}
			if seen && s.BytesOut == 0 && s.Response == "handshake_failed" && serverWaitedForClient(s) {
				partial = saw
			}
		}
		switch {
		case saw < n:
			return "uplink_drop_or_route_failure"
		case answered > 0:
			// The server sent a ServerHello to at least one of them and none
			// of the parallel handshakes got it. What the server did not
			// answer it never received in full.
			return "downlink_drop"
		case partial == saw:
			// Every ClientHello arrived cut: a two-segment hello whose second
			// segment never came.
			return "uplink_drop_or_route_failure"
		default:
			return "server_rejected_handshake"
		}
	case OutcomeBulkStall, OutcomeBulkReset:
		if !seen {
			return "uplink_drop_or_route_failure"
		}
		if a.Outcome == OutcomeBulkReset && s.Close == "client_reset" {
			return "rst_injected_bidirectional"
		}
		if a.Outcome == OutcomeBulkReset {
			return "rst_injected_or_path_reset"
		}
		if s.Detail["bulk"] == "down" {
			return "downlink_drop"
		}
		// Upload: the server counts what it received. Everything the client
		// sent arrived and the acknowledgement was lost → downlink.
		sent, _ := strconv.Atoi(a.Detail["bulk_bytes"])
		got, _ := strconv.Atoi(s.Detail["bulk_up_bytes"])
		if sent > 0 && got >= sent {
			return "downlink_drop"
		}
		return "uplink_drop_or_route_failure"
	case OutcomeTLSAlert, OutcomeTLSParse, OutcomeQUICHandshake:
		if a.Outcome == OutcomeQUICHandshake && isTimeoutErr(a.Error) {
			// The handshake ran out of time rather than failing: nothing
			// was modified. The QUIC forwarder only records what came in,
			// so which direction lost the later packets is unknown.
			if !seen {
				return "uplink_drop_or_route_failure"
			}
			return "stalled_after_server_saw_it"
		}
		if !seen {
			return "injected"
		}
		if s.Response == "handshake_failed" {
			if want, got := a.Detail["sni"], s.Detail["sni"]; want != got {
				return "uplink_modified"
			}
			return "server_rejected_handshake"
		}
		return "downlink_modified"
	case OutcomeUnexpected, OutcomeModified, OutcomeDNSMismatch, OutcomeDNSRcode, "dns_injected_race":
		if !seen {
			return "injected"
		}
		if s.Detail["mac"] == "invalid" {
			return "uplink_modified"
		}
		if replied {
			return "downlink_modified"
		}
		return "injected"
	case OutcomeCertMismatch:
		return "tls_mitm_or_wrong_server"
	case OutcomeServerError:
		return "server_error"
	}
	return "inconclusive"
}
