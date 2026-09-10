package classify

import (
	"fmt"
	"sort"

	"github.com/xarvel/CensorPulseCli/internal/client"
)

// modificationMerges are the merge results that say the path changed or
// forged traffic, as opposed to dropping it.
var modificationMerges = map[string]bool{"uplink_modified": true, "downlink_modified": true, "injected": true, "rst_injected_or_path_reset": true, "rst_injected_bidirectional": true, "tls_mitm_or_wrong_server": true}

// ruleModification is rule 7: modification / injection anywhere. Cells that
// a differential verdict of rules 1-6 already names get the mechanism
// attached to that verdict instead of a second finding; the rest are
// reported on their own, never above medium, since there is no control to
// compare with.
func (rc *ruleCtx) ruleModification() {
	// With two verdicts on one subject the later one is kept: see run.
	named := map[string]int{}
	for i, v := range rc.verdicts {
		named[v.Subject] = i
	}
	for _, c := range rc.cells {
		if c.TestID == "tcp.bulk" || c.TestID == "tcp.packets" || c.TestID == "udp.packets" || c.TestID == "tls.burst" || handshakeTestOf(c.TestID) != "" {
			continue // reported by rules 5b-5c with the byte offset / packet counts
		}
		// Sorted: the findings and their evidence must not follow map order,
		// or the same attempts classify to a differently ordered report.
		kinds := make([]string, 0, len(c.Merged))
		for merged := range c.Merged {
			kinds = append(kinds, merged)
		}
		sort.Strings(kinds)
		for _, merged := range kinds {
			n := c.Merged[merged]
			if n == 0 || !modificationMerges[merged] {
				continue
			}
			if i, ok := named[c.Key()]; ok {
				rc.verdicts[i].Evidence = append(rc.verdicts[i].Evidence, fmt.Sprintf("mechanism: %d/%d attempts merged as %s", n, c.Total, merged))
				continue
			}
			conf := "low"
			if n >= mediumMinAttempts {
				conf = "medium"
			}
			rc.add(merged, c.Key(), conf, fmt.Sprintf("%d/%d attempts classified %s; no differential control for this cell", n, c.Total, merged))
		}
	}
}

// ruleSynAck is rule 8, SYN-ACK timing. Two independent signals: tcp.rtt
// (connect vs payload round trip on one port) and the cross-port
// differential (a port whose TCP connect completes in a fraction of the time
// every other port needs is being answered by something closer than the
// server). Either alone is low confidence; together they are medium.
func (rc *ruleCtx) ruleSynAck() {
	rttSuspect := map[int]string{}
	for _, a := range rc.attempts {
		if a.TestID == "tcp.rtt" && a.Detail["synack_suspect"] == "true" {
			rttSuspect[a.DstPort] = fmt.Sprintf("tcp.rtt on %s: connect %s ms vs payload %s ms (ratio %s)", portKey("tcp", a.DstPort), a.Detail["connect_min_ms"], a.Detail["payload_min_ms"], a.Detail["connect_payload_ratio"])
		}
	}
	fast, ref := fastConnectPorts(rc.attempts)
	reported := map[int]bool{}
	// A transparent proxy found on the same port by rule 2 is the same
	// middlebox seen from the other side: the two findings corroborate.
	proxied := map[string]bool{}
	for _, v := range rc.verdicts {
		if v.Kind == "transparent_proxy_suspected" {
			proxied[v.Subject] = true
		}
	}
	for _, port := range fast.ports {
		subject := portKey("tcp", port)
		e := []string{fmt.Sprintf("median connect on %s is %.1f ms; on the other TCP ports %.1f ms (ratio %.2f)", subject, fast.median[port], ref, fast.median[port]/ref)}
		conf := "low"
		if s, ok := rttSuspect[port]; ok {
			e = append(e, s)
			conf = "medium"
		}
		if proxied[subject] {
			e = append(e, "transparent_proxy_suspected on the same port: the opaque payloads that the proxy cannot parse are the ones that never come back")
			conf = "medium"
		}
		e = append(e, "a SYN-ACK from a middlebox: transparent proxy / split-TCP; pcap with TTL would confirm")
		rc.add("synack_local_termination_suspected", subject, conf, e...)
		reported[port] = true
	}
	// Map order: one verdict per port, the final sort orders them.
	for port, s := range rttSuspect {
		if !reported[port] {
			rc.add("synack_spoof_signal", portKey("tcp", port), "low", s+"; no cross-port confirmation; needs pcap/TTL")
		}
	}
}

// The cross-port SYN-ACK differential.
const (
	// connectMinSamples is how many successful dials a port needs before its
	// median connect time means anything.
	connectMinSamples = 2
	// fastConnectMinPorts is how many TCP ports with a median the reference
	// needs: with two there is no telling which one is the odd one.
	fastConnectMinPorts = 3
	// fastConnectMinRefMs is the smallest reference (the median across the
	// ports) the rule works on, so that a LAN or loopback path never triggers it.
	fastConnectMinRefMs = 20
	// fastConnectRatio: a port is fast when its median connect is under this
	// fraction of the reference ...
	fastConnectRatio = 0.25
	// fastConnectMinGapMs: ... and this much faster in absolute terms, which
	// keeps jitter on a short path out.
	fastConnectMinGapMs = 20
)

// medianConnect is the median TCP connect duration on one port over every
// successful dial.
func medianConnect(attempts []*client.Attempt, port int) (float64, bool) {
	var v []float64
	for _, a := range attempts {
		if a.Transport == "tcp" && a.DstPort == port && a.TestID != "tcp.rtt" {
			if ms, ok := a.Stages["connect"]; ok && ms > 0 {
				v = append(v, ms)
			}
		}
	}
	if len(v) < connectMinSamples {
		return 0, false
	}
	return medianF(v), true
}

type fastPorts struct {
	ports  []int
	median map[int]float64
}

// fastConnectPorts finds TCP ports whose median connect time is a small
// fraction of the median across the other ports. The second result is that
// reference.
func fastConnectPorts(attempts []*client.Attempt) (fastPorts, float64) {
	out := fastPorts{median: map[int]float64{}}
	ports := map[int]bool{}
	for _, a := range attempts {
		if a.Transport == "tcp" {
			ports[a.DstPort] = true
		}
	}
	for p := range ports {
		if m, ok := medianConnect(attempts, p); ok {
			out.median[p] = m
		}
	}
	if len(out.median) < fastConnectMinPorts {
		return fastPorts{}, 0
	}
	all := make([]float64, 0, len(out.median))
	for _, m := range out.median {
		all = append(all, m)
	}
	ref := medianF(all)
	if ref < fastConnectMinRefMs {
		return fastPorts{}, ref
	}
	for p, m := range out.median {
		if m < ref*fastConnectRatio && ref-m > fastConnectMinGapMs {
			out.ports = append(out.ports, p)
		}
	}
	sort.Ints(out.ports)
	return out, ref
}
