package classify

import "fmt"

// Rules 1-3 read nothing but the baselines: the tcp.echo / udp.echo cells.

// ruleEndpoint is rule 1, endpoint-level: every baseline on every port failing.
func (rc *ruleCtx) ruleEndpoint() {
	var baselineFails []Cell
	for _, c := range rc.baselines {
		if c.fail() {
			baselineFails = append(baselineFails, c)
		}
	}
	if len(rc.baselines) > 0 && len(baselineFails) == len(rc.baselines) {
		var e []string
		for _, c := range baselineFails {
			e = append(e, rc.ev(c))
		}
		rc.add("endpoint_blocking_suspected", "all baseline echo tests", "medium", append([]string{"control plane reachable but every TCP and UDP echo failed"}, e...)...)
	}
}

// rulePortOrProxy is rule 2, port blocking: baseline echo fails on a port
// while it passes elsewhere AND nothing else gets through on that port
// either. When a recognised application protocol (HTTP, TLS, DNS) does pass
// on the same port while the opaque echo/random payloads are dropped after
// the server answered them, the port is not blocked: something in the path
// terminates or filters the flow by protocol (a transparent proxy or a
// protocol allow-list), and that is reported instead.
func (rc *ruleCtx) rulePortOrProxy() {
	for _, tr := range []string{"tcp", "udp"} {
		var pass, fail []Cell
		for _, c := range rc.baselines {
			if c.Transport != tr {
				continue
			}
			if c.pass() {
				pass = append(pass, c)
			} else if c.fail() {
				fail = append(fail, c)
			}
		}
		if len(pass) == 0 {
			continue
		}
		for _, f := range fail {
			var passingOther []Cell
			for _, o := range rc.cells {
				if o.Transport == tr && o.Port == f.Port && o.pass() && isAppProtocol(o.TestID) {
					passingOther = append(passingOther, o)
				}
			}
			if len(passingOther) == 0 {
				rc.add("port_blocking_suspected", portKey(tr, f.Port), confidence(f, pass[0]), rc.ev(f), "passing control: "+rc.ev(pass[0]))
				continue
			}
			rc.add("transparent_proxy_suspected", portKey(tr, f.Port), confidence(f, passingOther[0]), rc.proxyEvidence(f, passingOther[0], pass[0])...)
		}
	}
}

// proxyEvidence is the evidence of a port where the echo f fails while the
// application protocol app passes; elsewhere is a passing echo of the transport.
func (rc *ruleCtx) proxyEvidence(f, app, elsewhere Cell) []string {
	e := []string{rc.ev(f), "but on the same port: " + rc.ev(app)}
	if f.ServerSaw > 0 && (f.dominant() == "downlink_drop" || f.dominant() == "downlink_modified") {
		e = append(e, "the server received the opaque payload and answered; the answer never arrived: the path relays only traffic it can parse")
	} else if f.dominant() == "uplink_delayed_past_deadline" {
		e = append(e, "the server received the opaque payload only after the client had given up: the path held the flow instead of relaying it")
	}
	if f.Transport == "tcp" {
		if ms, ok := medianConnect(rc.attempts, f.Port); ok {
			e = append(e, fmt.Sprintf("median connect on this port %.1f ms", ms))
		}
	}
	return append(e, "passing echo elsewhere: "+rc.ev(elsewhere))
}

// ruleUDP is rule 3, UDP blocking: all UDP baselines fail while TCP baselines pass.
func (rc *ruleCtx) ruleUDP() {
	var tcpPass, udpTotal, udpFail int
	for _, c := range rc.baselines {
		if c.Transport == "tcp" && c.pass() {
			tcpPass++
		}
		if c.Transport == "udp" {
			udpTotal++
			if c.fail() {
				udpFail++
			}
		}
	}
	if tcpPass > 0 && udpTotal > 0 && udpFail == udpTotal {
		rc.add("udp_blocking_suspected", "all udp ports", "medium", fmt.Sprintf("%d/%d udp echo cells failed while %d tcp echo cells passed", udpFail, udpTotal, tcpPass))
	}
}
