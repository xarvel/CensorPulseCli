// Package classify derives differential verdicts from a set of attempts, as
// specified in specs/CLASSIFICATION.md. It never looks at a single failure in
// isolation: every verdict names the control that passed.
package classify

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/client"
)

// Verdict is one differential finding.
type Verdict struct {
	Kind       string   `json:"kind"`       // e.g. protocol_blocking_suspected
	Subject    string   `json:"subject"`    // test/port/variant the finding is about
	Confidence string   `json:"confidence"` // high|medium|low
	Evidence   []string `json:"evidence"`
}

// Cell aggregates attempts that share (test, transport, port, variant).
type Cell struct {
	TestID    string         `json:"test_id"`
	Transport string         `json:"transport"`
	Port      int            `json:"port"`
	Variant   string         `json:"variant"`
	Role      string         `json:"role"`
	Total     int            `json:"total"`
	OK        int            `json:"ok"`
	Outcomes  map[string]int `json:"outcomes"`
	Merged    map[string]int `json:"merged"`
	ServerSaw int            `json:"server_saw"`
}

// Key returns the stable identifier of a cell.
func (c Cell) Key() string {
	return fmt.Sprintf("%s %s/%d %s", c.TestID, c.Transport, c.Port, c.Variant)
}

func (c Cell) pass() bool { return c.Total > 0 && c.OK*2 > c.Total } // majority ok
func (c Cell) fail() bool { return c.Total > 0 && c.OK == 0 }
func (c Cell) dominant() string {
	best, n := "", -1
	for k, v := range c.Merged {
		if v > n || (v == n && k < best) {
			best, n = k, v
		}
	}
	return best
}

// Result is the classifier output.
type Result struct {
	Cells        []Cell        `json:"cells"`
	Verdicts     []Verdict     `json:"verdicts"`
	Summary      string        `json:"summary"`
	Notes        []string      `json:"notes,omitempty"`        // observations about the scan itself, not findings
	Destinations []Destination `json:"destinations,omitempty"` // per-site summary of the dest.* family
}

// Aggregate builds cells from attempts. Attempts flagged as part of a
// transient outage (detail.transient) are left out: they say nothing about
// the path's policy.
func Aggregate(attempts []*client.Attempt) []Cell {
	m := map[string]*Cell{}
	for _, a := range attempts {
		if a.Detail["transient"] == "true" {
			continue
		}
		k := fmt.Sprintf("%s|%s|%d|%s", a.TestID, a.Transport, a.DstPort, a.Variant)
		c, ok := m[k]
		if !ok {
			c = &Cell{TestID: a.TestID, Transport: a.Transport, Port: a.DstPort, Variant: a.Variant, Role: a.Role, Outcomes: map[string]int{}, Merged: map[string]int{}}
			m[k] = c
		}
		c.Total++
		if a.Outcome == client.OutcomeOK {
			c.OK++
		}
		c.Outcomes[a.Outcome]++
		c.Merged[a.Merged]++
		if a.Server != nil {
			c.ServerSaw++
		}
	}
	out := make([]Cell, 0, len(m))
	for _, c := range m {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

func confidence(failed, passed Cell) string {
	if failed.Total >= 3 && failed.OK == 0 && passed.Total >= 3 && passed.OK == passed.Total {
		return "high"
	}
	if failed.Total >= 2 && failed.OK*3 <= failed.Total && passed.pass() {
		return "medium"
	}
	return "low"
}

// handshakeTestOf maps a *.session test to its handshake-only control.
func handshakeTestOf(test string) string {
	switch test {
	case "wireguard.session":
		return "wireguard.init"
	case "openvpn.session":
		return "openvpn.reset"
	case "ikev2.session":
		return "ikev2.init"
	case "l2tp.session":
		return "l2tp.init"
	case "socks5.session":
		return "socks5.connect"
	case "vless.session":
		return "vless.reality"
	case "tor.link":
		return "tor.handshake"
	case "obfs4.session":
		return "obfs4.handshake"
	}
	return ""
}

// handshakeVariantOf maps a session variant to the handshake variant of the
// same signature by stripping the "+data" and "+control" suffixes.
func handshakeVariantOf(variant string) string {
	v := strings.TrimSuffix(variant, "+data")
	return strings.TrimSuffix(v, "+control")
}

func median(v []int) int {
	if len(v) == 0 {
		return 0
	}
	s := append([]int(nil), v...)
	sort.Ints(s)
	return s[len(s)/2]
}

func medianF(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	return s[len(s)/2]
}

// isAppProtocol reports whether a test family exercises a recognised
// application protocol a transparent proxy could relay (as opposed to
// opaque payloads, timing probes or long flows).
func isAppProtocol(test string) bool {
	return strings.HasPrefix(test, "http.") || strings.HasPrefix(test, "tls.") || strings.HasPrefix(test, "dns.") || test == "tor.dir"
}

func directionFrom(merged string) string {
	switch merged {
	case "uplink_drop_after_handshake", "uplink_drop_or_route_failure":
		return "data stopped on the way to the server"
	case "downlink_drop_after_handshake", "downlink_drop":
		return "the server answered every packet it saw; the answers were dropped on the way back"
	case "uplink_delayed_past_deadline":
		return "the server saw the data only after the client had given up: lost first, retransmitted later"
	case "stalled_after_server_saw_it":
		return "the server saw the first packet; which direction lost the rest is unknown"
	case "connect_diverged_middlebox_or_misattributed":
		return "the client never completed the TCP handshake, yet an empty connection from its address was accepted"
	}
	return merged
}

// natDetected reports whether the server saw the client's flows from a
// different source port than the client bound: a NAT (or proxy) rewrites
// them. The first example is returned for the evidence line.
func natDetected(attempts []*client.Attempt) (bool, string) {
	for _, a := range attempts {
		if a.Server != nil && a.SrcPort != 0 && a.Server.SrcPort != 0 && a.SrcPort != a.Server.SrcPort {
			return true, fmt.Sprintf("the client is behind NAT (source port %d left the client, the server saw %d)", a.SrcPort, a.Server.SrcPort)
		}
	}
	return false, ""
}

// transientWindow is the minimum evidence for a passing outage: this many
// failures, on this many ports, inside transientSpan, in cells that pass in
// the other rounds.
const (
	transientSpan  = 20 * time.Second
	transientMin   = 6
	transientPorts = 3
)

// flagTransient looks for a burst of failures across unrelated ports and
// families whose cells pass in the other rounds: a radio drop, a route flap,
// a NAT rebind. Those attempts are flagged detail.transient=true so that the
// cells are built without them, and a note describes the window. Failures in
// cells that fail consistently are never flagged: an outage does not excuse
// a rule that fires every time.
func flagTransient(attempts []*client.Attempt) []string {
	cells := Aggregate(attempts)
	passing := map[string]bool{}
	for _, c := range cells {
		if c.pass() {
			passing[c.Key()] = true
		}
	}
	var cand []*client.Attempt
	for _, a := range attempts {
		if a.Merged == "ok" || a.Outcome == client.OutcomeOK || a.Outcome == client.OutcomeInconclusive || a.Outcome == client.OutcomeServerError || a.StartedAt.IsZero() {
			continue
		}
		if passing[fmt.Sprintf("%s %s/%d %s", a.TestID, a.Transport, a.DstPort, a.Variant)] {
			cand = append(cand, a)
		}
	}
	sort.SliceStable(cand, func(i, j int) bool { return cand[i].StartedAt.Before(cand[j].StartedAt) })
	var notes []string
	flagged := map[*client.Attempt]bool{}
	for i := 0; i < len(cand); {
		// The widest window starting at cand[i].
		j := i
		for j+1 < len(cand) && cand[j+1].StartedAt.Sub(cand[i].StartedAt) <= transientSpan {
			j++
		}
		win := cand[i : j+1]
		ports, tests := map[string]bool{}, map[string]bool{}
		for _, a := range win {
			ports[fmt.Sprintf("%s/%d", a.Transport, a.DstPort)] = true
			tests[a.TestID] = true
		}
		if len(win) < transientMin || len(ports) < transientPorts {
			i++
			continue
		}
		var t0 time.Time
		for _, a := range attempts {
			if t0.IsZero() || (!a.StartedAt.IsZero() && a.StartedAt.Before(t0)) {
				t0 = a.StartedAt
			}
		}
		rounds := map[int]bool{}
		for _, a := range win {
			if a.Detail == nil {
				a.Detail = map[string]string{}
			}
			a.Detail["transient"] = "true"
			flagged[a] = true
			rounds[a.Round] = true
		}
		var rs []string
		for r := range rounds {
			rs = append(rs, strconv.Itoa(r))
		}
		sort.Strings(rs)
		notes = append(notes, fmt.Sprintf("transient outage: %d attempts on %d ports (%d test families) failed between +%.0fs and +%.0fs of the scan (round %s) while the same cells passed in the other rounds; they are flagged detail.transient=true and left out of the cells",
			len(win), len(ports), len(tests), win[0].StartedAt.Sub(t0).Seconds(), win[len(win)-1].StartedAt.Sub(t0).Seconds(), strings.Join(rs, ",")))
		i = j + 1
	}
	return notes
}

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
	if len(v) < 2 {
		return 0, false
	}
	return medianF(v), true
}

type fastPorts struct {
	ports  []int
	median map[int]float64
}

// fastConnectPorts finds TCP ports whose median connect time is a small
// fraction of the median across the other ports. The reference must be at
// least 20 ms so that a LAN or loopback path never triggers it.
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
	if len(out.median) < 3 {
		return fastPorts{}, 0
	}
	all := make([]float64, 0, len(out.median))
	for _, m := range out.median {
		all = append(all, m)
	}
	ref := medianF(all)
	if ref < 20 {
		return fastPorts{}, ref
	}
	for p, m := range out.median {
		if m < ref*0.25 && ref-m > 20 {
			out.ports = append(out.ports, p)
		}
	}
	sort.Ints(out.ports)
	return out, ref
}

// Classify derives verdicts.
func Classify(attempts []*client.Attempt, probeReachable bool) Result {
	return classify(attempts, probeReachable, false)
}

// ClassifyStandalone classifies a scan that had no server: the dest.* family
// alone. There is no control plane to be unreachable.
func ClassifyStandalone(attempts []*client.Attempt) Result {
	return classify(attempts, true, true)
}

func classify(attempts []*client.Attempt, probeReachable, standalone bool) Result {
	notes := flagTransient(attempts)
	cells := Aggregate(attempts)
	res := Result{Cells: cells, Notes: notes}
	if !probeReachable && !standalone {
		res.Verdicts = append(res.Verdicts, Verdict{Kind: "probe_unreachable", Subject: "control plane", Confidence: "high",
			Evidence: []string{"control API on the pinned TLS port did not answer; no protocol-level conclusion is possible"}})
		res.Summary = "probe_unreachable"
		return res
	}
	find := func(test, transport string, port int, variant string) (Cell, bool) {
		for _, c := range cells {
			if c.TestID == test && c.Transport == transport && c.Port == port && (variant == "" || c.Variant == variant) {
				return c, true
			}
		}
		return Cell{}, false
	}
	// handshakeCell finds the handshake-only control of a session cell: the
	// handshake variant of the same signature (a session variant is the
	// handshake variant plus "+control" / "+data": noise-ik+data ↔ noise-ik,
	// udp+tls-auth+data ↔ udp+tls-auth, udp+control+data ↔ udp), else the
	// same variant name, else any variant.
	handshakeCell := func(c Cell) (Cell, bool) {
		hs := handshakeTestOf(c.TestID)
		if hs == "" {
			return Cell{}, false
		}
		if h, ok := find(hs, c.Transport, c.Port, handshakeVariantOf(c.Variant)); ok {
			return h, true
		}
		if h, ok := find(hs, c.Transport, c.Port, c.Variant); ok {
			return h, true
		}
		return find(hs, c.Transport, c.Port, "")
	}
	byTest := map[string][]Cell{}
	for _, c := range cells {
		byTest[c.TestID] = append(byTest[c.TestID], c)
	}
	add := func(kind, subject, conf string, ev ...string) {
		res.Verdicts = append(res.Verdicts, Verdict{Kind: kind, Subject: subject, Confidence: conf, Evidence: ev})
	}
	ev := func(c Cell) string {
		return fmt.Sprintf("%s: %d/%d ok, dominant=%s, server_saw=%d", c.Key(), c.OK, c.Total, c.dominant(), c.ServerSaw)
	}

	// 1. Endpoint-level: every baseline on every port failing.
	var baselines, baselineFails []Cell
	for _, c := range cells {
		if c.TestID == "tcp.echo" || c.TestID == "udp.echo" {
			baselines = append(baselines, c)
			if c.fail() {
				baselineFails = append(baselineFails, c)
			}
		}
	}
	if len(baselines) > 0 && len(baselineFails) == len(baselines) {
		var e []string
		for _, c := range baselineFails {
			e = append(e, ev(c))
		}
		add("endpoint_blocking_suspected", "all baseline echo tests", "medium", append([]string{"control plane reachable but every TCP and UDP echo failed"}, e...)...)
	}

	// 2. Port blocking: baseline echo fails on a port while it passes
	// elsewhere AND nothing else gets through on that port either. When a
	// recognised application protocol (HTTP, TLS, DNS) does pass on the same
	// port while the opaque echo/random payloads are dropped after the server
	// answered them, the port is not blocked: something in the path
	// terminates or filters the flow by protocol (a transparent proxy or a
	// protocol allow-list), and that is reported instead.
	for _, tr := range []string{"tcp", "udp"} {
		var pass, fail []Cell
		for _, c := range baselines {
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
			for _, o := range cells {
				if o.Transport == tr && o.Port == f.Port && o.pass() && isAppProtocol(o.TestID) {
					passingOther = append(passingOther, o)
				}
			}
			if len(passingOther) == 0 {
				add("port_blocking_suspected", fmt.Sprintf("%s/%d", tr, f.Port), confidence(f, pass[0]), ev(f), "passing control: "+ev(pass[0]))
				continue
			}
			e := []string{ev(f), "but on the same port: " + ev(passingOther[0])}
			if f.ServerSaw > 0 && (f.dominant() == "downlink_drop" || f.dominant() == "downlink_modified") {
				e = append(e, "the server received the opaque payload and answered; the answer never arrived: the path relays only traffic it can parse")
			} else if f.dominant() == "uplink_delayed_past_deadline" {
				e = append(e, "the server received the opaque payload only after the client had given up: the path held the flow instead of relaying it")
			}
			if f.Transport == "tcp" {
				if ms, ok := medianConnect(attempts, f.Port); ok {
					e = append(e, fmt.Sprintf("median connect on this port %.1f ms", ms))
				}
			}
			e = append(e, "passing echo elsewhere: "+ev(pass[0]))
			add("transparent_proxy_suspected", fmt.Sprintf("%s/%d", tr, f.Port), confidence(f, passingOther[0]), e...)
		}
	}

	// 3. UDP blocking: all UDP baselines fail while TCP baselines pass.
	var tcpPass, udpTotal, udpFail int
	for _, c := range baselines {
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
		add("udp_blocking_suspected", "all udp ports", "medium", fmt.Sprintf("%d/%d udp echo cells failed while %d tcp echo cells passed", udpFail, udpTotal, tcpPass))
	}

	// 4. Protocol blocking: native handshake fails while echo + random pass on the same port.
	native := map[string]bool{"tcp.bulk": true, "openvpn.reset": true, "wireguard.init": true, "openvpn.session": true, "wireguard.session": true, "ikev2.init": true, "ikev2.session": true, "l2tp.init": true, "l2tp.session": true, "socks5.connect": true, "socks5.session": true, "vless.reality": true, "vless.session": true, "quic.v1": true, "tls.sni": true, "tls.version": true, "tls.alpn": true, "tls.fingerprint": true, "http.host": true, "dns.udp": true, "dns.tcp": true, "dns.dot": true,
		"tor.handshake": true, "tor.link": true, "tor.dir": true, "obfs4.handshake": true, "obfs4.session": true, "dtls.hello": true, "stun.binding": true}
	reportedFamily := map[string]bool{}
	for _, c := range cells {
		if !native[c.TestID] || !c.fail() {
			continue
		}
		if init, ok := handshakeCell(c); ok {
			if init.pass() {
				continue // handshake passes, data does not: rule 5c reports it
			}
			if init.fail() {
				continue // the handshake's own verdict covers the session
			}
		}
		famKey := fmt.Sprintf("%s %s/%d", c.TestID, c.Transport, c.Port)
		if reportedFamily[famKey] {
			continue
		}
		echoTest, randTest := "tcp.echo", "tcp.payload.random"
		if c.Transport == "udp" {
			echoTest, randTest = "udp.echo", "udp.payload.random"
		}
		echo, okE := find(echoTest, c.Transport, c.Port, "")
		rnd, okR := find(randTest, c.Transport, c.Port, "")
		if okE && echo.pass() && okR && rnd.fail() && c.Role != client.RoleControl {
			add("control_failed_inconclusive", c.Key(), "low", ev(c), "random-payload control also failed on this port: "+ev(rnd), "echo passed: "+ev(echo))
			continue
		}
		if okE && echo.pass() && (!okR || rnd.pass()) {
			// Only call it protocol blocking when the whole test family on
			// this port fails; per-variant failures are handled below.
			famFail := true
			for _, o := range byTest[c.TestID] {
				if o.Port == c.Port && o.Transport == c.Transport && !o.fail() {
					famFail = false
				}
			}
			if famFail && c.Role != client.RoleControl {
				e := []string{ev(c), "passing echo control: " + ev(echo)}
				if okR {
					e = append(e, "passing random control: "+ev(rnd))
				}
				conf := confidence(c, echo)
				if strings.HasPrefix(c.TestID, "ikev2.") || strings.HasPrefix(c.TestID, "l2tp.") {
					e = append(e, "consumer NAT routers with IPsec / L2TP passthrough ALGs drop or rewrite exactly these packets: a known confound on home networks, not necessarily the censor")
					// With a NAT in the path the ALG explanation is live and
					// the verdict cannot be high: the two are not separable
					// from one vantage point.
					if nat, line := natDetected(attempts); nat {
						e = append(e, line+"; an ALG on it cannot be ruled out from this vantage point")
						if conf == "high" {
							conf = "medium"
						}
					}
				}
				reportedFamily[famKey] = true
				add("protocol_blocking_suspected", famKey, conf, e...)
			}
		}
	}

	// 5. Variant-level differentials inside one test family on one port.
	for test, group := range byTest {
		if client.IsDestTest(test) {
			continue // one-sided family with its own rules (dest.go)
		}
		byPort := map[string][]Cell{}
		for _, c := range group {
			byPort[fmt.Sprintf("%s/%d", c.Transport, c.Port)] = append(byPort[fmt.Sprintf("%s/%d", c.Transport, c.Port)], c)
		}
		for port, cs := range byPort {
			var base *Cell
			for i := range cs {
				if cs[i].Role == client.RoleBaseline || (base == nil && cs[i].Role == client.RoleControl && strings.HasPrefix(test, "vless.")) {
					base = &cs[i]
				}
			}
			// When the nominal baseline fails but another variant of the same
			// family passes on the port, that variant is the control: the
			// rule then keys on what the baseline has and the passing one
			// lacks (a chrome parrot blocked while edge passes, for example).
			if base == nil || !base.pass() {
				base = nil
				for i := range cs {
					if cs[i].pass() && cs[i].Role != client.RoleControl {
						base = &cs[i]
						break
					}
				}
				if base == nil {
					continue
				}
			}
			for _, v := range cs {
				if v.Role == client.RoleBaseline || !v.fail() || v.Key() == base.Key() {
					continue
				}
				// A session variant whose own handshake passes is rule 5c's
				// finding (a session cut), not a variant differential.
				if init, ok := handshakeCell(v); ok && init.pass() {
					continue
				}
				kind := "variant_blocking_suspected"
				switch test {
				case "tls.sni", "http.host":
					if strings.HasPrefix(v.Variant, "trigger:") {
						kind = "sni_or_host_blocking_suspected"
					} else {
						kind = "sni_or_host_policy_suspected"
					}
				case "tls.fingerprint":
					kind = "fingerprint_blocking_suspected"
				case "vless.reality", "vless.session":
					if strings.HasPrefix(v.Variant, "reality:") {
						kind = "sni_ip_mismatch_blocking_suspected"
					}
				case "tls.alpn":
					kind = "alpn_policy_suspected"
				case "tls.version":
					kind = "tls_version_policy_suspected"
				case "dns.udp":
					kind = "dns_qtype_policy_suspected"
				case "socks5.connect":
					kind = "socks5_auth_policy_suspected"
				case "tor.handshake":
					kind = "tor_handshake_blocking_suspected"
				case "dtls.hello":
					kind = "dtls_fingerprint_blocking_suspected"
				}
				e := []string{ev(v), "passing baseline: " + ev(*base)}
				if test == "tor.handshake" {
					// Which plaintext feature the rule keys on: the ClientHello,
					// the certificate, or only the two together.
					state := func(variant string) string {
						for _, o := range cs {
							if o.Variant == variant {
								if o.fail() {
									return "fail"
								} else if o.pass() {
									return "pass"
								}
							}
						}
						return ""
					}
					hello, cert := state("tor-hello+probe-cert"), state("go-hello+tor-cert")
					switch {
					case hello == "fail" && cert == "fail":
						e = append(e, "both the tor ClientHello alone and the relay certificate alone fail: two independent rules, or a rule on either feature")
					case hello == "fail" && cert == "pass":
						e = append(e, "the tor ClientHello alone fails while the relay certificate with a plain hello passes: the rule keys on the ClientHello (no SNI + tor cipher list)")
					case hello == "pass" && cert == "fail":
						e = append(e, "the relay certificate alone fails while the tor ClientHello with the probe certificate passes: the rule keys on the TLS 1.2 certificate (www.<random>.com / .net)")
					case hello == "pass" && cert == "pass" && v.Variant == "tor-hello+tor-cert":
						e = append(e, "each feature alone passes; only the full tor shape fails: the rule needs both the ClientHello and the certificate")
					}
				}
				add(kind, fmt.Sprintf("%s %s %s", test, port, v.Variant), confidence(v, *base), e...)
			}
		}
	}

	// 5b. Long transfers: a cut or stall after N kilobytes while short
	// exchanges on the same port pass. The evidence carries the median offset.
	for _, c := range cells {
		if c.TestID != "tcp.bulk" || !c.fail() {
			continue
		}
		short, ok := find("tcp.echo", c.Transport, c.Port, "")
		if !ok || !short.pass() {
			continue
		}
		var offsets []int
		for _, a := range attempts {
			if a.TestID == c.TestID && a.DstPort == c.Port && a.Variant == c.Variant {
				if kb, err := strconv.Atoi(a.Detail["bulk_cut_kb"]); err == nil {
					offsets = append(offsets, kb)
				}
			}
		}
		sort.Ints(offsets)
		off := "unknown"
		if len(offsets) > 0 {
			off = fmt.Sprintf("~%d KB", offsets[len(offsets)/2])
		}
		kind := "bulk_transfer_cut_suspected"
		if strings.Contains(c.Variant, "trigger:") || strings.Contains(c.Variant, "list:") {
			kind = "sni_bulk_cut_suspected"
		}
		add(kind, c.Key(), confidence(c, short), ev(c), "transfer stopped at "+off, "short exchange on the same port passed: "+ev(short))
	}

	// 5b'. Small-packet flows: the same bytes as the echo, in many segments or
	// many datagrams, stop being answered while the one-packet echo passes on
	// the same port. Cross-checked against tcp.bulk on the same port: a byte
	// rule cuts the 64 KB transfer and not this flow; a packet rule cuts
	// this flow, and the bulk transfer only if it also crosses the count.
	for _, c := range cells {
		if (c.TestID != "tcp.packets" && c.TestID != "udp.packets") || !c.fail() {
			continue
		}
		echoTest := "tcp.echo"
		if c.Transport == "udp" {
			echoTest = "udp.echo"
		}
		echo, ok := find(echoTest, c.Transport, c.Port, "")
		if !ok || !echo.pass() {
			continue
		}
		var sent, acked, planned []int
		for _, a := range attempts {
			if a.TestID != c.TestID || a.DstPort != c.Port || a.Variant != c.Variant || a.Outcome == client.OutcomeOK {
				continue
			}
			if v, err := strconv.Atoi(a.Detail["packets_sent"]); err == nil {
				sent = append(sent, v)
			}
			if v, err := strconv.Atoi(a.Detail["packets_acked"]); err == nil {
				acked = append(acked, v)
			}
			if v, err := strconv.Atoi(a.Detail["packets_planned"]); err == nil {
				planned = append(planned, v)
			}
		}
		e := []string{ev(c), "one-packet echo on the same port passed: " + ev(echo)}
		if c.Transport == "udp" && len(acked) > 0 {
			e = append(e, fmt.Sprintf("datagrams answered before the cut: median %d of %d", median(acked), median(planned)))
		} else if len(sent) > 0 {
			e = append(e, fmt.Sprintf("segments written: median %d of %d; the reply never came", median(sent), median(planned)))
		}
		if c.Transport == "tcp" {
			bulkFail, bulkPass := false, false
			for _, o := range cells {
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
		add("packet_count_cut_suspected", c.Key(), confidence(c, echo), e...)
	}

	// 5b''. TLS handshake rate rule: N parallel handshakes to one name fail
	// while a single handshake to another name passes right after (the
	// attempt carries its own control). The plain tls.sni baseline on the
	// port is the outer control; the firefox burst says whether the rule is
	// fingerprint-dependent.
	for _, c := range cells {
		if c.TestID != "tls.burst" || c.Outcomes[client.OutcomeBurstFreeze] == 0 || c.OK*2 > c.Total {
			continue
		}
		outer, ok := find("tls.sni", "tcp", c.Port, "benign")
		conf := "low"
		if ok && outer.pass() {
			conf = confidence(c, outer)
		} else if c.Total >= 2 && c.Outcomes[client.OutcomeBurstFreeze]*2 > c.Total {
			conf = "medium"
		}
		var alphaOK, seen, answered, partial, spread []int
		fp, n := "", ""
		for _, a := range attempts {
			if a.TestID != c.TestID || a.DstPort != c.Port || a.Variant != c.Variant || a.Detail["transient"] == "true" {
				continue
			}
			fp, n = a.Detail["fingerprint"], a.Detail["burst_n"]
			if v, err := strconv.Atoi(a.Detail["alpha_ok"]); err == nil {
				alphaOK = append(alphaOK, v)
			}
			if v, err := strconv.Atoi(a.Detail["server_alpha_seen"]); err == nil {
				seen = append(seen, v)
			}
			if v, err := strconv.Atoi(a.Detail["server_alpha_answered"]); err == nil {
				answered = append(answered, v)
			} else if v, err := strconv.Atoi(a.Detail["server_alpha_hello"]); err == nil {
				answered = append(answered, v)
			}
			if v, err := strconv.Atoi(a.Detail["server_alpha_partial"]); err == nil {
				partial = append(partial, v)
			}
			if v, err := strconv.Atoi(a.Detail["burst_spread_ms"]); err == nil {
				spread = append(spread, v)
			}
		}
		e := []string{ev(c)}
		if len(alphaOK) > 0 {
			e = append(e, fmt.Sprintf("%s parallel handshakes (%s parrot, ClientHellos within ~%d ms): median %d passed; the single handshake to another name right after passed", n, fp, median(spread), median(alphaOK)))
		}
		if len(seen) > 0 {
			line := fmt.Sprintf("server saw median %d of %s ClientHellos and sent a ServerHello to %d", median(seen), n, median(answered))
			if len(partial) > 0 && median(partial) > 0 {
				line += fmt.Sprintf(", %d arrived cut mid-hello", median(partial))
			}
			e = append(e, line+": "+directionFrom(c.dominant()))
		}
		if ok {
			e = append(e, "single-handshake baseline on the same port: "+ev(outer))
		}
		for _, o := range cells {
			if o.TestID == "tls.burst" && o.Port == c.Port && o.Variant != c.Variant {
				if o.pass() {
					e = append(e, fmt.Sprintf("the same burst with the %s parrot passed: the rule is fingerprint-dependent (%s)", strings.SplitN(o.Variant, "-", 2)[0], ev(o)))
				} else if o.fail() {
					e = append(e, fmt.Sprintf("the same burst with the %s parrot failed too: the rule does not depend on the fingerprint (%s)", strings.SplitN(o.Variant, "-", 2)[0], ev(o)))
				}
			}
		}
		add("tls_burst_freeze_suspected", c.Key(), conf, e...)
	}

	// 5c. VPN sessions: the handshake is answered on a port but the data that
	// follows is not. This is the stateful-blocking signature ("handshake
	// completes, no traffic flows") that a handshake-only test cannot see.
	// A session test that fails together with its handshake test is
	// protocol blocking and is reported by rule 4.
	for _, c := range cells {
		if handshakeTestOf(c.TestID) == "" || c.pass() {
			continue
		}
		init, ok := handshakeCell(c)
		if !ok || !init.pass() {
			continue
		}
		var recv, sent, seen, ctlRecv, ctlSent, ctlSeen, firstLoss []int
		for _, a := range attempts {
			if a.TestID != c.TestID || a.DstPort != c.Port || a.Transport != c.Transport || a.Variant != c.Variant {
				continue
			}
			if v, err := strconv.Atoi(a.Detail["data_recv"]); err == nil {
				recv = append(recv, v)
			}
			if v, err := strconv.Atoi(a.Detail["data_sent"]); err == nil {
				sent = append(sent, v)
			}
			if v, err := strconv.Atoi(a.Detail["server_data_seen"]); err == nil {
				seen = append(seen, v)
			}
			if v, err := strconv.Atoi(a.Detail["ctl_recv"]); err == nil {
				ctlRecv = append(ctlRecv, v)
			}
			if v, err := strconv.Atoi(a.Detail["ctl_sent"]); err == nil {
				ctlSent = append(ctlSent, v)
			}
			if v, err := strconv.Atoi(a.Detail["server_ctl_seen"]); err == nil {
				ctlSeen = append(ctlSeen, v)
			}
			if a.Outcome == client.OutcomeSessionCut {
				if v, err := strconv.Atoi(a.Detail["data_first_loss"]); err == nil {
					firstLoss = append(firstLoss, v)
				}
			}
		}
		kind := strings.TrimSuffix(c.TestID, ".session") + "_session_cut_suspected"
		e := []string{ev(c), "handshake on the same port passed: " + ev(init)}
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
		// Confidence: high when the cut repeats (at least two rounds in
		// three) while the handshake and a plain baseline on the same port
		// (udp.echo / udp.packets, tcp.echo / tcp.packets) pass; otherwise
		// the general rule, capped at medium when a round passed.
		conf := confidence(c, init)
		if c.OK > 0 && conf == "high" {
			conf = "medium"
		}
		cut := c.Outcomes[client.OutcomeSessionCut]
		if cut*3 >= c.Total*2 && c.Total >= 3 && init.pass() {
			echoTest, packetsTest := "udp.echo", "udp.packets"
			if c.Transport == "tcp" {
				echoTest, packetsTest = "tcp.echo", "tcp.packets"
			}
			echo, okE := find(echoTest, c.Transport, c.Port, "")
			pk, okP := find(packetsTest, c.Transport, c.Port, "")
			if (okE && echo.pass()) || (okP && pk.pass()) {
				conf = "high"
				if okE && echo.pass() {
					e = append(e, "baseline on the same port passed: "+ev(echo))
				} else {
					e = append(e, "baseline on the same port passed: "+ev(pk))
				}
			}
		}
		add(kind, c.Key(), conf, e...)
	}

	// 6. DNS transport differentials and manipulation.
	if udp, ok := find("dns.udp", "udp", 0, ""); ok || true {
		_ = udp
		for _, c := range cells {
			if !strings.HasPrefix(c.TestID, "dns.") {
				continue
			}
			if c.Outcomes[client.OutcomeDNSMismatch]+c.Outcomes["dns_injected_race"] > 0 {
				kind := "dns_manipulation_suspected"
				if c.TestID == "dns.system" {
					kind = "system_resolver_manipulation_suspected"
				}
				add(kind, c.Key(), "medium", ev(c), "answer content did not match the authoritative nonce answer")
			}
		}
		var dnsUDP, dnsTCP *Cell
		for i := range cells {
			if cells[i].TestID == "dns.udp" && cells[i].Variant == "TXT" {
				dnsUDP = &cells[i]
			}
			if cells[i].TestID == "dns.tcp" {
				dnsTCP = &cells[i]
			}
		}
		if dnsUDP != nil && dnsTCP != nil && dnsUDP.fail() && dnsTCP.pass() {
			add("dns_udp_blocking_suspected", dnsUDP.Key(), confidence(*dnsUDP, *dnsTCP), ev(*dnsUDP), "passing control: "+ev(*dnsTCP))
		}
		// The DNS ports carry no echo test, so a blanket block of port 53 or
		// 853 would otherwise produce no verdict at all: use any passing echo
		// of the same transport as the control.
		for _, c := range cells {
			if !strings.HasPrefix(c.TestID, "dns.") || c.TestID == "dns.system" || c.TestID == "dns.doh" || !c.fail() {
				continue
			}
			if _, ok := find("tcp.echo", c.Transport, c.Port, ""); ok {
				continue
			}
			if _, ok := find("udp.echo", c.Transport, c.Port, ""); ok {
				continue
			}
			if dnsUDP != nil && dnsTCP != nil && c.TestID == "dns.udp" && dnsTCP.pass() {
				continue // already reported as dns_udp_blocking_suspected
			}
			echoTest := "tcp.echo"
			if c.Transport == "udp" {
				echoTest = "udp.echo"
			}
			var ctrl *Cell
			for i := range cells {
				if cells[i].TestID == echoTest && cells[i].pass() {
					ctrl = &cells[i]
					break
				}
			}
			if ctrl == nil {
				continue
			}
			add("dns_port_blocking_suspected", c.Key(), confidence(c, *ctrl), ev(c), "no echo runs on this port; passing echo on another port of the same transport: "+ev(*ctrl))
		}
	}

	// 7. Modification / injection anywhere. Cells that a differential verdict
	// above already names get the mechanism attached to that verdict instead
	// of a second finding; the rest are reported on their own, never above
	// medium, since there is no control to compare with.
	named := map[string]int{}
	for i, v := range res.Verdicts {
		named[v.Subject] = i
	}
	for _, c := range cells {
		for merged, n := range c.Merged {
			if n == 0 {
				continue
			}
			switch merged {
			case "uplink_modified", "downlink_modified", "injected", "rst_injected_or_path_reset", "rst_injected_bidirectional", "tls_mitm_or_wrong_server":
				if c.TestID == "tcp.bulk" || c.TestID == "tcp.packets" || c.TestID == "udp.packets" || c.TestID == "tls.burst" || handshakeTestOf(c.TestID) != "" {
					continue // reported above with the byte offset / packet counts
				}
				mech := fmt.Sprintf("mechanism: %d/%d attempts merged as %s", n, c.Total, merged)
				if i, ok := named[c.Key()]; ok {
					res.Verdicts[i].Evidence = append(res.Verdicts[i].Evidence, mech)
					continue
				}
				if i, ok := named[fmt.Sprintf("%s %s/%d %s", c.TestID, c.Transport, c.Port, c.Variant)]; ok {
					res.Verdicts[i].Evidence = append(res.Verdicts[i].Evidence, mech)
					continue
				}
				conf := "low"
				if n >= 2 {
					conf = "medium"
				}
				add(merged, c.Key(), conf, fmt.Sprintf("%d/%d attempts classified %s; no differential control for this cell", n, c.Total, merged))
			}
		}
	}
	// 8. SYN-ACK timing. Two independent signals: tcp.rtt (connect vs payload
	// round trip on one port) and the cross-port differential (a port whose
	// TCP connect completes in a fraction of the time every other port needs
	// is being answered by something closer than the server). Either alone is
	// low confidence; together they are medium.
	rttSuspect := map[int]string{}
	for _, a := range attempts {
		if a.TestID == "tcp.rtt" && a.Detail["synack_suspect"] == "true" {
			rttSuspect[a.DstPort] = fmt.Sprintf("tcp.rtt on tcp/%d: connect %s ms vs payload %s ms (ratio %s)", a.DstPort, a.Detail["connect_min_ms"], a.Detail["payload_min_ms"], a.Detail["connect_payload_ratio"])
		}
	}
	fast, ref := fastConnectPorts(attempts)
	reported := map[int]bool{}
	// A transparent proxy found on the same port by rule 2 is the same
	// middlebox seen from the other side: the two findings corroborate.
	proxied := map[string]bool{}
	for _, v := range res.Verdicts {
		if v.Kind == "transparent_proxy_suspected" {
			proxied[v.Subject] = true
		}
	}
	for _, port := range fast.ports {
		subject := fmt.Sprintf("tcp/%d", port)
		e := []string{fmt.Sprintf("median connect on tcp/%d is %.1f ms; on the other TCP ports %.1f ms (ratio %.2f)", port, fast.median[port], ref, fast.median[port]/ref)}
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
		add("synack_local_termination_suspected", subject, conf, e...)
		reported[port] = true
	}
	for port, s := range rttSuspect {
		if !reported[port] {
			add("synack_spoof_signal", fmt.Sprintf("tcp/%d", port), "low", s+"; no cross-port confirmation; needs pcap/TTL")
		}
	}

	// Real destinations: one-sided evidence with its own controls.
	destVerdicts(cells, add)

	sort.SliceStable(res.Verdicts, func(i, j int) bool {
		if res.Verdicts[i].Kind != res.Verdicts[j].Kind {
			return res.Verdicts[i].Kind < res.Verdicts[j].Kind
		}
		return res.Verdicts[i].Subject < res.Verdicts[j].Subject
	})
	res.Destinations = Destinations(attempts, cells, res.Verdicts)
	if len(res.Verdicts) == 0 {
		res.Summary = "clean: every test family passed on every port; no differential observed"
	} else {
		// Low-confidence findings are listed apart: a single unexplained
		// timeout must not read like a rule that fired three times.
		kinds, low := map[string]int{}, map[string]int{}
		for _, v := range res.Verdicts {
			if v.Confidence == "low" {
				low[v.Kind]++
			} else {
				kinds[v.Kind]++
			}
		}
		join := func(m map[string]int) string {
			var parts []string
			for k, n := range m {
				parts = append(parts, fmt.Sprintf("%s×%d", k, n))
			}
			sort.Strings(parts)
			return strings.Join(parts, ", ")
		}
		switch {
		case len(kinds) == 0:
			res.Summary = "low confidence only: " + join(low)
		case len(low) == 0:
			res.Summary = join(kinds)
		default:
			res.Summary = join(kinds) + "; low confidence: " + join(low)
		}
	}
	return res
}
