package classify

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/xarvel/CensorPulseCli/internal/client"
)

// Destination is the per-site summary of the dest.* family: what each layer
// did and the verdict that covers it. It is the view a UI shows per row.
type Destination struct {
	Domain     string            `json:"domain"`
	Category   string            `json:"category,omitempty"`
	Label      string            `json:"label,omitempty"`
	Verdict    string            `json:"verdict"`              // clear | nxdomain | <verdict kind> | degraded | inconclusive
	Confidence string            `json:"confidence,omitempty"` // of the verdict kind, when there is one
	Layers     map[string]string `json:"layers"`               // dns, tcp, tls, decoy, absent, proto, http → ok | skipped | <dominant outcome>
	Note       string            `json:"note,omitempty"`
}

// destFailed is a cell that failed on its own account: a layer skipped
// because an earlier layer had nothing to give it (no address), one that
// could not be assessed, or one that failed on the host itself (a local
// socket error) is not a failure.
func destFailed(c Cell) bool {
	if !c.fail() {
		return false
	}
	switch c.dominant() {
	case client.OutcomeSkipped, client.OutcomeInconclusive, client.OutcomeServerError:
		return false
	}
	return true
}

// resolverMinSites is how many sites must fail the same way before the
// system resolver as a whole is suspected at more than "low" (timeouts), or
// at all (mismatches): one site is that site's finding.
const resolverMinSites = 2

// destVerdicts derives the family's verdicts. It is one-sided evidence, so
// nothing here is ever more than medium and every verdict names the control
// measured the same way that passed (or, for a reset keyed on the name, the
// control on the same address that was never reset). The attempts are read
// for the timing of the resets.
func destVerdicts(attempts []*client.Attempt, cells []Cell, add func(kind, subject, conf string, ev ...string)) {
	find := func(test, variant string) (Cell, bool) {
		for _, c := range cells {
			if c.TestID == test && c.Variant == variant {
				return c, true
			}
		}
		return Cell{}, false
	}
	var domains []string
	seen := map[string]bool{}
	for _, c := range cells {
		if !client.IsDestTest(c.TestID) || c.TestID == "dest.nxdomain" || c.Variant == "anycast" {
			continue
		}
		d := destDomain(c.Variant)
		if !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}
	if len(domains) == 0 {
		if nx, ok := find("dest.nxdomain", "invalid"); ok {
			nxdomainVerdict(nx, add)
		}
		return
	}
	sort.Strings(domains)
	ev := func(c Cell) string {
		return fmt.Sprintf("%s: %d/%d ok, dominant=%s", c.Key(), c.OK, c.Total, c.dominant())
	}
	capped := func(failed, passed Cell) string {
		conf := confidence(failed, passed)
		if conf == "high" {
			conf = "medium" // one vantage point, no server half
		}
		return conf
	}

	// Family controls.
	if nx, ok := find("dest.nxdomain", "invalid"); ok {
		nxdomainVerdict(nx, add)
	}
	anycast, haveAnycast := find("dest.tcp", "anycast")
	transportOK := haveAnycast && anycast.pass()
	if haveAnycast && anycast.Measured() > 0 && !anycast.pass() {
		add("control_failed_inconclusive", anycast.Key(), "low", ev(anycast), "no clean anycast address connects on :443: the transport layers of the real destinations cannot be told from an outage")
	}

	// A passing dest.dns cell of a control site is the DNS control; failing
	// that, any passing dest.dns cell.
	var dnsControl *Cell
	for _, c := range cells {
		if c.TestID == "dest.dns" && c.pass() && (dnsControl == nil || (c.Role == client.RoleBaseline && dnsControl.Role != client.RoleBaseline)) {
			cc := c
			dnsControl = &cc
		}
	}
	// System resolver timing out across the board is one finding, not one
	// per site.
	dnsCells, dnsTimeouts, dnsMismatches := 0, 0, 0
	for _, c := range cells {
		if c.TestID == "dest.dns" && c.Variant != "anycast" {
			dnsCells++
			if destFailed(c) && c.dominant() == client.OutcomeDNSTimeout {
				dnsTimeouts++
			}
			if destFailed(c) && c.dominant() == client.OutcomeDNSMismatch {
				dnsMismatches++
			}
		}
	}
	systemDown := dnsCells > 0 && dnsTimeouts*2 >= dnsCells
	if systemDown {
		conf := "low"
		if transportOK && dnsTimeouts >= resolverMinSites {
			conf = "medium"
		}
		add("system_resolver_unreachable_suspected", "dest.dns udp/53", conf,
			fmt.Sprintf("%d of %d sites: the system resolver timed out while the trusted DoH resolvers answered", dnsTimeouts, dnsCells),
			"passing control: the trusted resolvers, and "+func() string {
				if transportOK {
					return ev(anycast)
				}
				return "no anycast control"
			}())
	}

	// The same for a resolver that agrees with the trusted ones on no site at
	// all. A platform resolver often cannot tell "no such name" from its own
	// failure (getaddrinfo's EAI_NONAME, Java's UnknownHostException), so a
	// dead or captive resolver denies every name: that is a finding about the
	// resolver, and no site may be called poisoned on it.
	systemUnreliable := dnsControl == nil && dnsMismatches >= resolverMinSites && dnsMismatches*2 >= dnsCells
	if systemUnreliable {
		add("system_resolver_unreliable_suspected", "dest.dns udp/53", "low",
			fmt.Sprintf("%d of %d sites: the system resolver's answer is not the one the trusted DoH resolvers give, and no site resolved cleanly through it", dnsMismatches, dnsCells),
			"a failing, captive or wholesale-substituted resolver cannot be told from per-site poisoning without a name it resolves correctly")
	}

	for _, d := range domains {
		dns, haveDNS := find("dest.dns", d)
		tcp, haveTCP := find("dest.tcp", d)
		real, haveTLS := find("dest.tls", d)
		decoy, haveDecoy := find("dest.tls", "decoy:"+d)
		absent, haveAbsent := find("dest.tls", "absent:"+d)
		httpc, haveHTTP := find("dest.http", d)
		proto, haveProto := find("dest.proto", d)

		if haveDNS && destFailed(dns) {
			switch dns.dominant() {
			case client.OutcomeDNSMismatch:
				e := []string{ev(dns)}
				if dnsControl != nil {
					e = append(e, "passing control: "+ev(*dnsControl))
					add("dest_dns_poisoning_suspected", dns.Key(), capped(dns, *dnsControl), append(e, "the system resolver's answer for this name is not the one the trusted resolvers give and does not serve; a control site resolves cleanly")...)
				} else if !systemUnreliable {
					add("dest_dns_poisoning_suspected", dns.Key(), "low", append(e, "no site resolved cleanly through the system resolver: the whole resolver may be substituted")...)
				}
			case client.OutcomeDNSTimeout:
				if !systemDown && transportOK {
					add("dest_dns_poisoning_suspected", dns.Key(), "low", ev(dns), "the system resolver timed out for this name only while the trusted resolvers answered; other names resolved: a per-name blackhole in the resolver, or loss", "passing control: "+ev(anycast))
				}
			}
		}

		if haveTCP && destFailed(tcp) && transportOK {
			e := []string{ev(tcp), "passing control: " + ev(anycast)}
			if haveDNS && dns.fail() && dns.dominant() == client.OutcomeDNSMismatch {
				e = append(e, "the addresses probed are the trusted resolvers' answers, not the poisoned ones")
			}
			switch tcp.dominant() {
			case client.OutcomeConnectTimeout:
				add("dest_tcp_blackhole_suspected", tcp.Key(), capped(tcp, anycast), append(e, "SYN to the site's address on :443 is never answered while a clean anycast address answers: the address (or prefix) is dropped")...)
			case client.OutcomeConnectReset, client.OutcomeConnectRefused:
				add("dest_tcp_reset_suspected", tcp.Key(), capped(tcp, anycast), append(e, "the connect is actively rejected (RST / refused) while a clean anycast address accepts: an injected reset or a sinkhole")...)
			default:
				add("dest_tcp_blocking_suspected", tcp.Key(), capped(tcp, anycast), e...)
			}
		}

		// The TCP layer is the control of the TLS verdicts. When it measured
		// nothing (skipped, or lost to an outage), the handshakes that got
		// past their own connect show that TCP to the address works.
		tcpPass := haveTCP && tcp.pass()
		tcpUnmeasured := !haveTCP || tcp.Measured() == 0
		tcpLine := "TCP to the address connected in the handshake attempts themselves (the TCP layer measured nothing)"
		if tcpPass {
			tcpLine = "passing control: TCP connect " + ev(tcp)
		}
		if haveTLS && destFailed(real) && (tcpPass || (tcpUnmeasured && !connectStage(real))) {
			switch {
			case connectStage(real):
				// No ClientHello left the host: dest.tls connects to the
				// site's first address only, dest.tcp walks up to four, so
				// "TCP passes" was another address. The name is not in
				// evidence at all; the first address is.
				if transportOK {
					add("dest_tcp_blackhole_suspected", real.Key(), "low", ev(real), "passing control: "+ev(anycast), "the site's primary address does not accept TCP on :443 while another of its addresses does ("+ev(tcp)+"): an address or prefix is dropped, the name was never sent")
				}
			case haveDecoy && decoy.pass():
				e := []string{ev(real), "passing control on the same address: " + ev(decoy)}
				if haveAbsent {
					e = append(e, "no SNI: "+ev(absent))
				}
				if real.dominant() == client.OutcomeTLSSpoof {
					e = append(e, "non-TLS bytes answered the ClientHello: an injected block page")
				}
				if r := earlyResets(attempts, real); r.line != "" {
					e = append(e, r.line)
				}
				add("dest_sni_blocking_suspected", real.Key(), capped(real, decoy), append(e, "the real name fails while a decoy name on the very same address completes the handshake: the rule keys on the SNI")...)
			case real.dominant() == client.OutcomeMidstreamReset && haveDecoy && destFailed(decoy) && timedOutOnly(decoy) && (!haveAbsent || timedOutOnly(absent) || absent.pass()):
				// The controls on the same address did not complete either,
				// but nothing reset them: they ran out of time (a slow path),
				// while the real name was reset. The reset keys on the name.
				r := earlyResets(attempts, real)
				e := []string{ev(real), "the decoy name on the same address was never reset, it timed out: " + ev(decoy)}
				if haveAbsent {
					e = append(e, "no SNI: "+ev(absent))
				}
				if r.line != "" {
					e = append(e, r.line)
				}
				// Without a passing control the verdict rests on the reset
				// itself: medium only when every measured attempt of the
				// real name was reset sooner than a round trip (injected on
				// the path), and at least twice.
				conf := "low"
				if r.early == real.Measured() && r.early >= mediumMinAttempts {
					conf = "medium"
				}
				add("dest_sni_blocking_suspected", real.Key(), conf, append(e, "only the real name draws a reset on this address, the handshakes with another name or none time out instead: the rule keys on the SNI")...)
			case haveDecoy && destFailed(decoy):
				e := []string{ev(real), "decoy name on the same address fails too: " + ev(decoy), tcpLine}
				if haveAbsent && absent.pass() {
					e = append(e, "a handshake without SNI passes: "+ev(absent)+"; the rule keys on any name, or on the handshake shape")
				}
				add("dest_tls_blocking_suspected", real.Key(), capped(real, tcp), append(e, "TCP connects but no TLS handshake with a name completes on the address: address-level or handshake-level interference, not the name alone")...)
			default:
				add("dest_tls_blocking_suspected", real.Key(), "low", ev(real), "no decoy handshake to compare with", tcpLine)
			}
		}

		// A target that speaks its own protocol has that handshake instead of
		// the TLS ones, and no decoy: the control is TCP to the same address.
		if haveProto && destFailed(proto) && (tcpPass || (tcpUnmeasured && !connectStage(proto))) {
			if connectStage(proto) {
				if transportOK {
					add("dest_tcp_blackhole_suspected", proto.Key(), "low", ev(proto), "passing control: "+ev(anycast), "the site's primary address does not accept TCP on :443 while another of its addresses does ("+ev(tcp)+"): an address or prefix is dropped, the handshake was never sent")
				}
			} else {
				e := []string{ev(proto), tcpLine}
				if proto.dominant() == client.OutcomeUnexpected {
					e = append(e, "something other than the service answered the handshake: a block page or a proxy")
				}
				if r := earlyResets(attempts, proto); r.line != "" {
					e = append(e, r.line)
				}
				add("dest_proto_blocking_suspected", proto.Key(), capped(proto, tcp), append(e, "TCP connects but the "+protoOf(attempts, d)+" handshake does not complete on the address: the path interferes with the service's own protocol")...)
			}
		}

		if haveHTTP && destFailed(httpc) && haveTLS && real.pass() {
			switch httpc.dominant() {
			case client.OutcomeHTTPLegalBlock:
				conf := "low"
				if httpc.Measured() >= mediumMinAttempts && httpc.OK == 0 {
					conf = "medium"
				}
				add("dest_legal_block_suspected", httpc.Key(), conf, ev(httpc), "passing control: TLS handshake "+ev(real), "HTTP 451 from the service after a clean handshake: the service refuses the region, the network did not interfere")
			case client.OutcomeCertMismatch:
				add("dest_tls_interception_suspected", httpc.Key(), "low", ev(httpc), "the certificate presented for the real name does not verify against the system roots while the handshake itself completes: interception, or a broken chain on the site")
			}
		}
	}
}

// protoOf names the protocol of a site's dest.proto attempts (detail.proto).
func protoOf(attempts []*client.Attempt, domain string) string {
	for _, a := range attempts {
		if a.TestID == "dest.proto" && a.Variant == domain && a.Detail["proto"] != "" {
			return a.Detail["proto"]
		}
	}
	return "service's own"
}

// timedOutOnly is a cell whose measured failures are all handshakes that ran
// out of time after the ClientHello went out: nothing answered, nothing
// reset or refused them.
func timedOutOnly(c Cell) bool {
	if c.Outcomes[client.OutcomePayloadTimeout] == 0 {
		return false
	}
	for o, n := range c.Outcomes {
		if n > 0 && o != client.OutcomeOK && o != client.OutcomePayloadTimeout && !unmeasuredMerged[o] {
			return false
		}
	}
	return true
}

// resetTiming is what the attempts of a cell say about their resets.
type resetTiming struct {
	early int    // attempts reset sooner than the TCP round trip
	line  string // the evidence line, "" when no reset was timed
}

// earlyResets reads the reset timing of the measured attempts of a dest.tls
// cell (client.ResetBeforeRTT): a reset that comes back sooner than a TCP
// round trip to the same address was sent by something closer than the
// server. The round trip is the shortest TCP handshake any dest.* attempt
// measured to the address (minRTT), the connection's own when it is shorter:
// one connect carries the jitter, or the SYN retransmission, of its moment.
func earlyResets(attempts []*client.Attempt, c Cell) resetTiming {
	var out resetTiming
	var resets, rtts []float64
	best := minRTT(attempts)
	for _, a := range attempts {
		if a.TestID != c.TestID || a.Variant != c.Variant || a.DstPort != c.Port || a.Detail["transient"] == "true" || a.Detail["cancelled"] == "true" || unmeasured(a) {
			continue
		}
		resetMs, rttMs, ok := client.ResetTiming(a)
		if !ok {
			continue
		}
		if m, ok := best[attemptIP(a)]; ok && (m < rttMs || !client.UsableRTT(rttMs)) {
			rttMs = m
		}
		resets, rtts = append(resets, resetMs), append(rtts, rttMs)
		if client.ResetBeforeRTT(resetMs, rttMs) {
			out.early++
		}
	}
	if len(resets) == 0 {
		return out
	}
	span := func(v []float64) string {
		lo, hi := v[0], v[0]
		for _, x := range v {
			lo, hi = min(lo, x), max(hi, x)
		}
		if int(lo) == int(hi) {
			return fmt.Sprintf("%.0f ms", lo)
		}
		return fmt.Sprintf("%.0f-%.0f ms", lo, hi)
	}
	switch {
	case out.early == len(resets):
		out.line = fmt.Sprintf("the reset came %s after the ClientHello, sooner than the TCP round trip to the address (%s): sent by a middlebox on the path, not by the server", span(resets), span(rtts))
	case out.early > 0:
		out.line = fmt.Sprintf("%d of %d resets came sooner than the TCP round trip to the address (reset %s after the ClientHello, round trip %s): injected on the path", out.early, len(resets), span(resets), span(rtts))
	default:
		out.line = fmt.Sprintf("the reset came %s after the ClientHello, the TCP round trip to the address took %s", span(resets), span(rtts))
	}
	return out
}

// attemptIP is the address a dest.* attempt connected to: detail.ip, or the
// host of detail.endpoint (dest.tcp).
func attemptIP(a *client.Attempt) string {
	if ip := a.Detail["ip"]; ip != "" {
		return ip
	}
	if host, _, err := net.SplitHostPort(a.Detail["endpoint"]); err == nil {
		return host
	}
	return ""
}

// minRTT is, per address, the shortest TCP handshake a dest.* attempt that
// was not flagged measured to it without a SYN retransmission.
func minRTT(attempts []*client.Attempt) map[string]float64 {
	out := map[string]float64{}
	for _, a := range attempts {
		if !client.IsDestTest(a.TestID) || a.Detail["transient"] == "true" || a.Detail["cancelled"] == "true" {
			continue
		}
		rtt, ok := a.Stages["connect"]
		ip := attemptIP(a)
		if !ok || ip == "" || !client.UsableRTT(rtt) {
			continue
		}
		if m, seen := out[ip]; !seen || rtt < m {
			out[ip] = rtt
		}
	}
	return out
}

// connectStage is a cell whose dominant failure happened before any payload
// was written: the address, not what was sent to it, is what failed.
func connectStage(c Cell) bool {
	switch c.dominant() {
	case client.OutcomeConnectTimeout, client.OutcomeConnectReset, client.OutcomeConnectRefused:
		return true
	}
	return false
}

func nxdomainVerdict(nx Cell, add func(kind, subject, conf string, ev ...string)) {
	if !destFailed(nx) || nx.dominant() != client.OutcomeDNSMismatch {
		return
	}
	conf := "low"
	if nx.Measured() >= mediumMinAttempts {
		conf = "medium"
	}
	add("nxdomain_hijack_suspected", nx.Key(), conf, fmt.Sprintf("%s: %d/%d ok, dominant=%s", nx.Key(), nx.OK, nx.Total, nx.dominant()), "a fresh name under the reserved .invalid TLD was answered with an address: the resolver invents answers (search/ad redirection, captive portal or a sinkhole)")
}

// destDomain strips the variant prefixes of the family.
func destDomain(variant string) string {
	for _, p := range []string{"decoy:", "absent:"} {
		if strings.HasPrefix(variant, p) {
			return strings.TrimPrefix(variant, p)
		}
	}
	return variant
}

// destOrder ranks the verdict kinds for the per-site summary: the layer
// closest to the user first.
var destOrder = []string{"dest_dns_poisoning_suspected", "dest_tcp_blackhole_suspected", "dest_tcp_reset_suspected", "dest_tcp_blocking_suspected", "dest_sni_blocking_suspected", "dest_tls_blocking_suspected", "dest_proto_blocking_suspected", "dest_legal_block_suspected", "dest_tls_interception_suspected"}

// layerOf names the per-site layer of a dest.* test and variant.
func layerOf(test, variant string) string {
	switch {
	case test == "dest.dns":
		return "dns"
	case test == "dest.tcp":
		return "tcp"
	case test == "dest.http":
		return "http"
	case test == "dest.proto":
		return "proto"
	case strings.HasPrefix(variant, "decoy:"):
		return "decoy"
	case strings.HasPrefix(variant, "absent:"):
		return "absent"
	}
	return "tls"
}

// layerValue is what a cell says about its layer: ok, the dominant failure,
// mixed:<dominant>, or for a cell that measured nothing its commonest
// result (skipped, server_error, inconclusive).
func layerValue(c Cell) string {
	switch {
	case c.Measured() == 0:
		return c.dominant()
	case c.OK == c.Measured():
		return "ok"
	case c.OK == 0:
		return c.dominant()
	}
	return "mixed:" + c.dominant()
}

// siteVerdict summarises a site no verdict kind covers. clear needs the
// deepest transport layer the site runs to have passed, the handshake with
// the real name (its own protocol's for a proto= target, TCP for a TCP-only
// one; a page fetched over TLS with the real name is that handshake passing
// too), and the DNS and HTTP layers
// that ran to have passed: not measured is not clear. A layer that failed on
// its own account makes the site degraded; one that measured nothing
// (skipped for want of an address, lost to the host's own failure, not
// assessable) leaves it inconclusive.
func siteVerdict(layers map[string]string, hasTLS bool) string {
	failed, unassessed := false, false
	for layer, v := range layers {
		switch {
		case layer == "decoy" || layer == "absent" || v == "ok":
			// A control failing on its own is not the site's problem.
		case layer == "dns" && v == client.OutcomeDNSRcode:
			return "nxdomain"
		case unmeasuredMerged[v]:
			if layer == "dns" || layer == "http" {
				unassessed = true
			}
		default:
			failed = true
		}
	}
	reached := layers["tcp"] == "ok"
	if v, ok := layers["proto"]; ok {
		reached = v == "ok"
	}
	if hasTLS {
		reached = layers["tls"] == "ok" || layers["http"] == "ok"
	}
	switch {
	case failed:
		return "degraded"
	case unassessed || !reached:
		return "inconclusive"
	}
	return "clear"
}

// Destinations builds the per-site summary from attempts, cells and verdicts.
// A layer whose every attempt was left out of the cells (flagged as part of
// an outage) reads "skipped".
func Destinations(attempts []*client.Attempt, cells []Cell, verdicts []Verdict) []Destination {
	meta := map[string]*Destination{}
	pos := map[string]int{}
	hasTLS := map[string]bool{}
	var order []string
	for _, a := range attempts {
		if !client.IsDestTest(a.TestID) || a.Detail["domain"] == "" {
			continue
		}
		d := a.Detail["domain"]
		if _, ok := meta[d]; !ok {
			meta[d] = &Destination{Domain: d, Category: a.Detail["category"], Label: a.Detail["label"], Layers: map[string]string{}}
			order = append(order, d)
			if n, err := strconv.Atoi(a.Detail["order"]); err == nil {
				pos[d] = n
			} else {
				pos[d] = 1 << 30
			}
		}
		if a.TestID == "dest.tls" && a.Variant == d {
			hasTLS[d] = true
		}
	}
	if len(order) == 0 {
		return nil
	}
	// Catalog order, then name: the summary reads like the list the scan ran.
	sort.SliceStable(order, func(i, j int) bool {
		if pos[order[i]] != pos[order[j]] {
			return pos[order[i]] < pos[order[j]]
		}
		return order[i] < order[j]
	})
	for _, c := range cells {
		if !client.IsDestTest(c.TestID) || c.TestID == "dest.nxdomain" || c.Variant == "anycast" {
			continue
		}
		dst := meta[destDomain(c.Variant)]
		if dst == nil {
			continue
		}
		dst.Layers[layerOf(c.TestID, c.Variant)] = layerValue(c)
	}
	for _, a := range attempts {
		if !client.IsDestTest(a.TestID) || a.Detail["transient"] != "true" {
			continue
		}
		if dst := meta[a.Detail["domain"]]; dst != nil {
			if l := layerOf(a.TestID, a.Variant); dst.Layers[l] == "" {
				dst.Layers[l] = client.OutcomeSkipped
			}
		}
	}
	rank := func(kind string) int {
		for i, k := range destOrder {
			if k == kind {
				return i
			}
		}
		return len(destOrder)
	}
	for _, v := range verdicts {
		if !strings.HasPrefix(v.Kind, "dest_") {
			continue
		}
		// subject: "dest.tls tcp/443 youtube.com"
		parts := strings.Fields(v.Subject)
		if len(parts) < 3 {
			continue
		}
		dst := meta[destDomain(parts[2])]
		if dst == nil {
			continue
		}
		if dst.Verdict == "" || rank(v.Kind) < rank(dst.Verdict) {
			dst.Verdict, dst.Confidence = v.Kind, v.Confidence
		}
	}
	out := make([]Destination, 0, len(order))
	for _, d := range order {
		dst := meta[d]
		if dst.Verdict == "" {
			dst.Verdict = siteVerdict(dst.Layers, hasTLS[d])
		}
		out = append(out, *dst)
	}
	return out
}
