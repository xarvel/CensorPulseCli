package classify

import (
	"fmt"
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
	Layers     map[string]string `json:"layers"`               // dns, tcp, tls, decoy, absent, http → ok | skipped | <dominant outcome>
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

// destVerdicts derives the family's verdicts. It is one-sided evidence, so
// nothing here is ever more than medium and every verdict names the control
// measured the same way that passed.
func destVerdicts(cells []Cell, add func(kind, subject, conf string, ev ...string)) {
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
	if haveAnycast && !anycast.pass() {
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
	dnsCells, dnsTimeouts := 0, 0
	for _, c := range cells {
		if c.TestID == "dest.dns" && c.Variant != "anycast" {
			dnsCells++
			if destFailed(c) && c.dominant() == client.OutcomeDNSTimeout {
				dnsTimeouts++
			}
		}
	}
	systemDown := dnsCells > 0 && dnsTimeouts*2 >= dnsCells
	if systemDown {
		conf := "low"
		if transportOK && dnsTimeouts >= 2 {
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

	for _, d := range domains {
		dns, haveDNS := find("dest.dns", d)
		tcp, haveTCP := find("dest.tcp", d)
		real, haveTLS := find("dest.tls", d)
		decoy, haveDecoy := find("dest.tls", "decoy:"+d)
		absent, haveAbsent := find("dest.tls", "absent:"+d)
		httpc, haveHTTP := find("dest.http", d)

		if haveDNS && destFailed(dns) {
			switch dns.dominant() {
			case client.OutcomeDNSMismatch:
				e := []string{ev(dns)}
				if dnsControl != nil {
					e = append(e, "passing control: "+ev(*dnsControl))
					add("dest_dns_poisoning_suspected", dns.Key(), capped(dns, *dnsControl), append(e, "the system resolver's answer for this name is not the one the trusted resolvers give and does not serve; a control site resolves cleanly")...)
				} else {
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

		if haveTLS && destFailed(real) && haveTCP && tcp.pass() {
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
				add("dest_sni_blocking_suspected", real.Key(), capped(real, decoy), append(e, "the real name fails while a decoy name on the very same address completes the handshake: the rule keys on the SNI")...)
			case haveDecoy && destFailed(decoy):
				e := []string{ev(real), "decoy name on the same address fails too: " + ev(decoy), "passing control: TCP connect " + ev(tcp)}
				if haveAbsent && absent.pass() {
					e = append(e, "a handshake without SNI passes: "+ev(absent)+"; the rule keys on any name, or on the handshake shape")
				}
				add("dest_tls_blocking_suspected", real.Key(), capped(real, tcp), append(e, "TCP connects but no TLS handshake with a name completes on the address: address-level or handshake-level interference, not the name alone")...)
			default:
				add("dest_tls_blocking_suspected", real.Key(), "low", ev(real), "no decoy handshake to compare with", "passing control: TCP connect "+ev(tcp))
			}
		}

		if haveHTTP && destFailed(httpc) && haveTLS && real.pass() {
			switch httpc.dominant() {
			case client.OutcomeHTTPLegalBlock:
				conf := "low"
				if httpc.Total >= 2 && httpc.OK == 0 {
					conf = "medium"
				}
				add("dest_legal_block_suspected", httpc.Key(), conf, ev(httpc), "passing control: TLS handshake "+ev(real), "HTTP 451 from the service after a clean handshake: the service refuses the region, the network did not interfere")
			case client.OutcomeCertMismatch:
				add("dest_tls_interception_suspected", httpc.Key(), "low", ev(httpc), "the certificate presented for the real name does not verify against the system roots while the handshake itself completes: interception, or a broken chain on the site")
			}
		}
	}
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
	if nx.Total >= 2 {
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
var destOrder = []string{"dest_dns_poisoning_suspected", "dest_tcp_blackhole_suspected", "dest_tcp_reset_suspected", "dest_tcp_blocking_suspected", "dest_sni_blocking_suspected", "dest_tls_blocking_suspected", "dest_legal_block_suspected", "dest_tls_interception_suspected"}

// Destinations builds the per-site summary from attempts, cells and verdicts.
func Destinations(attempts []*client.Attempt, cells []Cell, verdicts []Verdict) []Destination {
	meta := map[string]*Destination{}
	pos := map[string]int{}
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
	layerOf := func(c Cell) string {
		switch {
		case c.TestID == "dest.dns":
			return "dns"
		case c.TestID == "dest.tcp":
			return "tcp"
		case c.TestID == "dest.http":
			return "http"
		case strings.HasPrefix(c.Variant, "decoy:"):
			return "decoy"
		case strings.HasPrefix(c.Variant, "absent:"):
			return "absent"
		}
		return "tls"
	}
	for _, c := range cells {
		if !client.IsDestTest(c.TestID) || c.TestID == "dest.nxdomain" || c.Variant == "anycast" {
			continue
		}
		dst := meta[destDomain(c.Variant)]
		if dst == nil {
			continue
		}
		switch {
		case c.Total > 0 && c.OK == c.Total:
			dst.Layers[layerOf(c)] = "ok"
		case c.Total > 0 && c.OK == 0:
			dst.Layers[layerOf(c)] = c.dominant()
		default:
			dst.Layers[layerOf(c)] = "mixed:" + c.dominant()
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
			dst.Verdict = "clear"
			for layer, v := range dst.Layers {
				switch {
				case v == "ok" || v == "skipped":
				case layer == "dns" && v == client.OutcomeDNSRcode:
					dst.Verdict = "nxdomain"
				case v == client.OutcomeInconclusive, v == client.OutcomeSkipped:
					if dst.Verdict == "clear" {
						dst.Verdict = "inconclusive"
					}
				case layer == "decoy" || layer == "absent":
					// A control failing on its own is not the site's problem.
				case dst.Verdict == "clear" || dst.Verdict == "inconclusive":
					dst.Verdict = "degraded"
				}
			}
		}
		out = append(out, *dst)
	}
	return out
}
