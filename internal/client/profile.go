package client

import "strings"

// quickRule selects the plans of one test that the quick profile keeps: the
// transport, the conventional ports (nil = whatever port the catalog chose)
// and a variant prefix ("" = every variant).
type quickRule struct {
	Test      string
	Transport string
	Ports     []int
	Variant   string
}

// quickPlan is the country-neutral profile a phone runs: about forty flows
// covering the common DPI axes seen across Russia, Iran, China and other
// filtered networks. The full catalog stays the research mode: it is what
// finds a rule nobody has described yet.
//
// Every family keeps the control the classifier needs for a confident
// verdict on the same port: the opaque echo next to HTTP (transparent
// proxy), the handshake-only test next to the session test (stateful VPN
// cut), the UDP echo on the VPN ports, the random payload of obfs4 size.
var quickPlan = []quickRule{
	// Transparent proxy / split-TCP on the web ports; 4433 is the clean
	// reference for the SYN-ACK timing rule.
	{"tcp.echo", "tcp", []int{80, 8080, 443, 4433}, "cp1-64"},
	{"tcp.rtt", "tcp", []int{443}, ""},
	{"http.host", "tcp", []int{80, 8080, 443}, "benign"},
	{"http.host", "tcp", []int{80}, "trigger:"},
	// TLS on 443: the trigger name against a benign one and no name at all,
	// both protocol versions, and browser parrots from different stacks. A
	// lone Chrome cell is not enough to detect fingerprint discrimination.
	{"tls.sni", "tcp", []int{443}, "benign"},
	{"tls.sni", "tcp", []int{443}, "trigger:"},
	{"tls.sni", "tcp", []int{443}, "absent"},
	{"tls.version", "tcp", []int{443}, ""},
	{"tls.fingerprint", "tcp", []int{443}, "chrome"},
	{"tls.fingerprint", "tcp", []int{443}, "firefox"},
	{"tls.fingerprint", "tcp", []int{443}, "android"},
	// DNS: the probe's own resolver and the system one.
	{"dns.udp", "udp", []int{53}, ""},
	{"dns.system", "udp", nil, ""},
	// QUIC and Snowflake-like WebRTC on 443. STUN plus browser/Pion DTLS
	// fingerprints distinguish a blanket UDP failure from a shaped rule.
	{"quic.v1", "udp", []int{443}, ""},
	{"stun.binding", "udp", []int{443}, ""},
	{"dtls.hello", "udp", []int{443}, ""},
	// UDP baselines on the VPN ports.
	{"udp.echo", "udp", []int{443, 1194, 51820}, ""},
	// VPNs: OpenVPN with tls-auth on udp/1194 and tcp/443, WireGuard on
	// 51820, obfs4 and VLESS-Reality on 443. The session test carries the
	// verdict, the handshake-only test is its control.
	{"openvpn.reset", "udp", []int{1194}, "udp+tls-auth"},
	{"openvpn.session", "udp", []int{1194}, "udp+tls-auth+data"},
	{"openvpn.reset", "tcp", []int{443}, "tcp+tls-auth"},
	{"openvpn.session", "tcp", []int{443}, "tcp+tls-auth+data"},
	{"wireguard.init", "udp", []int{51820}, ""},
	{"wireguard.session", "udp", []int{51820}, ""},
	{"tcp.payload.random", "tcp", []int{443}, "random-2048"},
	{"obfs4.handshake", "tcp", []int{443}, ""},
	{"obfs4.session", "tcp", []int{443}, ""},
	// Vanilla Tor is still a useful protocol-shape probe in countries that
	// actively fingerprint or probe circumvention transports. The catalog
	// supplies a plain-TLS baseline, Tor TLS 1.2/1.3, and a link session on
	// this same port, avoiding the tcp/9001 port-number confound.
	{"tor.handshake", "tcp", []int{443}, ""},
	{"tor.link", "tcp", []int{443}, ""},
	{"vless.reality", "tcp", []int{443}, ""},
	{"vless.session", "tcp", []int{443}, "reality:"},
}

// QuickTests lists the test ids the quick profile draws from, in catalog
// order, for the `cpprobe tests` listing.
func QuickTests() []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range quickPlan {
		if !seen[r.Test] {
			seen[r.Test] = true
			out = append(out, r.Test)
		}
	}
	return out
}

// quickFilter keeps the plans quickPlan names, in catalog order. A rule
// whose ports the server does not offer falls back to the first plan of
// that test, transport and variant on any port; a rule whose variant the
// server cannot serve (no tls-auth key, say) falls back to the first plan
// of that test and transport on its ports, and failing both to the first
// plan of that test and transport at all, so that every family in the
// profile is exercised at least once on any server configuration.
func quickFilter(plans []Plan) []Plan {
	keep := make([]bool, len(plans))
	match := func(p Plan, r quickRule, port bool, variant bool) bool {
		if p.TestID != r.Test || p.Transport != r.Transport {
			return false
		}
		if variant && r.Variant != "" && !strings.HasPrefix(p.Variant, r.Variant) {
			return false
		}
		if port && r.Ports != nil && !containsInt(r.Ports, p.Port) {
			return false
		}
		return true
	}
	for _, r := range quickPlan {
		found := false
		for i, p := range plans {
			if match(p, r, true, true) {
				keep[i] = true
				found = true
			}
		}
		if found {
			continue
		}
		// Fallbacks, one plan each: the variant on another port, then any
		// variant on the rule's ports, then any variant on any port (a
		// server with unusual ports and without the variant's key).
		for _, relax := range []struct{ port, variant bool }{{false, true}, {true, false}, {false, false}} {
			for i, p := range plans {
				if match(p, r, relax.port, relax.variant) {
					keep[i] = true
					found = true
					break
				}
			}
			if found {
				break
			}
		}
	}
	var out []Plan
	for i, p := range plans {
		if keep[i] {
			out = append(out, p)
		}
	}
	return out
}

func containsInt(xs []int, x int) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
