package client

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/ovpn"
)

// Plan is one scheduled attempt (before repeats).
type Plan struct {
	TestID    string
	Group     string
	Role      string // baseline|variant|control
	Variant   string
	Transport string
	Port      int
	// Last plans run after everything else, one at a time: they may leave
	// the path in a state (a rate-rule freeze) that would taint other tests.
	Last bool
	// serial names the reservation pool the plan draws from
	// ("transport/port/kind"). Attempts sharing a pool never run at the same
	// time: the server matches a native handshake to the newest unused
	// reservation of that pool, which is only unambiguous when one attempt of
	// the pool is in flight. Empty for tests that correlate by nonce.
	serial string
	run    func(ctx context.Context, c *Client, a *Attempt) *Attempt
}

// reserveKind is the reservation kind a test family uses, "" when the test
// correlates by nonce instead. It must agree with the reserve() calls in the
// tests_*.go files.
func reserveKind(test, variant string) string {
	switch {
	case strings.HasPrefix(test, "tls."), strings.HasPrefix(test, "tor.handshake"), test == "tor.link":
		return model.ParseTLS
	case strings.HasPrefix(test, "vless."):
		return model.ParseVLESS
	case test == "tcp.packets":
		if strings.HasPrefix(variant, "tls") {
			return model.ParseTLS
		}
		return model.ParseEnvelope
	case test == "tcp.payload.random", test == "udp.payload.random":
		return model.ParseUnknown
	case strings.HasPrefix(test, "openvpn."):
		return model.ParseOpenVPN
	case strings.HasPrefix(test, "wireguard."):
		return model.ParseWireGuard
	case strings.HasPrefix(test, "ikev2."):
		return model.ParseIKE
	case strings.HasPrefix(test, "l2tp."):
		return model.ParseL2TP
	case strings.HasPrefix(test, "socks5."):
		return model.ParseSOCKS5
	case strings.HasPrefix(test, "obfs4."):
		return model.ParseObfs4
	case test == "quic.v1":
		return model.ParseQUIC
	case test == "dtls.hello":
		return model.ParseDTLS
	case test == "stun.binding":
		return model.ParseSTUN
	case test == "tor.dir":
		return model.ParseHTTP
	case test == "dns.udp" && strings.HasPrefix(variant, "trigger:"):
		return model.ParseDNS
	}
	return ""
}

// Roles.
const (
	RoleBaseline = "baseline"
	RoleVariant  = "variant"
	RoleControl  = "control"
)

// Catalog builds the P0 plan list from the server parameters and the
// requested test ids (empty = everything the server enabled).
func (c *Client) Catalog() []Plan {
	want := map[string]bool{}
	for _, t := range c.Session.Tests {
		want[t] = true
	}
	if len(c.opt.Tests) > 0 {
		filtered := map[string]bool{}
		for _, t := range c.opt.Tests {
			if want[t] {
				filtered[t] = true
			}
		}
		want = filtered
	}
	p := c.Params
	trigger := c.opt.TriggerHost
	var plans []Plan
	add := func(test, role, variant, transport string, port int, run func(ctx context.Context, c *Client, a *Attempt) *Attempt) {
		if !want[test] {
			return
		}
		pl := Plan{TestID: test, Group: transport + "/" + strconv.Itoa(port), Role: role, Variant: variant, Transport: transport, Port: port, run: run}
		if k := reserveKind(test, variant); k != "" {
			pl.serial = transport + "/" + strconv.Itoa(port) + "/" + k
		}
		plans = append(plans, pl)
	}
	addLast := func(test, role, variant, transport string, port int, run func(ctx context.Context, c *Client, a *Attempt) *Attempt) {
		add(test, role, variant, transport, port, run)
		if len(plans) > 0 && plans[len(plans)-1].TestID == test && plans[len(plans)-1].Variant == variant {
			plans[len(plans)-1].Last = true
		}
	}

	for _, port := range p.TCPPorts {
		add("tcp.echo", RoleBaseline, "cp1-64", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.tcpEcho(ctx, a, 64) })
		add("tcp.payload.random", RoleControl, "random-64", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.tcpRandom(ctx, a, 64) })
	}
	if len(p.TCPPorts) > 0 {
		port := pick(p.TCPPorts, 443)
		add("tcp.rtt", RoleBaseline, "x5", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.tcpRTT(ctx, a, 5) })
	}
	for _, port := range p.UDPPorts {
		add("udp.echo", RoleBaseline, "cp1-64", "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.udpEcho(ctx, a, 64) })
		add("udp.payload.random", RoleControl, "random-64", "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.udpRandom(ctx, a, 64) })
	}
	// HTTP: on every cleartext-capable TCP port that is conventionally HTTP.
	for _, port := range preferPorts(p.TCPPorts, 80, 8080, 443) {
		add("http.host", RoleBaseline, "benign", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
			return c.httpHost(ctx, a, a.Nonce+".probe.invalid")
		})
		add("http.host", RoleVariant, "trigger:"+trigger, "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
			return c.httpHost(ctx, a, trigger)
		})
		add("http.host", RoleControl, "random", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
			return c.httpHost(ctx, a, randHex(6)+".example")
		})
	}
	for _, port := range p.DNSPorts {
		add("dns.udp", RoleBaseline, "TXT", "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.dnsUDP(ctx, a, "TXT") })
		add("dns.udp", RoleVariant, "A", "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.dnsUDP(ctx, a, "A") })
		add("dns.udp", RoleVariant, "trigger:"+trigger, "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.dnsTrigger(ctx, a, trigger) })
		add("dns.tcp", RoleVariant, "TXT", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.dnsTCP(ctx, a, "TXT") })
	}
	if p.DoTPort != 0 {
		add("dns.dot", RoleVariant, "TXT", "tcp", p.DoTPort, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.dnsDoT(ctx, a, "TXT") })
	}
	// System-resolver test needs a real delegated zone; probe.invalid never
	// resolves through public DNS.
	if c.Zone() != "probe.invalid." && contains(p.Features, "whoami") {
		add("dns.system", RoleVariant, "whoami", "udp", 0, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.dnsSystem(ctx, a) })
	}
	if contains(p.Features, "doh") && (len(c.opt.Tests) == 0 || contains(c.opt.Tests, "dns.doh")) {
		want["dns.doh"] = true
		add("dns.doh", RoleVariant, "TXT", "tcp", c.opt.ControlPort, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.dnsDoH(ctx, a, "TXT") })
	}
	for _, port := range preferPorts(p.TCPPorts, 443, 8443, 4433) {
		port := port
		sniB := func(a *Attempt) string { return "b" + randHex(6) + ".probe.invalid" }
		add("tls.version", RoleBaseline, "1.3", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
			return c.tlsEcho(ctx, a, tlsOptions{SNI: sniB(a), MinVersion: 0x0304, MaxVersion: 0x0304, ALPN: []string{"cp1"}})
		})
		add("tls.version", RoleVariant, "1.2", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
			return c.tlsEcho(ctx, a, tlsOptions{SNI: sniB(a), MinVersion: 0x0303, MaxVersion: 0x0303, ALPN: []string{"cp1"}})
		})
		add("tls.sni", RoleBaseline, "benign", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
			return c.tlsEcho(ctx, a, tlsOptions{SNI: sniB(a), ALPN: []string{"cp1"}})
		})
		add("tls.sni", RoleVariant, "trigger:"+trigger, "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
			return c.tlsEcho(ctx, a, tlsOptions{SNI: trigger, ALPN: []string{"cp1"}})
		})
		add("tls.sni", RoleControl, "absent", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
			return c.tlsEcho(ctx, a, tlsOptions{SNI: "", ALPN: []string{"cp1"}})
		})
		for _, sni := range c.opt.SNIList {
			sni := sni
			add("tls.sni", RoleVariant, "list:"+sni, "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
				return c.tlsEcho(ctx, a, tlsOptions{SNI: sni, ALPN: []string{"cp1"}})
			})
		}
		for _, alpn := range []string{"http/1.1", "h2", "cp1", "none"} {
			alpn := alpn
			role := RoleVariant
			if alpn == "http/1.1" {
				role = RoleBaseline
			}
			add("tls.alpn", role, alpn, "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
				o := tlsOptions{SNI: sniB(a)}
				if alpn == "none" {
					o.NoALPN = true
				} else {
					o.ALPN = []string{alpn}
				}
				return c.tlsEcho(ctx, a, o)
			})
		}
		for _, fp := range fingerprintPlan {
			fp := fp
			role := RoleVariant
			if fp == "chrome" {
				role = RoleBaseline
			}
			add("tls.fingerprint", role, fp, "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
				return c.tlsEcho(ctx, a, tlsOptions{SNI: sniB(a), Fingerprint: fp, ALPN: []string{"http/1.1"}})
			})
		}
	}
	// Small-packet flows: the tcp.echo envelope in 2-byte segments (plain and
	// inside TLS) and a run of small UDP envelopes. Their control is the echo
	// test on the same port, which moves the same bytes in one packet. A rule
	// that counts packets per flow (rather than bytes) trips here and nowhere
	// else; a byte rule trips in tcp.bulk and not here.
	if len(p.TCPPorts) > 0 {
		port := preferPorts(p.TCPPorts, 80, 8080)[0]
		add("tcp.packets", RoleVariant, "plain-2B", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
			return c.tcpPackets(ctx, a, packetsOptions{})
		})
		tport := pick(p.TCPPorts, 443)
		add("tcp.packets", RoleVariant, "tls-2B", "tcp", tport, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
			return c.tcpPackets(ctx, a, packetsOptions{TLS: true, SNI: "b" + randHex(6) + ".probe.invalid"})
		})
	}
	if len(p.UDPPorts) > 0 {
		port := pick(p.UDPPorts, 443)
		add("udp.packets", RoleVariant, "cp1-32x32", "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
			return c.udpPackets(ctx, a, 32, 32)
		})
	}
	// Tor. tor.dir and obfs4 run with everything else; the TLS-shaped ones
	// run in the serial tail because the server picks the certificate from
	// the single pending reservation.
	// The feature is advertised whatever the port list; without a TCP port
	// there is nothing to pick an ORPort from.
	if contains(p.Features, "tor") && len(p.TCPPorts) > 0 {
		for _, port := range preferPorts(p.TCPPorts, 9030, 80) {
			add("tor.dir", RoleVariant, "consensus-microdesc", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.torDir(ctx, a) })
		}
		// The four TLS 1.2 variants put both plaintext features (hello shape,
		// certificate) on the wire and vary them independently; the @1.3
		// variant is the modern shape, where only the ClientHello is visible.
		orPort := pick(p.TCPPorts, 9001)
		allTorHandshakes := []torOptions{{}, {TorCert: true}, {TorHello: true}, {TorHello: true, TorCert: true}, {TorHello: true, TorCert: true, TLS13: true}}
		addTorHandshake := func(port int, options []torOptions) {
			for _, o := range options {
				o := o
				role := RoleVariant
				if !o.TorHello && !o.TorCert {
					role = RoleBaseline
				}
				addLast("tor.handshake", role, o.variant(), "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.torHandshake(ctx, a, o) })
			}
		}
		addTorHandshake(orPort, allTorHandshakes)
		addTorLink := func(port int) {
			addLast("tor.link", RoleVariant, "tor-hello+tor-cert", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
				return c.torHandshake(ctx, a, torOptions{TorHello: true, TorCert: true, Link: true})
			})
		}
		addTorLink(orPort)
		if p443 := pick(p.TCPPorts, 443); p443 != orPort {
			// On 443 keep the minimum differential set that answers the phone
			// profile's question without importing the whole research matrix:
			// plain TLS, Tor-shaped TLS 1.2 and modern TLS 1.3, plus a link.
			addTorHandshake(p443, []torOptions{{}, {TorHello: true, TorCert: true}, {TorHello: true, TorCert: true, TLS13: true}})
			addTorLink(p443)
		}
	}
	if contains(p.Features, "obfs4") {
		for _, port := range preferPorts(p.TCPPorts, 8388, 443) {
			// A random payload of obfs4 handshake size on the same port, so
			// that a rule on length / segment count is told from one on the
			// obfs4 shape itself (the 64-byte random control is too small).
			add("tcp.payload.random", RoleControl, "random-2048", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.tcpRandom(ctx, a, 2048) })
			add("obfs4.handshake", RoleVariant, "ntor-shaped", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.obfs4Handshake(ctx, a, false) })
			add("obfs4.session", RoleVariant, "ntor-shaped", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.obfs4Handshake(ctx, a, true) })
		}
	}
	// WebRTC as Snowflake uses it: STUN first, then DTLS with the pion
	// fingerprint; browser fingerprints are the controls.
	if contains(p.Features, "stun") {
		for _, port := range preferPorts(p.UDPPorts, 3478, 443) {
			add("stun.binding", RoleVariant, "rfc5389", "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.stunBinding(ctx, a) })
		}
	}
	if contains(p.Features, "dtls") {
		for _, port := range preferPorts(p.UDPPorts, 3478, 443) {
			for _, fp := range []string{"firefox-138", "pion", "chrome-136"} {
				fp := fp
				role := RoleVariant
				if fp == "firefox-138" {
					role = RoleBaseline
				}
				add("dtls.hello", role, fp, "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.dtlsHello(ctx, a, fp) })
			}
		}
	}
	// Rate rule on TLS handshakes: N parallel ClientHellos to one name, then
	// one to another name, then one without SNI. Runs last, because a
	// triggered freeze lasts minutes and would taint other TLS tests. Two
	// parrots: the burst with the browser fingerprint the rule is known to
	// act on, and the same burst with one it is known to ignore.
	if len(p.TCPPorts) > 0 {
		port := pick(p.TCPPorts, 443)
		n := c.opt.BurstN
		addLast("tls.burst", RoleVariant, fmt.Sprintf("chrome-x%d", n), "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
			return c.tlsBurst(ctx, a, burstOptions{N: n, Fingerprint: "chrome"})
		})
		addLast("tls.burst", RoleControl, fmt.Sprintf("firefox-x%d", n), "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
			return c.tlsBurst(ctx, a, burstOptions{N: n, Fingerprint: "firefox"})
		})
	}
	// Long transfers: plain HTTP and TLS, both directions. The TLS upload with
	// the trigger SNI (and every --sni-list entry) is the "does this name get
	// more than N kilobytes" question.
	if contains(p.Features, "bulk") {
		kb := c.opt.BulkKB
		for _, port := range preferPorts(p.TCPPorts, 80, 8080) {
			add("tcp.bulk", RoleBaseline, "up-plain", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
				return c.bulkTransfer(ctx, a, bulkOptions{Dir: "up", TotalKB: kb})
			})
			add("tcp.bulk", RoleVariant, "down-plain", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
				return c.bulkTransfer(ctx, a, bulkOptions{Dir: "down", TotalKB: kb})
			})
		}
		for _, port := range preferPorts(p.TCPPorts, 443, 8443, 4433) {
			port := port
			add("tcp.bulk", RoleBaseline, "up-tls", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
				return c.bulkTransfer(ctx, a, bulkOptions{Dir: "up", TLS: true, SNI: "b" + randHex(6) + ".probe.invalid", TotalKB: kb})
			})
			add("tcp.bulk", RoleVariant, "down-tls", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
				return c.bulkTransfer(ctx, a, bulkOptions{Dir: "down", TLS: true, SNI: "b" + randHex(6) + ".probe.invalid", TotalKB: kb})
			})
			add("tcp.bulk", RoleVariant, "up-tls:trigger:"+trigger, "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
				return c.bulkTransfer(ctx, a, bulkOptions{Dir: "up", TLS: true, SNI: trigger, TotalKB: kb})
			})
			for _, sni := range c.opt.SNIList {
				sni := sni
				add("tcp.bulk", RoleVariant, "up-tls:list:"+sni, "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
					return c.bulkTransfer(ctx, a, bulkOptions{Dir: "up", TLS: true, SNI: sni, TotalKB: kb})
				})
			}
		}
	}
	for _, port := range p.QUICPorts {
		port := port
		add("quic.v1", RoleVariant, "h3", "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
			return c.quicV1(ctx, a, "q"+randHex(6)+".probe.invalid")
		})
	}
	// OpenVPN: the plain reset and the tls-auth one (HMAC block + replay
	// fields on every control packet, 42-byte reset) are separate variants
	// on both transports, so that a rule keyed on the reset's shape shows as
	// a differential. The tls-auth variants need the key the server hands
	// out in params.
	ovpnAuths := []ovpn.Auth{ovpn.AuthNone}
	if p.OVPNTLSAuthKey != "" {
		ovpnAuths = append(ovpnAuths, ovpn.AuthTLS)
	}
	ovpnVariant := func(transport string, auth ovpn.Auth, session bool) string {
		v := transport
		if auth == ovpn.AuthTLS {
			v += "+tls-auth"
		} else if session {
			v += "+control"
		}
		if session {
			v += "+data"
		}
		return v
	}
	for _, auth := range ovpnAuths {
		auth := auth
		for _, port := range preferPorts(p.TCPPorts, 1194, 443) {
			add("openvpn.reset", RoleVariant, ovpnVariant("tcp", auth, false), "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
				return c.openvpnTCP(ctx, a, ovpnOptions{auth: auth})
			})
		}
		for _, port := range preferPorts(p.UDPPorts, 1194, 443) {
			add("openvpn.reset", RoleVariant, ovpnVariant("udp", auth, false), "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
				return c.openvpnUDP(ctx, a, ovpnOptions{auth: auth})
			})
		}
	}
	for _, port := range preferPorts(p.UDPPorts, 51820, 443) {
		add("wireguard.init", RoleVariant, "noise-ik", "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.wireguardInit(ctx, a) })
	}
	// Session tests: the same handshakes followed by data. Their control is
	// the handshake-only test on the same port: "init passes, session is cut"
	// is the stateful-blocking signature.
	if contains(p.Features, "vpn-session") {
		for _, port := range preferPorts(p.UDPPorts, 51820, 443) {
			add("wireguard.session", RoleVariant, "noise-ik+data", "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.wireguardSession(ctx, a) })
		}
		for _, auth := range ovpnAuths {
			auth := auth
			for _, port := range preferPorts(p.TCPPorts, 1194, 443) {
				add("openvpn.session", RoleVariant, ovpnVariant("tcp", auth, true), "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
					return c.openvpnTCP(ctx, a, ovpnOptions{auth: auth, session: true})
				})
			}
			for _, port := range preferPorts(p.UDPPorts, 1194, 443) {
				add("openvpn.session", RoleVariant, ovpnVariant("udp", auth, true), "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
					return c.openvpnUDP(ctx, a, ovpnOptions{auth: auth, session: true})
				})
			}
		}
	}
	if contains(p.Features, "ike") {
		for _, port := range preferPorts(p.UDPPorts, 500) {
			add("ikev2.init", RoleVariant, "plain", "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.ikev2(ctx, a, false) })
			add("ikev2.session", RoleVariant, "plain", "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.ikev2(ctx, a, false) })
		}
		for _, port := range preferPorts(p.UDPPorts, 4500) {
			add("ikev2.init", RoleVariant, "nat-t", "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.ikev2(ctx, a, true) })
			add("ikev2.session", RoleVariant, "nat-t", "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.ikev2(ctx, a, true) })
		}
	}
	if contains(p.Features, "l2tp") {
		for _, port := range preferPorts(p.UDPPorts, 1701) {
			add("l2tp.init", RoleVariant, "v2", "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.l2tpTunnel(ctx, a) })
			add("l2tp.session", RoleVariant, "v2", "udp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.l2tpTunnel(ctx, a) })
		}
	}
	if contains(p.Features, "socks5") {
		for _, port := range preferPorts(p.TCPPorts, 1080) {
			add("socks5.connect", RoleBaseline, "noauth", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.socks5Connect(ctx, a, false) })
			add("socks5.connect", RoleVariant, "userpass", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.socks5Connect(ctx, a, true) })
			add("socks5.session", RoleVariant, "noauth", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.socks5Connect(ctx, a, false) })
		}
	}
	if contains(p.Features, "vless") {
		reality := c.opt.RealitySNI
		for _, port := range preferPorts(p.TCPPorts, 443, 4433) {
			port := port
			add("vless.reality", RoleVariant, "reality:"+reality, "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.vlessReality(ctx, a, reality) })
			add("vless.reality", RoleControl, "benign", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
				return c.vlessReality(ctx, a, "b"+randHex(6)+".probe.invalid")
			})
			add("vless.session", RoleVariant, "reality:"+reality, "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.vlessReality(ctx, a, reality) })
			add("vless.session", RoleControl, "benign", "tcp", port, func(ctx context.Context, c *Client, a *Attempt) *Attempt {
				return c.vlessReality(ctx, a, "b"+randHex(6)+".probe.invalid")
			})
		}
	}
	if c.opt.Profile == "quick" {
		plans = quickFilter(plans)
	}
	// Real destinations ride along with every profile and are the whole plan
	// of a standalone scan.
	plans = append(plans, c.destPlans(c.destWanted())...)
	return plans
}

// handshakeTestOf maps a session test to the handshake-only test that is its
// control on the same port.
func handshakeTestOf(sessionTest string) string {
	switch sessionTest {
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

// preferPorts returns the conventional ports that the server actually offers,
// or the first offered port when none of them is present, so that every
// protocol family is exercised at least once on any configuration.
func preferPorts(offered []int, preferred ...int) []int {
	out := intersect(offered, preferred)
	if len(out) == 0 && len(offered) > 0 {
		out = offered[:1]
	}
	return out
}

func pick(ports []int, preferred int) int {
	for _, p := range ports {
		if p == preferred {
			return p
		}
	}
	return ports[0]
}

func intersect(a, b []int) []int {
	var out []int
	for _, x := range a {
		for _, y := range b {
			if x == y {
				out = append(out, x)
			}
		}
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
