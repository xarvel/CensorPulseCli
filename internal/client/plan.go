package client

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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
	if contains(p.Features, "tor") {
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

// Progress is called after each finished attempt.
type Progress func(done, total int, a *Attempt)

// Run executes every plan Repeat times in a random order with jitter, then
// fetches observations and merges them. It returns all attempts.
func (c *Client) Run(ctx context.Context, plans []Plan, progress Progress) ([]*Attempt, error) {
	type job struct {
		p     Plan
		round int
	}
	var jobs, tail []job
	for r := 1; r <= c.opt.Repeat; r++ {
		round := make([]job, 0, len(plans))
		for _, p := range plans {
			if p.Last {
				tail = append(tail, job{p, r})
				continue
			}
			round = append(round, job{p, r})
		}
		rand.Shuffle(len(round), func(i, j int) { round[i], round[j] = round[j], round[i] })
		jobs = append(jobs, round...)
	}
	// The tail is ordered by what it may leave behind: the Tor handshakes
	// first (every round), then the burst controls, then the bursts that are
	// meant to provoke a freeze, last of all. A provoked freeze can thus
	// only taint later chrome bursts, never a control.
	sort.SliceStable(tail, func(i, j int) bool { return tailRank(tail[i].p) < tailRank(tail[j].p) })
	total := len(jobs) + len(tail)
	var (
		mu       sync.Mutex
		attempts []*Attempt
		done     int
		poolsMu  sync.Mutex
		pools    = map[string]*sync.Mutex{}
	)
	pool := func(key string) *sync.Mutex {
		poolsMu.Lock()
		defer poolsMu.Unlock()
		m, ok := pools[key]
		if !ok {
			m = &sync.Mutex{}
			pools[key] = m
		}
		return m
	}
	worker := func(wg *sync.WaitGroup, queue chan job) {
		defer wg.Done()
		for j := range queue {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(time.Duration(250+rand.Intn(1000)) * time.Millisecond)
			a := newAttempt(j.p.TestID, j.p.Group, j.p.Role, j.p.Variant, j.p.Transport, j.p.Port, j.round)
			func() {
				if j.p.serial != "" {
					m := pool(j.p.serial)
					m.Lock()
					defer m.Unlock()
				}
				defer func() {
					if r := recover(); r != nil {
						a.fail(OutcomeServerError, fmt.Errorf("panic: %v", r))
					}
				}()
				j.p.run(ctx, c, a)
			}()
			mu.Lock()
			attempts = append(attempts, a)
			done++
			d, t := done, total
			mu.Unlock()
			if progress != nil {
				progress(d, t, a)
			}
		}
	}
	runPhase := func(js []job, parallel int) {
		var wg sync.WaitGroup
		queue := make(chan job)
		for i := 0; i < parallel; i++ {
			wg.Add(1)
			go worker(&wg, queue)
		}
		for _, j := range js {
			select {
			case queue <- j:
			case <-ctx.Done():
			}
			if ctx.Err() != nil {
				break
			}
		}
		close(queue)
		wg.Wait()
	}
	// Retry rounds: only the port groups that had a failure run again, so
	// that a failed cell and the controls the classifier compares it with on
	// the same port reach the three samples a confident verdict needs, while
	// a clean port stays at one attempt (the quick profile: 1 round + 2).
	// failedGroups lists the port groups with a failed attempt; with only
	// non-nil, just failures of those tests count.
	failedGroups := func(only map[string]bool) map[string]bool {
		out := map[string]bool{}
		mu.Lock()
		defer mu.Unlock()
		for _, a := range attempts {
			if only != nil && !only[a.TestID] {
				continue
			}
			if a.Outcome != OutcomeOK && a.Outcome != OutcomeSkipped {
				out[a.Group] = true
			}
		}
		return out
	}
	retryRounds := func(last bool, failed map[string]bool) []job {
		var retries []job
		for r := c.opt.Repeat + 1; r <= c.opt.Repeat+c.opt.Retry; r++ {
			round := make([]job, 0, len(plans))
			for _, p := range plans {
				if p.Last == last && failed[p.Group] {
					round = append(round, job{p, r})
				}
			}
			if last {
				sort.SliceStable(round, func(i, j int) bool { return tailRank(round[i].p) < tailRank(round[j].p) })
			} else {
				rand.Shuffle(len(round), func(i, j int) { round[i], round[j] = round[j], round[i] })
			}
			retries = append(retries, round...)
		}
		if len(retries) > 0 {
			mu.Lock()
			total += len(retries)
			mu.Unlock()
		}
		return retries
	}
	runPhase(jobs, c.opt.Parallel)
	if c.opt.Retry > 0 && ctx.Err() == nil {
		if retries := retryRounds(false, failedGroups(nil)); len(retries) > 0 {
			runPhase(retries, c.opt.Parallel)
		}
	}
	// The tail runs alone and serially: nothing else must be in flight while
	// a rate rule is being provoked, and one provoked freeze must not overlap
	// the next attempt.
	runPhase(tail, 1)
	// The tail's own retries, the same way but only where a tail cell itself
	// failed (its port group is shared with everything else on 443): those
	// cells (the Tor shapes, the bursts) are otherwise stuck at one sample in
	// the quick profile, and a verdict on them could never rise above low.
	if c.opt.Retry > 0 && ctx.Err() == nil && len(tail) > 0 {
		lastTests := map[string]bool{}
		for _, p := range plans {
			if p.Last {
				lastTests[p.TestID] = true
			}
		}
		if retries := retryRounds(true, failedGroups(lastTests)); len(retries) > 0 {
			runPhase(retries, 1)
		}
	}
	sort.SliceStable(attempts, func(i, j int) bool { return attempts[i].StartedAt.Before(attempts[j].StartedAt) })

	if c.standalone {
		for _, a := range attempts {
			a.Merged = mergeVerdict(a)
		}
		return attempts, nil
	}
	// Give the server a moment to close lingering flows, then merge.
	time.Sleep(1500 * time.Millisecond)
	obs, err := c.Observations(ctx)
	if err != nil {
		return attempts, fmt.Errorf("observations: %w", err)
	}
	mergeObservations(attempts, obs, c.ClockSkew)
	for _, a := range attempts {
		a.Merged = mergeVerdict(a)
	}
	return attempts, nil
}

// Remerge re-applies the merge table to attempts that already carry their
// server observation (a stored report), so that old reports benefit from a
// newer table. skew is the server clock minus the client clock at scan time;
// the burst counts that need the other alpha flows are taken from the detail
// recorded at scan time.
func Remerge(attempts []*Attempt, skew time.Duration) {
	for _, a := range attempts {
		if a.Server != nil {
			markServerDelay(a, a.Server, skew)
		}
		a.Merged = mergeVerdict(a)
	}
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

// tailRank orders the serial tail: Tor tests, then burst controls, then the
// provoking bursts.
func tailRank(p Plan) int {
	switch {
	case p.TestID == "tls.burst" && p.Role == RoleControl:
		return 1
	case p.TestID == "tls.burst":
		return 2
	}
	return 0
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
		case "tcp.packets":
			// packets_sent counts writes the kernel accepted; the cut position
			// is what the server received before the flow stalled.
			if a.Server != nil {
				if pb, err := strconv.Atoi(a.Server.Detail["partial_bytes"]); err == nil {
					if cb, err := strconv.Atoi(a.Detail["chunk_bytes"]); err == nil && cb > 0 {
						a.Detail["server_packets_seen"] = strconv.Itoa((pb + cb - 1) / cb)
					}
				}
			}
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
		if a.Nonce != "" {
			if o, ok := byNonce[a.TestID+"/"+a.Nonce]; ok {
				a.Server = o
				markServerDelay(a, o, skew)
				continue
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
				continue
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
			continue
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
