package classify

import (
	"strings"

	"github.com/xarvel/CensorPulseCli/internal/client"
)

// The scenarios are small on purpose: each one reaches a rule (or a branch of
// its evidence) with as few attempts as the rule allows. The transient-outage
// and dest.* ones are larger because their rules need that much to fire.
var goldenScenarios = []goldenScenario{
	// Control plane and the empty result.
	{name: "probe_unreachable", mode: modeUnreachable, verdicts: []string{"probe_unreachable:high"},
		attempts: func() []*client.Attempt {
			return x(3, mk("tcp.echo", bl, "cp1-64", "tcp", 443, "connect_timeout", "uplink_drop_or_route_failure", false))
		}},
	// A mixed cell that still passes is no finding; cancelled attempts and
	// attempts a stored report already carries as transient stay out of the cells.
	{name: "clean", mode: modeServer, verdicts: nil,
		attempts: func() []*client.Attempt {
			return all(
				x(3, connect(echo("tcp", 443), 40)),
				x(3, okA("tls.sni", bl, "benign", "tcp", 443)),
				x(2, okA("tls.sni", vr, "trigger:www.youtube.com", "tcp", 443)),
				one(lost("tls.sni", vr, "trigger:www.youtube.com", "tcp", 443)),
				one(detail(lost("tcp.echo", bl, "cp1-64", "tcp", 443), "cancelled", "true")),
				one(detail(lost("tcp.echo", bl, "cp1-64", "tcp", 443), "transient", "true")),
			)
		}},

	// Rule 1.
	{name: "endpoint_blocking", mode: modeServer, verdicts: []string{"endpoint_blocking_suspected:medium"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, mk("tcp.echo", bl, "cp1-64", "tcp", 443, "connect_timeout", "uplink_drop_or_route_failure", false)),
				x(2, mk("tcp.echo", bl, "cp1-64", "tcp", 80, "connect_timeout", "uplink_drop_or_route_failure", false)),
				x(3, lost("udp.echo", bl, "cp1-64", "udp", 443)),
			)
		}},

	// Rule 2, with the confidence ladder: 3/3 against a clean control is
	// high, two attempts or a control that lost a round medium, one attempt low.
	{name: "port_blocking_ladder", mode: modeServer,
		verdicts: []string{"port_blocking_suspected:high", "port_blocking_suspected:medium", "port_blocking_suspected:low", "port_blocking_suspected:medium"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, echo("tcp", 1194)),
				x(3, lost("tcp.echo", bl, "cp1-64", "tcp", 80)),
				x(2, lost("tcp.echo", bl, "cp1-64", "tcp", 8080)),
				x(1, lost("tcp.echo", bl, "cp1-64", "tcp", 8388)),
				// Half ok is neither a pass nor a fail: no verdict either way.
				one(echo("tcp", 9001), lost("tcp.echo", bl, "cp1-64", "tcp", 9001)),
				x(2, echo("udp", 443)),
				one(lost("udp.echo", bl, "cp1-64", "udp", 443)),
				x(3, lost("udp.echo", bl, "cp1-64", "udp", 51820)),
			)
		}},
	// Rule 2, the other branch: an application protocol passes on the port.
	{name: "transparent_proxy", mode: modeServer,
		verdicts: []string{"transparent_proxy_suspected:high", "transparent_proxy_suspected:medium", "transparent_proxy_suspected:low"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, echo("tcp", 1194)),
				// The server answered, the answer was dropped.
				x(3, connect(mk("tcp.echo", bl, "cp1-64", "tcp", 80, "payload_timeout", "downlink_drop", true), 3.0)),
				x(3, connect(okA("http.host", bl, "benign", "tcp", 80), 3.2)),
				// The path held the flow; no connect times on this port.
				x(2, mk("tcp.echo", bl, "cp1-64", "tcp", 8080, "payload_timeout", "uplink_delayed_past_deadline", true)),
				x(2, okA("tls.sni", bl, "benign", "tcp", 8080)),
				// UDP: neither mechanism line, no connect line.
				x(3, echo("udp", 443)),
				one(lost("udp.echo", bl, "cp1-64", "udp", 53)),
				one(okA("dns.udp", bl, "TXT", "udp", 53)),
			)
		}},

	// Rule 8.
	{name: "synack_ladder", mode: modeServer,
		verdicts: []string{"synack_local_termination_suspected:medium", "synack_local_termination_suspected:low", "synack_spoof_signal:low"},
		attempts: func() []*client.Attempt {
			rtt := func(port int, suspect string) *client.Attempt {
				// tcp.rtt connect times never enter the cross-port medians.
				return detail(connect(okA("tcp.rtt", bl, "x5", "tcp", port), 500), "synack_suspect", suspect, "connect_min_ms", "1.9", "payload_min_ms", "170", "connect_payload_ratio", "0.01")
			}
			return all(
				x(2, connect(echo("tcp", 80), 3)),
				x(2, connect(echo("tcp", 443), 3)),
				x(2, connect(echo("tcp", 1194), 110)),
				x(2, connect(echo("tcp", 4433), 110)),
				x(2, connect(echo("tcp", 8388), 110)),
				// Exactly a quarter of the reference is not "a fraction" yet.
				x(2, connect(echo("tcp", 8443), 27.5)),
				one(rtt(443, "true"), rtt(8388, "true"), rtt(80, "false")),
			)
		}},
	// The fast port must also be 20 ms faster than the reference.
	{name: "synack_short_path", mode: modeServer, verdicts: []string{"synack_spoof_signal:low"},
		attempts: func() []*client.Attempt {
			return all(
				x(2, connect(echo("tcp", 80), 5)),
				x(2, connect(echo("tcp", 443), 24)),
				x(2, connect(echo("tcp", 1194), 24)),
				x(2, connect(echo("tcp", 4433), 24)),
				one(detail(okA("tcp.rtt", bl, "x5", "tcp", 80), "synack_suspect", "true", "connect_min_ms", "4.8", "payload_min_ms", "49", "connect_payload_ratio", "0.10")),
			)
		}},
	// On a LAN every port is fast: the reference is under 20 ms.
	{name: "synack_lan", mode: modeServer, verdicts: nil,
		attempts: func() []*client.Attempt {
			return all(
				x(2, connect(echo("tcp", 80), 0.1)),
				x(2, connect(echo("tcp", 443), 0.4)),
				x(2, connect(echo("tcp", 1194), 0.4)),
			)
		}},
	// Ordering: rule 8 reads rule 2's transparent_proxy_suspected.
	{name: "transparent_proxy_corroborates_synack", mode: modeServer,
		verdicts: []string{"synack_local_termination_suspected:medium", "transparent_proxy_suspected:high"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, connect(mk("tcp.echo", bl, "cp1-64", "tcp", 80, "payload_timeout", "downlink_drop", true), 3)),
				x(3, connect(okA("http.host", bl, "benign", "tcp", 80), 3)),
				x(2, connect(echo("tcp", 1194), 110)),
				x(3, connect(echo("tcp", 4433), 110)),
				x(2, connect(echo("tcp", 8388), 110)),
			)
		}},

	// Rule 3. A native handshake under a UDP block gets no verdict of its own.
	{name: "udp_blocking", mode: modeServer, verdicts: []string{"udp_blocking_suspected:medium"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, echo("tcp", 443)),
				x(3, echo("tcp", 80)),
				x(3, lost("udp.echo", bl, "cp1-64", "udp", 443)),
				x(3, lost("udp.echo", bl, "cp1-64", "udp", 51820)),
				one(lost("wireguard.init", vr, "noise-ik", "udp", 51820)),
			)
		}},

	// Rule 4.
	{name: "protocol_blocking", mode: modeServer,
		verdicts: []string{"protocol_blocking_suspected:low", "protocol_blocking_suspected:medium", "protocol_blocking_suspected:high"},
		attempts: func() []*client.Attempt {
			return all(
				// Echo and random pass, the handshake does not. The session
				// that fails with it is covered by the handshake's verdict.
				x(3, echo("udp", 51820)),
				x(3, random("udp", 51820)),
				x(3, lost("wireguard.init", vr, "noise-ik", "udp", 51820)),
				x(3, lost("wireguard.session", vr, "noise-ik+data", "udp", 51820)),
				// No random control on the port.
				x(3, echo("udp", 443)),
				x(2, mk("quic.v1", vr, "h3", "udp", 443, "quic_no_response", "uplink_drop_or_route_failure", false)),
				// Two variants of one family: reported once, for the family.
				one(echo("udp", 1194)),
				one(lost("openvpn.reset", vr, "udp+tls-auth", "udp", 1194)),
				one(lost("openvpn.reset", vr, "udp+tls-crypt", "udp", 1194)),
			)
		}},
	// A handshake that is neither a pass nor a fail does not cover its session.
	{name: "protocol_blocking_mixed_handshake", mode: modeServer, verdicts: []string{"protocol_blocking_suspected:high"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, echo("udp", 51820)),
				one(okA("wireguard.init", vr, "noise-ik", "udp", 51820), lost("wireguard.init", vr, "noise-ik", "udp", 51820)),
				x(3, lost("wireguard.session", vr, "noise-ik+data", "udp", 51820)),
			)
		}},
	{name: "ipsec_alg_confound", mode: modeServer, verdicts: []string{"protocol_blocking_suspected:high", "protocol_blocking_suspected:medium"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, echo("udp", 500)),
				x(3, random("udp", 500)),
				x(3, lost("ikev2.init", vr, "plain", "udp", 500)),
				x(2, echo("udp", 1701)),
				x(2, lost("l2tp.init", vr, "v2", "udp", 1701)),
			)
		}},
	// Behind NAT the ALG explanation is live: never high.
	{name: "ipsec_behind_nat", mode: modeServer, verdicts: []string{"protocol_blocking_suspected:medium", "protocol_blocking_suspected:medium"},
		attempts: func() []*client.Attempt {
			nat := func(a *client.Attempt, left, saw int) *client.Attempt {
				a.SrcPort, a.Server.SrcPort = left, saw
				return a
			}
			return all(
				one(echo("udp", 500), nat(echo("udp", 500), 46762, 19355), nat(echo("udp", 500), 46763, 19356)),
				x(3, random("udp", 500)),
				x(3, lost("ikev2.init", vr, "plain", "udp", 500)),
				x(2, echo("udp", 1701)),
				x(2, lost("l2tp.init", vr, "v2", "udp", 1701)),
			)
		}},
	// The random control fails too: nothing can be said about the protocol.
	// A failing cell of control role is never a protocol finding.
	{name: "control_failed_inconclusive", mode: modeServer, verdicts: []string{"control_failed_inconclusive:low"},
		attempts: func() []*client.Attempt {
			return all(
				x(2, echo("udp", 443)),
				x(2, lost("udp.payload.random", ct, "random-64", "udp", 443)),
				x(2, mk("quic.v1", vr, "h3", "udp", 443, "quic_no_response", "uplink_drop_or_route_failure", false)),
				x(2, echo("tcp", 443)),
				x(2, lost("tcp.payload.random", ct, "random-64", "tcp", 443)),
				x(2, lost("vless.reality", ct, "benign", "tcp", 443)),
			)
		}},

	// Rule 5: the kind follows the test family.
	{name: "variants_tls", mode: modeServer,
		verdicts: []string{"alpn_policy_suspected:low", "fingerprint_blocking_suspected:medium", "sni_or_host_blocking_suspected:high", "sni_or_host_policy_suspected:medium", "tls_version_policy_suspected:low"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, okA("tls.sni", bl, "benign", "tcp", 443)),
				x(3, mk("tls.sni", vr, "trigger:www.youtube.com", "tcp", 443, "midstream_reset", "rst_injected_or_path_reset", false)),
				x(2, lost("tls.sni", ct, "absent", "tcp", 443)),
				one(okA("tls.alpn", bl, "http/1.1", "tcp", 443), lost("tls.alpn", vr, "h2", "tcp", 443)),
				one(okA("tls.version", bl, "1.3", "tcp", 443), mk("tls.version", vr, "1.2", "tcp", 443, "tls_alert", "uplink_drop_or_route_failure", false)),
				x(2, okA("tls.fingerprint", bl, "chrome", "tcp", 443)),
				x(2, lost("tls.fingerprint", vr, "firefox", "tcp", 443)),
			)
		}},
	{name: "variants_http_host", mode: modeServer, verdicts: []string{"sni_or_host_blocking_suspected:medium", "sni_or_host_policy_suspected:low"},
		attempts: func() []*client.Attempt {
			return all(
				x(2, okA("http.host", bl, "benign", "tcp", 80)),
				x(2, lost("http.host", vr, "trigger:www.youtube.com", "tcp", 80)),
				one(lost("http.host", ct, "random", "tcp", 80)),
			)
		}},
	{name: "variants_other", mode: modeServer,
		verdicts: []string{"dns_qtype_policy_suspected:low", "dtls_fingerprint_blocking_suspected:low", "sni_ip_mismatch_blocking_suspected:low", "socks5_auth_policy_suspected:low", "variant_blocking_suspected:low", "variant_blocking_suspected:low"},
		attempts: func() []*client.Attempt {
			return all(
				one(okA("dns.udp", bl, "TXT", "udp", 53), mk("dns.udp", vr, "A", "udp", 53, "dns_timeout", "uplink_drop_or_route_failure", false)),
				one(okA("socks5.connect", bl, "noauth", "tcp", 1080), lost("socks5.connect", vr, "userpass", "tcp", 1080)),
				one(okA("dtls.hello", bl, "firefox-138", "udp", 3478), lost("dtls.hello", vr, "pion", "udp", 3478)),
				// vless has no baseline role: the benign control is the baseline.
				one(okA("vless.reality", ct, "benign", "tcp", 443), lost("vless.reality", vr, "reality:www.microsoft.com", "tcp", 443)),
				// ... and when it is the control that fails, the generic kind.
				one(lost("vless.reality", ct, "benign", "tcp", 8443), okA("vless.reality", vr, "reality:www.microsoft.com", "tcp", 8443)),
				// A family without a kind of its own and without a baseline role.
				one(lost("openvpn.reset", vr, "udp+tls-auth", "udp", 1194), okA("openvpn.reset", vr, "udp+tls-crypt", "udp", 1194)),
			)
		}},
	// The nominal baseline fails: the first passing variant is the control.
	// The failing baseline itself is never the subject of a variant verdict.
	{name: "variant_alternate_baseline", mode: modeServer, verdicts: []string{"fingerprint_blocking_suspected:high"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, echo("tcp", 443)),
				x(3, lost("tls.fingerprint", bl, "chrome", "tcp", 443)),
				x(3, lost("tls.fingerprint", vr, "firefox", "tcp", 443)),
				x(3, okA("tls.fingerprint", vr, "edge", "tcp", 443)),
				x(3, okA("tls.fingerprint", vr, "golang", "tcp", 443)),
			)
		}},
	// tor.handshake: which plaintext feature the rule keys on.
	{name: "tor_handshake_hello_or_cert", mode: modeServer,
		verdicts: []string{"tor_handshake_blocking_suspected:low", "tor_handshake_blocking_suspected:low", "tor_handshake_blocking_suspected:low", "tor_handshake_blocking_suspected:low", "tor_handshake_blocking_suspected:low"},
		attempts: func() []*client.Attempt {
			return all(
				// Both features fail alone.
				one(okA("tor.handshake", bl, "go-hello+probe-cert", "tcp", 9001)),
				one(lost("tor.handshake", vr, "go-hello+tor-cert", "tcp", 9001)),
				one(lost("tor.handshake", vr, "tor-hello+probe-cert", "tcp", 9001)),
				one(lost("tor.handshake", vr, "tor-hello+tor-cert", "tcp", 9001)),
				// The ClientHello alone fails.
				one(okA("tor.handshake", bl, "go-hello+probe-cert", "tcp", 443)),
				one(okA("tor.handshake", vr, "go-hello+tor-cert", "tcp", 443)),
				one(lost("tor.handshake", vr, "tor-hello+probe-cert", "tcp", 443)),
				one(lost("tor.handshake", vr, "tor-hello+tor-cert", "tcp", 443)),
			)
		}},
	{name: "tor_handshake_cert_or_both", mode: modeServer,
		verdicts: []string{"tor_handshake_blocking_suspected:low", "tor_handshake_blocking_suspected:low", "tor_handshake_blocking_suspected:low", "tor_handshake_blocking_suspected:low", "tor_handshake_blocking_suspected:low"},
		attempts: func() []*client.Attempt {
			return all(
				// The certificate alone fails.
				one(okA("tor.handshake", bl, "go-hello+probe-cert", "tcp", 9001)),
				one(lost("tor.handshake", vr, "go-hello+tor-cert", "tcp", 9001)),
				one(okA("tor.handshake", vr, "tor-hello+probe-cert", "tcp", 9001)),
				one(lost("tor.handshake", vr, "tor-hello+tor-cert", "tcp", 9001)),
				// Only the full shape fails; the @1.3 variant gets no feature line.
				one(okA("tor.handshake", bl, "go-hello+probe-cert", "tcp", 443)),
				one(okA("tor.handshake", vr, "go-hello+tor-cert", "tcp", 443)),
				one(okA("tor.handshake", vr, "tor-hello+probe-cert", "tcp", 443)),
				one(lost("tor.handshake", vr, "tor-hello+tor-cert", "tcp", 443)),
				one(lost("tor.handshake", vr, "tor-hello+tor-cert@1.3", "tcp", 443)),
				// The single-feature variants did not run: no feature line.
				one(okA("tor.handshake", bl, "go-hello+probe-cert", "tcp", 8443)),
				one(lost("tor.handshake", vr, "tor-hello+tor-cert", "tcp", 8443)),
			)
		}},

	// Rule 5b. The offsets are read from every attempt of the cell, the
	// transient ones included: the stored report's 900 KB moves the median.
	{name: "bulk_cut", mode: modeServer,
		verdicts: []string{"bulk_transfer_cut_suspected:high", "sni_bulk_cut_suspected:medium", "variant_blocking_suspected:high", "variant_blocking_suspected:medium"},
		attempts: func() []*client.Attempt {
			down := func(kb string) *client.Attempt {
				return detail(mk("tcp.bulk", vr, "down-plain", "tcp", 443, "bulk_stall", "downlink_drop", true), "bulk_cut_kb", kb)
			}
			return all(
				x(3, echo("tcp", 443)),
				x(3, okA("tcp.bulk", bl, "up-plain", "tcp", 443)),
				one(down("16"), down("18"), down("16"), detail(down("900"), "transient", "true")),
				// No offset recorded; the reset is not reported a second time by rule 7.
				x(2, mk("tcp.bulk", vr, "up-tls:trigger:www.youtube.com", "tcp", 443, "bulk_reset", "rst_injected_or_path_reset", true)),
				// No echo on the port: no control, no verdict.
				one(mk("tcp.bulk", bl, "up-plain", "tcp", 8443, "bulk_stall", "downlink_drop", true)),
			)
		}},
	{name: "bulk_cut_whole_family", mode: modeServer,
		verdicts: []string{"bulk_transfer_cut_suspected:high", "protocol_blocking_suspected:high", "sni_bulk_cut_suspected:high"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, echo("tcp", 443)),
				x(3, detail(mk("tcp.bulk", bl, "up-plain", "tcp", 443, "bulk_stall", "downlink_drop", true), "bulk_cut_kb", "64")),
				x(3, detail(mk("tcp.bulk", vr, "up-tls:list:example.com", "tcp", 443, "bulk_stall", "downlink_drop", true), "bulk_cut_kb", "64")),
			)
		}},

	// Rule 5b', cross-checked against tcp.bulk on the same port.
	{name: "packet_count_cut", mode: modeServer,
		verdicts: []string{"bulk_transfer_cut_suspected:low", "packet_count_cut_suspected:high", "packet_count_cut_suspected:low", "packet_count_cut_suspected:medium", "packet_count_cut_suspected:low", "protocol_blocking_suspected:low"},
		attempts: func() []*client.Attempt {
			cut := func(test, variant, tr string, port int, kv ...string) *client.Attempt {
				return detail(mk(test, vr, variant, tr, port, "packets_cut", "downlink_drop_after_handshake", true), kv...)
			}
			return all(
				// tcp.bulk cut on the same port: a packet count.
				x(3, echo("tcp", 443)),
				one(cut("tcp.packets", "plain-2B", "tcp", 443, "packets_sent", "24", "packets_planned", "64")),
				one(cut("tcp.packets", "plain-2B", "tcp", 443, "packets_sent", "26", "packets_planned", "64")),
				one(cut("tcp.packets", "plain-2B", "tcp", 443, "packets_sent", "25", "packets_planned", "64")),
				one(mk("tcp.bulk", bl, "up-plain", "tcp", 443, "bulk_stall", "downlink_drop", true)),
				// tcp.bulk passes on the same port; no counts recorded.
				one(echo("tcp", 80), cut("tcp.packets", "plain-2B", "tcp", 80), okA("tcp.bulk", bl, "up-plain", "tcp", 80)),
				// UDP counts answered datagrams ...
				x(2, echo("udp", 443)),
				x(2, cut("udp.packets", "cp1-32x32", "udp", 443, "packets_sent", "32", "packets_acked", "20", "packets_planned", "32")),
				// ... and falls back to the sent count when none was recorded.
				one(echo("udp", 51820), cut("udp.packets", "cp1-32x32", "udp", 51820, "packets_sent", "32", "packets_planned", "32")),
				// No echo on the port: no control, no verdict.
				one(cut("tcp.packets", "plain-2B", "tcp", 8080, "packets_sent", "25", "packets_planned", "64")),
			)
		}},

	// Rule 5b''. The burst medians skip transient attempts (the other rules
	// that read attempts do not): the stored safari attempt changes nothing.
	{name: "tls_burst_freeze", mode: modeServer, verdicts: []string{"tls_burst_freeze_suspected:high"},
		attempts: func() []*client.Attempt {
			freeze := func(alphaOK string) *client.Attempt {
				return detail(mk("tls.burst", vr, "chrome-x8", "tcp", 443, "burst_freeze", "stalled_after_server_saw_it", true),
					"fingerprint", "chrome", "burst_n", "8", "alpha_ok", alphaOK, "server_alpha_seen", "8", "server_alpha_answered", "3", "server_alpha_partial", "2", "burst_spread_ms", "12")
			}
			return all(
				x(3, okA("tls.sni", bl, "benign", "tcp", 443)),
				one(freeze("2"), freeze("3"), freeze("2")),
				one(detail(freeze("8"), "fingerprint", "safari", "burst_n", "64", "transient", "true")),
				x(3, okA("tls.burst", ct, "firefox-x8", "tcp", 443)),
			)
		}},
	// Without the single-handshake baseline the attempt's own control decides.
	{name: "tls_burst_freeze_no_outer", mode: modeServer,
		verdicts: []string{"tls_burst_freeze_suspected:medium", "tls_burst_freeze_suspected:low", "tls_burst_freeze_suspected:low"},
		attempts: func() []*client.Attempt {
			freeze := func(port int, kv ...string) *client.Attempt {
				return detail(mk("tls.burst", vr, "chrome-x8", "tcp", port, "burst_freeze", "uplink_drop_or_route_failure", false), kv...)
			}
			return all(
				// Older servers report server_alpha_hello; nothing arrived cut.
				x(2, freeze(443, "fingerprint", "chrome", "burst_n", "8", "server_alpha_seen", "1", "server_alpha_hello", "0", "server_alpha_partial", "0")),
				x(2, lost("tls.burst", ct, "firefox-x8", "tcp", 443)),
				// Half froze: not a majority.
				one(freeze(4433), okA("tls.burst", vr, "chrome-x8", "tcp", 4433)),
				// A count without the fields around it: the median of nothing is 0.
				one(freeze(8443, "alpha_ok", "0")),
			)
		}},

	// Rule 5c: confidence. High when the cut repeats and a plain baseline on
	// the port passes (the echo, else the packets test).
	{name: "session_cut_confidence_baseline", mode: modeServer,
		verdicts: []string{"wireguard_session_cut_suspected:high", "wireguard_session_cut_suspected:high"},
		attempts: func() []*client.Attempt {
			cut := func(port int) *client.Attempt {
				return detail(mk("wireguard.session", vr, "noise-ik+data", "udp", port, "session_cut", "uplink_drop_after_handshake", true),
					"data_sent", "12", "data_recv", "2", "server_data_seen", "2", "data_first_loss", "3")
			}
			return all(
				x(3, echo("udp", 51820)),
				x(3, okA("wireguard.init", vr, "noise-ik", "udp", 51820)),
				x(3, cut(51820)),
				// Two cuts in three, and only the packets test as the baseline.
				x(3, okA("udp.packets", vr, "cp1-32x32", "udp", 443)),
				x(3, okA("wireguard.init", vr, "noise-ik", "udp", 443)),
				x(2, cut(443)),
				one(okA("wireguard.session", vr, "noise-ik+data", "udp", 443)),
			)
		}},
	{name: "session_cut_confidence_tcp", mode: modeServer, verdicts: []string{"openvpn_session_cut_suspected:high"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, echo("tcp", 443)),
				x(3, okA("openvpn.reset", vr, "tcp+tls-auth", "tcp", 443)),
				x(3, mk("openvpn.session", vr, "tcp+tls-auth+data", "tcp", 443, "session_cut", "uplink_drop_after_handshake", true)),
			)
		}},
	// ... otherwise the general ladder against the handshake.
	{name: "session_cut_confidence_general", mode: modeServer,
		verdicts: []string{"wireguard_session_cut_suspected:medium", "wireguard_session_cut_suspected:low", "wireguard_session_cut_suspected:high"},
		attempts: func() []*client.Attempt {
			cut := func(port int) *client.Attempt {
				return mk("wireguard.session", vr, "noise-ik+data", "udp", port, "session_cut", "uplink_drop_after_handshake", true)
			}
			return all(
				x(3, okA("wireguard.init", vr, "noise-ik", "udp", 53)),
				x(3, cut(53)),
				x(3, okA("wireguard.init", vr, "noise-ik", "udp", 1194)),
				x(2, cut(1194)),
				one(okA("wireguard.session", vr, "noise-ik+data", "udp", 1194)),
				x(2, okA("wireguard.init", vr, "noise-ik", "udp", 500)),
				one(cut(500), okA("wireguard.session", vr, "noise-ik+data", "udp", 500)),
			)
		}},
	// OpenVPN: which of the two channels was cut.
	{name: "session_cut_openvpn_channels", mode: modeServer,
		verdicts: []string{"openvpn_session_cut_suspected:low", "openvpn_session_cut_suspected:low", "openvpn_session_cut_suspected:low", "openvpn_session_cut_suspected:low"},
		attempts: func() []*client.Attempt {
			cut := func(variant, tr string, port int, kv ...string) *client.Attempt {
				return detail(mk("openvpn.session", vr, variant, tr, port, "session_cut", "uplink_drop_after_handshake", true), kv...)
			}
			return all(
				// The control channel itself.
				one(okA("openvpn.reset", vr, "udp", "udp", 1194)),
				one(cut("udp+control+data", "udp", 1194, "ctl_sent", "3", "ctl_recv", "0", "server_ctl_seen", "0")),
				// Control passed, not one data packet came back.
				one(okA("openvpn.reset", vr, "udp+tls-auth", "udp", 1194)),
				one(cut("udp+tls-auth+data", "udp", 1194, "ctl_sent", "3", "ctl_recv", "3", "server_ctl_seen", "3", "data_sent", "3", "data_recv", "0", "data_first_loss", "0", "server_data_seen", "1")),
				// Control passed, data cut after N packets.
				one(okA("openvpn.reset", vr, "tcp+tls-auth", "tcp", 443)),
				one(cut("tcp+tls-auth+data", "tcp", 443, "ctl_sent", "3", "ctl_recv", "3", "data_sent", "12", "data_recv", "2", "data_first_loss", "3", "server_data_seen", "12")),
				// Neither: the counts alone.
				one(okA("openvpn.reset", vr, "tcp+tls-crypt", "tcp", 443)),
				one(cut("tcp+tls-crypt+data", "tcp", 443, "ctl_sent", "3", "ctl_recv", "2", "data_sent", "12", "data_recv", "5")),
			)
		}},
	// The kind is built from the test id; the direction from the merge.
	{name: "session_cut_vpn_families", mode: modeServer,
		verdicts: []string{"ikev2_session_cut_suspected:low", "l2tp_session_cut_suspected:low", "wireguard_session_cut_suspected:low"},
		attempts: func() []*client.Attempt {
			return all(
				one(okA("wireguard.init", vr, "noise-ik", "udp", 51820)),
				one(detail(mk("wireguard.session", vr, "noise-ik+data", "udp", 51820, "session_cut", "uplink_drop_after_handshake", true), "server_data_seen", "2")),
				one(okA("ikev2.init", vr, "plain", "udp", 500)),
				one(detail(mk("ikev2.session", vr, "plain", "udp", 500, "session_cut", "downlink_drop_after_handshake", true), "server_data_seen", "12")),
				one(okA("l2tp.init", vr, "v2", "udp", 1701)),
				one(detail(mk("l2tp.session", vr, "v2", "udp", 1701, "session_cut", "uplink_delayed_past_deadline", true), "server_data_seen", "12")),
			)
		}},
	// A modification merge on a session cell is not reported again by rule 7,
	// and a session variant whose handshake passes is not a variant finding.
	{name: "session_cut_proxy_families", mode: modeServer,
		verdicts: []string{"obfs4_session_cut_suspected:low", "socks5_session_cut_suspected:low", "tor.link_session_cut_suspected:low", "vless_session_cut_suspected:low"},
		attempts: func() []*client.Attempt {
			return all(
				one(okA("socks5.connect", bl, "noauth", "tcp", 1080)),
				one(detail(mk("socks5.session", vr, "noauth", "tcp", 1080, "midstream_eof", "stalled_after_server_saw_it", true), "server_data_seen", "1")),
				one(okA("vless.reality", ct, "benign", "tcp", 443), okA("vless.reality", vr, "reality:www.microsoft.com", "tcp", 443)),
				one(okA("vless.session", ct, "benign", "tcp", 443)),
				one(detail(mk("vless.session", vr, "reality:www.microsoft.com", "tcp", 443, "session_cut", "connect_diverged_middlebox_or_misattributed", true), "server_data_seen", "0")),
				one(okA("obfs4.handshake", vr, "ntor-shaped", "tcp", 8443)),
				one(detail(mk("obfs4.session", vr, "ntor-shaped", "tcp", 8443, "midstream_reset", "rst_injected_or_path_reset", true), "server_data_seen", "4")),
				one(okA("tor.handshake", vr, "tor-hello+tor-cert", "tcp", 9001)),
				one(mk("tor.link", vr, "tor-hello+tor-cert", "tcp", 9001, "session_cut", "uplink_drop_after_handshake", true)),
			)
		}},
	// handshakeCell: the stripped variant, else the same name, else any
	// variant of the handshake test on the port; no handshake, no verdict.
	{name: "session_handshake_lookup", mode: modeServer, verdicts: []string{"l2tp_session_cut_suspected:low", "obfs4_session_cut_suspected:low"},
		attempts: func() []*client.Attempt {
			return all(
				one(okA("obfs4.handshake", vr, "ntor-shaped+data", "tcp", 443)),
				one(mk("obfs4.session", vr, "ntor-shaped+data", "tcp", 443, "session_cut", "uplink_drop_after_handshake", true)),
				one(okA("l2tp.init", vr, "v2", "udp", 1701)),
				one(mk("l2tp.session", vr, "v3", "udp", 1701, "session_cut", "uplink_drop_after_handshake", true)),
				one(okA("ikev2.init", vr, "plain", "udp", 500)),
				one(mk("ikev2.session", vr, "plain", "udp", 4500, "session_cut", "uplink_drop_after_handshake", true)),
			)
		}},

	// Rule 6. Ordering: rule 7 attaches the mechanism to the verdict that
	// names the cell, and with two of them (rule 5's and rule 6's) to the later one.
	{name: "dns_manipulation", mode: modeServer,
		verdicts: []string{"dns_manipulation_suspected:medium", "dns_manipulation_suspected:medium", "dns_qtype_policy_suspected:medium", "system_resolver_manipulation_suspected:medium"},
		attempts: func() []*client.Attempt {
			return all(
				x(2, okA("dns.udp", bl, "TXT", "udp", 53)),
				one(mk("dns.udp", bl, "TXT", "udp", 53, "dns_answer_mismatch", "downlink_modified", true)),
				x(3, mk("dns.udp", vr, "trigger:www.youtube.com", "udp", 53, "dns_injected_race", "injected", true)),
				x(2, mk("dns.system", vr, "whoami", "udp", 0, "dns_answer_mismatch", "dns_answer_mismatch", false)),
			)
		}},
	// The A cell fails with the TXT one and is not reported apart.
	{name: "dns_udp_blocking", mode: modeServer, verdicts: []string{"dns_udp_blocking_suspected:high"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, echo("udp", 443)),
				x(3, mk("dns.udp", bl, "TXT", "udp", 53, "dns_timeout", "uplink_drop_or_route_failure", false)),
				x(3, mk("dns.udp", vr, "A", "udp", 53, "dns_timeout", "uplink_drop_or_route_failure", false)),
				x(3, okA("dns.tcp", vr, "TXT", "tcp", 53)),
			)
		}},
	{name: "dns_port_blocking", mode: modeServer,
		verdicts: []string{"dns_port_blocking_suspected:high", "dns_port_blocking_suspected:low", "dns_port_blocking_suspected:medium", "protocol_blocking_suspected:low", "protocol_blocking_suspected:low"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, echo("tcp", 443)),
				x(3, echo("udp", 443)),
				x(3, lost("dns.dot", vr, "TXT", "tcp", 853)),
				x(2, mk("dns.udp", bl, "TXT", "udp", 53, "dns_timeout", "uplink_drop_or_route_failure", false)),
				// dns.tcp fails too: no UDP-only finding.
				one(lost("dns.tcp", vr, "TXT", "tcp", 53)),
				// DoH rides the control port and the system resolver has no port.
				x(2, lost("dns.doh", vr, "TXT", "tcp", 8443)),
				one(mk("dns.system", vr, "whoami", "udp", 0, "dns_timeout", "dns_timeout", false)),
				// A DNS cell on a port that has an echo is rule 4's.
				one(mk("dns.udp", vr, "A", "udp", 443, "dns_timeout", "uplink_drop_or_route_failure", false)),
				one(lost("dns.dot", vr, "TXT", "tcp", 443)),
			)
		}},
	// One query type fails while TXT passes on the very same port: rule 5
	// names the type, and rule 6 still calls the cell port blocking.
	{name: "dns_qtype_is_also_port_blocking", mode: modeServer, verdicts: []string{"dns_port_blocking_suspected:high", "dns_qtype_policy_suspected:high"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, echo("udp", 443)),
				x(3, okA("dns.udp", bl, "TXT", "udp", 53)),
				x(3, mk("dns.udp", vr, "A", "udp", 53, "dns_timeout", "uplink_drop_or_route_failure", false)),
			)
		}},
	// No control anywhere: no verdict, and the summary reads clean.
	{name: "dns_no_control", mode: modeServer, verdicts: nil,
		attempts: func() []*client.Attempt {
			return x(3, mk("dns.udp", bl, "TXT", "udp", 53, "dns_timeout", "uplink_drop_or_route_failure", false))
		}},

	// Rule 7: the mechanism goes to the verdict that names the cell, else it
	// is a finding of its own, medium from two attempts up.
	{name: "modification", mode: modeServer,
		verdicts: []string{"downlink_modified:low", "injected:medium", "rst_injected_bidirectional:low", "rst_injected_or_path_reset:low", "sni_or_host_blocking_suspected:high", "tls_mitm_or_wrong_server:medium", "uplink_modified:low"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, okA("tls.sni", bl, "benign", "tcp", 443)),
				x(3, mk("tls.sni", vr, "trigger:www.youtube.com", "tcp", 443, "midstream_reset", "rst_injected_or_path_reset", false)),
				one(echo("udp", 443)),
				x(2, okA("quic.v1", vr, "h3", "udp", 443)),
				one(mk("quic.v1", vr, "h3", "udp", 443, "tls_parse_failure", "downlink_modified", true)),
				// Two mechanisms in one cell: reported in name order.
				x(2, okA("http.host", bl, "benign", "tcp", 80)),
				one(mk("http.host", bl, "benign", "tcp", 80, "modified", "uplink_modified", true)),
				x(2, mk("http.host", bl, "benign", "tcp", 80, "modified", "injected", true)),
				x(2, mk("tls.fingerprint", bl, "chrome", "tcp", 443, "cert_mismatch", "tls_mitm_or_wrong_server", false)),
				one(mk("tcp.echo", bl, "cp1-64", "tcp", 8080, "midstream_reset", "rst_injected_bidirectional", true)),
				// One reset in a cell that passes: no verdict names it.
				x(2, okA("tls.alpn", bl, "http/1.1", "tcp", 443)),
				one(mk("tls.alpn", bl, "http/1.1", "tcp", 443, "midstream_reset", "rst_injected_or_path_reset", false)),
			)
		}},

	// Ordering: rule 7 looks the cell up among the verdicts of rules 1-6 by
	// subject, and when two of them name the cell the later rule's verdict
	// gets the mechanism: rule 5's over rule 4's, within rule 6 the port
	// finding over the manipulation one.
	{name: "modification_goes_to_the_later_verdict", mode: modeServer,
		verdicts: []string{"control_failed_inconclusive:low", "dns_manipulation_suspected:medium", "dns_port_blocking_suspected:high", "sni_or_host_blocking_suspected:high"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, echo("tcp", 443)),
				x(3, lost("tcp.payload.random", ct, "random-64", "tcp", 443)),
				x(3, okA("tls.sni", bl, "benign", "tcp", 443)),
				x(3, mk("tls.sni", vr, "trigger:www.youtube.com", "tcp", 443, "midstream_reset", "rst_injected_or_path_reset", false)),
				x(3, echo("udp", 443)),
				x(3, mk("dns.udp", bl, "TXT", "udp", 53, "dns_answer_mismatch", "injected", true)),
			)
		}},

	// Transient outage: six failures on three ports inside 20 s, in cells that
	// pass in the other rounds. The cell that fails every round keeps its verdict.
	{name: "transient_outage", mode: modeServer, verdicts: []string{"protocol_blocking_suspected:high"},
		attempts: func() []*client.Attempt {
			return all(
				threeRounds(outageCells(), []int{60, 64, 68, 72, 76, 80}),
				one(at(echo("udp", 51820), 1, 6), at(echo("udp", 51820), 2, 66), at(echo("udp", 51820), 3, 126)),
				one(at(lost("wireguard.init", vr, "noise-ik", "udp", 51820), 1, 7), at(lost("wireguard.init", vr, "noise-ik", "udp", 51820), 2, 67), at(lost("wireguard.init", vr, "noise-ik", "udp", 51820), 3, 127)),
			)
		}},
	// Five failures are not an outage; an inconclusive attempt does not count.
	{name: "transient_too_few", mode: modeServer, verdicts: nil,
		attempts: func() []*client.Attempt {
			out := threeRounds(outageCells(), []int{60, 64, 68, 72, 76, 80})
			for _, a := range out {
				if a.Round == 2 && a.TestID == "quic.v1" {
					a.Outcome, a.Merged = client.OutcomeInconclusive, "inconclusive"
				}
			}
			return out
		}},
	// Six failures over 21 s: no window of 20 s holds them all.
	{name: "transient_too_slow", mode: modeServer, verdicts: nil,
		attempts: func() []*client.Attempt { return threeRounds(outageCells(), []int{60, 64, 68, 72, 76, 81}) }},
	// Six failures on two ports are a rule on those ports, not an outage.
	{name: "transient_two_ports", mode: modeServer, verdicts: nil,
		attempts: func() []*client.Attempt {
			cells := []*client.Attempt{
				echo("tcp", 80), okA("http.host", bl, "benign", "tcp", 80), okA("http.host", ct, "random", "tcp", 80),
				echo("tcp", 443), okA("tls.sni", bl, "benign", "tcp", 443), okA("tls.sni", ct, "absent", "tcp", 443),
			}
			return threeRounds(cells, []int{60, 64, 68, 72, 76, 80})
		}},
	// A stray failure a minute earlier opens a window of one; the search moves
	// on and finds the burst. The rounds in the note are sorted as strings.
	{name: "transient_sliding_window", mode: modeServer, verdicts: nil,
		attempts: func() []*client.Attempt {
			out := threeRounds(append(outageCells(), echo("tcp", 1194)), []int{60, 64, 68, 72, 76, 80, -1})
			for _, a := range out {
				switch {
				case a.DstPort == 1194 && a.Round == 1:
					a.Outcome, a.Merged, a.Server = client.OutcomeConnectTimeout, "uplink_drop_or_route_failure", nil
				case a.Round == 2 && a.Transport == "udp":
					a.Round = 10
				case a.Round == 2:
					a.Round = 9
				}
			}
			return out
		}},

	// dest.*: one-sided evidence, never above medium.
	{name: "dest_sni_blocking", mode: modeStandalone, verdicts: []string{"dest_sni_blocking_suspected:low", "dest_sni_blocking_suspected:medium"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, mkDest("dest.tcp", ct, "anycast", 443, "ok", nil)),
				one(mkDest("dest.nxdomain", ct, "invalid", 53, "ok", nil)),
				site("wikipedia.org", "control", "0", bl, 1, "dns=ok", "tcp=ok", "tls=ok", "decoy=ok"),
				site("youtube.com", "dpi", "1", vr, 3, "tcp=ok", "tls=midstream_reset", "decoy=ok", "absent=ok"),
				// Non-TLS bytes answered the ClientHello.
				site("blockpage.example", "news", "", vr, 1, "tcp=ok", "tls=tls_spoof", "decoy=ok"),
			)
		}},
	{name: "dest_tls_blocking", mode: modeStandalone, verdicts: []string{"dest_tls_blocking_suspected:low", "dest_tls_blocking_suspected:low", "dest_tls_blocking_suspected:medium"},
		attempts: func() []*client.Attempt {
			return all(
				one(mkDest("dest.tcp", ct, "anycast", 443, "ok", nil)),
				// The decoy fails too, a handshake without SNI passes.
				site("x.com", "social", "2", vr, 2, "tcp=ok", "tls=payload_timeout", "decoy=payload_timeout", "absent=ok"),
				// No decoy ran, or it was skipped: nothing to compare with.
				site("nodecoy.example", "news", "1", vr, 1, "tcp=ok", "tls=payload_timeout"),
				site("decoyskipped.example", "news", "", vr, 1, "tcp=ok", "tls=tls_alert", "decoy=skipped"),
			)
		}},
	// The per-site summary takes the layer closest to the user: e.example is
	// poisoned and blackholed, and reads as poisoned.
	{name: "dest_tcp", mode: modeStandalone,
		verdicts: []string{"dest_dns_poisoning_suspected:medium", "dest_tcp_blackhole_suspected:medium", "dest_tcp_blackhole_suspected:medium", "dest_tcp_blackhole_suspected:low", "dest_tcp_blocking_suspected:medium", "dest_tcp_reset_suspected:low", "dest_tcp_reset_suspected:low", "dest_tcp_reset_suspected:low"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, mkDest("dest.tcp", ct, "anycast", 443, "ok", nil)),
				site("a.example", "news", "", vr, 3, "dns=ok", "tcp=connect_timeout", "tls=skipped"),
				site("b.example", "news", "", vr, 1, "tcp=connect_reset"),
				site("c.example", "news", "", vr, 1, "tcp=connect_refused"),
				site("d.example", "news", "", vr, 2, "tcp=payload_timeout"),
				site("e.example", "news", "", vr, 2, "dns=dns_answer_mismatch", "tcp=connect_timeout"),
				// dest.tls never connected to the first address while dest.tcp
				// reached another one: an address finding, not an SNI one.
				site("f.example", "news", "", vr, 1, "tcp=ok", "tls=connect_timeout", "decoy=ok"),
				// No detail.domain on the attempts: the verdict stands, the
				// per-site summary has no row to put it in.
				one(mk("dest.tcp", vr, "g.example", "tcp", 443, "connect_reset", "connect_reset", false)),
			)
		}},
	// The DNS control is a control site's cell when there is one.
	{name: "dest_dns", mode: modeStandalone, verdicts: []string{"dest_dns_poisoning_suspected:medium", "dest_dns_poisoning_suspected:low", "nxdomain_hijack_suspected:medium"},
		attempts: func() []*client.Attempt {
			return all(
				x(2, mkDest("dest.tcp", ct, "anycast", 443, "ok", nil)),
				x(2, mkDest("dest.nxdomain", ct, "invalid", 53, "dns_answer_mismatch", nil)),
				site("other.example", "news", "", vr, 2, "dns=ok"),
				site("wikipedia.org", "control", "", bl, 2, "dns=ok"),
				site("meduza.io", "news", "", vr, 2, "dns=dns_answer_mismatch", "tcp=ok"),
				// A timeout for one name only.
				site("slow.example", "news", "", vr, 1, "dns=dns_timeout"),
			)
		}},
	// The resolver times out for most sites: one finding, and the one site it
	// does answer wrongly has no control to be called poisoned against.
	{name: "dest_resolver_down", mode: modeStandalone, verdicts: []string{"dest_dns_poisoning_suspected:low", "system_resolver_unreachable_suspected:medium"},
		attempts: func() []*client.Attempt {
			return all(
				x(2, mkDest("dest.tcp", ct, "anycast", 443, "ok", nil)),
				site("a.example", "news", "", vr, 2, "dns=dns_timeout", "tcp=ok"),
				site("b.example", "news", "", vr, 2, "dns=dns_timeout", "tcp=ok"),
				site("c.example", "news", "", vr, 1, "dns=dns_answer_mismatch"),
			)
		}},
	{name: "dest_resolver_down_no_anycast", mode: modeStandalone, verdicts: []string{"nxdomain_hijack_suspected:low", "system_resolver_unreachable_suspected:low"},
		attempts: func() []*client.Attempt {
			return all(
				one(mkDest("dest.nxdomain", ct, "invalid", 53, "dns_answer_mismatch", nil)),
				site("a.example", "news", "", vr, 1, "dns=dns_timeout"),
			)
		}},
	{name: "dest_resolver_unreliable", mode: modeStandalone, verdicts: []string{"system_resolver_unreliable_suspected:low"},
		attempts: func() []*client.Attempt {
			return all(
				one(mkDest("dest.tcp", ct, "anycast", 443, "ok", nil)),
				site("a.example", "news", "", vr, 1, "dns=dns_answer_mismatch", "tcp=ok"),
				site("b.example", "news", "", vr, 1, "dns=dns_answer_mismatch", "tcp=ok"),
				site("c.example", "news", "", vr, 1, "dns=dns_answer_mismatch", "tcp=ok"),
			)
		}},
	// Without the anycast control the transport layers say nothing.
	{name: "dest_anycast_failed", mode: modeStandalone, verdicts: []string{"control_failed_inconclusive:low"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, mkDest("dest.tcp", ct, "anycast", 443, "connect_timeout", nil)),
				site("a.example", "news", "", vr, 1, "dns=ok", "tcp=connect_timeout", "tls=skipped"),
			)
		}},
	// dest.http, and the per-site verdicts that are not a verdict kind:
	// nxdomain, inconclusive, degraded (a mixed layer).
	{name: "dest_http", mode: modeStandalone, verdicts: []string{"dest_legal_block_suspected:medium", "dest_legal_block_suspected:low", "dest_tls_interception_suspected:low"},
		attempts: func() []*client.Attempt {
			return all(
				x(2, mkDest("dest.tcp", ct, "anycast", 443, "ok", nil)),
				site("claude.ai", "ai", "3", vr, 2, "dns=ok", "tcp=ok", "tls=ok", "decoy=ok", "http=http_legal_block"),
				site("one.example", "ai", "2", vr, 1, "tls=ok", "http=http_legal_block"),
				site("badcert.example", "news", "1", vr, 1, "tls=ok", "http=cert_mismatch"),
				site("gone.example", "news", "", vr, 1, "dns=dns_rcode", "tcp=skipped"),
				site("unknown.example", "news", "", vr, 1, "dns=ok", "tcp=inconclusive"),
				site("flaky.example", "news", "", vr, 1, "tcp=ok"),
				site("flaky.example", "news", "", vr, 1, "tcp=connect_timeout"),
			)
		}},
	// No site at all: the family controls still speak.
	{name: "dest_only_controls", mode: modeStandalone, verdicts: []string{"nxdomain_hijack_suspected:medium"},
		attempts: func() []*client.Attempt {
			return all(
				x(2, mkDest("dest.tcp", ct, "anycast", 443, "ok", nil)),
				x(2, mkDest("dest.nxdomain", ct, "invalid", 53, "dns_answer_mismatch", nil)),
			)
		}},
	// A server scan with the family on: both kinds of rule, one summary.
	{name: "dest_with_server_rules", mode: modeServer, verdicts: []string{"dest_sni_blocking_suspected:medium", "sni_or_host_blocking_suspected:high"},
		attempts: func() []*client.Attempt {
			return all(
				x(3, echo("tcp", 443)),
				x(3, okA("tls.sni", bl, "benign", "tcp", 443)),
				x(3, mk("tls.sni", vr, "trigger:www.youtube.com", "tcp", 443, "midstream_reset", "rst_injected_or_path_reset", false)),
				x(3, mkDest("dest.tcp", ct, "anycast", 443, "ok", nil)),
				site("youtube.com", "dpi", "0", vr, 3, "tcp=ok", "tls=midstream_reset", "decoy=ok"),
			)
		}},

	// The field run of 2026-09-18. Android cut the app off the network for
	// some seconds: the open sockets aborted (a control-plane POST, a
	// handshake to a real site), the next UDP send got EPERM, the platform
	// resolver refused. Everything that failed in flight then is flagged,
	// whatever it failed with (the chrome handshake timed out); what passed
	// stays; a dest layer lost whole reads skipped. No verdict comes of it.
	{name: "local_outage", mode: modeServer, verdicts: nil,
		attempts: func() []*client.Attempt {
			return all(
				one(span(echo("tcp", 443), 1, 1, 90), span(echo("tcp", 443), 2, 61, 90)),
				one(span(okA("tls.fingerprint", bl, "android", "tcp", 443), 1, 2, 400), span(okA("tls.fingerprint", bl, "android", "tcp", 443), 2, 62, 400)),
				one(span(failWith(mk("tls.fingerprint", vr, "firefox", "tcp", 443, client.OutcomeServerError, client.OutcomeServerError, false),
					`Post "https://‹server›:8443/v1/session/x/attempt": read tcp ‹local›->‹server›:8443: read: software caused connection abort`), 1, 10, 7800)),
				one(span(okA("tls.sni", bl, "benign", "tcp", 443), 1, 12, 300)),
				one(span(failWith(mkDest("dest.tls", vr, "wikipedia.org", 443, client.OutcomeMidstreamEOF, map[string]string{"category": "control"}),
					"read tcp ‹local›->185.15.59.224:443: read: software caused connection abort"), 1, 15, 2449)),
				one(span(detail(mk("dns.udp", bl, "TXT", "udp", 53, client.OutcomeServerError, client.OutcomeServerError, false), "local_error", "eperm"), 1, 18, 2)),
				one(span(mkDest("dest.dns", vr, "github.com", 53, client.OutcomeInconclusive, map[string]string{"category": "vcs",
					"system_error": "resolver error 1: android.system.ErrnoException: resNetworkResult failed: ECONNREFUSED (Connection refused)"}), 1, 19, 1500)),
				one(span(mk("tls.fingerprint", vr, "chrome", "tcp", 443, client.OutcomePayloadTimeout, "uplink_drop_or_route_failure", false), 1, 19, 1500)),
				one(span(mkDest("dest.tls", vr, "play.google.com", 443, client.OutcomeSkipped, map[string]string{"category": "store"}), 1, 19, 1)),
				one(span(mkDest("dest.dns", vr, "play.google.com", 53, client.OutcomeOK, map[string]string{"category": "store"}), 1, 40, 900)),
				one(span(mkDest("dest.tcp", vr, "play.google.com", 443, client.OutcomeOK, map[string]string{"category": "store"}), 1, 41, 70)),
				one(span(mkDest("dest.dns", vr, "wikipedia.org", 53, client.OutcomeOK, map[string]string{"category": "control"}), 1, 42, 800)),
				one(span(mkDest("dest.tcp", vr, "wikipedia.org", 443, client.OutcomeOK, map[string]string{"category": "control"}), 1, 43, 90)),
			)
		}},
	// What measured nothing is never evidence: a fault of the host or the
	// server (server_error) fails no cell. The field run had a fingerprint,
	// a DNS port, a protocol and a session cut out of these.
	{name: "unmeasured_not_evidence", mode: modeServer, verdicts: nil,
		attempts: func() []*client.Attempt {
			return all(
				x(2, echo("tcp", 443)),
				x(2, okA("tls.fingerprint", bl, "android", "tcp", 443)),
				x(2, mk("tls.fingerprint", vr, "firefox", "tcp", 443, client.OutcomeServerError, client.OutcomeServerError, false)),
				x(2, echo("udp", 443)),
				one(mk("dns.udp", bl, "TXT", "udp", 53, client.OutcomeServerError, client.OutcomeServerError, false)),
				one(mk("quic.v1", vr, "h3", "udp", 443, client.OutcomeServerError, client.OutcomeServerError, false)),
				x(2, echo("udp", 1194)),
				x(2, okA("openvpn.reset", vr, "udp+tls-auth", "udp", 1194)),
				one(mk("openvpn.session", vr, "udp+tls-auth+data", "udp", 1194, client.OutcomeServerError, client.OutcomeServerError, false)),
			)
		}},
	// Sites whose own handshake measured nothing are not clear: every
	// transport layer skipped (no address for the whole scan), the TLS layer
	// skipped behind a passing TCP one, or every connect failing on the host
	// (an IPv6 answer on a phone without IPv6: no blackhole either). A page
	// fetched with the real name is the handshake passing.
	{name: "dest_unmeasured_sites", mode: modeStandalone, verdicts: nil,
		attempts: func() []*client.Attempt {
			return all(
				x(2, mkDest("dest.tcp", ct, "anycast", 443, "ok", nil)),
				site("wikipedia.org", "control", "0", bl, 1, "dns=ok", "tcp=ok", "tls=ok", "decoy=ok", "absent=ok"),
				site("gateway.discord.gg", "messenger", "1", vr, 1, "dns=ok", "tcp=skipped", "tls=skipped", "decoy=skipped", "absent=skipped"),
				site("play.google.com", "store", "2", vr, 1, "dns=ok", "tcp=ok", "tls=skipped", "decoy=payload_timeout", "absent=skipped"),
				site("claude.ai", "ai", "3", vr, 1, "dns=ok", "tcp=ok", "tls=skipped", "decoy=ok", "http=ok"),
				x(2, detail(mkDest("dest.tcp", vr, "youtube.com", 443, client.OutcomeServerError, map[string]string{"category": "video", "order": "4"}), "local_error", client.LocalNoRoute)),
				x(2, detail(mkDest("dest.tls", vr, "youtube.com", 443, client.OutcomeServerError, map[string]string{"category": "video", "order": "4"}), "local_error", client.LocalNoRoute)),
				site("youtube.com", "video", "4", vr, 2, "dns=ok"),
			)
		}},
	// A reset that comes back sooner than a round trip to the address is
	// injected on the path; when only the real name draws it and the other
	// handshakes on the address time out, the rule keys on the SNI. dw.com:
	// both resets early. meduza.io: one connect went through a SYN
	// retransmission, the shortest handshake to the address (dest.tcp) is the
	// round trip. late.example: the resets came after a round trip, the
	// server may have sent them. both.example: the decoy is reset too.
	// A target that speaks its own protocol (the WhatsApp gateway) is judged
	// on that handshake against TCP to the same address; a clean handshake
	// makes it clear with no TLS layer at all.
	{name: "dest_proto", mode: modeStandalone, verdicts: []string{"dest_proto_blocking_suspected:low", "dest_proto_blocking_suspected:medium", "dest_tcp_blackhole_suspected:medium"},
		attempts: func() []*client.Attempt {
			return all(
				x(2, mkDest("dest.tcp", ct, "anycast", 443, "ok", nil)),
				site("g.whatsapp.net", "messenger", "1", vr, 2, "dns=ok", "tcp=ok", "proto=ok"),
				site("reset.example", "messenger", "2", vr, 2, "dns=ok", "tcp=ok", "proto=midstream_reset"),
				site("proxied.example", "messenger", "3", vr, 1, "dns=ok", "tcp=ok", "proto=unexpected_response"),
				site("silent.example", "messenger", "4", vr, 2, "dns=ok", "tcp=connect_timeout", "proto=connect_timeout"),
			)
		}},
	{name: "dest_sni_early_reset", mode: modeStandalone, verdicts: []string{"dest_sni_blocking_suspected:medium", "dest_sni_blocking_suspected:low", "dest_sni_blocking_suspected:medium", "dest_tls_blocking_suspected:medium"},
		attempts: func() []*client.Attempt {
			ip := func(a *client.Attempt, addr string) *client.Attempt { return detail(a, "ip", addr) }
			ep := func(a *client.Attempt, addr string) *client.Attempt { return detail(a, "endpoint", addr+":443") }
			meta := func(order string) map[string]string { return map[string]string{"category": "news", "order": order} }
			return all(
				x(2, mkDest("dest.tcp", ct, "anycast", 443, "ok", nil)),
				site("dw.com", "news", "1", vr, 2, "dns=ok", "decoy=payload_timeout", "absent=payload_timeout"),
				x(2, ep(connect(mkDest("dest.tcp", vr, "dw.com", 443, "ok", meta("1")), 94), "194.55.26.46")),
				one(ip(stages(mkDest("dest.tls", vr, "dw.com", 443, client.OutcomeMidstreamReset, meta("1")), 94, 94, 128), "194.55.26.46"),
					ip(stages(mkDest("dest.tls", vr, "dw.com", 443, client.OutcomeMidstreamReset, meta("1")), 96, 96, 148), "194.55.26.46")),
				site("meduza.io", "news", "2", vr, 2, "dns=ok", "decoy=payload_timeout", "absent=payload_timeout"),
				x(2, ep(connect(mkDest("dest.tcp", vr, "meduza.io", 443, "ok", meta("2")), 64), "8.47.69.0")),
				one(ip(stages(mkDest("dest.tls", vr, "meduza.io", 443, client.OutcomeMidstreamReset, meta("2")), 72, 72, 107), "8.47.69.0"),
					ip(stages(mkDest("dest.tls", vr, "meduza.io", 443, client.OutcomeMidstreamReset, meta("2")), 1087, 1087, 1120), "8.47.69.0")),
				site("late.example", "news", "3", vr, 2, "dns=ok", "decoy=payload_timeout"),
				x(2, ep(connect(mkDest("dest.tcp", vr, "late.example", 443, "ok", meta("3")), 40), "198.51.100.3")),
				x(2, ip(stages(mkDest("dest.tls", vr, "late.example", 443, client.OutcomeMidstreamReset, meta("3")), 40, 40, 160), "198.51.100.3")),
				site("both.example", "news", "4", vr, 2, "dns=ok", "tcp=ok", "decoy=midstream_reset"),
				x(2, ip(stages(mkDest("dest.tls", vr, "both.example", 443, client.OutcomeMidstreamReset, meta("4")), 50, 50, 70), "198.51.100.4")),
			)
		}},
}

// outageCells are six cells on exactly three ports, one attempt each.
func outageCells() []*client.Attempt {
	return []*client.Attempt{
		echo("tcp", 80), okA("http.host", bl, "benign", "tcp", 80),
		echo("tcp", 443), okA("tls.sni", bl, "benign", "tcp", 443),
		echo("udp", 443), okA("quic.v1", vr, "h3", "udp", 443),
	}
}

// threeRounds runs every cell once per round: round 1 from +0 s, round 3 from
// +120 s, one second apart, all passing. In round 2 cell i fails at
// +round2[i] s, or passes at +60+i s when round2[i] is negative.
func threeRounds(cells []*client.Attempt, round2 []int) []*client.Attempt {
	var out []*client.Attempt
	for round := 1; round <= 3; round++ {
		for i, c := range cells {
			a := x(1, c)[0]
			sec := (round-1)*60 + i
			if round == 2 && round2[i] >= 0 {
				sec = round2[i]
				a.Outcome, a.Merged, a.Server = client.OutcomeConnectTimeout, "uplink_drop_or_route_failure", nil
			}
			out = append(out, at(a, round, sec))
		}
	}
	return out
}

// site builds n rounds of the dest.* layers of one domain, each given as
// "layer=outcome" with layer one of dns, tcp, tls, decoy, absent, http. role
// is the role of the site's own cells (baseline for a control site).
func site(domain, category, order, role string, n int, layers ...string) []*client.Attempt {
	meta := map[string]string{"category": category}
	if order != "" {
		meta["order"] = order
	}
	var out []*client.Attempt
	for i := 0; i < n; i++ {
		for _, l := range layers {
			layer, outcome, _ := strings.Cut(l, "=")
			switch layer {
			case "dns":
				out = append(out, mkDest("dest.dns", role, domain, 53, outcome, meta))
			case "tcp":
				out = append(out, mkDest("dest.tcp", role, domain, 443, outcome, meta))
			case "tls":
				out = append(out, mkDest("dest.tls", role, domain, 443, outcome, meta))
			case "decoy":
				out = append(out, mkDest("dest.tls", ct, "decoy:"+domain, 443, outcome, meta))
			case "absent":
				out = append(out, mkDest("dest.tls", ct, "absent:"+domain, 443, outcome, meta))
			case "http":
				out = append(out, mkDest("dest.http", role, domain, 443, outcome, meta))
			case "proto":
				out = append(out, detail(mkDest("dest.proto", role, domain, 443, outcome, meta), "proto", "whatsapp"))
			}
		}
	}
	return out
}
