package integration

import (
	"strings"
	"testing"

	"github.com/xarvel/CensorPulseCli/internal/client"
)

// TestCleanPathIsClean runs the full P0 catalog against an in-process server
// over loopback: every attempt must succeed, every attempt must be matched
// with a server observation and the classifier must emit no verdict.
func TestCleanPathIsClean(t *testing.T) {
	startServer(t)
	attempts, res, c := scan(t, "127.0.0.1", nil, 1)
	if !c.PinMatched {
		for _, a := range attempts {
			if a.Outcome == client.OutcomeCertMismatch || strings.Contains(a.Error, "pin mismatch") {
				t.Errorf("pin mismatch on %s %s/%d %s: %s (server detail %v)", a.TestID, a.Transport, a.DstPort, a.Variant, a.Error, serverDetail(a))
			}
		}
		t.Error("pin was not matched on a direct connection")
	}
	if len(attempts) < 30 {
		t.Fatalf("only %d attempts planned", len(attempts))
	}
	for _, a := range attempts {
		if a.Outcome != client.OutcomeOK {
			t.Errorf("%s %s/%d %s: outcome=%s err=%s merged=%s", a.TestID, a.Transport, a.DstPort, a.Variant, a.Outcome, a.Error, a.Merged)
		}
		if a.Server == nil {
			t.Errorf("%s %s/%d %s: no server observation matched", a.TestID, a.Transport, a.DstPort, a.Variant)
		}
		if a.Merged != "ok" {
			t.Errorf("%s %s/%d %s: merged=%s", a.TestID, a.Transport, a.DstPort, a.Variant, a.Merged)
		}
	}
	if len(res.Verdicts) != 0 {
		t.Errorf("unexpected verdicts: %+v", res.Verdicts)
	}
	families := map[string]bool{}
	for _, a := range attempts {
		families[a.TestID] = true
	}
	for _, want := range []string{"tcp.echo", "tcp.payload.random", "tcp.rtt", "udp.echo", "udp.payload.random", "http.host", "dns.udp", "dns.tcp", "dns.dot", "dns.doh", "tls.version", "tls.sni", "tls.alpn", "tls.fingerprint", "tls.burst", "tcp.packets", "udp.packets", "tor.handshake", "tor.link", "tor.dir", "obfs4.handshake", "obfs4.session", "dtls.hello", "stun.binding", "quic.v1", "openvpn.reset", "wireguard.init", "openvpn.session", "wireguard.session", "ikev2.init", "ikev2.session", "l2tp.init", "l2tp.session", "socks5.connect", "socks5.session", "vless.reality", "vless.session"} {
		if !families[want] {
			t.Errorf("test family %s was not exercised", want)
		}
	}
	// The burst runs last: every other attempt must have finished before the
	// first burst started.
	var lastOther, firstBurst = int64(0), int64(1 << 62)
	fps := map[string]bool{}
	for _, a := range attempts {
		t0 := a.StartedAt.UnixMilli()
		if a.TestID == "tls.burst" {
			if t0 < firstBurst {
				firstBurst = t0
			}
			if a.Detail["alpha_ok"] != a.Detail["burst_n"] || a.Detail["server_alpha_seen"] != a.Detail["burst_n"] {
				t.Errorf("clean burst: alpha_ok=%s server_alpha_seen=%s of %s", a.Detail["alpha_ok"], a.Detail["server_alpha_seen"], a.Detail["burst_n"])
			}
		} else if t0 > lastOther {
			lastOther = t0
		}
		if a.TestID == "tls.fingerprint" {
			fps[a.Variant] = true
		}
		if a.TestID == "udp.packets" && a.Detail["server_packets_seen"] != a.Detail["packets_planned"] {
			t.Errorf("udp.packets: server saw %s of %s", a.Detail["server_packets_seen"], a.Detail["packets_planned"])
		}
		if a.TestID == "tor.handshake" || a.TestID == "tor.link" {
			wantCert := "probe"
			if strings.Contains(a.Variant, "tor-cert") {
				wantCert = "tor"
			}
			if a.Detail["server_cert"] != wantCert {
				t.Errorf("%s %s: server presented %q certificate, want %q", a.TestID, a.Variant, a.Detail["server_cert"], wantCert)
			}
			if a.Detail["cells_recv"] != "CERTS,AUTH_CHALLENGE,NETINFO" {
				t.Errorf("%s %s: link cells %q", a.TestID, a.Variant, a.Detail["cells_recv"])
			}
			if a.Server != nil && strings.Contains(a.Variant, "tor-hello") && a.Server.Detail["hello_shape"] != "tor" {
				t.Errorf("%s %s: server did not recognise the tor ClientHello: %v", a.TestID, a.Variant, a.Server.Detail)
			}
		}
	}
	if firstBurst < lastOther {
		t.Errorf("tls.burst started (%d) before the last other attempt (%d)", firstBurst, lastOther)
	}
	for _, fp := range []string{"edge", "android"} {
		if !fps[fp] {
			t.Errorf("fingerprint %s not exercised", fp)
		}
	}
}

func serverDetail(a *client.Attempt) map[string]string {
	if a.Server == nil {
		return nil
	}
	return a.Server.Detail
}
