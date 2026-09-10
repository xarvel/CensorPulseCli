package integration

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xarvel/CensorPulseCli/internal/client"
	"github.com/xarvel/CensorPulseCli/internal/tor"
)

// torCipherList is the wire form of the tor cipher list, the feature the
// fault proxy keys on (as a censor matching the ClientHello would).
var torCipherList = func() []byte {
	var b []byte
	// the TLS 1.2 part of the list, common to the 1.2-only and the 1.3 hello
	for _, s := range tor.CipherSuites[3 : len(tor.CipherSuites)-1] {
		b = append(b, byte(s>>8), byte(s))
	}
	return b
}()

// TestTorHelloRST: the path resets every TLS connection whose ClientHello
// has the tor shape, whatever the certificate. The plain-hello variants
// pass (including the one that gets the relay certificate), so the
// classifier must say the rule keys on the ClientHello.
func TestTorHelloRST(t *testing.T) {
	startServer(t)
	startProxy(t, proxyIP, proxiedPorts, func(port int, first []byte) faultAction {
		if len(first) > 5 && first[0] == 0x16 && bytes.Contains(first, torCipherList) {
			return actRST
		}
		return actPass
	})
	attempts, res, _ := scan(t, proxyIP, []string{"tcp.echo", "tor.handshake"}, 2)
	for _, a := range attempts {
		switch {
		case a.TestID != "tor.handshake":
			if a.Outcome != client.OutcomeOK {
				t.Errorf("%s: %s (%s)", a.TestID, a.Outcome, a.Error)
			}
		case strings.HasPrefix(a.Variant, "tor-hello"):
			if a.Outcome != client.OutcomeMidstreamReset && a.Outcome != client.OutcomeConnectReset && a.Outcome != client.OutcomeMidstreamEOF {
				t.Errorf("tor.handshake %s: outcome %s (%s)", a.Variant, a.Outcome, a.Error)
			}
		default:
			if a.Outcome != client.OutcomeOK {
				t.Errorf("tor.handshake %s: outcome %s (%s)", a.Variant, a.Outcome, a.Error)
			}
			if a.Variant == "go-hello+tor-cert" && a.Detail["server_cert"] != "tor" {
				t.Errorf("go-hello+tor-cert: got %q certificate", a.Detail["server_cert"])
			}
		}
	}
	if !hasVerdict(res, "tor_handshake_blocking_suspected", "tor-hello+tor-cert") {
		t.Fatalf("expected tor_handshake_blocking_suspected, got %+v", res.Verdicts)
	}
	for _, v := range res.Verdicts {
		if v.Kind == "rst_injected_or_path_reset" || v.Kind == "rst_injected_bidirectional" {
			continue // the per-cell merge result of the same resets; informative, not a second finding
		}
		if v.Kind != "tor_handshake_blocking_suspected" {
			t.Errorf("unexpected verdict %s %s", v.Kind, v.Subject)
			continue
		}
		joined := strings.Join(v.Evidence, "\n")
		if !strings.Contains(joined, "keys on the ClientHello") {
			t.Errorf("%s: evidence should name the ClientHello as the feature:\n%s", v.Subject, joined)
		}
	}
}
