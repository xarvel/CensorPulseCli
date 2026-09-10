package integration

import (
	"strings"
	"testing"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/client"
)

var ovpnSessionVariants = []string{"udp+control+data", "udp+tls-auth+data", "tcp+control+data", "tcp+tls-auth+data"}
var ovpnResetVariants = []string{"udp", "udp+tls-auth", "tcp", "tcp+tls-auth"}

// TestOpenVPNSessionClean: both layouts on both transports complete the
// reset, the control channel and the data channel end to end, and the
// server's counts agree with the client's.
func TestOpenVPNSessionClean(t *testing.T) {
	startServer(t)
	attempts, res, _ := scan(t, "127.0.0.1", []string{"openvpn.reset", "openvpn.session"}, 1)
	seen := map[string]bool{}
	for _, a := range attempts {
		seen[a.TestID+"/"+a.Variant] = true
		if a.Outcome != client.OutcomeOK || a.Merged != "ok" {
			t.Errorf("%s %s/%d %s: outcome=%s merged=%s err=%s", a.TestID, a.Transport, a.DstPort, a.Variant, a.Outcome, a.Merged, a.Error)
			continue
		}
		if a.Server == nil {
			t.Errorf("%s %s: no server observation", a.TestID, a.Variant)
			continue
		}
		wantAuth := "none"
		if strings.Contains(a.Variant, "tls-auth") {
			wantAuth = "tls-auth"
		}
		if a.Server.Detail["control_auth"] != wantAuth {
			t.Errorf("%s %s: server saw control_auth=%q, want %q", a.TestID, a.Variant, a.Server.Detail["control_auth"], wantAuth)
		}
		if a.TestID != "openvpn.session" {
			continue
		}
		d := a.Detail
		if d["ctl_sent"] != "3" || d["ctl_recv"] != "3" {
			t.Errorf("%s %s: control channel %s/%s", a.TestID, a.Variant, d["ctl_recv"], d["ctl_sent"])
		}
		if d["data_sent"] != "12" || d["data_recv"] != d["data_sent"] {
			t.Errorf("%s %s: data channel %s/%s", a.TestID, a.Variant, d["data_recv"], d["data_sent"])
		}
		if d["server_data_seen"] != d["data_sent"] || d["server_ctl_seen"] != d["ctl_sent"] {
			t.Errorf("%s %s: server saw data %s / ctl %s, client sent %s / %s", a.TestID, a.Variant, d["server_data_seen"], d["server_ctl_seen"], d["data_sent"], d["ctl_sent"])
		}
		if a.Transport == "tcp" && !strings.Contains(a.Server.Response, "data") {
			t.Errorf("%s %s: server response %q", a.TestID, a.Variant, a.Server.Response)
		}
	}
	for _, v := range ovpnSessionVariants {
		if !seen["openvpn.session/"+v] {
			t.Errorf("variant openvpn.session %s not planned", v)
		}
	}
	for _, v := range ovpnResetVariants {
		if !seen["openvpn.reset/"+v] {
			t.Errorf("variant openvpn.reset %s not planned", v)
		}
	}
	if len(res.Verdicts) != 0 {
		t.Errorf("unexpected verdicts: %+v", res.Verdicts)
	}
}

// TestOpenVPNDataChannelCut: the path lets the reset and the whole control
// channel through and swallows every P_DATA_V2 the client sends, on UDP and
// on TCP (the Tattelecom signature: TLS handshake and PUSH_REPLY complete,
// then not one data packet crosses). openvpn.reset passes, openvpn.session
// reports session_cut with the control channel intact, the merge says
// uplink, and the classifier names it with high confidence.
func TestOpenVPNDataChannelCut(t *testing.T) {
	startServer(t)
	// The test server offers no port 1194, so OpenVPN runs on the first
	// offered port of each transport; the faults key on the packet shape,
	// not the port.
	startProxy(t, proxyIP, proxiedPorts, func(port int, first []byte) faultAction {
		if len(first) > 2 && first[2]>>3 == 7 && (first[1] == 14 || first[1] == 42) {
			return actDropOVPNData
		}
		return actPass
	})
	startUDPRelay(t, proxyIP, []int{udpA, udpB, udpC}, func(port int, b []byte) bool {
		return len(b) > 8 && b[0] == 9<<3
	})
	attempts, res, _ := scanWithTimeout(t, proxyIP, []string{"tcp.echo", "tcp.payload.random", "udp.echo", "udp.payload.random", "openvpn.reset", "openvpn.session"}, 3, 1500*time.Millisecond)
	cut := map[string]int{}
	for _, a := range attempts {
		switch a.TestID {
		case "openvpn.session":
			if a.Outcome != client.OutcomeSessionCut {
				t.Errorf("%s %s: outcome %s (%s), want session_cut", a.Transport, a.Variant, a.Outcome, a.Error)
				continue
			}
			cut[a.Variant]++
			d := a.Detail
			if d["ctl_recv"] == "0" || d["ctl_recv"] == "" {
				t.Errorf("%s %s: control channel should have passed, ctl_recv=%q", a.Transport, a.Variant, d["ctl_recv"])
			}
			if d["data_recv"] != "0" || d["data_first_loss"] != "0" {
				t.Errorf("%s %s: data_recv=%q data_first_loss=%q", a.Transport, a.Variant, d["data_recv"], d["data_first_loss"])
			}
			if d["server_data_seen"] != "0" || d["server_ctl_seen"] != d["ctl_sent"] {
				t.Errorf("%s %s: server saw data %q ctl %q (ctl_sent %q)", a.Transport, a.Variant, d["server_data_seen"], d["server_ctl_seen"], d["ctl_sent"])
			}
			if a.Merged != "uplink_drop_after_handshake" {
				t.Errorf("%s %s: merged %s", a.Transport, a.Variant, a.Merged)
			}
		default:
			if a.Outcome != client.OutcomeOK {
				t.Errorf("%s %s/%d %s: %s (%s)", a.TestID, a.Transport, a.DstPort, a.Variant, a.Outcome, a.Error)
			}
		}
	}
	for _, v := range ovpnSessionVariants {
		if cut[v] != 3 {
			t.Errorf("variant %s: %d/3 rounds cut", v, cut[v])
		}
	}
	verdicts := 0
	for _, v := range res.Verdicts {
		if v.Kind != "openvpn_session_cut_suspected" {
			t.Errorf("unexpected verdict %+v", v)
			continue
		}
		verdicts++
		if v.Confidence != "high" {
			t.Errorf("%s: confidence %s, want high (%v)", v.Subject, v.Confidence, v.Evidence)
		}
		joined := strings.Join(v.Evidence, "\n")
		if !strings.Contains(joined, "control channel passed") || !strings.Contains(joined, "data channel cut: not one data packet came back") {
			t.Errorf("%s: evidence does not say control passed / data cut: %v", v.Subject, v.Evidence)
		}
		if !strings.Contains(joined, "data stopped on the way to the server") {
			t.Errorf("%s: evidence does not give the direction: %v", v.Subject, v.Evidence)
		}
	}
	if verdicts != len(ovpnSessionVariants) {
		t.Errorf("%d openvpn_session_cut_suspected verdicts, want %d: %+v", verdicts, len(ovpnSessionVariants), res.Verdicts)
	}
}

// TestOpenVPNTLSAuthResetRejectedWithoutKey: a tls-auth reset with a wrong
// HMAC gets no answer, like from a real server.
func TestOpenVPNTLSAuthBadHMACIsSilent(t *testing.T) {
	startServer(t)
	bad := append([]byte{7 << 3}, make([]byte, 41)...)
	udpSilent(t, udpB, bad, "tls-auth reset with a bogus hmac")
}
