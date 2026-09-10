package integration

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xarvel/CensorPulseCli/internal/client"
)

// The fault proxy listens on 127.0.0.2 and relays to the server on
// 127.0.0.1, so the client is pointed at 127.0.0.2 and sees the injected
// path behaviour while the server's observations stay honest.
const proxyIP = "127.0.0.2"

var proxiedPorts = []int{ctrlPort, tcpA, tcpB, tcpC}

// sniOf extracts the SNI from a raw ClientHello (enough for the test).
func sniOf(b []byte) string {
	i := bytes.Index(b, []byte(".probe.invalid"))
	if i > 0 {
		return "probe.invalid"
	}
	if bytes.Contains(b, []byte("www.youtube.com")) {
		return "www.youtube.com"
	}
	return ""
}

// TestDropAfterPayload: the path swallows every TCP payload on one port.
// Client: payload_timeout. Server: never saw it. Merge: uplink drop.
// Classifier: port_blocking_suspected on that port.
func TestDropAfterPayload(t *testing.T) {
	startServer(t)
	startProxy(t, proxyIP, proxiedPorts, func(port int, first []byte) faultAction {
		if port == tcpC {
			return actDropUplink
		}
		return actPass
	})
	attempts, res, _ := scan(t, proxyIP, []string{"tcp.echo", "tcp.payload.random"}, 3)
	for _, a := range attempts {
		if a.DstPort == tcpC {
			if a.Outcome != client.OutcomePayloadTimeout {
				t.Errorf("port %d: outcome %s want payload_timeout", tcpC, a.Outcome)
			}
			if a.Merged != "uplink_drop_or_route_failure" {
				t.Errorf("port %d: merged %s", tcpC, a.Merged)
			}
		} else if a.Outcome != client.OutcomeOK {
			t.Errorf("port %d: unexpected %s", a.DstPort, a.Outcome)
		}
	}
	if !hasVerdict(res, "port_blocking_suspected", "tcp/21194") {
		t.Errorf("expected port_blocking_suspected for tcp/%d, got %+v", tcpC, res.Verdicts)
	}
	for _, v := range res.Verdicts {
		if v.Kind == "port_blocking_suspected" && v.Confidence != "high" {
			t.Errorf("3/3 vs 3/3 should be high confidence, got %s", v.Confidence)
		}
	}
}

// TestRSTOnTriggerSNI: the path resets TLS connections whose ClientHello
// carries the trigger SNI; benign and absent SNI pass.
func TestRSTOnTriggerSNI(t *testing.T) {
	startServer(t)
	startProxy(t, proxyIP, proxiedPorts, func(port int, first []byte) faultAction {
		if len(first) > 5 && first[0] == 0x16 && sniOf(first) == "www.youtube.com" {
			return actRST
		}
		return actPass
	})
	attempts, res, _ := scan(t, proxyIP, []string{"tcp.echo", "tls.sni"}, 3)
	for _, a := range attempts {
		if a.TestID != "tls.sni" {
			continue
		}
		if strings.HasPrefix(a.Variant, "trigger:") {
			if a.Outcome != client.OutcomeMidstreamReset && a.Outcome != client.OutcomeConnectReset && a.Outcome != client.OutcomeMidstreamEOF {
				t.Errorf("trigger SNI: outcome %s (%s)", a.Outcome, a.Error)
			}
			if a.Server != nil {
				t.Errorf("trigger SNI: server should not have seen the hello, got %+v", a.Server)
			}
		} else if a.Outcome != client.OutcomeOK {
			t.Errorf("%s SNI: outcome %s", a.Variant, a.Outcome)
		}
	}
	if !hasVerdict(res, "sni_or_host_blocking_suspected", "trigger:") {
		t.Errorf("expected sni_or_host_blocking_suspected, got %+v", res.Verdicts)
	}
}

// TestModifiedDownlink: the path corrupts server replies on one port. The
// envelope MAC catches it: client=modified, server replied, merge=downlink_modified.
func TestModifiedDownlink(t *testing.T) {
	startServer(t)
	startProxy(t, proxyIP, proxiedPorts, func(port int, first []byte) faultAction {
		if port == tcpB && bytes.HasPrefix(first, []byte("CP1")) {
			return actModifyDown
		}
		return actPass
	})
	attempts, res, _ := scan(t, proxyIP, []string{"tcp.echo"}, 2)
	for _, a := range attempts {
		if a.DstPort != tcpB {
			continue
		}
		if a.Outcome != client.OutcomeModified {
			t.Errorf("modified port: outcome %s (%s)", a.Outcome, a.Error)
		}
		if a.Merged != "downlink_modified" {
			t.Errorf("modified port: merged %s", a.Merged)
		}
	}
	if !hasVerdict(res, "downlink_modified", "") {
		t.Errorf("expected downlink_modified verdict, got %+v", res.Verdicts)
	}
}

// TestDelayIsNotBlocking: 400 ms of extra latency must stay "ok".
func TestDelayIsNotBlocking(t *testing.T) {
	startServer(t)
	startProxy(t, proxyIP, proxiedPorts, func(port int, first []byte) faultAction {
		if port == tcpA {
			return actDelay
		}
		return actPass
	})
	attempts, res, _ := scan(t, proxyIP, []string{"tcp.echo", "http.host"}, 1)
	for _, a := range attempts {
		if a.Outcome != client.OutcomeOK {
			t.Errorf("%s port %d: %s (%s)", a.TestID, a.DstPort, a.Outcome, a.Error)
		}
		if a.DstPort == tcpA && a.Stages["first_byte"] < 350 {
			t.Errorf("delay not reflected in stages: %+v", a.Stages)
		}
	}
	if len(res.Verdicts) != 0 {
		t.Errorf("delay produced verdicts: %+v", res.Verdicts)
	}
}

// TestBulkCutAfterNKB: the path lets short exchanges through but resets a
// long-lived flow once ~16 KB have crossed it. Short tests stay ok; tcp.bulk
// fails with the byte offset; the classifier names it with the offset.
func TestBulkCutAfterNKB(t *testing.T) {
	startServer(t)
	startProxy(t, proxyIP, proxiedPorts, func(port int, first []byte) faultAction {
		if port == tcpA { // every flow on this port, TLS included: short exchanges stay under 16 KB
			return actCutAfter16KB
		}
		return actPass
	})
	attempts, res, _ := scan(t, proxyIP, []string{"tcp.echo", "http.host", "tcp.bulk"}, 2)
	sawCut := false
	for _, a := range attempts {
		switch a.TestID {
		case "tcp.echo", "http.host":
			if a.Outcome != client.OutcomeOK {
				t.Errorf("%s port %d: %s (%s)", a.TestID, a.DstPort, a.Outcome, a.Error)
			}
		case "tcp.bulk":
			if a.DstPort != tcpA {
				if a.Outcome != client.OutcomeOK {
					t.Errorf("bulk on untouched port %d: %s (%s)", a.DstPort, a.Outcome, a.Error)
				}
				continue
			}
			if a.Outcome != client.OutcomeBulkReset && a.Outcome != client.OutcomeBulkStall {
				t.Errorf("bulk %s on cut port: outcome %s (%s)", a.Variant, a.Outcome, a.Error)
			}
			if kb := a.Detail["bulk_cut_kb"]; kb == "" {
				t.Errorf("bulk %s: no cut offset recorded", a.Variant)
			} else {
				sawCut = true
			}
		}
	}
	if !sawCut {
		t.Fatal("no bulk attempt recorded a cut offset")
	}
	if !hasVerdict(res, "bulk_transfer_cut_suspected", "tcp/20080") {
		t.Errorf("expected bulk_transfer_cut_suspected on tcp/%d, got %+v", tcpA, res.Verdicts)
	}
}
