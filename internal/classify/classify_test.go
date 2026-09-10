package classify

import (
	"strings"
	"testing"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/client"
	"github.com/xarvel/CensorPulseCli/internal/model"
)

func mk(test, role, variant, tr string, port int, outcome, merged string, seen bool) *client.Attempt {
	a := &client.Attempt{TestID: test, Role: role, Variant: variant, Transport: tr, DstPort: port, Outcome: outcome, Merged: merged}
	if seen {
		a.Server = &model.Observation{}
	}
	return a
}

func rep(n int, f func() *client.Attempt) []*client.Attempt {
	var out []*client.Attempt
	for i := 0; i < n; i++ {
		out = append(out, f())
	}
	return out
}

func kinds(r Result) map[string]int {
	m := map[string]int{}
	for _, v := range r.Verdicts {
		m[v.Kind]++
	}
	return m
}

func TestProtocolBlocking(t *testing.T) {
	var at []*client.Attempt
	at = append(at, rep(3, func() *client.Attempt { return mk("udp.echo", "baseline", "cp1-64", "udp", 51820, "ok", "ok", true) })...)
	at = append(at, rep(3, func() *client.Attempt {
		return mk("udp.payload.random", "control", "random-64", "udp", 51820, "ok", "ok", true)
	})...)
	at = append(at, rep(3, func() *client.Attempt {
		return mk("wireguard.init", "variant", "noise-ik", "udp", 51820, "payload_timeout", "uplink_drop_or_route_failure", false)
	})...)
	r := Classify(at, true)
	k := kinds(r)
	if k["protocol_blocking_suspected"] != 1 {
		t.Fatalf("verdicts: %+v", r.Verdicts)
	}
	if r.Verdicts[0].Confidence != "high" {
		t.Errorf("confidence %s", r.Verdicts[0].Confidence)
	}
}

func TestControlFailedIsInconclusive(t *testing.T) {
	var at []*client.Attempt
	at = append(at, rep(3, func() *client.Attempt { return mk("udp.echo", "baseline", "cp1-64", "udp", 443, "ok", "ok", true) })...)
	at = append(at, rep(3, func() *client.Attempt {
		return mk("udp.payload.random", "control", "random-64", "udp", 443, "payload_timeout", "uplink_drop_or_route_failure", false)
	})...)
	at = append(at, rep(3, func() *client.Attempt {
		return mk("quic.v1", "variant", "h3", "udp", 443, "quic_no_response", "uplink_drop_or_route_failure", false)
	})...)
	k := kinds(Classify(at, true))
	if k["protocol_blocking_suspected"] != 0 || k["control_failed_inconclusive"] != 1 {
		t.Fatalf("kinds: %+v", k)
	}
}

func TestEndpointAndUDPBlocking(t *testing.T) {
	var at []*client.Attempt
	for _, p := range []int{80, 443} {
		p := p
		at = append(at, rep(3, func() *client.Attempt { return mk("tcp.echo", "baseline", "cp1-64", "tcp", p, "ok", "ok", true) })...)
		at = append(at, rep(3, func() *client.Attempt {
			return mk("udp.echo", "baseline", "cp1-64", "udp", p, "payload_timeout", "uplink_drop_or_route_failure", false)
		})...)
	}
	k := kinds(Classify(at, true))
	if k["udp_blocking_suspected"] != 1 || k["endpoint_blocking_suspected"] != 0 {
		t.Fatalf("kinds: %+v", k)
	}
	// now everything fails
	for _, a := range at {
		a.Outcome, a.Merged, a.Server = "connect_timeout", "uplink_drop_or_route_failure", nil
	}
	k = kinds(Classify(at, true))
	if k["endpoint_blocking_suspected"] != 1 {
		t.Fatalf("kinds: %+v", k)
	}
}

func TestSNIDifferential(t *testing.T) {
	var at []*client.Attempt
	at = append(at, rep(3, func() *client.Attempt { return mk("tls.sni", "baseline", "benign", "tcp", 443, "ok", "ok", true) })...)
	at = append(at, rep(3, func() *client.Attempt { return mk("tls.sni", "control", "absent", "tcp", 443, "ok", "ok", true) })...)
	at = append(at, rep(2, func() *client.Attempt {
		return mk("tls.sni", "variant", "trigger:x", "tcp", 443, "midstream_reset", "rst_injected_or_path_reset", false)
	})...)
	r := Classify(at, true)
	k := kinds(r)
	// The reset is the mechanism of the differential finding, not a second
	// finding of its own.
	if k["sni_or_host_blocking_suspected"] != 1 || k["rst_injected_or_path_reset"] != 0 {
		t.Fatalf("kinds: %+v", k)
	}
	mech := false
	for _, e := range r.Verdicts[0].Evidence {
		if strings.Contains(e, "mechanism:") && strings.Contains(e, "rst_injected_or_path_reset") {
			mech = true
		}
	}
	if !mech {
		t.Errorf("mechanism not attached: %+v", r.Verdicts[0])
	}
}

// A port where HTTP passes but opaque payloads are dropped after the server
// answered them is a transparent proxy, not port blocking (the RU mobile
// case of 2026-09-11: tcp/80 and tcp/8080).
func TestTransparentProxyIsNotPortBlocking(t *testing.T) {
	var at []*client.Attempt
	at = append(at, rep(3, func() *client.Attempt { return mk("tcp.echo", "baseline", "cp1-64", "tcp", 1194, "ok", "ok", true) })...)
	at = append(at, rep(3, func() *client.Attempt {
		return mk("tcp.echo", "baseline", "cp1-64", "tcp", 80, "payload_timeout", "downlink_drop", true)
	})...)
	at = append(at, rep(3, func() *client.Attempt {
		return mk("tcp.payload.random", "control", "random-64", "tcp", 80, "payload_timeout", "downlink_drop", true)
	})...)
	at = append(at, rep(3, func() *client.Attempt { return mk("http.host", "baseline", "benign", "tcp", 80, "ok", "ok", true) })...)
	r := Classify(at, true)
	k := kinds(r)
	if k["port_blocking_suspected"] != 0 || k["transparent_proxy_suspected"] != 1 {
		t.Fatalf("kinds: %+v", k)
	}
	for _, v := range r.Verdicts {
		if v.Kind == "transparent_proxy_suspected" && v.Confidence != "high" {
			t.Errorf("confidence %s", v.Confidence)
		}
	}
	// Without the passing HTTP family it is port blocking.
	at = at[:9]
	k = kinds(Classify(at, true))
	if k["port_blocking_suspected"] != 1 || k["transparent_proxy_suspected"] != 0 {
		t.Fatalf("kinds: %+v", k)
	}
}

// Handshake passes, data does not: the stateful VPN blocking signature.
func TestVPNSessionCut(t *testing.T) {
	var at []*client.Attempt
	at = append(at, rep(3, func() *client.Attempt { return mk("udp.echo", "baseline", "cp1-64", "udp", 51820, "ok", "ok", true) })...)
	at = append(at, rep(3, func() *client.Attempt {
		return mk("udp.payload.random", "control", "random-64", "udp", 51820, "ok", "ok", true)
	})...)
	at = append(at, rep(3, func() *client.Attempt {
		return mk("wireguard.init", "variant", "noise-ik", "udp", 51820, "ok", "ok", true)
	})...)
	at = append(at, rep(3, func() *client.Attempt {
		a := mk("wireguard.session", "variant", "noise-ik+data", "udp", 51820, "session_cut", "uplink_drop_after_handshake", true)
		a.Detail = map[string]string{"data_sent": "12", "data_recv": "2", "server_data_seen": "2"}
		return a
	})...)
	r := Classify(at, true)
	k := kinds(r)
	if k["wireguard_session_cut_suspected"] != 1 || k["protocol_blocking_suspected"] != 0 || k["uplink_drop_after_handshake"] != 0 {
		t.Fatalf("kinds: %+v", k)
	}
	v := r.Verdicts[0]
	if v.Confidence != "high" || len(v.Evidence) < 3 {
		t.Errorf("verdict: %+v", v)
	}
	// When the handshake itself fails, it is protocol blocking, reported once.
	for _, a := range at {
		if a.TestID == "wireguard.init" {
			a.Outcome, a.Merged, a.Server = "payload_timeout", "uplink_drop_or_route_failure", nil
		}
	}
	k = kinds(Classify(at, true))
	if k["wireguard_session_cut_suspected"] != 0 || k["protocol_blocking_suspected"] != 1 {
		t.Fatalf("kinds: %+v", k)
	}
}

// A port whose SYN-ACK comes back in a fraction of the time the other ports
// need is answered by something closer than the server.
func TestSynAckCrossPort(t *testing.T) {
	var at []*client.Attempt
	for _, port := range []int{80, 443, 1194, 4433, 8388} {
		port := port
		ms := 110.0
		if port == 80 || port == 443 {
			ms = 3.0
		}
		at = append(at, rep(3, func() *client.Attempt {
			a := mk("tcp.echo", "baseline", "cp1-64", "tcp", port, "ok", "ok", true)
			a.Stages = map[string]float64{"connect": ms}
			return a
		})...)
	}
	rtt := mk("tcp.rtt", "baseline", "x5", "tcp", 443, "ok", "ok", true)
	rtt.Detail = map[string]string{"synack_suspect": "true", "connect_min_ms": "1.9", "payload_min_ms": "170", "connect_payload_ratio": "0.01"}
	at = append(at, rtt)
	r := Classify(at, true)
	k := kinds(r)
	if k["synack_local_termination_suspected"] != 2 || k["synack_spoof_signal"] != 0 {
		t.Fatalf("kinds: %+v", k)
	}
	for _, v := range r.Verdicts {
		if v.Subject == "tcp/443" && v.Confidence != "medium" {
			t.Errorf("tcp/443 with tcp.rtt confirmation should be medium: %+v", v)
		}
		if v.Subject == "tcp/80" && v.Confidence != "low" {
			t.Errorf("tcp/80 without tcp.rtt should be low: %+v", v)
		}
	}
	// On a LAN (every port fast) nothing fires.
	for _, a := range at {
		if a.TestID == "tcp.echo" {
			a.Stages["connect"] = 0.4
		}
	}
	at = at[:len(at)-1]
	if k := kinds(Classify(at, true)); len(k) != 0 {
		t.Fatalf("kinds: %+v", k)
	}
}

func TestProbeUnreachable(t *testing.T) {
	r := Classify(nil, false)
	if len(r.Verdicts) != 1 || r.Verdicts[0].Kind != "probe_unreachable" {
		t.Fatalf("%+v", r)
	}
}

// A burst of failures across unrelated ports whose cells pass in the other
// rounds is an outage of the scan, not a rule: the attempts are flagged and
// left out of the cells, and the note names the window.
func TestTransientOutageIsFlagged(t *testing.T) {
	t0 := time.Date(2026, 9, 13, 6, 30, 48, 0, time.UTC)
	var at []*client.Attempt
	ports := []int{80, 443, 1194, 4433, 8388, 9001}
	for round := 1; round <= 3; round++ {
		for i, port := range ports {
			a := mk("tcp.echo", "baseline", "cp1-64", "tcp", port, "ok", "ok", true)
			a.Round = round
			a.StartedAt = t0.Add(time.Duration(round*60+i) * time.Second)
			if round == 1 {
				a.Outcome, a.Merged, a.Server = "connect_timeout", "uplink_drop_or_route_failure", nil
			}
			at = append(at, a)
		}
	}
	// One cell that fails every round is a rule and must survive the window.
	for round := 1; round <= 3; round++ {
		a := mk("wireguard.init", "variant", "noise-ik", "udp", 51820, "payload_timeout", "uplink_drop_or_route_failure", false)
		a.Round, a.StartedAt = round, t0.Add(time.Duration(round*60+2)*time.Second)
		at = append(at, a)
		e := mk("udp.echo", "baseline", "cp1-64", "udp", 51820, "ok", "ok", true)
		e.Round, e.StartedAt = round, t0.Add(time.Duration(round*60+3)*time.Second)
		at = append(at, e)
	}
	r := Classify(at, true)
	if len(r.Notes) != 1 || !strings.HasPrefix(r.Notes[0], "transient outage: 6 attempts on 6 ports") {
		t.Fatalf("notes: %v", r.Notes)
	}
	flagged := 0
	for _, a := range at {
		if a.Detail["transient"] == "true" {
			flagged++
			if a.TestID != "tcp.echo" || a.Round != 1 {
				t.Errorf("flagged %s round %d", a.TestID, a.Round)
			}
		}
	}
	if flagged != 6 {
		t.Fatalf("flagged %d", flagged)
	}
	for _, c := range r.Cells {
		if c.TestID == "tcp.echo" && (c.Total != 2 || c.OK != 2) {
			t.Errorf("cell without the outage: %+v", c)
		}
	}
	k := kinds(r)
	if k["protocol_blocking_suspected"] != 1 || k["port_blocking_suspected"] != 0 {
		t.Fatalf("kinds: %+v", k)
	}
	// Fewer failures, or on fewer ports, are not an outage.
	for _, a := range at {
		if a.TestID == "tcp.echo" && a.Round == 1 && (a.DstPort == 80 || a.DstPort == 443 || a.DstPort == 1194 || a.DstPort == 4433) {
			a.Outcome, a.Merged = "ok", "ok"
			delete(a.Detail, "transient")
		} else {
			delete(a.Detail, "transient")
		}
	}
	if r := Classify(at, true); len(r.Notes) != 0 {
		t.Fatalf("two failures flagged as outage: %v", r.Notes)
	}
}

// Behind NAT the IPsec / L2TP ALG cannot be told from a censor: never high.
func TestIKEBehindNATIsNotHigh(t *testing.T) {
	var at []*client.Attempt
	at = append(at, rep(3, func() *client.Attempt { return mk("udp.echo", "baseline", "cp1-64", "udp", 500, "ok", "ok", true) })...)
	at = append(at, rep(3, func() *client.Attempt {
		return mk("udp.payload.random", "control", "random-64", "udp", 500, "ok", "ok", true)
	})...)
	at = append(at, rep(3, func() *client.Attempt {
		return mk("ikev2.init", "variant", "plain", "udp", 500, "payload_timeout", "uplink_drop_or_route_failure", false)
	})...)
	conf := func() string {
		for _, v := range Classify(at, true).Verdicts {
			if v.Kind == "protocol_blocking_suspected" {
				return v.Confidence
			}
		}
		return ""
	}
	if c := conf(); c != "high" {
		t.Fatalf("without NAT evidence: %s", c)
	}
	at[0].SrcPort, at[0].Server.SrcPort = 46762, 19355
	if c := conf(); c != "medium" {
		t.Fatalf("behind NAT: %s", c)
	}
}

// A transparent proxy found on the same port corroborates the fast SYN-ACK.
func TestSynAckCorroboratedByProxy(t *testing.T) {
	var at []*client.Attempt
	for _, port := range []int{80, 1194, 4433, 8388} {
		port := port
		ms := 110.0
		if port == 80 {
			ms = 3.0
		}
		outcome, merged := "ok", "ok"
		if port == 80 {
			outcome, merged = "payload_timeout", "downlink_drop"
		}
		at = append(at, rep(3, func() *client.Attempt {
			a := mk("tcp.echo", "baseline", "cp1-64", "tcp", port, outcome, merged, true)
			a.Stages = map[string]float64{"connect": ms}
			return a
		})...)
	}
	at = append(at, rep(3, func() *client.Attempt {
		a := mk("http.host", "baseline", "benign", "tcp", 80, "ok", "ok", true)
		a.Stages = map[string]float64{"connect": 3.0}
		return a
	})...)
	r := Classify(at, true)
	k := kinds(r)
	if k["transparent_proxy_suspected"] != 1 || k["synack_local_termination_suspected"] != 1 {
		t.Fatalf("kinds: %+v", k)
	}
	for _, v := range r.Verdicts {
		if v.Kind == "synack_local_termination_suspected" && v.Confidence != "medium" {
			t.Errorf("corroborated SYN-ACK should be medium: %+v", v)
		}
	}
	if strings.Contains(r.Summary, "low confidence") {
		t.Errorf("summary: %s", r.Summary)
	}
}

// Low-confidence findings are listed apart in the summary.
func TestSummarySeparatesLowConfidence(t *testing.T) {
	var at []*client.Attempt
	at = append(at, rep(3, func() *client.Attempt { return mk("udp.echo", "baseline", "cp1-64", "udp", 443, "ok", "ok", true) })...)
	a := mk("quic.v1", "variant", "h3", "udp", 443, "tls_parse_failure", "downlink_modified", true)
	at = append(at, a, mk("quic.v1", "variant", "h3", "udp", 443, "ok", "ok", true), mk("quic.v1", "variant", "h3", "udp", 443, "ok", "ok", true))
	r := Classify(at, true)
	if r.Summary != "low confidence only: downlink_modified×1" {
		t.Fatalf("summary: %q", r.Summary)
	}
}
