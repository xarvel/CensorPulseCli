package client

import (
	"testing"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/model"
)

func obs(bytesOut int, response, serverError, closeReason string) *model.Observation {
	return &model.Observation{BytesOut: bytesOut, Response: response, ServerError: serverError, Close: closeReason, Detail: map[string]string{}}
}

func attempt(outcome, transport string, server *model.Observation) *Attempt {
	return &Attempt{TestID: "t", Transport: transport, Outcome: outcome, Server: server, Detail: map[string]string{}, Stages: map[string]float64{"first_write": 2, "done": 1500}}
}

// A ServerHello that went out before the client's answer got lost is a reply
// the path dropped, whatever the server's handshake error says.
func TestMergeServerRepliedThenReadError(t *testing.T) {
	a := attempt(OutcomePayloadTimeout, "tcp", obs(879, "handshake_failed", "EOF", "client_eof"))
	if got := mergeVerdict(a); got != "downlink_drop" {
		t.Fatalf("got %s, want downlink_drop", got)
	}
	// Nothing went out and the server timed out reading: the request was cut
	// on the way in.
	a = attempt(OutcomePayloadTimeout, "tcp", obs(0, "handshake_failed", "read tcp: i/o timeout", "timeout"))
	if got := mergeVerdict(a); got != "uplink_drop_or_route_failure" {
		t.Fatalf("got %s, want uplink_drop_or_route_failure", got)
	}
	// A genuine server fault stays a server error.
	a = attempt(OutcomePayloadTimeout, "tcp", obs(0, "handshake_failed", "tls: no cipher suite supported", "normal"))
	if got := mergeVerdict(a); got != "server_error" {
		t.Fatalf("got %s, want server_error", got)
	}
}

// The client never completed the TCP handshake: an empty connection accepted
// in the reservation window is not the server staying silent.
func TestMergeConnectTimeoutWithEmptyServerFlow(t *testing.T) {
	a := attempt(OutcomeConnectTimeout, "tcp", obs(0, "silence", "", "client_eof"))
	if got := mergeVerdict(a); got != "connect_diverged_middlebox_or_misattributed" {
		t.Fatalf("got %s", got)
	}
	// With a payload written and the server recording an empty connection,
	// the payload was cut on the way in (T-Mobile RU 2026-09-17: the tls-auth
	// reset on tcp/443 and tcp/1194, 44 bytes after a completed handshake,
	// never reached the server).
	a = attempt(OutcomePayloadTimeout, "tcp", obs(0, "silence", "", "timeout"))
	a.Server.Parse = model.ParseEmpty
	if got := mergeVerdict(a); got != "uplink_drop_or_route_failure" {
		t.Fatalf("got %s, want uplink_drop_or_route_failure", got)
	}
	// A request that arrived and got no answer is the server staying silent.
	a = attempt(OutcomePayloadTimeout, "tcp", obs(0, "silence", "", "client_eof"))
	a.Server.Parse = model.ParseEnvelope
	a.Server.BytesIn = 64
	if got := mergeVerdict(a); got != "server_silent" {
		t.Fatalf("got %s, want server_silent", got)
	}
}

// udp.packets: the server's observations are matched by nonce, not by source
// port, because behind NAT the port the server sees is not ours. A round that
// lost one datagram in the middle and got the rest answered is not a cut.
func TestMergeUDPPacketsSeenByNonce(t *testing.T) {
	a := attempt(OutcomePacketsCut, "udp", nil)
	a.TestID = "udp.packets"
	a.DstPort = 443
	a.SrcPort = 40000
	a.Nonce = "n1"
	a.nonces = []string{"n1", "n2", "n3", "n4"}
	a.Detail["packets_sent"] = "4"
	obs := []model.Observation{
		{TestID: "udp.packets", Transport: "udp", DstPort: 443, SrcPort: 12345, Nonce: "n1", Response: "echo", BytesOut: 8},
		{TestID: "udp.packets", Transport: "udp", DstPort: 443, SrcPort: 12345, Nonce: "n2", Response: "echo", BytesOut: 8},
		{TestID: "udp.packets", Transport: "udp", DstPort: 443, SrcPort: 12345, Nonce: "n4", Response: "echo", BytesOut: 8},
	}
	mergeObservations([]*Attempt{a}, obs, 0)
	if a.Detail["server_packets_seen"] != "3" {
		t.Fatalf("server_packets_seen = %q, want 3", a.Detail["server_packets_seen"])
	}
	if a.Server == nil || a.Server.Nonce != "n1" {
		t.Fatalf("first datagram's observation not attached: %+v", a.Server)
	}
	if got := mergeVerdict(a); got != "uplink_drop_or_route_failure" {
		t.Fatalf("merged = %q, want uplink_drop_or_route_failure (3 of 4 seen)", got)
	}
}

// The server saw the payload only after the client had given up: late, not
// dropped on the way back.
func TestMergeDelayedPastDeadline(t *testing.T) {
	a := attempt(OutcomePayloadTimeout, "tcp", obs(373, "http_200", "", "normal"))
	a.Detail["server_delay_ms"] = "3966"
	if got := mergeVerdict(a); got != "uplink_delayed_past_deadline" {
		t.Fatalf("got %s", got)
	}
	a.Detail["server_delay_ms"] = "120"
	if got := mergeVerdict(a); got != "downlink_drop" {
		t.Fatalf("prompt reply: got %s, want downlink_drop", got)
	}
	// Within the skew margin nothing is claimed.
	a.Detail["server_delay_ms"] = "2000"
	if got := mergeVerdict(a); got != "downlink_drop" {
		t.Fatalf("inside margin: got %s, want downlink_drop", got)
	}
}

func TestMarkServerDelay(t *testing.T) {
	start := time.Date(2026, 9, 13, 6, 30, 0, 0, time.UTC)
	a := &Attempt{StartedAt: start, Stages: map[string]float64{"first_write": 10}, Detail: map[string]string{}}
	o := &model.Observation{FirstSeenAt: start.Add(4*time.Second + 310*time.Millisecond)}
	markServerDelay(a, o, 300*time.Millisecond)
	if a.Detail["server_delay_ms"] != "4000" {
		t.Fatalf("delay %s", a.Detail["server_delay_ms"])
	}
}

// A QUIC handshake that ran out of time is not a modified downlink.
func TestMergeQUICTimeoutIsNotModified(t *testing.T) {
	a := attempt(OutcomeQUICHandshake, "udp", obs(0, "quic_forwarded", "", "normal"))
	a.Error = "context deadline exceeded"
	if got := mergeVerdict(a); got != "stalled_after_server_saw_it" {
		t.Fatalf("got %s", got)
	}
	a.Server = nil
	if got := mergeVerdict(a); got != "uplink_drop_or_route_failure" {
		t.Fatalf("unseen: got %s", got)
	}
	// A real crypto failure with the server having replied keeps its meaning.
	a = attempt(OutcomeQUICHandshake, "udp", obs(0, "quic_forwarded", "", "normal"))
	a.Error = "CRYPTO_ERROR 0x128 (remote): tls: bad certificate"
	if got := mergeVerdict(a); got != "downlink_modified" {
		t.Fatalf("crypto error: got %s", got)
	}
}

// tls.burst: the server answering some of the parallel hellos that never
// arrive is a downlink drop; hellos that arrived cut are an uplink drop; the
// server only "rejected" when it saw whole hellos and answered none.
func TestMergeBurst(t *testing.T) {
	mk := func(seen, answered, hello, partial string) *Attempt {
		a := attempt(OutcomeBurstFreeze, "tcp", obs(0, "handshake_failed", "", "client_eof"))
		a.Detail = map[string]string{"burst_n": "4", "server_alpha_seen": seen, "server_alpha_answered": answered, "server_alpha_hello": hello, "server_alpha_partial": partial}
		return a
	}
	cases := []struct{ seen, answered, hello, partial, want string }{
		{"2", "0", "0", "0", "uplink_drop_or_route_failure"},
		{"4", "1", "0", "3", "downlink_drop"},
		{"4", "4", "4", "0", "downlink_drop"},
		{"4", "0", "0", "4", "uplink_drop_or_route_failure"},
		{"4", "0", "0", "0", "server_rejected_handshake"},
	}
	for _, c := range cases {
		if got := mergeVerdict(mk(c.seen, c.answered, c.hello, c.partial)); got != c.want {
			t.Errorf("seen=%s answered=%s partial=%s: got %s, want %s", c.seen, c.answered, c.partial, got, c.want)
		}
	}
	// An old report without the counts reads the attached observation.
	a := attempt(OutcomeBurstFreeze, "tcp", obs(1966, "handshake_failed", "read tcp: i/o timeout", "timeout"))
	a.Detail = map[string]string{"burst_n": "4", "server_alpha_seen": "4", "server_alpha_hello": "0"}
	if got := mergeVerdict(a); got != "downlink_drop" {
		t.Fatalf("old report, server sent bytes: got %s", got)
	}
	a = attempt(OutcomeBurstFreeze, "tcp", obs(0, "handshake_failed", "read tcp: i/o timeout", "timeout"))
	a.Detail = map[string]string{"burst_n": "4", "server_alpha_seen": "4", "server_alpha_hello": "0"}
	if got := mergeVerdict(a); got != "uplink_drop_or_route_failure" {
		t.Fatalf("old report, hello cut: got %s", got)
	}
}

func TestEstimateSkew(t *testing.T) {
	before := time.Date(2026, 9, 13, 6, 30, 48, 0, time.UTC)
	after := before.Add(100 * time.Millisecond)
	if got := EstimateSkew("2026-09-13T06:30:48.350Z", before, after); got != 300*time.Millisecond {
		t.Fatalf("skew %v", got)
	}
	if got := EstimateSkew("garbage", before, after); got != 0 {
		t.Fatalf("unparsable: %v", got)
	}
}
