package integration

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/client"
)

// TestPacketCountCut: the path freezes a flow after 20 client segments,
// whatever their size. tcp.echo (one segment) passes, tcp.packets (the same
// envelope in 2-byte segments) is cut, and the classifier names the packet
// counter with the echo as control.
func TestPacketCountCut(t *testing.T) {
	startServer(t)
	startProxy(t, proxyIP, proxiedPorts, func(port int, first []byte) faultAction {
		if port == tcpA {
			return actCutAfter20Pkts
		}
		return actPass
	})
	attempts, res, _ := scan(t, proxyIP, []string{"tcp.echo", "tcp.packets"}, 2)
	for _, a := range attempts {
		switch {
		case a.TestID == "tcp.echo":
			if a.Outcome != client.OutcomeOK {
				t.Errorf("tcp.echo port %d: %s (%s)", a.DstPort, a.Outcome, a.Error)
			}
		case a.TestID == "tcp.packets" && a.DstPort == tcpA:
			if a.Outcome != client.OutcomePacketsCut {
				t.Errorf("tcp.packets %s on the counting port: outcome %s (%s)", a.Variant, a.Outcome, a.Error)
			}
			if a.Detail["packets_sent"] == "" {
				t.Errorf("tcp.packets: no packets_sent recorded")
			}
			if a.Server == nil {
				t.Errorf("tcp.packets: the server saw the first 20 segments, an observation is expected")
			} else if a.Merged != "uplink_drop_or_route_failure" {
				t.Errorf("tcp.packets: merged %s, want uplink (the server never got the whole envelope)", a.Merged)
			}
		case a.TestID == "tcp.packets":
			if a.Outcome != client.OutcomeOK {
				t.Errorf("tcp.packets %s on untouched port %d: %s (%s)", a.Variant, a.DstPort, a.Outcome, a.Error)
			}
		}
	}
	if !hasVerdict(res, "packet_count_cut_suspected", "tcp/20080") {
		t.Errorf("expected packet_count_cut_suspected on tcp/%d, got %+v", tcpA, res.Verdicts)
	}
	for _, v := range res.Verdicts {
		if v.Kind != "packet_count_cut_suspected" {
			t.Errorf("unexpected verdict %s %s", v.Kind, v.Subject)
		}
	}
}

// sniFull extracts a *.probe.invalid server name from a raw ClientHello.
func sniFull(b []byte) string {
	i := bytes.Index(b, []byte(".probe.invalid"))
	if i < 0 {
		return ""
	}
	j := i
	for j > 0 && (b[j-1] >= 'a' && b[j-1] <= 'z' || b[j-1] >= '0' && b[j-1] <= '9' || b[j-1] == '.' || b[j-1] == '-') {
		j--
	}
	return string(b[j : i+len(".probe.invalid")])
}

// TestBurstFreeze: the path counts TLS ClientHellos per server name; from
// the fourth one within a second it swallows the flow. Single handshakes to
// other names pass, so tls.sni stays clean, tls.burst reports burst_freeze
// for both parrots and the classifier says the rule does not depend on the
// fingerprint.
func TestBurstFreeze(t *testing.T) {
	startServer(t)
	var mu sync.Mutex
	type hit struct {
		n    int
		last time.Time
	}
	seen := map[string]*hit{}
	startProxy(t, proxyIP, proxiedPorts, func(port int, first []byte) faultAction {
		if len(first) < 6 || first[0] != 0x16 {
			return actPass
		}
		sni := sniFull(first)
		if sni == "" {
			return actPass
		}
		mu.Lock()
		defer mu.Unlock()
		h := seen[sni]
		if h == nil || time.Since(h.last) > time.Second {
			h = &hit{}
			seen[sni] = h
		}
		h.n++
		h.last = time.Now()
		// From the third hello on, the name is frozen: the rule in the field
		// freezes "all current and further attempts", which for a burst of
		// four means at least the last two here (the first two were already
		// relayed when the count crossed the threshold).
		if h.n >= 3 {
			return actDropUplink
		}
		return actPass
	})
	attempts, res, _ := scan(t, proxyIP, []string{"tcp.echo", "tls.sni", "tls.burst"}, 2)
	bursts := 0
	for _, a := range attempts {
		switch a.TestID {
		case "tls.sni", "tcp.echo":
			if a.Outcome != client.OutcomeOK {
				t.Errorf("%s %s: %s (%s)", a.TestID, a.Variant, a.Outcome, a.Error)
			}
		case "tls.burst":
			bursts++
			if a.Outcome != client.OutcomeBurstFreeze {
				t.Errorf("tls.burst %s: outcome %s (%s) detail=%v", a.Variant, a.Outcome, a.Error, a.Detail)
				continue
			}
			if a.Detail["alpha_ok"] != "2" || a.Detail["beta_outcome"] != client.OutcomeOK || a.Detail["gamma_outcome"] != client.OutcomeOK {
				t.Errorf("tls.burst %s: alpha_ok=%s beta=%s gamma=%s", a.Variant, a.Detail["alpha_ok"], a.Detail["beta_outcome"], a.Detail["gamma_outcome"])
			}
			if a.Detail["server_alpha_seen"] != "2" {
				t.Errorf("tls.burst %s: server saw %s alpha hellos, want 2", a.Variant, a.Detail["server_alpha_seen"])
			}
			if a.Merged != "uplink_drop_or_route_failure" {
				t.Errorf("tls.burst %s: merged %s", a.Variant, a.Merged)
			}
		}
	}
	if bursts != 4 {
		t.Errorf("expected 4 burst attempts (2 parrots × 2 rounds), got %d", bursts)
	}
	if !hasVerdict(res, "tls_burst_freeze_suspected", "chrome-x4") {
		t.Fatalf("expected tls_burst_freeze_suspected for chrome-x4, got %+v", res.Verdicts)
	}
	for _, v := range res.Verdicts {
		if v.Kind != "tls_burst_freeze_suspected" {
			t.Errorf("unexpected verdict %s %s", v.Kind, v.Subject)
			continue
		}
		joined := strings.Join(v.Evidence, "\n")
		if !strings.Contains(joined, "does not depend on the fingerprint") {
			t.Errorf("%s: evidence should say the rule is fingerprint-independent:\n%s", v.Subject, joined)
		}
		if !strings.Contains(joined, "single-handshake baseline") {
			t.Errorf("%s: evidence should cite the tls.sni baseline:\n%s", v.Subject, joined)
		}
	}
}
