package client

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/server"
)

func plan(test, transport string, port int, variant string) Plan {
	return Plan{TestID: test, Transport: transport, Port: port, Variant: variant, Group: transport + "/" + strconv.Itoa(port)}
}

// The quick profile keeps one cell per rule on the conventional ports and
// drops the rest of the catalog.
func TestQuickFilterKeepsConventionalCells(t *testing.T) {
	catalog := []Plan{
		plan("tcp.echo", "tcp", 80, "cp1-64"),
		plan("tcp.echo", "tcp", 1080, "cp1-64"),
		plan("tcp.echo", "tcp", 443, "cp1-64"),
		plan("tcp.payload.random", "tcp", 443, "random-64"),
		plan("tcp.payload.random", "tcp", 443, "random-2048"),
		plan("tcp.payload.random", "tcp", 8388, "random-2048"),
		plan("tls.sni", "tcp", 443, "benign"),
		plan("tls.sni", "tcp", 443, "trigger:www.youtube.com"),
		plan("tls.sni", "tcp", 443, "absent"),
		plan("tls.sni", "tcp", 443, "list:example.org"),
		plan("tls.sni", "tcp", 4433, "benign"),
		plan("tls.version", "tcp", 443, "1.3"),
		plan("tls.version", "tcp", 443, "1.2"),
		plan("tls.fingerprint", "tcp", 443, "chrome"),
		plan("tls.fingerprint", "tcp", 443, "firefox"),
		plan("tls.fingerprint", "tcp", 443, "android"),
		plan("tls.fingerprint", "tcp", 443, "safari"),
		plan("stun.binding", "udp", 443, "rfc5389"),
		plan("dtls.hello", "udp", 443, "firefox-138"),
		plan("dtls.hello", "udp", 443, "pion"),
		plan("dtls.hello", "udp", 443, "chrome-136"),
		plan("tor.handshake", "tcp", 443, "go-hello+probe-cert"),
		plan("tor.handshake", "tcp", 443, "tor-hello+tor-cert"),
		plan("tor.handshake", "tcp", 443, "tor-hello+tor-cert@1.3"),
		plan("tor.link", "tcp", 443, "tor-hello+tor-cert"),
		plan("openvpn.session", "udp", 1194, "udp+control+data"),
		plan("openvpn.session", "udp", 1194, "udp+tls-auth+data"),
		plan("openvpn.session", "udp", 443, "udp+tls-auth+data"),
		plan("wireguard.session", "udp", 51820, "noise-ik+data"),
		plan("wireguard.session", "udp", 443, "noise-ik+data"),
		plan("tls.burst", "tcp", 443, "chrome-x4"),
		plan("tor.dir", "tcp", 9030, "consensus-microdesc"),
	}
	got := map[string]bool{}
	for _, p := range quickFilter(catalog) {
		got[p.TestID+" "+p.Group+" "+p.Variant] = true
	}
	want := []string{
		"tcp.echo tcp/80 cp1-64", "tcp.echo tcp/443 cp1-64",
		"tcp.payload.random tcp/443 random-2048",
		"tls.sni tcp/443 benign", "tls.sni tcp/443 trigger:www.youtube.com", "tls.sni tcp/443 absent",
		"tls.version tcp/443 1.3", "tls.version tcp/443 1.2",
		"tls.fingerprint tcp/443 chrome", "tls.fingerprint tcp/443 firefox", "tls.fingerprint tcp/443 android",
		"stun.binding udp/443 rfc5389", "dtls.hello udp/443 firefox-138", "dtls.hello udp/443 pion", "dtls.hello udp/443 chrome-136",
		"tor.handshake tcp/443 go-hello+probe-cert", "tor.handshake tcp/443 tor-hello+tor-cert", "tor.handshake tcp/443 tor-hello+tor-cert@1.3",
		"tor.link tcp/443 tor-hello+tor-cert",
		"openvpn.session udp/1194 udp+tls-auth+data",
		"wireguard.session udp/51820 noise-ik+data",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing %s", w)
		}
	}
	for _, drop := range []string{
		"tcp.echo tcp/1080 cp1-64", "tcp.payload.random tcp/443 random-64", "tcp.payload.random tcp/8388 random-2048",
		"tls.sni tcp/443 list:example.org", "tls.sni tcp/4433 benign", "tls.fingerprint tcp/443 safari",
		"openvpn.session udp/1194 udp+control+data", "openvpn.session udp/443 udp+tls-auth+data",
		"wireguard.session udp/443 noise-ik+data", "tls.burst tcp/443 chrome-x4", "tor.dir tcp/9030 consensus-microdesc",
	} {
		if got[drop] {
			t.Errorf("kept %s", drop)
		}
	}
}

// A server without the conventional port, or without the tls-auth key, still
// gets one cell per family.
func TestQuickFilterFallsBack(t *testing.T) {
	catalog := []Plan{
		plan("wireguard.session", "udp", 4000, "noise-ik+data"),
		plan("wireguard.session", "udp", 4001, "noise-ik+data"),
		plan("openvpn.session", "udp", 1194, "udp+control+data"),
		plan("openvpn.session", "udp", 443, "udp+control+data"),
	}
	got := quickFilter(catalog)
	if len(got) != 2 {
		t.Fatalf("got %d plans, want 2: %+v", len(got), got)
	}
	if got[0].TestID != "wireguard.session" || got[0].Port != 4000 {
		t.Errorf("wireguard fallback: %+v", got[0])
	}
	if got[1].TestID != "openvpn.session" || got[1].Port != 1194 || got[1].Variant != "udp+control+data" {
		t.Errorf("openvpn fallback: %+v", got[1])
	}
}

func TestQuickTestsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, id := range QuickTests() {
		if seen[id] {
			t.Errorf("duplicate %s", id)
		}
		seen[id] = true
	}
	if len(seen) < 10 {
		t.Errorf("quick profile draws from %d tests, expected more", len(seen))
	}
}

// The quick profile against the real catalog of a default server: every
// rule matches on its own ports and variant (a typo in a rule would silently
// take a fallback), the count is the "about forty" the docs promise, every
// session cell has its handshake control in the same port group, and the
// only tail cells are the Tor shapes.
func TestQuickPlanAgainstDefaultServer(t *testing.T) {
	cfg := server.Default()
	key := make([]byte, 64)
	c := &Client{
		opt: Options{Profile: "quick", Repeat: 1, TriggerHost: "www.youtube.com", RealitySNI: "www.microsoft.com", BurstN: 4, SessionPackets: 12},
		Params: model.Params{
			TCPPorts: cfg.TCPPorts, UDPPorts: cfg.UDPPorts, DNSPorts: cfg.DNSPorts, DoTPort: cfg.DoTPort,
			DNSZone: "probe.example.net.", QUICPorts: cfg.UDPPorts,
			// The feature list a default server advertises (server.Params).
			Features:       []string{"cp1", "reservations", "doh", "bulk", "whoami", "vpn-session", "ike", "l2tp", "socks5", "vless", "burst", "packets", "tor", "obfs4", "dtls", "stun"},
			OVPNTLSAuthKey: base64.StdEncoding.EncodeToString(key),
		},
		Session: model.SessionResponse{Tests: server.KnownTests},
	}
	plans := c.Catalog()
	if len(plans) < 40 || len(plans) > 50 {
		t.Fatalf("quick plan has %d cells, want about forty: %+v", len(plans), keys(plans))
	}
	for _, r := range quickPlan {
		exact := false
		for _, p := range plans {
			if p.TestID == r.Test && p.Transport == r.Transport && (r.Ports == nil || containsInt(r.Ports, p.Port)) && strings.HasPrefix(p.Variant, r.Variant) {
				exact = true
				break
			}
		}
		if !exact {
			t.Errorf("rule %+v matched nothing exactly on a default server (fallback taken or typo)", r)
		}
	}
	seen := map[string]bool{}
	groups := map[string]map[string]bool{}
	for _, p := range plans {
		k := p.TestID + " " + p.Transport + "/" + strconv.Itoa(p.Port) + " " + p.Variant
		if seen[k] {
			t.Errorf("duplicate cell %s", k)
		}
		seen[k] = true
		if groups[p.Group] == nil {
			groups[p.Group] = map[string]bool{}
		}
		groups[p.Group][p.TestID] = true
		if p.Last && !strings.HasPrefix(p.TestID, "tor.") {
			t.Errorf("unexpected tail cell %s", k)
		}
	}
	for _, p := range plans {
		if h := handshakeTestOf(p.TestID); h != "" && !groups[p.Group][h] {
			t.Errorf("%s in %s has no %s control in the same group", p.TestID, p.Group, h)
		}
	}
}

func keys(plans []Plan) []string {
	out := make([]string, 0, len(plans))
	for _, p := range plans {
		out = append(out, p.TestID+" "+p.Transport+"/"+strconv.Itoa(p.Port)+" "+p.Variant)
	}
	return out
}
