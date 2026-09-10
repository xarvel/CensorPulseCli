package classify

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/xarvel/CensorPulseCli/internal/client"
)

// handshakeTestOf maps a *.session test to its handshake-only control.
func handshakeTestOf(test string) string {
	switch test {
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

// handshakeVariantOf maps a session variant to the handshake variant of the
// same signature by stripping the "+data" and "+control" suffixes.
func handshakeVariantOf(variant string) string {
	v := strings.TrimSuffix(variant, "+data")
	return strings.TrimSuffix(v, "+control")
}

// echoTestFor names the baseline echo test of a transport.
func echoTestFor(transport string) string { return plainTestFor(transport, "echo") }

// plainTestFor names one of the opaque-payload tests of a transport (echo,
// payload.random, packets): the controls the protocol tests on the same port
// are compared with. Anything that is not UDP rides TCP.
func plainTestFor(transport, name string) string {
	if transport == "udp" {
		return "udp." + name
	}
	return "tcp." + name
}

// detailInts collects an integer detail field over attempts, skipping the
// attempts that do not carry it (or carry something that is not a number).
// With several keys an attempt gives the first one that parses: a field
// that was renamed is read under both names.
func detailInts(attempts []*client.Attempt, keys ...string) []int {
	var out []int
	for _, a := range attempts {
		for _, k := range keys {
			if v, err := strconv.Atoi(a.Detail[k]); err == nil {
				out = append(out, v)
				break
			}
		}
	}
	return out
}

func median(v []int) int {
	if len(v) == 0 {
		return 0
	}
	s := append([]int(nil), v...)
	sort.Ints(s)
	return s[len(s)/2]
}

func medianF(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	return s[len(s)/2]
}

// isAppProtocol reports whether a test family exercises a recognised
// application protocol a transparent proxy could relay (as opposed to
// opaque payloads, timing probes or long flows).
func isAppProtocol(test string) bool {
	return strings.HasPrefix(test, "http.") || strings.HasPrefix(test, "tls.") || strings.HasPrefix(test, "dns.") || test == "tor.dir"
}

func directionFrom(merged string) string {
	switch merged {
	case "uplink_drop_after_handshake", "uplink_drop_or_route_failure":
		return "data stopped on the way to the server"
	case "downlink_drop_after_handshake", "downlink_drop":
		return "the server answered every packet it saw; the answers were dropped on the way back"
	case "uplink_delayed_past_deadline":
		return "the server saw the data only after the client had given up: lost first, retransmitted later"
	case "stalled_after_server_saw_it":
		return "the server saw the first packet; which direction lost the rest is unknown"
	case "connect_diverged_middlebox_or_misattributed":
		return "the client never completed the TCP handshake, yet an empty connection from its address was accepted"
	}
	return merged
}

// natDetected reports whether the server saw the client's flows from a
// different source port than the client bound: a NAT (or proxy) rewrites
// them. The first example is returned for the evidence line.
func natDetected(attempts []*client.Attempt) (bool, string) {
	for _, a := range attempts {
		if a.Server != nil && a.SrcPort != 0 && a.Server.SrcPort != 0 && a.SrcPort != a.Server.SrcPort {
			return true, fmt.Sprintf("the client is behind NAT (source port %d left the client, the server saw %d)", a.SrcPort, a.Server.SrcPort)
		}
	}
	return false, ""
}
