package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/xarvel/CensorPulseCli/internal/dnsx"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "slow" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

func TestCloseReason(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{nil, "normal"},
		{io.EOF, "client_eof"},
		{fmt.Errorf("read: %w", io.EOF), "client_eof"},
		{io.ErrUnexpectedEOF, "server_error"}, // a cut frame is not a clean EOF
		{syscall.ECONNRESET, "client_reset"},
		{&net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)}, "client_reset"},
		{os.ErrDeadlineExceeded, "timeout"},
		{&net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}, "timeout"},
		{timeoutErr{}, "timeout"},
		{fmt.Errorf("tls: %w", timeoutErr{}), "timeout"},
		{syscall.EPIPE, "server_error"},
		{errors.New("bad frame"), "server_error"},
	} {
		if got := closeReason(tc.err); got != tc.want {
			t.Errorf("closeReason(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestIsTLSClientHello(t *testing.T) {
	hello := func(recMinor, hsType byte) []byte { return []byte{0x16, 0x03, recMinor, 0x00, 0x2a, hsType, 0x00} }
	for _, tc := range []struct {
		name string
		b    []byte
		want bool
	}{
		{"tls1.0 record version", hello(0x01, 0x01), true},
		{"tls1.2 record version", hello(0x03, 0x01), true},
		{"record minor 4", hello(0x04, 0x01), true},
		{"record minor 5", hello(0x05, 0x01), false},
		{"server hello", hello(0x03, 0x02), false},
		{"exactly 6 bytes", hello(0x01, 0x01)[:6], true},
		{"5 bytes", hello(0x01, 0x01)[:5], false},
		{"application data", []byte{0x17, 0x03, 0x03, 0, 1, 1}, false},
		{"dtls", []byte{0x16, 0xfe, 0xfd, 0, 0, 1}, false},
		{"empty", nil, false},
	} {
		if got := isTLSClientHello(tc.b); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestIsHTTPRequest(t *testing.T) {
	for _, m := range []string{"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "PRI", "CONNECT"} {
		if !isHTTPRequest([]byte(m + " / HTTP/1.1\r\n")) {
			t.Errorf("%s request not recognised", m)
		}
	}
	for _, b := range []string{"", "GET", "GET/ HTTP/1.1", "get / HTTP/1.1", "TRACE / HTTP/1.1", " GET / HTTP/1.1", "HTTP/1.1 200 OK", "CP1\x01"} {
		if isHTTPRequest([]byte(b)) {
			t.Errorf("%q recognised as an HTTP request", b)
		}
	}
}

func TestIsQUIC(t *testing.T) {
	long := func(first byte, version uint32, n int) []byte {
		b := make([]byte, n)
		b[0] = first
		b[1], b[2], b[3], b[4] = byte(version>>24), byte(version>>16), byte(version>>8), byte(version)
		return b
	}
	short := func(first byte, n int) []byte {
		b := make([]byte, n)
		b[0] = first
		return b
	}
	for _, tc := range []struct {
		name string
		b    []byte
		want bool
	}{
		{"v1 initial", long(0xc0, 1, 1200), true},
		{"v2", long(0xc0, 0x6b3343cf, 1200), true},
		{"version negotiation", long(0x80, 0, 5), true},
		{"grease version", long(0xc0, 0x1a2a3a4a, 1200), true},
		{"grease-looking but wrong nibbles", long(0xc0, 0x1a2a3a4b, 1200), false},
		{"draft-29", long(0xc0, 0xff00001d, 1200), false},
		{"long header, 4 bytes", long(0xc0, 1, 5)[:4], false},
		{"short header with the fixed bit", short(0x40, 20), true},
		{"short header, 19 bytes", short(0x40, 19), false},
		{"short header without the fixed bit", short(0x3f, 64), false},
		{"empty", nil, false},
	} {
		if got := isQUIC(tc.b); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestSessionAndTestFromQName(t *testing.T) {
	const sidHex = "00112233445566778899aabbccddeeff"
	for _, tc := range []struct {
		name, qname, wantSID, wantTest string
	}{
		{"client convention", "abcd." + sidHex + ".dns.udp.probe.invalid.", sidHex, "dns.udp"},
		{"no trailing dot", "abcd." + sidHex + ".dns.udp.probe.invalid", sidHex, "dns.udp"},
		{"single-label test", "abcd." + sidHex + ".dns.probe.invalid.", sidHex, "dns"},
		{"upper-case hex is taken as is", "abcd." + strings.ToUpper(sidHex) + ".dns.udp.probe.invalid.", strings.ToUpper(sidHex), "dns.udp"},
		{"sid too short", "abcd." + sidHex[:30] + ".dns.udp.probe.invalid.", "", "dns.udp"},
		{"sid not hex", "abcd." + strings.Repeat("zz", 16) + ".dns.udp.probe.invalid.", "", "dns.udp"},
		{"too few labels", sidHex + ".dns.probe.invalid.", "", ""},
		{"bare zone", "probe.invalid.", "", ""},
		{"empty", "", "", ""},
		// The whoami form puts a label in front, so the sid is not where the
		// convention expects it: such queries are never attributed by name.
		{"whoami form", "whoami.abcd." + sidHex + ".dns.system.probe.invalid.", "", sidHex + ".dns.system"},
	} {
		if got := sessionFromQName(tc.qname); got != tc.wantSID {
			t.Errorf("%s: sessionFromQName = %q, want %q", tc.name, got, tc.wantSID)
		}
		if got := testFromQName(tc.qname); got != tc.wantTest {
			t.Errorf("%s: testFromQName = %q, want %q", tc.name, got, tc.wantTest)
		}
	}
}

// A delegated zone has more than two labels; the test id must not swallow
// the zone's first labels.
func TestTestFromQNameDelegatedZone(t *testing.T) {
	prev := dnsx.Zone
	t.Cleanup(func() { dnsx.Zone = prev })
	dnsx.SetZone("probe.example.com")
	const sidHex = "00112233445566778899aabbccddeeff"
	if got := testFromQName("abcd." + sidHex + ".dns.udp.probe.example.com."); got != "dns.udp" {
		t.Errorf("testFromQName in a three-label zone = %q, want dns.udp", got)
	}
	if got := testFromQName("abcd." + sidHex + ".dns.tcp.probe.example.com"); got != "dns.tcp" {
		t.Errorf("testFromQName without the trailing dot = %q, want dns.tcp", got)
	}
	// Outside the zone nothing is known about the suffix: two labels, as before.
	if got := testFromQName("abcd." + sidHex + ".dns.udp.other.test."); got != "dns.udp" {
		t.Errorf("testFromQName outside the zone = %q, want dns.udp", got)
	}
	if got := sessionFromQName("abcd." + sidHex + ".dns.udp.probe.example.com."); got != sidHex {
		t.Errorf("sessionFromQName in a three-label zone = %q", got)
	}
}

func TestBoolStr(t *testing.T) {
	if boolStr(true) != "valid" || boolStr(false) != "invalid" {
		t.Error("boolStr: want valid / invalid")
	}
}

func TestFmtVersions(t *testing.T) {
	got := fmtVersions([]uint16{tls.VersionTLS13, tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10, 0x7f1c})
	if got != "1.3,1.2,1.1,1.0,0x7f1c" {
		t.Errorf("fmtVersions = %q", got)
	}
	if fmtVersions(nil) != "" {
		t.Error("fmtVersions(nil) not empty")
	}
}

func TestHelloFingerprint(t *testing.T) {
	a := &tls.ClientHelloInfo{SupportedVersions: []uint16{tls.VersionTLS13}, CipherSuites: []uint16{0x1301, 0x1302}, SupportedProtos: []string{"h2"}}
	b := &tls.ClientHelloInfo{SupportedVersions: []uint16{tls.VersionTLS13}, CipherSuites: []uint16{0x1302, 0x1301}, SupportedProtos: []string{"h2"}}
	fa, fb := helloFingerprint(a), helloFingerprint(b)
	if len(fa) != 24 || fa != helloFingerprint(a) {
		t.Errorf("fingerprint %q: want 24 stable hex chars", fa)
	}
	if fa == fb {
		t.Error("cipher order does not change the fingerprint")
	}
}

func TestAddrPortOf(t *testing.T) {
	ip, port := addrPortOf(strAddr("[::ffff:192.0.2.1]:4242"))
	if ip.String() != "192.0.2.1" || port != 4242 {
		t.Errorf("v4-mapped = %s %d, want it unmapped", ip, port)
	}
	if ip, port := addrPortOf(strAddr("not an address")); ip.IsValid() || port != 0 {
		t.Errorf("garbage = %s %d, want the zero value", ip, port)
	}
}
