package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/dest"
)

// The tests in this file pin what the field run of 2026-09-18 (a phone on a
// Russian mobile network, engine v0.1.0) got wrong.

// The dest.* exchanges past the TCP connect get destMinTimeout: the adaptive
// attempt timeout is calibrated on one small exchange with the control
// point, and at its 1.5 s floor the handshakes of real sites, the control
// sites' included, timed out on a lossy path.
func TestDestTimeoutHasItsOwnFloor(t *testing.T) {
	c, err := New(Options{Sites: true, AdaptiveTimeout: true, Timeout: 6 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c.controlRTT = 100 * time.Millisecond // the field run: 102 ms
	if got := c.attemptTimeout(); got != 1500*time.Millisecond {
		t.Fatalf("attempt timeout %v, want the 1.5 s floor", got)
	}
	if got := c.destTimeout(); got != destMinTimeout {
		t.Fatalf("dest timeout %v, want %v", got, destMinTimeout)
	}
	// A slow path's adaptive timeout above the floor stands.
	c.controlRTT = 800 * time.Millisecond
	if got := c.destTimeout(); got != 5300*time.Millisecond {
		t.Fatalf("slow path: %v, want 5.3 s", got)
	}
	// Never past --timeout.
	c.opt.Timeout = 3 * time.Second
	c.controlRTT = 100 * time.Millisecond
	if got := c.destTimeout(); got != 3*time.Second {
		t.Fatalf("under a 3 s --timeout: %v", got)
	}
}

// A real site that answers the ClientHello after 2 s: past the adaptive
// floor, within the dest floor.
func TestDestHandshakeOutlastsTheAdaptiveFloor(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	defer srv.Close()
	certs := srv.TLS.Certificates
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const delay = 2 * time.Second
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(delay)
		tc := tls.Server(conn, &tls.Config{Certificates: certs})
		_ = tc.Handshake()
		time.Sleep(100 * time.Millisecond)
	}()
	c, _ := New(Options{Sites: true, AdaptiveTimeout: true, Timeout: 6 * time.Second})
	c.controlRTT = 100 * time.Millisecond
	if c.attemptTimeout() >= delay || c.destTimeout() <= delay {
		t.Fatalf("the test needs attempt timeout %v < %v < dest timeout %v", c.attemptTimeout(), delay, c.destTimeout())
	}
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	a := newAttempt("dest.tls", "tcp/443", RoleVariant, "example.com", "tcp", DestPort, 1)
	if out, _, err := c.destHandshakeOn(context.Background(), conn, "example.com", a); out != OutcomeOK {
		t.Fatalf("handshake: %s (%v)", out, err)
	}
}

// Android tears an app's sockets down when it cuts the app off the network:
// ECONNABORTED on the open ones, EPERM on the next send. Those are the host's
// failures, never a path outcome, and they are marked.
func TestLocalSocketFailuresAreTheHosts(t *testing.T) {
	abort := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNABORTED)}
	eperm := &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("write", syscall.EPERM)}
	for _, tc := range []struct {
		err  error
		name string
	}{{abort, "econnaborted"}, {eperm, "eperm"}} {
		for _, afterWrite := range []bool{false, true} {
			if got := classifyNetErr(tc.err, afterWrite); got != OutcomeServerError {
				t.Errorf("%v (afterWrite=%v) = %s, want server_error", tc.err, afterWrite, got)
			}
		}
		a := newAttempt("dest.tls", "tcp/443", RoleVariant, "wikipedia.org", "tcp", 443, 1)
		a.fail(classifyNetErr(tc.err, true), tc.err)
		if a.Detail["local_error"] != tc.name || LocalFailure(a) != tc.name {
			t.Errorf("%v: detail %v, LocalFailure %q", tc.err, a.Detail, LocalFailure(a))
		}
	}
	// A control-plane call that failed this way is marked too, whatever the
	// test made of it.
	post := &url.Error{Op: "Post", URL: "https://203.0.113.1:8443/v1/session/x/attempt", Err: abort}
	a := newAttempt("tls.fingerprint", "tcp/443", RoleVariant, "firefox", "tcp", 443, 1)
	a.fail(OutcomeServerError, post)
	if a.Detail["local_error"] != "econnaborted" {
		t.Errorf("control-plane abort not marked: %v", a.Detail)
	}
	// A peer's reset is the path's.
	reset := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}
	if localErrName(reset) != "" || classifyNetErr(reset, true) != OutcomeMidstreamReset {
		t.Errorf("a reset read as local: %q / %s", localErrName(reset), classifyNetErr(reset, true))
	}
}

// "Unreachable" is the host's own only when nothing left the host: a UDP
// "connect", or a TCP connect refused at once by the routing table (an IPv6
// address on a phone without IPv6). A later one is a router's ICMP.
func TestUnreachableIsLocalOnlyWhenNothingLeftTheHost(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENETUNREACH, syscall.EHOSTUNREACH} {
		err := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
		if got := localErrName(dialError(err, 200*time.Microsecond, false)); got != LocalNoRoute {
			t.Errorf("%v at once: %q, want %s", errno, got, LocalNoRoute)
		}
		if got := classifyNetErr(dialError(err, 200*time.Microsecond, false), false); got != OutcomeServerError {
			t.Errorf("%v at once: outcome %s", errno, got)
		}
		if got := localErrName(dialError(err, time.Second, true)); got != LocalNoRoute {
			t.Errorf("%v on a UDP connect: %q", errno, got)
		}
		late := dialError(err, 80*time.Millisecond, false)
		if localErrName(late) != "" || classifyNetErr(late, false) != OutcomeConnectTimeout {
			t.Errorf("%v after 80 ms: %q / %s, want the path's connect_timeout", errno, localErrName(late), classifyNetErr(late, false))
		}
	}
}

// A report written before local_error carries only the operating system's
// words; those are the same on Linux, Android and Darwin.
func TestLocalFailureFromAnOlderReport(t *testing.T) {
	for _, tc := range []struct {
		a    Attempt
		want string
	}{
		{Attempt{Outcome: OutcomeServerError, Error: `Post "https://‹server›:8443/v1/session/x/attempt": read tcp ‹local›->‹server›:8443: read: software caused connection abort`}, "econnaborted"},
		{Attempt{Outcome: OutcomeMidstreamEOF, Error: "read tcp ‹local›->185.15.59.224:443: read: software caused connection abort"}, "econnaborted"},
		{Attempt{Outcome: OutcomeServerError, Error: "write udp ‹local›->‹server›:53: write: operation not permitted"}, "eperm"},
		{Attempt{Outcome: OutcomeInconclusive, Detail: map[string]string{"system_error": "resolver error 1: android.system.ErrnoException: resNetworkResult failed: ECONNREFUSED (Connection refused)"}}, "resolver_blocked"},
		{Attempt{Outcome: OutcomeMidstreamReset, Error: "read tcp ‹local›->194.55.26.46:443: read: connection reset by peer"}, ""},
		{Attempt{Outcome: OutcomeOK, Error: "software caused connection abort"}, ""},
	} {
		if got := LocalFailure(&tc.a); got != tc.want {
			t.Errorf("%q %v: %q, want %q", tc.a.Error, tc.a.Detail, got, tc.want)
		}
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("offline")
}

// Android's resolver answers an app whose network the system blocked with
// ECONNREFUSED: the dest.dns attempt is marked as the host's failure.
func TestAndroidResolverRefusalMarksTheHost(t *testing.T) {
	c, _ := New(Options{Sites: true, SystemResolver: func(context.Context, string) ([]netip.Addr, error) {
		return nil, errors.New("resolver error 1: android.system.ErrnoException: resNetworkResult failed: ECONNREFUSED (Connection refused)")
	}})
	c.dest.once.Do(func() { c.dest.hc = &http.Client{Transport: failingTransport{}} })
	a := newAttempt("dest.dns", "udp/53", RoleVariant, "github.com", "udp", 53, 1)
	res := c.resolveTarget(context.Background(), dest.Target{Domain: "github.com"}, a)
	if len(res.ips) != 0 || a.Detail["local_error"] != "resolver_blocked" || LocalFailure(a) != "resolver_blocked" {
		t.Fatalf("ips %v, outcome %s, detail %v", res.ips, a.Outcome, a.Detail)
	}
}

// A resolution without an address (taken during an outage) is resolved
// again once it is destReresolveAfter old; one with an address holds for the
// whole scan.
func TestDestResolveRetriesAnEmptyResolution(t *testing.T) {
	ctx := context.Background()
	c, _ := New(Options{Sites: true})
	tg := dest.Target{Domain: "dc", SkipDNS: true, FixedIPs: []string{"149.154.167.50"}}
	empty := &destResolution{source: "none", at: time.Now()}
	c.dest.resolved = map[string]*destResolution{"dc": empty}
	if r := c.destResolve(ctx, tg); r != empty {
		t.Fatalf("a fresh empty resolution was not kept: %+v", r)
	}
	empty.at = time.Now().Add(-destReresolveAfter - time.Second)
	r := c.destResolve(ctx, tg)
	if r == empty || dest.Strings(r.ips) != "149.154.167.50" {
		t.Fatalf("a stale empty resolution was not resolved again: %+v", r)
	}
	r.at = time.Now().Add(-time.Hour)
	if r2 := c.destResolve(ctx, tg); r2 != r {
		t.Fatal("a resolution with an address was resolved again")
	}
}

// Without an IPv6 route a v6 address is never probed.
func TestDestUsableSkipsIPv6WithoutARoute(t *testing.T) {
	c, _ := New(Options{Sites: true, LocalAddr: "127.0.0.1"}) // bound to IPv4: no IPv6 from here
	if c.destUsable(netip.MustParseAddr("2a00:1450:400f:810::200e")) {
		t.Fatal("a v6 address is usable from a socket bound to IPv4")
	}
	if !c.destUsable(netip.MustParseAddr("108.177.14.93")) {
		t.Fatal("a v4 address is not usable")
	}
}

// Disagreement verification: poisoning needs the system address to have
// answered and refused while the trusted one served. A check that did not
// finish verifies nothing (the field run: github.com's system address timed
// out its handshake at 1.5 s and the site was called poisoned).
func TestJudgeDisagreement(t *testing.T) {
	served := serveResult{handshake: true, chain: "true", why: "tls:ok"}
	timeout := serveResult{why: "tls:payload_timeout", outcome: OutcomePayloadTimeout}
	for _, tc := range []struct {
		name    string
		sys, tr serveResult
		want    int
	}{
		{"system serves: geo-DNS", served, timeout, disagreementGeoDNS},
		{"system timed out", timeout, served, disagreementUnverified},
		{"system connect timed out", serveResult{why: "tcp:connect_timeout", outcome: OutcomeConnectTimeout}, served, disagreementUnverified},
		{"system failed on the host", serveResult{why: "tcp:server_error", outcome: OutcomeServerError}, served, disagreementUnverified},
		{"system reset", serveResult{why: "tls:midstream_reset", outcome: OutcomeMidstreamReset}, served, disagreementPoisoned},
		{"system foreign certificate", serveResult{handshake: true, chain: "x509: certificate is valid for block.example", why: "cert:x509"}, served, disagreementPoisoned},
		{"trusted timed out too", serveResult{why: "tls:midstream_reset", outcome: OutcomeMidstreamReset}, timeout, disagreementUnverified},
		{"neither serves", serveResult{why: "tls:midstream_reset", outcome: OutcomeMidstreamReset}, serveResult{why: "tls:tls_alert", outcome: OutcomeTLSAlert}, disagreementNeitherServes},
	} {
		if got := judgeDisagreement(tc.sys, tc.tr); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
}

// A reset that comes back sooner than a round trip to the address was not
// sent by the server. The field run: dw.com reset 34-52 ms after the
// ClientHello, TCP handshake 94 ms.
func TestResetBeforeRTT(t *testing.T) {
	a := &Attempt{Outcome: OutcomeMidstreamReset, Stages: map[string]float64{"connect": 94, "first_write": 94, "done": 147}, Detail: map[string]string{}}
	resetMs, rttMs, ok := ResetTiming(a)
	if !ok || resetMs != 53 || rttMs != 94 || !ResetBeforeRTT(resetMs, rttMs) {
		t.Fatalf("dw.com: reset %v rtt %v ok %v", resetMs, rttMs, ok)
	}
	markResetTiming(a)
	if a.Detail["reset_ms"] != "53" || a.Detail["reset_before_rtt"] != "true" {
		t.Fatalf("detail: %v", a.Detail)
	}
	// A reset after a full round trip may be the server's.
	if ResetBeforeRTT(80, 60) {
		t.Fatal("a reset after a round trip read as injected")
	}
	// A connect with a SYN retransmission in it does not measure the round trip.
	if ResetBeforeRTT(33, 1087) || UsableRTT(1087) {
		t.Fatal("a retransmitted connect used as the round trip")
	}
	b := &Attempt{Outcome: OutcomeMidstreamReset, Stages: map[string]float64{"connect": 1087, "first_write": 1087, "done": 1120}, Detail: map[string]string{}}
	markResetTiming(b)
	if b.Detail["reset_ms"] != "33" || b.Detail["reset_before_rtt"] != "" {
		t.Fatalf("retransmitted connect: %v", b.Detail)
	}
	// Only a reset is timed.
	if _, _, ok := ResetTiming(&Attempt{Outcome: OutcomePayloadTimeout, Stages: a.Stages}); ok {
		t.Fatal("a timeout was timed as a reset")
	}
}

// Remerge brings the attempts of a v0.1.0 report in line with this build.
func TestRemergeReinterpretsAnOlderReport(t *testing.T) {
	abort := &Attempt{TestID: "tls.fingerprint", Transport: "tcp", Outcome: OutcomeServerError,
		Error: `Post "https://‹server›:8443/v1/session/x/attempt": read tcp ‹local›->‹server›:8443: read: software caused connection abort`}
	wiki := &Attempt{TestID: "dest.tls", Transport: "tcp", Outcome: OutcomeMidstreamEOF, Stages: map[string]float64{"connect": 95, "first_write": 1596, "done": 2449},
		Error: "read tcp ‹local›->185.15.59.224:443: read: software caused connection abort", Detail: map[string]string{}}
	// youtube.com: the only trusted answer was an AAAA, the phone had no
	// IPv6, and v0.1.0 read the host's "unreachable" as a connect timeout.
	v6 := &Attempt{TestID: "dest.tcp", Transport: "tcp", Outcome: OutcomeConnectTimeout, Stages: map[string]float64{"done": 1, "first_write": 0}, Detail: map[string]string{}}
	github := &Attempt{TestID: "dest.dns", Transport: "udp", Outcome: OutcomeDNSMismatch, Detail: map[string]string{
		"tamper": "system_address_fails", "verify_ip": "140.82.121.4", "verify_system": "tls:payload_timeout", "verify_trusted": "tls:ok"}}
	poisoned := &Attempt{TestID: "dest.dns", Transport: "udp", Outcome: OutcomeDNSMismatch, Detail: map[string]string{
		"tamper": "system_address_fails", "verify_ip": "5.5.5.5", "verify_system": "tls:midstream_reset", "verify_trusted": "tls:ok"}}
	dw := &Attempt{TestID: "dest.tls", Transport: "tcp", Outcome: OutcomeMidstreamReset, Stages: map[string]float64{"connect": 94, "first_write": 94, "done": 128}, Detail: map[string]string{}}
	slow := &Attempt{TestID: "dest.tcp", Transport: "tcp", Outcome: OutcomeConnectTimeout, Stages: map[string]float64{"done": 3003, "first_write": 1502}, Detail: map[string]string{}}
	Remerge([]*Attempt{abort, wiki, v6, github, poisoned, dw, slow}, 0)
	for _, tc := range []struct {
		name          string
		a             *Attempt
		outcome, keyV string
	}{
		{"control-plane abort", abort, OutcomeServerError, "econnaborted"},
		{"aborted handshake", wiki, OutcomeServerError, "econnaborted"},
		{"v6 without a route", v6, OutcomeServerError, LocalNoRoute},
		{"slow connect", slow, OutcomeConnectTimeout, ""},
	} {
		if tc.a.Outcome != tc.outcome || tc.a.Merged != tc.outcome || tc.a.Detail["local_error"] != tc.keyV {
			t.Errorf("%s: outcome %s merged %s detail %v", tc.name, tc.a.Outcome, tc.a.Merged, tc.a.Detail)
		}
	}
	if github.Outcome != OutcomeInconclusive || github.Detail["tamper"] != "" {
		t.Errorf("unfinished verification: %s %v", github.Outcome, github.Detail)
	}
	if poisoned.Outcome != OutcomeDNSMismatch || poisoned.Detail["tamper"] != "system_address_fails" {
		t.Errorf("a verified poisoning changed: %s %v", poisoned.Outcome, poisoned.Detail)
	}
	if dw.Detail["reset_ms"] != "34" || dw.Detail["reset_before_rtt"] != "true" {
		t.Errorf("reset timing: %v", dw.Detail)
	}
}
