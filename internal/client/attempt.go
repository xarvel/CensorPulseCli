package client

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/model"
)

// Outcome values (see CLASSIFICATION.md, low-level outcomes).
const (
	OutcomeOK             = "ok"
	OutcomeConnectTimeout = "connect_timeout"
	OutcomeConnectRefused = "connect_refused"
	OutcomeConnectReset   = "connect_reset"
	OutcomePayloadTimeout = "payload_timeout"
	OutcomeMidstreamReset = "midstream_reset"
	OutcomeMidstreamEOF   = "midstream_eof"
	OutcomeTLSAlert       = "tls_alert"
	OutcomeTLSParse       = "tls_parse_failure"
	OutcomeTLSSpoof       = "tls_spoof"    // non-TLS bytes came back to a ClientHello
	OutcomeBulkStall      = "bulk_stall"   // long transfer stopped making progress
	OutcomeBulkReset      = "bulk_reset"   // long transfer was reset/closed by the path
	OutcomeSessionCut     = "session_cut"  // VPN handshake completed but data packets stopped coming back
	OutcomePacketsCut     = "packets_cut"  // a flow of small packets stopped being answered after N packets
	OutcomeBurstFreeze    = "burst_freeze" // parallel TLS handshakes to one SNI froze while a single handshake to another SNI passed
	OutcomeCertMismatch   = "cert_mismatch"
	OutcomeHTTPLegalBlock = "http_legal_block" // dest.http: HTTP 451 after a clean handshake, the service refuses the region
	OutcomeModified       = "modified"
	OutcomeUnexpected     = "unexpected_response"
	OutcomeDNSTimeout     = "dns_timeout"
	OutcomeDNSRcode       = "dns_rcode"
	OutcomeDNSMismatch    = "dns_answer_mismatch"
	OutcomeQUICNoResponse = "quic_no_response"
	OutcomeQUICHandshake  = "quic_handshake_failure"
	OutcomeServerError    = "server_error"
	OutcomeInconclusive   = "inconclusive"
	OutcomeSkipped        = "skipped"
)

// Attempt is the client-side half of the evidence for one flow.
type Attempt struct {
	ID        string             `json:"id"`
	TestID    string             `json:"test_id"`
	Group     string             `json:"group"`   // classification group key, e.g. "tcp/443"
	Role      string             `json:"role"`    // baseline|variant|control
	Variant   string             `json:"variant"` // free-form variant label
	Transport string             `json:"transport"`
	DstPort   int                `json:"dst_port"`
	SrcPort   int                `json:"src_port,omitempty"`
	Round     int                `json:"round"`
	StartedAt time.Time          `json:"started_at"`
	Stages    map[string]float64 `json:"stages_ms"` // connect, first_write, first_byte, done (ms since StartedAt)
	Outcome   string             `json:"outcome"`
	Error     string             `json:"error,omitempty"`
	BytesOut  int                `json:"bytes_out"`
	BytesIn   int                `json:"bytes_in"`
	Nonce     string             `json:"nonce,omitempty"`
	AttemptID string             `json:"attempt_id,omitempty"` // server reservation id
	Detail    map[string]string  `json:"detail,omitempty"`

	// Filled after observations are fetched.
	Server *model.Observation `json:"server,omitempty"`
	Merged string             `json:"merged,omitempty"` // CLASSIFICATION.md merge table result

	// nonces of every envelope the attempt sent when there was more than one
	// (udp.packets): the server records one observation per datagram, and
	// behind NAT the source port it sees is not ours, so the nonces are the
	// only way to count what arrived. Not part of the report.
	nonces []string
}

func newAttempt(testID, group, role, variant, transport string, port, round int) *Attempt {
	return &Attempt{ID: randHex(8), TestID: testID, Group: group, Role: role, Variant: variant, Transport: transport, DstPort: port, Round: round,
		StartedAt: time.Now(), Stages: map[string]float64{}, Detail: map[string]string{}}
}

func (a *Attempt) mark(stage string) {
	a.Stages[stage] = float64(time.Since(a.StartedAt).Microseconds()) / 1000
}

// markSince records a stage as the time elapsed since start, for stages whose
// duration matters more than their offset (the TCP connect).
func (a *Attempt) markSince(stage string, start time.Time) {
	a.Stages[stage] = float64(time.Since(start).Microseconds()) / 1000
}

// restart moves the attempt's clock to now, after work that is not part of
// the measured flow (the control-plane reservation). The time spent is kept
// as the "reserve" stage so that nothing is hidden.
func (a *Attempt) restart() {
	a.mark("reserve")
	a.StartedAt = time.Now()
}

func (a *Attempt) fail(outcome string, err error) *Attempt {
	a.Outcome = outcome
	if err != nil {
		a.Error = err.Error()
		// Marked whatever the test made of the error (a control-plane call
		// that failed this way is a server_error too): the classifier dates
		// a local outage from these attempts.
		if name := localErrName(err); name != "" {
			a.markLocal(name)
		}
	}
	a.mark("done")
	return a
}

// markLocal records that the attempt ended on a failure of the host itself.
func (a *Attempt) markLocal(name string) {
	if a.Detail == nil {
		a.Detail = map[string]string{}
	}
	a.Detail["local_error"] = name
}

func (a *Attempt) ok() *Attempt {
	a.Outcome = OutcomeOK
	a.mark("done")
	return a
}

// localErrnos are socket failures of the host itself: no address to bind,
// permission, descriptor or buffer exhaustion, interface down, and a socket
// the operating system tore down under the scan. ECONNABORTED is only ever
// local on Linux and Darwin (a peer's RST is ECONNRESET): Android destroys
// an app's sockets when it cuts the app off the network (background
// restrictions, Data Saver) or the network goes away, and answers the app's
// next sends with EPERM; iOS defuncts the sockets of a suspended app. On
// Windows the host's own retransmission give-up is WSAECONNABORTED, a
// different errno that does not match here, so a path that drops everything
// still reads as one. "Unreachable" is not in the list: a router on the path
// reports it too (see dialError).
var localErrnos = []struct {
	errno syscall.Errno
	name  string
}{
	{syscall.EADDRNOTAVAIL, "eaddrnotavail"}, {syscall.EADDRINUSE, "eaddrinuse"}, {syscall.EACCES, "eacces"},
	{syscall.EPERM, "eperm"}, {syscall.EAFNOSUPPORT, "eafnosupport"}, {syscall.EINVAL, "einval"},
	{syscall.EMFILE, "emfile"}, {syscall.ENFILE, "enfile"}, {syscall.ENOBUFS, "enobufs"},
	{syscall.ENETDOWN, "enetdown"}, {syscall.ECONNABORTED, "econnaborted"},
}

// localSyncWithin bounds a connect that failed before any packet left: the
// host's own routing refused it in the connect call itself. An ICMP
// unreachable from a router takes at least a round trip to that router.
const localSyncWithin = 5 * time.Millisecond

// hostError is a failure the host produced although its errno can also come
// from the path: "unreachable" from the host's own routing table (an IPv6
// address on a phone without IPv6, an interface that went away), not from
// an ICMP message of a router.
type hostError struct {
	name string
	err  error
}

func (e *hostError) Error() string { return e.err.Error() }
func (e *hostError) Unwrap() error { return e.err }

// dialError returns a dial's error, marked as the host's own when it is an
// "unreachable" that cannot have come from the path: a UDP "connect" sends
// nothing, and a TCP connect that fails within localSyncWithin never waited
// for the network. A later one is a router's ICMP (a censor's reject among
// them) and stays a path failure.
func dialError(err error, elapsed time.Duration, udp bool) error {
	if err == nil || (!udp && elapsed >= localSyncWithin) {
		return err
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return &hostError{name: LocalNoRoute, err: err}
	}
	return err
}

// LocalNoRoute is the local_error of a dial the host's own routing refused.
const LocalNoRoute = "no_route"

// localErrName names the local socket failure err carries, or "".
func localErrName(err error) string {
	if err == nil {
		return ""
	}
	var he *hostError
	if errors.As(err, &he) {
		return he.name
	}
	for _, e := range localErrnos {
		if errors.Is(err, e.errno) {
			return e.name
		}
	}
	return ""
}

// androidResolverBlocked is what Android's DNS resolver answers an app whose
// network access the system has blocked (DnsProxyListener refuses the query
// of a blocked UID with ECONNREFUSED), as the platform resolver hook passes
// it on in the error text.
const androidResolverBlocked = "resNetworkResult failed: ECONNREFUSED"

// LocalFailure names the failure of the host itself a failed attempt ended
// on, or "": detail.local_error, or for a report written before the engine
// recorded it, the operating system's words in the error (the text of
// ECONNABORTED and EPERM is the same on Linux, Android and Darwin) and
// Android's resolver refusing a blocked app.
func LocalFailure(a *Attempt) string {
	if a.Outcome == OutcomeOK {
		return ""
	}
	if n := a.Detail["local_error"]; n != "" {
		return n
	}
	switch {
	case strings.Contains(a.Error, "software caused connection abort"):
		return "econnaborted"
	case strings.Contains(a.Error, "operation not permitted"):
		return "eperm"
	case strings.Contains(a.Detail["system_error"], androidResolverBlocked):
		return "resolver_blocked"
	}
	return ""
}

// Reset timing (ResetBeforeRTT): a connect that took this long went through
// a SYN retransmission (the initial RTO is one second) and no longer measures
// the round trip, and a reset counts as early when it came back within this
// share of the round trip (jitter on a mobile path is some tens of percent).
const (
	rttMaxConnect = time.Second
	rttEarlyShare = 0.8
)

// ResetTiming reads the timing of a handshake the path reset: how long after
// the ClientHello the reset came (resetMs) and how long the TCP handshake on
// the same connection took (rttMs). ok is false when the attempt is not a
// reset after a measured connect and write.
func ResetTiming(a *Attempt) (resetMs, rttMs float64, ok bool) {
	if a.Outcome != OutcomeMidstreamReset {
		return 0, 0, false
	}
	rtt, okC := a.Stages["connect"]
	wrote, okW := a.Stages["first_write"]
	done, okD := a.Stages["done"]
	if !okC || !okW || !okD || rtt <= 0 || done < wrote {
		return 0, 0, false
	}
	return done - wrote, rtt, true
}

// ResetBeforeRTT reports a reset that came back sooner than a TCP round trip
// of rttMs to the same address: a server's reset cannot, so one that does was
// sent by a middlebox closer than the server, an injection. A round trip that
// went through a SYN retransmission measures nothing.
func ResetBeforeRTT(resetMs, rttMs float64) bool {
	return rttMs > 0 && rttMs < float64(rttMaxConnect.Milliseconds()) && resetMs < rttEarlyShare*rttMs
}

// UsableRTT reports a connect time that measures the round trip: one without
// a SYN retransmission in it.
func UsableRTT(rttMs float64) bool {
	return rttMs > 0 && rttMs < float64(rttMaxConnect.Milliseconds())
}

// markResetTiming records the reset timing of a handshake the path reset
// (detail.reset_ms, and detail.reset_before_rtt when it came sooner than the
// connection's own TCP round trip).
func markResetTiming(a *Attempt) {
	resetMs, rttMs, ok := ResetTiming(a)
	if !ok {
		return
	}
	a.Detail["reset_ms"] = strconv.FormatFloat(resetMs, 'f', 0, 64)
	if ResetBeforeRTT(resetMs, rttMs) {
		a.Detail["reset_before_rtt"] = "true"
	}
}

// classifyNetErr maps a Go error to an outcome, depending on whether the
// application payload had already been written.
func classifyNetErr(err error, afterWrite bool) string {
	// A cancelled scan is the caller's doing, not the path's: without this a
	// dial interrupted by Stop falls through to connect_reset below.
	if errors.Is(err, context.Canceled) {
		return OutcomeSkipped
	}
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return OutcomeTLSAlert
	}
	if _, ok := remoteAlert(err); ok {
		// crypto/tls wraps a received alert as net.OpError{Op: "remote error"}.
		return OutcomeTLSAlert
	}
	var rhe tls.RecordHeaderError
	if errors.As(err, &rhe) {
		return OutcomeTLSSpoof
	}
	// Local socket failures are the host's problem, not the path's: never a
	// censorship outcome.
	if localErrName(err) != "" {
		return OutcomeServerError
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return OutcomeConnectRefused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		if afterWrite {
			return OutcomeMidstreamReset
		}
		return OutcomeConnectReset
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		if afterWrite {
			return OutcomeMidstreamEOF
		}
		return OutcomeConnectReset
	case errors.Is(err, os.ErrDeadlineExceeded):
		if afterWrite {
			return OutcomePayloadTimeout
		}
		return OutcomeConnectTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		if afterWrite {
			return OutcomePayloadTimeout
		}
		return OutcomeConnectTimeout
	}
	s := err.Error()
	if strings.Contains(s, "spki pin mismatch") {
		return OutcomeCertMismatch
	}
	if strings.Contains(s, "tls:") || strings.Contains(s, "handshake") {
		return OutcomeTLSParse
	}
	if strings.Contains(s, "no route") || strings.Contains(s, "unreachable") {
		return OutcomeConnectTimeout
	}
	if afterWrite {
		return OutcomeMidstreamEOF
	}
	return OutcomeConnectReset
}
