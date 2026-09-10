package client

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
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
	}
	a.mark("done")
	return a
}

func (a *Attempt) ok() *Attempt {
	a.Outcome = OutcomeOK
	a.mark("done")
	return a
}

// classifyNetErr maps a Go error to an outcome, depending on whether the
// application payload had already been written.
func classifyNetErr(err error, afterWrite bool) string {
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
	// Local socket failures (no address to bind, permission, descriptor
	// exhaustion, interface down) are the host's problem, not the path's:
	// never a censorship outcome.
	for _, e := range []error{syscall.EADDRNOTAVAIL, syscall.EADDRINUSE, syscall.EACCES, syscall.EPERM, syscall.EAFNOSUPPORT, syscall.EINVAL, syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENETDOWN} {
		if errors.Is(err, e) {
			return OutcomeServerError
		}
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
