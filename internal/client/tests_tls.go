package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/xarvel/CensorPulseCli/internal/model"
)

// tlsOptions pin down one ClientHello variant.
type tlsOptions struct {
	SNI        string
	MinVersion uint16
	MaxVersion uint16
	ALPN       []string
	NoALPN     bool
	// Fingerprint selects a uTLS parrot; empty = Go crypto/tls.
	Fingerprint string
}

// utlsIDs are the ClientHello parrots the client can wear. The second group
// (edge, android, 360, qq) is there as controls: fingerprint-based rules seen
// in the field act on the "big" browser parrots and let these through, so a
// scan that fails chrome/safari/ios and passes edge/android names the axis.
var utlsIDs = map[string]utls.ClientHelloID{
	"chrome":     utls.HelloChrome_Auto,
	"firefox":    utls.HelloFirefox_Auto,
	"safari":     utls.HelloSafari_Auto,
	"ios":        utls.HelloIOS_Auto,
	"edge":       utls.HelloEdge_Auto,
	"android":    utls.HelloAndroid_11_OkHttp,
	"360":        utls.Hello360_Auto,
	"qq":         utls.HelloQQ_Auto,
	"golang":     utls.HelloGolang,
	"randomized": utls.HelloRandomized,
}

// fingerprintPlan is the set exercised by tls.fingerprint in catalog order.
var fingerprintPlan = []string{"chrome", "firefox", "safari", "ios", "edge", "android", "golang"}

// tlsEcho performs a TLS handshake with the requested surface and then runs the
// envelope echo inside the session. The handshake stage is recorded even when
// the echo fails, so the classifier can tell "ClientHello blocked" from
// "session established but application data dropped".
func (c *Client) tlsEcho(ctx context.Context, a *Attempt, o tlsOptions) *Attempt {
	// Native handshakes cannot carry the envelope before the session exists,
	// so reserve a window for the ClientHello itself.
	if err := c.reserveTLS(ctx, a, o); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	return c.tlsEchoReserved(ctx, a, o)
}

// reserveTLS records the variant and reserves the ClientHello window.
func (c *Client) reserveTLS(ctx context.Context, a *Attempt, o tlsOptions) error {
	a.Detail["sni"] = o.SNI
	if o.Fingerprint != "" {
		a.Detail["fingerprint"] = o.Fingerprint
	}
	return c.reserve(ctx, a, "tcp", model.ParseTLS)
}

// tlsEchoReserved is tlsEcho after the reservation: dial, handshake, echo.
// Split out so that tls.burst can reserve every window first and then fire
// the handshakes within one RTT of each other.
func (c *Client) tlsEchoReserved(ctx context.Context, a *Attempt, o tlsOptions) *Attempt {
	raw, err := c.dialTCP(ctx, a)
	if err != nil {
		return a.fail(classifyNetErr(err, false), err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(c.attemptTimeout()))

	var conn net.Conn
	var state tls.ConnectionState
	if o.Fingerprint == "" {
		cfg := c.pinnedTLS(o.SNI)
		cfg.MinVersion, cfg.MaxVersion = o.MinVersion, o.MaxVersion
		if !o.NoALPN {
			cfg.NextProtos = o.ALPN
		}
		tc := tls.Client(raw, cfg)
		a.mark("first_write")
		if err := tc.HandshakeContext(ctx); err != nil {
			noteTLSFailure(a, err)
			return a.fail(tlsOutcome(err), err)
		}
		state = tc.ConnectionState()
		conn = tc
	} else {
		id, ok := utlsIDs[o.Fingerprint]
		if !ok {
			return a.fail(OutcomeSkipped, fmt.Errorf("unknown fingerprint %q", o.Fingerprint))
		}
		std := c.pinnedTLS(o.SNI)
		ucfg := &utls.Config{ServerName: o.SNI, InsecureSkipVerify: true, MinVersion: o.MinVersion, MaxVersion: o.MaxVersion}
		// uTLS has its own certificate types; re-run the pin check by hand.
		ucfg.VerifyPeerCertificate = std.VerifyPeerCertificate
		if !o.NoALPN && len(o.ALPN) > 0 {
			ucfg.NextProtos = o.ALPN
		}
		uc := utls.UClient(raw, ucfg, id)
		a.mark("first_write")
		if err := uc.HandshakeContext(ctx); err != nil {
			noteTLSFailure(a, err)
			return a.fail(tlsOutcome(err), err)
		}
		us := uc.ConnectionState()
		state = tls.ConnectionState{Version: us.Version, NegotiatedProtocol: us.NegotiatedProtocol, CipherSuite: us.CipherSuite}
		conn = uc
	}
	a.mark("handshake")
	a.Detail["negotiated_version"] = tlsVersionName(state.Version)
	a.Detail["negotiated_alpn"] = state.NegotiatedProtocol
	a.Detail["cipher"] = tls.CipherSuiteName(state.CipherSuite)
	// Echo over the established session. Stage "first_write" is re-marked so
	// that timings refer to application data from here on.
	return c.echoOnConn(conn, a, 64, true)
}

// remoteAlert reports whether err is a TLS alert the peer sent. crypto/tls
// wraps a received alert in a net.OpError with Op "remote error" around an
// unexported type, so errors.As on tls.AlertError never matches it; the
// description is matched instead. The second value is the alert code.
func remoteAlert(err error) (tls.AlertError, bool) {
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return alert, true
	}
	var op *net.OpError
	if !errors.As(err, &op) || op.Op != "remote error" || op.Err == nil {
		return 0, false
	}
	text := op.Err.Error()
	for code := 0; code < 256; code++ {
		if tls.AlertError(code).Error() == text {
			return tls.AlertError(code), true
		}
	}
	return 0, false
}

func tlsOutcome(err error) string {
	if _, ok := remoteAlert(err); ok {
		return OutcomeTLSAlert
	}
	var ualert utls.AlertError
	if errors.As(err, &ualert) {
		return OutcomeTLSAlert
	}
	var rhe tls.RecordHeaderError
	if errors.As(err, &rhe) {
		return OutcomeTLSSpoof
	}
	var urhe utls.RecordHeaderError
	if errors.As(err, &urhe) {
		return OutcomeTLSSpoof
	}
	o := classifyNetErr(err, true)
	if o == OutcomeMidstreamEOF || o == OutcomeMidstreamReset || o == OutcomePayloadTimeout {
		// The ClientHello was sent; the failure happened before ServerHello.
		return o
	}
	return o
}

// noteTLSFailure records what came back instead of a ServerHello.
func noteTLSFailure(a *Attempt, err error) {
	var rhe tls.RecordHeaderError
	if errors.As(err, &rhe) {
		a.Detail["response_prefix"] = fmt.Sprintf("%x", rhe.RecordHeader[:])
		return
	}
	var urhe utls.RecordHeaderError
	if errors.As(err, &urhe) {
		a.Detail["response_prefix"] = fmt.Sprintf("%x", urhe.RecordHeader[:])
		return
	}
	if alert, ok := remoteAlert(err); ok {
		a.Detail["alert"] = alert.Error()
		return
	}
	var ualert utls.AlertError
	if errors.As(err, &ualert) {
		a.Detail["alert"] = ualert.Error()
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	}
	return fmt.Sprintf("0x%04x", v)
}
