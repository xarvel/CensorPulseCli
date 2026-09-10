package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/proto"
	"github.com/xarvel/CensorPulseCli/internal/tlsx"
	"github.com/xarvel/CensorPulseCli/internal/vless"
)

// vlessReality reproduces what a REALITY client puts on the wire: a
// Chrome-shaped TLS 1.3 ClientHello carrying sni (somebody else's name for
// the reality variant, a probe name for the benign control), then a VLESS
// request that immediately carries a TLS ClientHello (TLS-in-TLS). For
// vless.session, application-data-shaped records follow and the server
// mirrors them. The pin check stays on: the server's certificate is ours.
func (c *Client) vlessReality(ctx context.Context, a *Attempt, sni string) *Attempt {
	a.Detail["sni"] = sni
	a.Detail["fingerprint"] = "chrome"
	if err := c.reserve(ctx, a, "tcp", model.ParseVLESS); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	raw, err := c.dialTCP(ctx, a)
	if err != nil {
		return a.fail(classifyNetErr(err, false), err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(c.attemptTimeout()))
	std := c.pinnedTLS(sni)
	ucfg := &utls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}} //nolint:gosec // pin-based trust
	ucfg.VerifyPeerCertificate = std.VerifyPeerCertificate
	uc := utls.UClient(raw, ucfg, utls.HelloChrome_Auto)
	a.mark("first_write")
	if err := uc.HandshakeContext(ctx); err != nil {
		noteTLSFailure(a, err)
		return a.fail(tlsOutcome(err), err)
	}
	a.mark("handshake")
	st := uc.ConnectionState()
	a.Detail["negotiated_version"] = tlsVersionName(st.Version)
	a.Detail["negotiated_alpn"] = st.NegotiatedProtocol
	raw.SetDeadline(time.Time{})

	dst := randHex(6) + ".probe.invalid"
	// Request header and the first inner record go out together, as Xray
	// does: the inner ClientHello is what a TLS-in-TLS detector keys on.
	inner := tlsx.ClientHello(dst)
	first := append(vless.Request(dst, 443), inner...)
	uc.SetWriteDeadline(time.Now().Add(c.attemptTimeout()))
	if _, err := uc.Write(first); err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	a.BytesOut += len(first)
	br := bufio.NewReaderSize(uc, 16<<10)
	uc.SetReadDeadline(time.Now().Add(c.attemptTimeout()))
	hdr := make([]byte, vless.ResponseLen)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	a.BytesIn += len(hdr)
	a.mark("first_byte")
	if hdr[0] != vless.Version {
		a.Detail["response_prefix"] = hex.EncodeToString(hdr)
		return a.fail(OutcomeUnexpected, fmt.Errorf("vless response %x", hdr))
	}
	echo := make([]byte, len(inner))
	n, err := io.ReadFull(br, echo)
	a.BytesIn += n
	if err != nil {
		a.Detail["data_sent"], a.Detail["data_recv"] = "1", "0"
		return a.fail(OutcomeSessionCut, fmt.Errorf("inner ClientHello not echoed: %w", err))
	}
	if a.TestID != "vless.session" {
		return a.ok()
	}
	return c.tcpMirrorLoop(a, uc, br, func(i, size int) []byte {
		return tlsx.AppData(proto.RandomPayload(max(size-5, 16)))
	})
}
