package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/xarvel/CensorPulseCli/internal/httpecho"
	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/proto"
	"github.com/xarvel/CensorPulseCli/internal/wg"
)

func (c *Client) udpConn(a *Attempt) (*net.UDPConn, error) {
	raddr := &net.UDPAddr{IP: c.target.AsSlice(), Port: a.DstPort}
	conn, err := net.DialUDP("udp", c.udpLocal(), raddr)
	if err != nil {
		return nil, err
	}
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		a.SrcPort = la.Port
	}
	a.mark("connect")
	return conn, nil
}

// udpExchange sends one datagram and waits for one reply.
func (c *Client) udpExchange(a *Attempt, out []byte) ([]byte, error) {
	conn, err := c.udpConn(a)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return c.udpExchangeOn(conn, a, out)
}

// udpExchangeOn is udpExchange on a socket the caller keeps (session tests
// must stay on one 5-tuple after the handshake).
func (c *Client) udpExchangeOn(conn *net.UDPConn, a *Attempt, out []byte) ([]byte, error) {
	if _, err := conn.Write(out); err != nil {
		return nil, err
	}
	a.BytesOut = len(out)
	a.mark("first_write")
	conn.SetReadDeadline(time.Now().Add(c.attemptTimeout()))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	a.mark("first_byte")
	a.BytesIn = n
	return buf[:n], nil
}

func udpOutcome(err error) string {
	o := classifyNetErr(err, true)
	if o == OutcomeConnectRefused {
		return OutcomeConnectRefused // ICMP port unreachable surfaced by the kernel
	}
	return o
}

// udpEcho sends a cookie-bearing envelope and validates the echo.
func (c *Client) udpEcho(ctx context.Context, a *Attempt, size int) *Attempt {
	payload := proto.RandomPayload(size)
	wire, nonce, err := c.envelope(a.TestID, 1, payload, true)
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	a.Nonce = hex.EncodeToString(nonce[:])
	got, err := c.udpExchange(a, wire)
	if err != nil {
		return a.fail(udpOutcome(err), err)
	}
	if !proto.IsEnvelope(got) {
		a.Detail["response_prefix"] = hex.EncodeToString(got[:min(len(got), 16)])
		return a.fail(OutcomeUnexpected, fmt.Errorf("non-envelope reply"))
	}
	if _, why := c.checkReply(got, nonce, payload); why != "" {
		a.Detail["reply_check"] = why
		return a.fail(OutcomeModified, fmt.Errorf("reply check: %s", why))
	}
	return a.ok()
}

// udpRandom sends random bytes (reserved) and expects the 8-byte hash ack.
func (c *Client) udpRandom(ctx context.Context, a *Attempt, size int) *Attempt {
	payload := proto.RandomPayload(size)
	payload[0] = 0xff // avoid every dispatched first byte: TLS 0x16, HTTP verbs, CP1 magic, OpenVPN opcode, WireGuard type 1-4, SOCKS5 0x05, VLESS 0x00, QUIC long-header 0x80
	sum := sha256.Sum256(payload)
	if err := c.reserve(ctx, a, "udp", model.ParseUnknown); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	got, err := c.udpExchange(a, payload)
	if err != nil {
		return a.fail(udpOutcome(err), err)
	}
	if !bytes.Equal(got[:min(8, len(got))], sum[:8]) {
		a.Detail["response_prefix"] = hex.EncodeToString(got[:min(len(got), 16)])
		return a.fail(OutcomeUnexpected, fmt.Errorf("hash ack mismatch"))
	}
	return a.ok()
}

// wireguardInit sends an authenticated handshake initiation to the server's
// static key and validates the response cryptographically.
func (c *Client) wireguardInit(ctx context.Context, a *Attempt) *Attempt {
	var serverPub [32]byte
	pub, err := base64Decode(c.Params.WGPublicKey)
	if err != nil || len(pub) != 32 {
		return a.fail(OutcomeServerError, fmt.Errorf("server did not advertise a WireGuard key"))
	}
	copy(serverPub[:], pub)
	if err := c.reserve(ctx, a, "udp", model.ParseWireGuard); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	static, err := wg.NewKeyPair()
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	st, init, err := wg.CreateInitiation(static, serverPub, [32]byte{})
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	got, err := c.udpExchange(a, init)
	if err != nil {
		return a.fail(udpOutcome(err), err)
	}
	if err := st.ConsumeResponse(got, [32]byte{}); err != nil {
		a.Detail["response_prefix"] = hex.EncodeToString(got[:min(len(got), 16)])
		if len(got) == wg.ResponseSize {
			return a.fail(OutcomeModified, err)
		}
		return a.fail(OutcomeUnexpected, err)
	}
	return a.ok()
}

// quicV1 opens a QUIC v1 connection with HTTP/3 and fetches the echo.
func (c *Client) quicV1(ctx context.Context, a *Attempt, sni string) *Attempt {
	if err := c.reserve(ctx, a, "udp", model.ParseQUIC); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	nonce := hex.EncodeToString(proto.RandomPayload(12))
	a.Nonce = nonce
	path := httpecho.Path(c.Session.SessionID, a.TestID, nonce)

	udpConn, err := net.ListenUDP("udp", c.udpLocal())
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	defer udpConn.Close()
	if la, ok := udpConn.LocalAddr().(*net.UDPAddr); ok {
		a.SrcPort = la.Port
	}
	tlsConf := c.pinnedTLS(sni)
	tlsConf.NextProtos = []string{"h3"}
	qconf := &quic.Config{HandshakeIdleTimeout: c.attemptTimeout(), MaxIdleTimeout: c.attemptTimeout()}
	dctx, cancel := context.WithTimeout(ctx, c.attemptTimeout())
	defer cancel()
	raddr := &net.UDPAddr{IP: c.target.AsSlice(), Port: a.DstPort}
	a.mark("first_write")
	qc, err := quic.DialEarly(dctx, udpConn, raddr, tlsConf, qconf)
	if err != nil {
		if _, ok := err.(*quic.IdleTimeoutError); ok || dctx.Err() != nil {
			return a.fail(OutcomeQUICNoResponse, err)
		}
		return a.fail(OutcomeQUICHandshake, err)
	}
	a.mark("connect")
	a.mark("first_byte")
	defer qc.CloseWithError(0, "done")
	tr := &http3.Transport{}
	hc := tr.NewClientConn(qc)
	req, _ := http.NewRequestWithContext(dctx, http.MethodGet, "https://"+net.JoinHostPort(c.target.String(), strconv.Itoa(a.DstPort))+path, nil)
	req.Host = sni
	resp, err := hc.RoundTrip(req)
	if err != nil {
		// DialEarly returns before the handshake is confirmed; whether it
		// ever completed says at which stage the exchange died.
		select {
		case <-qc.HandshakeComplete():
			a.Detail["quic_stage"] = "request"
		default:
			a.Detail["quic_stage"] = "handshake"
		}
		return a.fail(OutcomeQUICHandshake, err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	a.BytesIn = len(body)
	a.Detail["status"] = strconv.Itoa(resp.StatusCode)
	want := httpecho.Body(sni, path, nonce)
	if err != nil || resp.StatusCode != 200 || !bytes.Equal(body, want) {
		a.Detail["body_prefix"] = string(body[:min(len(body), 96)])
		return a.fail(OutcomeModified, fmt.Errorf("h3 body mismatch"))
	}
	return a.ok()
}

var _ = tls.VersionTLS13
