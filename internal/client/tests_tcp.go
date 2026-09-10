package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/httpecho"
	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/ovpn"
	"github.com/xarvel/CensorPulseCli/internal/proto"
	"github.com/xarvel/CensorPulseCli/internal/tlsx"
)

func (c *Client) tcpAddr(port int) string {
	return net.JoinHostPort(c.target.String(), strconv.Itoa(port))
}

// dialTCP connects and records the connect duration (SYN → SYN-ACK, measured
// from the dial itself so that it is comparable across tests) and the local
// port.
func (c *Client) dialTCP(ctx context.Context, a *Attempt) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, c.attemptTimeout())
	defer cancel()
	start := time.Now()
	conn, err := c.dialer().DialContext(dctx, "tcp", c.tcpAddr(a.DstPort))
	if err != nil {
		return nil, dialError(err, time.Since(start), false)
	}
	a.markSince("connect", start)
	if ta, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		a.SrcPort = ta.Port
	}
	return conn, nil
}

// readAll reads until the peer closes, the deadline hits, or max bytes.
func readUntilClose(conn net.Conn, deadline time.Time, max int) ([]byte, error) {
	conn.SetReadDeadline(deadline)
	var buf bytes.Buffer
	tmp := make([]byte, 8192)
	for buf.Len() < max {
		n, err := conn.Read(tmp)
		buf.Write(tmp[:n])
		if err != nil {
			return buf.Bytes(), err
		}
	}
	return buf.Bytes(), nil
}

// tcpEcho sends one CP1 envelope over raw TCP and validates the echo.
func (c *Client) tcpEcho(ctx context.Context, a *Attempt, size int) *Attempt {
	conn, err := c.dialTCP(ctx, a)
	if err != nil {
		return a.fail(classifyNetErr(err, false), err)
	}
	defer conn.Close()
	return c.echoOnConn(conn, a, size, false)
}

// echoOnConn runs the envelope exchange on an established (possibly TLS) conn.
func (c *Client) echoOnConn(conn net.Conn, a *Attempt, size int, viaTLS bool) *Attempt {
	payload := proto.RandomPayload(size)
	wire, nonce, err := c.envelope(a.TestID, 1, payload, false)
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	a.Nonce = hex.EncodeToString(nonce[:])
	conn.SetWriteDeadline(time.Now().Add(c.attemptTimeout()))
	if _, err := conn.Write(wire); err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	a.BytesOut += len(wire)
	a.mark("first_write")
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(c.attemptTimeout()))
	for {
		total, _ := proto.ReplyLen(buf)
		if total > 0 {
			break
		}
		n, err := conn.Read(tmp)
		if n > 0 && len(buf) == 0 {
			a.mark("first_byte")
		}
		buf = append(buf, tmp[:n]...)
		a.BytesIn += n
		if err != nil {
			if len(buf) > 0 && !proto.IsEnvelope(buf) {
				a.Detail["response_prefix"] = hex.EncodeToString(buf[:min(len(buf), 16)])
				return a.fail(OutcomeUnexpected, err)
			}
			return a.fail(classifyNetErr(err, true), err)
		}
		if len(buf) >= 4 && !proto.IsEnvelope(buf) {
			a.Detail["response_prefix"] = hex.EncodeToString(buf[:min(len(buf), 16)])
			return a.fail(OutcomeUnexpected, fmt.Errorf("non-envelope reply"))
		}
	}
	rep, why := c.checkReply(buf, nonce, payload)
	if why != "" {
		a.Detail["reply_check"] = why
		return a.fail(OutcomeModified, fmt.Errorf("reply check: %s", why))
	}
	a.Detail["server_rtt_us"] = strconv.FormatInt(rep.RepliedAt.Sub(rep.SeenAt).Microseconds(), 10)
	return a.ok()
}

// tcpRandom sends random bytes and expects the 8-byte hash ack after the
// server's quiet period.
func (c *Client) tcpRandom(ctx context.Context, a *Attempt, size int) *Attempt {
	payload := proto.RandomPayload(size)
	// Avoid accidentally looking like a known protocol (TLS 0x16, HTTP verbs,
	// CP1 magic, OpenVPN length prefix).
	payload[0] = 0xff // see udpRandom: keep clear of every protocol first byte the dispatcher recognises
	sum := sha256.Sum256(payload)
	if err := c.reserve(ctx, a, "tcp", model.ParseUnknown); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	conn, err := c.dialTCP(ctx, a)
	if err != nil {
		return a.fail(classifyNetErr(err, false), err)
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(c.attemptTimeout()))
	if _, err := conn.Write(payload); err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	a.BytesOut = len(payload)
	a.mark("first_write")
	got, err := readUntilClose(conn, time.Now().Add(c.attemptTimeout()), 64)
	a.BytesIn = len(got)
	if len(got) > 0 {
		a.mark("first_byte")
	}
	if len(got) == 0 {
		return a.fail(classifyNetErr(err, true), err)
	}
	if !bytes.Equal(got[:min(8, len(got))], sum[:8]) {
		a.Detail["response_prefix"] = hex.EncodeToString(got[:min(len(got), 16)])
		return a.fail(OutcomeUnexpected, fmt.Errorf("hash ack mismatch"))
	}
	return a.ok()
}

// tcpRTT measures connect RTT against payload RTT over several connections.
// A connect that completes materially faster than the application round trip
// is the signature of a middlebox answering the SYN on the server's behalf.
func (c *Client) tcpRTT(ctx context.Context, a *Attempt, n int) *Attempt {
	var connectMin, payloadMin float64 = 1e9, 1e9
	okCount := 0
	for i := 0; i < n; i++ {
		sub := newAttempt(a.TestID, a.Group, a.Role, a.Variant, "tcp", a.DstPort, a.Round)
		conn, err := c.dialTCP(ctx, sub)
		if err != nil {
			a.Detail["error_"+strconv.Itoa(i)] = err.Error()
			continue
		}
		start := time.Now()
		r := c.echoOnConn(conn, sub, 64, false)
		conn.Close()
		if r.Outcome != OutcomeOK {
			a.Detail["error_"+strconv.Itoa(i)] = r.Outcome
			continue
		}
		okCount++
		a.Nonce = sub.Nonce
		a.BytesOut += sub.BytesOut
		a.BytesIn += sub.BytesIn
		payloadRTT := float64(time.Since(start).Microseconds()) / 1000
		if sub.Stages["connect"] < connectMin {
			connectMin = sub.Stages["connect"]
		}
		if payloadRTT < payloadMin {
			payloadMin = payloadRTT
		}
	}
	a.Detail["samples_ok"] = strconv.Itoa(okCount)
	if okCount == 0 {
		return a.fail(OutcomeInconclusive, fmt.Errorf("no successful samples"))
	}
	a.Detail["connect_min_ms"] = fmt.Sprintf("%.2f", connectMin)
	a.Detail["payload_min_ms"] = fmt.Sprintf("%.2f", payloadMin)
	ratio := connectMin / payloadMin
	a.Detail["connect_payload_ratio"] = fmt.Sprintf("%.2f", ratio)
	// Below 0.5 the SYN-ACK came back in less than half the time a real
	// server round trip takes: suspicious, but only a signal without pcap.
	if ratio < 0.5 && payloadMin-connectMin > 20 {
		a.Detail["synack_suspect"] = "true"
	}
	return a.ok()
}

// httpHost sends a cleartext HTTP/1.1 request with the given Host header.
func (c *Client) httpHost(ctx context.Context, a *Attempt, host string) *Attempt {
	nonce := hex.EncodeToString(proto.RandomPayload(12))
	a.Nonce = nonce
	path := httpecho.Path(c.Session.SessionID, a.TestID, nonce)
	conn, err := c.dialTCP(ctx, a)
	if err != nil {
		return a.fail(classifyNetErr(err, false), err)
	}
	defer conn.Close()
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, host)
	conn.SetWriteDeadline(time.Now().Add(c.attemptTimeout()))
	if _, err := conn.Write([]byte(req)); err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	a.BytesOut = len(req)
	a.mark("first_write")
	conn.SetReadDeadline(time.Now().Add(c.attemptTimeout()))
	br := bufio.NewReader(conn)
	if _, err := br.Peek(1); err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	a.mark("first_byte")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		raw, _ := io.ReadAll(io.LimitReader(br, 256))
		a.Detail["response_prefix"] = strings.ToValidUTF8(string(raw[:min(len(raw), 64)]), "?")
		return a.fail(OutcomeUnexpected, err)
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	a.BytesIn = len(body)
	a.Detail["status"] = strconv.Itoa(resp.StatusCode)
	if loc := resp.Header.Get("Location"); loc != "" {
		a.Detail["location"] = loc
	}
	want := httpecho.Body(host, path, nonce)
	if resp.StatusCode != http.StatusOK || !bytes.Equal(body, want) || resp.Header.Get("X-CP1-Nonce") != nonce {
		a.Detail["body_sha256"] = hexSum(body)
		a.Detail["body_prefix"] = strings.ToValidUTF8(string(body[:min(len(body), 96)]), "?")
		if resp.StatusCode == http.StatusOK && rerr != nil {
			return a.fail(classifyNetErr(rerr, true), rerr)
		}
		return a.fail(OutcomeModified, fmt.Errorf("status %d / body mismatch", resp.StatusCode))
	}
	return a.ok()
}

// openvpnTCP sends a client hard reset over TCP (2-byte length framing) and
// expects a server hard reset; with o.session it goes on with the control
// and data channels on the same connection.
func (c *Client) openvpnTCP(ctx context.Context, a *Attempt, o ovpnOptions) *Attempt {
	layout, err := c.ovpnLayout(o.auth)
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	if err := c.reserve(ctx, a, "tcp", model.ParseOpenVPN); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	conn, err := c.dialTCP(ctx, a)
	if err != nil {
		return a.fail(classifyNetErr(err, false), err)
	}
	defer conn.Close()
	pkt, sid := layout.ClientReset()
	conn.SetWriteDeadline(time.Now().Add(c.attemptTimeout()))
	if _, err := conn.Write(ovpn.FrameTCP(pkt)); err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	a.BytesOut = 2 + len(pkt)
	a.mark("first_write")
	br := bufio.NewReaderSize(conn, 8192)
	readFrame := func() ([]byte, error) {
		var lenb [2]byte
		if _, err := io.ReadFull(br, lenb[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(lenb[:]))
		if n == 0 || n > ovpn.MaxPacketLen {
			return nil, fmt.Errorf("bad frame length %d", n)
		}
		pkt := make([]byte, n)
		_, err := io.ReadFull(br, pkt)
		return pkt, err
	}
	// The server reset: its frame length tells the layout apart (26 plain,
	// 54 tls-auth); anything else that comes back is recorded as unexpected.
	conn.SetReadDeadline(time.Now().Add(c.attemptTimeout()))
	var lenb [2]byte
	n, err := io.ReadFull(br, lenb[:])
	a.BytesIn = n
	if n > 0 {
		a.mark("first_byte")
	}
	var got []byte
	if err == nil {
		frameLen := int(binary.BigEndian.Uint16(lenb[:]))
		if frameLen == 0 || frameLen > ovpn.MaxPacketLen {
			a.Detail["response_prefix"] = hex.EncodeToString(lenb[:])
			return a.fail(OutcomeUnexpected, fmt.Errorf("bad frame length %d", frameLen))
		}
		got = make([]byte, frameLen)
		var m int
		m, err = io.ReadFull(br, got)
		a.BytesIn += m
		got = got[:m]
	}
	if err != nil {
		if a.BytesIn > 0 {
			a.Detail["response_prefix"] = hex.EncodeToString(append(lenb[:n], got...)[:min(a.BytesIn, 16)])
			return a.fail(OutcomeUnexpected, err)
		}
		return a.fail(classifyNetErr(err, true), err)
	}
	csid, ssid, perr := layout.ParseServerReset(got)
	if perr != nil || csid != sid {
		a.Detail["response_prefix"] = hex.EncodeToString(append(lenb[:], got...)[:min(2+len(got), 16)])
		if errors.Is(perr, ovpn.ErrBadHMAC) {
			return a.fail(OutcomeModified, perr)
		}
		return a.fail(OutcomeUnexpected, fmt.Errorf("not a matching server reset"))
	}
	if !o.session {
		return a.ok()
	}
	link := ovpnLink{
		write: func(p []byte) error {
			out := ovpn.FrameTCP(p)
			conn.SetWriteDeadline(time.Now().Add(c.attemptTimeout()))
			if _, err := conn.Write(out); err != nil {
				return err
			}
			a.BytesOut += len(out)
			return nil
		},
		read: func(deadline time.Time) ([]byte, error) {
			conn.SetReadDeadline(deadline)
			p, err := readFrame()
			if err != nil {
				return nil, err
			}
			a.BytesIn += 2 // the length prefix; the packet itself is counted by the caller
			return p, nil
		},
	}
	return c.openvpnSession(a, link, layout, sid, ssid)
}

// ovpnControlPayload is the i-th control packet payload: a real ClientHello
// first, then handshake-shaped TLS records of varying size.
func ovpnControlPayload(i int, size int) []byte {
	if i == 0 {
		if ch := tlsx.ClientHello("b" + randHex(6) + ".probe.invalid"); len(ch) > 0 {
			return ch
		}
	}
	body := proto.RandomPayload(max(size-5, 16))
	return tlsx.Record(body)
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
