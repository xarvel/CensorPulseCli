package client

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/proto"
)

// packetsOptions describe one tcp.packets attempt: the same 64-byte envelope
// that tcp.echo sends in one write, pushed in ChunkBytes-sized writes with a
// pause between them. With TCP_NODELAY (Go's default) every write leaves as
// its own segment, so a rule that counts packets per flow instead of bytes
// trips on this flow and not on tcp.echo.
type packetsOptions struct {
	TLS        bool
	SNI        string
	ChunkBytes int
	Gap        time.Duration
	Payload    int
}

// tcpPackets sends the envelope in small segments and expects the echo.
func (c *Client) tcpPackets(ctx context.Context, a *Attempt, o packetsOptions) *Attempt {
	if o.ChunkBytes <= 0 {
		o.ChunkBytes = 2
	}
	if o.Gap <= 0 {
		o.Gap = 20 * time.Millisecond
	}
	if o.Payload <= 0 {
		o.Payload = 64
	}
	a.Detail["chunk_bytes"] = strconv.Itoa(o.ChunkBytes)
	payload := proto.RandomPayload(o.Payload)
	wire, nonce, err := c.envelope(a.TestID, 1, payload, false)
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	a.Nonce = hex.EncodeToString(nonce[:])
	a.Detail["packets_planned"] = strconv.Itoa((len(wire) + o.ChunkBytes - 1) / o.ChunkBytes)
	if o.TLS {
		a.Detail["sni"] = o.SNI
	}
	// A flow cut before the whole envelope arrived cannot identify itself by
	// nonce; the reservation lets the server attribute the partial envelope.
	kind := model.ParseEnvelope
	if o.TLS {
		kind = model.ParseTLS
	}
	if err := c.reserve(ctx, a, "tcp", kind); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	raw, err := c.dialTCP(ctx, a)
	if err != nil {
		return a.fail(classifyNetErr(err, false), err)
	}
	defer raw.Close()
	var conn net.Conn = raw
	if o.TLS {
		cfg := c.pinnedTLS(o.SNI)
		cfg.NextProtos = []string{"cp1"}
		tc := tls.Client(raw, cfg)
		raw.SetDeadline(time.Now().Add(c.attemptTimeout()))
		if err := tc.HandshakeContext(ctx); err != nil {
			noteTLSFailure(a, err)
			return a.fail(tlsOutcome(err), err)
		}
		a.mark("handshake")
		conn = tc
	}
	sent := 0
	for off := 0; off < len(wire); off += o.ChunkBytes {
		end := min(off+o.ChunkBytes, len(wire))
		conn.SetWriteDeadline(time.Now().Add(c.attemptTimeout()))
		if _, err := conn.Write(wire[off:end]); err != nil {
			a.Detail["packets_sent"] = strconv.Itoa(sent)
			return a.fail(packetsOutcome(classifyNetErr(err, true)), err)
		}
		if sent == 0 {
			a.mark("first_write")
		}
		sent++
		a.BytesOut += end - off
		if end < len(wire) {
			select {
			case <-time.After(o.Gap):
			case <-ctx.Done():
				return a.fail(OutcomeSkipped, ctx.Err())
			}
		}
	}
	a.Detail["packets_sent"] = strconv.Itoa(sent)
	a.mark("last_write")
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(c.attemptTimeout()))
	for {
		if total, _ := proto.ReplyLen(buf); total > 0 {
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
			return a.fail(packetsOutcome(classifyNetErr(err, true)), err)
		}
		if len(buf) >= 4 && !proto.IsEnvelope(buf) {
			a.Detail["response_prefix"] = hex.EncodeToString(buf[:min(len(buf), 16)])
			return a.fail(OutcomeUnexpected, fmt.Errorf("non-envelope reply"))
		}
	}
	if _, why := c.checkReply(buf, nonce, payload); why != "" {
		a.Detail["reply_check"] = why
		return a.fail(OutcomeModified, fmt.Errorf("reply check: %s", why))
	}
	return a.ok()
}

// packetsOutcome maps a mid-flow failure of a small-packet flow to
// packets_cut; everything else keeps its meaning.
func packetsOutcome(o string) string {
	switch o {
	case OutcomePayloadTimeout, OutcomeMidstreamReset, OutcomeMidstreamEOF:
		return OutcomePacketsCut
	}
	return o
}

// udpPackets sends N small cookie-bearing envelopes on one socket, one after
// the other, each expecting its echo, and records where the echoes stopped.
// The server answers every datagram independently and records one
// observation per nonce, so the nonces this attempt sent count what it saw
// (the source port is useless for that behind NAT).
func (c *Client) udpPackets(ctx context.Context, a *Attempt, n, size int) *Attempt {
	if n <= 0 {
		n = 32
	}
	if size <= 0 {
		size = 32
	}
	a.Detail["packets_planned"] = strconv.Itoa(n)
	conn, err := c.udpConn(a)
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	defer conn.Close()
	acked, sent, firstLoss, unanswered := 0, 0, -1, 0
	var lastErr error
	timeout := c.attemptTimeout()
	if timeout > 2*time.Second {
		timeout = 2 * time.Second // per datagram; a lost one must not eat the whole budget
	}
	buf := make([]byte, 2048)
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			return a.fail(OutcomeSkipped, ctx.Err())
		}
		payload := proto.RandomPayload(size)
		wire, nonce, err := c.envelope(a.TestID, uint32(i+1), payload, true)
		if err != nil {
			return a.fail(OutcomeServerError, err)
		}
		if i == 0 {
			a.Nonce = hex.EncodeToString(nonce[:])
		}
		a.nonces = append(a.nonces, hex.EncodeToString(nonce[:]))
		if _, err := conn.Write(wire); err != nil {
			lastErr = err
			break
		}
		sent++
		a.BytesOut += len(wire)
		if i == 0 {
			a.mark("first_write")
		}
		conn.SetReadDeadline(time.Now().Add(timeout))
		got := 0
		for {
			m, err := conn.Read(buf)
			if err != nil {
				lastErr = err
				break
			}
			a.BytesIn += m
			if !proto.IsEnvelope(buf[:m]) {
				continue
			}
			if _, why := c.checkReply(buf[:m], nonce, payload); why == "" {
				got = 1
				break
			}
		}
		if got == 1 {
			if acked == 0 {
				a.mark("first_byte")
			}
			acked++
			unanswered = 0
			lastErr = nil
		} else {
			unanswered++
			if firstLoss < 0 {
				firstLoss = i + 1
			}
		}
		if unanswered >= 3 {
			break // three unanswered in a row: the flow is cut, stop wasting time
		}
	}
	a.Detail["packets_sent"] = strconv.Itoa(sent)
	a.Detail["packets_acked"] = strconv.Itoa(acked)
	if firstLoss > 0 {
		a.Detail["first_loss"] = strconv.Itoa(firstLoss)
	}
	// The loop above stops after three unanswered datagrams in a row: that
	// is a cut wherever it lands, including on the last three of the burst
	// (sent == n then). A write error that ended the burst early is one too.
	// Loss in the middle of an answered run is ordinary packet loss and is
	// recorded without failing the attempt.
	cut := unanswered >= 3 || sent < n
	switch {
	case acked == n:
		return a.ok()
	case acked == 0 && sent > 0:
		if lastErr != nil {
			return a.fail(udpOutcome(lastErr), lastErr)
		}
		return a.fail(OutcomePayloadTimeout, fmt.Errorf("no datagram answered"))
	case cut:
		return a.fail(OutcomePacketsCut, fmt.Errorf("echo stopped after %d of %d datagrams (first loss at #%d)", acked, sent, firstLoss))
	default:
		a.Detail["packets_lost"] = strconv.Itoa(sent - acked)
		return a.ok()
	}
}
