package client

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/ovpn"
	"github.com/xarvel/CensorPulseCli/internal/proto"
	"github.com/xarvel/CensorPulseCli/internal/wg"
)

// The *.session tests answer the question a handshake-only test cannot: is a
// VPN flow that got past the handshake still allowed to carry data? Stateful
// blocking (the common "handshake completes, no traffic flows" symptom) only
// shows after a few packets have crossed in both directions.

// sessionSizes are the plaintext sizes cycled through a session, shaped like
// an interactive flow with full-size segments in it. Kept under 1100 bytes so
// that every datagram fits a conservative cellular MTU.
var sessionSizes = []int{96, 1024, 1024, 160, 1024, 64, 512, 1024}

// errModified marks a reply that arrived but failed authentication.
var errModified = errors.New("reply failed authentication")

// sessionCutAfter is how many consecutive lost packets end the loop early:
// after that the flow is considered cut and waiting longer only costs time.
const sessionCutAfter = 3

// vpnDataLoop drives the data phase. send transmits packet i with the given
// payload; recv waits for one reply until deadline and returns its payload
// length; payload builds the i-th plaintext for a target size.
func (c *Client) vpnDataLoop(a *Attempt, send func(i int, payload []byte) error, recv func(deadline time.Time) (int, error), payload func(i, size int) []byte) *Attempt {
	n := c.opt.SessionPackets
	if n <= 0 {
		n = 12
	}
	sent, recvd, firstLoss := 0, 0, -1
	consecutiveLost := 0
	var bytesEchoed int
	timeout := c.attemptTimeout()
	if timeout > 3*time.Second {
		timeout = 3 * time.Second
	}
	for i := 0; i < n; i++ {
		p := payload(i, sessionSizes[i%len(sessionSizes)])
		if err := send(i, p); err != nil {
			a.Detail["data_sent"] = strconv.Itoa(sent)
			a.Detail["data_recv"] = strconv.Itoa(recvd)
			return a.fail(classifyNetErr(err, true), err)
		}
		sent++
		if i == 0 {
			a.mark("data_first_write")
		}
		got, err := recv(time.Now().Add(timeout))
		if err != nil {
			if errors.Is(err, errModified) {
				a.Detail["data_sent"] = strconv.Itoa(sent)
				a.Detail["data_recv"] = strconv.Itoa(recvd)
				return a.fail(OutcomeModified, err)
			}
			if o := classifyNetErr(err, true); o != OutcomePayloadTimeout {
				a.Detail["data_sent"] = strconv.Itoa(sent)
				a.Detail["data_recv"] = strconv.Itoa(recvd)
				// A stream torn down while the data phase is unanswered is
				// still a cut flow: on TCP a path that swallows the tunnel
				// packets leaves the peer idle, and the peer hangs up before
				// the client runs out of patience. Keep the cut as the
				// outcome (that is what the operator did to the tunnel) and
				// record how the flow ended, so the raw form is not lost.
				if recvd == 0 {
					if firstLoss < 0 {
						firstLoss = i
					}
					a.Detail["data_close"] = o
					a.Detail["data_first_loss"] = strconv.Itoa(firstLoss)
					return a.fail(OutcomeSessionCut, fmt.Errorf("session cut: 0/%d data packets answered, the flow ended with %s (first loss at #%d)", sent, o, firstLoss))
				}
				return a.fail(o, err)
			}
			if firstLoss < 0 {
				firstLoss = i
			}
			consecutiveLost++
			if consecutiveLost >= sessionCutAfter {
				break // the flow is cut; more waiting only costs time
			}
			continue
		}
		if recvd == 0 {
			a.mark("data_first_byte")
		}
		consecutiveLost = 0
		recvd++
		bytesEchoed += got
		time.Sleep(120 * time.Millisecond)
	}
	a.Detail["data_sent"] = strconv.Itoa(sent)
	a.Detail["data_recv"] = strconv.Itoa(recvd)
	a.Detail["data_bytes_echoed"] = strconv.Itoa(bytesEchoed)
	if firstLoss >= 0 {
		a.Detail["data_first_loss"] = strconv.Itoa(firstLoss)
	}
	if recvd == sent {
		return a.ok()
	}
	// Only a flow that stopped being answered is a cut. Sporadic loss in the
	// middle of an otherwise answered exchange is ordinary packet loss: it is
	// recorded (data_lost) and the attempt still counts as passed, so that a
	// lossy Wi-Fi does not become a "session cut" verdict.
	if consecutiveLost >= sessionCutAfter {
		return a.fail(OutcomeSessionCut, fmt.Errorf("session cut: %d/%d data packets answered, the last %d unanswered (first loss at #%d)", recvd, sent, consecutiveLost, firstLoss))
	}
	a.Detail["data_lost"] = strconv.Itoa(sent - recvd)
	return a.ok()
}

// wireguardSession completes the handshake exactly like wireguard.init, then
// exchanges authenticated transport packets on the same 5-tuple.
func (c *Client) wireguardSession(ctx context.Context, a *Attempt) *Attempt {
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
	conn, err := c.udpConn(a)
	if err != nil {
		return a.fail(udpOutcome(err), err)
	}
	defer conn.Close()
	got, err := c.udpExchangeOn(conn, a, init)
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
	a.mark("handshake")
	keys, _ := st.Keys()
	buf := make([]byte, 2048)
	return c.vpnDataLoop(a, func(i int, payload []byte) error {
		pkt := wg.SealTransport(keys.Send, st.PeerIdx, uint64(i), payload)
		if _, err := conn.Write(pkt); err != nil {
			return err
		}
		a.BytesOut += len(pkt)
		return nil
	}, func(deadline time.Time) (int, error) {
		conn.SetReadDeadline(deadline)
		n, err := conn.Read(buf)
		if err != nil {
			return 0, err
		}
		a.BytesIn += n
		if !wg.LooksLikeTransport(buf[:n]) {
			a.Detail["response_prefix"] = hex.EncodeToString(buf[:min(n, 16)])
			return 0, errModified
		}
		_, plain, err := wg.OpenTransport(keys.Recv, buf[:n])
		if err != nil {
			return 0, errModified
		}
		return len(plain), nil
	}, func(i, size int) []byte { return proto.RandomPayload(size) })
}

// ovpnOptions selects the control-channel layout of an OpenVPN flow and
// whether it goes on past the reset exchange (openvpn.session).
type ovpnOptions struct {
	auth    ovpn.Auth
	session bool
}

// ovpnLink is the transport of one OpenVPN flow: a datagram socket, or a
// TCP stream with OpenVPN's 2-byte length framing. write sends one packet,
// read returns the next one (acks included) before deadline.
type ovpnLink struct {
	write func(pkt []byte) error
	read  func(deadline time.Time) ([]byte, error)
}

// ovpnControlPackets is how many P_CONTROL_V1 the client sends after the
// reset before switching to the data channel: a ClientHello and two more
// records, so that the flow has the shape of a finished handshake. The data
// phase that follows is what --session-packets sizes.
const ovpnControlPackets = 3

// ovpnControlSizes are the control payload sizes (0 = the real ClientHello).
var ovpnControlSizes = []int{0, 512, 160}

// ovpnLayout builds the client side of a control-channel layout. tls-auth
// needs the static key the server advertises in params.
func (c *Client) ovpnLayout(auth ovpn.Auth) (*ovpn.Layout, error) {
	if auth != ovpn.AuthTLS {
		return ovpn.Plain(), nil
	}
	key, err := base64Decode(c.Params.OVPNTLSAuthKey)
	if err != nil {
		return nil, fmt.Errorf("server did not advertise an OpenVPN tls-auth key")
	}
	c2s, s2c, err := ovpn.TLSAuthDirKeys(key)
	if err != nil {
		return nil, err
	}
	return ovpn.TLSAuth(c2s, s2c), nil
}

// sessionReplyTimeout is how long a session test waits for one reply.
func (c *Client) sessionReplyTimeout() time.Duration {
	timeout := c.attemptTimeout()
	if timeout > 3*time.Second {
		timeout = 3 * time.Second
	}
	return timeout
}

// openvpnSession runs what follows an answered reset: the control channel
// (ovpnControlPackets P_CONTROL_V1, the first acking the server reset, each
// expected to be answered with a control packet), then the data channel
// (P_DATA_V2 sealed with the per-attempt keys, echoed by the server under
// the other direction's key). The two phases are counted apart
// (ctl_sent/ctl_recv, data_sent/data_recv) so that "control passed, data
// cut" is visible in the report; that is the signature the real client
// showed (TLS handshake, PUSH_REPLY, then not one data packet either way).
func (c *Client) openvpnSession(a *Attempt, link ovpnLink, layout *ovpn.Layout, csid, ssid [8]byte) *Attempt {
	a.mark("handshake")
	c2s, s2c := ovpn.DeriveDataKeys(c.key, a.AttemptID)
	timeout := c.sessionReplyTimeout()
	recvControl := func(deadline time.Time) (int, error) {
		for {
			b, err := link.read(deadline)
			if err != nil {
				return 0, err
			}
			a.BytesIn += len(b)
			if ovpn.Opcode(b) == ovpn.OpAckV1 {
				continue
			}
			p, err := layout.Parse(b)
			if err != nil || p.Op != ovpn.OpControlV1 {
				a.Detail["response_prefix"] = hex.EncodeToString(b[:min(len(b), 16)])
				return 0, errModified
			}
			return len(p.Payload), nil
		}
	}
	ctlSent, ctlRecv := 0, 0
	for i := 0; i < ovpnControlPackets; i++ {
		var acks []uint32
		if i == 0 {
			acks = []uint32{0} // the server reset, acked on the first control packet like a real client
		}
		pkt := layout.Control(csid, uint32(i+1), ovpnControlPayload(i, ovpnControlSizes[i]), acks, ssid)
		if err := link.write(pkt); err != nil {
			a.Detail["ctl_sent"], a.Detail["ctl_recv"] = strconv.Itoa(ctlSent), strconv.Itoa(ctlRecv)
			return a.fail(classifyNetErr(err, true), err)
		}
		ctlSent++
		if i == 0 {
			a.mark("control_first_write")
		}
		_, err := recvControl(time.Now().Add(timeout))
		if err != nil {
			if errors.Is(err, errModified) {
				a.Detail["ctl_sent"], a.Detail["ctl_recv"] = strconv.Itoa(ctlSent), strconv.Itoa(ctlRecv)
				return a.fail(OutcomeModified, err)
			}
			if o := classifyNetErr(err, true); o != OutcomePayloadTimeout {
				a.Detail["ctl_sent"], a.Detail["ctl_recv"] = strconv.Itoa(ctlSent), strconv.Itoa(ctlRecv)
				return a.fail(o, err)
			}
			continue
		}
		if ctlRecv == 0 {
			a.mark("control_first_byte")
		}
		ctlRecv++
	}
	a.Detail["ctl_sent"], a.Detail["ctl_recv"] = strconv.Itoa(ctlSent), strconv.Itoa(ctlRecv)
	if ctlRecv == 0 {
		a.Detail["data_sent"], a.Detail["data_recv"] = "0", "0"
		return a.fail(OutcomeSessionCut, fmt.Errorf("control channel cut: 0/%d control packets answered after the reset", ctlSent))
	}
	var pid uint32
	return c.vpnDataLoop(a, func(i int, payload []byte) error {
		pid++
		return link.write(c2s.Seal(0, pid, payload))
	}, func(deadline time.Time) (int, error) {
		for {
			b, err := link.read(deadline)
			if err != nil {
				return 0, err
			}
			a.BytesIn += len(b)
			if op := ovpn.Opcode(b); op == ovpn.OpAckV1 || op == ovpn.OpControlV1 {
				continue // a late control packet
			}
			if !ovpn.IsData(b) {
				a.Detail["response_prefix"] = hex.EncodeToString(b[:min(len(b), 16)])
				return 0, errModified
			}
			_, plain, err := s2c.Open(b)
			if err != nil {
				return 0, errModified
			}
			return len(plain), nil
		}
	}, ovpnDataPayload)
}

// ovpnDataPayload is the i-th data plaintext: the 16-byte keepalive ping
// first (a real client's first data packet, 40 bytes on the wire), then
// random payloads of the session sizes.
func ovpnDataPayload(i, size int) []byte {
	if i == 0 {
		return append([]byte(nil), ovpn.PingMagic...)
	}
	return proto.RandomPayload(size)
}

// openvpnUDP sends a client hard reset over UDP and expects a server hard
// reset; with o.session it goes on with the control and data channels on the
// same socket.
func (c *Client) openvpnUDP(ctx context.Context, a *Attempt, o ovpnOptions) *Attempt {
	layout, err := c.ovpnLayout(o.auth)
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	if err := c.reserve(ctx, a, "udp", model.ParseOpenVPN); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	pkt, sid := layout.ClientReset()
	conn, err := c.udpConn(a)
	if err != nil {
		return a.fail(udpOutcome(err), err)
	}
	defer conn.Close()
	got, err := c.udpExchangeOn(conn, a, pkt)
	if err != nil {
		return a.fail(udpOutcome(err), err)
	}
	csid, ssid, perr := layout.ParseServerReset(got)
	if perr != nil || csid != sid {
		a.Detail["response_prefix"] = hex.EncodeToString(got[:min(len(got), 16)])
		if errors.Is(perr, ovpn.ErrBadHMAC) {
			return a.fail(OutcomeModified, perr)
		}
		return a.fail(OutcomeUnexpected, fmt.Errorf("not a matching server reset"))
	}
	if !o.session {
		return a.ok()
	}
	buf := make([]byte, 2048)
	link := ovpnLink{
		write: func(p []byte) error {
			if _, err := conn.Write(p); err != nil {
				return err
			}
			a.BytesOut += len(p)
			return nil
		},
		read: func(deadline time.Time) ([]byte, error) {
			conn.SetReadDeadline(deadline)
			n, err := conn.Read(buf)
			if err != nil {
				return nil, err
			}
			return buf[:n], nil
		},
	}
	return c.openvpnSession(a, link, layout, sid, ssid)
}
