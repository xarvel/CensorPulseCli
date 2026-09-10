package client

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/ike"
	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/proto"
	"github.com/xarvel/CensorPulseCli/internal/wg"
)

// ikev2 runs IKE_SA_INIT (ikev2.init) and, for ikev2.session, IKE_AUTH
// followed by ESP-in-UDP data (NAT-T variant) or further IKE_AUTH-shaped
// exchanges (plain variant, where ESP would be its own IP protocol and is
// out of reach for an unprivileged client).
func (c *Client) ikev2(ctx context.Context, a *Attempt, natt bool) *Attempt {
	if err := c.reserve(ctx, a, "udp", model.ParseIKE); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	kp, err := wg.NewKeyPair() // a real Curve25519 public key for the KE payload
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	spii := ike.RandomSPI()
	init := ike.SAInit(spii, kp.Public)
	frame := func(b []byte) []byte {
		if natt {
			return ike.AddNATT(b)
		}
		return b
	}
	a.Detail["natt"] = fmt.Sprint(natt)
	conn, err := c.udpConn(a)
	if err != nil {
		return a.fail(udpOutcome(err), err)
	}
	defer conn.Close()
	got, err := c.udpExchangeOn(conn, a, frame(init))
	if err != nil {
		return a.fail(udpOutcome(err), err)
	}
	msg, gotNATT := ike.StripNATT(got)
	hdr, perr := ike.ParseHeader(msg)
	if perr != nil || hdr.SPIi != spii || hdr.Exchange != ike.ExchangeSAInit || hdr.Flags&ike.FlagResponse == 0 || gotNATT != natt {
		a.Detail["response_prefix"] = hex.EncodeToString(got[:min(len(got), 16)])
		if perr == nil {
			return a.fail(OutcomeModified, fmt.Errorf("IKE_SA_INIT response does not match"))
		}
		return a.fail(OutcomeUnexpected, fmt.Errorf("not an IKE_SA_INIT response"))
	}
	if a.TestID != "ikev2.session" {
		return a.ok()
	}
	a.mark("handshake")
	spir := hdr.SPIr
	// IKE_AUTH: one SK-shaped request, answered with an SK-shaped response.
	auth := ike.Auth(spii, spir, 1, 400, false)
	got, err = c.udpExchangeOn(conn, a, frame(auth))
	if err != nil {
		a.Detail["data_sent"], a.Detail["data_recv"] = "1", "0"
		return a.fail(OutcomeSessionCut, fmt.Errorf("IKE_AUTH unanswered: %w", err))
	}
	msg, _ = ike.StripNATT(got)
	if h, perr := ike.ParseHeader(msg); perr != nil || h.Exchange != ike.ExchangeAuth || h.SPIi != spii {
		a.Detail["response_prefix"] = hex.EncodeToString(got[:min(len(got), 16)])
		return a.fail(OutcomeUnexpected, fmt.Errorf("not an IKE_AUTH response"))
	}
	a.Detail["ike_auth"] = "answered"
	buf := make([]byte, 2048)
	recv := func(deadline time.Time) (int, error) {
		conn.SetReadDeadline(deadline)
		n, err := conn.Read(buf)
		if err != nil {
			return 0, err
		}
		a.BytesIn += n
		return n, nil
	}
	if natt {
		// ESP-in-UDP data with the SPI both ends derive from SPIr.
		spi := ike.ESPSPIFor(spir)
		return c.vpnDataLoop(a, func(i int, payload []byte) error {
			pkt := ike.ESP(spi, uint32(i+1), payload)
			if _, err := conn.Write(pkt); err != nil {
				return err
			}
			a.BytesOut += len(pkt)
			return nil
		}, func(deadline time.Time) (int, error) {
			n, err := recv(deadline)
			if err != nil {
				return 0, err
			}
			if !ike.IsESPUDP(buf[:n]) || ike.ESPSPI(buf[:n]) != spi {
				a.Detail["response_prefix"] = hex.EncodeToString(buf[:min(n, 16)])
				return 0, errModified
			}
			return n - ike.ESPHeaderLen, nil
		}, func(i, size int) []byte { return proto.RandomPayload(size &^ 15) })
	}
	// Plain UDP/500: further IKE_AUTH-shaped exchanges (message ids 2..N),
	// the shape of a client that keeps its IKE SA busy (CREATE_CHILD_SA,
	// informational) without ever touching raw IP.
	return c.vpnDataLoop(a, func(i int, payload []byte) error {
		pkt := ike.Auth(spii, spir, uint32(i+2), len(payload), false)
		if _, err := conn.Write(pkt); err != nil {
			return err
		}
		a.BytesOut += len(pkt)
		return nil
	}, func(deadline time.Time) (int, error) {
		n, err := recv(deadline)
		if err != nil {
			return 0, err
		}
		if h, perr := ike.ParseHeader(buf[:n]); perr != nil || h.SPIi != spii {
			a.Detail["response_prefix"] = hex.EncodeToString(buf[:min(n, 16)])
			return 0, errModified
		}
		return n - ike.HeaderLen, nil
	}, func(i, size int) []byte { return proto.RandomPayload(size) })
}

var _ net.Conn
