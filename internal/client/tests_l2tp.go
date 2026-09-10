package client

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/l2tp"
	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/proto"
)

// l2tpTunnel runs SCCRQ/SCCRP (l2tp.init) and, for l2tp.session, completes
// the tunnel and a session (SCCCN, ICRQ/ICRP, ICCN) and then exchanges PPP
// data messages, all on the same UDP 5-tuple.
func (c *Client) l2tpTunnel(ctx context.Context, a *Attempt) *Attempt {
	if err := c.reserve(ctx, a, "udp", model.ParseL2TP); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	tunnel := l2tp.RandomID()
	conn, err := c.udpConn(a)
	if err != nil {
		return a.fail(udpOutcome(err), err)
	}
	defer conn.Close()
	got, err := c.udpExchangeOn(conn, a, l2tp.SCCRQ(tunnel, "probe-"+randHex(4)))
	if err != nil {
		return a.fail(udpOutcome(err), err)
	}
	ctl, perr := l2tp.ParseControl(got)
	if perr != nil || ctl.MessageType != l2tp.MsgSCCRP || ctl.TunnelID != tunnel || ctl.AssignedTunnel == 0 {
		a.Detail["response_prefix"] = hex.EncodeToString(got[:min(len(got), 16)])
		if perr == nil {
			return a.fail(OutcomeModified, fmt.Errorf("SCCRP does not match our tunnel"))
		}
		return a.fail(OutcomeUnexpected, fmt.Errorf("not an SCCRP"))
	}
	if a.TestID != "l2tp.session" {
		return a.ok()
	}
	a.mark("handshake")
	peer := ctl.AssignedTunnel
	buf := make([]byte, 2048)
	// Control steps before data: each must be acknowledged.
	step := func(out []byte, want uint16) (l2tp.Control, error) {
		got, err := c.udpExchangeOn(conn, a, out)
		if err != nil {
			return l2tp.Control{}, err
		}
		c2, perr := l2tp.ParseControl(got)
		if perr != nil || c2.MessageType != want {
			a.Detail["response_prefix"] = hex.EncodeToString(got[:min(len(got), 16)])
			return c2, fmt.Errorf("expected message %d", want)
		}
		return c2, nil
	}
	fail := func(stage string, err error) *Attempt {
		a.Detail["l2tp_stage"] = stage
		a.Detail["data_sent"], a.Detail["data_recv"] = "0", "0"
		if o := classifyNetErr(err, true); o == OutcomePayloadTimeout {
			return a.fail(OutcomeSessionCut, fmt.Errorf("%s unanswered: %w", stage, err))
		}
		return a.fail(OutcomeUnexpected, err)
	}
	if _, err := step(l2tp.SCCCN(peer), l2tp.MsgZLB); err != nil {
		return fail("scccn", err)
	}
	session := l2tp.RandomID()
	icrp, err := step(l2tp.ICRQ(peer, session, 2, 2), l2tp.MsgICRP)
	if err != nil {
		return fail("icrq", err)
	}
	peerSession := icrp.AssignedSession
	if _, err := step(l2tp.ICCN(peer, peerSession, 3, 3), l2tp.MsgZLB); err != nil {
		return fail("iccn", err)
	}
	a.Detail["l2tp_stage"] = "data"
	return c.vpnDataLoop(a, func(i int, payload []byte) error {
		pkt := l2tp.Data(peer, peerSession, payload)
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
		if !l2tp.IsData(buf[:n]) || l2tp.DataTunnel(buf[:n]) != tunnel {
			a.Detail["response_prefix"] = hex.EncodeToString(buf[:min(n, 16)])
			return 0, errModified
		}
		return n - l2tp.DataHeaderLen, nil
	}, func(i, size int) []byte {
		if i == 0 {
			return l2tp.PPPLCPConfigureRequest(1)
		}
		return l2tp.PPPIP(proto.RandomPayload(max(size-4, 20)))
	})
}
