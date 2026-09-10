package client

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"

	"github.com/xarvel/CensorPulseCli/internal/dtlsx"
	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/stun"
)

// dtlsHello runs the first two flights of a WebRTC DTLS 1.2 handshake with a
// chosen ClientHello fingerprint: ClientHello, HelloVerifyRequest,
// ClientHello with the cookie, ServerHello. It stops there: the point is
// whether datagrams with this fingerprint cross the path.
func (c *Client) dtlsHello(ctx context.Context, a *Attempt, fingerprint string) *Attempt {
	a.Detail["dtls_fp"] = fingerprint
	if err := c.reserve(ctx, a, "udp", model.ParseDTLS); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	conn, err := c.udpConn(a)
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	defer conn.Close()
	ch, err := dtlsx.ClientHello(fingerprint, nil, 0)
	if err != nil {
		return a.fail(OutcomeSkipped, err)
	}
	got, err := c.udpExchangeOn(conn, a, ch)
	if err != nil {
		return a.fail(udpOutcome(err), err)
	}
	msgs, perr := dtlsx.Parse(got)
	if perr != nil || len(msgs) == 0 || msgs[0].Type != dtlsx.TypeHelloVerify {
		a.Detail["response_prefix"] = hex.EncodeToString(got[:min(len(got), 16)])
		return a.fail(OutcomeUnexpected, fmt.Errorf("expected HelloVerifyRequest"))
	}
	cookie := dtlsx.CookieOf(msgs[0].Body)
	a.mark("hello_verify")
	ch2, err := dtlsx.ClientHello(fingerprint, cookie, 1)
	if err != nil {
		return a.fail(OutcomeSkipped, err)
	}
	out := a.BytesOut
	got, err = c.udpExchangeOn(conn, a, ch2)
	a.BytesOut += out
	if err != nil {
		a.Detail["stage_failed"] = "cookie"
		return a.fail(udpOutcome(err), err)
	}
	msgs, perr = dtlsx.Parse(got)
	if perr != nil || len(msgs) == 0 || msgs[0].Type != dtlsx.TypeServerHello {
		a.Detail["response_prefix"] = hex.EncodeToString(got[:min(len(got), 16)])
		return a.fail(OutcomeUnexpected, fmt.Errorf("expected ServerHello"))
	}
	a.mark("handshake")
	return a.ok()
}

// stunBinding sends an RFC 5389 Binding Request and expects the success
// response with our reflexive address, as every WebRTC session starts.
func (c *Client) stunBinding(ctx context.Context, a *Attempt) *Attempt {
	if err := c.reserve(ctx, a, "udp", model.ParseSTUN); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	req, tx := stun.BindingRequest()
	got, err := c.udpExchange(a, req)
	if err != nil {
		return a.fail(udpOutcome(err), err)
	}
	mapped, perr := stun.ParseBindingSuccess(got, tx)
	if perr != nil {
		a.Detail["response_prefix"] = hex.EncodeToString(got[:min(len(got), 16)])
		return a.fail(OutcomeUnexpected, perr)
	}
	a.Detail["mapped_addr"] = mapped.String()
	if ca, err := netip.ParseAddr(c.Session.ClientAddr); err == nil && mapped.Addr().Unmap() != ca.Unmap() {
		a.Detail["mapped_addr_differs"] = "true"
	}
	return a.ok()
}
