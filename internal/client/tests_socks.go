package client

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/proto"
	"github.com/xarvel/CensorPulseCli/internal/socks5"
	"github.com/xarvel/CensorPulseCli/internal/tlsx"
)

// socks5Connect runs the SOCKS5 greeting, optional username/password
// sub-negotiation and a CONNECT to a probe name (socks5.connect); for
// socks5.session it then pushes TLS-shaped data through the "tunnel", which
// the probe server mirrors. The destination is never dialled by anyone.
func (c *Client) socks5Connect(ctx context.Context, a *Attempt, userpass bool) *Attempt {
	if err := c.reserve(ctx, a, "tcp", model.ParseSOCKS5); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	conn, err := c.dialTCP(ctx, a)
	if err != nil {
		return a.fail(classifyNetErr(err, false), err)
	}
	defer conn.Close()
	br := bufio.NewReaderSize(conn, 8192)
	write := func(b []byte) error {
		conn.SetWriteDeadline(time.Now().Add(c.attemptTimeout()))
		_, err := conn.Write(b)
		a.BytesOut += len(b)
		return err
	}
	readN := func(n int) ([]byte, error) {
		conn.SetReadDeadline(time.Now().Add(c.attemptTimeout()))
		b := make([]byte, n)
		_, err := io.ReadFull(br, b)
		a.BytesIn += len(b)
		return b, err
	}
	methods := []byte{socks5.MethodNoAuth}
	if userpass {
		methods = []byte{socks5.MethodNoAuth, socks5.MethodUser}
	}
	if err := write(socks5.Greeting(methods...)); err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	a.mark("first_write")
	rep, err := readN(2)
	if err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	a.mark("first_byte")
	if rep[0] != socks5.Version || rep[1] == socks5.MethodNone {
		a.Detail["response_prefix"] = hex.EncodeToString(rep)
		return a.fail(OutcomeUnexpected, fmt.Errorf("method reply %x", rep))
	}
	if rep[1] == socks5.MethodUser {
		if err := write(socks5.UserPass("probe", randHex(8))); err != nil {
			return a.fail(classifyNetErr(err, true), err)
		}
		ar, err := readN(2)
		if err != nil {
			return a.fail(classifyNetErr(err, true), err)
		}
		if ar[0] != 1 || ar[1] != 0 {
			a.Detail["response_prefix"] = hex.EncodeToString(ar)
			return a.fail(OutcomeUnexpected, fmt.Errorf("auth reply %x", ar))
		}
		a.Detail["auth"] = "userpass"
	}
	dst := randHex(6) + ".probe.invalid"
	if err := write(socks5.Connect(dst, 443)); err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	cr, err := readN(10)
	if err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	if !socks5.IsReply(cr) || cr[1] != socks5.RepSuccess {
		a.Detail["response_prefix"] = hex.EncodeToString(cr)
		return a.fail(OutcomeUnexpected, fmt.Errorf("connect reply %x", cr))
	}
	if a.TestID != "socks5.session" {
		return a.ok()
	}
	a.mark("handshake")
	return c.tcpMirrorLoop(a, conn, br, func(i, size int) []byte {
		if i == 0 {
			return tlsx.ClientHello(dst)
		}
		return tlsx.AppData(proto.RandomPayload(max(size-5, 16)))
	})
}

// tcpMirrorLoop is vpnDataLoop for a stream the server mirrors byte for
// byte: each chunk is written and the same number of bytes is expected back.
func (c *Client) tcpMirrorLoop(a *Attempt, conn net.Conn, br *bufio.Reader, payload func(i, size int) []byte) *Attempt {
	var want int
	return c.vpnDataLoop(a, func(i int, p []byte) error {
		want = len(p)
		conn.SetWriteDeadline(time.Now().Add(c.attemptTimeout()))
		if _, err := conn.Write(p); err != nil {
			return err
		}
		a.BytesOut += len(p)
		return nil
	}, func(deadline time.Time) (int, error) {
		conn.SetReadDeadline(deadline)
		b := make([]byte, want)
		n, err := io.ReadFull(br, b)
		a.BytesIn += n
		if err != nil {
			return 0, err
		}
		return n, nil
	}, payload)
}
