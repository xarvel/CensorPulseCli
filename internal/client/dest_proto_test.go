package client

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/dest"
)

// waServer accepts one connection, reads the client hello and answers with
// reply (nil: says nothing and holds the connection; reset: RST).
func waServer(t *testing.T, reply []byte, reset bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		hello := make([]byte, len(dest.WhatsAppHello()))
		if _, err := io.ReadFull(conn, hello); err != nil || string(hello[:2]) != "WA" {
			return
		}
		switch {
		case reset:
			conn.(*net.TCPConn).SetLinger(0)
		case reply != nil:
			conn.Write(reply)
		default:
			time.Sleep(3 * time.Second)
		}
	}()
	return ln.Addr().String()
}

func TestDestProtoOnWhatsApp(t *testing.T) {
	c, err := New(Options{Sites: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	// ephemeral 32, static 48, payload 3 inside serverHello (field 3).
	inner := append(append(append([]byte{0x0a, 32}, make([]byte, 32)...), append([]byte{0x12, 48}, make([]byte, 48)...)...), 0x1a, 3, 1, 2, 3)
	body := append([]byte{0x1a, byte(len(inner))}, inner...)
	serverHello := append([]byte{0, 0, byte(len(body))}, body...)
	wa := dest.Target{Domain: "chat.example", Proto: dest.ProtoWhatsApp}
	for _, tc := range []struct {
		name  string
		reply []byte
		reset bool
		want  string
	}{
		{"server hello", serverHello, false, OutcomeOK},
		{"reset", nil, true, OutcomeMidstreamReset},
		{"block page", []byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"), false, OutcomeUnexpected},
		{"silence", nil, false, OutcomePayloadTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", waServer(t, tc.reply, tc.reset))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			a := &Attempt{Detail: map[string]string{}, Stages: map[string]float64{}}
			got, err := c.destProtoOn(context.Background(), conn, wa, a)
			if got != tc.want {
				t.Fatalf("outcome %s (%v), want %s", got, err, tc.want)
			}
			if got == OutcomeOK && a.Detail["server_hello"] != "ephemeral=32 static=48 payload=3" {
				t.Fatalf("server_hello %q", a.Detail["server_hello"])
			}
		})
	}
}
