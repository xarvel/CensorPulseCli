// Package tlsx builds TLS-shaped bytes for tests that carry TLS inside another
// protocol (OpenVPN control channel, SOCKS5 tunnel, VLESS stream): a genuine
// ClientHello and handshake-typed records, so that what a DPI sees inside the
// carrier has the same shape as real traffic.
package tlsx

import (
	"crypto/tls"
	"encoding/binary"
	"net"
	"time"
)

// ClientHello returns the bytes of a genuine TLS ClientHello record captured
// from Go's TLS stack over an in-memory pipe. One classic key share (no
// hybrid post-quantum share) keeps it under 300 bytes, which is what most
// real clients still send and what fits one OpenVPN control packet.
func ClientHello(serverName string) []byte {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		tc := tls.Client(a, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, //nolint:gosec // bytes only
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}})
		_ = tc.Handshake()
	}()
	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, _ := b.Read(buf)
	return buf[:n]
}

// Record wraps payload into a handshake-typed TLS record.
func Record(payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0], out[1], out[2] = 0x16, 0x03, 0x03
	binary.BigEndian.PutUint16(out[3:], uint16(len(payload)))
	copy(out[5:], payload)
	return out
}

// AppData wraps payload into an application-data record (what flows after a
// TLS 1.3 handshake).
func AppData(payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0], out[1], out[2] = 0x17, 0x03, 0x03
	binary.BigEndian.PutUint16(out[3:], uint16(len(payload)))
	copy(out[5:], payload)
	return out
}

// IsClientHello is the cheap shape check for a ClientHello record.
func IsClientHello(b []byte) bool {
	return len(b) >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x04 && b[5] == 0x01
}
