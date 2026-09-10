package tlsx

import (
	"bytes"
	"testing"
)

// IsClientHello runs on the first bytes of every TCP connection the demuxer
// sees and on the payload of OpenVPN control packets, SOCKS5 tunnels and
// VLESS streams: six bytes of anybody's choosing.

func FuzzIsClientHello(f *testing.F) {
	f.Add(Record([]byte{0x01, 0x00, 0x00, 0x00}))
	f.Add(Record([]byte{0x02}))
	f.Add(Record(nil))
	f.Add(AppData([]byte{0x01}))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x01})
	f.Add([]byte{0x16, 0x03, 0x05, 0x00, 0x01, 0x01}) // no such TLS version
	f.Fuzz(func(t *testing.T, b []byte) {
		if !IsClientHello(b) {
			return
		}
		// What is accepted is a handshake record whose first message is a
		// ClientHello; re-framing the payload differs in the version byte at
		// most (a first ClientHello says 03 01, Record always 03 03).
		again := Record(b[5:])
		again[2] = b[2]
		if !bytes.Equal(again[:3], b[:3]) || !bytes.Equal(again[5:], b[5:]) || b[5] != 0x01 {
			t.Fatalf("accepted %x", b)
		}
	})
}
