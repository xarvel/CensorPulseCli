// Package vless builds and recognises the VLESS request/response headers
// that Xray clients send inside a TLS (REALITY) stream. On the wire a REALITY
// connection is TLS 1.3 with a browser fingerprint and somebody else's SNI;
// what a DPI can act on is that SNI/IP relation and the TLS-in-TLS shape of
// the data that follows. The probe reproduces exactly that: a browser-shaped
// ClientHello with a foreign SNI, then a VLESS request carrying a TLS
// ClientHello, then application-data-shaped records, all echoed by the server.
package vless

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

const (
	Version    = 0
	CmdTCP     = 1
	CmdUDP     = 2
	CmdMux     = 3
	ATypIPv4   = 1
	ATypDomain = 2
	ATypIPv6   = 3

	ResponseLen = 2 // version + addons length
)

var ErrNotVLESS = errors.New("vless: not a VLESS request")

// Request builds a VLESS request header for a TCP connection to host:port
// with a random UUID and no addons.
func Request(host string, port uint16) []byte {
	out := make([]byte, 1, 64)
	out[0] = Version
	var uuid [16]byte
	rand.Read(uuid[:])
	out = append(out, uuid[:]...)
	out = append(out, 0) // addons length
	out = append(out, CmdTCP)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	out = append(out, p[:]...)
	out = append(out, ATypDomain, byte(len(host)))
	return append(out, host...)
}

// Parsed is a decoded request header.
type Parsed struct {
	Cmd  byte
	Host string
	Port uint16
	Len  int
}

// IsRequest is the shape check used inside the TLS stream.
func IsRequest(b []byte) bool { _, err := Parse(b); return err == nil }

// Parse decodes a request header.
func Parse(b []byte) (Parsed, error) {
	var r Parsed
	if len(b) < 1+16+1+1+2+1 || b[0] != Version {
		return r, ErrNotVLESS
	}
	addons := int(b[17])
	i := 18 + addons
	if len(b) < i+1+2+1 {
		return r, ErrNotVLESS
	}
	r.Cmd = b[i]
	if r.Cmd < CmdTCP || r.Cmd > CmdMux {
		return r, ErrNotVLESS
	}
	r.Port = binary.BigEndian.Uint16(b[i+1 : i+3])
	atyp := b[i+3]
	i += 4
	switch atyp {
	case ATypIPv4:
		if len(b) < i+4 {
			return r, ErrNotVLESS
		}
		r.Host, i = "ip", i+4
	case ATypIPv6:
		if len(b) < i+16 {
			return r, ErrNotVLESS
		}
		r.Host, i = "ip", i+16
	case ATypDomain:
		if len(b) < i+1 || len(b) < i+1+int(b[i]) {
			return r, ErrNotVLESS
		}
		r.Host = string(b[i+1 : i+1+int(b[i])])
		i += 1 + int(b[i])
	default:
		return r, ErrNotVLESS
	}
	r.Len = i
	return r, nil
}

// Response is the server header: version and empty addons.
func Response() []byte { return []byte{Version, 0} }
