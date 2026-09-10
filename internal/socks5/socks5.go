// Package socks5 builds and recognises the SOCKS5 (RFC 1928 / 1929) client
// greeting, optional username/password sub-negotiation and CONNECT request.
// The probe server never connects anywhere: it answers CONNECT with success
// and echoes the bytes that follow, which is enough to measure whether the
// SOCKS5 wire shape and a tunnel that carries TLS survive the path.
package socks5

import (
	"encoding/binary"
	"errors"
)

const (
	Port = 1080

	Version      = 5
	MethodNoAuth = 0x00
	MethodUser   = 0x02
	MethodNone   = 0xff

	CmdConnect = 1
	ATypIPv4   = 1
	ATypDomain = 3
	ATypIPv6   = 4

	RepSuccess = 0
)

var ErrNotSOCKS = errors.New("socks5: not a SOCKS5 message")

// IsGreeting is the shape check for the client greeting.
func IsGreeting(b []byte) bool {
	return len(b) >= 3 && b[0] == Version && b[1] >= 1 && b[1] <= 4 && len(b) >= 2+int(b[1])
}

// Greeting builds the client greeting offering the given methods.
func Greeting(methods ...byte) []byte {
	return append([]byte{Version, byte(len(methods))}, methods...)
}

// GreetingMethods returns the methods offered.
func GreetingMethods(b []byte) []byte { return b[2 : 2+int(b[1])] }

// MethodReply is the server's method selection.
func MethodReply(m byte) []byte { return []byte{Version, m} }

// UserPass builds the RFC 1929 sub-negotiation request.
func UserPass(user, pass string) []byte {
	out := []byte{1, byte(len(user))}
	out = append(out, user...)
	out = append(out, byte(len(pass)))
	return append(out, pass...)
}

// ParseUserPass validates a sub-negotiation request.
func ParseUserPass(b []byte) (user, pass string, err error) {
	if len(b) < 3 || b[0] != 1 {
		return "", "", ErrNotSOCKS
	}
	ul := int(b[1])
	if len(b) < 3+ul {
		return "", "", ErrNotSOCKS
	}
	user = string(b[2 : 2+ul])
	pl := int(b[2+ul])
	if len(b) < 3+ul+pl {
		return "", "", ErrNotSOCKS
	}
	return user, string(b[3+ul : 3+ul+pl]), nil
}

// UserPassReply is the sub-negotiation answer (status 0 = ok).
func UserPassReply(status byte) []byte { return []byte{1, status} }

// Connect builds a CONNECT request to a domain name.
func Connect(host string, port uint16) []byte {
	out := []byte{Version, CmdConnect, 0, ATypDomain, byte(len(host))}
	out = append(out, host...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	return append(out, p[:]...)
}

// Request is a parsed CONNECT/BIND/UDP request.
type Request struct {
	Cmd  byte
	Host string
	Port uint16
	Len  int // bytes consumed
}

// ParseRequest decodes a request; it returns ErrNotSOCKS when more bytes
// are needed or the shape is wrong.
func ParseRequest(b []byte) (Request, error) {
	var r Request
	if len(b) < 7 || b[0] != Version || b[2] != 0 {
		return r, ErrNotSOCKS
	}
	r.Cmd = b[1]
	var n int
	switch b[3] {
	case ATypIPv4:
		n = 4
	case ATypIPv6:
		n = 16
	case ATypDomain:
		n = 1 + int(b[4])
	default:
		return r, ErrNotSOCKS
	}
	if len(b) < 4+n+2 {
		return r, ErrNotSOCKS
	}
	switch b[3] {
	case ATypDomain:
		r.Host = string(b[5 : 5+int(b[4])])
	default:
		r.Host = "ip"
	}
	r.Port = binary.BigEndian.Uint16(b[4+n : 4+n+2])
	r.Len = 4 + n + 2
	return r, nil
}

// Reply builds a request reply with an IPv4 bind address of 0.0.0.0:0.
func Reply(rep byte) []byte {
	return []byte{Version, rep, 0, ATypIPv4, 0, 0, 0, 0, 0, 0}
}

// IsReply is the shape check for a 10-byte IPv4 reply.
func IsReply(b []byte) bool { return len(b) >= 10 && b[0] == Version && b[2] == 0 && b[3] == ATypIPv4 }
