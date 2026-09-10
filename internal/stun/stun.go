// Package stun implements the two RFC 5389 messages a WebRTC client (and so
// Snowflake) exchanges with a STUN server before any DTLS: a Binding Request
// and the Binding Success Response carrying XOR-MAPPED-ADDRESS.
package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	magicCookie    = 0x2112A442
	typeBindingReq = 0x0001
	typeBindingOK  = 0x0101
	attrXORMapped  = 0x0020
	HeaderLen      = 20
)

// BindingRequest returns a request with a fresh transaction id (and the id).
func BindingRequest() ([]byte, [12]byte) {
	var tx [12]byte
	rand.Read(tx[:])
	b := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(b, typeBindingReq)
	binary.BigEndian.PutUint32(b[4:], magicCookie)
	copy(b[8:], tx[:])
	return b, tx
}

// IsBindingRequest reports whether b is a STUN Binding Request.
func IsBindingRequest(b []byte) bool {
	return len(b) >= HeaderLen && binary.BigEndian.Uint16(b) == typeBindingReq &&
		binary.BigEndian.Uint32(b[4:]) == magicCookie && int(binary.BigEndian.Uint16(b[2:]))+HeaderLen == len(b)
}

// TransactionID of any STUN message.
func TransactionID(b []byte) (tx [12]byte) {
	if len(b) >= HeaderLen {
		copy(tx[:], b[8:20])
	}
	return
}

// BindingSuccess answers a request with the peer's XOR-mapped address.
func BindingSuccess(tx [12]byte, peer netip.AddrPort) []byte {
	ip := peer.Addr().Unmap()
	var val []byte
	if ip.Is4() {
		a := ip.As4()
		val = make([]byte, 8)
		val[1] = 0x01
		binary.BigEndian.PutUint16(val[2:], peer.Port()^(magicCookie>>16))
		binary.BigEndian.PutUint32(val[4:], binary.BigEndian.Uint32(a[:])^magicCookie)
	} else {
		a := ip.As16()
		val = make([]byte, 20)
		val[1] = 0x02
		binary.BigEndian.PutUint16(val[2:], peer.Port()^(magicCookie>>16))
		var xor [16]byte
		binary.BigEndian.PutUint32(xor[:], magicCookie)
		copy(xor[4:], tx[:])
		for i := range a {
			val[4+i] = a[i] ^ xor[i]
		}
	}
	attr := make([]byte, 4+len(val))
	binary.BigEndian.PutUint16(attr, attrXORMapped)
	binary.BigEndian.PutUint16(attr[2:], uint16(len(val)))
	copy(attr[4:], val)
	b := make([]byte, HeaderLen, HeaderLen+len(attr))
	binary.BigEndian.PutUint16(b, typeBindingOK)
	binary.BigEndian.PutUint16(b[2:], uint16(len(attr)))
	binary.BigEndian.PutUint32(b[4:], magicCookie)
	copy(b[8:], tx[:])
	return append(b, attr...)
}

// ParseBindingSuccess checks a response against the request's transaction
// id and returns the XOR-mapped address.
func ParseBindingSuccess(b []byte, tx [12]byte) (netip.AddrPort, error) {
	if len(b) < HeaderLen || binary.BigEndian.Uint16(b) != typeBindingOK || binary.BigEndian.Uint32(b[4:]) != magicCookie {
		return netip.AddrPort{}, errors.New("stun: not a binding success response")
	}
	if TransactionID(b) != tx {
		return netip.AddrPort{}, errors.New("stun: transaction id mismatch")
	}
	rest := b[HeaderLen:]
	for len(rest) >= 4 {
		t := binary.BigEndian.Uint16(rest)
		l := int(binary.BigEndian.Uint16(rest[2:]))
		if len(rest) < 4+l {
			break
		}
		v := rest[4 : 4+l]
		if t == attrXORMapped && len(v) >= 8 {
			port := binary.BigEndian.Uint16(v[2:]) ^ (magicCookie >> 16)
			switch v[1] {
			case 0x01:
				var a [4]byte
				binary.BigEndian.PutUint32(a[:], binary.BigEndian.Uint32(v[4:])^magicCookie)
				return netip.AddrPortFrom(netip.AddrFrom4(a), port), nil
			case 0x02:
				if len(v) < 20 {
					break
				}
				var xor, a [16]byte
				binary.BigEndian.PutUint32(xor[:], magicCookie)
				copy(xor[4:], tx[:])
				for i := range a {
					a[i] = v[4+i] ^ xor[i]
				}
				return netip.AddrPortFrom(netip.AddrFrom16(a), port), nil
			}
		}
		rest = rest[4+l+(4-l%4)%4:]
	}
	return netip.AddrPort{}, errors.New("stun: no XOR-MAPPED-ADDRESS")
}
