// Package ike builds and recognises the first exchanges of IKEv2 (RFC 7296):
// IKE_SA_INIT request/response with a real Curve25519 key exchange payload,
// an IKE_AUTH request/response whose SK payload has the right shape, and
// ESP-in-UDP (RFC 3948) data on port 4500. No IPsec SA is ever established
// and no keys are derived: the probe measures whether the wire shape of an
// IPsec/IKEv2 setup and of the ESP that follows survives the path.
package ike

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

const (
	HeaderLen = 28
	Version   = 0x20

	ExchangeSAInit = 34
	ExchangeAuth   = 35

	FlagInitiator = 0x08
	FlagResponse  = 0x20

	PayloadNone   = 0
	PayloadSA     = 33
	PayloadKE     = 34
	PayloadNonce  = 40
	PayloadNotify = 41
	PayloadVendor = 43
	PayloadSK     = 46

	NotifyNATDetectionSource = 16388
	NotifyNATDetectionDest   = 16389

	DHGroupCurve25519 = 31
	NonceLen          = 32
	NATDetectionLen   = 20
	NATTMarkerLen     = 4 // RFC 3948 non-ESP marker on UDP 4500

	ESPHeaderLen = 8 // SPI(4) + sequence(4)
)

var ErrNotIKE = errors.New("ike: not an IKEv2 message")

// Header is the fixed IKEv2 header.
type Header struct {
	SPIi, SPIr  [8]byte
	NextPayload byte
	Exchange    byte
	Flags       byte
	MessageID   uint32
	Length      uint32
}

// ParseHeader validates the header of one datagram (without NAT-T marker).
func ParseHeader(b []byte) (Header, error) {
	var h Header
	if len(b) < HeaderLen || b[17] != Version {
		return h, ErrNotIKE
	}
	copy(h.SPIi[:], b[0:8])
	copy(h.SPIr[:], b[8:16])
	h.NextPayload = b[16]
	h.Exchange = b[18]
	h.Flags = b[19]
	h.MessageID = binary.BigEndian.Uint32(b[20:24])
	h.Length = binary.BigEndian.Uint32(b[24:28])
	if h.Length != uint32(len(b)) || (h.Exchange != ExchangeSAInit && h.Exchange != ExchangeAuth) {
		return h, ErrNotIKE
	}
	return h, nil
}

// Looks is the cheap shape check used by the UDP demuxer.
func Looks(b []byte) bool { _, err := ParseHeader(b); return err == nil }

// StripNATT removes the RFC 3948 non-ESP marker when present.
func StripNATT(b []byte) ([]byte, bool) {
	if len(b) > NATTMarkerLen && b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 && Looks(b[NATTMarkerLen:]) {
		return b[NATTMarkerLen:], true
	}
	return b, false
}

// AddNATT prepends the non-ESP marker.
func AddNATT(b []byte) []byte { return append(make([]byte, NATTMarkerLen, NATTMarkerLen+len(b)), b...) }

// IsESPUDP reports whether b looks like ESP-in-UDP: a non-zero SPI followed
// by a sequence number and at least one block of payload. The caller must
// still know the SPI; random datagrams satisfy the shape.
func IsESPUDP(b []byte) bool {
	return len(b) >= ESPHeaderLen+16 && binary.BigEndian.Uint32(b[0:4]) != 0
}

// ESPSPI returns the SPI of an ESP-in-UDP datagram.
func ESPSPI(b []byte) uint32 { return binary.BigEndian.Uint32(b[0:4]) }

// ESP builds an ESP-in-UDP datagram: SPI, sequence, payload (opaque here;
// real ESP is encrypted and padded to the cipher block plus a 12–16 byte ICV,
// which the sizes chosen by the caller imitate).
func ESP(spi, seq uint32, payload []byte) []byte {
	out := make([]byte, ESPHeaderLen+len(payload))
	binary.BigEndian.PutUint32(out[0:4], spi)
	binary.BigEndian.PutUint32(out[4:8], seq)
	copy(out[8:], payload)
	return out
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// RandomSPI returns a non-zero 8-byte IKE SPI.
func RandomSPI() (spi [8]byte) {
	for spi == ([8]byte{}) {
		copy(spi[:], randBytes(8))
	}
	return spi
}

type payloadWriter struct {
	out  []byte
	prev int // offset of the previous payload header's next-payload byte
}

func (w *payloadWriter) add(typ byte, body []byte) {
	if w.prev >= 0 {
		w.out[w.prev] = typ
	} else {
		w.out[16] = typ // header's next payload
	}
	w.prev = len(w.out)
	hdr := []byte{PayloadNone, 0, 0, 0}
	binary.BigEndian.PutUint16(hdr[2:], uint16(4+len(body)))
	w.out = append(w.out, hdr...)
	w.out = append(w.out, body...)
}

func (w *payloadWriter) finish() []byte {
	binary.BigEndian.PutUint32(w.out[24:28], uint32(len(w.out)))
	return w.out
}

func newMessage(spii, spir [8]byte, exchange, flags byte, msgID uint32) *payloadWriter {
	out := make([]byte, HeaderLen, 640)
	copy(out[0:8], spii[:])
	copy(out[8:16], spir[:])
	out[16] = PayloadNone
	out[17] = Version
	out[18] = exchange
	out[19] = flags
	binary.BigEndian.PutUint32(out[20:24], msgID)
	return &payloadWriter{out: out, prev: -1}
}

// saProposal is one IKE proposal: AES-CBC-256, HMAC-SHA2-256 PRF and
// integrity, Curve25519. This is what a current strongSwan/libreswan client
// leads with.
func saProposal() []byte {
	transform := func(more byte, typ byte, id uint16, keyLen uint16) []byte {
		t := []byte{more, 0, 0, 8, typ, 0, 0, 0}
		binary.BigEndian.PutUint16(t[6:], id)
		if keyLen != 0 {
			attr := []byte{0x80, 14, 0, 0}
			binary.BigEndian.PutUint16(attr[2:], keyLen)
			t = append(t, attr...)
			binary.BigEndian.PutUint16(t[2:], uint16(len(t)))
		}
		return t
	}
	var ts []byte
	ts = append(ts, transform(3, 1, 12, 256)...) // ENCR_AES_CBC 256
	ts = append(ts, transform(3, 2, 5, 0)...)    // PRF_HMAC_SHA2_256
	ts = append(ts, transform(3, 3, 12, 0)...)   // AUTH_HMAC_SHA2_256_128
	ts = append(ts, transform(0, 4, DHGroupCurve25519, 0)...)
	prop := []byte{0, 0, 0, 0, 1, 1, 0, 4} // last proposal, len, #1, IKE, SPI size 0, 4 transforms
	binary.BigEndian.PutUint16(prop[2:], uint16(8+len(ts)))
	return append(prop, ts...)
}

func kePayload(pub [32]byte) []byte {
	b := make([]byte, 4, 36)
	binary.BigEndian.PutUint16(b[0:], DHGroupCurve25519)
	return append(b, pub[:]...)
}

func notify(typ uint16, data []byte) []byte {
	b := []byte{0, 0, 0, 0} // protocol 0, SPI size 0, type
	binary.BigEndian.PutUint16(b[2:], typ)
	return append(b, data...)
}

// SAInit builds an IKE_SA_INIT request: SA, KE (Curve25519 public key),
// Ni, NAT detection notifies and a vendor ID.
func SAInit(spii [8]byte, kePub [32]byte) []byte {
	m := newMessage(spii, [8]byte{}, ExchangeSAInit, FlagInitiator, 0)
	m.add(PayloadSA, saProposal())
	m.add(PayloadKE, kePayload(kePub))
	m.add(PayloadNonce, randBytes(NonceLen))
	m.add(PayloadNotify, notify(NotifyNATDetectionSource, randBytes(NATDetectionLen)))
	m.add(PayloadNotify, notify(NotifyNATDetectionDest, randBytes(NATDetectionLen)))
	m.add(PayloadVendor, randBytes(16))
	return m.finish()
}

// SAInitResponse answers a request: the same proposal, KEr, Nr and the NAT
// detection notifies. Without the vendor ID it is always shorter than the
// request.
func SAInitResponse(req Header, spir [8]byte, kePub [32]byte) []byte {
	m := newMessage(req.SPIi, spir, ExchangeSAInit, FlagResponse, 0)
	m.add(PayloadSA, saProposal())
	m.add(PayloadKE, kePayload(kePub))
	m.add(PayloadNonce, randBytes(NonceLen))
	m.add(PayloadNotify, notify(NotifyNATDetectionSource, randBytes(NATDetectionLen)))
	m.add(PayloadNotify, notify(NotifyNATDetectionDest, randBytes(NATDetectionLen)))
	return m.finish()
}

// Auth builds an IKE_AUTH request: one Encrypted (SK) payload of the given
// inner size (IV + ciphertext + ICV shape).
func Auth(spii, spir [8]byte, msgID uint32, innerLen int, response bool) []byte {
	flags := byte(FlagInitiator)
	if response {
		flags = FlagResponse
	}
	m := newMessage(spii, spir, ExchangeAuth, flags, msgID)
	if innerLen < 32 {
		innerLen = 32
	}
	m.add(PayloadSK, randBytes(innerLen))
	return m.finish()
}

// ESPSPIFor derives the ESP SPI a session uses from the responder SPI, so
// that both ends agree without a CHILD_SA negotiation.
func ESPSPIFor(spir [8]byte) uint32 {
	spi := binary.BigEndian.Uint32(spir[0:4])
	if spi == 0 {
		spi = 0x0badcafe
	}
	return spi
}
