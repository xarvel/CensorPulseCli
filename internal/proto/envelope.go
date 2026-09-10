// Package proto implements the CensorPulse Probe Protocol v1 wire pieces that
// are shared by the client and the server: the CP1 test envelope, the session
// token and the UDP address-validation cookie.
//
// The envelope is what the client sends inside "our own" transports (raw TCP,
// UDP, inside a TLS session, as an HTTP body, ...). It carries enough identity
// to let the server correlate the flow with a session and a test without any
// state on the wire beyond the session key exchanged over the control plane.
//
// Request layout (big endian):
//
//	0..2   magic "CP1"
//	3      version (1)
//	4      kind (1 = request, 2 = reply)
//	5      flags (bit0: cookie present)
//	6..21  session_id (16 bytes)
//	22     test_id length
//	..     test_id (ASCII)
//	..     nonce (12 bytes)
//	..     seq (uint32)
//	..     cookie (16 bytes, only if flag bit0)
//	..     payload length (uint16)
//	..     payload
//	..     mac: HMAC-SHA256(session_key, everything above)[:16]
//
// Reply layout:
//
//	"CP1", version, kind=2, flags=0, session_id, test_id, nonce, seq,
//	recv_len (uint16), payload_sha256 (32 bytes),
//	seen_at (int64 unix nanos), replied_at (int64 unix nanos), mac[16]
package proto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	Magic       = "CP1"
	Version     = 1
	KindRequest = 1
	KindReply   = 2

	flagCookie = 0x01

	SessionIDLen = 16
	NonceLen     = 12
	CookieLen    = 16
	MACLen       = 16

	// MaxPayload bounds a single envelope payload. UDP tests must stay below
	// a conservative MTU; TCP tests may use the full range.
	MaxPayload = 8192
	// MaxUDPPayload keeps UDP envelopes under 1200 bytes total.
	MaxUDPPayload = 1000
)

var (
	ErrNotEnvelope = errors.New("proto: not a CP1 envelope")
	ErrBadMAC      = errors.New("proto: envelope MAC mismatch")
	ErrTruncated   = errors.New("proto: truncated envelope")
)

// Request is a decoded client envelope.
type Request struct {
	SessionID [SessionIDLen]byte
	TestID    string
	Nonce     [NonceLen]byte
	Seq       uint32
	Cookie    []byte // nil when absent
	Payload   []byte
	// Raw holds the exact bytes that were parsed (used for hashing).
	Raw []byte
}

// Reply is a decoded server envelope.
type Reply struct {
	SessionID     [SessionIDLen]byte
	TestID        string
	Nonce         [NonceLen]byte
	Seq           uint32
	RecvLen       uint16
	PayloadSHA256 [32]byte
	SeenAt        time.Time
	RepliedAt     time.Time
}

// NewNonce returns a fresh random nonce.
func NewNonce() (n [NonceLen]byte) {
	if _, err := rand.Read(n[:]); err != nil {
		panic(err)
	}
	return n
}

// RandomPayload returns n random bytes (used both as envelope payload and as
// the "random bytes" negative control).
func RandomPayload(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// IsEnvelope reports whether b starts like a CP1 envelope.
func IsEnvelope(b []byte) bool {
	return len(b) >= 6 && bytes.HasPrefix(b, []byte(Magic)) && b[3] == Version
}

// EncodeRequest serialises a request and appends its MAC.
func EncodeRequest(r *Request, key []byte) ([]byte, error) {
	if len(r.TestID) == 0 || len(r.TestID) > 255 {
		return nil, fmt.Errorf("proto: bad test id length %d", len(r.TestID))
	}
	if len(r.Payload) > MaxPayload {
		return nil, fmt.Errorf("proto: payload too large: %d", len(r.Payload))
	}
	if r.Cookie != nil && len(r.Cookie) != CookieLen {
		return nil, fmt.Errorf("proto: bad cookie length %d", len(r.Cookie))
	}
	var flags byte
	if r.Cookie != nil {
		flags |= flagCookie
	}
	buf := make([]byte, 0, 64+len(r.TestID)+len(r.Payload))
	buf = append(buf, Magic...)
	buf = append(buf, Version, KindRequest, flags)
	buf = append(buf, r.SessionID[:]...)
	buf = append(buf, byte(len(r.TestID)))
	buf = append(buf, r.TestID...)
	buf = append(buf, r.Nonce[:]...)
	buf = binary.BigEndian.AppendUint32(buf, r.Seq)
	if r.Cookie != nil {
		buf = append(buf, r.Cookie...)
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(r.Payload)))
	buf = append(buf, r.Payload...)
	buf = append(buf, mac(key, buf)...)
	return buf, nil
}

// RequestHeaderLen returns the minimum number of bytes needed to know the full
// length of a request envelope starting with b, or 0 if b is too short.
// It returns the total envelope length once enough bytes are available.
func RequestLen(b []byte) (total int, need int) {
	// fixed prefix up to test_id length byte
	if len(b) < 23 {
		return 0, 23
	}
	tl := int(b[22])
	off := 23 + tl + NonceLen + 4
	if b[5]&flagCookie != 0 {
		off += CookieLen
	}
	if len(b) < off+2 {
		return 0, off + 2
	}
	pl := int(binary.BigEndian.Uint16(b[off:]))
	total = off + 2 + pl + MACLen
	if len(b) < total {
		return 0, total
	}
	return total, total
}

// PeekRequest reads whatever identity a truncated request already carries:
// the session id (from 22 bytes on), the test id and the nonce (once they are
// complete). It lets the server attribute a flow that was cut before the
// whole envelope arrived (small-packet tests) without trusting it: the MAC
// was never checked, so the caller must mark the observation as partial.
func PeekRequest(b []byte) (sid [SessionIDLen]byte, testID string, nonce [NonceLen]byte, have int) {
	if !IsEnvelope(b) || b[4] != KindRequest || len(b) < 22 {
		return sid, "", nonce, 0
	}
	copy(sid[:], b[6:22])
	have = 1
	if len(b) < 23 {
		return
	}
	tl := int(b[22])
	if len(b) < 23+tl {
		return
	}
	testID = string(b[23 : 23+tl])
	have = 2
	if len(b) < 23+tl+NonceLen {
		return
	}
	copy(nonce[:], b[23+tl:23+tl+NonceLen])
	have = 3
	return
}

// DecodeRequest parses a request. verify is called with the session id and
// must return the session key (or nil if the session is unknown). When the
// key is unknown the request is still returned together with ErrBadMAC so the
// server can record an observation for it.
func DecodeRequest(b []byte, keyFor func(sid [SessionIDLen]byte) []byte) (*Request, error) {
	if !IsEnvelope(b) || b[4] != KindRequest {
		return nil, ErrNotEnvelope
	}
	total, _ := RequestLen(b)
	if total == 0 {
		return nil, ErrTruncated
	}
	b = b[:total]
	r := &Request{Raw: b}
	flags := b[5]
	copy(r.SessionID[:], b[6:22])
	tl := int(b[22])
	off := 23
	r.TestID = string(b[off : off+tl])
	off += tl
	copy(r.Nonce[:], b[off:off+NonceLen])
	off += NonceLen
	r.Seq = binary.BigEndian.Uint32(b[off:])
	off += 4
	if flags&flagCookie != 0 {
		r.Cookie = append([]byte(nil), b[off:off+CookieLen]...)
		off += CookieLen
	}
	pl := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	r.Payload = append([]byte(nil), b[off:off+pl]...)
	off += pl
	key := keyFor(r.SessionID)
	if key == nil || !hmac.Equal(b[off:off+MACLen], mac(key, b[:off])) {
		return r, ErrBadMAC
	}
	return r, nil
}

// EncodeReply serialises the server reply for req.
func EncodeReply(req *Request, seenAt, repliedAt time.Time, key []byte) []byte {
	sum := sha256.Sum256(req.Payload)
	buf := make([]byte, 0, 128+len(req.TestID))
	buf = append(buf, Magic...)
	buf = append(buf, Version, KindReply, 0)
	buf = append(buf, req.SessionID[:]...)
	buf = append(buf, byte(len(req.TestID)))
	buf = append(buf, req.TestID...)
	buf = append(buf, req.Nonce[:]...)
	buf = binary.BigEndian.AppendUint32(buf, req.Seq)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(req.Payload)))
	buf = append(buf, sum[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(seenAt.UnixNano()))
	buf = binary.BigEndian.AppendUint64(buf, uint64(repliedAt.UnixNano()))
	buf = append(buf, mac(key, buf)...)
	return buf
}

// ReplyLen mirrors RequestLen for replies.
func ReplyLen(b []byte) (total int, need int) {
	if len(b) < 23 {
		return 0, 23
	}
	tl := int(b[22])
	total = 23 + tl + NonceLen + 4 + 2 + 32 + 8 + 8 + MACLen
	if len(b) < total {
		return 0, total
	}
	return total, total
}

// DecodeReply parses and authenticates a reply with the session key.
func DecodeReply(b []byte, key []byte) (*Reply, error) {
	if !IsEnvelope(b) || b[4] != KindReply {
		return nil, ErrNotEnvelope
	}
	total, _ := ReplyLen(b)
	if total == 0 {
		return nil, ErrTruncated
	}
	b = b[:total]
	r := &Reply{}
	copy(r.SessionID[:], b[6:22])
	tl := int(b[22])
	off := 23
	r.TestID = string(b[off : off+tl])
	off += tl
	copy(r.Nonce[:], b[off:off+NonceLen])
	off += NonceLen
	r.Seq = binary.BigEndian.Uint32(b[off:])
	off += 4
	r.RecvLen = binary.BigEndian.Uint16(b[off:])
	off += 2
	copy(r.PayloadSHA256[:], b[off:off+32])
	off += 32
	r.SeenAt = time.Unix(0, int64(binary.BigEndian.Uint64(b[off:])))
	off += 8
	r.RepliedAt = time.Unix(0, int64(binary.BigEndian.Uint64(b[off:])))
	off += 8
	if !hmac.Equal(b[off:off+MACLen], mac(key, b[:off])) {
		return r, ErrBadMAC
	}
	return r, nil
}

func mac(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)[:MACLen]
}
