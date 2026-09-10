package proto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"time"
)

// Session identity helpers. The server keeps session state in memory; the
// token and cookie exist so that the server can authenticate control-plane
// calls and UDP datagrams without trusting anything the client asserts.

// NewSessionID returns 128 random bits.
func NewSessionID() (id [SessionIDLen]byte) {
	if _, err := rand.Read(id[:]); err != nil {
		panic(err)
	}
	return id
}

// ParseSessionID decodes a hex session id.
func ParseSessionID(s string) (id [SessionIDLen]byte, err error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != SessionIDLen {
		return id, errors.New("proto: bad session id")
	}
	copy(id[:], b)
	return id, nil
}

// SessionKey derives the per-session envelope key from the server master key.
func SessionKey(master []byte, sid [SessionIDLen]byte) []byte {
	h := hmac.New(sha256.New, master)
	h.Write([]byte("cp1-session-key"))
	h.Write(sid[:])
	return h.Sum(nil)
}

// Token is an opaque bearer credential: session_id || expiry || mac.
func Token(master []byte, sid [SessionIDLen]byte, exp time.Time) string {
	buf := make([]byte, 0, SessionIDLen+8+MACLen)
	buf = append(buf, sid[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(exp.Unix()))
	h := hmac.New(sha256.New, master)
	h.Write([]byte("cp1-token"))
	h.Write(buf)
	buf = append(buf, h.Sum(nil)[:MACLen]...)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// VerifyToken checks a token and returns the session id and expiry.
func VerifyToken(master []byte, tok string, now time.Time) (sid [SessionIDLen]byte, exp time.Time, err error) {
	b, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(b) != SessionIDLen+8+MACLen {
		return sid, exp, errors.New("proto: malformed token")
	}
	h := hmac.New(sha256.New, master)
	h.Write([]byte("cp1-token"))
	h.Write(b[:SessionIDLen+8])
	if !hmac.Equal(h.Sum(nil)[:MACLen], b[SessionIDLen+8:]) {
		return sid, exp, errors.New("proto: token mac mismatch")
	}
	copy(sid[:], b[:SessionIDLen])
	exp = time.Unix(int64(binary.BigEndian.Uint64(b[SessionIDLen:])), 0)
	if now.After(exp) {
		return sid, exp, errors.New("proto: token expired")
	}
	return sid, exp, nil
}

// Cookie binds a session to the source address observed on the control plane.
// It is 16 bytes and must be present in every UDP envelope; the server
// recomputes it with the datagram's source IP and stays silent on mismatch,
// which makes the UDP listeners useless as reflectors.
func Cookie(master []byte, sid [SessionIDLen]byte, ip netip.Addr, exp time.Time) []byte {
	h := hmac.New(sha256.New, master)
	h.Write([]byte("cp1-udp-cookie"))
	h.Write(sid[:])
	ipb := ip.Unmap().AsSlice()
	h.Write(ipb)
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], uint64(exp.Unix()))
	h.Write(e[:])
	return h.Sum(nil)[:CookieLen]
}

// VerifyCookie is a constant-time comparison helper.
func VerifyCookie(master []byte, sid [SessionIDLen]byte, ip netip.Addr, exp time.Time, got []byte) bool {
	return len(got) == CookieLen && hmac.Equal(got, Cookie(master, sid, ip, exp))
}
