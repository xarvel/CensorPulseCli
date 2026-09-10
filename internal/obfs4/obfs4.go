// Package obfs4 builds the wire shape of the obfs4 (lyrebird) handshake: a
// client request of random-looking bytes carrying an HMAC mark keyed by the
// bridge's node id and identity key, padded to a random length, and the
// matching server response. The probe does not run the ntor key exchange:
// the representative and the AUTH tag are random bytes, which is exactly what
// they look like on the wire (an Elligator 2 representative is uniform by
// construction). What can be tested is whether a flow of this shape and size
// reaches the server and is answered; nothing after the handshake is real
// obfs4 traffic, the server just mirrors framed random bytes.
package obfs4

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	mrand "math/rand"
	"strconv"
	"time"
)

// Constants from obfs4-spec.txt.
const (
	NodeIDLen         = 20
	KeyLen            = 32
	MarkLen           = 16
	MACLen            = 16
	AuthLen           = 32
	MaxHandshakeLen   = 8192
	clientMinPad      = 85
	clientMaxPad      = 8128
	serverMinPad      = 0
	serverMaxPad      = 8096
	clientHandshakeNP = KeyLen + MarkLen + MACLen           // 64
	serverHandshakeNP = KeyLen + AuthLen + MarkLen + MACLen // 96
	// MaxFrame is the largest data-phase frame (2-byte length + secretbox).
	MaxFrame = 1448
)

// Identity is the public half a bridge distributes in its "cert=" line:
// node id followed by the Curve25519 identity public key.
type Identity struct {
	NodeID [NodeIDLen]byte
	Public [KeyLen]byte
}

// ParseIdentity decodes the 52 raw bytes of a bridge cert.
func ParseIdentity(raw []byte) (Identity, error) {
	var id Identity
	if len(raw) != NodeIDLen+KeyLen {
		return id, errors.New("obfs4: identity must be 52 bytes")
	}
	copy(id.NodeID[:], raw[:NodeIDLen])
	copy(id.Public[:], raw[NodeIDLen:])
	return id, nil
}

// Bytes is the inverse of ParseIdentity.
func (id Identity) Bytes() []byte {
	return append(append([]byte(nil), id.NodeID[:]...), id.Public[:]...)
}

func (id Identity) key() []byte { return append(append([]byte(nil), id.Public[:]...), id.NodeID[:]...) }

func mac128(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)[:MarkLen]
}

// EpochHour is the E value of the handshake: hours since the Unix epoch as
// a decimal string.
func EpochHour(t time.Time) string { return strconv.FormatInt(t.Unix()/3600, 10) }

// ClientRequest builds X' | P_C | M_C | MAC_C with a random representative
// and random padding of realistic length.
func ClientRequest(id Identity, now time.Time) []byte {
	repr := make([]byte, KeyLen)
	rand.Read(repr)
	pad := make([]byte, clientMinPad+mrand.Intn(clientMaxPad-clientMinPad+1))
	rand.Read(pad)
	k := id.key()
	mark := mac128(k, repr)
	req := append(append(append([]byte(nil), repr...), pad...), mark...)
	req = append(req, mac128(k, append(append([]byte(nil), req...), EpochHour(now)...))...)
	return req
}

// FindClientRequest scans buf for a complete client request under id and
// returns its length. It accepts E-1, E and E+1 like a real server. n == 0
// when no request is found; more bytes may still arrive.
func FindClientRequest(buf []byte, id Identity, now time.Time) (n int, ok bool) {
	if len(buf) < clientHandshakeNP+clientMinPad {
		return 0, false
	}
	k := id.key()
	mark := mac128(k, buf[:KeyLen])
	return findMark(buf, k, mark, KeyLen+clientMinPad, now)
}

// ServerResponse builds Y' | AUTH | P_S | M_S | MAC_S. The padding is bounded
// by maxLen so that the answer never exceeds the request it answers.
func ServerResponse(id Identity, now time.Time, maxLen int) []byte {
	repr := make([]byte, KeyLen)
	rand.Read(repr)
	auth := make([]byte, AuthLen)
	rand.Read(auth)
	padMax := serverMaxPad
	if lim := maxLen - serverHandshakeNP; lim < padMax {
		padMax = lim
	}
	if padMax < serverMinPad {
		padMax = serverMinPad
	}
	pad := make([]byte, serverMinPad+mrand.Intn(padMax-serverMinPad+1))
	rand.Read(pad)
	k := id.key()
	mark := mac128(k, repr)
	resp := append(append(append(append([]byte(nil), repr...), auth...), pad...), mark...)
	resp = append(resp, mac128(k, append(append([]byte(nil), resp...), EpochHour(now)...))...)
	return resp
}

// FindServerResponse is the client-side counterpart of FindClientRequest.
func FindServerResponse(buf []byte, id Identity, now time.Time) (n int, ok bool) {
	if len(buf) < serverHandshakeNP {
		return 0, false
	}
	k := id.key()
	mark := mac128(k, buf[:KeyLen])
	return findMark(buf, k, mark, KeyLen+AuthLen, now)
}

func findMark(buf, k, mark []byte, from int, now time.Time) (int, bool) {
	limit := len(buf) - MarkLen - MACLen
	if limit > MaxHandshakeLen-MarkLen-MACLen {
		limit = MaxHandshakeLen - MarkLen - MACLen
	}
	for i := from; i <= limit; i++ {
		if !hmac.Equal(buf[i:i+MarkLen], mark) {
			continue
		}
		end := i + MarkLen
		for _, dh := range []int64{0, -1, 1} {
			e := strconv.FormatInt(now.Unix()/3600+dh, 10)
			want := mac128(k, append(append([]byte(nil), buf[:end]...), e...))
			if hmac.Equal(buf[end:end+MACLen], want) {
				return end + MACLen, true
			}
		}
	}
	return 0, false
}

// Frame is a data-phase frame shape: an "obfuscated" 2-byte length followed
// by n bytes that stand in for the NaCl secretbox. Everything is random; the
// receiver mirrors it, it does not decrypt it.
func Frame(n int) []byte {
	if n > MaxFrame {
		n = MaxFrame
	}
	if n < 32 {
		n = 32
	}
	b := make([]byte, 2+n)
	rand.Read(b)
	binary.BigEndian.PutUint16(b, uint16(n)^binary.BigEndian.Uint16(b[2:4]))
	return b
}
