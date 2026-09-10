// Package wg implements just enough of the WireGuard Noise_IKpsk2 handshake to
// send a valid, authenticated handshake initiation (148 bytes), to answer it
// with a valid handshake response (92 bytes), and to derive the transport keys
// so that both sides can exchange a bounded number of authenticated transport
// data packets (type 4). The data packets carry probe padding, never IP
// traffic: the probe proves that a WireGuard flow survives past the handshake,
// which is where session-aware blocking (handshake passes, data does not) shows.
//
// Reference: https://www.wireguard.com/protocol/
package wg

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	MessageInitiationType = 1
	MessageResponseType   = 2
	MessageTransportType  = 4
	InitiationSize        = 148
	ResponseSize          = 92
	TransportHeaderSize   = 16 // type(1) reserved(3) receiver(4) counter(8)
	TransportOverhead     = TransportHeaderSize + 16
	MaxTransportPlaintext = 1400

	construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	identifier   = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	labelMAC1    = "mac1----"
)

var (
	initialChainKey [32]byte
	initialHash     [32]byte
)

func init() {
	initialChainKey = blake2s.Sum256([]byte(construction))
	initialHash = mixHash(initialChainKey, []byte(identifier))
}

var ErrBadMessage = errors.New("wg: malformed or unauthenticated message")

// KeyPair is a Curve25519 static or ephemeral key pair.
type KeyPair struct {
	Private [32]byte
	Public  [32]byte
}

// NewKeyPair generates a random key pair.
func NewKeyPair() (KeyPair, error) {
	var kp KeyPair
	if _, err := rand.Read(kp.Private[:]); err != nil {
		return kp, err
	}
	kp.Private[0] &= 248
	kp.Private[31] = (kp.Private[31] & 127) | 64
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return kp, err
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

// KeyPairFromPrivate derives the public key from a private key.
func KeyPairFromPrivate(priv [32]byte) (KeyPair, error) {
	kp := KeyPair{Private: priv}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return kp, err
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

// InitiatorState is what the initiator keeps between sending the initiation
// and consuming the response.
type InitiatorState struct {
	chainKey  [32]byte
	hash      [32]byte
	ephemeral KeyPair
	static    KeyPair
	SenderIdx uint32

	// Filled by ConsumeResponse.
	PeerIdx uint32 // the responder's sender index: receiver index of our transport packets
	keys    TransportKeys
	ready   bool
}

// TransportKeys are the symmetric keys derived at the end of the handshake.
type TransportKeys struct {
	Send [32]byte
	Recv [32]byte
}

// Keys returns the transport keys once ConsumeResponse succeeded.
func (st *InitiatorState) Keys() (TransportKeys, bool) { return st.keys, st.ready }

// CreateInitiation builds a handshake initiation addressed to serverPub.
func CreateInitiation(static KeyPair, serverPub [32]byte, psk [32]byte) (*InitiatorState, []byte, error) {
	eph, err := NewKeyPair()
	if err != nil {
		return nil, nil, err
	}
	st := &InitiatorState{static: static, ephemeral: eph}
	if err := binary.Read(rand.Reader, binary.LittleEndian, &st.SenderIdx); err != nil {
		return nil, nil, err
	}
	st.chainKey = initialChainKey
	st.hash = mixHash(initialHash, serverPub[:])

	msg := make([]byte, InitiationSize)
	msg[0] = MessageInitiationType
	binary.LittleEndian.PutUint32(msg[4:8], st.SenderIdx)
	copy(msg[8:40], eph.Public[:])
	st.chainKey = kdf1(st.chainKey, eph.Public[:])
	st.hash = mixHash(st.hash, eph.Public[:])

	ss, err := curve25519.X25519(eph.Private[:], serverPub[:])
	if err != nil {
		return nil, nil, err
	}
	var key [32]byte
	st.chainKey, key = kdf2(st.chainKey, ss)
	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg[40:40], zeroNonce(), static.Public[:], st.hash[:])
	st.hash = mixHash(st.hash, msg[40:88])

	ss, err = curve25519.X25519(static.Private[:], serverPub[:])
	if err != nil {
		return nil, nil, err
	}
	st.chainKey, key = kdf2(st.chainKey, ss)
	aead, _ = chacha20poly1305.New(key[:])
	ts := tai64n(time.Now())
	aead.Seal(msg[88:88], zeroNonce(), ts[:], st.hash[:])
	st.hash = mixHash(st.hash, msg[88:116])

	macKey := blake2s.Sum256(append([]byte(labelMAC1), serverPub[:]...))
	m, _ := blake2s.New128(macKey[:])
	m.Write(msg[:116])
	copy(msg[116:132], m.Sum(nil))
	// mac2 stays zero: no cookie reply in play.
	return st, msg, nil
}

// ConsumeResponse validates a handshake response for st. psk must match the
// responder's (all-zero when unused).
func (st *InitiatorState) ConsumeResponse(msg []byte, psk [32]byte) error {
	if len(msg) != ResponseSize || msg[0] != MessageResponseType {
		return ErrBadMessage
	}
	if binary.LittleEndian.Uint32(msg[8:12]) != st.SenderIdx {
		return ErrBadMessage
	}
	var respEph [32]byte
	copy(respEph[:], msg[12:44])
	chain := kdf1(st.chainKey, respEph[:])
	h := mixHash(st.hash, respEph[:])
	ss, err := curve25519.X25519(st.ephemeral.Private[:], respEph[:])
	if err != nil {
		return err
	}
	chain = kdf1(chain, ss)
	ss, err = curve25519.X25519(st.static.Private[:], respEph[:])
	if err != nil {
		return err
	}
	chain = kdf1(chain, ss)
	var tau, key [32]byte
	chain, tau, key = kdf3(chain, psk[:])
	h = mixHash(h, tau[:])
	aead, _ := chacha20poly1305.New(key[:])
	if _, err := aead.Open(nil, zeroNonce(), msg[44:60], h[:]); err != nil {
		return ErrBadMessage
	}
	st.PeerIdx = binary.LittleEndian.Uint32(msg[4:8])
	// Transport keys: initiator sends with T1, receives with T2.
	st.keys.Send, st.keys.Recv = kdf2(chain, nil)
	st.ready = true
	return nil
}

// InitiationInfo is what a responder learns from a valid initiation.
type InitiationInfo struct {
	SenderIdx    uint32
	PeerStatic   [32]byte
	Timestamp    [12]byte
	MAC1Valid    bool
	StaticValid  bool
	TimestampOK  bool
	responseHash [32]byte
	chainKey     [32]byte
	ephemeral    [32]byte
}

// CheckMAC1 verifies only the outer mac1 (cheap, no DH) for the given static
// public key.
func CheckMAC1(msg []byte, serverPub [32]byte) bool {
	if len(msg) != InitiationSize || msg[0] != MessageInitiationType {
		return false
	}
	macKey := blake2s.Sum256(append([]byte(labelMAC1), serverPub[:]...))
	m, _ := blake2s.New128(macKey[:])
	m.Write(msg[:116])
	return hmac.Equal(m.Sum(nil), msg[116:132])
}

// ConsumeInitiation validates an initiation against the responder's static
// key. It accepts any initiator static key (the probe has no peer list): the
// property being proven is cryptographic integrity of the handshake in
// transit, not authorisation.
func ConsumeInitiation(msg []byte, server KeyPair) (*InitiationInfo, error) {
	if len(msg) != InitiationSize || msg[0] != MessageInitiationType {
		return nil, ErrBadMessage
	}
	info := &InitiationInfo{SenderIdx: binary.LittleEndian.Uint32(msg[4:8])}
	info.MAC1Valid = CheckMAC1(msg, server.Public)
	if !info.MAC1Valid {
		return info, ErrBadMessage
	}
	chain := initialChainKey
	h := mixHash(initialHash, server.Public[:])
	copy(info.ephemeral[:], msg[8:40])
	chain = kdf1(chain, info.ephemeral[:])
	h = mixHash(h, info.ephemeral[:])
	ss, err := curve25519.X25519(server.Private[:], info.ephemeral[:])
	if err != nil {
		return info, err
	}
	var key [32]byte
	chain, key = kdf2(chain, ss)
	aead, _ := chacha20poly1305.New(key[:])
	staticPlain, err := aead.Open(nil, zeroNonce(), msg[40:88], h[:])
	if err != nil {
		return info, ErrBadMessage
	}
	copy(info.PeerStatic[:], staticPlain)
	info.StaticValid = true
	h = mixHash(h, msg[40:88])
	ss, err = curve25519.X25519(server.Private[:], info.PeerStatic[:])
	if err != nil {
		return info, err
	}
	chain, key = kdf2(chain, ss)
	aead, _ = chacha20poly1305.New(key[:])
	tsPlain, err := aead.Open(nil, zeroNonce(), msg[88:116], h[:])
	if err != nil {
		return info, ErrBadMessage
	}
	copy(info.Timestamp[:], tsPlain)
	info.TimestampOK = true
	h = mixHash(h, msg[88:116])
	info.responseHash = h
	info.chainKey = chain
	return info, nil
}

// ResponderSession is what the responder keeps after answering an initiation:
// its own index (the receiver index the initiator will put on transport
// packets), the initiator's index, and the transport keys.
type ResponderSession struct {
	LocalIdx uint32
	PeerIdx  uint32
	Keys     TransportKeys
}

// CreateResponse builds the 92-byte handshake response for a consumed
// initiation and returns the responder-side session state.
func CreateResponse(info *InitiationInfo, server KeyPair, psk [32]byte) ([]byte, *ResponderSession, error) {
	eph, err := NewKeyPair()
	if err != nil {
		return nil, nil, err
	}
	var idx uint32
	if err := binary.Read(rand.Reader, binary.LittleEndian, &idx); err != nil {
		return nil, nil, err
	}
	msg := make([]byte, ResponseSize)
	msg[0] = MessageResponseType
	binary.LittleEndian.PutUint32(msg[4:8], idx)
	binary.LittleEndian.PutUint32(msg[8:12], info.SenderIdx)
	copy(msg[12:44], eph.Public[:])
	chain := kdf1(info.chainKey, eph.Public[:])
	h := mixHash(info.responseHash, eph.Public[:])
	ss, err := curve25519.X25519(eph.Private[:], info.ephemeral[:])
	if err != nil {
		return nil, nil, err
	}
	chain = kdf1(chain, ss)
	ss, err = curve25519.X25519(eph.Private[:], info.PeerStatic[:])
	if err != nil {
		return nil, nil, err
	}
	chain = kdf1(chain, ss)
	var tau, key [32]byte
	chain, tau, key = kdf3(chain, psk[:])
	h = mixHash(h, tau[:])
	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg[44:44], zeroNonce(), nil, h[:])
	macKey := blake2s.Sum256(append([]byte(labelMAC1), info.PeerStatic[:]...))
	m, _ := blake2s.New128(macKey[:])
	m.Write(msg[:60])
	copy(msg[60:76], m.Sum(nil))
	sess := &ResponderSession{LocalIdx: idx, PeerIdx: info.SenderIdx}
	// Responder receives with T1 (the initiator's send key) and sends with T2.
	sess.Keys.Recv, sess.Keys.Send = kdf2(chain, nil)
	return msg, sess, nil
}

// LooksLikeInitiation is a cheap shape check used by the UDP demuxer.
func LooksLikeInitiation(b []byte) bool {
	return len(b) == InitiationSize && b[0] == MessageInitiationType && b[1] == 0 && b[2] == 0 && b[3] == 0
}

// LooksLikeTransport is the shape check for a transport data packet.
func LooksLikeTransport(b []byte) bool {
	return len(b) >= TransportOverhead && b[0] == MessageTransportType && b[1] == 0 && b[2] == 0 && b[3] == 0
}

// TransportReceiver returns the receiver index of a transport packet.
func TransportReceiver(b []byte) uint32 { return binary.LittleEndian.Uint32(b[4:8]) }

// SealTransport builds a transport data packet. The plaintext is zero-padded
// to a multiple of 16 bytes exactly like a real WireGuard peer does.
func SealTransport(key [32]byte, receiver uint32, counter uint64, plaintext []byte) []byte {
	padded := len(plaintext)
	if r := padded % 16; r != 0 {
		padded += 16 - r
	}
	buf := make([]byte, padded)
	copy(buf, plaintext)
	out := make([]byte, TransportHeaderSize, TransportHeaderSize+padded+16)
	out[0] = MessageTransportType
	binary.LittleEndian.PutUint32(out[4:8], receiver)
	binary.LittleEndian.PutUint64(out[8:16], counter)
	aead, _ := chacha20poly1305.New(key[:])
	return aead.Seal(out, transportNonce(counter), buf, nil)
}

// OpenTransport authenticates and decrypts a transport data packet, returning
// its counter and the (padded) plaintext.
func OpenTransport(key [32]byte, b []byte) (uint64, []byte, error) {
	if !LooksLikeTransport(b) {
		return 0, nil, ErrBadMessage
	}
	counter := binary.LittleEndian.Uint64(b[8:16])
	aead, _ := chacha20poly1305.New(key[:])
	plain, err := aead.Open(nil, transportNonce(counter), b[TransportHeaderSize:], nil)
	if err != nil {
		return counter, nil, ErrBadMessage
	}
	return counter, plain, nil
}

func transportNonce(counter uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.LittleEndian.PutUint64(n[4:], counter)
	return n
}

// --- primitives ---

func newBlake() hash.Hash {
	h, _ := blake2s.New256(nil)
	return h
}

func hmac1(key, in []byte) [32]byte {
	m := hmac.New(newBlake, key)
	m.Write(in)
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

func kdf1(key [32]byte, input []byte) [32]byte {
	t0 := hmac1(key[:], input)
	return hmac1(t0[:], []byte{0x1})
}

func kdf2(key [32]byte, input []byte) (t1, t2 [32]byte) {
	t0 := hmac1(key[:], input)
	t1 = hmac1(t0[:], []byte{0x1})
	t2 = hmac1(t0[:], append(append([]byte{}, t1[:]...), 0x2))
	return
}

func kdf3(key [32]byte, input []byte) (t1, t2, t3 [32]byte) {
	t0 := hmac1(key[:], input)
	t1 = hmac1(t0[:], []byte{0x1})
	t2 = hmac1(t0[:], append(append([]byte{}, t1[:]...), 0x2))
	t3 = hmac1(t0[:], append(append([]byte{}, t2[:]...), 0x3))
	return
}

func mixHash(h [32]byte, data []byte) [32]byte {
	x, _ := blake2s.New256(nil)
	x.Write(h[:])
	x.Write(data)
	var out [32]byte
	copy(out[:], x.Sum(nil))
	return out
}

func zeroNonce() []byte { return make([]byte, chacha20poly1305.NonceSize) }

func tai64n(t time.Time) [12]byte {
	var out [12]byte
	binary.BigEndian.PutUint64(out[:8], uint64(t.Unix())+0x400000000000000a)
	binary.BigEndian.PutUint32(out[8:], uint32(t.Nanosecond()))
	return out
}
