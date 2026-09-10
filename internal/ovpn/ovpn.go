// Package ovpn builds and recognises the packets of an OpenVPN TLS-mode flow
// as the probe replays it: P_CONTROL_HARD_RESET_CLIENT_V2 (opcode 7) from the
// client, P_CONTROL_HARD_RESET_SERVER_V2 (opcode 8) from the server, the
// P_ACK_V1 (5) / P_CONTROL_V1 (4) exchange that carries the TLS handshake,
// and the P_DATA_V2 (9) packets of the data channel that follow it.
//
// Two control-channel layouts are supported. The plain one carries no
// authentication. The tls-auth one is what most deployments use: every
// control packet carries an HMAC-SHA1 over its content plus a replay packet
// id and a timestamp, keyed from a static key both ends know. A path that
// keys on the reset's length or on the presence of the HMAC block behaves
// differently on the two, so the probe runs both as separate variants.
//
// The data channel is AES-256-GCM with the 4-byte packet id as the explicit
// part of the nonce, framed exactly like OpenVPN's P_DATA_V2 (opcode/key id,
// 24-bit peer id, packet id, ciphertext, 16-byte tag). The keys are not the
// result of a TLS handshake: both ends derive them from the control-plane
// session key and the reservation id (DeriveDataKeys), which is enough to
// authenticate echoes and to tell a modified reply from a dropped one.
package ovpn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

const (
	OpControlV1         = 4
	OpAckV1             = 5
	OpHardResetClientV2 = 7
	OpHardResetServerV2 = 8
	OpDataV2            = 9

	SIDLen    = 8
	HMACLen   = 20 // HMAC-SHA1
	ReplayLen = 8  // packet_id(4) + net_time(4), the tls-auth replay fields

	// Plain layout sizes.
	ClientResetLen = 14 // op(1) sid(8) ack_len=0(1) pid(4)
	ServerResetLen = 26 // op(1) sid(8) ack_len=1(1) ack_pid(4) remote_sid(8) pid(4)
	AckLen         = 22 // op(1) sid(8) ack_len=1(1) ack_pid(4) remote_sid(8)
	ControlHdrLen  = 14 // op(1) sid(8) ack_len=0(1) pid(4)
	// tls-auth layout sizes: the plain ones plus hmac(20) + replay(8).
	ClientResetLenTLSAuth = ClientResetLen + HMACLen + ReplayLen // 42
	ServerResetLenTLSAuth = ServerResetLen + HMACLen + ReplayLen // 54
	AckLenTLSAuth         = AckLen + HMACLen + ReplayLen         // 50
	ControlHdrLenTLSAuth  = ControlHdrLen + HMACLen + ReplayLen  // 42

	MaxControlLen = 1400
	MaxPacketLen  = 4096 // bound on one TCP frame

	// Data channel (P_DATA_V2, AEAD mode).
	DataHdrLen = 8  // op/keyid(1) peer_id(3) packet_id(4)
	DataTagLen = 16 // GCM tag
	DataKeyLen = 32 // AES-256

	// TLSAuthKeyLen is the size of the probe's tls-auth static key as
	// advertised in params. OpenVPN's file holds 256 bytes of which one
	// 64-byte block per direction is the HMAC key and only the first 20
	// bytes of it feed HMAC-SHA1; the probe hands out one 64-byte block and
	// slices two 20-byte keys from it (TLSAuthDirKeys).
	TLSAuthKeyLen = 64
)

var (
	ErrNotReset   = errors.New("ovpn: not a hard reset packet")
	ErrNotControl = errors.New("ovpn: not a control/ack packet")
	ErrNotData    = errors.New("ovpn: not a data packet")
	ErrBadHMAC    = errors.New("ovpn: tls-auth hmac mismatch")
	ErrBadTag     = errors.New("ovpn: data packet failed authentication")
	ErrShort      = errors.New("ovpn: packet truncated")
)

// PingMagic is the plaintext OpenVPN sends as a keepalive ping (ping.c). It
// is invisible under the cipher, but it makes the probe's first data packet
// the size a real client's first data packet has: 16 bytes of plaintext.
var PingMagic = []byte{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}

// Auth is the control-channel layout.
type Auth int

const (
	AuthNone Auth = iota // plain control channel
	AuthTLS              // tls-auth: HMAC-SHA1 + replay id + net time on every control packet
)

func (a Auth) String() string {
	if a == AuthTLS {
		return "tls-auth"
	}
	return "none"
}

// Opcode returns the opcode of a packet (0 for an empty one).
func Opcode(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	return int(b[0] >> 3)
}

// SessionOf returns the 8-byte session id carried by any control packet.
func SessionOf(b []byte) (sid [8]byte, ok bool) {
	if len(b) < 1+SIDLen {
		return sid, false
	}
	copy(sid[:], b[1:9])
	return sid, true
}

// IsControlOp reports whether op is a control-channel opcode.
func IsControlOp(op int) bool {
	return op == OpControlV1 || op == OpAckV1 || op == OpHardResetClientV2 || op == OpHardResetServerV2
}

// Packet is a parsed control-channel packet of either layout.
type Packet struct {
	Op        int
	KeyID     int
	SID       [8]byte
	Acks      []uint32
	RemoteSID [8]byte // valid when len(Acks) > 0
	PID       uint32  // message packet id; absent on P_ACK_V1
	Payload   []byte
	// tls-auth replay fields (zero on the plain layout).
	ReplayID uint32
	NetTime  uint32
}

// Layout builds and parses the control channel of one flow. SendKey
// authenticates the packets this side builds, RecvKey verifies the ones it
// parses (tls-auth only). The replay packet id starts at 1 and increments per
// packet built, like OpenVPN's.
type Layout struct {
	Auth    Auth
	SendKey []byte
	RecvKey []byte
	replay  uint32
	now     func() time.Time
}

// Plain returns the layout without tls-auth.
func Plain() *Layout { return &Layout{Auth: AuthNone} }

// TLSAuth returns a tls-auth layout with the given HMAC-SHA1 keys.
func TLSAuth(send, recv []byte) *Layout {
	return &Layout{Auth: AuthTLS, SendKey: send, RecvKey: recv, replay: 1, now: time.Now}
}

// TLSAuthDirKeys splits the probe's 64-byte static key into the two
// direction keys: bytes 0..20 authenticate client→server packets, bytes
// 32..52 server→client (the equivalent of key-direction 1 on the client and
// 0 on the server).
func TLSAuthDirKeys(static []byte) (c2s, s2c []byte, err error) {
	if len(static) != TLSAuthKeyLen {
		return nil, nil, errors.New("ovpn: tls-auth key must be 64 bytes")
	}
	return static[0:HMACLen], static[32 : 32+HMACLen], nil
}

// NewTLSAuthKey generates a fresh static key.
func NewTLSAuthKey() []byte {
	k := make([]byte, TLSAuthKeyLen)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}

// HdrLen is the size of a control packet of this layout with nAcks
// piggy-backed acks and no payload (message packet id included).
func (l *Layout) HdrLen(nAcks int) int {
	n := ControlHdrLen + 4*nAcks
	if nAcks > 0 {
		n += SIDLen
	}
	if l.Auth == AuthTLS {
		n += HMACLen + ReplayLen
	}
	return n
}

// Build serialises p. The tls-auth HMAC is computed over
// replay(8) | op/keyid(1) | sid(8) | ack_len.. | payload, i.e. the replay
// fields first and then the packet without the hmac field, and is placed on
// the wire between the session id and the replay fields (OpenVPN's
// swap_hmac layout).
func (l *Layout) Build(p *Packet) []byte {
	head := make([]byte, 0, 1+SIDLen)
	head = append(head, byte(p.Op<<3|p.KeyID&7))
	head = append(head, p.SID[:]...)
	body := make([]byte, 0, 1+4*len(p.Acks)+SIDLen+4+len(p.Payload))
	body = append(body, byte(len(p.Acks)))
	for _, a := range p.Acks {
		body = binary.BigEndian.AppendUint32(body, a)
	}
	if len(p.Acks) > 0 {
		body = append(body, p.RemoteSID[:]...)
	}
	if p.Op != OpAckV1 {
		body = binary.BigEndian.AppendUint32(body, p.PID)
		body = append(body, p.Payload...)
	}
	if l.Auth != AuthTLS {
		return append(head, body...)
	}
	var replay [ReplayLen]byte
	id := l.replay
	if id == 0 {
		id = 1
	}
	l.replay = id + 1
	now := time.Now
	if l.now != nil {
		now = l.now
	}
	binary.BigEndian.PutUint32(replay[0:4], id)
	binary.BigEndian.PutUint32(replay[4:8], uint32(now().Unix()))
	mac := hmac.New(sha1.New, l.SendKey)
	mac.Write(replay[:])
	mac.Write(head)
	mac.Write(body)
	out := make([]byte, 0, len(head)+HMACLen+ReplayLen+len(body))
	out = append(out, head...)
	out = mac.Sum(out)
	out = append(out, replay[:]...)
	return append(out, body...)
}

// Parse validates a control packet of this layout. With tls-auth and a
// RecvKey the HMAC is verified (ErrBadHMAC on mismatch); without a RecvKey
// the fields are only unpacked.
func (l *Layout) Parse(b []byte) (*Packet, error) {
	if len(b) < 1+SIDLen+1 || !IsControlOp(Opcode(b)) {
		return nil, ErrNotControl
	}
	p := &Packet{Op: Opcode(b), KeyID: int(b[0] & 7)}
	copy(p.SID[:], b[1:9])
	rest := b[9:]
	if l.Auth == AuthTLS {
		if len(rest) < HMACLen+ReplayLen+1 {
			return nil, ErrShort
		}
		tag := rest[:HMACLen]
		replay := rest[HMACLen : HMACLen+ReplayLen]
		rest = rest[HMACLen+ReplayLen:]
		if l.RecvKey != nil {
			mac := hmac.New(sha1.New, l.RecvKey)
			mac.Write(replay)
			mac.Write(b[:9])
			mac.Write(rest)
			if !hmac.Equal(mac.Sum(nil), tag) {
				return nil, ErrBadHMAC
			}
		}
		p.ReplayID = binary.BigEndian.Uint32(replay[0:4])
		p.NetTime = binary.BigEndian.Uint32(replay[4:8])
	}
	nAcks := int(rest[0])
	rest = rest[1:]
	need := 4 * nAcks
	if nAcks > 0 {
		need += SIDLen
	}
	if len(rest) < need {
		return nil, ErrShort
	}
	for i := 0; i < nAcks; i++ {
		p.Acks = append(p.Acks, binary.BigEndian.Uint32(rest[4*i:]))
	}
	rest = rest[4*nAcks:]
	if nAcks > 0 {
		copy(p.RemoteSID[:], rest[:SIDLen])
		rest = rest[SIDLen:]
	}
	if p.Op == OpAckV1 {
		if len(rest) != 0 {
			return nil, ErrNotControl
		}
		return p, nil
	}
	if len(rest) < 4 {
		return nil, ErrShort
	}
	p.PID = binary.BigEndian.Uint32(rest)
	p.Payload = rest[4:]
	return p, nil
}

// ClientReset builds a P_CONTROL_HARD_RESET_CLIENT_V2 with key_id 0 and a
// random session id (14 bytes plain, 42 with tls-auth).
func (l *Layout) ClientReset() (pkt []byte, sessionID [8]byte) {
	if _, err := rand.Read(sessionID[:]); err != nil {
		panic(err)
	}
	return l.Build(&Packet{Op: OpHardResetClientV2, SID: sessionID}), sessionID
}

// ServerReset builds the P_CONTROL_HARD_RESET_SERVER_V2 answering a client
// reset: it acks the client's packet 0 and carries a fresh server session id
// (26 bytes plain, 54 with tls-auth).
func (l *Layout) ServerReset(clientSession [8]byte) (pkt []byte, serverSession [8]byte) {
	if _, err := rand.Read(serverSession[:]); err != nil {
		panic(err)
	}
	return l.Build(&Packet{Op: OpHardResetServerV2, SID: serverSession, Acks: []uint32{0}, RemoteSID: clientSession}), serverSession
}

// ParseClientReset validates a client hard reset and returns its session id.
func (l *Layout) ParseClientReset(b []byte) (sessionID [8]byte, err error) {
	if a, ok := IsClientReset(b); !ok || a != l.Auth {
		return sessionID, ErrNotReset
	}
	p, err := l.Parse(b)
	if err != nil {
		return sessionID, err
	}
	if len(p.Acks) != 0 || len(p.Payload) != 0 {
		return sessionID, ErrNotReset
	}
	return p.SID, nil
}

// ParseServerReset validates a server reset and returns the client session
// id it acknowledges and the server's own.
func (l *Layout) ParseServerReset(b []byte) (clientSession, serverSession [8]byte, err error) {
	if Opcode(b) != OpHardResetServerV2 {
		return clientSession, serverSession, ErrNotReset
	}
	want := ServerResetLen
	if l.Auth == AuthTLS {
		want = ServerResetLenTLSAuth
	}
	if len(b) != want {
		return clientSession, serverSession, ErrNotReset
	}
	p, err := l.Parse(b)
	if err != nil {
		return clientSession, serverSession, err
	}
	if len(p.Acks) != 1 || p.Acks[0] != 0 || len(p.Payload) != 0 {
		return clientSession, serverSession, ErrNotReset
	}
	return p.RemoteSID, p.SID, nil
}

// Ack builds a P_ACK_V1 from sid acknowledging pid of the remote session.
func (l *Layout) Ack(sid, remote [8]byte, pid uint32) []byte {
	return l.Build(&Packet{Op: OpAckV1, SID: sid, Acks: []uint32{pid}, RemoteSID: remote})
}

// Control builds a P_CONTROL_V1 carrying payload as message pid. acks (with
// remote) are piggy-backed when given, as OpenVPN does when an ack is pending
// while a control packet goes out.
func (l *Layout) Control(sid [8]byte, pid uint32, payload []byte, acks []uint32, remote [8]byte) []byte {
	return l.Build(&Packet{Op: OpControlV1, SID: sid, PID: pid, Payload: payload, Acks: acks, RemoteSID: remote})
}

// IsClientReset reports whether b is a client hard reset of either layout and
// which layout it uses (the two differ in length only).
func IsClientReset(b []byte) (Auth, bool) {
	if Opcode(b) != OpHardResetClientV2 {
		return AuthNone, false
	}
	switch len(b) {
	case ClientResetLen:
		return AuthNone, true
	case ClientResetLenTLSAuth:
		return AuthTLS, true
	}
	return AuthNone, false
}

// IsClientResetTCP reports whether b (a TCP stream prefix) starts with the
// 2-byte length prefix of a client hard reset of either layout.
func IsClientResetTCP(b []byte) bool {
	if len(b) < 3 {
		return false
	}
	n := int(binary.BigEndian.Uint16(b))
	return (n == ClientResetLen || n == ClientResetLenTLSAuth) && b[2]>>3 == OpHardResetClientV2
}

// FrameTCP prepends the 2-byte big-endian length used by OpenVPN over TCP.
func FrameTCP(pkt []byte) []byte {
	out := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(out, uint16(len(pkt)))
	copy(out[2:], pkt)
	return out
}

// DataKey is one direction of the data channel: an AES-256-GCM key and the
// 8 implicit nonce bytes that follow the 4-byte packet id, as in OpenVPN's
// AEAD mode.
type DataKey struct {
	aead cipher.AEAD
	iv   [8]byte
}

// DeriveDataKeys derives the client→server and server→client data keys of
// one flow. Both ends hold the control-plane session key (handed over the
// pinned TLS control API) and the reservation id of the attempt; nothing has
// to be added to the reserve response:
//
//	base = HMAC-SHA256(session_key, "openvpn-data:" + attempt_id)
//	c2s  = HMAC-SHA256(base, "c2s"), s2c = HMAC-SHA256(base, "s2c")
//	implicit IV of a direction = HMAC-SHA256(dir_key, "implicit-iv")[:8]
func DeriveDataKeys(sessionKey []byte, attemptID string) (c2s, s2c *DataKey) {
	base := hmacSHA256(sessionKey, []byte("openvpn-data:"+attemptID))
	return newDataKey(hmacSHA256(base, []byte("c2s"))), newDataKey(hmacSHA256(base, []byte("s2c")))
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func newDataKey(k []byte) *DataKey {
	block, err := aes.NewCipher(k[:DataKeyLen])
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	d := &DataKey{aead: aead}
	copy(d.iv[:], hmacSHA256(k, []byte("implicit-iv")))
	return d
}

// Seal builds a P_DATA_V2 (key_id 0) for peerID carrying plain as packet pid.
// The 8-byte header is the associated data; the wire size is
// DataHdrLen + len(plain) + DataTagLen.
func (k *DataKey) Seal(peerID, pid uint32, plain []byte) []byte {
	out := make([]byte, DataHdrLen, DataHdrLen+len(plain)+DataTagLen)
	out[0] = OpDataV2 << 3
	out[1], out[2], out[3] = byte(peerID>>16), byte(peerID>>8), byte(peerID)
	binary.BigEndian.PutUint32(out[4:8], pid)
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[0:4], pid)
	copy(nonce[4:], k.iv[:])
	return k.aead.Seal(out, nonce[:], plain, out[:DataHdrLen])
}

// Open authenticates a P_DATA_V2 and returns its packet id and plaintext.
func (k *DataKey) Open(b []byte) (pid uint32, plain []byte, err error) {
	if !IsData(b) {
		return 0, nil, ErrNotData
	}
	pid = binary.BigEndian.Uint32(b[4:8])
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[0:4], pid)
	copy(nonce[4:], k.iv[:])
	plain, err = k.aead.Open(nil, nonce[:], b[DataHdrLen:], b[:DataHdrLen])
	if err != nil {
		return pid, nil, ErrBadTag
	}
	return pid, plain, nil
}

// IsData reports whether b has the shape of a P_DATA_V2 with key_id 0.
func IsData(b []byte) bool {
	return len(b) >= DataHdrLen+DataTagLen && b[0] == OpDataV2<<3
}

// DataPeer returns the 24-bit peer id of a P_DATA_V2.
func DataPeer(b []byte) uint32 {
	return uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
