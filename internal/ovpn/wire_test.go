package ovpn

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The bytes these builders put on the wire are the measurement: a DPI box
// keys on the opcode byte, on the 14/42-byte length of the reset, on the
// position of the HMAC block. The goldens below pin them field by field
// (names as in OpenVPN's ssl_pkt.h / the package comment), so that a builder
// that moves one byte fails with the name of the field that moved.

var (
	wireSID    = [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	wireRemote = [8]byte{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8}
	// 1_800_000_000 = 0x6b49d200, the net_time of every tls-auth golden.
	wireNow = time.Unix(1_800_000_000, 0)
)

// wireTLSAuth is a tls-auth layout on the package's injectable clock, keyed
// with 20 bytes of 0x0b.
func wireTLSAuth() *Layout {
	l := TLSAuth(bytes.Repeat([]byte{0x0b}, HMACLen), nil)
	l.now = func() time.Time { return wireNow }
	return l
}

func TestWirePlainControl(t *testing.T) {
	const clientReset = `
		38                | opcode 7 P_CONTROL_HARD_RESET_CLIENT_V2 << 3, key_id 0
		??*8              | session id (random)
		00                | ack_len 0
		00000000          | message packet id 0`
	a, sidA := Plain().ClientReset()
	b, _ := Plain().ClientReset()
	checkRandom(t, "client reset", a, b, checkWire(t, "client reset", a, clientReset))
	if !bytes.Equal(a[1:9], sidA[:]) {
		t.Errorf("client reset: returned session id %x is not the one on the wire %x", sidA, a[1:9])
	}

	const serverReset = `
		40                | opcode 8 P_CONTROL_HARD_RESET_SERVER_V2 << 3, key_id 0
		??*8              | session id (random)
		01                | ack_len 1
		00000000          | ack of the client's packet id 0
		0102030405060708  | remote session id: the client's
		00000000          | message packet id 0`
	a, sidA = Plain().ServerReset(wireSID)
	b, _ = Plain().ServerReset(wireSID)
	checkRandom(t, "server reset", a, b, checkWire(t, "server reset", a, serverReset))
	if !bytes.Equal(a[1:9], sidA[:]) {
		t.Errorf("server reset: returned session id %x is not the one on the wire %x", sidA, a[1:9])
	}

	checkWire(t, "ack", Plain().Ack(wireSID, wireRemote, 3), `
		28                | opcode 5 P_ACK_V1 << 3, key_id 0
		0102030405060708  | session id
		01                | ack_len 1
		00000003          | acked packet id
		a1a2a3a4a5a6a7a8  | remote session id`)

	checkWire(t, "control", Plain().Control(wireSID, 2, []byte("hello"), nil, [8]byte{}), `
		20                | opcode 4 P_CONTROL_V1 << 3, key_id 0
		0102030405060708  | session id
		00                | ack_len 0: no remote session id follows
		00000002          | message packet id
		68656c6c6f        | payload (a TLS record in a real flow)`)

	checkWire(t, "control with piggy-backed acks", Plain().Control(wireSID, 1, []byte("hello"), []uint32{0, 7}, wireRemote), `
		20                | opcode 4 P_CONTROL_V1 << 3, key_id 0
		0102030405060708  | session id
		02                | ack_len 2
		00000000 00000007 | acked packet ids
		a1a2a3a4a5a6a7a8  | remote session id
		00000001          | message packet id
		68656c6c6f        | payload`)

	checkWire(t, "key_id", Plain().Build(&Packet{Op: OpControlV1, KeyID: 3, SID: wireSID})[:1], `
		23                | opcode 4 << 3 | key_id 3`)

	checkWire(t, "tcp frame", FrameTCP(Plain().Ack(wireSID, wireRemote, 3)), `
		0016              | packet length 22, big endian (OpenVPN over TCP)
		28                | opcode 5 P_ACK_V1 << 3
		0102030405060708  | session id
		01                | ack_len 1
		00000003          | acked packet id
		a1a2a3a4a5a6a7a8  | remote session id`)
}

// tls-auth puts hmac(20) and the replay fields packet_id(4) net_time(4)
// between the session id and ack_len (OpenVPN's swap_hmac layout). The HMAC
// is HMAC-SHA1(key, packet_id | net_time | op | session id | ack_len ..).
func TestWireTLSAuthControl(t *testing.T) {
	l := wireTLSAuth()
	checkWire(t, "tls-auth control", l.Control(wireSID, 1, []byte("hello"), []uint32{0}, wireRemote), `
		20                                        | opcode 4 P_CONTROL_V1 << 3, key_id 0
		0102030405060708                          | session id
		a6220382cb810bac92d307f6d0153c420e9a2a96  | hmac-sha1
		00000001                                  | replay packet id: first packet of the layout
		6b49d200                                  | net_time
		01                                        | ack_len 1
		00000000                                  | acked packet id
		a1a2a3a4a5a6a7a8                          | remote session id
		00000001                                  | message packet id
		68656c6c6f                                | payload`)

	// Same layout, next packet: the replay id counts up and the HMAC follows.
	checkWire(t, "tls-auth ack", l.Ack(wireSID, wireRemote, 3), `
		28                                        | opcode 5 P_ACK_V1 << 3, key_id 0
		0102030405060708                          | session id
		0bda63af448a8b594fbdc330c8f08f99f9ddc3d3  | hmac-sha1
		00000002                                  | replay packet id: second packet of the layout
		6b49d200                                  | net_time
		01                                        | ack_len 1
		00000003                                  | acked packet id
		a1a2a3a4a5a6a7a8                          | remote session id`)

	// The resets carry a random session id, and with it a MAC that differs
	// every time: pinned are the length (42 / 54, what a length rule keys
	// on) and everything around the two.
	const clientReset = `
		38                | opcode 7 P_CONTROL_HARD_RESET_CLIENT_V2 << 3, key_id 0
		??*8              | session id (random)
		??*20             | hmac-sha1 (over the random session id)
		00000001          | replay packet id
		6b49d200          | net_time
		00                | ack_len 0
		00000000          | message packet id 0`
	a, _ := wireTLSAuth().ClientReset()
	b, _ := wireTLSAuth().ClientReset()
	checkRandom(t, "tls-auth client reset", a, b, checkWire(t, "tls-auth client reset", a, clientReset))
	if _, err := TLSAuth(nil, bytes.Repeat([]byte{0x0b}, HMACLen)).ParseClientReset(a); err != nil {
		t.Errorf("tls-auth client reset: hmac does not verify: %v", err)
	}

	const serverReset = `
		40                | opcode 8 P_CONTROL_HARD_RESET_SERVER_V2 << 3, key_id 0
		??*8              | session id (random)
		??*20             | hmac-sha1 (over the random session id)
		00000001          | replay packet id
		6b49d200          | net_time
		01                | ack_len 1
		00000000          | ack of the client's packet id 0
		0102030405060708  | remote session id: the client's
		00000000          | message packet id 0`
	a, _ = wireTLSAuth().ServerReset(wireSID)
	b, _ = wireTLSAuth().ServerReset(wireSID)
	checkRandom(t, "tls-auth server reset", a, b, checkWire(t, "tls-auth server reset", a, serverReset))
	if _, _, err := TLSAuth(nil, bytes.Repeat([]byte{0x0b}, HMACLen)).ParseServerReset(a); err != nil {
		t.Errorf("tls-auth server reset: hmac does not verify: %v", err)
	}
}

// The static key is cut like OpenVPN's key-direction 0/1: the first 20 bytes
// of each 32-byte half.
func TestWireTLSAuthDirKeys(t *testing.T) {
	static := make([]byte, TLSAuthKeyLen)
	for i := range static {
		static[i] = byte(i)
	}
	c2s, s2c, err := TLSAuthDirKeys(static)
	if err != nil {
		t.Fatal(err)
	}
	checkWire(t, "client→server key", c2s, `000102030405060708090a0b0c0d0e0f10111213 | bytes 0..20 of the static key`)
	checkWire(t, "server→client key", s2c, `202122232425262728292a2b2c2d2e2f30313233 | bytes 32..52 of the static key`)
	if a, b := NewTLSAuthKey(), NewTLSAuthKey(); len(a) != TLSAuthKeyLen || bytes.Equal(a, b) {
		t.Errorf("NewTLSAuthKey: %d bytes, two keys equal: %v", len(a), bytes.Equal(a, b))
	}
}

// P_DATA_V2 in AEAD mode. Keys, implicit IV and with them the ciphertext are
// a function of (session key, attempt id): a change to DeriveDataKeys' labels
// shows up here as a moved ciphertext.
func TestWireData(t *testing.T) {
	c2s, s2c := DeriveDataKeys(bytes.Repeat([]byte{0x42}, 32), "attempt-1")
	checkWire(t, "data c2s", c2s.Seal(0x010203, 1, PingMagic), `
		48                               | opcode 9 P_DATA_V2 << 3, key_id 0
		010203                           | peer id, 24 bits
		00000001                         | packet id: the explicit part of the nonce
		0853a3c1aa52ef3def3a3e175fb2d6de | AES-256-GCM ciphertext of the 16-byte ping magic
		ad3acfccca10b734597f93867ade1205 | GCM tag over header and ciphertext`)
	checkWire(t, "data s2c", s2c.Seal(0, 0x01020304, nil), `
		48                               | opcode 9 P_DATA_V2 << 3, key_id 0
		000000                           | peer id
		01020304                         | packet id
		ff07f563d6e1dce07785dd7132087ce2 | GCM tag (empty plaintext)`)
}

// checkWire compares got with a golden written as an annotated dump, one
// field per line: "hex | field name". Hex digits are exact bytes (blanks are
// free); "??*N" stands for N bytes that differ from packet to packet. A
// mismatch is reported with the name of the field, not as two hex strings to
// diff by eye. The offsets of the unpinned regions are returned for
// checkRandom. (Each protocol package carries a copy of these two helpers:
// test code cannot be imported across packages.)
func checkWire(t *testing.T, what string, got []byte, golden string) (random [][2]int) {
	t.Helper()
	off, failed := 0, false
	for _, line := range strings.Split(strings.TrimSpace(golden), "\n") {
		spec, name, _ := strings.Cut(line, "|")
		spec, name = strings.Join(strings.Fields(spec), ""), strings.TrimSpace(name)
		n := len(spec) / 2
		if c, ok := strings.CutPrefix(spec, "??*"); ok {
			n, _ = strconv.Atoi(c)
		}
		if off+n > len(got) {
			t.Errorf("%s: field %q wants bytes %d..%d, the packet has %d", what, name, off, off+n, len(got))
			failed = true
			break
		}
		if strings.HasPrefix(spec, "??") {
			random = append(random, [2]int{off, off + n})
		} else if want, err := hex.DecodeString(spec); err != nil {
			t.Fatalf("%s: golden line %q: %v", what, line, err)
		} else if !bytes.Equal(got[off:off+n], want) {
			t.Errorf("%s: field %q at offset %d: got %x, want %x", what, name, off, got[off:off+n], want)
			failed = true
		}
		off += n
	}
	if off != len(got) && !failed {
		t.Errorf("%s: %d bytes on the wire, the golden describes %d", what, len(got), off)
		failed = true
	}
	if failed {
		t.Logf("%s, whole packet: %x", what, got)
	}
	return random
}

// checkRandom asserts that the unpinned regions really vary between two
// builds: a session id that comes out the same twice is a fingerprint.
// Regions under four bytes are skipped, they collide by chance too often.
func checkRandom(t *testing.T, what string, a, b []byte, random [][2]int) {
	t.Helper()
	for _, r := range random {
		if r[1]-r[0] >= 4 && r[1] <= len(a) && r[1] <= len(b) && bytes.Equal(a[r[0]:r[1]], b[r[0]:r[1]]) {
			t.Errorf("%s: bytes %d..%d are identical in two builds: %x", what, r[0], r[1], a[r[0]:r[1]])
		}
	}
}
