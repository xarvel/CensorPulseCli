package wg

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"
)

// WireGuard has no plaintext beyond four header bytes and the sizes 148 / 92
// / 16+n+16, and those are exactly what a DPI rule for it matches. The
// handshake messages are built from fresh ephemeral keys (no injection point
// in the package), so their goldens pin the layout and leave the key material
// open; what is left open is then checked by doing the cryptography again.
// Field names as on https://www.wireguard.com/protocol/.

func TestWireInitiation(t *testing.T) {
	server, client := fuzzKeys(t)
	const golden = `
		01       | message type 1: handshake initiation
		000000   | reserved, zero
		??*4     | sender index (random, little endian)
		??*32    | unencrypted ephemeral: a fresh Curve25519 public key
		??*48    | encrypted static: the initiator's public key + 16-byte tag
		??*28    | encrypted timestamp: 12-byte TAI64N + 16-byte tag
		??*16    | mac1: keyed BLAKE2s-128 over the 116 bytes above
		00000000000000000000000000000000 | mac2: zero, no cookie reply in play`
	st, a, err := CreateInitiation(client, server.Public, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := CreateInitiation(client, server.Public, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	checkRandom(t, "initiation", a, b, checkWire(t, "initiation", a, golden))
	if len(a) != InitiationSize || binary.LittleEndian.Uint32(a[4:8]) != st.SenderIdx {
		t.Errorf("initiation: %d bytes, sender index %x on the wire, %x in the state", len(a), a[4:8], st.SenderIdx)
	}
	if !bytes.Equal(a, withMAC1(a, server.Public, 116)) {
		t.Errorf("initiation: mac1 is not BLAKE2s-128(BLAKE2s-256(\"mac1----\" | responder public), msg[:116])")
	}
	info, err := ConsumeInitiation(a, server)
	if err != nil || info.PeerStatic != client.Public {
		t.Fatalf("initiation: encrypted static does not open to the initiator's key: %v", err)
	}
	// TAI64N: 0x400000000000000a + unix seconds, big endian, then nanoseconds.
	secs := int64(binary.BigEndian.Uint64(info.Timestamp[:8]) - 0x400000000000000a)
	if d := time.Since(time.Unix(secs, 0)); d < -time.Minute || d > time.Minute {
		t.Errorf("initiation: timestamp %x is %s away from now", info.Timestamp, d)
	}
}

func TestWireResponse(t *testing.T) {
	server, client := fuzzKeys(t)
	st, init, err := CreateInitiation(client, server.Public, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	info, err := ConsumeInitiation(init, server)
	if err != nil {
		t.Fatal(err)
	}
	const golden = `
		02       | message type 2: handshake response
		000000   | reserved, zero
		??*4     | sender index (random, little endian)
		??*4     | receiver index: the initiation's sender index
		??*32    | unencrypted ephemeral: a fresh Curve25519 public key
		??*16    | encrypted nothing: the tag of an empty AEAD
		??*16    | mac1: keyed BLAKE2s-128 over the 60 bytes above
		00000000000000000000000000000000 | mac2: zero`
	a, sess, err := CreateResponse(info, server, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := CreateResponse(info, server, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	random := checkWire(t, "response", a, golden)
	// The receiver index is the one region that must NOT differ: it echoes
	// the initiation.
	checkRandom(t, "response", a, b, append(random[:1:1], random[2:]...))
	if !bytes.Equal(a[8:12], init[4:8]) || binary.LittleEndian.Uint32(a[4:8]) != sess.LocalIdx {
		t.Errorf("response: receiver %x (initiation sender %x), sender %x (session %x)", a[8:12], init[4:8], a[4:8], sess.LocalIdx)
	}
	if !bytes.Equal(a, withMAC1(a, client.Public, 60)) {
		t.Errorf("response: mac1 is not BLAKE2s-128(BLAKE2s-256(\"mac1----\" | initiator public), msg[:60])")
	}
	if err := st.ConsumeResponse(a, [32]byte{}); err != nil {
		t.Errorf("response: the initiator rejects it: %v", err)
	}
}

// Transport data is a pure function of its inputs: pinned whole. The
// ciphertext and tag were cross-checked against an independent
// ChaCha20-Poly1305 (nonce = 4 zero bytes | counter, little endian).
func TestWireTransport(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	checkWire(t, "transport", SealTransport(key, 0xdeadbeef, 7, []byte("probe padding, not an IP packet")), `
		04                | message type 4: transport data
		000000            | reserved, zero
		efbeadde          | receiver index, little endian
		0700000000000000  | counter, little endian: the nonce
		817deb2a47c80ae80652275d9ba430f45de982209fcd40558aea52848c8ca31c | 31 bytes of plaintext zero-padded to 32, encrypted
		54c60db48425b2aacfbfb97d94f2e962 | Poly1305 tag`)
	checkWire(t, "keepalive", SealTransport(key, 1, 0, nil), `
		04                | message type 4: transport data
		000000            | reserved, zero
		01000000          | receiver index, little endian
		0000000000000000  | counter
		10324f800a160bd9a1794255be7ec29d | Poly1305 tag of an empty packet: 32 bytes in all, the keepalive size`)
	for plain, wire := range map[int]int{1: 48, 16: 48, 17: 64, MaxTransportPlaintext: 16 + 1408 + 16} {
		if n := len(SealTransport(key, 1, 1, make([]byte, plain))); n != wire {
			t.Errorf("transport: %d bytes of plaintext make %d on the wire, want %d (padding to 16)", plain, n, wire)
		}
	}
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
