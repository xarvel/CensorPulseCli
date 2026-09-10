package obfs4

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"
)

// obfs4 is built to have no fixed bytes at all, so there is no hex to pin:
// what the wire shows is a length, and the two HMACs that let the other end
// find the handshake inside the noise. The goldens pin exactly that: the
// length bounds of obfs4-spec.txt §4, the positions of M and MAC, and the two
// MAC constructions, recomputed here with crypto/hmac rather than with the
// package's own helper.
//
// Not pinned, because the builders draw them from math/rand and crypto/rand
// with no injection point: the padding length of one particular handshake
// and every content byte.

var (
	wireID = Identity{
		NodeID: [NodeIDLen]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
		Public: [KeyLen]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf},
	}
	// 1_800_000_000 / 3600 = 500000: the E of the handshake MAC.
	wireNow = time.Unix(1_800_000_000, 0)
)

// specMAC is HMAC-SHA256-128 keyed with B | NODEID, as obfs4-spec.txt §4
// writes it.
func specMAC(parts ...[]byte) []byte {
	h := hmac.New(sha256.New, append(append([]byte(nil), wireID.Public[:]...), wireID.NodeID[:]...))
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)[:16]
}

// checkHandshake verifies the tail of a request or response: M over the
// representative, MAC over everything before it plus the epoch hour.
func checkHandshake(t *testing.T, what string, msg []byte) {
	t.Helper()
	n := len(msg)
	if want := specMAC(msg[:32]); !bytes.Equal(msg[n-32:n-16], want) {
		t.Errorf("%s: field %q at offset %d: got %x, want HMAC-SHA256-128(B | NODEID, representative) = %x", what, "M (mark)", n-32, msg[n-32:n-16], want)
	}
	if want := specMAC(msg[:n-16], []byte("500000")); !bytes.Equal(msg[n-16:], want) {
		t.Errorf("%s: field %q at offset %d: got %x, want HMAC-SHA256-128(B | NODEID, message | \"500000\") = %x", what, "MAC", n-16, msg[n-16:], want)
	}
}

func TestWireClientRequest(t *testing.T) {
	// X' (32) | P_C (85..8128) | M_C (16) | MAC_C (16)
	lengths := map[int]bool{}
	var prev []byte
	for i := 0; i < 32; i++ {
		req := ClientRequest(wireID, wireNow)
		if len(req) < 32+85+16+16 || len(req) > MaxHandshakeLen {
			t.Fatalf("client request of %d bytes, the spec allows %d..%d", len(req), 32+85+16+16, MaxHandshakeLen)
		}
		checkHandshake(t, "client request", req)
		if prev != nil && bytes.Equal(req[:32], prev[:32]) {
			t.Errorf("client request: the representative is identical in two builds: %x", req[:32])
		}
		lengths[len(req)] = true
		prev = req
	}
	if len(lengths) < 16 {
		t.Errorf("client request: %d distinct lengths in 32 builds; the padding length is the only thing a length rule sees, it has to vary", len(lengths))
	}
}

func TestWireServerResponse(t *testing.T) {
	// Y' (32) | AUTH (32) | P_S (0..8096) | M_S (16) | MAC_S (16). With no
	// room for padding the layout is fixed, which makes it a golden.
	const golden = `
		??*32             | Y': Elligator 2 representative (random here)
		??*32             | AUTH: ntor authentication tag (random here)
		??*16             | M_S: HMAC over Y', checked below
		??*16             | MAC_S: HMAC over all of the above and the epoch hour, checked below`
	a, b := ServerResponse(wireID, wireNow, serverHandshakeNP), ServerResponse(wireID, wireNow, serverHandshakeNP)
	checkRandom(t, "server response", a, b, checkWire(t, "server response", a, golden))
	checkHandshake(t, "server response", a)
	if n := len(ServerResponse(wireID, wireNow, 0)); n != 96 {
		t.Errorf("server response with no budget: %d bytes, want the bare 96", n)
	}
	for i := 0; i < 32; i++ {
		resp := ServerResponse(wireID, wireNow, 500)
		if len(resp) < 96 || len(resp) > 500 {
			t.Fatalf("server response of %d bytes for a 500-byte request: it must never be the longer one", len(resp))
		}
		checkHandshake(t, "padded server response", resp)
	}
}

func TestWireFrameAndIdentity(t *testing.T) {
	// A data frame is a length xor-ed with a mask and n bytes of secretbox
	// stand-in. The mask here is the first two payload bytes.
	for _, n := range []int{32, 100, MaxFrame} {
		f := Frame(n)
		if len(f) != 2+n || int(binary.BigEndian.Uint16(f)^binary.BigEndian.Uint16(f[2:4])) != n {
			t.Errorf("frame of %d: %d bytes on the wire, length field %x xor %x", n, len(f), f[:2], f[2:4])
		}
	}
	if a, b := Frame(64), Frame(64); bytes.Equal(a, b) {
		t.Errorf("frame: identical in two builds: %x", a)
	}

	if e := EpochHour(wireNow); e != "500000" {
		t.Errorf("EpochHour: %q, want hours since the epoch in decimal", e)
	}
	checkWire(t, "identity", wireID.Bytes(), `
		0102030405060708090a0b0c0d0e0f1011121314 | node id, 20 bytes
		a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf | Curve25519 identity public key`)
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
