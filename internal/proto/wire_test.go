package proto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The CP1 envelope is the probe's own protocol: the control measurement
// every other shape is compared with, and the format two independently
// updated binaries (server, mobile client) have to agree on. Nothing in the
// encoders is random; every message is pinned whole, MACs included. The MAC,
// key, cookie and token values below were computed outside this package
// (HMAC-SHA256 with the labels and field order of the package comment), so
// they pin the construction and not just today's output.
//
// Inputs: master key 32 x 0x4d, session id 00..0f, nonce a0..ab, the clock
// at 1_800_000_000.

var (
	wireMaster = bytes.Repeat([]byte{0x4d}, 32)
	wireSID    = [SessionIDLen]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	wireNonce  = [NonceLen]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab}
	wireNow    = time.Unix(1_800_000_000, 0)
	wireExp    = wireNow.Add(10 * time.Minute) // 1_800_000_600 = 0x6b49d458
)

func TestWireKeysTokenCookie(t *testing.T) {
	checkWire(t, "session key", SessionKey(wireMaster, wireSID), `
		92e3863c6349d60863bdc1b057c8bbac59cab41bbb40b202cda6686026041c68 | HMAC-SHA256(master, "cp1-session-key" | session id)`)

	checkWire(t, "cookie", Cookie(wireMaster, wireSID, netip.MustParseAddr("203.0.113.5"), wireExp), `
		fb2e62db571b8dfc0d3d9bd71b61f01e | HMAC-SHA256(master, "cp1-udp-cookie" | session id | 4-byte address | expiry, 8 bytes big endian)[:16]`)
	if mapped := Cookie(wireMaster, wireSID, netip.MustParseAddr("::ffff:203.0.113.5"), wireExp); !bytes.Equal(mapped, Cookie(wireMaster, wireSID, netip.MustParseAddr("203.0.113.5"), wireExp)) {
		t.Errorf("cookie: a v4-mapped address gives %x, not the IPv4 cookie", mapped)
	}

	// The token is base64url without padding over these 40 bytes.
	const token = "AAECAwQFBgcICQoLDA0ODwAAAABrSdRYXBAY8-NuVodkYem9mD8PFA"
	if got := Token(wireMaster, wireSID, wireExp); got != token {
		t.Errorf("token: got %s, want %s", got, token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	checkWire(t, "token bytes", raw, `
		000102030405060708090a0b0c0d0e0f | session id
		000000006b49d458  | expiry, unix seconds, big endian
		5c1018f3e36e56876461e9bd983f0f14 | HMAC-SHA256(master, "cp1-token" | session id | expiry)[:16]`)
}

func TestWireRequest(t *testing.T) {
	key := SessionKey(wireMaster, wireSID)
	wire, err := EncodeRequest(&Request{SessionID: wireSID, TestID: "tcp.echo", Nonce: wireNonce, Seq: 7, Payload: []byte("payload")}, key)
	if err != nil {
		t.Fatal(err)
	}
	checkWire(t, "request", wire, `
		435031            | magic "CP1"
		01                | version 1
		01                | kind: request
		00                | flags: no cookie
		000102030405060708090a0b0c0d0e0f | session id
		08                | test id length
		7463702e6563686f  | test id "tcp.echo"
		a0a1a2a3a4a5a6a7a8a9aaab | nonce
		00000007          | seq
		0007              | payload length
		7061796c6f6164    | payload
		d871ac5ffcf4fe99e04e1498dc046e9c | mac: HMAC-SHA256(session key, everything above)[:16]`)

	// The UDP form: flag bit 0 and the 16-byte cookie between seq and the
	// payload length.
	cookie := Cookie(wireMaster, wireSID, netip.MustParseAddr("203.0.113.5"), wireExp)
	wire, err = EncodeRequest(&Request{SessionID: wireSID, TestID: "udp.echo", Nonce: wireNonce, Seq: 1, Cookie: cookie}, key)
	if err != nil {
		t.Fatal(err)
	}
	checkWire(t, "request with cookie", wire, `
		435031            | magic "CP1"
		01                | version 1
		01                | kind: request
		01                | flags: bit 0, cookie present
		000102030405060708090a0b0c0d0e0f | session id
		08                | test id length
		7564702e6563686f  | test id "udp.echo"
		a0a1a2a3a4a5a6a7a8a9aaab | nonce
		00000001          | seq
		fb2e62db571b8dfc0d3d9bd71b61f01e | cookie
		0000              | payload length 0
		1eff0253fcbd655c67d23b2375e1460b | mac`)
}

func TestWireReply(t *testing.T) {
	key := SessionKey(wireMaster, wireSID)
	req := &Request{SessionID: wireSID, TestID: "tcp.echo", Nonce: wireNonce, Seq: 7, Payload: []byte("payload")}
	seen := wireNow.Add(5 * time.Nanosecond)
	checkWire(t, "reply", EncodeReply(req, seen, seen.Add(time.Millisecond), key), `
		435031            | magic "CP1"
		01                | version 1
		02                | kind: reply
		00                | flags
		000102030405060708090a0b0c0d0e0f | session id, echoed
		08                | test id length
		7463702e6563686f  | test id, echoed
		a0a1a2a3a4a5a6a7a8a9aaab | nonce, echoed
		00000007          | seq, echoed
		0007              | recv_len: bytes of payload the server got
		239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5 | sha256 of that payload
		18fae27693b40005  | seen_at, unix nanoseconds, big endian
		18fae27693c34245  | replied_at: one millisecond later
		ca0c39b05001770e8f1dd7b8711734a7 | mac: HMAC-SHA256(session key, everything above)[:16]`)
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
