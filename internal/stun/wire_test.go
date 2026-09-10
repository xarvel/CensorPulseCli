package stun

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// A STUN Binding Request is 20 plaintext bytes and the first datagram of
// every WebRTC (and so Snowflake) session: type, length and the magic cookie
// are what a rule matches. Field names as in RFC 5389 §6 (header) and §15.2
// (XOR-MAPPED-ADDRESS).

var wireTx = [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}

func TestWireBindingRequest(t *testing.T) {
	const golden = `
		0001              | message type: Binding Request
		0000              | message length 0: no attributes
		2112a442          | magic cookie
		??*12             | transaction id (random)`
	a, txA := BindingRequest()
	b, _ := BindingRequest()
	checkRandom(t, "binding request", a, b, checkWire(t, "binding request", a, golden))
	if !bytes.Equal(a[8:20], txA[:]) {
		t.Errorf("binding request: returned transaction id %x is not the one on the wire %x", txA, a[8:20])
	}
}

func TestWireBindingSuccess(t *testing.T) {
	checkWire(t, "binding success, IPv4", BindingSuccess(wireTx, netip.MustParseAddrPort("203.0.113.7:51820")), `
		0101              | message type: Binding Success Response
		000c              | message length 12
		2112a442          | magic cookie
		0102030405060708090a0b0c | transaction id of the request
		0020              | attribute type: XOR-MAPPED-ADDRESS
		0008              | attribute length 8
		00                | reserved
		01                | family: IPv4
		eb7e              | X-Port: 51820 (ca6c) xor 2112
		ea12d545          | X-Address: 203.0.113.7 (cb007107) xor 2112a442`)

	// A v4-mapped peer (a dual-stack socket reports those) is answered as
	// IPv4, byte for byte the same.
	mapped := BindingSuccess(wireTx, netip.MustParseAddrPort("[::ffff:203.0.113.7]:51820"))
	if plain := BindingSuccess(wireTx, netip.MustParseAddrPort("203.0.113.7:51820")); !bytes.Equal(mapped, plain) {
		t.Errorf("binding success for a v4-mapped peer: %x, want %x", mapped, plain)
	}

	checkWire(t, "binding success, IPv6", BindingSuccess(wireTx, netip.MustParseAddrPort("[2001:db8::7]:4433")), `
		0101              | message type: Binding Success Response
		0018              | message length 24
		2112a442          | magic cookie
		0102030405060708090a0b0c | transaction id of the request
		0020              | attribute type: XOR-MAPPED-ADDRESS
		0014              | attribute length 20
		00                | reserved
		02                | family: IPv6
		3043              | X-Port: 4433 (1151) xor 2112
		0113a9fa          | X-Address, first word: 20010db8 xor the magic cookie
		010203040506070809 0a0b0b | X-Address, rest: 0..0007 xor the transaction id`)
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
