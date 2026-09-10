package ike

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// IKEv2 is plaintext until IKE_AUTH: every byte of IKE_SA_INIT below is
// something a DPI box can match, down to the order of the transforms. The
// goldens follow RFC 7296 §3 field by field; nonces, NAT detection hashes,
// the vendor id and the SK payload are random in the builders (no injection
// point in the package), so they are pinned by position and length only.

var (
	wireSPIi = [8]byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
	wireSPIr = [8]byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28}
)

func wireKE() (pub [32]byte) {
	for i := range pub {
		pub[i] = byte(0x80 + i)
	}
	return pub
}

// The SA payload is the same in the request and in the response: one
// proposal, four transforms (RFC 7296 §3.3).
const wireProposal = `
		0000 002c         | proposal: last (0), reserved, length 44
		01 01 00 04       | proposal #1, protocol IKE (1), SPI size 0, 4 transforms
		03 00 000c        | transform: more follow (3), reserved, length 12
		01 00 000c        | type 1 ENCR, reserved, id 12 ENCR_AES_CBC
		800e 0100         | attribute 14 key length (TV format), 256
		03 00 0008        | transform: more follow, length 8
		02 00 0005        | type 2 PRF, id 5 PRF_HMAC_SHA2_256
		03 00 0008        | transform: more follow, length 8
		03 00 000c        | type 3 INTEG, id 12 AUTH_HMAC_SHA2_256_128
		00 00 0008        | transform: last (0), length 8
		04 00 001f        | type 4 D-H group, id 31 curve25519`

func TestWireSAInit(t *testing.T) {
	const golden = `
		1112131415161718  | initiator SPI
		0000000000000000  | responder SPI: zero in the first message
		21                | next payload 33 SA
		20                | version 2.0
		22                | exchange type 34 IKE_SA_INIT
		08                | flags: initiator
		00000000          | message id 0
		000000e4          | length 228
		22 00 0030        | SA payload: next 34 KE, not critical, length 48` + wireProposal + `
		28 00 0028        | KE payload: next 40 Ni, length 40
		001f 0000         | D-H group 31, reserved
		808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f | key exchange data: the Curve25519 public key
		29 00 0024        | nonce payload: next 41 N, length 36
		??*32             | Ni (random)
		29 00 001c        | notify payload: next 41 N, length 28
		00 00 4004        | protocol 0, SPI size 0, type 16388 NAT_DETECTION_SOURCE_IP
		??*20             | SHA-1 sized hash (random here)
		2b 00 001c        | notify payload: next 43 V, length 28
		00 00 4005        | protocol 0, SPI size 0, type 16389 NAT_DETECTION_DESTINATION_IP
		??*20             | SHA-1 sized hash (random here)
		00 00 0014        | vendor id payload: last, length 20
		??*16             | vendor id (random)`
	a, b := SAInit(wireSPIi, wireKE()), SAInit(wireSPIi, wireKE())
	checkRandom(t, "IKE_SA_INIT request", a, b, checkWire(t, "IKE_SA_INIT request", a, golden))
}

func TestWireSAInitResponse(t *testing.T) {
	const golden = `
		1112131415161718  | initiator SPI, from the request
		2122232425262728  | responder SPI
		21                | next payload 33 SA
		20                | version 2.0
		22                | exchange type 34 IKE_SA_INIT
		20                | flags: response
		00000000          | message id 0
		000000d0          | length 208: the request minus its vendor id
		22 00 0030        | SA payload: next 34 KE, not critical, length 48` + wireProposal + `
		28 00 0028        | KE payload: next 40 Nr, length 40
		001f 0000         | D-H group 31, reserved
		808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f | key exchange data
		29 00 0024        | nonce payload: next 41 N, length 36
		??*32             | Nr (random)
		29 00 001c        | notify payload: next 41 N, length 28
		00 00 4004        | NAT_DETECTION_SOURCE_IP
		??*20             | hash (random here)
		00 00 001c        | notify payload: last, length 28
		00 00 4005        | NAT_DETECTION_DESTINATION_IP
		??*20             | hash (random here)`
	req := Header{SPIi: wireSPIi}
	a, b := SAInitResponse(req, wireSPIr, wireKE()), SAInitResponse(req, wireSPIr, wireKE())
	checkRandom(t, "IKE_SA_INIT response", a, b, checkWire(t, "IKE_SA_INIT response", a, golden))
}

func TestWireAuth(t *testing.T) {
	const request = `
		1112131415161718  | initiator SPI
		2122232425262728  | responder SPI
		2e                | next payload 46 SK
		20                | version 2.0
		23                | exchange type 35 IKE_AUTH
		08                | flags: initiator
		00000001          | message id 1
		000001b0          | length 432
		00 00 0194        | SK payload: next 0, length 404
		??*400            | IV + ciphertext + ICV shape (random)`
	a, b := Auth(wireSPIi, wireSPIr, 1, 400, false), Auth(wireSPIi, wireSPIr, 1, 400, false)
	checkRandom(t, "IKE_AUTH request", a, b, checkWire(t, "IKE_AUTH request", a, request))

	// A response, and the floor of 32 inner bytes.
	checkWire(t, "IKE_AUTH response", Auth(wireSPIi, wireSPIr, 1, 0, true), `
		1112131415161718  | initiator SPI
		2122232425262728  | responder SPI
		2e                | next payload 46 SK
		20                | version 2.0
		23                | exchange type 35 IKE_AUTH
		20                | flags: response
		00000001          | message id 1
		00000040          | length 64
		00 00 0024        | SK payload: next 0, length 36
		??*32             | inner bytes: never fewer than 32`)
}

// ESP-in-UDP and the RFC 3948 non-ESP marker that tells IKE from ESP on 4500.
func TestWireESPAndNATT(t *testing.T) {
	checkWire(t, "ESP", ESP(0x01020304, 7, []byte{0xe0, 0xe1, 0xe2, 0xe3}), `
		01020304          | SPI
		00000007          | sequence number
		e0e1e2e3          | payload (opaque)`)
	checkWire(t, "NAT-T", AddNATT([]byte{0xaa, 0xbb}), `
		00000000          | non-ESP marker: an SPI of zero
		aabb              | the IKE message`)
	if spi := ESPSPIFor(wireSPIr); spi != 0x21222324 {
		t.Errorf("ESPSPIFor: %#x, want the first four bytes of the responder SPI", spi)
	}
	if spi := ESPSPIFor([8]byte{4: 1}); spi != 0x0badcafe {
		t.Errorf("ESPSPIFor with a zero prefix: %#x, want 0x0badcafe (SPI 0 is the non-ESP marker)", spi)
	}
	if a, b := RandomSPI(), RandomSPI(); a == b || a == ([8]byte{}) {
		t.Errorf("RandomSPI: %x %x", a, b)
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
