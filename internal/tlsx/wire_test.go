package tlsx

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// These bytes travel inside the OpenVPN control channel, the SOCKS5 tunnel
// and the VLESS stream: they are the "TLS inside" that a TLS-in-anything
// detector looks for. Field names as in RFC 8446 §4.1.2 / §5.1.

func TestWireRecords(t *testing.T) {
	checkWire(t, "handshake record", Record([]byte{0x01, 0x02, 0x03}), `
		16                | content type: handshake
		0303              | legacy record version: TLS 1.2
		0003              | length 3
		010203            | fragment`)
	checkWire(t, "application data record", AppData([]byte{0x01, 0x02, 0x03}), `
		17                | content type: application data
		0303              | legacy record version: TLS 1.2
		0003              | length 3
		010203            | fragment`)
	if r := Record(make([]byte, 0x1234)); !bytes.Equal(r[3:5], []byte{0x12, 0x34}) {
		t.Errorf("record length field: %x, want 1234 (big endian)", r[3:5])
	}
}

// ClientHello is whatever crypto/tls sends for the package's Config, so this
// golden pins the Go toolchain as much as the package: a Go release that
// reorders cipher suites or adds an extension changes what the carrier tests
// put on the wire, and this is where that shows. When it fails after a Go
// upgrade, look at the new hello, decide whether the shape is still one a
// real client sends, and re-capture. (The suite order is the one crypto/tls
// uses on hardware with AES-GCM support, which is every CI runner and every
// phone; without it the ChaCha20 suites come first.)
func TestWireClientHello(t *testing.T) {
	const golden = `
		16                | content type: handshake
		0301              | legacy record version: TLS 1.0, as every first ClientHello
		0110              | record length 272
		01                | handshake type: client_hello
		00010c            | handshake length 268
		0303              | legacy_version: TLS 1.2
		??*32             | random
		20                | legacy_session_id length 32
		??*32             | legacy_session_id (random: TLS 1.3 middlebox compatibility mode)
		001a              | cipher_suites length 26
		c02b c02f c02c c030 cca9 cca8 c009 c013 c00a c014 | the TLS 1.2 ECDHE suites
		1301 1302 1303    | the TLS 1.3 suites
		01 00             | legacy_compression_methods: null
		00a9              | extensions length 169
		0000 0014         | extension server_name, length 20
		0012 00 000f      | list length 18, type host_name, name length 15
		782e70726f62652e696e76616c6964 | "x.probe.invalid"
		000b 0002 0100    | ec_point_formats: uncompressed
		ff01 0001 00      | renegotiation_info: empty
		0017 0000         | extended_master_secret
		0012 0000         | signed_certificate_timestamp
		0005 0005 0100000000 | status_request: OCSP
		000a 0006 0004    | supported_groups, 2 entries
		001d 0017         | x25519, secp256r1: the package's CurvePreferences
		000d 0016 0014    | signature_algorithms, 10 entries
		0804 0403 0807 0805 0806 0401 0501 0601 0503 0603 | schemes
		0032 001a 0018    | signature_algorithms_cert, 12 entries
		0804 0403 0807 0805 0806 0401 0501 0601 0503 0603 0201 0203 | schemes
		002b 0005 04      | supported_versions, 2 entries
		0304 0303         | TLS 1.3, TLS 1.2
		0033 0026 0024    | key_share, one entry: no hybrid post-quantum share
		001d 0020         | x25519, 32 bytes
		??*32             | the ephemeral public key (random)`
	a, b := ClientHello("x.probe.invalid"), ClientHello("x.probe.invalid")
	checkRandom(t, "ClientHello", a, b, checkWire(t, "ClientHello", a, golden))
	// The package comment promises a hello that fits one OpenVPN control
	// packet next to its header.
	if len(a) >= 300 {
		t.Errorf("ClientHello is %d bytes, the carriers count on fewer than 300", len(a))
	}
	if !IsClientHello(a) {
		t.Errorf("ClientHello is not recognised by IsClientHello: %x", a[:6])
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
