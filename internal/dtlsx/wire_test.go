package dtlsx

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// A DTLS ClientHello is plaintext, and DTLS fingerprinting is how Snowflake
// was blocked in practice: the rule keys on the cipher list, the extension
// order, the record version. Every byte of the three fingerprints is pinned,
// the 32-byte random aside (no injection point in the package). Field names
// as in RFC 6347 §4.1 (record), §4.2.2 (handshake header) and §4.2.1
// (HelloVerifyRequest).

func TestWireClientHelloPion(t *testing.T) {
	const first = `
		16                | content type: handshake
		fefd              | record version: DTLS 1.2 (pion says 1.2 from the first record on)
		0000              | epoch 0
		000000000000      | sequence number 0
		0088              | length 136
		01                | handshake type: client_hello
		00007c            | length 124
		0000              | message_seq 0
		000000            | fragment_offset 0
		00007c            | fragment_length 124: not fragmented
		fefd              | client_version: DTLS 1.2
		??*32             | random
		00                | session_id length 0
		00                | cookie length 0: the first ClientHello
		0010              | cipher_suites length 16
		c02b c02f cca9 cca8 c00a c014 c02c c030 | the pion/webrtc v4 default suites
		01 00             | compression_methods: null
		0042              | extensions length 66
		000d 0016 0014    | signature_algorithms, 10 entries
		0403 0503 0603 0807 0804 0805 0806 0401 0501 0601 | schemes
		ff01 0001 00      | renegotiation_info: empty
		000a 0008 0006    | supported_groups, 3 entries
		001d 0017 0018    | x25519, P-256, P-384
		000b 0002 01 00   | ec_point_formats: uncompressed
		000e 0009 0006    | use_srtp, 3 profiles
		0008 0007 0001 00 | AEAD_AES_256_GCM, AEAD_AES_128_GCM, AES128_CM_HMAC_SHA1_80; no MKI
		0017 0000         | extended_master_secret`
	a, err := ClientHello("pion", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := ClientHello("pion", nil, 0)
	checkRandom(t, "pion ClientHello", a, b, checkWire(t, "pion ClientHello", a, first))

	// The second flight: same hello with the server's cookie, and both
	// sequence numbers moved to 1.
	second, err := ClientHello("pion", []byte("0123456789abcdef"), 1)
	if err != nil {
		t.Fatal(err)
	}
	checkWire(t, "pion ClientHello with cookie", second[:25+2+32+2+16], `
		16                | content type: handshake
		fefd              | record version: DTLS 1.2
		0000              | epoch 0
		000000000001      | sequence number 1
		0098              | length 152: 16 bytes more
		01                | handshake type: client_hello
		00008c            | length 140
		0001              | message_seq 1
		000000            | fragment_offset 0
		00008c            | fragment_length 140
		fefd              | client_version: DTLS 1.2
		??*32             | random
		00                | session_id length 0
		10                | cookie length 16
		30313233343536373839616263646566 | cookie, as sent in the HelloVerifyRequest`)
	if !bytes.Equal(second[25+2+32+2+16:], a[25+2+32+2:]) {
		t.Errorf("pion ClientHello with cookie: the bytes after the cookie differ from the first hello")
	}
}

// The browser fingerprints are captures (covert-dtls); what matters is that
// they leave this package as captured, with the browsers' record version
// feff on the first flight.
func TestWireClientHelloBrowsers(t *testing.T) {
	const firefox = `
		16                | content type: handshake
		feff              | record version: DTLS 1.0, as NSS and BoringSSL send before negotiation
		0000              | epoch 0
		000000000000      | sequence number 0
		00b0              | length 176
		01                | handshake type: client_hello
		0000a4            | length 164
		0000              | message_seq 0
		000000            | fragment_offset 0
		0000a4            | fragment_length 164
		fefd              | client_version: DTLS 1.2
		??*32             | random
		00                | session_id length 0
		00                | cookie length 0
		0010              | cipher_suites length 16
		c02b c02f cca9 cca8 c00a c009 c013 c014 | the Firefox 138 suites
		01 00             | compression_methods: null
		006a              | extensions length 106
		0017 0000         | extended_master_secret
		ff01 0001 00      | renegotiation_info: empty
		000a 0008 0006 001d 0017 0018 | supported_groups: x25519, P-256, P-384
		000b 0002 01 00   | ec_point_formats: uncompressed
		0010 0012 0010    | ALPN, 16 bytes
		06 776562727463   | "webrtc"
		08 632d776562727463 | "c-webrtc"
		000d 0020 001e    | signature_algorithms, 15 entries
		0403 0503 0603 0203 0804 0805 0806 0401 0501 0601 0201 0402 0502 0602 0202 | schemes
		001c 0002 4000    | record_size_limit 16384
		000e 000b 0008    | use_srtp, 4 profiles
		0007 0008 0001 0002 00 | profiles; no MKI`
	const chrome = `
		16                | content type: handshake
		feff              | record version: DTLS 1.0
		0000              | epoch 0
		000000000000      | sequence number 0
		008c              | length 140
		01                | handshake type: client_hello
		000080            | length 128
		0000              | message_seq 0
		000000            | fragment_offset 0
		000080            | fragment_length 128
		fefd              | client_version: DTLS 1.2
		??*32             | random
		00                | session_id length 0
		00                | cookie length 0
		0016              | cipher_suites length 22
		c02b c02f cca9 cca8 c009 c013 c00a c014 009c 002f 0035 | the Chrome 136 suites
		01 00             | compression_methods: null
		0040              | extensions length 64
		000a 0008 0006 001d 0017 0018 | supported_groups: x25519, P-256, P-384
		000d 0014 0012    | signature_algorithms, 9 entries
		0403 0804 0401 0503 0805 0501 0806 0601 0201 | schemes
		0017 0000         | extended_master_secret
		000b 0002 01 00   | ec_point_formats: uncompressed
		000e 0009 0006    | use_srtp, 3 profiles
		0001 0008 0007 00 | profiles; no MKI
		ff01 0001 00      | renegotiation_info: empty`
	for name, golden := range map[string]string{"firefox-138": firefox, "chrome-136": chrome} {
		a, err := ClientHello(name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := ClientHello(name, nil, 0)
		checkRandom(t, name+" ClientHello", a, b, checkWire(t, name+" ClientHello", a, golden))
	}
	if len(Fingerprints) != 3 {
		t.Errorf("%d fingerprints, 3 have a golden: pin the new one", len(Fingerprints))
	}
}

func TestWireServerFlights(t *testing.T) {
	checkWire(t, "HelloVerifyRequest", HelloVerifyRequest([]byte("0123456789abcdef")), `
		16                | content type: handshake
		fefd              | record version: DTLS 1.2
		0000              | epoch 0
		000000000000      | sequence number 0
		001f              | length 31
		03                | handshake type: hello_verify_request
		000013            | length 19
		0000              | message_seq 0
		000000            | fragment_offset 0
		000013            | fragment_length 19
		feff              | server_version: DTLS 1.0, as RFC 6347 §4.2.1 asks for
		10                | cookie length 16
		30313233343536373839616263646566 | cookie`)

	const serverHello = `
		16                | content type: handshake
		fefd              | record version: DTLS 1.2
		0000              | epoch 0
		000000000001      | sequence number 1
		0054              | length 84
		02                | handshake type: server_hello
		000048            | length 72
		0001              | message_seq 1
		000000            | fragment_offset 0
		000048            | fragment_length 72
		fefd              | server_version: DTLS 1.2
		??*32             | random
		00                | session_id length 0
		c02b              | cipher_suite: the one the caller selected
		00                | compression_method: null
		0020              | extensions length 32
		ff01 0001 00      | renegotiation_info: empty
		0017 0000         | extended_master_secret
		000e 0005 0002 0007 00 | use_srtp: AEAD_AES_128_GCM; no MKI
		000b 0002 01 00   | ec_point_formats: uncompressed
		000a 0004 0002 001d | supported_groups in a ServerHello: the pion quirk a censor keyed on in 2021
		16                | second record, content type: handshake
		fefd              | record version: DTLS 1.2
		0000              | epoch 0
		000000000002      | sequence number 2
		000c              | length 12
		0e                | handshake type: server_hello_done
		000000            | length 0
		0002              | message_seq 2
		000000            | fragment_offset 0
		000000            | fragment_length 0`
	a, b := ServerHello(0xc02b, true), ServerHello(0xc02b, true)
	checkRandom(t, "ServerHello", a, b, checkWire(t, "ServerHello", a, serverHello))

	// Without the quirk: eight bytes shorter, three length fields follow.
	plain := ServerHello(0xc02f, false)
	checkWire(t, "ServerHello without supported_groups", plain[:25], `
		16                | content type: handshake
		fefd              | record version: DTLS 1.2
		0000              | epoch 0
		000000000001      | sequence number 1
		004c              | length 76
		02                | handshake type: server_hello
		000040            | length 64
		0001              | message_seq 1
		000000            | fragment_offset 0
		000040            | fragment_length 64`)
	checkWire(t, "ServerHello without supported_groups, tail", plain[25+2+32:], `
		00                | session_id length 0
		c02f              | cipher_suite
		00                | compression_method: null
		0018              | extensions length 24
		ff01 0001 00      | renegotiation_info: empty
		0017 0000         | extended_master_secret
		000e 0005 0002 0007 00 | use_srtp: AEAD_AES_128_GCM; no MKI
		000b 0002 01 00   | ec_point_formats: uncompressed
		16 fefd 0000 000000000002 000c | ServerHelloDone record
		0e 000000 0002 000000 000000   | server_hello_done, message_seq 2`)
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
