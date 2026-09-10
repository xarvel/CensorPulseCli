package tor

import (
	"bytes"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Two kinds of bytes leave this package. The ClientHello is plaintext and is
// what a Tor rule on a DPI box matches (cipher list, no SNI, no ALPN); the
// cells travel inside TLS, where only their sizes show: 514 bytes per fixed
// cell, the VERSIONS / CERTS / AUTH_CHALLENGE / NETINFO sequence of a v3+
// link handshake. Field names as in tor-spec.txt §3 (cell format) and §4
// (negotiating and initializing connections).

// fixedCell checks a 514-byte cell: the golden describes its head, the rest
// must be the zero padding of tor-spec §3.
func fixedCell(t *testing.T, what string, cell []byte, golden string) [][2]int {
	t.Helper()
	if len(cell) != FixedCellLen {
		t.Fatalf("%s: %d bytes, a fixed cell of link protocol 4+ is %d", what, len(cell), FixedCellLen)
	}
	n := goldenLen(golden)
	random := checkWire(t, what, cell[:n], golden)
	if pad := bytes.TrimRight(cell[n:], "\x00"); len(pad) != 0 {
		t.Errorf("%s: padding after byte %d is not zero: %x", what, n, pad)
	}
	return random
}

// goldenLen is the number of bytes a golden describes.
func goldenLen(golden string) int {
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(golden), "\n") {
		spec, _, _ := strings.Cut(line, "|")
		spec = strings.Join(strings.Fields(spec), "")
		if c, ok := strings.CutPrefix(spec, "??*"); ok {
			k, _ := strconv.Atoi(c)
			n += k
		} else {
			n += len(spec) / 2
		}
	}
	return n
}

func TestWireVersions(t *testing.T) {
	checkWire(t, "VERSIONS", VersionsCell(Versions), `
		0000              | CircID 0, on two bytes: no link protocol negotiated yet
		07                | command 7 VERSIONS
		0006              | length 6
		0003 0004 0005    | link protocols 3, 4, 5`)
}

func TestWireVarCells(t *testing.T) {
	checkWire(t, "variable-length cell", VarCell(0x01020304, CmdVPadding, []byte{0xaa, 0xbb}), `
		01020304          | CircID, four bytes from link protocol 4 on
		80                | command 128 VPADDING
		0002              | length
		aabb              | payload`)

	const certs = `
		00000000          | CircID 0
		81                | command 129 CERTS
		0587              | length 1415
		04                | number of certificates
		02 0360           | CertType 2: RSA1024 identity, self-signed; 864 bytes
		??*864            | certificate (random here: nothing verifies it)
		04 008c           | CertType 4: Ed25519 signing key, signed by the identity; 140 bytes
		??*140            | certificate
		05 008c           | CertType 5: TLS link certificate, signed by the signing key; 140 bytes
		??*140            | certificate
		07 0102           | CertType 7: Ed25519 identity, signed by the RSA identity; 258 bytes
		??*258            | certificate`
	a, b := CertsCell(), CertsCell()
	checkRandom(t, "CERTS", a, b, checkWire(t, "CERTS", a, certs))

	const challenge = `
		00000000          | CircID 0
		82                | command 130 AUTH_CHALLENGE
		0026              | length 38
		??*32             | challenge (random)
		0002              | number of methods
		0001 0003         | RSA-SHA256-TLSSecret, Ed25519-SHA256-RFC5705`
	a, b = AuthChallengeCell(), AuthChallengeCell()
	checkRandom(t, "AUTH_CHALLENGE", a, b, checkWire(t, "AUTH_CHALLENGE", a, challenge))
}

func TestWireFixedCells(t *testing.T) {
	now := time.Unix(1_800_000_000, 0) // 0x6b49d200
	fixedCell(t, "NETINFO", NetinfoCell(now, net.IPv4(203, 0, 113, 7), []net.IP{net.IPv4(198, 51, 100, 1), net.ParseIP("2001:db8::1")}), `
		00000000          | CircID 0
		08                | command 8 NETINFO
		6b49d200          | timestamp
		04 04 cb007107    | other address: type IPv4, length 4, 203.0.113.7
		02                | number of this side's addresses
		04 04 c6336401    | IPv4 198.51.100.1
		06 10 20010db8000000000000000000000001 | type IPv6, length 16, 2001:db8::1`)

	const createFast = `
		80000007          | CircID 7 with the high bit the initiator sets
		05                | command 5 CREATE_FAST
		??*20             | X: key material (random)`
	a, b := CreateFastCell(7), CreateFastCell(7)
	checkRandom(t, "CREATE_FAST", a, b, fixedCell(t, "CREATE_FAST", a, createFast))

	const createdFast = `
		80000007          | CircID, as in the request
		06                | command 6 CREATED_FAST
		??*20             | Y: key material (random)
		??*20             | KH: derivative key data (random here)`
	a, b = CreatedFastCell(0x80000007), CreatedFastCell(0x80000007)
	checkRandom(t, "CREATED_FAST", a, b, fixedCell(t, "CREATED_FAST", a, createdFast))

	fixedCell(t, "fixed-length cell", FixedCell(0x01020304, CmdPadding, []byte{0xaa}), `
		01020304          | CircID
		00                | command 0 PADDING
		aa                | payload, zero-padded to 509 bytes`)
}

// hello marshals the ClientHello uTLS sends for the package's preset, the
// way the client test applies it, without a connection.
func hello(t *testing.T, tls12Only bool) []byte {
	t.Helper()
	uc := utls.UClient(nil, &utls.Config{InsecureSkipVerify: true}, utls.HelloCustom)
	if err := uc.ApplyPreset(ClientHelloSpec(tls12Only)); err != nil {
		t.Fatal(err)
	}
	if err := uc.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	return uc.HandshakeState.Hello.Raw
}

// The hello of a C tor on OpenSSL 3: no server_name, no ALPN, no session
// ticket, the cipher list of src/lib/tls/ciphers.inc. This is the plaintext
// a Tor rule matches, so it is pinned down to the extension order.
const (
	wireHelloSuites12 = `
		c02b c02f cca9 cca8 c02c c030 c00a c009 c013 c014 009c 009d 002f 0035 | the TLS 1.2 list of ciphers.inc, in order
		00ff              | TLS_EMPTY_RENEGOTIATION_INFO_SCSV, which OpenSSL appends`
	wireHelloExtensions12 = `
		000b 0004 03 000102 | ec_point_formats: uncompressed and both compressed forms
		000a 0016 0014    | supported_groups, 10 entries
		001d 0017 001e 0019 0018 0100 0101 0102 0103 0104 | x25519, P-256, x448, P-521, P-384, ffdhe2048..8192
		0016 0000         | encrypt_then_mac
		0017 0000         | extended_master_secret
		000d 002a 0028    | signature_algorithms, 20 entries
		0403 0503 0603 0807 0808 0809 080a 080b 0804 0805 0806 0401 0501 0601 0303 0301 0302 0402 0502 0602 | the OpenSSL default list, ed448 (0808) and DSA included`
)

func TestWireClientHello(t *testing.T) {
	const tls13 = `
		01                | handshake type: client_hello
		0000fe            | length 254
		0303              | legacy_version: TLS 1.2
		??*32             | random
		20                | legacy_session_id length 32
		??*32             | legacy_session_id (random)
		0024              | cipher_suites length 36
		1301 1303 1302    | the TLS 1.3 suites in tor's order` + wireHelloSuites12 + `
		01 00             | legacy_compression_methods: null
		0091              | extensions length 145: no server_name, no ALPN, no session_ticket` + wireHelloExtensions12 + `
		002b 0005 04 0304 0303 | supported_versions: TLS 1.3, TLS 1.2
		002d 0002 01 01   | psk_key_exchange_modes: psk_dhe_ke
		0033 0026 0024    | key_share, one entry
		001d 0020         | x25519, 32 bytes
		??*32             | the ephemeral public key (random)`
	a, b := hello(t, false), hello(t, false)
	checkRandom(t, "ClientHello", a, b, checkWire(t, "ClientHello", a, tls13))

	// The 1.2-only variant exists to get the link certificate onto the wire
	// in plaintext: the same hello minus everything TLS 1.3.
	const tls12 = `
		01                | handshake type: client_hello
		0000bf            | length 191
		0303              | legacy_version: TLS 1.2
		??*32             | random
		20                | legacy_session_id length 32
		??*32             | legacy_session_id (random)
		001e              | cipher_suites length 30` + wireHelloSuites12 + `
		01 00             | legacy_compression_methods: null
		0058              | extensions length 88` + wireHelloExtensions12
	a, b = hello(t, true), hello(t, true)
	checkRandom(t, "ClientHello, TLS 1.2 only", a, b, checkWire(t, "ClientHello, TLS 1.2 only", a, tls12))
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
