package l2tp

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// L2TPv2 without IPsec is plaintext end to end: the flags word, the AVP
// order and the PPP frame behind the data header are all there for a DPI box
// to match. The goldens follow RFC 2661 §3.1 (header) and §4.1 (AVP: M bit |
// length, vendor id, attribute type, value). Only two fields are random in
// the builders: the call serial number and the LCP magic number.

func TestWireTunnelSetup(t *testing.T) {
	checkWire(t, "SCCRQ", SCCRQ(0x1234, "probe-1"), `
		c802              | flags: T (control), L (length), S (sequence), version 2
		0054              | length 84
		0000              | tunnel id 0: the peer has not assigned one yet
		0000              | session id 0
		0000 0000         | Ns 0, Nr 0
		8008 0000 0000    | AVP: mandatory, length 8; vendor 0; attribute 0 Message Type
		0001              | SCCRQ
		8008 0000 0002    | AVP: Protocol Version
		0100              | version 1, revision 0
		800d 0000 0007    | AVP: Host Name, length 13
		70726f62652d31    | "probe-1"
		800a 0000 0003    | AVP: Framing Capabilities, length 10
		00000003          | sync and async
		8008 0000 0009    | AVP: Assigned Tunnel ID
		1234              | our tunnel id
		8008 0000 000a    | AVP: Receive Window Size
		0004              | 4
		8011 0000 0008    | AVP: Vendor Name, length 17
		43656e736f7250756c7365 | "CensorPulse"`)

	checkWire(t, "SCCRP", SCCRP(0x1234, 0x5678, "cpprobe"), `
		c802              | flags: T, L, S, version 2
		003b              | length 59: shorter than the SCCRQ it answers
		1234              | tunnel id: the one the peer assigned
		0000              | session id 0
		0000 0001         | Ns 0, Nr 1
		8008 0000 0000    | AVP: Message Type
		0002              | SCCRP
		8008 0000 0002    | AVP: Protocol Version
		0100              | version 1, revision 0
		800a 0000 0003    | AVP: Framing Capabilities
		00000003          | sync and async
		800d 0000 0007    | AVP: Host Name, length 13
		637070726f6265    | "cpprobe"
		8008 0000 0009    | AVP: Assigned Tunnel ID
		5678              | our tunnel id`)

	checkWire(t, "SCCCN", SCCCN(0x5678), `
		c802              | flags: T, L, S, version 2
		0014              | length 20
		5678              | tunnel id
		0000              | session id 0
		0001 0001         | Ns 1, Nr 1
		8008 0000 0000    | AVP: Message Type
		0003              | SCCCN`)
}

func TestWireSessionSetup(t *testing.T) {
	const icrq = `
		c802              | flags: T, L, S, version 2
		0026              | length 38
		5678              | tunnel id
		0000              | session id 0: the peer has not assigned one yet
		0002 0001         | Ns 2, Nr 1
		8008 0000 0000    | AVP: Message Type
		000a              | ICRQ
		8008 0000 000e    | AVP: Assigned Session ID
		0005              | our session id
		800a 0000 000f    | AVP: Call Serial Number, length 10
		??*4              | serial (random)`
	a, b := ICRQ(0x5678, 5, 2, 1), ICRQ(0x5678, 5, 2, 1)
	checkRandom(t, "ICRQ", a, b, checkWire(t, "ICRQ", a, icrq))

	checkWire(t, "ICRP", ICRP(0x1234, 5, 6, 1, 3), `
		c802              | flags: T, L, S, version 2
		001c              | length 28
		1234              | tunnel id
		0005              | session id: the one the peer assigned
		0001 0003         | Ns 1, Nr 3
		8008 0000 0000    | AVP: Message Type
		000b              | ICRP
		8008 0000 000e    | AVP: Assigned Session ID
		0006              | our session id`)

	checkWire(t, "ICCN", ICCN(0x5678, 6, 3, 2), `
		c802              | flags: T, L, S, version 2
		0028              | length 40
		5678              | tunnel id
		0006              | session id
		0003 0002         | Ns 3, Nr 2
		8008 0000 0000    | AVP: Message Type
		000c              | ICCN
		800a 0000 0018    | AVP: (Tx) Connect Speed
		05f5e100          | 100 000 000 bit/s
		800a 0000 0013    | AVP: Framing Type
		00000001          | synchronous`)

	checkWire(t, "ZLB", ZLB(0x1234, 5, 1, 2), `
		c802              | flags: T, L, S, version 2
		000c              | length 12: header only, the acknowledgement
		1234              | tunnel id
		0005              | session id
		0001 0002         | Ns 1, Nr 2`)
}

func TestWireData(t *testing.T) {
	const lcp = `
		0002              | flags: data message, no length, no sequence, version 2
		1234              | tunnel id
		0005              | session id
		ff03              | PPP address and control
		c021              | protocol: LCP
		01 07 000e        | Configure-Request, identifier 7, length 14
		01 04 05dc        | option 1 MRU, length 4: 1500
		05 06             | option 5 Magic-Number, length 6
		??*4              | magic number (random)`
	a, b := Data(0x1234, 5, PPPLCPConfigureRequest(7)), Data(0x1234, 5, PPPLCPConfigureRequest(7))
	checkRandom(t, "data with LCP", a, b, checkWire(t, "data with LCP", a, lcp))

	checkWire(t, "data with IP", Data(0x1234, 5, PPPIP([]byte{0x45, 0x00})), `
		0002              | flags: data message, version 2
		1234              | tunnel id
		0005              | session id
		ff03              | PPP address and control
		0021              | protocol: IPv4
		4500              | payload`)

	for i := 0; i < 100; i++ {
		if RandomID() == 0 {
			t.Fatal("RandomID returned 0, the id that means \"not assigned yet\"")
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
