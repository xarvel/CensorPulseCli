package vless

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// The VLESS header travels inside TLS, so no DPI box reads it; what it fixes
// is the size and position of the TLS-in-TLS payload behind it, which is the
// signal. Layout as in the Xray VLESS protocol description: version, UUID,
// addons length, command, port, address type, address.

func TestWireRequest(t *testing.T) {
	const golden = `
		00                | version 0
		??*16             | UUID (random: the probe has no accounts)
		00                | addons length 0: no protobuf addons, no flow
		01                | command: TCP
		01bb              | port 443, network order
		02                | address type: domain name
		0f                | length of the name, 15
		782e70726f62652e696e76616c6964 | "x.probe.invalid"`
	a, b := Request("x.probe.invalid", 443), Request("x.probe.invalid", 443)
	checkRandom(t, "request", a, b, checkWire(t, "request", a, golden))
}

func TestWireResponse(t *testing.T) {
	checkWire(t, "response", Response(), `
		00                | version 0, echoing the request
		00                | addons length 0`)
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
