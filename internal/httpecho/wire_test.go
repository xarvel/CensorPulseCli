package httpecho

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// This package is the text both ends of the HTTP tests agree on: the request
// path, the response body, the bulk keystream. The client compares the body
// byte for byte with its own Body(), so a server and a client built from
// different commits only interoperate while these stay put, and a middlebox
// that re-serialises JSON is caught by exactly these bytes. The goldens are
// strings where the wire is text. The SHA-256 values were computed outside
// the package.

const wireSID = "00112233445566778899aabbccddeeff"

func TestWirePaths(t *testing.T) {
	if got, want := Path(wireSID, "http.echo", "abcdef"), "/v1/echo/00112233445566778899aabbccddeeff/http.echo/abcdef"; got != want {
		t.Errorf("echo path: got %q, want %q", got, want)
	}
	if got, want := BulkPath(wireSID, "tcp.bulk", "abcdef", "up", 7), "/v1/bulk/00112233445566778899aabbccddeeff/tcp.bulk/abcdef/up/7"; got != want {
		t.Errorf("bulk upload path: got %q, want %q (…/up/<chunk sequence>)", got, want)
	}
	if got, want := BulkPath(wireSID, "tcp.bulk", "abcdef", "down", 1048576), "/v1/bulk/00112233445566778899aabbccddeeff/tcp.bulk/abcdef/down/1048576"; got != want {
		t.Errorf("bulk download path: got %q, want %q (…/down/<byte count>)", got, want)
	}
}

func TestWireBody(t *testing.T) {
	// encoding/json sorts the keys; the host goes in hashed, so that a
	// rewritten Host header changes the body without echoing attacker text.
	const want = `{"host_sha256":"b003d9e549426cfc7facd5043a378c7f6720a5728faed33d7158ba816f2e4f7a",` +
		`"magic":"CP1",` +
		`"nonce":"abcdef",` +
		`"path":"/v1/echo/00112233445566778899aabbccddeeff/http.echo/abcdef"}` + "\n"
	got := Body("probe.example", Path(wireSID, "http.echo", "abcdef"), "abcdef")
	if string(got) != want {
		t.Errorf("body:\n got  %q\n want %q", got, want)
	}
}

func TestWireKeystream(t *testing.T) {
	got := make([]byte, 40)
	Keystream("abcdef", 0, got)
	checkWire(t, "keystream", got, `
		3a155a253d457fe5ef8a2a1d735c86817452292dbb3fe37f67bae1e1deeb06e1 | block 0: sha256(seed | 0 as 8 bytes big endian)
		f5defd6eb508c89d  | block 1, first 8 bytes: sha256(seed | 1)`)
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
