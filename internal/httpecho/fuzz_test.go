package httpecho

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// The HTTP listeners hand the request path of any client to these parsers,
// already percent-decoded: it can hold any byte. The session id and the nonce
// are echoed into a response header, so beyond "no panic" the property is
// that whatever is accepted is plain hex.

const fuzzSID = "00112233445566778899aabbccddeeff"

func FuzzParsePath(f *testing.F) {
	f.Add(Path(fuzzSID, "http.echo", "abcdef"))
	f.Add(Path(fuzzSID, "http.echo", "abcdef") + "/")
	f.Add(Path(fuzzSID, "", ""))
	f.Add(Path("short", "t", "ab"))
	f.Add(Path(fuzzSID, "t", "ab\r\nX-Injected: 1"))
	f.Add(BulkPath(fuzzSID, "tcp.bulk", "abcdef", "up", 7))
	f.Add("")
	f.Fuzz(func(t *testing.T, p string) {
		sid, test, nonce, ok := ParsePath(p)
		if !ok {
			if sid != "" || test != "" || nonce != "" {
				t.Fatalf("fields without ok: %q %q %q", sid, test, nonce)
			}
			return
		}
		if _, err := hex.DecodeString(sid); err != nil || len(sid) != 32 {
			t.Fatalf("session id %q", sid)
		}
		if _, err := hex.DecodeString(nonce); err != nil {
			t.Fatalf("nonce %q", nonce)
		}
		if again := Path(sid, test, nonce); again != "/"+strings.Trim(p, "/") {
			t.Fatalf("Path(ParsePath(p)) = %q, p = %q", again, p)
		}
	})
}

func FuzzParseBulkPath(f *testing.F) {
	f.Add(BulkPath(fuzzSID, "tcp.bulk", "abcdef", "up", 7))
	f.Add(BulkPath(fuzzSID, "tcp.bulk", "abcdef", "down", 1<<20))
	f.Add(BulkPath(fuzzSID, "t", "ab", "down", -1))
	f.Add(BulkPath(fuzzSID, "t", "ab", "sideways", 1))
	f.Add(BulkPath(fuzzSID, "t", "ab\r\nX-Injected: 1", "up", 1))
	f.Add("/v1/bulk/" + fuzzSID + "/t/ab/up/99999999999999999999") // does not fit an int
	f.Add(Path(fuzzSID, "http.echo", "abcdef"))
	f.Fuzz(func(t *testing.T, p string) {
		b, ok := ParseBulkPath(p)
		if !ok {
			if b != nil {
				t.Fatalf("request without ok: %+v", b)
			}
			return
		}
		if _, err := hex.DecodeString(b.SessionID); err != nil || len(b.SessionID) != 32 {
			t.Fatalf("session id %q", b.SessionID)
		}
		if _, err := hex.DecodeString(b.Nonce); err != nil {
			t.Fatalf("nonce %q", b.Nonce)
		}
		if b.N < 0 || (b.Dir != "up" && b.Dir != "down") {
			t.Fatalf("accepted %+v", b)
		}
		// The count may be spelled "+7" or "007", so the comparison is on the
		// parsed form, not on the string.
		again, ok := ParseBulkPath(BulkPath(b.SessionID, b.TestID, b.Nonce, b.Dir, b.N))
		if !ok || *again != *b {
			t.Fatalf("ParseBulkPath(BulkPath(x)) = %+v, x = %+v", again, b)
		}
	})
}

// FuzzKeystream: the seed is the nonce from the request path and the length
// follows the byte count in it. Any window must equal the same bytes of a
// longer read; the offset is the server's own counter and never negative.
func FuzzKeystream(f *testing.F) {
	f.Add("abcdef", int64(0), uint16(100), uint16(31))
	f.Add("", int64(4095), uint16(4096), uint16(1))
	f.Add("seed", int64(1)<<40, uint16(65), uint16(64))
	f.Fuzz(func(t *testing.T, seed string, offset int64, n, skip uint16) {
		if offset < 0 || offset > 1<<60 || skip > n {
			return
		}
		whole := make([]byte, n)
		Keystream(seed, offset, whole)
		window := make([]byte, n-skip)
		Keystream(seed, offset+int64(skip), window)
		if !bytes.Equal(window, whole[skip:]) {
			t.Fatalf("window at %d+%d differs from the whole read", offset, skip)
		}
	})
}
