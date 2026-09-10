package vless

import (
	"bytes"
	"testing"
)

// Parse reads the first bytes a client sends inside the TLS stream of the
// REALITY listener. The addons length and the host length are the sender's.

func FuzzParse(f *testing.F) {
	req := Request("x.probe.invalid", 443)
	f.Add(req)
	f.Add(req[:20])
	f.Add(append(append([]byte(nil), req...), 0x16, 0x03, 0x01)) // the TLS-in-TLS payload behind it
	f.Add(Request("", 0))
	f.Add(Request(string(bytes.Repeat([]byte{'h'}, 255)), 65535))
	ipv4 := append(append([]byte(nil), req[:18]...), CmdUDP, 0, 53, ATypIPv4, 203, 0, 113, 7)
	f.Add(ipv4)
	addons := append(append([]byte(nil), req[:17]...), 0xff) // 255 bytes of addons announced, none carried
	f.Add(addons)
	f.Add(Response())
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := Parse(b)
		if IsRequest(b) != (err == nil) {
			t.Fatalf("IsRequest and Parse disagree on %x", b)
		}
		if err != nil {
			return
		}
		if r.Len < 22 || r.Len > len(b) {
			t.Fatalf("consumed %d of %d bytes", r.Len, len(b))
		}
		// Request only builds TCP to a domain name without addons; past the
		// random UUID that form can be compared byte for byte.
		if r.Cmd == CmdTCP && b[17] == 0 && b[21] == ATypDomain {
			if again := Request(r.Host, r.Port); len(again) != r.Len || !bytes.Equal(again[17:], b[17:r.Len]) {
				t.Fatalf("Request(Parse(b)) != b\n b     %x\n again %x", b[:r.Len], again)
			}
		}
	})
}
