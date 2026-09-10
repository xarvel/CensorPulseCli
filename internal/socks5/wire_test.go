package socks5

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// SOCKS5 is plaintext and tiny: a rule for it is a rule on these exact
// bytes. Nothing in the builders is random, so every message is pinned
// whole. Field names as in RFC 1928 (§3 greeting, §4 request, §6 reply) and
// RFC 1929 (§2 username/password).

func TestWireNegotiation(t *testing.T) {
	checkWire(t, "greeting", Greeting(MethodNoAuth, MethodUser), `
		05                | VER 5
		02                | NMETHODS 2
		00 02             | METHODS: no authentication, username/password`)
	checkWire(t, "method reply", MethodReply(MethodUser), `
		05                | VER 5
		02                | METHOD: username/password`)
	checkWire(t, "refusal", MethodReply(MethodNone), `
		05                | VER 5
		ff                | METHOD: no acceptable methods`)
	checkWire(t, "username/password", UserPass("probe", "secret"), `
		01                | VER 1 of the sub-negotiation, not 5
		05                | ULEN 5
		70726f6265        | UNAME "probe"
		06                | PLEN 6
		736563726574      | PASSWD "secret"`)
	checkWire(t, "username/password reply", UserPassReply(0), `
		01                | VER 1
		00                | STATUS: success`)
}

func TestWireConnect(t *testing.T) {
	checkWire(t, "connect", Connect("x.probe.invalid", 443), `
		05                | VER 5
		01                | CMD: CONNECT
		00                | RSV
		03                | ATYP: domain name
		0f                | length of the name, 15
		782e70726f62652e696e76616c6964 | DST.ADDR "x.probe.invalid"
		01bb              | DST.PORT 443, network order`)
	checkWire(t, "reply", Reply(RepSuccess), `
		05                | VER 5
		00                | REP: succeeded
		00                | RSV
		01                | ATYP: IPv4
		00000000          | BND.ADDR 0.0.0.0: the server never connects anywhere
		0000              | BND.PORT 0`)
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
