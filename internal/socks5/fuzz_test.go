package socks5

import (
	"bytes"
	"testing"
)

// The SOCKS5 listener parses the first bytes of any TCP connection to its
// port: greeting, RFC 1929 sub-negotiation, request. Every length in them is
// the sender's.

func FuzzGreeting(f *testing.F) {
	f.Add(Greeting(MethodNoAuth))
	f.Add(Greeting(MethodNoAuth, MethodUser))
	f.Add(Greeting(1, 2, 3, 4, 5)) // five methods: more than IsGreeting accepts
	f.Add(Greeting())
	f.Add([]byte{Version, 4, 0})        // four methods announced, one carried
	f.Add([]byte{4, 1, 0, 80, 1, 2, 3}) // SOCKS4
	f.Add(append(Greeting(0), 1, 2, 3)) // greeting with the next message behind it
	f.Fuzz(func(t *testing.T, b []byte) {
		// GreetingMethods slices b[2:2+b[1]] unchecked; IsGreeting is the
		// guard tcpSOCKS5 runs first, and it hands over exactly the greeting
		// (server/tcp.go).
		if !IsGreeting(b) {
			return
		}
		n := 2 + int(b[1])
		methods := GreetingMethods(b[:n])
		if len(methods) != int(b[1]) || !bytes.Equal(Greeting(methods...), b[:n]) {
			t.Fatalf("Greeting(GreetingMethods(b)) != b: %x", b)
		}
	})
}

func FuzzParseUserPass(f *testing.F) {
	up := UserPass("probe", "secret")
	f.Add(up)
	f.Add(up[:len(up)-1])
	f.Add(UserPass("", ""))
	f.Add(UserPass(string(bytes.Repeat([]byte{'u'}, 255)), string(bytes.Repeat([]byte{'p'}, 255))))
	f.Add([]byte{1, 0xff, 'x'}) // user length past the end
	f.Fuzz(func(t *testing.T, b []byte) {
		user, pass, err := ParseUserPass(b)
		if err != nil {
			return
		}
		again := UserPass(user, pass)
		if len(again) > len(b) || !bytes.Equal(again, b[:len(again)]) {
			t.Fatalf("UserPass(ParseUserPass(b)) is not a prefix of b\n b     %x\n again %x", b, again)
		}
	})
}

func FuzzParseRequest(f *testing.F) {
	req := Connect("x.probe.invalid", 443)
	f.Add(req)
	f.Add(req[:8])
	f.Add(Connect("", 0))
	f.Add(Connect(string(bytes.Repeat([]byte{'h'}, 255)), 65535))
	f.Add([]byte{Version, CmdConnect, 0, ATypIPv4, 203, 0, 113, 7, 0x01, 0xbb})
	f.Add(append([]byte{Version, CmdConnect, 0, ATypIPv6}, make([]byte, 18)...))
	f.Add(Reply(RepSuccess))
	f.Fuzz(func(t *testing.T, b []byte) {
		IsReply(b)
		r, err := ParseRequest(b)
		if err != nil {
			return
		}
		if r.Len < 7 || r.Len > len(b) {
			t.Fatalf("consumed %d of %d bytes", r.Len, len(b))
		}
		// Connect only builds CONNECT to a domain name; that is the form
		// that can be compared byte for byte.
		if r.Cmd == CmdConnect && b[3] == ATypDomain {
			if again := Connect(r.Host, r.Port); !bytes.Equal(again, b[:r.Len]) {
				t.Fatalf("Connect(ParseRequest(b)) != b\n b     %x\n again %x", b[:r.Len], again)
			}
		}
	})
}
