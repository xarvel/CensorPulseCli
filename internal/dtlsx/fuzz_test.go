package dtlsx

import (
	"bytes"
	"sort"
	"testing"
	"time"
)

// Parse, ParseClientHello and CookieOf read datagrams from anybody who can
// reach the UDP port. No input may panic or keep the record walk spinning,
// and the flights this package builds must parse back to what went in.

// within fails the test when fn does not return: a walk that stops advancing
// would otherwise hang the fuzzer without a report. A panic inside fn is
// re-raised on the test goroutine so the fuzzer can minimise the input.
func within(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		fn()
	}()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case p := <-done:
		if p != nil {
			panic(p)
		}
	case <-timer.C:
		t.Fatalf("parser did not return within %s", d)
	}
}

func fingerprintNames() []string {
	var names []string
	for name := range Fingerprints {
		names = append(names, name)
	}
	sort.Strings(names) // map order would reshuffle the seed corpus on every run
	return names
}

func FuzzParse(f *testing.F) {
	for _, name := range fingerprintNames() {
		ch, err := ClientHello(name, []byte("0123456789abcdef"), 1)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(ch)
		f.Add(ch[:len(ch)-1])
	}
	f.Add(HelloVerifyRequest([]byte("cookiecookiecook")))
	f.Add(ServerHello(0xc02b, true))
	f.Add(record(nil))                                                 // empty record: the walk must still advance
	f.Add(record([]byte{1, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0})) // fragment announcing 16 MiB
	f.Fuzz(func(t *testing.T, b []byte) {
		IsHandshake(b)
		var msgs []Message
		var err error
		within(t, 5*time.Second, func() { msgs, err = Parse(b) })
		for _, m := range msgs {
			switch m.Type {
			case TypeClientHello:
				ParseClientHello(m.Body)
			case TypeHelloVerify:
				CookieOf(m.Body)
			}
		}
		if err != nil || len(msgs) != 1 || len(b) != 13+12+len(msgs[0].Body) {
			return
		}
		// One message filling one record: re-framing it gives the datagram
		// back, once the fields Parse does not return are copied over (record
		// epoch/sequence, total message length, fragment offset).
		again := recordWith(uint16(b[1])<<8|uint16(b[2]), 0, handshake(msgs[0].Type, msgs[0].Seq, msgs[0].Body))
		copy(again[3:11], b[3:11])
		copy(again[14:17], b[14:17])
		copy(again[19:22], b[19:22])
		if !bytes.Equal(again, b) {
			t.Fatalf("re-framed message differs\n b     %x\n again %x", b, again)
		}
	})
}

func FuzzParseClientHello(f *testing.F) {
	for _, name := range fingerprintNames() {
		for _, cookie := range [][]byte{nil, []byte("0123456789abcdef")} {
			ch, err := ClientHello(name, cookie, 0)
			if err != nil {
				f.Fatal(err)
			}
			msgs, err := Parse(ch)
			if err != nil || len(msgs) != 1 {
				f.Fatalf("%s: %v", name, err)
			}
			f.Add(msgs[0].Body)
			f.Add(msgs[0].Body[:40])
		}
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		var info ClientHelloInfo
		var err error
		within(t, 5*time.Second, func() { info, err = ParseClientHello(body) })
		if err != nil {
			return
		}
		if len(info.Cookie) > 255 || 2*len(info.CipherSuites) > len(body) || 4*len(info.Extensions) > len(body) {
			t.Fatalf("more fields than bytes: %+v from %d bytes", info, len(body))
		}
	})
}

func FuzzCookieOf(f *testing.F) {
	for _, cookie := range [][]byte{nil, []byte("cookiecookiecook"), bytes.Repeat([]byte{7}, 255)} {
		msgs, err := Parse(HelloVerifyRequest(cookie))
		if err != nil || len(msgs) != 1 {
			f.Fatal(err)
		}
		f.Add(msgs[0].Body)
	}
	f.Add([]byte{0xfe, 0xff, 0x20, 1, 2, 3}) // cookie length past the end
	f.Fuzz(func(t *testing.T, body []byte) {
		cookie := CookieOf(body)
		if cookie == nil {
			return
		}
		// HelloVerifyRequest always writes server_version fe ff, so only the
		// cookie part of the body can be compared.
		msgs, err := Parse(HelloVerifyRequest(cookie))
		if err != nil || len(msgs) != 1 || !bytes.Equal(msgs[0].Body[2:], body[2:3+len(cookie)]) {
			t.Fatalf("HelloVerifyRequest(CookieOf(body)) != body: cookie %x body %x", cookie, body)
		}
	})
}
