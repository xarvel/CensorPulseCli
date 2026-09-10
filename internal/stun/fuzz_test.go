package stun

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

// The STUN port answers anybody, and the client parses whatever comes back
// from the address it asked, which an on-path box can forge.

// within fails the test when fn does not return: an attribute walk that
// stops advancing would otherwise hang the fuzzer without a report. A panic
// inside fn is re-raised on the test goroutine so the fuzzer can minimise
// the input.
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

var fuzzTx = [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

func FuzzParseBindingSuccess(f *testing.F) {
	v4 := BindingSuccess(fuzzTx, netip.MustParseAddrPort("203.0.113.7:51820"))
	v6 := BindingSuccess(fuzzTx, netip.MustParseAddrPort("[2001:db8::7]:4433"))
	f.Add(v4)
	f.Add(v6)
	f.Add(v4[:len(v4)-1])
	f.Add(v6[:HeaderLen+4+8]) // family says IPv6, value holds eight bytes
	// Fixed today: the last attribute without its padding made the walk
	// slice past the end of the datagram.
	f.Add(append(append([]byte(nil), v4[:HeaderLen]...), 0x00, 0x01, 0x00, 0x01, 0xAA))
	f.Add(append(append([]byte(nil), v4[:HeaderLen]...), 0x00, 0x01, 0xff, 0xff)) // attribute length past the end
	req, _ := BindingRequest()
	f.Add(req)
	f.Fuzz(func(t *testing.T, b []byte) {
		// Parsed against its own transaction id, so that the id check never
		// keeps the fuzzer out of the attribute walk.
		var ap netip.AddrPort
		var err error
		within(t, 5*time.Second, func() { ap, err = ParseBindingSuccess(b, TransactionID(b)) })
		if err == nil && !ap.IsValid() {
			t.Fatalf("no error and no address from %x", b)
		}
		if _, err := ParseBindingSuccess(b, [12]byte{0xff}); err == nil && TransactionID(b) != [12]byte{0xff} {
			t.Fatalf("accepted under a foreign transaction id: %x", b)
		}
	})
}

// FuzzBindingRoundTrip: Parse(Build(x)) == x for any transaction id and
// address. The builder unmaps a v4-mapped address, so that is the form the
// parser hands back.
func FuzzBindingRoundTrip(f *testing.F) {
	f.Add(fuzzTx[:], netip.MustParseAddr("203.0.113.7").AsSlice(), uint16(51820))
	f.Add(fuzzTx[:], netip.MustParseAddr("2001:db8::7").AsSlice(), uint16(4433))
	f.Add(fuzzTx[:], netip.MustParseAddr("::ffff:203.0.113.7").AsSlice(), uint16(0))
	f.Fuzz(func(t *testing.T, txb, ipb []byte, port uint16) {
		ip, ok := netip.AddrFromSlice(ipb)
		if !ok || len(txb) != 12 {
			return
		}
		tx := [12]byte(txb)
		want := netip.AddrPortFrom(ip.Unmap(), port)
		resp := BindingSuccess(tx, netip.AddrPortFrom(ip, port))
		if IsBindingRequest(resp) || TransactionID(resp) != tx {
			t.Fatalf("response shape: %x", resp)
		}
		got, err := ParseBindingSuccess(resp, tx)
		if err != nil || got != want {
			t.Fatalf("got %v %v, want %v\n resp %x", got, err, want, resp)
		}
	})
}

func FuzzIsBindingRequest(f *testing.F) {
	req, _ := BindingRequest()
	f.Add(req)
	f.Add(req[:HeaderLen-1])
	f.Add(append(append([]byte(nil), req...), 0x80, 0x22, 0x00, 0x00)) // trailing attribute the length field does not cover
	f.Add(BindingSuccess(fuzzTx, netip.MustParseAddrPort("203.0.113.7:51820")))
	f.Fuzz(func(t *testing.T, b []byte) {
		tx := TransactionID(b)
		if !IsBindingRequest(b) {
			return
		}
		// A request is its 20-byte header plus the attributes its length
		// field covers; the header is all this package builds.
		head := make([]byte, HeaderLen)
		head[1] = typeBindingReq
		head[2], head[3] = byte((len(b)-HeaderLen)>>8), byte(len(b)-HeaderLen)
		copy(head[4:], []byte{0x21, 0x12, 0xa4, 0x42})
		copy(head[8:], tx[:])
		if !bytes.Equal(head, b[:HeaderLen]) {
			t.Fatalf("header round trip\n b    %x\n head %x", b[:HeaderLen], head)
		}
	})
}
