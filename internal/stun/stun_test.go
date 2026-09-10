package stun

import (
	"net/netip"
	"testing"
)

func TestBindingRoundTrip(t *testing.T) {
	req, tx := BindingRequest()
	if !IsBindingRequest(req) || len(req) != HeaderLen {
		t.Fatalf("request %x", req)
	}
	for _, peer := range []string{"203.0.113.7:51820", "[2001:db8::7]:4433"} {
		ap := netip.MustParseAddrPort(peer)
		resp := BindingSuccess(tx, ap)
		if IsBindingRequest(resp) {
			t.Fatal("response mistaken for a request")
		}
		got, err := ParseBindingSuccess(resp, tx)
		if err != nil || got != ap {
			t.Fatalf("%s: %v %v", peer, err, got)
		}
		var other [12]byte
		if _, err := ParseBindingSuccess(resp, other); err == nil {
			t.Fatal("transaction id mismatch must be rejected")
		}
	}
}

// The last attribute may arrive without its padding: that is a response with
// no mapped address, not an index out of range.
func TestParseBindingSuccessUnpaddedTail(t *testing.T) {
	_, tx := BindingRequest()
	resp := BindingSuccess(tx, netip.MustParseAddrPort("203.0.113.7:51820"))[:HeaderLen]
	resp = append(resp, 0x00, 0x01, 0x00, 0x01, 0xAA) // type 1, length 1, one value byte, no padding
	if _, err := ParseBindingSuccess(resp, tx); err == nil {
		t.Fatal("expected an error for a response without XOR-MAPPED-ADDRESS")
	}
}
