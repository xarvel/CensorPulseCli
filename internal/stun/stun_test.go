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
