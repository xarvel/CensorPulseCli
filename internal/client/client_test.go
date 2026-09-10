package client

import "testing"

func TestNewRejectsMalformedPinAndLocalAddress(t *testing.T) {
	if _, err := New(Options{Target: "127.0.0.1", Pin: "not-a-pin"}); err == nil {
		t.Fatal("malformed pin was accepted")
	}
	if _, err := New(Options{Target: "127.0.0.1", LocalAddr: "eth0"}); err == nil {
		t.Fatal("interface name was accepted as a local IP")
	}
}
