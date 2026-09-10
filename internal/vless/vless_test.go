package vless

import "testing"

func TestRequestRoundTrip(t *testing.T) {
	req := Request("x.probe.invalid", 443)
	if !IsRequest(req) {
		t.Fatal("request shape")
	}
	r, err := Parse(append(req, 1, 2, 3))
	if err != nil || r.Cmd != CmdTCP || r.Host != "x.probe.invalid" || r.Port != 443 || r.Len != len(req) {
		t.Fatalf("parse %+v %v", r, err)
	}
	if _, err := Parse(req[:20]); err == nil {
		t.Fatal("truncated must not parse")
	}
	if IsRequest([]byte{0x16, 0x03, 0x01}) {
		t.Fatal("tls record is not vless")
	}
	if len(Response()) != ResponseLen {
		t.Fatal("response")
	}
}
