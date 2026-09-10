package ike

import "testing"

func TestSAInitRoundTrip(t *testing.T) {
	spii := RandomSPI()
	var pub [32]byte
	pub[0] = 9
	req := SAInit(spii, pub)
	if !Looks(req) {
		t.Fatalf("request does not parse: %d bytes", len(req))
	}
	h, err := ParseHeader(req)
	if err != nil || h.SPIi != spii || h.Exchange != ExchangeSAInit || h.Flags != FlagInitiator || h.NextPayload != PayloadSA {
		t.Fatalf("header %+v %v", h, err)
	}
	spir := RandomSPI()
	resp := SAInitResponse(h, spir, pub)
	if len(resp) >= len(req) {
		t.Fatalf("response %d must be shorter than request %d", len(resp), len(req))
	}
	rh, err := ParseHeader(resp)
	if err != nil || rh.SPIi != spii || rh.SPIr != spir || rh.Flags != FlagResponse {
		t.Fatalf("response header %+v %v", rh, err)
	}
	natt := AddNATT(req)
	if Looks(natt) {
		t.Fatal("NAT-T framed message must not parse as plain")
	}
	if inner, ok := StripNATT(natt); !ok || len(inner) != len(req) {
		t.Fatal("NAT-T strip")
	}
	auth := Auth(spii, spir, 1, 400, false)
	ah, err := ParseHeader(auth)
	if err != nil || ah.Exchange != ExchangeAuth || ah.NextPayload != PayloadSK || len(auth) != HeaderLen+4+400 {
		t.Fatalf("auth %+v %v len=%d", ah, err, len(auth))
	}
	esp := ESP(ESPSPIFor(spir), 7, make([]byte, 64))
	if !IsESPUDP(esp) || ESPSPI(esp) != ESPSPIFor(spir) {
		t.Fatal("esp")
	}
	if Looks(make([]byte, 64)) || IsESPUDP(make([]byte, 64)) {
		t.Fatal("zeros must not look like IKE or ESP")
	}
}
