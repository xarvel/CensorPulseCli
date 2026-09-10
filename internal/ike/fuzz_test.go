package ike

import (
	"bytes"
	"testing"
)

// UDP 500 and 4500 take datagrams from anybody. ParseHeader and StripNATT see
// all of them; ESPSPI sees the ones that passed IsESPUDP.

var (
	fuzzSPIi = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	fuzzSPIr = [8]byte{9, 10, 11, 12, 13, 14, 15, 16}
)

func ikeSeeds() [][]byte {
	req := SAInit(fuzzSPIi, [32]byte{0: 9})
	h, _ := ParseHeader(req)
	return [][]byte{
		req, req[:HeaderLen], req[:HeaderLen-1],
		SAInitResponse(h, fuzzSPIr, [32]byte{0: 7}),
		Auth(fuzzSPIi, fuzzSPIr, 1, 400, false),
		Auth(fuzzSPIi, fuzzSPIr, 1, 0, true),
		AddNATT(req),
		AddNATT(nil), // the marker alone
		ESP(0x01020304, 7, make([]byte, 64)),
	}
}

func FuzzParseHeader(f *testing.F) {
	for _, s := range ikeSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := ParseHeader(b)
		if Looks(b) != (err == nil) {
			t.Fatalf("Looks and ParseHeader disagree on %x", b)
		}
		if err != nil {
			return
		}
		// The 28-byte header is all ParseHeader reads: rebuilding it from the
		// parsed fields must give those bytes back (byte 17 is the version,
		// which a successful parse pins to 0x20).
		again := newMessage(h.SPIi, h.SPIr, h.Exchange, h.Flags, h.MessageID).out
		again[16] = h.NextPayload
		again[24], again[25], again[26], again[27] = byte(h.Length>>24), byte(h.Length>>16), byte(h.Length>>8), byte(h.Length)
		if !bytes.Equal(again, b[:HeaderLen]) || int(h.Length) != len(b) {
			t.Fatalf("header round trip\n b     %x\n again %x", b[:HeaderLen], again)
		}
	})
}

func FuzzStripNATT(f *testing.F) {
	for _, s := range ikeSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		inner, ok := StripNATT(b)
		if !ok {
			if !bytes.Equal(inner, b) {
				t.Fatalf("unmarked datagram came back changed")
			}
			return
		}
		if !Looks(inner) || !bytes.Equal(AddNATT(inner), b) {
			t.Fatalf("AddNATT(StripNATT(b)) != b: %x", b)
		}
	})
}

func FuzzESP(f *testing.F) {
	for _, s := range ikeSeeds() {
		f.Add(s)
	}
	f.Add(ESP(0, 1, make([]byte, 16))) // SPI 0 is the non-ESP marker, never ESP
	f.Add(ESP(1, 1, make([]byte, 15))) // one byte short of a block
	f.Fuzz(func(t *testing.T, b []byte) {
		// ESPSPI reads b[0:4] unchecked; IsESPUDP is the guard the UDP
		// demuxer runs first (server/udp.go).
		if !IsESPUDP(b) {
			return
		}
		spi := ESPSPI(b)
		if spi == 0 {
			t.Fatalf("IsESPUDP accepted SPI 0: %x", b)
		}
		seq := uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])
		if again := ESP(spi, seq, b[ESPHeaderLen:]); !bytes.Equal(again, b) {
			t.Fatalf("ESP(ESPSPI(b), seq, payload) != b\n b     %x\n again %x", b, again)
		}
	})
}
