package obfs4

import (
	"testing"
	"time"
)

// FindClientRequest runs on the first bytes of any TCP connection to the
// obfs4 port, FindServerResponse on whatever answers the client. A fuzzer
// cannot guess a 16-byte HMAC mark, so each target also plants the correct
// mark at a position of the fuzzer's choosing: that is what reaches the MAC
// check at every offset, including the last one that still fits.

var (
	fuzzID  = Identity{NodeID: [NodeIDLen]byte{0: 0xaa, 19: 0xbb}, Public: [KeyLen]byte{0: 0xcc, 31: 0xdd}}
	fuzzNow = time.Unix(1_800_000_000, 0)
)

type finder func(buf []byte, id Identity, now time.Time) (int, bool)

func fuzzFind(t *testing.T, find finder, minLen, from int, buf []byte, pos uint16) {
	check := func(b []byte) {
		n, ok := find(b, fuzzID, fuzzNow)
		if !ok {
			if n != 0 {
				t.Fatalf("n=%d without ok", n)
			}
			return
		}
		if n < minLen || n > len(b) || n > MaxHandshakeLen {
			t.Fatalf("n=%d out of range (len %d)", n, len(b))
		}
		// What was found is a complete handshake on its own.
		if m, ok := find(b[:n], fuzzID, fuzzNow); !ok || m != n {
			t.Fatalf("prefix of %d bytes does not verify again: %d %v", n, m, ok)
		}
	}
	check(buf)
	if len(buf) < from+MarkLen+MACLen {
		return
	}
	planted := append([]byte(nil), buf...)
	at := from + int(pos)%(len(planted)-MarkLen-MACLen-from+1)
	copy(planted[at:], mac128(fuzzID.key(), planted[:KeyLen]))
	check(planted)
}

func FuzzFindClientRequest(f *testing.F) {
	req := ClientRequest(fuzzID, fuzzNow)
	f.Add(req, uint16(0))
	f.Add(append(append([]byte(nil), req...), Frame(100)...), uint16(7))
	f.Add(req[:len(req)-1], uint16(0xffff))
	f.Add(ClientRequest(fuzzID, fuzzNow.Add(time.Hour)), uint16(1)) // E+1: accepted
	f.Add(ClientRequest(fuzzID, fuzzNow.Add(3*time.Hour)), uint16(2))
	f.Add(make([]byte, clientHandshakeNP+clientMinPad), uint16(0)) // the shortest buffer that is searched
	f.Fuzz(func(t *testing.T, buf []byte, pos uint16) {
		fuzzFind(t, FindClientRequest, clientHandshakeNP+clientMinPad, KeyLen+clientMinPad, buf, pos)
	})
}

func FuzzFindServerResponse(f *testing.F) {
	resp := ServerResponse(fuzzID, fuzzNow, 2000)
	f.Add(resp, uint16(0))
	f.Add(append(append([]byte(nil), resp...), Frame(100)...), uint16(7))
	f.Add(resp[:len(resp)-1], uint16(0xffff))
	f.Add(ServerResponse(fuzzID, fuzzNow, 0), uint16(1)) // no padding at all
	f.Add(make([]byte, serverHandshakeNP), uint16(0))
	f.Fuzz(func(t *testing.T, buf []byte, pos uint16) {
		fuzzFind(t, FindServerResponse, serverHandshakeNP, KeyLen+AuthLen, buf, pos)
	})
}

// FuzzHandshakeRoundTrip: whatever the clock says, a request or response
// built now is found whole, and still found by a peer whose clock is up to an
// hour off (E-1 and E+1 are accepted, as in the spec).
func FuzzHandshakeRoundTrip(f *testing.F) {
	f.Add(int64(1_800_000_000), int16(0), uint16(2000))
	f.Add(int64(1_800_000_000), int16(3599), uint16(0))
	f.Add(int64(0), int16(-3600), uint16(9000))
	f.Fuzz(func(t *testing.T, unix int64, skew int16, maxLen uint16) {
		if skew > 3600 || skew < -3600 || unix > 1<<40 || unix < -(1<<40) {
			return // keep unix+skew away from int64 overflow
		}
		now := time.Unix(unix, 0)
		peer := time.Unix(unix+int64(skew), 0)
		req := ClientRequest(fuzzID, now)
		if n, ok := FindClientRequest(req, fuzzID, peer); !ok || n != len(req) {
			t.Fatalf("request of %d bytes: n=%d ok=%v", len(req), n, ok)
		}
		resp := ServerResponse(fuzzID, now, int(maxLen))
		if n, ok := FindServerResponse(resp, fuzzID, peer); !ok || n != len(resp) {
			t.Fatalf("response of %d bytes: n=%d ok=%v", len(resp), n, ok)
		}
		if int(maxLen) >= serverHandshakeNP && len(resp) > int(maxLen) {
			t.Fatalf("response of %d bytes exceeds maxLen %d", len(resp), maxLen)
		}
	})
}
