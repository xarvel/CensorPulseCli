package proto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// The CP1 envelope is parsed on every raw TCP/UDP port before anything is
// known about the sender, and the token and cookie verifiers are the first
// thing the control API and the UDP listeners run on a request. A fuzzer
// cannot forge an HMAC, so the envelope targets also feed a copy of the input
// with the MAC repaired: that is what gets past authentication with
// attacker-shaped lengths.

var (
	fuzzMaster = bytes.Repeat([]byte{0x4d}, 32)
	fuzzSID    = [SessionIDLen]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	fuzzNonce  = [NonceLen]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab}
	fuzzKey    = SessionKey(fuzzMaster, fuzzSID)
	fuzzNow    = time.Unix(1_800_000_000, 0)
)

func fuzzKeyFor([SessionIDLen]byte) []byte { return fuzzKey }

func requestSeeds(f *testing.F) [][]byte {
	f.Helper()
	var out [][]byte
	for _, r := range []*Request{
		{SessionID: fuzzSID, TestID: "tcp.echo", Nonce: fuzzNonce, Seq: 7, Payload: []byte("payload")},
		{SessionID: fuzzSID, TestID: "udp.echo", Nonce: fuzzNonce, Cookie: Cookie(fuzzMaster, fuzzSID, netip.MustParseAddr("203.0.113.5"), fuzzNow)},
		{SessionID: fuzzSID, TestID: strings.Repeat("t", 255), Nonce: fuzzNonce, Payload: make([]byte, MaxPayload)},
	} {
		wire, err := EncodeRequest(r, fuzzKey)
		if err != nil {
			f.Fatal(err)
		}
		out = append(out, wire, wire[:len(wire)-1], wire[:30], wire[:22], append(append([]byte(nil), wire...), 1, 2, 3))
	}
	return out
}

// checkRequest is the property of one decoded request against the bytes it
// came from.
func checkRequest(t *testing.T, b []byte, r *Request, total int) {
	t.Helper()
	sid, testID, nonce, have := PeekRequest(b)
	if have != 3 || sid != r.SessionID || testID != r.TestID || nonce != r.Nonce {
		t.Fatalf("PeekRequest disagrees with DecodeRequest: have=%d %x %q %x", have, sid, testID, nonce)
	}
	if !bytes.Equal(r.Raw, b[:total]) {
		t.Fatalf("Raw is not the envelope")
	}
	again, err := EncodeRequest(r, fuzzKey)
	if err != nil || b[5]&^flagCookie != 0 {
		return // what the encoder refuses to build: empty test id, oversized payload, unknown flag bits
	}
	if !bytes.Equal(again[:len(again)-MACLen], b[:total-MACLen]) {
		t.Fatalf("EncodeRequest(DecodeRequest(b)) != b\n b     %x\n again %x", b[:total], again)
	}
}

func FuzzDecodeRequest(f *testing.F) {
	for _, s := range requestSeeds(f) {
		f.Add(s)
	}
	f.Add([]byte("CP1\x01\x01\x01"))
	f.Add([]byte("CP1\x01\x02\x00")) // a reply is not a request
	f.Fuzz(func(t *testing.T, b []byte) {
		total, need := RequestLen(b)
		if total != 0 && (total != need || total > len(b)) || total == 0 && need <= len(b) {
			t.Fatalf("RequestLen = %d,%d for %d bytes", total, need, len(b))
		}
		PeekRequest(b)
		r, err := DecodeRequest(b, fuzzKeyFor)
		switch {
		case err == nil:
			checkRequest(t, b, r, total)
		case errors.Is(err, ErrBadMAC):
			if r == nil {
				t.Fatal("ErrBadMAC without the parsed request")
			}
			checkRequest(t, b, r, total)
			// Same bytes, MAC repaired: must authenticate.
			fixed := append([]byte(nil), b[:total]...)
			copy(fixed[total-MACLen:], mac(fuzzKey, fixed[:total-MACLen]))
			if _, err := DecodeRequest(fixed, fuzzKeyFor); err != nil {
				t.Fatalf("repaired MAC rejected: %v\n %x", err, fixed)
			}
			if _, err := DecodeRequest(fixed, func([SessionIDLen]byte) []byte { return nil }); !errors.Is(err, ErrBadMAC) {
				t.Fatalf("unknown session: %v", err)
			}
		case r != nil:
			t.Fatalf("request next to %v", err)
		}
	})
}

func FuzzDecodeReply(f *testing.F) {
	req := &Request{SessionID: fuzzSID, TestID: "tcp.echo", Nonce: fuzzNonce, Seq: 7, Payload: []byte("payload")}
	rep := EncodeReply(req, fuzzNow, fuzzNow.Add(time.Millisecond), fuzzKey)
	f.Add(rep)
	f.Add(rep[:len(rep)-1])
	f.Add(rep[:23])
	f.Add(append(append([]byte(nil), rep...), 1, 2, 3))
	for _, s := range requestSeeds(f)[:2] {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		total, need := ReplyLen(b)
		if total != 0 && (total != need || total > len(b)) || total == 0 && need <= len(b) {
			t.Fatalf("ReplyLen = %d,%d for %d bytes", total, need, len(b))
		}
		r, err := DecodeReply(b, fuzzKey)
		if err == nil || !errors.Is(err, ErrBadMAC) {
			return
		}
		if r == nil {
			t.Fatal("ErrBadMAC without the parsed reply")
		}
		fixed := append([]byte(nil), b[:total]...)
		copy(fixed[total-MACLen:], mac(fuzzKey, fixed[:total-MACLen]))
		got, err := DecodeReply(fixed, fuzzKey)
		if err != nil || got.TestID != r.TestID || got.Seq != r.Seq || got.RecvLen != r.RecvLen || !got.SeenAt.Equal(r.SeenAt) {
			t.Fatalf("repaired MAC: %v %+v", err, got)
		}
	})
}

// FuzzEnvelopeRoundTrip: Decode(Encode(x)) == x for requests and for the
// reply the server builds from them.
func FuzzEnvelopeRoundTrip(f *testing.F) {
	f.Add("tcp.echo", uint32(7), false, []byte("payload"), int64(1_800_000_000_000_000_000), int64(1_800_000_000_001_000_000))
	f.Add("u", uint32(0xffffffff), true, []byte(nil), int64(0), int64(-1))
	f.Fuzz(func(t *testing.T, testID string, seq uint32, withCookie bool, payload []byte, seenNs, repliedNs int64) {
		req := &Request{SessionID: fuzzSID, TestID: testID, Nonce: fuzzNonce, Seq: seq, Payload: payload}
		if withCookie {
			req.Cookie = Cookie(fuzzMaster, fuzzSID, netip.MustParseAddr("203.0.113.5"), fuzzNow)
		}
		wire, err := EncodeRequest(req, fuzzKey)
		if err != nil {
			if len(testID) >= 1 && len(testID) <= 255 && len(payload) <= MaxPayload {
				t.Fatalf("encoder refused a valid request: %v", err)
			}
			return
		}
		got, err := DecodeRequest(wire, fuzzKeyFor)
		if err != nil || got.TestID != testID || got.Seq != seq || got.Nonce != fuzzNonce || got.SessionID != fuzzSID ||
			!bytes.Equal(got.Payload, payload) || !bytes.Equal(got.Cookie, req.Cookie) || (got.Cookie == nil) != !withCookie {
			t.Fatalf("request: %v %+v", err, got)
		}
		rep, err := DecodeReply(EncodeReply(got, time.Unix(0, seenNs), time.Unix(0, repliedNs), fuzzKey), fuzzKey)
		if err != nil || rep.TestID != testID || rep.Seq != seq || rep.Nonce != fuzzNonce || int(rep.RecvLen) != len(payload) ||
			rep.SeenAt.UnixNano() != seenNs || rep.RepliedAt.UnixNano() != repliedNs {
			t.Fatalf("reply: %v %+v", err, rep)
		}
	})
}

func FuzzVerifyToken(f *testing.F) {
	tok := Token(fuzzMaster, fuzzSID, fuzzNow.Add(10*time.Minute))
	f.Add(tok)
	f.Add(tok[:len(tok)-1])
	f.Add(tok + "=")
	f.Add(Token(fuzzMaster, fuzzSID, fuzzNow.Add(-time.Second))) // expired
	f.Add(Token([]byte("another master"), fuzzSID, fuzzNow.Add(time.Hour)))
	f.Add("")
	f.Fuzz(func(t *testing.T, tok string) {
		sid, exp, err := VerifyToken(fuzzMaster, tok, fuzzNow)
		if err == nil {
			// base64url tolerates stray bits in the last character, so the
			// comparison is on what the token says, not on its spelling.
			s2, e2, err := VerifyToken(fuzzMaster, Token(fuzzMaster, sid, exp), fuzzNow)
			if err != nil || s2 != sid || !e2.Equal(exp) || fuzzNow.After(exp) {
				t.Fatalf("Token(VerifyToken(tok)) does not verify: %v", err)
			}
			return
		}
		// Same session id and expiry under a correct MAC: only "expired" may
		// still refuse it.
		raw, derr := base64.RawURLEncoding.DecodeString(tok)
		if derr != nil || len(raw) != SessionIDLen+8+MACLen {
			return
		}
		copy(sid[:], raw)
		var e int64
		for _, c := range raw[SessionIDLen : SessionIDLen+8] {
			e = e<<8 | int64(c)
		}
		// (An expiry beyond 1<<50 seconds is outside what time.Time orders
		// correctly; no token the server signs comes near it.)
		if _, _, err := VerifyToken(fuzzMaster, Token(fuzzMaster, sid, time.Unix(e, 0)), fuzzNow); err != nil && e >= fuzzNow.Unix() && e < 1<<50 {
			t.Fatalf("re-signed token refused: %v", err)
		}
	})
}

func FuzzVerifyCookie(f *testing.F) {
	ip := netip.MustParseAddr("203.0.113.5")
	f.Add(Cookie(fuzzMaster, fuzzSID, ip, fuzzNow), ip.AsSlice(), fuzzNow.Unix())
	f.Add(Cookie(fuzzMaster, fuzzSID, ip, fuzzNow)[:CookieLen-1], ip.AsSlice(), fuzzNow.Unix())
	f.Add([]byte(nil), netip.MustParseAddr("::ffff:203.0.113.5").AsSlice(), int64(-1))
	f.Add(make([]byte, CookieLen), []byte{1, 2, 3}, int64(0)) // not an address at all
	f.Fuzz(func(t *testing.T, got, ipb []byte, exp int64) {
		addr, _ := netip.AddrFromSlice(ipb) // the zero Addr when ipb is not 4 or 16 bytes
		when := time.Unix(exp, 0)
		if VerifyCookie(fuzzMaster, fuzzSID, addr, when, got) && !bytes.Equal(got, Cookie(fuzzMaster, fuzzSID, addr, when)) {
			t.Fatalf("verified a cookie that is not the cookie: %x", got)
		}
		c := Cookie(fuzzMaster, fuzzSID, addr, when)
		if len(c) != CookieLen || !VerifyCookie(fuzzMaster, fuzzSID, addr, when, c) || !VerifyCookie(fuzzMaster, fuzzSID, addr.Unmap(), when, c) {
			t.Fatalf("own cookie does not verify for %v", addr)
		}
	})
}

func FuzzParseSessionID(f *testing.F) {
	f.Add(hex.EncodeToString(fuzzSID[:]))
	f.Add(strings.ToUpper(hex.EncodeToString(fuzzSID[:])))
	f.Add(hex.EncodeToString(fuzzSID[:])[:31])
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		id, err := ParseSessionID(s)
		if err != nil {
			if id != ([SessionIDLen]byte{}) {
				t.Fatalf("id next to an error: %x", id)
			}
			return
		}
		if hex.EncodeToString(id[:]) != strings.ToLower(s) {
			t.Fatalf("ParseSessionID(%q) = %x", s, id)
		}
	})
}
