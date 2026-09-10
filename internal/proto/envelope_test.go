package proto

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	master := RandomPayload(32)
	sid := NewSessionID()
	key := SessionKey(master, sid)
	req := &Request{SessionID: sid, TestID: "tcp.echo", Nonce: NewNonce(), Seq: 7, Payload: RandomPayload(64)}
	wire, err := EncodeRequest(req, key)
	if err != nil {
		t.Fatal(err)
	}
	if !IsEnvelope(wire) {
		t.Fatal("not recognised as envelope")
	}
	total, need := RequestLen(wire)
	if total != len(wire) || need != len(wire) {
		t.Fatalf("RequestLen = %d,%d want %d", total, need, len(wire))
	}
	// truncated prefix must report need > have
	if tot, need := RequestLen(wire[:10]); tot != 0 || need <= 10 {
		t.Fatalf("truncated RequestLen = %d,%d", tot, need)
	}
	got, err := DecodeRequest(append(wire, 1, 2, 3), func([SessionIDLen]byte) []byte { return key })
	if err != nil {
		t.Fatal(err)
	}
	if got.TestID != req.TestID || got.Seq != 7 || !bytes.Equal(got.Payload, req.Payload) || got.Nonce != req.Nonce {
		t.Fatal("request fields mismatch")
	}
	// tampered payload → MAC failure but still parsed
	bad := append([]byte(nil), wire...)
	bad[len(bad)-MACLen-1] ^= 0xff
	if _, err := DecodeRequest(bad, func([SessionIDLen]byte) []byte { return key }); err != ErrBadMAC {
		t.Fatalf("tampered: err = %v want ErrBadMAC", err)
	}
	// unknown session → ErrBadMAC with parsed request
	if r, err := DecodeRequest(wire, func([SessionIDLen]byte) []byte { return nil }); err != ErrBadMAC || r == nil || r.TestID != "tcp.echo" {
		t.Fatalf("unknown session: %v %v", r, err)
	}

	seen := time.Now()
	rep := EncodeReply(got, seen, seen.Add(time.Millisecond), key)
	if len(rep) > len(wire) {
		t.Fatalf("reply (%d) larger than request (%d): amplification", len(rep), len(wire))
	}
	dr, err := DecodeReply(rep, key)
	if err != nil {
		t.Fatal(err)
	}
	if dr.Nonce != req.Nonce || dr.RecvLen != 64 || dr.TestID != "tcp.echo" {
		t.Fatal("reply fields mismatch")
	}
	if _, err := DecodeReply(rep, RandomPayload(32)); err != ErrBadMAC {
		t.Fatalf("reply wrong key: %v", err)
	}
}

func TestTokenAndCookie(t *testing.T) {
	master := RandomPayload(32)
	sid := NewSessionID()
	exp := time.Now().Add(10 * time.Minute)
	tok := Token(master, sid, exp)
	gsid, gexp, err := VerifyToken(master, tok, time.Now())
	if err != nil || gsid != sid || gexp.Unix() != exp.Unix() {
		t.Fatalf("verify: %v", err)
	}
	if _, _, err := VerifyToken(master, tok, exp.Add(time.Second)); err == nil {
		t.Fatal("expired token accepted")
	}
	if _, _, err := VerifyToken(RandomPayload(32), tok, time.Now()); err == nil {
		t.Fatal("token accepted with wrong master")
	}
	ip := netip.MustParseAddr("203.0.113.5")
	c := Cookie(master, sid, ip, exp)
	if !VerifyCookie(master, sid, ip, exp, c) {
		t.Fatal("cookie should verify")
	}
	if VerifyCookie(master, sid, netip.MustParseAddr("203.0.113.6"), exp, c) {
		t.Fatal("cookie verified for other ip")
	}
	// v4-mapped v6 must equal v4
	if !VerifyCookie(master, sid, netip.MustParseAddr("::ffff:203.0.113.5"), exp, c) {
		t.Fatal("cookie should be address-family agnostic for mapped v4")
	}
}
