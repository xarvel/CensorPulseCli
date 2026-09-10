package ovpn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestPlainControlPackets(t *testing.T) {
	l := Plain()
	pkt, csid := l.ClientReset()
	if len(pkt) != ClientResetLen {
		t.Fatalf("client reset %d bytes", len(pkt))
	}
	if a, ok := IsClientReset(pkt); !ok || a != AuthNone {
		t.Fatal("client reset not recognised")
	}
	if got, err := l.ParseClientReset(pkt); err != nil || got != csid {
		t.Fatal("client reset round trip")
	}
	srv, ssid := l.ServerReset(csid)
	if len(srv) != ServerResetLen {
		t.Fatalf("server reset %d bytes", len(srv))
	}
	if c, s, err := l.ParseServerReset(srv); err != nil || c != csid || s != ssid {
		t.Fatal("server reset round trip")
	}
	a := l.Ack(csid, ssid, 0)
	if len(a) != AckLen || Opcode(a) != OpAckV1 {
		t.Fatal("ack shape")
	}
	if p, err := l.Parse(a); err != nil || p.Op != OpAckV1 || len(p.Acks) != 1 || p.Acks[0] != 0 || p.RemoteSID != ssid {
		t.Fatalf("ack parse: %+v %v", p, err)
	}
	c := l.Control(csid, 3, []byte("abc"), nil, [8]byte{})
	if len(c) != ControlHdrLen+3 {
		t.Fatalf("control %d bytes", len(c))
	}
	p, err := l.Parse(c)
	if err != nil || p.Op != OpControlV1 || p.SID != csid || p.PID != 3 || string(p.Payload) != "abc" || len(p.Acks) != 0 {
		t.Fatalf("control round trip: %+v %v", p, err)
	}
	// Control with a piggy-backed ack (the client's first control after
	// the server reset).
	c = l.Control(csid, 1, []byte("hello"), []uint32{0}, ssid)
	if len(c) != l.HdrLen(1)+5 {
		t.Fatalf("control+ack %d bytes, want %d", len(c), l.HdrLen(1)+5)
	}
	p, err = l.Parse(c)
	if err != nil || len(p.Acks) != 1 || p.RemoteSID != ssid || p.PID != 1 || string(p.Payload) != "hello" {
		t.Fatalf("control+ack round trip: %+v %v", p, err)
	}
	if !IsClientResetTCP(FrameTCP(pkt)) {
		t.Fatal("tcp framing")
	}
	if _, err := l.Parse([]byte{OpDataV2 << 3, 0, 0, 0, 0, 0, 0, 1, 2, 3}); !errors.Is(err, ErrNotControl) {
		t.Fatal("data packet parsed as control")
	}
}

func TestTLSAuthControlPackets(t *testing.T) {
	static := NewTLSAuthKey()
	c2s, s2c, err := TLSAuthDirKeys(static)
	if err != nil || len(c2s) != HMACLen || len(s2c) != HMACLen || bytes.Equal(c2s, s2c) {
		t.Fatal("direction keys")
	}
	client := TLSAuth(c2s, s2c)
	server := TLSAuth(s2c, c2s)
	fixed := time.Unix(1_800_000_000, 0)
	client.now = func() time.Time { return fixed }

	pkt, csid := client.ClientReset()
	if len(pkt) != ClientResetLenTLSAuth {
		t.Fatalf("client reset %d bytes, want %d", len(pkt), ClientResetLenTLSAuth)
	}
	if a, ok := IsClientReset(pkt); !ok || a != AuthTLS {
		t.Fatal("tls-auth client reset not recognised")
	}
	// Wire layout: op | sid | hmac | packet_id=1 | net_time | ack_len=0 | msg_pid=0
	if pkt[0] != OpHardResetClientV2<<3 || binary.BigEndian.Uint32(pkt[29:33]) != 1 || binary.BigEndian.Uint32(pkt[33:37]) != uint32(fixed.Unix()) || pkt[37] != 0 {
		t.Fatalf("client reset layout: %x", pkt)
	}
	got, err := server.ParseClientReset(pkt)
	if err != nil || got != csid {
		t.Fatalf("server did not accept the client reset: %v", err)
	}
	if _, err := Plain().ParseClientReset(pkt); !errors.Is(err, ErrNotReset) {
		t.Fatal("plain layout accepted a tls-auth reset")
	}
	// A flipped payload byte and a flipped hmac byte both fail verification.
	for _, i := range []int{0, 5, 12, 29, 36, 41} {
		bad := append([]byte(nil), pkt...)
		bad[i] ^= 0x01
		if _, err := server.Parse(bad); !errors.Is(err, ErrBadHMAC) && !errors.Is(err, ErrNotControl) {
			t.Errorf("byte %d flipped: err=%v, want hmac mismatch", i, err)
		}
	}
	// Wrong key: silent drop material.
	if _, err := TLSAuth(nil, s2c).Parse(pkt); !errors.Is(err, ErrBadHMAC) {
		t.Fatal("wrong key accepted")
	}
	// Without a receive key the fields are unpacked, not verified.
	if p, err := TLSAuth(nil, nil).Parse(pkt); err != nil || p.ReplayID != 1 || p.NetTime != uint32(fixed.Unix()) {
		t.Fatalf("keyless parse: %+v %v", p, err)
	}

	srv, ssid := server.ServerReset(csid)
	if len(srv) != ServerResetLenTLSAuth {
		t.Fatalf("server reset %d bytes, want %d", len(srv), ServerResetLenTLSAuth)
	}
	c, s, err := client.ParseServerReset(srv)
	if err != nil || c != csid || s != ssid {
		t.Fatalf("client did not accept the server reset: %v", err)
	}
	if _, _, err := server.ParseServerReset(srv); !errors.Is(err, ErrBadHMAC) {
		t.Fatal("server reset verified with the wrong direction key")
	}

	// Replay ids increment per packet built.
	ctl1 := client.Control(csid, 1, []byte("hello"), []uint32{0}, ssid)
	ctl2 := client.Control(csid, 2, bytes.Repeat([]byte{7}, 100), nil, [8]byte{})
	p1, err1 := server.Parse(ctl1)
	p2, err2 := server.Parse(ctl2)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if p1.ReplayID != 2 || p2.ReplayID != 3 || p1.PID != 1 || p2.PID != 2 || len(p1.Acks) != 1 || p1.RemoteSID != ssid || len(p2.Payload) != 100 {
		t.Fatalf("control packets: %+v %+v", p1, p2)
	}
	if len(ctl2) != ControlHdrLenTLSAuth+100 || len(ctl1) != client.HdrLen(1)+5 {
		t.Fatalf("control sizes %d %d", len(ctl1), len(ctl2))
	}
	ack := server.Ack(ssid, csid, 1)
	if len(ack) != AckLenTLSAuth {
		t.Fatalf("ack %d bytes", len(ack))
	}
	if p, err := client.Parse(ack); err != nil || p.Op != OpAckV1 || p.Acks[0] != 1 {
		t.Fatalf("ack: %+v %v", p, err)
	}
	if !IsClientResetTCP(FrameTCP(pkt)) {
		t.Fatal("tcp framing of a tls-auth reset")
	}
	// Truncated packets are errors, never panics.
	for i := 1; i < len(ctl1); i++ {
		if _, err := server.Parse(ctl1[:i]); err == nil {
			t.Errorf("truncated to %d bytes parsed", i)
		}
	}
}

func TestDataChannel(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	c2s, s2c := DeriveDataKeys(key, "attempt-1")
	other, _ := DeriveDataKeys(key, "attempt-2")
	plain := bytes.Repeat([]byte{1, 2, 3}, 100)
	pkt := c2s.Seal(0, 1, plain)
	if len(pkt) != DataHdrLen+len(plain)+DataTagLen {
		t.Fatalf("wire size %d", len(pkt))
	}
	if pkt[0] != 0x48 || pkt[1] != 0 || pkt[2] != 0 || pkt[3] != 0 || binary.BigEndian.Uint32(pkt[4:8]) != 1 {
		t.Fatalf("header %x", pkt[:8])
	}
	if !IsData(pkt) || Opcode(pkt) != OpDataV2 || DataPeer(pkt) != 0 {
		t.Fatal("shape")
	}
	pid, got, err := c2s.Open(pkt)
	if err != nil || pid != 1 || !bytes.Equal(got, plain) {
		t.Fatalf("open: %v", err)
	}
	// The other direction, another attempt and a tampered byte all fail.
	if _, _, err := s2c.Open(pkt); !errors.Is(err, ErrBadTag) {
		t.Fatal("s2c key opened a c2s packet")
	}
	if _, _, err := other.Open(pkt); !errors.Is(err, ErrBadTag) {
		t.Fatal("another attempt's key opened the packet")
	}
	bad := append([]byte(nil), pkt...)
	bad[20] ^= 0xff
	if _, _, err := c2s.Open(bad); !errors.Is(err, ErrBadTag) {
		t.Fatal("tampered packet opened")
	}
	bad = append([]byte(nil), pkt...)
	binary.BigEndian.PutUint32(bad[4:8], 2) // packet id is associated data
	if _, _, err := c2s.Open(bad); !errors.Is(err, ErrBadTag) {
		t.Fatal("packet id change not detected")
	}
	if _, _, err := c2s.Open(pkt[:DataHdrLen+3]); !errors.Is(err, ErrNotData) {
		t.Fatal("short packet accepted")
	}
	// A ping-sized first packet is 40 bytes on the wire.
	if n := len(c2s.Seal(0, 1, PingMagic)); n != 40 {
		t.Fatalf("ping datagram %d bytes", n)
	}
	// Peer id is carried in the header.
	if p := s2c.Seal(0x010203, 7, plain); DataPeer(p) != 0x010203 {
		t.Fatal("peer id")
	}
}
