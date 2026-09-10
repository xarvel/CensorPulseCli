package ovpn

import (
	"bytes"
	"testing"
	"time"
)

// Every function below is fed by a datagram or a TCP frame that anybody on
// the path can write. The property is the same everywhere: no input panics,
// and whatever parses can be rebuilt into the bytes it came from. The seeds
// come from the package's own builders, so they run under plain `go test`.

var (
	fuzzSID    = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	fuzzRemote = [8]byte{9, 10, 11, 12, 13, 14, 15, 16}
	fuzzC2S    = bytes.Repeat([]byte{0xa1}, HMACLen)
	fuzzS2C    = bytes.Repeat([]byte{0xb2}, HMACLen)
	fuzzTime   = time.Unix(1_800_000_000, 0)
)

// fuzzTLSAuth is a tls-auth layout with a fixed clock and replay counter, so
// that a rebuilt packet carries the replay fields of the parsed one.
func fuzzTLSAuth(send, recv []byte, replay, netTime uint32) *Layout {
	l := TLSAuth(send, recv)
	l.replay = replay
	l.now = func() time.Time { return time.Unix(int64(netTime), 0) }
	return l
}

func controlSeeds(l func() *Layout) [][]byte {
	reset, sid := l().ClientReset()
	srv, _ := l().ServerReset(sid)
	ctl := l().Control(fuzzSID, 1, []byte("hello"), []uint32{0, 7}, fuzzRemote)
	return [][]byte{
		reset, srv, ctl, ctl[:len(ctl)-7],
		l().Ack(fuzzSID, fuzzRemote, 3),
		l().Control(fuzzSID, 2, nil, nil, [8]byte{}),
		FrameTCP(reset),
		{OpControlV1 << 3, 0, 0, 0, 0, 0, 0, 0, 0, 0xff}, // 255 acks announced, none carried
		{},
	}
}

func FuzzParsePlain(f *testing.F) {
	for _, s := range controlSeeds(Plain) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		// The cheap checks the demuxers run on every datagram.
		Opcode(b)
		SessionOf(b)
		IsClientReset(b)
		IsClientResetTCP(b)
		Plain().ParseClientReset(b)
		Plain().ParseServerReset(b)
		p, err := Plain().Parse(b)
		if err != nil {
			return
		}
		if got := Plain().Build(p); !bytes.Equal(got, b) {
			t.Fatalf("Build(Parse(b)) != b\n b   %x\n got %x\n pkt %+v", b, got, p)
		}
	})
}

func FuzzParseTLSAuth(f *testing.F) {
	for _, s := range controlSeeds(func() *Layout { return fuzzTLSAuth(fuzzC2S, nil, 1, uint32(fuzzTime.Unix())) }) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		TLSAuth(nil, fuzzC2S).ParseClientReset(b)
		TLSAuth(nil, fuzzC2S).ParseServerReset(b)
		// Keyed: only a packet with a valid HMAC parses, and it rebuilds
		// byte for byte from its own replay fields (Build turns a replay id
		// of 0 into 1, so that one cannot round-trip).
		if p, err := TLSAuth(nil, fuzzC2S).Parse(b); err == nil && p.ReplayID != 0 {
			if got := fuzzTLSAuth(fuzzC2S, nil, p.ReplayID, p.NetTime).Build(p); !bytes.Equal(got, b) {
				t.Fatalf("keyed Build(Parse(b)) != b\n b   %x\n got %x", b, got)
			}
		}
		// Keyless: the fields are unpacked without verification, which is the
		// path a fuzzer can actually walk. Everything but the HMAC block
		// (bytes 9..29) must survive the round trip.
		p, err := TLSAuth(nil, nil).Parse(b)
		if err != nil || p.ReplayID == 0 {
			return
		}
		got := fuzzTLSAuth(fuzzC2S, nil, p.ReplayID, p.NetTime).Build(p)
		if len(got) != len(b) || !bytes.Equal(got[:9], b[:9]) || !bytes.Equal(got[9+HMACLen:], b[9+HMACLen:]) {
			t.Fatalf("keyless Build(Parse(b)) != b outside the hmac\n b   %x\n got %x", b, got)
		}
	})
}

// FuzzControlRoundTrip goes the other way: Parse(Build(x)) == x for any
// packet the builders can be asked for, on both layouts.
func FuzzControlRoundTrip(f *testing.F) {
	f.Add(false, uint8(0), uint8(0), uint64(1), uint64(2), uint32(0), uint8(0), []byte(nil))
	f.Add(true, uint8(1), uint8(0), uint64(1), uint64(2), uint32(1), uint8(1), []byte("hello"))
	f.Add(true, uint8(2), uint8(3), uint64(1), uint64(2), uint32(9), uint8(4), []byte(nil))
	f.Add(false, uint8(3), uint8(7), uint64(1), uint64(2), uint32(9), uint8(255), []byte{0})
	ops := []int{OpHardResetClientV2, OpHardResetServerV2, OpAckV1, OpControlV1}
	f.Fuzz(func(t *testing.T, tlsAuth bool, opSel, keyID uint8, sid, remote uint64, pid uint32, nAcks uint8, payload []byte) {
		want := &Packet{Op: ops[int(opSel)%len(ops)], KeyID: int(keyID & 7), PID: pid, Payload: payload}
		for i := range want.SID {
			want.SID[i] = byte(sid >> (8 * i))
			want.RemoteSID[i] = byte(remote >> (8 * i))
		}
		for i := 0; i < int(nAcks); i++ {
			want.Acks = append(want.Acks, pid+uint32(i))
		}
		build, parse := Plain(), Plain()
		if tlsAuth {
			build, parse = fuzzTLSAuth(fuzzC2S, fuzzS2C, 5, 77), TLSAuth(fuzzS2C, fuzzC2S)
		}
		wire := build.Build(want)
		if len(wire) != build.HdrLen(len(want.Acks))+len(payload) && want.Op != OpAckV1 {
			t.Fatalf("wire size %d, HdrLen says %d + %d", len(wire), build.HdrLen(len(want.Acks)), len(payload))
		}
		got, err := parse.Parse(wire)
		if err != nil {
			t.Fatalf("Parse(Build(%+v)): %v", want, err)
		}
		if got.Op != want.Op || got.KeyID != want.KeyID || got.SID != want.SID || len(got.Acks) != len(want.Acks) {
			t.Fatalf("header: got %+v want %+v", got, want)
		}
		for i := range want.Acks {
			if got.Acks[i] != want.Acks[i] {
				t.Fatalf("ack %d: got %d want %d", i, got.Acks[i], want.Acks[i])
			}
		}
		if len(want.Acks) > 0 && got.RemoteSID != want.RemoteSID {
			t.Fatalf("remote sid: got %x want %x", got.RemoteSID, want.RemoteSID)
		}
		// A P_ACK_V1 carries neither a message packet id nor a payload.
		if want.Op != OpAckV1 && (got.PID != want.PID || !bytes.Equal(got.Payload, want.Payload)) {
			t.Fatalf("message: got %d %x want %d %x", got.PID, got.Payload, want.PID, want.Payload)
		}
		if tlsAuth && (got.ReplayID != 5 || got.NetTime != 77) {
			t.Fatalf("replay fields: %d %d", got.ReplayID, got.NetTime)
		}
	})
}

func FuzzDataKeyOpen(f *testing.F) {
	c2s, s2c := DeriveDataKeys(bytes.Repeat([]byte{0x42}, 32), "attempt-1")
	ping := c2s.Seal(0x010203, 1, PingMagic)
	f.Add(ping)
	f.Add(ping[:DataHdrLen+DataTagLen-1])
	f.Add(c2s.Seal(0, 0xffffffff, nil))
	f.Add(s2c.Seal(0, 2, bytes.Repeat([]byte{7}, 100))) // the other direction: must not open
	f.Add([]byte{OpDataV2 << 3})
	f.Fuzz(func(t *testing.T, b []byte) {
		pid, plain, err := c2s.Open(b)
		// DataPeer indexes b[1..3] unchecked; IsData is the guard every
		// caller runs first (server/udp.go, server/tcp.go).
		if !IsData(b) {
			if err == nil {
				t.Fatalf("opened a packet IsData rejects: %x", b)
			}
			return
		}
		peer := DataPeer(b)
		if err != nil {
			return
		}
		if got := c2s.Seal(peer, pid, plain); !bytes.Equal(got, b) {
			t.Fatalf("Seal(Open(b)) != b\n b   %x\n got %x", b, got)
		}
	})
}
