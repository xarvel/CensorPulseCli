package wg

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/blake2s"
)

// The three Consume/Open functions take a datagram straight from the socket.
// A fuzzer cannot forge a MAC, so on its own it never gets past the first
// check; each target therefore also feeds a copy of the input with the cheap
// outer fields repaired (mac1, receiver index), which is what reaches the
// Curve25519 and AEAD code with attacker-chosen points and ciphertext.

func fuzzKeys(t testing.TB) (server, client KeyPair) {
	t.Helper()
	server, err := KeyPairFromPrivate([32]byte{0: 0x08, 1: 0x11, 31: 0x40})
	if err != nil {
		t.Fatal(err)
	}
	client, err = KeyPairFromPrivate([32]byte{0: 0x10, 1: 0x22, 31: 0x40})
	if err != nil {
		t.Fatal(err)
	}
	return server, client
}

// withMAC1 returns msg with a valid mac1 for pub over its first n bytes.
func withMAC1(msg []byte, pub [32]byte, n int) []byte {
	out := append([]byte(nil), msg...)
	key := blake2s.Sum256(append([]byte(labelMAC1), pub[:]...))
	m, _ := blake2s.New128(key[:])
	m.Write(out[:n])
	copy(out[n:n+16], m.Sum(nil))
	return out
}

func FuzzConsumeInitiation(f *testing.F) {
	server, client := fuzzKeys(f)
	_, init, err := CreateInitiation(client, server.Public, [32]byte{})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(init)
	f.Add(init[:InitiationSize-1])
	f.Add(make([]byte, InitiationSize))
	lowOrder := append([]byte(nil), init...) // all-zero ephemeral: X25519 refuses the point
	copy(lowOrder[8:40], make([]byte, 32))
	f.Add(lowOrder)
	f.Fuzz(func(t *testing.T, b []byte) {
		LooksLikeInitiation(b)
		CheckMAC1(b, server.Public)
		info, err := ConsumeInitiation(b, server)
		if err == nil {
			// Only a genuine initiation gets here; it must be answerable.
			if !info.MAC1Valid || !info.StaticValid || !info.TimestampOK {
				t.Fatalf("accepted with %+v", info)
			}
			if _, _, err := CreateResponse(info, server, [32]byte{}); err != nil {
				t.Fatalf("CreateResponse after a valid initiation: %v", err)
			}
		}
		if len(b) != InitiationSize || b[0] != MessageInitiationType {
			return
		}
		if info, err := ConsumeInitiation(withMAC1(b, server.Public, 116), server); info == nil || !info.MAC1Valid {
			t.Fatalf("repaired mac1 not accepted: %+v %v", info, err)
		}
	})
}

func FuzzConsumeResponse(f *testing.F) {
	server, client := fuzzKeys(f)
	st, init, err := CreateInitiation(client, server.Public, [32]byte{})
	if err != nil {
		f.Fatal(err)
	}
	info, err := ConsumeInitiation(init, server)
	if err != nil {
		f.Fatal(err)
	}
	resp, _, err := CreateResponse(info, server, [32]byte{})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(resp)
	f.Add(resp[:ResponseSize-1])
	f.Add(make([]byte, ResponseSize))
	f.Fuzz(func(t *testing.T, b []byte) {
		// A fresh copy of the state per input: a successful ConsumeResponse
		// writes the transport keys into it.
		fresh := *st
		if err := fresh.ConsumeResponse(b, [32]byte{}); err == nil {
			if _, ok := fresh.Keys(); !ok || fresh.PeerIdx != binary.LittleEndian.Uint32(b[4:8]) {
				t.Fatalf("accepted without keys / with the wrong peer index")
			}
		} else if _, ok := fresh.Keys(); ok {
			t.Fatalf("keys marked ready after %v", err)
		}
		if len(b) != ResponseSize {
			return
		}
		// Same input addressed to this initiator: reaches the DH with the
		// fuzzer's ephemeral and the AEAD with its ciphertext.
		mine := append([]byte(nil), b...)
		mine[0] = MessageResponseType
		binary.LittleEndian.PutUint32(mine[8:12], st.SenderIdx)
		fresh = *st
		fresh.ConsumeResponse(mine, [32]byte{})
	})
}

func FuzzOpenTransport(f *testing.F) {
	key := [32]byte{0: 1, 31: 2}
	pkt := SealTransport(key, 0xdeadbeef, 7, []byte("probe padding, not an IP packet"))
	f.Add(pkt)
	f.Add(pkt[:TransportOverhead-1])
	f.Add(SealTransport(key, 0, 0, nil)) // keepalive: header and tag only
	f.Add(SealTransport([32]byte{}, 1, 1, make([]byte, 16)))
	f.Fuzz(func(t *testing.T, b []byte) {
		ctr, plain, err := OpenTransport(key, b)
		// TransportReceiver reads b[4:8] unchecked; LooksLikeTransport is the
		// guard the UDP demuxer runs first (server/udp.go).
		if !LooksLikeTransport(b) {
			if err == nil {
				t.Fatalf("opened a packet LooksLikeTransport rejects: %x", b)
			}
			return
		}
		receiver := TransportReceiver(b)
		if err != nil {
			return
		}
		if got := SealTransport(key, receiver, ctr, plain); len(plain)%16 == 0 && !bytes.Equal(got, b) {
			t.Fatalf("SealTransport(OpenTransport(b)) != b\n b   %x\n got %x", b, got)
		}
	})
}
