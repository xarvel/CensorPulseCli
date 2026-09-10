package wg

import "testing"

func TestHandshakeRoundTrip(t *testing.T) {
	server, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	client, _ := NewKeyPair()
	var psk [32]byte
	st, init, err := CreateInitiation(client, server.Public, psk)
	if err != nil {
		t.Fatal(err)
	}
	if len(init) != InitiationSize || !LooksLikeInitiation(init) {
		t.Fatalf("initiation size %d", len(init))
	}
	info, err := ConsumeInitiation(init, server)
	if err != nil {
		t.Fatalf("consume initiation: %v", err)
	}
	if info.PeerStatic != client.Public || !info.TimestampOK {
		t.Fatal("responder did not recover initiator static key")
	}
	resp, rs, err := CreateResponse(info, server, psk)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != ResponseSize {
		t.Fatalf("response size %d", len(resp))
	}
	if err := st.ConsumeResponse(resp, psk); err != nil {
		t.Fatalf("initiator rejected response: %v", err)
	}
	// Transport keys agree and data packets round-trip in both directions.
	ik, ok := st.Keys()
	if !ok || ik.Send != rs.Keys.Recv || ik.Recv != rs.Keys.Send {
		t.Fatal("transport keys do not match between initiator and responder")
	}
	if st.PeerIdx != rs.LocalIdx || rs.PeerIdx != st.SenderIdx {
		t.Fatal("indices do not match")
	}
	plain := []byte("probe padding, not an IP packet")
	pkt := SealTransport(ik.Send, st.PeerIdx, 7, plain)
	if !LooksLikeTransport(pkt) || TransportReceiver(pkt) != rs.LocalIdx || len(pkt) != TransportOverhead+32 {
		t.Fatalf("transport packet shape: len=%d", len(pkt))
	}
	ctr, got, err := OpenTransport(rs.Keys.Recv, pkt)
	if err != nil || ctr != 7 || string(got[:len(plain)]) != string(plain) {
		t.Fatalf("responder could not open transport packet: %v", err)
	}
	back := SealTransport(rs.Keys.Send, rs.PeerIdx, 7, got)
	if _, _, err := OpenTransport(ik.Recv, back); err != nil {
		t.Fatalf("initiator could not open echoed packet: %v", err)
	}
	pkt[len(pkt)-1] ^= 1
	if _, _, err := OpenTransport(rs.Keys.Recv, pkt); err == nil {
		t.Fatal("tampered transport packet accepted")
	}

	// Wrong server key → mac1 fails, no DH performed.
	other, _ := NewKeyPair()
	if _, err := ConsumeInitiation(init, other); err == nil {
		t.Fatal("initiation accepted by wrong responder key")
	}
	// Flipped byte inside the encrypted static → auth failure.
	bad := append([]byte(nil), init...)
	bad[50] ^= 1
	if CheckMAC1(bad, server.Public) {
		t.Fatal("mac1 should fail after modification")
	}
	// Tampered response → initiator rejects.
	badResp := append([]byte(nil), resp...)
	badResp[50] ^= 1
	if err := st.ConsumeResponse(badResp, psk); err == nil {
		t.Fatal("tampered response accepted")
	}
}
