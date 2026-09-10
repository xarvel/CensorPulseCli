package obfs4

import (
	"crypto/rand"
	"testing"
	"time"
)

func testIdentity() Identity {
	var id Identity
	rand.Read(id.NodeID[:])
	rand.Read(id.Public[:])
	return id
}

func TestHandshakeRoundTrip(t *testing.T) {
	id := testIdentity()
	now := time.Now()
	req := ClientRequest(id, now)
	if len(req) < clientHandshakeNP+clientMinPad || len(req) > MaxHandshakeLen {
		t.Fatalf("request length %d", len(req))
	}
	// trailing data (the first frame) must not confuse the search
	n, ok := FindClientRequest(append(append([]byte(nil), req...), Frame(100)...), id, now.Add(30*time.Minute))
	if !ok || n != len(req) {
		t.Fatalf("find: ok=%v n=%d want %d", ok, n, len(req))
	}
	if _, ok := FindClientRequest(req[:len(req)-1], id, now); ok {
		t.Fatal("truncated request must not verify")
	}
	other := testIdentity()
	if _, ok := FindClientRequest(req, other, now); ok {
		t.Fatal("request must not verify under another identity")
	}
	if _, ok := FindClientRequest(req, id, now.Add(3*time.Hour)); ok {
		t.Fatal("request must not verify three epochs later")
	}
	resp := ServerResponse(id, now, len(req))
	if len(resp) > len(req) {
		t.Fatalf("response %d longer than request %d", len(resp), len(req))
	}
	m, ok := FindServerResponse(resp, id, now)
	if !ok || m != len(resp) {
		t.Fatalf("server response: ok=%v m=%d want %d", ok, m, len(resp))
	}
	raw, err := ParseIdentity(id.Bytes())
	if err != nil || raw != id {
		t.Fatalf("identity round trip: %v", err)
	}
}

func TestFrameBounds(t *testing.T) {
	if f := Frame(5000); len(f) != 2+MaxFrame {
		t.Fatalf("frame capped at %d, got %d", MaxFrame, len(f)-2)
	}
	if f := Frame(1); len(f) != 34 {
		t.Fatalf("frame floor 32, got %d", len(f)-2)
	}
}
