package httpecho

import (
	"bytes"
	"testing"
)

func TestBulkPathRoundTrip(t *testing.T) {
	sid := "00112233445566778899aabbccddeeff"
	p := BulkPath(sid, "tcp.bulk", "abcdef", "up", 7)
	b, ok := ParseBulkPath(p)
	if !ok || b.SessionID != sid || b.TestID != "tcp.bulk" || b.Nonce != "abcdef" || b.Dir != "up" || b.N != 7 {
		t.Fatalf("parse: %+v %v", b, ok)
	}
	if _, ok := ParseBulkPath("/v1/bulk/short/x/y/up/1"); ok {
		t.Fatal("accepted a bad session id")
	}
	if _, ok := ParseBulkPath(BulkPath(sid, "t", "n", "sideways", 1)); ok {
		t.Fatal("accepted a bad direction")
	}
}

func TestKeystreamIsOffsetConsistent(t *testing.T) {
	whole := make([]byte, 10000)
	Keystream("seed", 0, whole)
	// any window computed from its absolute offset must match the whole
	for _, off := range []int{0, 1, 31, 32, 33, 4095, 4096, 7777} {
		win := make([]byte, 100)
		Keystream("seed", int64(off), win)
		if !bytes.Equal(win, whole[off:off+100]) {
			t.Fatalf("window at %d differs", off)
		}
	}
	other := make([]byte, 100)
	Keystream("seed2", 0, other)
	if bytes.Equal(other, whole[:100]) {
		t.Fatal("different seeds produced the same stream")
	}
}
