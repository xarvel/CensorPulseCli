package tlsx

import "testing"

func TestClientHello(t *testing.T) {
	ch := ClientHello("x.probe.invalid")
	if len(ch) < 100 || len(ch) > 1400 || !IsClientHello(ch) {
		t.Fatalf("bad client hello: %d bytes", len(ch))
	}
	if r := Record([]byte{1, 2, 3}); len(r) != 8 || r[0] != 0x16 || r[4] != 3 {
		t.Fatal("record")
	}
	if r := AppData([]byte{1}); r[0] != 0x17 {
		t.Fatal("appdata")
	}
}
