package dtlsx

import "testing"

func TestClientHelloBuildParse(t *testing.T) {
	for name := range Fingerprints {
		b, err := ClientHello(name, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !IsHandshake(b) {
			t.Fatalf("%s: not recognised as handshake", name)
		}
		msgs, err := Parse(b)
		if err != nil || len(msgs) != 1 || msgs[0].Type != TypeClientHello {
			t.Fatalf("%s: parse %v %+v", name, err, msgs)
		}
		info, err := ParseClientHello(msgs[0].Body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if info.Version != 0xfefd || len(info.Cookie) != 0 || len(info.CipherSuites) < 8 || len(info.Extensions) < 4 {
			t.Fatalf("%s: %+v", name, info)
		}
		cookie := []byte("0123456789abcdef")
		b2, _ := ClientHello(name, cookie, 1)
		msgs, _ = Parse(b2)
		info2, err := ParseClientHello(msgs[0].Body)
		if err != nil || string(info2.Cookie) != string(cookie) || msgs[0].Seq != 1 || b2[3] != 0 || b2[10] != 1 {
			t.Fatalf("%s: cookie round trip %v %+v", name, err, info2)
		}
		if len(info2.Extensions) != len(info.Extensions) || len(info2.CipherSuites) != len(info.CipherSuites) {
			t.Fatalf("%s: cookie insertion changed the body", name)
		}
	}
	// pion: exactly the pion/webrtc v4 defaults
	msgs, _ := Parse(mustHello("pion"))
	info, _ := ParseClientHello(msgs[0].Body)
	if len(info.CipherSuites) != 8 || info.CipherSuites[0] != 0xc02b || info.CipherSuites[7] != 0xc030 {
		t.Fatalf("pion suites %x", info.CipherSuites)
	}
	want := []uint16{0x000d, 0xff01, 0x000a, 0x000b, 0x000e, 0x0017}
	if len(info.Extensions) != len(want) {
		t.Fatalf("pion extensions %v", info.Extensions)
	}
	for i := range want {
		if info.Extensions[i] != want[i] {
			t.Fatalf("pion extensions %v want %v", info.Extensions, want)
		}
	}
}

func mustHello(name string) []byte {
	b, err := ClientHello(name, nil, 0)
	if err != nil {
		panic(err)
	}
	return b
}

func TestServerFlights(t *testing.T) {
	cookie := []byte("cookiecookiecook")
	hvr := HelloVerifyRequest(cookie)
	msgs, err := Parse(hvr)
	if err != nil || len(msgs) != 1 || msgs[0].Type != TypeHelloVerify || string(CookieOf(msgs[0].Body)) != string(cookie) {
		t.Fatalf("hvr %v %+v", err, msgs)
	}
	sh := ServerHello(0xc02b, true)
	msgs, err = Parse(sh)
	if err != nil || len(msgs) != 2 || msgs[0].Type != TypeServerHello || msgs[1].Type != 14 {
		t.Fatalf("server hello %v %+v", err, msgs)
	}
}
